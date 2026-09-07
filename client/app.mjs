import { verifyBundle } from './verify.mjs';
import { verifyBundleAgent } from './agent-bundle.mjs';
import { parseJSONStrict } from '../web/service-receipt.mjs';

const byID = (id) => document.getElementById(id);
const state = { config: null, original: null, bundle: null, raw: null, originalRaw: null, result: null, expectedNonce: null, busy: false, tampered: false };
let verificationRevision = 0;
const setText = (id, value) => { byID(id).textContent = value ?? '—'; };
const setRow = (rowID, textID, value) => { const show = value !== undefined && value !== null && value !== ''; byID(rowID).hidden = !show; if (show) setText(textID, value); };
const scenario = () => document.querySelector('input[name="scenario"]:checked').value;
const mode = () => byID('mode').value;
const formatTime = (value) => { const date = new Date(value); return Number.isFinite(date.getTime()) ? new Intl.DateTimeFormat('zh-TW', {dateStyle:'short',timeStyle:'medium'}).format(date) : '未附觀測時間'; };

function showError(message) { setText('error', message); byID('error').hidden = false; }
function clearError() { byID('error').hidden = true; }
function enabledState() {
  byID('run').disabled = state.busy || !state.config || (mode() === 'live' && !liveReady());
  byID('download').disabled = state.busy || !state.bundle;
  byID('tamper').disabled = state.busy || !state.original || state.tampered;
  byID('restore').hidden = !state.tampered;
  byID('import-button').disabled = state.busy;
  byID('mode').disabled = state.busy;
  document.querySelectorAll('input[name="scenario"]').forEach(input => { input.disabled = state.busy; });
}
function liveReady() { return Boolean(state.config?.compute_configured && state.config?.live_ready); }
function currentExample() {
  const examples = state.config?.examples ?? [];
  return examples.find(example => example.mode === mode()) ?? examples.find(example => !example.mode) ?? examples[0];
}
function updateComparison() {
  const example = currentExample();
  const requirement = example?.payment_required?.accepts?.[0] ?? example?.accepts?.[0];
  setText('endpoint', example?.url ?? '尚未設定範例');
  setText('baseline-heading', mode() === 'live' ? '原始付款要求範例' : '演練觀測基準');
  const amount = requirement?.amount ?? requirement?.maxAmountRequired ?? '—';
  const network = requirement?.network ?? '—';
  for (const prefix of ['baseline','submitted']) { setText(`${prefix}-network`, network); setText(`${prefix}-amount`, amount); }
  setText('baseline-payee', requirement?.payTo ?? '—');
  const changed = scenario() === 'payee_changed';
  setText('submitted-payee', changed ? (example?.mutation_pay_to ?? state.config?.mutation_pay_to ?? '0x2222222222222222222222222222222222222222') : requirement?.payTo);
  byID('comparison').classList.toggle('is-changed', changed);
  byID('change-marker').hidden = !changed;
  setText('scenario-note', changed ? '受控測試：修改範例的收款地址，不代表發現真實攻擊。' : '以同一份付款要求進行比對，不發送付款。');
}
function updateModeNotice() {
  const live = mode() === 'live';
  setText('mode-tag', live ? 'LIVE REQUEST' : 'REHEARSAL');
  setText('mode-description', live ? (liveReady() ? '使用 IFF 公開觀測與真實 0G 推理。驗證狀態依此次回應逐項顯示。' : '真實模式尚未就緒。請在頁尾開啟金鑰設定，並確認 IFF 範例已備妥。') : '演練資料 · 收據由本機演練金鑰簽署，解說使用固定文字；未呼叫 0G。');
  byID('live-password-row').hidden = !(live && state.config?.live_password_required);
}
function clearResult() {
  verificationRevision += 1;
  state.original = null; state.bundle = null; state.result = null; state.tampered = false; state.expectedNonce = null;
  state.raw = null; state.originalRaw = null;
  byID('explanation-empty').hidden = false; byID('explanation-result').hidden = true;
  setText('explanation-source','尚未產生'); setText('proof-status','等待查核結果');
  byID('proof-status').classList.remove('is-fail'); byID('checks').replaceChildren();
  setText('tamper-status',''); setText('bundle-json','尚未產生證據包。'); setText('run-status','');
  enabledState();
}

async function fetchJSON(path, options = {}) {
  const response = await fetch(path, { credentials:'same-origin',redirect:'error',cache:'no-store',...options });
  const text = await response.text();
  if (text.length > 1024 * 1024) throw new Error('回應超出可接受大小。');
  let data; try { data = parseJSONStrict(text).value; } catch { throw new Error('服務回傳無法解析的內容，請重新啟動 Labs 服務。'); }
  if (!response.ok) {
    const messages = {
      compute_not_configured:'0G 金鑰尚未設定。請從頁尾開啟金鑰設定分頁。',
      live_not_configured:'真實查核尚未準備好。請設定 0G 金鑰及已觀測的 endpoint 範例。',
      rate_limited:'查核次數已達暫時限制，請稍候再試。',
      live_budget_exhausted:'本次啟動的真實查核次數已用完，請確認花費後調整服務設定。',
      iff_unavailable:'暫時無法取得 IFF 證據，請稍後重試。',
      compute_unavailable:'0G 暫時無法提供推理，請稍後重試。',
    };
    throw new Error(messages[data.code ?? data.error] ?? data.message ?? `服務暫時無法完成查核（${response.status}）。`);
  }
  return data;
}

function verificationOptions(bundle) {
  const demo = bundle.mode === 'rehearsal';
  return {
    expectedIssuer: demo ? 'https://witness.example' : (state.config?.iff_origin ?? 'https://ifandonlyif.io'),
    trustedKeyIDs: demo ? (state.config?.demo_key_ids ?? []) : (state.config?.trusted_key_ids ?? []),
    expectedNonce: state.expectedNonce ?? undefined,
    trustedComputeSigners: state.config?.trusted_compute_signers ?? {},
  };
}
function verificationPolicyKey(config) {
  // Include only caller policy, never a key directory from an uploaded bundle.
  // Receipt bytes and the action nonce remain unchanged during settings edits.
  return JSON.stringify([
    config?.iff_origin ?? 'https://ifandonlyif.io',
    config?.trusted_key_ids ?? [], config?.demo_key_ids ?? [],
    config?.trusted_compute_signers ?? {}, config?.agentic_trust ?? {},
  ]);
}
function markTrustRefreshPending() {
  if (state.result) {
    const identityChecks = new Set(['iff_issuer', 'compute_identity', 'agentic-signature']);
    state.result = { ...state.result, checks: state.result.checks.map(check => identityChecks.has(check.id)
      ? { ...check, status: 'unverified', detail: '信任設定已更新，正在依新設定重新核對現有證據。' } : check) };
    renderChecks();
  }
  setText('proof-status', '信任設定已更新，正在重新核對…');
}
async function verifyCurrent() {
  const bundle = state.bundle;
  if (!bundle) return false;
  const revision = ++verificationRevision;
  const raw = state.raw;
  const policy = verificationPolicyKey(state.config);
  const agenticTrust = state.config?.agentic_trust ?? {};
  const result = await verifyBundle(raw ?? bundle, verificationOptions(bundle));
  result.checks = result.checks.filter(check=>check.id!=='agent_identity');
  result.checks.push(...verifyBundleAgent(raw ?? bundle, agenticTrust).checks);
  // WebCrypto is asynchronous: an old pin/bundle check must never overwrite a
  // newer check, a cleared result, or a result verified after returning settings.
  if (revision !== verificationRevision || state.bundle !== bundle || state.raw !== raw || verificationPolicyKey(state.config) !== policy) return false;
  state.result = result;
  renderResult();
  return true;
}
function renderChecks() {
  const list = byID('checks'); list.replaceChildren();
  for (const check of state.result.checks) {
    const li = document.createElement('li');
    const status = ['pass','fail','warning','unverified'].includes(check.status) ? check.status : 'unverified';
    li.className = `check ${status}`;
    const symbol = document.createElement('span'); symbol.className = 'check-symbol'; symbol.setAttribute('aria-hidden','true');
    symbol.textContent = ({pass:'✓',fail:'×',warning:'!',unverified:'○'})[status];
    const content = document.createElement('details'); const summary = document.createElement('summary'); const title = document.createElement('span'); const badge = document.createElement('span'); const detail = document.createElement('p');
    title.className = 'check-title'; title.textContent = check.label;
    badge.className = 'check-badge'; badge.textContent = ({pass:'符合',fail:'不符',warning:'注意',unverified:'未驗證'})[status];
    detail.textContent = check.detail; content.open = status === 'fail';
    summary.append(title,badge); content.append(summary,detail); li.append(symbol,content); list.append(li);
  }
  const failed = state.result.checks.some(check => check.status === 'fail');
  setText('proof-status',failed ? '內容或簽章核對不符' : '已完成本機核對 · 來源分項顯示');
  byID('proof-status').classList.toggle('is-fail', failed);
}
function renderResult() {
  const bundle = state.bundle;
  renderChecks();
  byID('explanation-empty').hidden = true; byID('explanation-result').hidden = false;
  const response = typeof bundle.iff?.response === 'string' ? parseJSONStrict(bundle.iff.response).value : {};
  const signed = state.result.iffResult?.subject ?? state.result.iffResult ?? {};
  const verdict = signed.verdict ?? response.verdict ?? 'unobserved';
  setText('verdict', verdict); byID('verdict').className = `verdict ${['consistent','diverged','stale','unobserved'].includes(verdict) ? verdict : ''}`;
  setText('verdict-detail',({consistent:'與觀測基準一致',diverged:'與觀測基準有差異',stale:'觀測資料已過期',unobserved:'尚無足夠觀測'})[verdict] ?? '查看簽署內容');
  const isDemo = bundle.mode === 'rehearsal';
  setText('explanation-source',bundle.explanation?.source === '0g' ? '0G 回應 · 依下方驗證' : '演練固定文字');
  setText('explanation-text',bundle.explanation?.text ?? '此證據包未附解說。');
  setText('explanation-boundary',state.result.checks.some(check=>check.status==='fail') ? '此副本未通過所有內容核對。以上文字不可當作已驗證結果；請查看右側失敗項目。' : isDemo ? '演練使用本機簽章，不代表正式 IFF 觀測或 0G 推理。' : '這段解說不改寫 IFF 判定。推理簽章、身份與內容綁定須分別核對。');
  setText('observed-at',formatTime(response.observed?.observed_at ?? response.provenance?.observed_at));
  setText('received-fingerprint',response.received?.set_fingerprint ?? '未附');
  setText('model-name',bundle.compute?.model ?? '未呼叫');
  setText('compute-status',({not_requested:'未呼叫 0G',router_verified:'Router 回報通過；獨立核對見右側',independently_verified:'服務回報已獨立驗證；本機核對見右側',verification_failed:'驗證未通過',unavailable:'尚未取得可核對證明'})[bundle.compute?.status] ?? '未附驗證狀態');
  const computeInfo = bundle.compute ?? {}; const proof = computeInfo.proof ?? null;
  setRow('compute-reason-row','compute-reason', computeInfo.error || proof?.reason || '');
  setRow('router-tee-row','router-tee', computeInfo.router_tee_verified === true ? '是（Router 自行回報，非簽章證明）' : computeInfo.router_tee_verified === false ? '否' : '');
  setRow('proof-signer-row','proof-signer', proof?.signer_address ?? '');
  setRow('proof-provider-row','proof-provider', proof ? `${proof.provider_url ?? computeInfo.provider ?? '—'}${proof.provider_type ? `（${proof.provider_type}）` : ''}` : '');
  setRow('proof-chain-row','proof-chain', proof ? `${proof.chain_id ?? '—'} / ${proof.registry ?? '—'}` : '');
  setRow('proof-block-row','proof-block', proof?.block_number ?? '');
  setText('bundle-json',state.raw ?? JSON.stringify(bundle,null,2)); enabledState();
}

async function runCheck() {
  clearError(); clearResult(); updateModeNotice(); updateComparison(); state.busy = true; enabledState(); document.body.classList.add('is-running');
  setText('run-label','查核中…'); setText('run-status',mode() === 'live' ? '正在取得 IFF 證據並呼叫 0G；完成後會在本機核對收據。' : '建立演練收據，並在瀏覽器核對簽章與內容…');
  setText('tamper-status','');
  const nonce = `witness_${crypto.randomUUID()}`;
  try {
    const bundle = await fetchJSON('/api/check',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mode:mode(),scenario:scenario(),nonce,password:byID('live-password').value}),signal:AbortSignal.timeout(110000)});
    state.expectedNonce = nonce; state.original = structuredClone(bundle); state.bundle = bundle;
    await verifyCurrent();
    setText('run-status',bundle.mode === 'rehearsal' ? '演練完成。可以下載證據包，或試著修改判定。' : '查核完成。請分別查看 IFF 與 0G 的驗證狀態。');
  } catch(error) {
    setText('run-status',''); showError(error.name === 'TimeoutError' ? '查核等候逾時。請確認服務狀態後重試。' : error.message);
  } finally { state.busy = false; document.body.classList.remove('is-running'); setText('run-label','執行查核'); enabledState(); void refreshConfig(); }
}

async function tamper() {
  clearError();
  try {
    state.bundle = structuredClone(state.original);
    state.raw = null;
    const raw = state.bundle.iff.response;
    // Change only the outer field, preserving all other raw bytes and the receipt.
    const old = parseJSONStrict(raw).value.verdict;
    const replacement = old === 'consistent' ? 'diverged' : 'consistent';
    const pattern = /("verdict"\s*:\s*")(consistent|diverged|unobserved|stale)(")/;
    if (!pattern.test(raw)) throw new Error('此證據包未包含可供測試的判定欄位。');
    state.bundle.iff.response = raw.replace(pattern,(_,before,_value,after)=>`${before}${replacement}${after}`);
    state.tampered = true;
    await verifyCurrent();
    setText('tamper-status',state.result.checks.some(check=>check.status==='fail') ? '已發現替換：原簽章仍在，但外層結果與簽署內容不一致。' : '尚未偵測到差異，請查看各項檢查結果。');
  } catch(error) { showError(error.message); }
  enabledState();
}
async function restore() {
  clearError(); state.bundle = structuredClone(state.original); state.raw = state.originalRaw; state.tampered = false;
  try { await verifyCurrent(); setText('tamper-status','已還原原始證據，並重新核對。'); } catch(error) { showError(error.message); }
  enabledState();
}
function download() {
  const blob = new Blob([state.raw ?? JSON.stringify(state.bundle,null,2)],{type:'application/json'});
  const url = URL.createObjectURL(blob); const link = document.createElement('a'); link.href=url;
  link.download=`iff-witness-${state.bundle.mode === 'live' ? 'live' : 'rehearsal'}${state.tampered?'-tampered':''}.json`;
  link.click(); setTimeout(()=>URL.revokeObjectURL(url),1000);
}
async function importBundle(event) {
  const file = event.target.files?.[0]; if(!file)return; clearError();
  try {
    if(file.size>1024*1024)throw new Error('證據包不能超過 1 MiB。');
    const bytes = await file.arrayBuffer(); const text = new TextDecoder('utf-8',{fatal:true}).decode(bytes);
    const bundle = parseJSONStrict(text).value;
    if(bundle?.schema!=='iff-witness/bundle/v1' || typeof bundle.iff?.response!=='string' || !bundle.request || !bundle.compute || !bundle.explanation)throw new Error('請選擇完整的 IFF Witness v1 證據包。');
    parseJSONStrict(bundle.iff.response);
    state.expectedNonce=null; state.original=structuredClone(bundle); state.bundle=bundle; state.tampered=false;
    state.raw=text; state.originalRaw=text;
    await verifyCurrent();
    setText('run-status','已匯入並在本機核對。匯入內容未傳送到 IFF 或 0G。'); setText('tamper-status','');
    setText('mode-description',`正在檢視匯入檔案（檔案標示：${bundle.mode==='rehearsal'?'演練':'真實請求'}）。身份可信度以分項核對結果為準。`);
    setText('mode-tag','IMPORTED');
    setText('endpoint',bundle.request.url ?? '匯入檔案未附 endpoint');
    setText('baseline-heading','匯入檔案未附完整基準');
    for (const field of ['network','amount','payee']) setText(`baseline-${field}`,'請查看簽署證據');
    const importedPayment=bundle.request.payment_required?.accepts?.[0];
    setText('submitted-network',importedPayment?.network); setText('submitted-amount',importedPayment?.amount); setText('submitted-payee',importedPayment?.payTo);
    byID('comparison').classList.remove('is-changed'); byID('change-marker').hidden=true;
    setText('scenario-note','正在檢視匯入內容；再次執行查核將使用目前選擇的範例。');
  }catch(error){showError(error.message);}finally{event.target.value='';enabledState();}
}
byID('run').addEventListener('click',runCheck); byID('tamper').addEventListener('click',tamper); byID('restore').addEventListener('click',restore);
byID('download').addEventListener('click',download); byID('import-button').addEventListener('click',()=>byID('import-file').click());
byID('import-file').addEventListener('change',importBundle);
byID('mode').addEventListener('change',()=>{clearError();clearResult();updateModeNotice();updateComparison();});
document.querySelectorAll('input[name="scenario"]').forEach(input=>input.addEventListener('change',()=>{clearError();clearResult();updateModeNotice();updateComparison();}));

let refreshingConfig = false;
let refreshConfigAgain = false;
async function refreshConfig(initial = false) {
  if (refreshingConfig) { refreshConfigAgain = true; return; }
  if (state.busy) return;
  refreshingConfig = true;
  try {
    const config = await fetchJSON('/api/config',{signal:AbortSignal.timeout(10000)});
    if (state.busy) return;
    const policyChanged = verificationPolicyKey(state.config) !== verificationPolicyKey(config);
    state.config = config;
    const option = byID('mode').querySelector('option[value="live"]');
    option.disabled = !liveReady(); option.textContent = liveReady() ? '真實 IFF + 0G' : '真實 IFF + 0G（待設定）';
    // Preserve an already displayed receipt when returning from settings.
    if (!state.bundle) { updateModeNotice(); updateComparison(); }
    else if (policyChanged) {
      markTrustRefreshPending();
      try { await verifyCurrent(); }
      catch { showError('信任設定已更新，但目前無法完成本機重新核對。請重新匯入原證據包。'); }
    }
    enabledState();
  } catch(error) {
    if (initial) { showError(error.message); setText('mode-description','設定讀取失敗。請確認 Labs 服務已啟動，然後重新整理。'); }
  } finally {
    refreshingConfig=false;
    // A save/clear notification can arrive while an older config GET is still
    // pending. Fetch once more so the older response cannot hide the new pins.
    if (refreshConfigAgain) { refreshConfigAgain=false; void refreshConfig(); }
  }
}
window.addEventListener('focus',()=>void refreshConfig());
document.addEventListener('visibilitychange',()=>{if(document.visibilityState==='visible')void refreshConfig();});
const settingsUpdates = typeof BroadcastChannel === 'function' ? new BroadcastChannel('iff-witness-settings') : null;
if (settingsUpdates) settingsUpdates.onmessage=event=>{if(event.data==='changed')void refreshConfig();};
await refreshConfig(true);
