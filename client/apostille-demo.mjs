import exampleText from '../examples/agentic-demo-bundle.json';
import { signExample, verifyExample, addSpace, createReceiverExample, MAX_ARTIFACT_BYTES, MAX_BUNDLE_BYTES } from './apostille-example.mjs';

const byID = id => document.getElementById(id);
const text = (id, value) => { const node = byID(id); if (node.textContent !== value) node.textContent = value; };
const sample = new TextEncoder().encode(exampleText);
const fresh = () => ({ current: null, result: null, stage: 0, downloads: new Set(), error: null });
const sessions = { demo: fresh(), import: fresh() };
let mode = 'demo';
let busy = false;
let kitBusy = false;
let receiverKit = null;
let kitError = '';
const kitDownloads = new Set();
const bytesLabel = size => `${Number(size).toLocaleString()} bytes`;
const state = () => sessions[mode];

function renderGuide() {
  const { stage, current } = sessions.demo;
  const source = byID('ap-source').files?.[0];
  const descriptions = [
    ['第 1 步 / 簽署', '先替一份檔案加上來源簽章',
      source ? '使用你選的檔案建立臨時簽章，再立即核對。檔案只在這個分頁處理，不會上傳。' : '我們準備了一份 Witness 演練證據包。按下按鈕，就會用臨時金鑰簽署，再立即核對。',
      source ? '簽署選取的檔案 →' : '簽署範例檔案 →', '你會看到：簽章有效，而且原件相符。'],
    ['第 2 步 / 改動', '只加一個空白，再看查驗結果',
      '接下來會在原件副本的結尾加入一個空白。簽章檔保持同一份，再重新比對。',
      '加一個空白並查驗 →', '預期：簽章仍有效，原件比對不符。抓到差異就代表這一步成功。'],
    ['第 3 步 / 還原', '還原原件，確認結果能恢復',
      '剛才的不符是刻意安排的測試。現在移除加上的空白，用同一份簽章重新查驗。',
      '還原原件並查驗 →', '預期：檔案回到簽署時的樣子，原件比對重新相符。'],
    ['三步完成 / 可以交付', '原件已還原，兩項查驗都通過',
      '你已走過「原件相符 → 改動被發現 → 還原後相符」。接著可下載兩份檔案，試試接收者的查驗流程。',
      '查看下載與交接方式 ↓', '記住：簽章有效和原件相符是兩項檢查；它們不會證明內容屬實。'],
  ];
  const copy = descriptions[stage];
  ['ap-stage-label', 'ap-step-title', 'ap-step-copy', 'ap-next', 'ap-expect'].forEach((id, i) => text(id, copy[i]));
  if (busy && mode === 'demo') text('ap-next', ['正在簽署與查驗…', '正在加入空白並比對…', '正在還原與查驗…'][stage] || '正在處理…');
  text('ap-progress', `已完成 ${stage} / 3`);
  byID('ap-reset').hidden = !stage;
  byID('ap-source-options').hidden = stage !== 0;
  byID('ap-use-sample').hidden = !source;
  document.querySelectorAll('#ap-steps li').forEach((node, i) => {
    node.classList.toggle('is-done', i < stage);
    if (i === stage) node.setAttribute('aria-current', 'step'); else node.removeAttribute('aria-current');
    node.querySelector('.ap-step-number').textContent = i < stage ? '✓' : i + 1;
    text(`ap-step-state-${i}`, i < stage ? '已完成' : i === stage ? '目前步驟' : '待完成');
  });
  byID('ap-feedback').hidden = !stage;
  if (stage && current) {
    const originalSize = bytesLabel(current.original.length);
    const feedback = [null,
      ['第 1 步完成：簽章有效，原件相符', `已替 ${originalSize} 的檔案產生來源簽章。原件沒有被修改，簽章另存在一份檔案裡。`],
      ['改動已被發現，這一步成功了', `檔案從 ${originalSize} 變成 ${bytesLabel(current.bytes.length)}，多了一個空白。簽章檔沒變，所以簽章仍有效；原件比對則正確顯示不符。`],
      ['三種情況都驗過了', `原件已回到 ${originalSize}，簽章有效、檔案相符。接收者只需這兩份檔案，不需要簽署時的私鑰。`],
    ][stage];
    text('ap-feedback-title', feedback[0]); text('ap-feedback-copy', feedback[1]);
  }
}

function renderResults() {
  const { current, result, stage, error, downloads } = state();
  const source = byID('ap-source').files?.[0];
  text('ap-record-name', current?.name || (mode === 'demo' ? source?.name || 'Witness 演練證據包' : '等待選擇對應原件'));
  text('ap-file-description', mode === 'demo'
    ? source ? '你選取的原件，只在此分頁簽署與查驗。' : '公開演練資料，不會呼叫 IFF 或 0G 服務。'
    : '原件與簽章檔需成對；檔名相同不代表內容相同。');
  text('ap-signed-size', result ? bytesLabel(result.artifact_size) : '尚未查驗');
  text('ap-size', current ? bytesLabel(current.bytes.length) : mode === 'demo' ? bytesLabel(source?.size ?? sample.length) : '尚未選擇');
  byID('ap-change-badge').hidden = !(mode === 'demo' && stage === 2 && result);
  byID('ap-byte-view').hidden = !(current && mode === 'demo' && result);
  byID('ap-added-space').hidden = stage !== 2;
  if (current && mode === 'demo') {
    // Display the actual last bytes as visible characters; never insert file HTML.
    const tail = Array.from(current.original.slice(-16), byte => byte === 10 ? '↵' : byte === 13 ? '␍' : byte === 32 ? '␠' : byte >= 33 && byte <= 126 ? String.fromCharCode(byte) : '·').join('');
    text('ap-tail', '…' + tail);
  }
  const hasResult = Boolean(result);
  const matches = hasResult && result.original_matches;
  byID('ap-signature-check').classList.toggle('is-valid', hasResult);
  byID('ap-signature-check').classList.toggle('is-invalid', Boolean(error));
  byID('ap-match-check').classList.toggle('is-valid', matches);
  byID('ap-match-check').classList.toggle('is-invalid', hasResult && !matches);
  text('ap-signature-icon', hasResult ? '✓' : error ? '!' : '—');
  text('ap-match-icon', hasResult ? matches ? '✓' : '≠' : '—');
  text('ap-signature', hasResult ? '有效。簽章與金鑰綁定都通過核對。' : error ? '未通過查驗，請依錯誤提示重新操作。' : busy ? '正在核對簽章與金鑰綁定…' : '簽署或匯入後，會核對簽章與金鑰綁定。');
  text('ap-match', hasResult ? matches ? '相符。檔案的雜湊與大小都與簽署時一致。' : '不符。目前檔案與簽署時的內容不同。' : error ? '尚未完成比對。' : busy ? '等待簽章核對，再比對原件…' : '簽署或匯入後，會比對檔案的雜湊與大小。');
  byID('ap-result').dataset.status = hasResult ? matches ? 'valid' : 'mismatch' : 'waiting';
  let message = mode === 'demo' ? '先按簽署按鈕，開始第一步。' : '先選擇簽章檔與原件，才可開始查驗。';
  if (result) {
    if (mode === 'demo') message = stage === 1 ? '第 1 步完成。現在兩項都通過，接著測試加一個空白會怎樣。'
      : stage === 2 ? '第 2 步完成：成功抓到差異。簽章記錄沒有被改動，但你手上的原件已不同。下一步還原它。'
      : '測試完成。還原後，原件再次相符。簽章可以核對檔案綁定，但內容是否屬實仍需其他證據。';
    else message = matches ? '查驗完成：簽章有效，原件相符。你已核對檔案綁定；簽署者身分與內容真實性仍未建立。'
      : '查驗完成：原件不符。請向提供者索取與這份簽章對應的原件；重新排版 JSON 或多加空白也會造成差異。';
  }
  if (busy) message = mode === 'demo' ? '正在本機處理，完成後會更新步驟與兩項查驗結果…' : '正在本機核對簽章與原件，檔案不會上傳…';
  if (error) message = '這次查驗未完成。請查看上方提示，修正後再試；不會保留先前的通過結果。';
  text('ap-message', message);
  byID('ap-error').hidden = !error;
  if (error) { text('ap-error-title', error.title); text('ap-error-detail', error.detail); }
  byID('ap-technical').hidden = !hasResult;
  if (result) {
    text('ap-digest', result.artifact_sha256); text('ap-key', result.source_key_id);
    text('ap-scope', `${result.certificate_scope} · ${result.certificate_scope === 'producer_only' ? '只有來源簽章，沒有 issuer 證書' : '包含 issuer 的來源簽章檢查證書'}`);
    text('ap-trust', `${result.issuer_trust} · 未設定獨立的 issuer 信任政策`);
    text('ap-agent', result.agent_binding); text('ap-truth', `${result.content_truth} · 未證明內容屬實`);
    text('ap-freshness', `${result.freshness} · 目前撤銷狀態仍未知`);
  }
  byID('ap-handoff').hidden = !(mode === 'demo' && stage === 3 && matches);
  text('ap-download-note', downloads.size === 2 ? '已送出兩份檔案的下載，請到瀏覽器下載資料夾確認。接著可切換到接收者查驗。'
    : downloads.size === 1 ? `已送出${downloads.has('original') ? '原件' : '簽章檔'}的下載；還需要下載${downloads.has('original') ? '簽章檔' : '原件'}。`
    : '需要兩份檔案；簽章檔不包含原件或私鑰。');
}


function renderKit() {
  byID('ap-kit-generate').className = receiverKit ? 'text-button' : 'button secondary';
  text('ap-kit-generate', kitBusy ? '正在產生與核對配對檔案…' : receiverKit ? '重新產生一組' : '產生一組測試檔案');
  byID('ap-kit-ready').hidden = !receiverKit;
  byID('ap-kit-status').classList.toggle('is-error', Boolean(kitError));
  const downloaded = ['bundle', 'original'].filter(kind => kitDownloads.has(kind));
  text('ap-kit-status', kitBusy ? '正在本機簽署，並先確認原件會通過、改動版會不符…'
    : kitError ? kitError
    : !receiverKit ? '產生後，先下載簽章檔和原件，再用下方兩個欄位選取它們。'
    : downloaded.length === 2 ? '兩份必要檔案已送出下載。請確認下載資料夾，再到下方選取這一組檔案。'
    : downloaded.length === 1 ? `已送出${downloaded[0] === 'bundle' ? '簽章檔' : '原件'}的下載；還需要下載${downloaded[0] === 'bundle' ? '原件' : '簽章檔'}。`
    : '測試檔案已準備好！配對自我檢查通過，請先下載下方兩份檔案。');
  if (receiverKit) {
    text('ap-kit-id', `這一組的編號：${receiverKit.id} · 請使用同一編號的檔案`);
    for (const kind of ['bundle', 'original', 'changed']) text(`ap-kit-${kind}-name`, receiverKit.files[kind].name);
  }
}

function render() {
  byID('ap-guide').hidden = mode !== 'demo';
  byID('ap-steps').hidden = mode !== 'demo';
  byID('ap-receiver').hidden = mode !== 'import';
  byID('ap-mode-demo').setAttribute('aria-pressed', String(mode === 'demo'));
  byID('ap-mode-import').setAttribute('aria-pressed', String(mode === 'import'));
  byID('ap-lab').setAttribute('aria-busy', String(busy || kitBusy));
  document.querySelectorAll('button, input').forEach(node => { node.disabled = busy || kitBusy; });
  const selected = Number(Boolean(byID('ap-bundle-file').files?.[0])) + Number(Boolean(byID('ap-original-file').files?.[0]));
  byID('ap-import').disabled = busy || kitBusy || selected !== 2;
  text('ap-import', busy && mode === 'import' ? '正在查驗…' : '查驗這兩份檔案 →');
  text('ap-files-ready', busy && mode === 'import' ? '正在核對，請稍候…'
    : sessions.import.error ? '查驗未完成，請依下方提示修正後再試。'
    : sessions.import.result ? sessions.import.result.original_matches ? '查驗完成：簽章有效、原件相符。詳細結果在下方。' : '查驗完成：原件不符。請查看下方的原因與處理方式。'
    : selected === 2 ? '兩份已備妥，可開始查驗（2 / 2）。' : `請${selected ? '再' : '先'}選擇${selected ? '另一份' : '兩份'}檔案（${selected} / 2）。`);
  renderGuide(); renderResults(); renderKit();
}

async function readFile(file, limit, label) {
  if (!file) throw new Error(`請選擇${label}。`);
  if (file.size > limit) throw new Error(`${label}超過 ${limit.toLocaleString()} bytes 上限。`);
  const bytes = new Uint8Array(await file.arrayBuffer());
  if (bytes.length > limit) throw new Error(`${label}超過大小上限。`);
  return bytes;
}

async function run(action, focusID) {
  if (busy || kitBusy) return;
  const session = state();
  busy = true; session.error = null; session.result = null; render();
  try { await action(session); }
  catch (error) {
    session.current = null; session.result = null; session.stage = 0;
    session.error = {
      title: /^(請選擇|測試原件超過|原件超過|Apostille 簽章檔超過)/.test(error.message) ? error.message
        : error.name === 'NotSupportedError' || !globalThis.crypto?.subtle ? '此瀏覽器不支援需要的簽章功能，請使用新版瀏覽器或下方的命令列指引。'
        : mode === 'import' ? '無法完成查驗。請確認簽章檔格式正確，並重新選擇對應的原件。'
        : '這一步尚未完成。請確認檔案小於 1 MiB，或改用內建範例再試一次。',
      detail: error.message,
    };
  } finally {
    busy = false; render();
    // Keep keyboard users on the next operation instead of losing focus when disabled.
    byID(focusID).focus({ preventScroll: true });
  }
}

function switchMode(next) {
  if (busy || kitBusy) return;
  mode = next; render();
}
function resetDemo(useSample = false) {
  if (busy || kitBusy) return;
  sessions.demo = fresh();
  if (useSample) { byID('ap-source').value = ''; byID('ap-source-options').open = false; }
  render();
}
function revealHandoff() {
  byID('ap-handoff-title').focus({ preventScroll: true });
  byID('ap-handoff').scrollIntoView({ block: 'nearest', behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth' });
}
function download(bytes, filename) {
  const url = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }));
  const link = document.createElement('a'); link.href = url; link.download = filename;
  link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
}
byID('ap-kit-generate').addEventListener('click', async () => {
  if (busy || kitBusy) return;
  kitBusy = true; kitError = ''; render();
  try {
    receiverKit = await createReceiverExample(sample);
    kitDownloads.clear();
    // New material starts a fresh recipient check; never show a previous pass
    // beside a newly generated pair or silently keep previously selected files.
    byID('ap-bundle-file').value = ''; byID('ap-original-file').value = '';
    sessions.import = fresh();
  } catch (error) {
    kitError = '未能產生測試檔案。請使用支援 Ed25519 的新版瀏覽器，或依頁面下方的命令列指引產生。';
  } finally {
    kitBusy = false; render(); byID('ap-kit-generate').focus({ preventScroll: true });
  }
});
for (const kind of ['bundle', 'original', 'changed']) {
  byID(`ap-kit-download-${kind}`).addEventListener('click', () => {
    if (busy || kitBusy || !receiverKit) return;
    const file = receiverKit.files[kind]; download(file.bytes, file.name);
    kitDownloads.add(kind); render();
  });
}
byID('ap-kit-choose').addEventListener('click', () => {
  byID('ap-bundle-file').focus({ preventScroll: true });
  byID('ap-receiver-files').scrollIntoView({ block: 'start', behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth' });
});
byID('ap-next').addEventListener('click', () => {
  if (busy || kitBusy) return;
  if (sessions.demo.stage === 3) { revealHandoff(); return; }
  run(async session => {
    const nextStage = session.stage + 1;
    let candidate;
    if (nextStage === 1) {
      const source = byID('ap-source').files?.[0];
      const original = source ? await readFile(source, MAX_ARTIFACT_BYTES - 1, '測試原件') : sample.slice();
      candidate = { original, bytes: original, bundle: await signExample(original), name: source?.name || 'Witness 演練證據包' };
    } else {
      candidate = { ...session.current, bytes: nextStage === 2 ? addSpace(session.current.original) : session.current.original };
    }
    const result = await verifyExample(candidate.bundle, candidate.bytes);
    if (result.original_matches !== (nextStage !== 2)) throw new Error('查驗結果不符合這一步的預期，請重新開始測試。');
    session.current = candidate; session.result = result; session.stage = nextStage;
  }, 'ap-next');
});
byID('ap-import').addEventListener('click', () => run(async session => {
  const originalFile = byID('ap-original-file').files?.[0];
  const bundle = new TextDecoder('utf-8', { fatal: true }).decode(await readFile(byID('ap-bundle-file').files?.[0], MAX_BUNDLE_BYTES, 'Apostille 簽章檔'));
  const original = await readFile(originalFile, MAX_ARTIFACT_BYTES, '原件');
  const result = await verifyExample(bundle, original);
  session.current = { original, bytes: original, bundle, name: originalFile.name }; session.result = result;
}, 'ap-import'));
byID('ap-reset').addEventListener('click', () => { resetDemo(); byID('ap-next').focus(); });
byID('ap-use-sample').addEventListener('click', () => { resetDemo(true); byID('ap-next').focus(); });
byID('ap-source').addEventListener('change', () => resetDemo());
for (const id of ['ap-bundle-file', 'ap-original-file']) byID(id).addEventListener('change', () => { sessions.import = fresh(); render(); });
byID('ap-mode-demo').addEventListener('click', () => switchMode('demo'));
byID('ap-mode-import').addEventListener('click', () => switchMode('import'));
byID('ap-open-receiver').addEventListener('click', () => {
  switchMode('import'); byID('ap-mode-import').focus(); byID('ap-mode-import').scrollIntoView({ block: 'start' });
});
for (const [id, kind, filename] of [['ap-download-original', 'original', 'witness-original.json'], ['ap-download-bundle', 'bundle', 'apostille-bundle.json']]) {
  byID(id).addEventListener('click', () => {
    const session = sessions.demo;
    if (busy || session.stage !== 3 || !session.result?.original_matches) return;
    download(kind === 'original' ? session.current.bytes : session.current.bundle, filename);
    session.downloads.add(kind); render();
  });
}
render();
