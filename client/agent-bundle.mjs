import { verifyAgentProof } from './agentic.mjs';
import { parseJSONStrict } from '../web/service-receipt.mjs';

const MAX_BYTES = 2 * 1024 * 1024;
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

function check(id, status, label, detail) {
  return { id: 'agentic-bundle-' + id, status, label, detail };
}

// Compare strict syntax trees, not decoded Number values: the original number
// tokens 9007199254740992 and 9007199254740993 must remain distinct.
function canonical(node, omitAgent = false) {
  if (node.kind === 'object') {
    const entries = node.entries.filter(({ key }) => !(omitAgent && key === 'agent'));
    entries.sort((left, right) => left.key < right.key ? -1 : left.key > right.key ? 1 : 0);
    return '{' + entries.map(({ key, node: child }) => JSON.stringify(key) + ':' + canonical(child)).join(',') + '}';
  }
  if (node.kind === 'array') return '[' + node.items.map((item) => canonical(item)).join(',') + ']';
  return node.canonical;
}

function objectText(value) {
  const ancestors = new Set();
  function inspect(item, depth = 0) {
    if (depth > 128) throw new Error('Bundle is too deeply nested.');
    if (typeof item === 'number' && (!Number.isFinite(item) || !Number.isSafeInteger(item))) {
      throw new Error('非整數或不安全的數值需使用原始 JSON 文字；物件輸入無法保留其精確數字表示。');
    }
    if (item === null || typeof item !== 'object') return;
    if (ancestors.has(item)) throw new Error('證據包內含循環參照。');
    ancestors.add(item);
    for (const child of Object.values(item)) inspect(child, depth + 1);
    ancestors.delete(item);
  }
  inspect(value);
  return JSON.stringify(value);
}

function document(text) {
  if (typeof text !== 'string' || encoder.encode(text).length > MAX_BYTES) throw new Error('需要範圍受限的原始 JSON 文字。');
  const parsed = parseJSONStrict(text);
  if (parsed.node.kind !== 'object') throw new Error('需要 JSON 物件。');
  return parsed;
}

function transcriptText(transcript, name) {
  const raw = transcript?.[name];
  const encoded = transcript?.[name + 'Base64'];
  if (raw !== undefined && encoded !== undefined) throw new Error('transcript 位元組定義模糊（同時提供原始與 base64 兩種）。');
  if (typeof raw === 'string') return raw;
  if (raw instanceof Uint8Array) return decoder.decode(raw);
  if (typeof encoded !== 'string' || encoded.length > MAX_BYTES * 2 || !/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)) throw new Error('缺少原始 transcript 位元組。');
  const binary = atob(encoded);
  if (binary.length > MAX_BYTES) throw new Error('transcript 超過大小限制。');
  return decoder.decode(Uint8Array.from(binary, (character) => character.charCodeAt(0)));
}

/**
 * Connect an Agentic ID signed HTTP transcript to this displayed Witness
 * bundle. Identity/domain trust comes only from caller-supplied options.
 * Pass original JSON text when numbers require exact lexical preservation.
 */
export function verifyBundleAgent(input, options = {}) {
  let bundleDocument;
  try {
    bundleDocument = document(typeof input === 'string' ? input : objectText(input));
  } catch (error) {
    return { checks: [check('format', 'fail', 'Agent 證據包格式', error.message)] };
  }
  const bundle = bundleDocument.value;
  if (bundle.agent === null || bundle.agent === undefined) {
    return { checks: [{ id: 'agent_identity', status: 'unverified', label: 'Agent 身份', detail: '未附 Agentic ID 服務證明。' }] };
  }

  const result = verifyAgentProof(bundle.agent, options);
  const checks = [...result.checks];
  const transcript = bundle.agent?.transcript;
  const routeMatches = transcript?.method === 'POST' && transcript?.uri === '/api/check' && transcript?.status === 200;
  checks.push(check('route', routeMatches ? 'pass' : 'fail', 'Agent 服務路徑', routeMatches
    ? '簽署的 transcript 描述為 POST /api/check、HTTP 200。'
    : '簽署的 transcript 必須描述 POST /api/check、HTTP 200。'));

  try {
    const request = document(transcriptText(transcript, 'rawRequest'));
    const expected = { mode: bundle.mode, scenario: bundle.scenario, nonce: bundle.request?.receipt?.nonce };
    if (Object.values(expected).some((value) => typeof value !== 'string' || value === '')) throw new Error('證據包未明確標示這次查核的 mode、scenario 與 nonce。');
    const matches = canonical(request.node) === canonical(document(JSON.stringify(expected)).node);
    checks.push(check('request', matches ? 'pass' : 'fail', 'Agent 請求與查核內容', matches
      ? '簽署的請求 JSON 與此證據包的 mode、scenario 及收據 nonce 相符。'
      : '簽署的請求與此證據包的 mode、scenario 或收據 nonce 不符。'));
  } catch (error) {
    checks.push(check('request', 'fail', 'Agent 請求與查核內容', error.message));
  }

  try {
    const response = document(transcriptText(transcript, 'rawResponse'));
    if (response.value.agent !== undefined && response.value.agent !== null) throw new Error('擷取的回應必須包含 agent:null 或省略 agent 欄位；不支援巢狀證明替換。');
    const matches = canonical(response.node, true) === canonical(bundleDocument.node, true);
    checks.push(check('response', matches ? 'pass' : 'fail', 'Agent 回應與顯示證據包', matches
      ? '顯示的整份證據包與簽署的 HTTP 回應相符，僅排除後續附加的頂層 agent 證明欄位。'
      : '顯示的證據包與簽署的回應不符。即使保留有效的 transcript，也不能證明遭竄改的解說或證據內容為真。'));
  } catch (error) {
    checks.push(check('response', 'fail', 'Agent 回應與顯示證據包', error.message));
  }
  return { ...result, checks };
}
