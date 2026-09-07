import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const PIN = 'sha256:' + 'a'.repeat(64);
const OTHER_PIN = 'sha256:' + 'b'.repeat(64);
const config = (pins = []) => ({ iff_origin: 'https://ifandonlyif.io', trusted_key_ids: pins, demo_key_ids: [], compute_configured: true, live_ready: true, examples: [] });
const deferred = () => {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
};
const tick = () => new Promise(resolve => setImmediate(resolve));

class NodeStub {
  constructor() {
    this.value = 'live'; this.children = []; this.listeners = {}; this.textContent = '';
    this.classList = { add() {}, remove() {}, toggle() {} };
  }
  addEventListener(name, callback) { this.listeners[name] = callback; }
  setAttribute(name, value) { this[name] = value; }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  querySelector() { return new NodeStub(); }
}

// Run the actual UI module with a tiny DOM and injected verifier/network
// boundaries. This tests refresh sequencing; crypto correctness is covered by
// verify.test.mjs. No real browser, external service, or inference is called.
async function harness(initialConfig = config()) {
  const nodes = new Map();
  const node = id => { if (!nodes.has(id)) nodes.set(id, new NodeStub()); return nodes.get(id); };
  const choices = [new NodeStub()];
  choices[0].value = 'consistent';
  const document = {
    getElementById: node, querySelector: () => choices[0], querySelectorAll: () => choices,
    createElement: () => new NodeStub(), body: new NodeStub(), addEventListener() {}, visibilityState: 'visible',
  };
  const controls = { responses: [initialConfig], verifier: null };
  const fetches = [], verifications = [];
  const verify = async (bundle, options) => {
    const call = { bundle, options }; verifications.push(call);
    if (controls.verifier) return controls.verifier(call, verifications.length);
    return proofResult(options);
  };
  const fetch = async (url, options) => {
    assert.equal(url, '/api/config', 'Refresh must not call any inference or evidence endpoint.');
    fetches.push({ url, options });
    assert.ok(controls.responses.length, 'Unexpected extra config request.');
    const response = await controls.responses.shift();
    return { ok: true, text: async () => JSON.stringify(response) };
  };
  const source = (await readFile(new URL('./app.mjs', import.meta.url), 'utf8')).replace(/^import[^\n]*\n/gm, '');
  const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
  const boot = new AsyncFunction('verifyBundle', 'verifyBundleAgent', 'parseJSONStrict', 'document', 'window', 'fetch', 'BroadcastChannel',
    source + '\nreturn { state, refreshConfig, verifyCurrent, clearResult };');
  const app = await boot(verify, () => ({ checks: [] }), text => ({ value: JSON.parse(text) }), document, { addEventListener() {} }, fetch, undefined);
  return { ...app, nodes, controls, fetches, verifications };
}

function proofResult(options, marker = '') {
  return { checks: [
    { id: 'iff_signature', status: 'pass', label: 'Signature', detail: marker },
    { id: 'iff_issuer', status: options.trustedKeyIDs.includes(PIN) ? 'pass' : 'unverified', label: 'Issuer', detail: marker },
  ], iffResult: { subject: { verdict: 'consistent' } } };
}

function installReceipt(app) {
  const bundle = { schema: 'iff-witness/bundle/v1', mode: 'live', scenario: 'consistent',
    request: { url: 'https://fixture.example/', receipt: { nonce: 'existing-request' } },
    iff: { response: '{"verdict":"consistent","received":{"set_fingerprint":"fixture"}}' },
    explanation: { source: '0g', text: 'Existing explanation.' }, compute: { status: 'unavailable' }, agent: null };
  const raw = JSON.stringify(bundle, null, 2);
  Object.assign(app.state, { bundle, original: structuredClone(bundle), raw, originalRaw: raw, expectedNonce: 'existing-request', tampered: true });
  return { bundle, raw, original: app.state.original };
}

const issuerStatus = app => app.state.result.checks.find(check => check.id === 'iff_issuer').status;

test('editing and clearing IFF pins reverify the displayed receipt without changing bytes or calling inference', async () => {
  const app = await harness();
  const retained = installReceipt(app);
  await app.verifyCurrent();
  assert.equal(issuerStatus(app), 'unverified');
  app.controls.responses.push(config([PIN]));
  await app.refreshConfig();
  assert.equal(issuerStatus(app), 'pass');
  app.controls.responses.push(config([]));
  await app.refreshConfig();
  assert.equal(issuerStatus(app), 'unverified');
  assert.equal(app.verifications.length, 3);
  assert.equal(app.fetches.length, 3);
  assert.equal(app.state.bundle, retained.bundle);
  assert.equal(app.state.original, retained.original);
  assert.equal(app.state.raw, retained.raw);
  assert.equal(app.state.originalRaw, retained.raw);
  assert.equal(app.state.expectedNonce, 'existing-request');
  assert.equal(app.state.tampered, true);
});

test('unchanged public configuration does not needlessly reverify an existing proof', async () => {
  const app = await harness(config([PIN]));
  installReceipt(app); await app.verifyCurrent();
  app.controls.responses.push({ ...config([PIN]), compute_configured: false, live_ready: false });
  await app.refreshConfig();
  assert.equal(app.verifications.length, 1);
  assert.equal(issuerStatus(app), 'pass');
});

test('a slower old-policy verification cannot overwrite the cleared-pin result', async () => {
  const app = await harness(config([PIN]));
  installReceipt(app);
  const slow = deferred();
  app.controls.verifier = (call, index) => index === 1 ? slow.promise : proofResult(call.options, 'new policy');
  const oldVerification = app.verifyCurrent();
  app.controls.responses.push(config([]));
  await app.refreshConfig();
  assert.equal(issuerStatus(app), 'unverified');
  slow.resolve(proofResult({ trustedKeyIDs: [PIN] }, 'stale policy'));
  assert.equal(await oldVerification, false);
  assert.equal(issuerStatus(app), 'unverified');
  assert.equal(app.state.result.checks[0].detail, 'new policy');
});

test('old green identity is invalidated while the new-policy verifier is pending', async () => {
  const app = await harness(config([PIN]));
  installReceipt(app); await app.verifyCurrent();
  const pending = deferred();
  app.controls.verifier = () => pending.promise;
  app.controls.responses.push(config([OTHER_PIN]));
  const refresh = app.refreshConfig();
  await tick();
  assert.equal(issuerStatus(app), 'unverified');
  assert.match(app.nodes.get('proof-status').textContent, /重新核對/);
  pending.resolve(proofResult({ trustedKeyIDs: [OTHER_PIN] }));
  await refresh;
  assert.equal(issuerStatus(app), 'unverified');
});

test('a settings notification during an older config GET queues a fresh policy lookup', async () => {
  const app = await harness(config([PIN]));
  installReceipt(app); await app.verifyCurrent();
  const oldConfig = deferred();
  app.controls.responses.push(oldConfig.promise, config([]));
  const refresh = app.refreshConfig();
  await app.refreshConfig();
  oldConfig.resolve(config([PIN]));
  await refresh;
  await tick();
  assert.equal(app.fetches.length, 3);
  assert.equal(issuerStatus(app), 'unverified');
});

test('clearing the displayed receipt prevents an outstanding verification from restoring it', async () => {
  const app = await harness(config([PIN]));
  installReceipt(app);
  const pending = deferred();
  app.controls.verifier = () => pending.promise;
  const verify = app.verifyCurrent();
  app.clearResult();
  pending.resolve(proofResult({ trustedKeyIDs: [PIN] }));
  assert.equal(await verify, false);
  assert.equal(app.state.bundle, null);
  assert.equal(app.state.result, null);
});
