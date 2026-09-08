import test from 'node:test';
import assert from 'node:assert/strict';
import { AbiCoder, Wallet, getBytes, keccak256, solidityPackedKeccak256, toUtf8Bytes } from 'ethers';
import { verifyBundleAgent } from './agent-bundle.mjs';

// Deterministic test-only identity; never an actual 0G agent deployment.
const wallet = new Wallet('0x' + '11'.repeat(32));
const options = { chainId: 16602, contractAddress: '0x' + '22'.repeat(20), expectedSigner: wallet.address, now: 1788600000 };
const status = (result, id) => result.checks.find((item) => item.id === id)?.status;

async function fixture({ omitAgent = false, mode = 'rehearsal', responseRaw, transcriptOverrides = {} } = {}) {
  const source = { schema: 'iff-witness/bundle/v1', mode, scenario: 'consistent', request: { receipt: { version: '1', nonce: 'test-request-1' } }, explanation: { source: 'rehearsal', text: 'Fixture answer.' }, agent: null };
  if (omitAgent) delete source.agent;
  const rawResponse = responseRaw ?? JSON.stringify(source);
  const transcript = { method: 'POST', uri: '/api/check', status: 200, rawRequest: JSON.stringify({ mode, scenario: 'consistent', nonce: 'test-request-1' }), rawResponse, ...transcriptOverrides };
  const taskHash = solidityPackedKeccak256(['string', 'string', 'bytes32', 'bytes32', 'string'], [transcript.method, transcript.uri, keccak256(toUtf8Bytes(transcript.rawRequest)), keccak256(toUtf8Bytes(transcript.rawResponse)), String(transcript.status)]);
  const proof = { agent_id: '33', submitter: '0x' + '00'.repeat(20), timestamp: options.now - 5, deadline: options.now + 3600, task_hash: taskHash, data_hashes: [], framework_hash: '0x' + '44'.repeat(32) };
  const digest = keccak256(AbiCoder.defaultAbiCoder().encode(['uint256', 'address', 'address', 'uint256', 'uint256', 'uint256', 'bytes32', 'bytes32', 'bytes32'], [options.chainId, options.contractAddress, proof.submitter, proof.agent_id, proof.timestamp, proof.deadline, proof.task_hash, solidityPackedKeccak256(['bytes32[]'], [proof.data_hashes]), proof.framework_hash]));
  const signature = await wallet.signMessage(getBytes(digest));
  const agent = { proof: signature + '.' + Buffer.from(JSON.stringify(proof)).toString('base64url'), transcript };
  const bundle = { ...JSON.parse(rawResponse), agent };
  return { bundle, agent, rawResponse };
}

test('unchanged signed bundle binds request, response and route with independently pinned identity', async () => {
  for (const omitAgent of [false, true]) {
    const { bundle } = await fixture({ omitAgent });
    const result = verifyBundleAgent(bundle, options);
    for (const id of ['agentic-transcript', 'agentic-signature', 'agentic-bundle-route', 'agentic-bundle-request', 'agentic-bundle-response']) assert.equal(status(result, id), 'pass', id);
  }
});

test('optional API password preserves request binding and warns about shared credentials', async () => {
  for (const mode of ['rehearsal', 'live']) {
    for (const password of ['', 'test-only-passphrase']) {
      const rawRequest = JSON.stringify({ mode, scenario: 'consistent', nonce: 'test-request-1', password });
      const { bundle } = await fixture({ mode, transcriptOverrides: { rawRequest } });
      for (const base64 of [false, true]) {
        if (base64) {
          bundle.agent.transcript.rawRequestBase64 = Buffer.from(rawRequest).toString('base64');
          delete bundle.agent.transcript.rawRequest;
        }
        const before = JSON.stringify(bundle);
        const result = verifyBundleAgent(bundle, options);
        for (const id of ['agentic-transcript', 'agentic-signature', 'agentic-bundle-request', 'agentic-bundle-response']) assert.equal(status(result, id), 'pass', id);
        assert.equal(status(result, 'agentic-bundle-credential'), password ? 'warning' : undefined);
        if (password) assert.ok(!JSON.stringify(result.checks).includes(password), 'Checks must never repeat the password.');
        assert.equal(JSON.stringify(bundle), before, 'Verification must not rewrite signed bytes.');
      }
    }
  }
});

test('changing an optional password still invalidates the signed transcript', async () => {
  const rawRequest = '{"mode":"live","scenario":"consistent","nonce":"test-request-1","password":"test-only-passphrase"}';
  const { bundle } = await fixture({ mode: 'live', transcriptOverrides: { rawRequest } });
  bundle.agent.transcript.rawRequest = rawRequest.replace('test-only-passphrase', 'changed-passphrase');
  const result = verifyBundleAgent(bundle, options);
  assert.equal(status(result, 'agentic-signature'), 'pass');
  assert.equal(status(result, 'agentic-transcript'), 'fail');
});

test('password support does not admit unknown fields, mistyped passwords or altered check fields', async () => {
  const request = { mode: 'live', scenario: 'consistent', nonce: 'test-request-1', password: 'test-only-passphrase' };
  for (const extra of [{ url: 'https://unrequested.example/' }, { password: null }, { password: 42 }, { password: {} }, { nonce: 'wrong' }, { scenario: 'payee_changed' }, { mode: 'rehearsal' }]) {
    const { bundle } = await fixture({ mode: 'live', transcriptOverrides: { rawRequest: JSON.stringify({ ...request, ...extra }) } });
    const result = verifyBundleAgent(bundle, options);
    assert.equal(status(result, 'agentic-signature'), 'pass');
    assert.equal(status(result, 'agentic-transcript'), 'pass');
    assert.equal(status(result, 'agentic-bundle-request'), 'fail');
  }
  const duplicate = JSON.stringify(request).replace('"password":', '"password":"first","password":');
  const { bundle } = await fixture({ mode: 'live', transcriptOverrides: { rawRequest: duplicate } });
  assert.equal(status(verifyBundleAgent(bundle, options), 'agentic-bundle-request'), 'fail');
});

test('altered outer explanation cannot retain a passing agent response binding', async () => {
  const { bundle } = await fixture();
  bundle.explanation.text = 'Changed answer.';
  const result = verifyBundleAgent(bundle, options);
  assert.equal(status(result, 'agentic-signature'), 'pass');
  assert.equal(status(result, 'agentic-transcript'), 'pass');
  assert.equal(status(result, 'agentic-bundle-response'), 'fail');
});

test('wrong bundle mode, scenario or nonce fails the exact check request binding', async () => {
  for (const mutate of [(bundle) => { bundle.mode = 'live'; }, (bundle) => { bundle.scenario = 'payee_changed'; }, (bundle) => { bundle.request.receipt.nonce = 'other-request'; }]) {
    const { bundle } = await fixture();
    mutate(bundle);
    assert.equal(status(verifyBundleAgent(bundle, options), 'agentic-bundle-request'), 'fail');
  }
});

test('a valid signature for the wrong method, URI or status cannot be used for a successful check', async () => {
  for (const transcriptOverrides of [{ method: 'GET' }, { uri: '/api/check?other=1' }, { status: 500 }]) {
    const { bundle } = await fixture({ transcriptOverrides });
    const result = verifyBundleAgent(bundle, options);
    assert.equal(status(result, 'agentic-transcript'), 'pass');
    assert.equal(status(result, 'agentic-signature'), 'pass');
    assert.equal(status(result, 'agentic-bundle-route'), 'fail');
  }
});

test('strict syntax-tree comparison preserves large numeric tokens and rejects lossy object inputs', async () => {
  const responseRaw = '{"schema":"iff-witness/bundle/v1","mode":"rehearsal","scenario":"consistent","request":{"receipt":{"nonce":"test-request-1"}},"explanation":{"text":"Fixture."},"counter":9007199254740993,"agent":null}';
  const { bundle, agent } = await fixture({ responseRaw });
  const raw = responseRaw.replace('"agent":null', '"agent":' + JSON.stringify(agent));
  assert.equal(status(verifyBundleAgent(raw, options), 'agentic-bundle-response'), 'pass');
  // Change only the displayed token, retaining the original transcript.
  const modified = raw.replace('"counter":9007199254740993', '"counter":9007199254740992');
  assert.equal(status(verifyBundleAgent(modified, options), 'agentic-bundle-response'), 'fail');
  assert.equal(status(verifyBundleAgent(bundle, options), 'agentic-bundle-format'), 'fail');
});

test('signed non-null agent sibling and duplicate JSON keys fail closed', async () => {
  const first = await fixture();
  const source = JSON.parse(first.rawResponse); source.agent = { unexpected: 'already attached' };
  const { bundle } = await fixture({ responseRaw: JSON.stringify(source) });
  assert.equal(status(verifyBundleAgent(bundle, options), 'agentic-bundle-response'), 'fail');
  const normal = await fixture();
  const duplicate = JSON.stringify(normal.bundle).replace('"mode":"rehearsal"', '"mode":"live","mode":"rehearsal"');
  assert.equal(status(verifyBundleAgent(duplicate, options), 'agentic-bundle-format'), 'fail');
});

test('missing agent yields one unverified check and bundled identity cannot supply trust', async () => {
  assert.deepEqual(verifyBundleAgent({ agent: null }).checks.map(({ id, status }) => ({ id, status })), [{ id: 'agent_identity', status: 'unverified' }]);
  const { bundle } = await fixture();
  bundle.agent.identity = options;
  assert.equal(status(verifyBundleAgent(bundle), 'agentic-signature'), 'unverified');
});

test('portable base64 transcripts bind UTF-8 JSON without changing original bytes', async () => {
  const { bundle } = await fixture();
  const transcript = bundle.agent.transcript;
  transcript.rawRequestBase64 = Buffer.from(transcript.rawRequest).toString('base64'); delete transcript.rawRequest;
  transcript.rawResponseBase64 = Buffer.from(transcript.rawResponse).toString('base64'); delete transcript.rawResponse;
  const result = verifyBundleAgent(bundle, options);
  assert.equal(status(result, 'agentic-transcript'), 'pass');
  assert.equal(status(result, 'agentic-bundle-request'), 'pass');
  assert.equal(status(result, 'agentic-bundle-response'), 'pass');
});
