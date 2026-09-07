import assert from 'node:assert/strict';
import test from 'node:test';
import { AbiCoder, Wallet, getBytes, keccak256, solidityPackedKeccak256, toUtf8Bytes } from 'ethers';
import { agentTaskHash, parseAgentProof, verifyAgentProof } from './agentic.mjs';

// Deterministic, publicly known TEST-ONLY signer. No network or wallet funding.
const wallet = new Wallet(`0x${'11'.repeat(32)}`);
const now = 1788600000;
const domain = { chainId: 16602, contractAddress: `0x${'22'.repeat(20)}`, expectedSigner: wallet.address, now };
const transcript = {
  method: 'POST', uri: '/api/check', status: 200,
  rawRequest: '{"mode":"rehearsal","nonce":"測試"}',
  rawResponse: '{"explanation":{"text":"A bounded observation, not a safety verdict."}}\n',
};

// Independently encode the published Go/SDK wire spec, rather than asking the
// production verifier to construct its own signing fixture.
function referenceTaskHash(value) {
  const request = value.rawRequestBase64 === undefined ? toUtf8Bytes(value.rawRequest) : Buffer.from(value.rawRequestBase64, 'base64');
  const response = value.rawResponseBase64 === undefined ? toUtf8Bytes(value.rawResponse) : Buffer.from(value.rawResponseBase64, 'base64');
  return solidityPackedKeccak256(['string', 'string', 'bytes32', 'bytes32', 'string'],
    [value.method, value.uri, keccak256(request), keccak256(response), String(value.status)]);
}

async function fixture(value = transcript, overrides = {}) {
  const proof = {
    agent_id: '33', submitter: `0x${'00'.repeat(20)}`, timestamp: now - 5, deadline: now + 3595,
    task_hash: referenceTaskHash(value), data_hashes: [`0x${'33'.repeat(32)}`], framework_hash: `0x${'44'.repeat(32)}`,
    ...overrides,
  };
  const digest = keccak256(AbiCoder.defaultAbiCoder().encode(
    ['uint256', 'address', 'address', 'uint256', 'uint256', 'uint256', 'bytes32', 'bytes32', 'bytes32'],
    [domain.chainId, domain.contractAddress, proof.submitter, proof.agent_id, proof.timestamp, proof.deadline,
      proof.task_hash, solidityPackedKeccak256(['bytes32[]'], [proof.data_hashes]), proof.framework_hash],
  ));
  const signature = await wallet.signMessage(getBytes(digest));
  return { proof: `${signature}.${Buffer.from(JSON.stringify(proof)).toString('base64url')}`, transcript: { ...value } };
}

const statusOf = (result, id) => result.checks.find((item) => item.id === `agentic-${id}`)?.status;

test('captures the official signed HTTP transcript with independently pinned identity', async () => {
  const envelope = await fixture();
  assert.equal(agentTaskHash(envelope.transcript), referenceTaskHash(transcript));
  const result = verifyAgentProof(envelope, domain);
  assert.equal(statusOf(result, 'transcript'), 'pass');
  assert.equal(statusOf(result, 'signature'), 'pass');
  assert.equal(statusOf(result, 'time'), 'pass');
  assert.equal(statusOf(result, 'chain'), 'unverified');
  assert.equal(statusOf(result, 'scope'), 'warning');
  assert.equal(result.agentId, '33');
});

test('rejects edits to each HTTP transcript component, including JSON whitespace', async () => {
  const envelope = await fixture();
  for (const mutation of [
    { rawRequest: `${transcript.rawRequest} ` }, { rawResponse: transcript.rawResponse.replace('bounded', 'guaranteed') },
    { method: 'GET' }, { uri: '/api/check?mode=other' }, { status: 201 },
  ]) {
    const result = verifyAgentProof({ ...envelope, transcript: { ...transcript, ...mutation } }, domain);
    assert.equal(statusOf(result, 'transcript'), 'fail');
    assert.equal(statusOf(result, 'signature'), 'pass');
  }
});

test('wrong identity, chain, contract, or signed fields fail the signer comparison', async () => {
  const envelope = await fixture();
  for (const mutation of [
    { expectedSigner: `0x${'55'.repeat(20)}` }, { chainId: 16661 }, { contractAddress: `0x${'66'.repeat(20)}` },
  ]) assert.equal(statusOf(verifyAgentProof(envelope, { ...domain, ...mutation }), 'signature'), 'fail');
  const parsed = parseAgentProof(envelope.proof);
  for (const mutation of [
    { submitter: `0x${'77'.repeat(20)}` }, { agentId: 34n }, { frameworkHash: `0x${'88'.repeat(32)}` },
    { deadline: BigInt(now + 5000) }, { dataHashes: [] },
  ]) assert.equal(statusOf(verifyAgentProof({ ...envelope, proof: { ...parsed, ...mutation } }, domain), 'signature'), 'fail');
});

test('embedded identity and domain cannot establish independently pinned trust', async () => {
  const envelope = { ...await fixture(), identity: domain, expectedSigner: wallet.address, chainId: domain.chainId, contractAddress: domain.contractAddress };
  assert.equal(statusOf(verifyAgentProof(envelope), 'signature'), 'unverified');
  assert.equal(statusOf(verifyAgentProof(envelope, { chainId: domain.chainId, contractAddress: domain.contractAddress }), 'signature'), 'unverified');
});

test('expiration preserves historical signature verification; future time fails freshness', async () => {
  const expired = await fixture(transcript, { timestamp: now - 7200, deadline: now - 3600 });
  const result = verifyAgentProof(expired, domain);
  assert.equal(statusOf(result, 'signature'), 'pass');
  assert.equal(statusOf(result, 'time'), 'warning');
  const future = await fixture(transcript, { timestamp: now + 300, deadline: now + 3900 });
  assert.equal(statusOf(verifyAgentProof(future, domain), 'time'), 'fail');
});

test('preserves arbitrary raw bytes through the portable base64 transcript form', async () => {
  const value = {
    method: 'POST', uri: '/api/check', status: 200,
    rawRequestBase64: Buffer.from([0, 255, 128, 10]).toString('base64'),
    rawResponseBase64: Buffer.from([255, 0, 254, 128, 10]).toString('base64'),
  };
  const result = verifyAgentProof(await fixture(value), domain);
  assert.equal(statusOf(result, 'transcript'), 'pass');
  assert.equal(statusOf(result, 'signature'), 'pass');
});

test('missing bytes, ambiguous bytes, and excessive input fail closed', async () => {
  const envelope = await fixture();
  for (const rawResponse of [undefined, {}, 'x'.repeat(2 * 1024 * 1024 + 1)]) {
    assert.equal(statusOf(verifyAgentProof({ ...envelope, transcript: { ...transcript, rawResponse } }, domain), 'transcript'), 'fail');
  }
  assert.equal(statusOf(verifyAgentProof({ ...envelope, transcript: { ...transcript, rawRequestBase64: '' } }, domain), 'transcript'), 'fail');
});

test('missing proofs are unverified; malformed proofs never crash the view', async () => {
  assert.equal(statusOf(verifyAgentProof(null), 'presence'), 'unverified');
  for (const proof of ['not-a-proof', '0x123.invalid@base64', {}, 'x'.repeat(33000)]) {
    assert.equal(statusOf(verifyAgentProof({ proof }, domain), 'format'), 'fail');
  }
  const envelope = await fixture();
  const parsed = parseAgentProof(envelope.proof);
  assert.equal(statusOf(verifyAgentProof({ ...envelope, proof: { ...parsed, signature: `0x${'00'.repeat(65)}` } }, domain), 'signature'), 'fail');
  assert.equal(statusOf(verifyAgentProof({ ...envelope, proof: { ...parsed, agentId: Number.MAX_SAFE_INTEGER + 1 } }, domain), 'format'), 'fail');
});
