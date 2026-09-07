import { writeFile } from 'node:fs/promises';
import { AbiCoder, Wallet, concat, getBytes, keccak256, solidityPackedKeccak256, toUtf8Bytes } from 'ethers';

// Builds two importable "AgenticID service proof" demo bundles using a
// public, deterministic TEST-ONLY signing key (also used in
// client/agentic.test.mjs) — never a funded wallet, never a live sealed
// sandbox. Run this against a locally running `make witness` (rehearsal
// mode makes no outbound request) to capture one real, unmodified bundle,
// then attach a self-signed X-Agent-Proof envelope over its exact bytes.
//
// Usage: node scripts/build-agentic-demo.mjs [http://127.0.0.1:8094]

const base = process.argv[2] ?? 'http://127.0.0.1:8094';
const wallet = new Wallet(`0x${'11'.repeat(32)}`);
const domain = { chainId: 16602n, contractAddress: `0x${'22'.repeat(20)}` };

const nonce = `witness_agentic-demo-${Date.now().toString(16)}`;
const requestBody = { mode: 'rehearsal', scenario: 'consistent', nonce };
const rawRequest = JSON.stringify(requestBody);

const response = await fetch(`${base}/api/check`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: rawRequest,
});
const rawResponse = await response.text();
if (!response.ok) throw new Error(`/api/check failed: ${response.status} ${rawResponse}`);
const bundle = JSON.parse(rawResponse);
if (bundle.agent !== null) throw new Error('Expected the captured bundle to carry agent:null before attaching a proof.');

function agentTaskHash({ method, uri, status, rawRequest: request, rawResponse: reply }) {
  return solidityPackedKeccak256(
    ['string', 'string', 'bytes32', 'bytes32', 'string'],
    [method, uri, keccak256(toUtf8Bytes(request)), keccak256(toUtf8Bytes(reply)), String(status)],
  );
}

async function sign(transcript) {
  const taskHash = agentTaskHash(transcript);
  const proofFields = {
    agent_id: '1',
    submitter: `0x${'00'.repeat(20)}`,
    timestamp: Math.floor(Date.now() / 1000) - 5,
    deadline: Math.floor(Date.now() / 1000) + 10 * 365 * 24 * 3600, // Never expires before a hackathon deadline.
    task_hash: taskHash,
    data_hashes: [keccak256(toUtf8Bytes('iff-witness/agentic-demo/v1'))],
    framework_hash: keccak256(toUtf8Bytes('iff-witness-example')),
  };
  const digest = keccak256(AbiCoder.defaultAbiCoder().encode(
    ['uint256', 'address', 'address', 'uint256', 'uint256', 'uint256', 'bytes32', 'bytes32', 'bytes32'],
    [domain.chainId, domain.contractAddress, proofFields.submitter, proofFields.agent_id, proofFields.timestamp,
      proofFields.deadline, proofFields.task_hash, solidityPackedKeccak256(['bytes32[]'], [proofFields.data_hashes]), proofFields.framework_hash],
  ));
  const signature = await wallet.signMessage(getBytes(digest));
  return {
    proof: `${signature}.${Buffer.from(JSON.stringify(proofFields)).toString('base64url')}`,
    transcript,
  };
}

const transcript = { method: 'POST', uri: '/api/check', status: 200, rawRequest, rawResponse };
const agent = await sign(transcript);

const withAgent = { ...bundle, agent };
await writeFile(new URL('../examples/agentic-demo-bundle.json', import.meta.url), JSON.stringify(withAgent, null, 2) + '\n');

// A tampered companion: the visible explanation text is edited after the
// fact, but the Agent envelope still points at the ORIGINAL signed bytes —
// so "Agent 回應與顯示證據包" must fail while the signature itself stays valid.
const tampered = structuredClone(withAgent);
tampered.explanation.text = `${tampered.explanation.text}（此處為示範竄改文字，簽署的原始回應並未改變）`;
await writeFile(new URL('../examples/agentic-demo-bundle-tampered.json', import.meta.url), JSON.stringify(tampered, null, 2) + '\n');

console.log('Wrote examples/agentic-demo-bundle.json and examples/agentic-demo-bundle-tampered.json');
console.log(`Signer address (set as WITNESS_AGENT_SIGNER): ${wallet.address}`);
console.log(`Chain ID (WITNESS_AGENT_CHAIN_ID): ${domain.chainId}`);
console.log(`Contract address (WITNESS_AGENT_CONTRACT): ${domain.contractAddress}`);
