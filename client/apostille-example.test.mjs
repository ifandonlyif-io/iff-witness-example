import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, writeFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { generateKeyFile, importKeyFile, createRegistration, createStatement, canonical, PROTOCOL } from './third-party/apostille/apostille-core.mjs';
import { signExample, verifyExample, addSpace, createReceiverExample, MAX_ARTIFACT_BYTES, MAX_BUNDLE_BYTES } from './apostille-example.mjs';

const original = new Uint8Array(await readFile(new URL('../examples/agentic-demo-bundle.json', import.meta.url)));

test('real offline signatures retain producer-only scope and unknown trust without exporting keys', async () => {
  const oldFetch = globalThis.fetch;
  globalThis.fetch = () => { throw new Error('The offline example must not use the network.'); };
  try {
    const encoded = await signExample(original);
    const bundle = JSON.parse(encoded);
    assert.equal(bundle.certificate, null);
    assert.equal(bundle.delegation.kind, 'agent-delegation');
    assert.equal(bundle.acceptance.kind, 'agent-acceptance');
    assert.doesNotMatch(encoded, /"(?:seed|private_key|api_key)"/);
    const checked = await verifyExample(encoded, original);
    assert.equal(checked.signature_check, 'valid');
    assert.equal(checked.protocol, 'https://ifandonlyif.io/apostille/spec/0.3');
    assert.equal(checked.signature_algorithm, 'ML-DSA-65');
    assert.equal(checked.original_matches, true);
    assert.equal(checked.certificate_scope, 'producer_only');
    assert.equal(checked.issuer_trust, 'unknown');
    assert.equal(checked.agent_binding, 'admin_key_delegation');
    assert.equal(checked.organization_binding, 'unproven');
    assert.equal(checked.content_truth, 'not_established');
    assert.equal(checked.freshness, 'unknown');
    assert.equal(checked.authorization_policy, 'unknown');
  } finally { globalThis.fetch = oldFetch; }
});

test('adding JSON whitespace preserves the signature but fails exact original-file comparison', async () => {
  const bundle = await signExample(original);
  const changed = addSpace(original);
  assert.deepEqual(JSON.parse(new TextDecoder().decode(changed)), JSON.parse(new TextDecoder().decode(original)));
  assert.equal((await verifyExample(bundle, changed)).signature_check, 'valid');
  assert.equal((await verifyExample(bundle, changed)).original_matches, false);
  assert.equal((await verifyExample(bundle, original)).original_matches, true);
});

test('altered envelopes and swapped delegation cannot pass signature or key-binding checks', async () => {
  const bundle = JSON.parse(await signExample(original));
  const altered = structuredClone(bundle);
  altered.statement.payload_sha256 = '0'.repeat(64);
  await assert.rejects(verifyExample(JSON.stringify(altered), original));
  const other = JSON.parse(await signExample(original));
  assert.notEqual(bundle.statement.signature.key_id, other.statement.signature.key_id);
  bundle.delegation = other.delegation;
  bundle.acceptance = other.acceptance;
  await assert.rejects(verifyExample(JSON.stringify(bundle), original));
});

test('different evidence and mutable input buffers cannot silently replace the selected bytes', async () => {
  const mutable = Buffer.from(original);
  const signing = signExample(mutable);
  mutable[0] ^= 1;
  const bundle = await signing;
  assert.equal((await verifyExample(bundle, original)).original_matches, true);
  assert.equal((await verifyExample(bundle, mutable)).original_matches, false);
  const checking = verifyExample(bundle, mutable);
  mutable.set(original);
  assert.equal((await checking).original_matches, false);
});

test('oversized files and malformed/duplicate-key bundles are rejected', async () => {
  await assert.rejects(signExample(new Uint8Array(MAX_ARTIFACT_BYTES + 1)), /1 MiB/);
  await assert.rejects(verifyExample(' '.repeat(MAX_BUNDLE_BYTES + 1), original), /256 KiB/);
  await assert.rejects(verifyExample('{"protocol":1,"protocol":2}', original));
  assert.throws(() => addSpace(new Uint8Array(MAX_ARTIFACT_BYTES)), /1 MiB/);
});

test('CLI demo exports no key files, verifies offline and refuses to overwrite output', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'witness-apostille-test-'));
  const output = join(directory, 'demo');
  const cli = new URL('../scripts/apostille.mjs', import.meta.url);
  const run = (...args) => spawnSync(process.execPath, [cli.pathname, ...args], { encoding: 'utf8', timeout: 30000 });
  try {
    const demo = run('demo', output);
    assert.equal(demo.status, 0, demo.stderr);
    assert.deepEqual((await readdir(output)).sort(), ['apostille-bundle.json', 'witness-original.json', 'witness-with-space.json']);
    const bundlePath = join(output, 'apostille-bundle.json');
    const artifactPath = join(output, 'witness-original.json');
    assert.equal(run('verify', bundlePath, artifactPath).status, 0);
    assert.equal(run('verify', bundlePath, join(output, 'witness-with-space.json')).status, 1);
    assert.equal(run('demo', output).status, 2);
    assert.equal(run('sign', artifactPath, bundlePath).status, 2);
    await writeFile(bundlePath, '{}');
    assert.equal(run('verify', bundlePath, artifactPath).status, 1);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('receiver download kit has a real matching pair and a detectable changed original', async () => {
  const mutable = Buffer.from(original);
  const creating = createReceiverExample(mutable);
  mutable[0] ^= 1;
  const { id, files } = await creating;
  assert.deepEqual(Object.keys(files).sort(), ['bundle', 'changed', 'original']);
  assert.equal(new Set(Object.values(files).map(file => file.name)).size, 3);
  for (const file of Object.values(files)) assert.ok(file.name.includes(id));
  assert.deepEqual(files.original.bytes, original);
  assert.equal(files.changed.bytes.length, original.length + 1);
  assert.equal(files.changed.bytes.at(-1), 0x20);
  const bundle = new TextDecoder().decode(files.bundle.bytes);
  assert.doesNotMatch(bundle, /"(?:seed|private_key|api_key)"/);
  const good = await verifyExample(bundle, files.original.bytes);
  const changed = await verifyExample(bundle, files.changed.bytes);
  assert.equal(good.original_matches, true);
  assert.equal(good.issuer_trust, 'unknown');
  assert.equal(good.certificate_scope, 'producer_only');
  assert.equal(changed.signature_check, 'valid');
  assert.equal(changed.original_matches, false);
});

test('new examples are Core 0.3 ML-DSA-65 while a Core 0.1 Ed25519 bundle still verifies', async () => {
  const bundle = JSON.parse(await signExample(original));
  for (const envelope of [bundle.statement, bundle.delegation, bundle.acceptance]) {
    assert.equal(envelope.protocol, 'https://ifandonlyif.io/apostille/spec/0.3');
    assert.equal(envelope.signature.algorithm, 'ML-DSA-65');
  }
  const admin = await importKeyFile(await generateKeyFile({ algorithm: 'Ed25519' }));
  const agent = await importKeyFile(await generateKeyFile({ algorithm: 'Ed25519' }));
  const registration = await createRegistration(admin, agent, 'urn:example:witness:apostille');
  const statement = await createStatement(original, 'application/octet-stream', agent, registration);
  const legacy = canonical({ protocol: PROTOCOL, statement, ...registration, certificate: null });
  const checked = await verifyExample(legacy, original);
  assert.equal(checked.protocol, PROTOCOL);
  assert.equal(checked.signature_algorithm, 'Ed25519');
  assert.equal(checked.original_matches, true);
  assert.equal((await verifyExample(legacy, addSpace(original))).original_matches, false);
});
