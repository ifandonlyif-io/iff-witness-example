import {
  PROTOCOL, MAX_INPUT_BYTES, b64, canonical, fingerprint, createRegistration,
  createStatement, verifyArtifact, verifyBundle,
} from './third-party/apostille/apostille-core.mjs';

export const MAX_ARTIFACT_BYTES = 1024 * 1024;
export const MAX_BUNDLE_BYTES = MAX_INPUT_BYTES;
const encoder = new TextEncoder();

function artifactBytes(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length > MAX_ARTIFACT_BYTES) {
    throw new Error('原件必須是最多 1 MiB 的檔案。');
  }
  return bytes;
}

async function ephemeralSigner() {
  // No seed export, key file, persistence, account registration or hosted call.
  const pair = await crypto.subtle.generateKey('Ed25519', false, ['sign', 'verify']);
  const publicKey = b64(new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey)));
  return { key: pair.privateKey, publicKey, keyID: await fingerprint(publicKey) };
}

export async function signExample(bytes) {
  // Copy before the first await: the signed original must be the selected bytes,
  // even if the caller reuses its input buffer while WebCrypto is running.
  const original = new Uint8Array(artifactBytes(bytes));
  const admin = await ephemeralSigner();
  const agent = await ephemeralSigner();
  const registration = await createRegistration(admin, agent, 'urn:example:witness:apostille');
  const statement = await createStatement(original, 'application/octet-stream', agent, registration);
  return canonical({ protocol: PROTOCOL, statement, ...registration, certificate: null }) + '\n';
}

export async function verifyExample(bundleText, bytes) {
  if (typeof bundleText !== 'string' || encoder.encode(bundleText).length > MAX_BUNDLE_BYTES) {
    throw new Error('Apostille bundle 不能超過 256 KiB。');
  }
  const original = new Uint8Array(artifactBytes(bytes));
  // No issuer/key policy is inferred from the bundle. All checks stay offline.
  const result = await verifyBundle(bundleText, { at: new Date() });
  return {
    signature_check: 'valid',
    original_matches: await verifyArtifact(result, original),
    certificate_scope: result.certificate_scope,
    issuer_trust: result.issuer_trust,
    agent_binding: result.agent_binding,
    organization_binding: result.organization_binding,
    content_truth: result.content_truth,
    freshness: result.freshness,
    authorization_policy: result.authorization_policy,
    artifact_sha256: result.statement.artifact_sha256,
    artifact_size: result.statement.artifact_size,
    source_key_id: result.statement.issuer_key_id,
  };
}

export function addSpace(bytes) {
  artifactBytes(bytes);
  if (bytes.length >= MAX_ARTIFACT_BYTES) throw new Error('原件已達 1 MiB，無法再加入空白。');
  const changed = new Uint8Array(bytes.length + 1);
  changed.set(bytes); changed[bytes.length] = 0x20;
  return changed;
}

// Generate downloadable test material and confirm both expected outcomes before
// offering it. Only public bytes leave this helper; signExample exports no key.
export async function createReceiverExample(bytes) {
  const original = new Uint8Array(artifactBytes(bytes));
  const changed = addSpace(original);
  const bundle = await signExample(original);
  const [good, tampered] = await Promise.all([
    verifyExample(bundle, original), verifyExample(bundle, changed),
  ]);
  if (!good.original_matches || tampered.original_matches) throw new Error('測試檔案的配對自我檢查未通過。');
  const id = crypto.randomUUID().slice(0, 8);
  return { id, files: {
    bundle: { name: `apostille-${id}.json`, bytes: encoder.encode(bundle) },
    original: { name: `witness-${id}-original.json`, bytes: original },
    changed: { name: `witness-${id}-changed.json`, bytes: changed },
  } };
}
