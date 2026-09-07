import { AbiCoder, concat, getAddress, getBytes, hashMessage, keccak256, recoverAddress, toUtf8Bytes } from 'ethers';

const MAX_BODY_BYTES = 2 * 1024 * 1024;
const MAX_HEADER_BYTES = 32 * 1024;
const UINT256_MAX = (1n << 256n) - 1n;
const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';
const coder = AbiCoder.defaultAbiCoder();

function check(id, status, label, detail) {
  return { id: `agentic-${id}`, status, label, detail };
}

function uint256(value, label) {
  if (typeof value === 'number' && !Number.isSafeInteger(value)) throw new Error(`Invalid ${label}`);
  if (!['number', 'string', 'bigint'].includes(typeof value) || String(value).length > 78 || !/^\d+$/.test(String(value))) throw new Error(`Invalid ${label}`);
  const result = BigInt(value);
  if (result > UINT256_MAX) throw new Error(`Invalid ${label}`);
  return result;
}

function address(value, label, allowZero = false) {
  if (typeof value !== 'string' || !/^0x[\da-fA-F]{40}$/.test(value)) throw new Error(`Invalid ${label}`);
  const result = getAddress(value);
  if (!allowZero && result === ZERO_ADDRESS) throw new Error(`Invalid ${label}`);
  return result;
}

function bytes32(value, label) {
  if (typeof value !== 'string' || !/^0x[\da-fA-F]{64}$/.test(value)) throw new Error(`Invalid ${label}`);
  return value.toLowerCase();
}

function decodeBase64(value, url = false) {
  if (typeof value !== 'string' || value.length > MAX_BODY_BYTES * 2) throw new Error('Invalid base64 bytes');
  const expression = url ? /^[A-Za-z0-9_-]*={0,2}$/ : /^[A-Za-z0-9+/]*={0,2}$/;
  if (!expression.test(value) || value.length % 4 === 1) throw new Error('Invalid base64 bytes');
  const standard = url ? value.replace(/-/g, '+').replace(/_/g, '/') : value;
  const binary = atob(standard);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

/** Parse the actual X-Agent-Proof header or a previously parsed SDK proof. */
export function parseAgentProof(value) {
  let proof = value;
  if (typeof value === 'string') {
    if (value.length > MAX_HEADER_BYTES) throw new Error('Proof header is too large');
    const separator = value.indexOf('.');
    if (separator < 0) throw new Error('Malformed X-Agent-Proof header');
    const decoded = new TextDecoder('utf-8', { fatal: true }).decode(decodeBase64(value.slice(separator + 1), true));
    proof = { ...JSON.parse(decoded), signature: value.slice(0, separator) };
  }
  if (!proof || typeof proof !== 'object' || Array.isArray(proof)) throw new Error('Missing proof');
  const dataHashes = proof.dataHashes ?? proof.data_hashes;
  if (!Array.isArray(dataHashes) || dataHashes.length > 128) throw new Error('Invalid data hashes');
  if (typeof proof.signature !== 'string' || !/^0x[\da-fA-F]{130}$/.test(proof.signature)) throw new Error('Invalid signature');
  const parsed = {
    agentId: uint256(proof.agentId ?? proof.agent_id, 'agent ID'),
    submitter: address(proof.submitter, 'submitter', true),
    timestamp: uint256(proof.timestamp, 'timestamp'),
    deadline: uint256(proof.deadline, 'deadline'),
    taskHash: bytes32(proof.taskHash ?? proof.task_hash, 'task hash'),
    dataHashes: dataHashes.map((item) => bytes32(item, 'data hash')),
    frameworkHash: bytes32(proof.frameworkHash ?? proof.framework_hash, 'framework hash'),
    signature: proof.signature,
  };
  if (parsed.agentId === 0n || parsed.deadline <= parsed.timestamp) throw new Error('Invalid proof identity or time window');
  return parsed;
}

function transcriptBody(transcript, name) {
  const raw = transcript[name];
  const encoded = transcript[`${name}Base64`];
  if (raw !== undefined && encoded !== undefined) throw new Error('Ambiguous transcript body');
  let bytes;
  if (encoded !== undefined) bytes = decodeBase64(encoded);
  else if (typeof raw === 'string') bytes = toUtf8Bytes(raw);
  else if (raw instanceof Uint8Array) bytes = raw;
  else throw new Error('Exact request and response bytes are required');
  if (bytes.length > MAX_BODY_BYTES) throw new Error('Transcript body is too large');
  return bytes;
}

/** Match sealed/internal/proxy/proxy.go, including raw bytes and decimal status. */
export function agentTaskHash(transcript) {
  if (!transcript || typeof transcript !== 'object') throw new Error('Missing transcript');
  const { method, uri, status } = transcript;
  if (typeof method !== 'string' || !/^[A-Z]{1,32}$/.test(method)) throw new Error('Invalid HTTP method');
  if (typeof uri !== 'string' || !uri.startsWith('/') || uri.length > 8192 || /[\s#]/.test(uri)) throw new Error('An exact request URI is required');
  if (!Number.isInteger(status) || status < 100 || status > 599) throw new Error('Invalid HTTP status');
  return keccak256(concat([
    toUtf8Bytes(method), toUtf8Bytes(uri),
    keccak256(transcriptBody(transcript, 'rawRequest')),
    keccak256(transcriptBody(transcript, 'rawResponse')),
    toUtf8Bytes(String(status)),
  ]));
}

function signingDigest(proof, chainId, contractAddress) {
  const encoded = coder.encode(
    ['uint256', 'address', 'address', 'uint256', 'uint256', 'uint256', 'bytes32', 'bytes32', 'bytes32'],
    [chainId, contractAddress, proof.submitter, proof.agentId, proof.timestamp, proof.deadline,
      proof.taskHash, keccak256(concat(proof.dataHashes)), proof.frameworkHash],
  );
  // Pass bytes: hashMessage(hexString) would sign the textual hex characters.
  return hashMessage(getBytes(keccak256(encoded)));
}

/**
 * Offline, read-only verification. Trusted identity/domain values come ONLY from
 * options, never from the imported envelope. `now` is Unix seconds.
 * Envelope: { proof: headerOrSDKProof, transcript: { method, uri, status,
 * rawRequest, rawResponse } }. Base64 forms preserve non-UTF-8 response bytes.
 */
export function verifyAgentProof(envelope, options = {}) {
  const checks = [];
  const input = envelope?.proof ?? envelope?.header ?? envelope?.xAgentProof;
  if (!input) {
    return { checks: [check('presence', 'unverified', 'AgenticID 服務證明', '未擷取到 X-Agent-Proof。未宣稱任何 Agent 身份或 TEE 主張。')] };
  }
  let proof;
  try {
    proof = parseAgentProof(input);
  } catch {
    return { checks: [check('format', 'fail', '證明格式', '此證明格式錯誤或不支援。')] };
  }

  try {
    const matches = agentTaskHash(envelope.transcript) === proof.taskHash;
    checks.push(check('transcript', matches ? 'pass' : 'fail', '完整請求與回應',
      matches ? '原始 HTTP 請求、回應、URI、方法與狀態碼皆與簽署的 task hash 相符。' : 'HTTP transcript 與簽署的 task hash 不符。'));
  } catch {
    checks.push(check('transcript', 'fail', '完整請求與回應', '需要完整、大小受限且包含精確 body 位元組的 transcript；重新序列化過的 JSON 不算數。'));
  }

  let recoveredSigner;
  const hasDomain = options.chainId !== undefined && options.chainId !== '' && options.contractAddress;
  if (!hasDomain) {
    checks.push(check('signature', 'unverified', '簽章與網域', '請提供驗證端釘選的 chain ID 與 AgenticID 合約地址。收據內嵌的數值不可信任。'));
  } else {
    try {
      const chainId = uint256(options.chainId, 'chain ID');
      if (chainId === 0n) throw new Error('Invalid chain ID');
      const contractAddress = address(options.contractAddress, 'identity contract');
      recoveredSigner = recoverAddress(signingDigest(proof, chainId, contractAddress), proof.signature);
      if (!options.expectedSigner) {
        checks.push(check('signature', 'unverified', '簽章與身份', `已復原簽署者 ${recoveredSigner}；但沒有獨立釘選的 Agent 簽署地址可供比對。`));
      } else {
        const expectedSigner = address(options.expectedSigner, 'expected signer');
        const matches = recoveredSigner === expectedSigner;
        checks.push(check('signature', matches ? 'pass' : 'fail', '簽章與身份',
          matches ? `EIP-191 簽章與驗證端釘選的簽署者 ${expectedSigner} 及網域相符。` : '簽章與驗證端釘選的簽署者及網域不符。'));
      }
    } catch {
      checks.push(check('signature', 'fail', '簽章與身份', '簽章或驗證端提供的身份／網域無效。'));
    }
  }

  try {
    const now = uint256(options.now ?? Math.floor(Date.now() / 1000), 'current time');
    const future = proof.timestamp > now + 30n;
    const expired = proof.deadline <= now;
    checks.push(check('time', future ? 'fail' : expired ? 'warning' : 'pass', '證明時間窗',
      future ? '簽署的服務時間超過 30 秒時鐘容許誤差，落在未來。' : expired
        ? '提交時間窗已過期。這不會使歷史簽章失效，也不代表遭竄改。'
        : '簽署的提交時間窗尚未過期。這不代表 endpoint 目前狀態不變。'));
  } catch {
    checks.push(check('time', 'fail', '證明時間窗', '驗證端提供的時間無效；請提供 Unix 秒數。'));
  }

  checks.push(check('chain', 'unverified', '目前鏈上狀態與 TEE',
    '此離線核對不會查詢鏈上狀態、驗證目前的 iData／framework 允許清單，也不會執行遠端認證。身份釘選值須另行獨立建立。'));
  checks.push(check('scope', 'warning', '此服務證明的範圍',
    '此簽章將 Agent 的聲明與 HTTP 位元組綁定；不代表解說內容正確、付款安全，或外部 IFF 觀測的蒐集方式。單憑匯入的檔案，無法證明曾經歷真正的 sealed HTTP header 通道。'));

  return { checks, agentId: proof.agentId.toString(), recoveredSigner };
}
