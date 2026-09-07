import http from 'node:http';
import { isAbsolute } from 'node:path';
import { pathToFileURL } from 'node:url';

const MAX_RESPONSE_BYTES = 64 * 1024;
const SERVICE_PATH = '/api/check';

/** All requests use socketPath; this helper has no network-host input. */
function socketRequest(socketPath, method, payload) {
  return new Promise((resolve, reject) => {
    const body = payload === undefined ? undefined : JSON.stringify(payload);
    const request = http.request({
      socketPath, method, path: '/services', timeout: 5000,
      headers: body === undefined ? {} : { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) },
    }, (response) => {
      const chunks = [];
      let size = 0;
      response.on('data', (chunk) => {
        size += chunk.length;
        if (size > MAX_RESPONSE_BYTES) request.destroy(new Error('Sealed registry response exceeded the size limit'));
        else chunks.push(chunk);
      });
      response.on('error', reject);
      response.on('end', () => {
        if (response.statusCode < 200 || response.statusCode >= 300) {
          reject(new Error(`Sealed registry returned HTTP ${response.statusCode}`));
          return;
        }
        try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
        catch { reject(new Error('Sealed registry returned invalid JSON')); }
      });
    });
    request.on('timeout', () => request.destroy(new Error('Sealed registry timed out')));
    request.on('error', reject);
    request.end(body);
  });
}

export async function registerWitnessService({ socketPath = process.env.SEAL_SIGN_SOCK || '/run/seal-sign.sock', port = 8094, replace = false } = {}) {
  if (typeof socketPath !== 'string' || !isAbsolute(socketPath) || socketPath.includes('\0') || socketPath.length > 1024) throw new Error('A local absolute Unix socket path is required');
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('A valid loopback port is required');
  const backend = `http://127.0.0.1:${port}`;
  const response = await socketRequest(socketPath, 'GET');
  if (!Array.isArray(response?.services) || response.services.length > 128 || response.services.some((service) => !service || typeof service !== 'object' || typeof service.path !== 'string')) {
    throw new Error('Sealed registry returned an invalid service list');
  }
  const existing = response.services.find((service) => service.path === SERVICE_PATH);
  if (existing && (existing.backend !== backend || existing.method !== 'POST') && !replace) {
    throw new Error('/api/check already points elsewhere; inspect the registry before explicitly using --replace');
  }
  const service = {
    path: SERVICE_PATH, method: 'POST', backend,
    description: 'IFF Witness: explain a public x402 evidence snapshot and return a verifiable receipt.',
  };
  // /services replaces the whole registry: retain every unrelated entry.
  const services = [...response.services.filter((entry) => entry.path !== SERVICE_PATH), service];
  await socketRequest(socketPath, 'POST', { services });
  return { path: SERVICE_PATH, method: service.method, backend, preservedServices: services.length - 1 };
}

async function main() {
  const options = {};
  const args = process.argv.slice(2);
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === '--help') {
      process.stdout.write('Run inside an existing 0G Sealed Sandbox:\nnode agentic/register-service.mjs [--socket /run/seal-sign.sock] [--port 8094] [--replace]\n');
      return;
    }
    if (argument === '--replace') options.replace = true;
    else if (argument === '--socket' && args[index + 1]) options.socketPath = args[++index];
    else if (argument === '--port' && /^\d+$/.test(args[index + 1] ?? '')) options.port = Number(args[++index]);
    else throw new Error('Unknown or incomplete option; use --help');
  }
  const result = await registerWitnessService(options);
  process.stdout.write(`Registered ${result.method} ${result.path} at ${result.backend}; preserved ${result.preservedServices} other services.\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`Registration failed: ${error.message}\n`);
    process.exitCode = 1;
  });
}
