import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { registerWitnessService } from './register-service.mjs';

async function registry(t, initial) {
  const directory = await mkdtemp(join(tmpdir(), 'iff-reg-'));
  const socketPath = join(directory, 's.sock');
  const state = { services: initial, writes: 0 };
  const server = http.createServer((request, response) => {
    assert.equal(request.url, '/services');
    if (request.method === 'GET') {
      response.end(JSON.stringify({ services: state.services }));
      return;
    }
    const chunks = [];
    request.on('data', (chunk) => chunks.push(chunk));
    request.on('end', () => {
      state.services = JSON.parse(Buffer.concat(chunks).toString()).services;
      state.writes += 1;
      response.end(JSON.stringify({ services: state.services }));
    });
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(socketPath, resolve); });
  t.after(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    await rm(directory, { recursive: true, force: true });
  });
  return { socketPath, state };
}

test('registers the bounded Witness service while retaining unrelated registry entries', async (t) => {
  const other = { path: '/api/other', method: 'GET', backend: 'http://127.0.0.1:9001', description: 'Already installed' };
  const { socketPath, state } = await registry(t, [other]);
  const result = await registerWitnessService({ socketPath });
  assert.equal(result.preservedServices, 1);
  assert.deepEqual(state.services[0], other);
  assert.equal(state.services[1].path, '/api/check');
  assert.equal(state.services[1].backend, 'http://127.0.0.1:8094');
  await registerWitnessService({ socketPath });
  assert.equal(state.services.length, 2);
});

test('does not replace an unrelated /api/check deployment without an explicit flag', async (t) => {
  const { socketPath, state } = await registry(t, [{ path: '/api/check', method: 'GET', backend: 'http://127.0.0.1:9999' }]);
  await assert.rejects(registerWitnessService({ socketPath }), /already points elsewhere/);
  assert.equal(state.writes, 0);
  await registerWitnessService({ socketPath, replace: true });
  assert.equal(state.services[0].method, 'POST');
});

test('refuses invalid socket paths and port values without attempting a connection', async () => {
  for (const socketPath of ['https://example.com/services', 'relative.sock', '/tmp/invalid\0.sock']) {
    await assert.rejects(registerWitnessService({ socketPath }), /Unix socket/);
  }
  for (const port of [0, 65536, 1.1, '8094']) await assert.rejects(registerWitnessService({ port }), /loopback port/);
});
