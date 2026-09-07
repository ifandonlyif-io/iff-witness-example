import test from 'node:test';
import assert from 'node:assert/strict';
import { validAPIKey, parseIFFKeyIDs } from './settings-values.mjs';

test('settings accepts bounded single-line bearer tokens only', () => {
  for (const key of ['demo-key_123', 'abc.DEF/ghi+~==', 'a'.repeat(512)]) assert.equal(validAPIKey(key), true);
  for (const key of ['', 'a'.repeat(513), 'key with space', 'key\nheader', 'abc=def', null, '私鑰']) assert.equal(validAPIKey(key), false);
});

test('public fingerprint input trims, splits and deduplicates canonical IDs', () => {
  const a = `sha256:${'a'.repeat(64)}`;
  const b = `sha256:${'1'.repeat(64)}`;
  assert.deepEqual(parseIFFKeyIDs(` ${a}\r\n${b}, ${a} `), [a, b]);
  assert.deepEqual(parseIFFKeyIDs(' \n, '), []);
  assert.equal(parseIFFKeyIDs(Array(16).fill(a).join('\n')).length, 1);
  assert.throws(() => parseIFFKeyIDs(Array(17).fill(a).join('\n')), /16/);
});

test('public fingerprint input rejects secrets, raw keys and noncanonical values', () => {
  for (const value of ['demo-secret', '0x' + 'a'.repeat(64), 'sha256:' + 'A'.repeat(64), 'sha256:' + 'a'.repeat(63), 'sha256:' + 'a'.repeat(65), 'sha256:' + 'g'.repeat(64), 'sha256:' + 'a'.repeat(32) + '\t' + 'a'.repeat(32)]) {
    assert.throws(() => parseIFFKeyIDs(value), /完整公鑰指紋/);
  }
});
