import { readFile, writeFile, mkdir, stat } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { signExample, verifyExample, addSpace, MAX_ARTIFACT_BYTES, MAX_BUNDLE_BYTES } from '../client/apostille-example.mjs';

async function boundedFile(path, maximum) {
  const info = await stat(path);
  if (!info.isFile() || info.size > maximum) throw new Error(`Expected a regular file of at most ${maximum} bytes: ${path}`);
  const bytes = new Uint8Array(await readFile(path));
  if (bytes.length > maximum) throw new Error('File grew beyond the size limit.');
  return bytes;
}
const decode = bytes => new TextDecoder('utf-8', { fatal: true }).decode(bytes);
const save = (path, bytes) => writeFile(path, bytes, { flag: 'wx', mode: 0o600 });
const [command, first, second, ...extra] = process.argv.slice(2);
if (extra.length || !first || !['demo', 'sign', 'verify'].includes(command) || (command === 'demo' ? second : !second)) {
  console.error('Usage:\n  npm run apostille -- demo <new-output-directory>\n  npm run apostille -- sign <original-file> <new-bundle-file>\n  npm run apostille -- verify <bundle-file> <original-file>\nOffline producer-only example. New keys are ephemeral; no account, issuance or publication.');
  process.exitCode = 2;
} else {
  try {
    if (command === 'demo') {
      const directory = resolve(first);
      const original = await boundedFile(new URL('../examples/agentic-demo-bundle.json', import.meta.url), MAX_ARTIFACT_BYTES);
      const bundle = await signExample(original);
      // Refuse an existing directory so a demo never overwrites the caller's files.
      await mkdir(directory, { mode: 0o700 });
      await save(join(directory, 'witness-original.json'), original);
      await save(join(directory, 'apostille-bundle.json'), bundle);
      await save(join(directory, 'witness-with-space.json'), addSpace(original));
      console.log(JSON.stringify({ example: 'public rehearsal fixture; not live IFF/0G proof', output_directory: directory,
        original: await verifyExample(bundle, original), changed: await verifyExample(bundle, addSpace(original)) }, null, 2));
    } else if (command === 'sign') {
      const original = await boundedFile(first, MAX_ARTIFACT_BYTES);
      const bundle = await signExample(original);
      await save(second, bundle);
      console.log(JSON.stringify(await verifyExample(bundle, original), null, 2));
    } else {
      const bundle = decode(await boundedFile(first, MAX_BUNDLE_BYTES));
      const original = await boundedFile(second, MAX_ARTIFACT_BYTES);
      const result = await verifyExample(bundle, original);
      console.log(JSON.stringify(result, null, 2));
      process.exitCode = result.original_matches ? 0 : 1;
    }
  } catch (error) {
    console.error(error.message);
    process.exitCode = ['ENOENT', 'EEXIST', 'EACCES', 'ENOTDIR'].includes(error.code) ? 2 : 1;
  }
}
