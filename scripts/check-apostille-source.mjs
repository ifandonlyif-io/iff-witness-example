import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
const root = new URL('../client/third-party/apostille/', import.meta.url);
const manifest = JSON.parse(await readFile(new URL('SOURCE.json', root), 'utf8'));
for (const [name, file] of Object.entries(manifest.files)) {
  const bytes = await readFile(new URL(name, root));
  if (createHash('sha256').update(bytes).digest('hex') !== file.sha256) {
    throw new Error(`Pinned Apostille source drift: ${name}. Update from a reviewed release, not locally.`);
  }
}
console.log(`Apostille source matches ${manifest.tag} (${manifest.commit}).`);
