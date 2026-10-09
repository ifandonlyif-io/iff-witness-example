import './check-apostille-source.mjs';
import { readFile } from 'node:fs/promises';
import { build } from 'esbuild';
import { fileURLToPath } from 'node:url';
const apostilleLicense = await readFile(new URL('../client/third-party/apostille/LICENSE', import.meta.url), 'utf8');
const root = fileURLToPath(new URL('../', import.meta.url));
await build({
  absWorkingDir: root, entryPoints: ['client/app.mjs','client/settings.mjs'], outdir: 'web',
  bundle: true, format: 'esm', platform: 'browser', target: ['es2022'],
  minify: true, legalComments: 'eof', logLevel: 'info',
});
await build({
  absWorkingDir: root, entryPoints: ['client/apostille-demo.mjs'], outdir: 'web',
  bundle: true, format: 'esm', platform: 'browser', target: ['es2022'],
  loader: { '.json': 'text' },
  banner: { js: '/*! Apostille Core 0.3 (verifies 0.1–0.3) · v0.4.0-alpha.1\n' + apostilleLicense + '*/' },
  minify: true, legalComments: 'eof', logLevel: 'info',
});
