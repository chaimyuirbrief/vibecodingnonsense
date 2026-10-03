// Bundle the worker the way the platform will (SPEC §11 "How to verify"):
// catches unresolved imports AND missing named exports across modules, which
// a syntax check does not. Also syntax-checks every browser script.

import { build } from 'esbuild';
import { readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
let failed = false;

async function bundle(entry, platform) {
  try {
    const r = await build({
      entryPoints: [path.join(root, entry)],
      bundle: true,
      write: false,
      format: 'esm',
      platform,
      target: 'es2022',
      logLevel: 'silent',
      metafile: true,
    });
    const bytes = r.outputFiles.reduce((n, f) => n + f.contents.length, 0);
    console.log(`✓ ${entry}  (${(bytes / 1024).toFixed(1)} KiB, ${Object.keys(r.metafile.inputs).length} modules)`);
  } catch (e) {
    failed = true;
    console.log(`✗ ${entry}`);
    for (const err of e.errors || [e]) console.log('   ', err.text || err.message, err.location ? `(${err.location.file}:${err.location.line})` : '');
  }
}

await bundle('worker.js', 'neutral');
for (const f of readdirSync(path.join(root, 'public', 'js'))) {
  if (f.endsWith('.js')) await bundle(path.join('public', 'js', f), 'browser');
}
process.exit(failed ? 1 : 0);
