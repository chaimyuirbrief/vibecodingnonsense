// One command for every suite: `npm test` (optionally `npm test -- streak`
// to run only files whose path contains "streak").
//
// Three outcomes per suite, not two (SPEC §13.5): passed, failed, and DID NOT
// REPORT. A suite whose imports broke prints nothing and exits; a runner that
// only greps for failures calls that success. This one does not. A suite that
// reports zero tests is also broken.

import { spawn } from 'node:child_process';
import { readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import os from 'node:os';

const here = path.dirname(fileURLToPath(import.meta.url));
const filter = process.argv.slice(2).filter((a) => !a.startsWith('-'));

function walk(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = path.join(dir, name);
    if (statSync(p).isDirectory()) {
      if (name === 'helpers' || name === 'fixtures') continue;
      out.push(...walk(p));
    } else if (name.endsWith('.test.mjs')) out.push(p);
  }
  return out.sort();
}

const files = walk(here).filter((f) => !filter.length || filter.some((s) => f.includes(s)));
if (!files.length) {
  console.log('No test files matched.');
  process.exit(1);
}

function runOne(file) {
  return new Promise((resolve) => {
    const started = Date.now();
    const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', file], {
      cwd: path.resolve(here, '..'),
      env: { ...process.env, NODE_NO_WARNINGS: '1' },
    });
    let out = '';
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (out += d));
    const timer = setTimeout(() => child.kill('SIGKILL'), 15 * 60 * 1000);
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ file, code, out, ms: Date.now() - started });
    });
  });
}

const concurrency = Math.max(1, Math.min(4, os.cpus().length));
const queue = [...files];
const results = [];
await Promise.all(
  Array.from({ length: concurrency }, async () => {
    while (queue.length) results.push(await runOne(queue.shift()));
  }),
);
results.sort((a, b) => a.file.localeCompare(b.file));

let passed = 0;
let failed = 0;
let broken = 0;
for (const r of results) {
  const rel = path.relative(path.resolve(here, '..'), r.file);
  const m = r.out.match(/^(\d+) passed, (\d+) failed$/m);
  if (!m) {
    broken++;
    console.log(`✗ ${rel}  DID NOT REPORT — it failed to run (exit ${r.code})`);
    console.log(r.out.split('\n').slice(-25).map((l) => '    ' + l).join('\n'));
    continue;
  }
  const p = Number(m[1]);
  const f = Number(m[2]);
  if (p === 0 && f === 0) {
    broken++;
    console.log(`✗ ${rel}  REPORTED ZERO TESTS`);
    continue;
  }
  passed += p;
  failed += f;
  if (f > 0 || r.code !== 0) {
    if (f === 0) broken++;
    console.log(`✗ ${rel}  ${p} passed, ${f} failed (exit ${r.code})`);
    console.log(r.out.split('\n').filter((l) => l.trim()).slice(0, 60).map((l) => '    ' + l).join('\n'));
  } else {
    console.log(`✓ ${rel}  ${p} passed  (${(r.ms / 1000).toFixed(1)}s)`);
  }
}

console.log(`\n${results.length} suites: ${passed} tests passed, ${failed} failed, ${broken} suites broken`);
process.exit(failed || broken ? 1 : 0);
