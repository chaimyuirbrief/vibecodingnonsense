// Minimal harness. Every suite ends with `await run()`, which prints exactly
// one line "N passed, M failed". The runner treats a suite that never prints
// that line — or prints "0 passed, 0 failed" — as BROKEN, not as passing
// (SPEC §13.5): a suite whose imports broke reports nothing, and silence must
// never read as success.
//
//   import { test, assert, run } from '../helpers/t.js';
//   test('does a thing', async () => { assert.equal(1, 1); });
//   await run();
//
// TEST_ONLY=substring runs only matching test names.

import assert from 'node:assert/strict';

export { assert };

const tests = [];

export function test(name, fn) {
  if (typeof fn !== 'function') throw new TypeError(`test '${name}' has no function`);
  tests.push({ name, fn });
}

// Drain fire-and-forget promises (pages deliberately do not await some work).
export async function drain(rounds = 12) {
  for (let i = 0; i < rounds; i++) await new Promise((r) => setTimeout(r, 0));
}

export async function run() {
  let passed = 0;
  let failed = 0;
  const only = process.env.TEST_ONLY;
  for (const { name, fn } of tests) {
    if (only && !name.includes(only)) continue;
    try {
      await fn();
      passed++;
    } catch (e) {
      failed++;
      const msg = (e && e.stack ? e.stack : String(e)).split('\n').slice(0, 8).join('\n      ');
      console.log(`  ✗ ${name}\n      ${msg}`);
    }
  }
  console.log(`${passed} passed, ${failed} failed`);
  process.exitCode = failed ? 1 : 0;
}
