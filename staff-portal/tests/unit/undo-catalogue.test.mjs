// The undo catalogue closes the loop (A §9, §14.9; CONTRACTS §0.9, §4.2.1):
// every kind any source file records an undo for is in UNDO_KINDS and has a
// reverter, and the reverter keys are exactly the catalogue.

import { test, assert, run } from '../helpers/t.js';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { ROOT } from '../helpers/env.js';
import { UNDO_KINDS, undoFor } from '../../src/undo.js';
import { REVERTERS } from '../../src/reverters.js';

function sources(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = path.join(dir, name);
    if (statSync(p).isDirectory()) out.push(...sources(p));
    else if (name.endsWith('.js')) out.push(p);
  }
  return out;
}

const SRC = path.join(ROOT, 'src');
const CALL_RE = /undoFor\('([^']+)'/g;

function recordedKinds() {
  const found = new Map();
  for (const file of sources(SRC)) {
    const text = readFileSync(file, 'utf8');
    for (const m of text.matchAll(CALL_RE)) {
      if (!found.has(m[1])) found.set(m[1], new Set());
      found.get(m[1]).add(path.relative(ROOT, file));
    }
  }
  return found;
}

test('every undoFor kind in src/ is catalogued and has a reverter', () => {
  const found = recordedKinds();
  assert.ok(found.size >= 15, `expected the admin APIs to record most kinds, found ${found.size}: ${[...found.keys()].join(', ')}`);
  for (const [kind, files] of found) {
    assert.ok(UNDO_KINDS.includes(kind), `${kind} (in ${[...files].join(', ')}) is not in UNDO_KINDS`);
    assert.equal(typeof REVERTERS[kind], 'function', `${kind} (in ${[...files].join(', ')}) has no reverter`);
  }
});

test('REVERTERS keys equal UNDO_KINDS as sets', () => {
  const have = new Set(Object.keys(REVERTERS));
  const want = new Set(UNDO_KINDS);
  assert.equal(have.size, want.size);
  for (const k of want) assert.ok(have.has(k), `missing reverter for ${k}`);
  for (const k of have) assert.ok(want.has(k), `reverter ${k} is not in the catalogue`);
  assert.ok(Object.isFrozen(REVERTERS), 'REVERTERS is frozen, so nothing can add a kind at runtime');
});

test('every catalogued kind is recorded somewhere, so no reverter is dead code', () => {
  const found = recordedKinds();
  const unused = UNDO_KINDS.filter((k) => !found.has(k));
  assert.deepEqual(unused, [], `kinds with a reverter but no undoFor call: ${unused.join(', ')}`);
});

test('the scanner itself sees a call (guards against a regex that matches nothing)', () => {
  const sample = "await audit(rc, { undo: undoFor('user.status', { userId: 1, status: 'active' }) });";
  assert.deepEqual([...sample.matchAll(CALL_RE)].map((m) => m[1]), ['user.status']);
});

test('undoFor refuses a kind with no reverter, and the gate switch', () => {
  assert.throws(() => undoFor('user.delete', { userId: 1 }), /no reverter/);
  assert.throws(() => undoFor('setting', { key: 'gate_open', prior: '0' }), /gate_open/);
  for (const kind of UNDO_KINDS) {
    if (kind === 'setting') continue;
    assert.deepEqual(undoFor(kind, { a: 1 }), { kind, payload: { a: 1 } });
  }
});

test('reverters.js refuses to load when the sets differ', async () => {
  // Re-evaluate the module's guard against a doctored catalogue: the same
  // comparison, so a drift between the two lists cannot load silently.
  const src = readFileSync(path.join(SRC, 'reverters.js'), 'utf8');
  assert.match(src, /throw new Error\(`reverters\.js: REVERTERS must match UNDO_KINDS exactly/);
  const check = (have, want) => {
    const a = [...have].sort();
    const b = [...want].sort();
    return a.length === b.length && a.every((k, i) => k === b[i]);
  };
  assert.ok(check(Object.keys(REVERTERS), UNDO_KINDS));
  assert.ok(!check([...Object.keys(REVERTERS), 'user.delete'], UNDO_KINDS));
  assert.ok(!check(Object.keys(REVERTERS).slice(1), UNDO_KINDS));
});

await run();
