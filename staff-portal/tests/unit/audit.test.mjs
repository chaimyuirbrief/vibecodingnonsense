import { test, assert, run } from '../helpers/t.js';
import { makeEnvWithSchema } from '../helpers/env.js';
import { canonicalJson, iso } from '../../src/util.js';
import { sha256Hex } from '../../src/crypto.js';
import { audit, auditError, verifyChain, listAudit, getAuditEntry, listAuditForUser, scrub, formatError, GENESIS_HASH } from '../../src/audit.js';
import { UNDO_KINDS, undoFor, isUndoKind } from '../../src/undo.js';

const HOSTILE = [null, undefined, NaN, Infinity, '', '   ', 'abc', {}, [], true, 0, Symbol('x')];
const show = (v) => (typeof v === 'symbol' ? 'Symbol' : JSON.stringify(v) ?? String(v));

// The contract's definition, re-implemented here independently of audit.js.
const HASHED = ['seq', 'at', 'actor_id', 'actor_label', 'action', 'target_type', 'target_id', 'outcome', 'severity', 'detail', 'before_state', 'after_state', 'error', 'ip', 'device_id', 'session_ref', 'undo_kind', 'undo_payload', 'reverts_id', 'prev_hash'];
async function expectedHash(row) {
  const content = Object.fromEntries(HASHED.map((k) => [k, row[k]]));
  return sha256Hex(row.prev_hash + '\n' + canonicalJson(content));
}

function rcFor(env, extra = {}) {
  return {
    env,
    nowMs: env.__clock(),
    ip: '81.2.69.142',
    device: { id: 'dev_abc123' },
    session: { id: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2' },
    user: { id: 7, email: 'jane@acme.com' },
    ...extra,
  };
}

function rows(env) {
  return env.DB.q('SELECT * FROM audit_log ORDER BY seq');
}

async function fill(env, n, rc = rcFor(env)) {
  for (let i = 1; i <= n; i++) {
    await audit(rc, { action: i % 2 ? 'user.edit' : 'device.rename', target: { type: 'user', id: i }, detail: `Row ${i}`, before: { n: i - 1 }, after: { n: i } });
  }
}

async function quietly(fn) {
  const orig = console.error;
  const logged = [];
  console.error = (...a) => logged.push(a.map(String).join(' '));
  try {
    return { value: await fn(), logged };
  } finally {
    console.error = orig;
  }
}

// ---------------------------------------------------------------- undo.js

test('UNDO_KINDS is exactly the §4.2.1 list, frozen; undoFor refuses anything else', () => {
  assert.deepEqual([...UNDO_KINDS], [
    'user.status', 'user.role', 'user.temp_role', 'user.profile', 'device.status', 'device.label',
    'network.allow.add', 'network.allow.remove', 'network.allow.edit', 'network.block.add', 'network.block.remove',
    'setting', 'mfa.reset', 'role.create', 'role.edit', 'role.delete', 'streak', 'destination.add', 'destination.remove',
  ]);
  assert.ok(Object.isFrozen(UNDO_KINDS));
  assert.throws(() => UNDO_KINDS.push('x'));
  for (const k of UNDO_KINDS) {
    assert.equal(isUndoKind(k), true);
    assert.deepEqual(undoFor(k, { id: 1 }), { kind: k, payload: { id: 1 } });
  }
  for (const k of ['user.delete', 'gate.open', 'login.success', 'audit.revert', 'USER.STATUS', 'toString', '__proto__', ...HOSTILE]) {
    assert.equal(isUndoKind(k), false, show(k));
    assert.throws(() => undoFor(k, { id: 1 }), Error, show(k));
  }
  for (const p of [null, undefined, 'x', 1, [], true]) assert.throws(() => undoFor('user.status', p), Error, show(p));
  assert.throws(() => undoFor('setting', { key: 'gate_open', prior: '0' }), /gate_open/);
  assert.doesNotThrow(() => undoFor('setting', { key: 'access_mode', prior: null }));
});

// ---------------------------------------------------------------- the chain

test('the first row links to 64 zeros, and every hash is SHA-256(prev_hash + "\\n" + canonical content)', async () => {
  const env = await makeEnvWithSchema();
  const r1 = await audit(rcFor(env), { action: 'user.status', target: { type: 'user', id: 42 }, detail: 'Suspended bob', before: { status: 'active' }, after: { status: 'suspended' }, undo: undoFor('user.status', { userId: 42, status: 'active' }) });
  const r2 = await audit(rcFor(env), { action: 'login.success' });
  assert.deepEqual(r1, { id: 1, seq: 1 });
  assert.deepEqual(r2, { id: 2, seq: 2 });
  const [a, b] = rows(env);
  assert.equal(GENESIS_HASH, '0'.repeat(64));
  assert.equal(a.prev_hash, '0'.repeat(64));
  assert.equal(a.hash, await expectedHash(a));
  assert.equal(b.prev_hash, a.hash);
  assert.equal(b.hash, await expectedHash(b));
  assert.match(a.hash, /^[0-9a-f]{64}$/);
});

test('a chain of 200 rows verifies', async () => {
  const env = await makeEnvWithSchema();
  await fill(env, 200);
  assert.deepEqual(await verifyChain(env), { ok: true, checked: 200, head_seq: 200, broken_at: null });
  const empty = await makeEnvWithSchema();
  assert.deepEqual(await verifyChain(empty), { ok: true, checked: 0, head_seq: 0, broken_at: null });
});

test('tampering with one row’s detail is reported at exactly that row', async () => {
  const env = await makeEnvWithSchema();
  await fill(env, 200);
  env.DB.q("UPDATE audit_log SET detail = 'Nothing to see here' WHERE seq = 137");
  const v = await verifyChain(env);
  assert.equal(v.ok, false);
  assert.equal(v.checked, 136);
  assert.equal(v.head_seq, 200);
  assert.deepEqual(v.broken_at, { seq: 137, id: 137, reason: 'hash_mismatch' });
});

test('tampering with any hashed column is detected', async () => {
  const cols = { actor_id: 99, actor_label: 'x', action: 'login.fail', target_type: 'device', target_id: '9', outcome: 'failure', severity: 'critical', before_state: '{}', after_state: null, error: 'x', ip: '91.198.174.1', device_id: 'other', session_ref: 'zzz', undo_kind: 'user.status', undo_payload: '{}', reverts_id: 3, at: '2020-01-01T00:00:00.000Z' };
  for (const [col, val] of Object.entries(cols)) {
    const env = await makeEnvWithSchema();
    await fill(env, 12);
    env.DB.q(`UPDATE audit_log SET ${col} = ? WHERE seq = 6`, val);
    const v = await verifyChain(env);
    assert.deepEqual(v.broken_at, { seq: 6, id: 6, reason: 'hash_mismatch' }, col);
  }
});

test('deleting a middle row is detected; so is re-hashing a tampered row', async () => {
  const env = await makeEnvWithSchema();
  await fill(env, 200);
  env.DB.q('DELETE FROM audit_log WHERE seq = 100');
  let v = await verifyChain(env);
  assert.deepEqual(v.broken_at, { seq: 101, id: 101, reason: 'seq_gap' });
  assert.equal(v.checked, 99);

  // An attacker who edits a row AND recomputes its hash breaks the next link.
  const env2 = await makeEnvWithSchema();
  await fill(env2, 50);
  const row = env2.DB.q('SELECT * FROM audit_log WHERE seq = 20')[0];
  row.detail = 'Rewritten';
  env2.DB.q('UPDATE audit_log SET detail = ?, hash = ? WHERE seq = 20', row.detail, await expectedHash(row));
  v = await verifyChain(env2);
  assert.deepEqual(v.broken_at, { seq: 21, id: 21, reason: 'prev_mismatch' });

  // Renumbering seq to hide a deletion is caught by the hash (seq is hashed).
  const env3 = await makeEnvWithSchema();
  await fill(env3, 10);
  env3.DB.q('DELETE FROM audit_log WHERE seq = 10');
  env3.DB.q('DELETE FROM audit_log WHERE seq = 1');
  v = await verifyChain(env3);
  assert.deepEqual(v.broken_at, { seq: 2, id: 2, reason: 'seq_gap' }, 'the genesis row is missing');
});

test('a tampered seq cannot hide rows from verification', async () => {
  for (const val of ['abc', -1, 0, 5.5, 999, new Uint8Array([1])]) {
    const env = await makeEnvWithSchema();
    await fill(env, 10);
    env.DB.q('UPDATE audit_log SET seq = ? WHERE seq = 10', val);
    const v = await verifyChain(env);
    assert.equal(v.ok, false, `seq ${JSON.stringify(val)}`);
    assert.equal(v.broken_at.reason, 'seq_gap');
    assert.equal(v.broken_at.id, 10);
    if (val === 'abc') assert.equal(v.head_seq, null, 'an unreadable head is reported as such');
  }
  // Moving the genesis row's seq out of the way is caught at the start.
  const env = await makeEnvWithSchema();
  await fill(env, 4);
  env.DB.q('UPDATE audit_log SET seq = -1 WHERE seq = 1');
  assert.deepEqual((await verifyChain(env)).broken_at, { seq: -1, id: 1, reason: 'seq_gap' });
});

test('verification pages through more than one batch of 500', async () => {
  const env = await makeEnvWithSchema();
  await fill(env, 1105);
  assert.deepEqual(await verifyChain(env), { ok: true, checked: 1105, head_seq: 1105, broken_at: null });
  env.DB.q("UPDATE audit_log SET detail = 'x' WHERE seq = 1003");
  assert.deepEqual((await verifyChain(env)).broken_at, { seq: 1003, id: 1003, reason: 'hash_mismatch' });
});

// ---------------------------------------------------------------- concurrency

test('30 concurrent audit() calls → 30 rows, seq 1..30 contiguous, chain verifies', async () => {
  const env = await makeEnvWithSchema();
  const rc = rcFor(env);
  let inserts = 0;
  const orig = env.DB.prepare.bind(env.DB);
  env.DB.prepare = (sql) => {
    if (/^INSERT INTO audit_log/.test(sql)) inserts++;
    return orig(sql);
  };
  const results = await Promise.all(Array.from({ length: 30 }, (_, i) => audit(rc, { action: 'user.edit', detail: `c${i}` })));
  assert.equal(inserts, 30, 'writes from one request queue: no lost races, no retries');
  assert.ok(results.every((r) => r && Number.isInteger(r.seq)));
  assert.deepEqual(rows(env).map((r) => r.seq), Array.from({ length: 30 }, (_, i) => i + 1));
  assert.deepEqual(new Set(rows(env).map((r) => r.detail)).size, 30);
  assert.equal((await verifyChain(env)).ok, true);
});

test('writers in different requests race on the conditional insert and all land', async () => {
  const env = await makeEnvWithSchema();
  // Distinct ctx objects = distinct requests: no shared queue, real contention.
  // Deterministic, not lucky: an attempt only fails because another writer
  // succeeded, so with 8 writers nobody can lose more than 7 times.
  const calls = Array.from({ length: 8 }, (_, i) => audit(rcFor(env, { ctx: { waitUntil() {} } }), { action: 'user.edit', detail: `r${i}` }));
  const results = await Promise.all(calls);
  assert.ok(results.every((r) => r !== null), JSON.stringify(results));
  assert.deepEqual(rows(env).map((r) => r.seq), [1, 2, 3, 4, 5, 6, 7, 8]);
  assert.equal((await verifyChain(env)).ok, true);
});

test('a lost race re-reads the head; after 8 lost attempts it gives up, logs, and returns null', async () => {
  const env = await makeEnvWithSchema();
  await fill(env, 3);
  const orig = env.DB.prepare.bind(env.DB);
  let inserts = 0;
  let mode = 'always-lose';
  env.DB.prepare = (sql) => {
    const st = orig(sql);
    if (!/^INSERT INTO audit_log/.test(sql)) return st;
    return {
      bind: (...args) => {
        const bound = st.bind(...args);
        return {
          run: async () => {
            inserts++;
            if (mode === 'always-lose') return { success: true, meta: { changes: 0 } };
            if (mode === 'unique-once' && inserts === 1) throw new Error('UNIQUE constraint failed: audit_log.seq');
            return bound.run();
          },
        };
      },
    };
  };
  const { value, logged } = await quietly(() => audit(rcFor(env), { action: 'user.edit' }));
  assert.equal(value, null);
  assert.equal(inserts, 8, 'exactly 8 attempts');
  assert.ok(logged.some((l) => /gave up/.test(l)));
  assert.equal(rows(env).length, 3, 'no row written');

  inserts = 0;
  mode = 'unique-once';
  const r = await audit(rcFor(env), { action: 'user.edit' });
  assert.deepEqual(r, { id: 4, seq: 4 });
  assert.equal(inserts, 2, 'a UNIQUE(seq) error is a lost race: retried');
  assert.equal((await verifyChain(env)).ok, true);
});

// ---------------------------------------------------------------- never throws

test('audit() and auditError() never throw — even with the table gone', async () => {
  const env = await makeEnvWithSchema();
  env.DB.q('DROP TABLE audit_log');
  const { value, logged } = await quietly(async () => [await audit(rcFor(env), { action: 'user.edit' }), await auditError(rcFor(env), 'user.create', new Error('boom'))]);
  assert.deepEqual(value, [null, null]);
  assert.ok(logged.length >= 2, 'the failure is logged');
});

test('hostile contexts and entries resolve without throwing', async () => {
  const env = await makeEnvWithSchema();
  const evil = {
    get action() {
      throw new Error('getter');
    },
  };
  const { value } = await quietly(async () => {
    const out = [];
    for (const v of HOSTILE) {
      out.push(await audit(v, { action: 'x' }));
      out.push(await audit(rcFor(env), v));
      out.push(await auditError(v, v, v, v));
      out.push(await audit({ env: v }, { action: 'x' }));
    }
    out.push(await audit(rcFor(env), evil));
    out.push(await audit(rcFor(env, { user: evil, session: evil, device: evil }), { action: 'x' }));
    return out;
  });
  assert.ok(Array.isArray(value));
  assert.equal((await verifyChain(env)).ok, true, 'whatever was written still verifies');
  // A hostile entry field never becomes a value it shouldn't.
  await quietly(async () => {
    for (const v of HOSTILE) await audit(rcFor(env), { action: 'user.edit', outcome: v, severity: v, target: v, detail: v, before: v, after: v, error: v, undo: v, actorId: v, actorLabel: v, revertsId: v });
  });
  for (const r of rows(env)) {
    assert.ok(['success', 'failure', 'denied'].includes(r.outcome));
    assert.ok(['info', 'notice', 'warning', 'critical'].includes(r.severity));
    assert.ok(r.actor_id === null || Number.isInteger(r.actor_id));
    assert.ok(r.target_id === null || typeof r.target_id === 'string');
  }
  assert.equal((await verifyChain(env)).ok, true);
});

// ---------------------------------------------------------------- row contents

test('actor, request context, target and defaults are recorded as stored types', async () => {
  const env = await makeEnvWithSchema();
  await audit(rcFor(env), { action: 'user.status', outcome: 'denied', target: { type: 'user', id: 42 }, detail: 'Refused' });
  await audit(rcFor(env), { action: 'device.block', actorId: 3, actorLabel: 'Bob', target: { type: 'device', id: 'dev_9' } });
  await audit({ env, nowMs: env.__clock() }, { action: 'setup.complete', outcome: 'failure', severity: 'bogus' });
  await audit(rcFor(env), { action: 'x', actorId: null, actorLabel: null, outcome: 'maybe' });
  const [a, b, c, d] = rows(env);
  assert.equal(a.actor_id, 7);
  assert.equal(a.actor_label, 'jane@acme.com');
  assert.equal(a.target_type, 'user');
  assert.equal(a.target_id, '42', 'target_id is text');
  assert.equal(a.outcome, 'denied');
  assert.equal(a.severity, 'notice');
  assert.equal(a.ip, '81.2.69.142');
  assert.equal(a.device_id, 'dev_abc123');
  assert.equal(a.session_ref, 'a1b2c3d4e5f6');
  assert.equal(a.at, iso(env.__clock()));
  assert.equal(b.actor_id, 3);
  assert.equal(b.actor_label, 'Bob');
  assert.equal(b.target_id, 'dev_9');
  assert.equal(b.outcome, 'success');
  assert.equal(b.severity, 'info');
  assert.equal(c.actor_id, null);
  assert.equal(c.ip, null);
  assert.equal(c.session_ref, null);
  assert.equal(c.severity, 'warning', 'failure → warning by default; unknown severity ignored');
  assert.equal(d.actor_id, null, 'an explicit null actor is a system action');
  assert.equal(d.outcome, 'failure', 'an unrecognised outcome is not reported as success');
  // No full session id anywhere.
  assert.ok(!JSON.stringify(rows(env)).includes('a1b2c3d4e5f6a7b8'));
});

test('the real error is recorded: name, message, three stack frames, capped', async () => {
  const env = await makeEnvWithSchema();
  const err = new TypeError("Cannot read properties of undefined (reading 'id')");
  await auditError(rcFor(env), 'user.create', err, { target: { type: 'user', id: 5 } });
  const r = rows(env)[0];
  assert.equal(r.outcome, 'failure');
  assert.equal(r.severity, 'critical');
  assert.equal(r.action, 'user.create');
  assert.equal(r.target_id, '5');
  assert.equal(r.detail, 'Unexpected failure during user.create.');
  const lines = r.error.split('\n');
  assert.equal(lines[0], "TypeError: Cannot read properties of undefined (reading 'id')");
  assert.ok(lines.length >= 2 && lines.length <= 4, r.error);
  for (const l of lines.slice(1)) assert.match(l, /^at /);
  assert.equal(formatError(new Error('x'.repeat(5000))).length, 2000);
  assert.equal(formatError('D1_ERROR: no such column: foo'), 'D1_ERROR: no such column: foo');
  assert.match(formatError({ code: 7 }), /^Non-error thrown: /);
  assert.equal(formatError(null), null);
  await auditError(rcFor(env), 'user.edit', 'plain string failure', { detail: 'Could not save.' });
  assert.equal(rows(env)[1].error, 'plain string failure');
  assert.equal(rows(env)[1].detail, 'Could not save.');
});

test('detail is capped at 1000 characters', async () => {
  const env = await makeEnvWithSchema();
  await audit(rcFor(env), { action: 'x', detail: 'y'.repeat(5000) });
  assert.equal(rows(env)[0].detail.length, 1000);
});

test('scrub removes credential-looking keys at any depth, including inside arrays', async () => {
  const env = await makeEnvWithSchema();
  const before = {
    status: 'active',
    password: 'hunter2-secret-value',
    Password_Hash: 'deadbeefhash',
    profile: { name: 'Jane', api_token: 'tok_live_123', nested: [{ secret: 'shh-1', ok: 1 }, { backupCode: 'ABCDE-FGHJK', ok: 2 }] },
    cookieJar: 'sid=abc',
    sessionId: 'sess-xyz',
    salt: 'NaCl',
    list: [[{ totp_secret: 'JBSWY3DP' }]],
  };
  await audit(rcFor(env), { action: 'user.edit', before, after: { otp_code: '123456', status: 'suspended' } });
  const r = rows(env)[0];
  assert.deepEqual(JSON.parse(r.before_state), { list: [[{}]], profile: { name: 'Jane', nested: [{ ok: 1 }, { ok: 2 }] }, status: 'active' });
  assert.deepEqual(JSON.parse(r.after_state), { status: 'suspended' });
  const all = JSON.stringify(r);
  for (const s of ['hunter2', 'deadbeefhash', 'tok_live', 'shh-1', 'ABCDE-FGHJK', 'sid=abc', 'sess-xyz', 'NaCl', 'JBSWY3DP', '123456']) assert.ok(!all.includes(s), `leaked ${s}`);
  // The caller's object is untouched.
  assert.equal(before.password, 'hunter2-secret-value');
  // Cycles and depth do not throw.
  const cyc = { a: 1 };
  cyc.self = cyc;
  assert.deepEqual(scrub(cyc), { a: 1, self: '[cycle]' });
  let deep = { v: 1 };
  for (let i = 0; i < 50; i++) deep = { d: deep };
  assert.doesNotThrow(() => scrub(deep));
  assert.deepEqual(scrub({ f: () => 1, s: Symbol('x'), n: NaN, b: 10n, u: undefined }), { b: '10', f: null, n: null, s: null });
});

test('before/after larger than 16 KiB store a truncation marker', async () => {
  const env = await makeEnvWithSchema();
  await audit(rcFor(env), { action: 'x', before: { blob: 'z'.repeat(20000) }, after: { ok: true } });
  const r = rows(env)[0];
  const b = JSON.parse(r.before_state);
  assert.equal(b._truncated, true);
  assert.ok(b.bytes > 16 * 1024);
  assert.ok(!r.before_state.includes('zzzz'));
  assert.deepEqual(JSON.parse(r.after_state), { ok: true });
});

test('awkward strings survive storage byte-for-byte, so honest rows always verify', async () => {
  const env = await makeEnvWithSchema();
  await audit(rcFor(env), { action: 'x', detail: 'lone \uD800 surrogate, NUL \u0000 and emoji 🔥', before: { 'k\uDC00': 'v\u0000' } });
  // Numeric strings for INTEGER columns are normalised before hashing; SQLite
  // would otherwise store 42 while the hash covered "42".
  await audit(rcFor(env), { action: 'x', actorId: '42', revertsId: '1', target: { type: 'user', id: 42 } });
  const r = rows(env)[1];
  assert.equal(r.actor_id, 42);
  assert.equal(r.reverts_id, 1);
  assert.equal(r.target_id, '42');
  assert.equal((await verifyChain(env)).ok, true);
});

test('undo is stored as kind + canonical payload; a hand-built unknown kind is dropped', async () => {
  const env = await makeEnvWithSchema();
  await audit(rcFor(env), { action: 'user.status', undo: undoFor('user.status', { userId: 42, status: 'active' }) });
  const { value } = await quietly(() => audit(rcFor(env), { action: 'x', undo: { kind: 'user.delete', payload: { id: 1 } } }));
  assert.ok(value);
  const [a, b] = rows(env);
  assert.equal(a.undo_kind, 'user.status');
  assert.equal(a.undo_payload, canonicalJson({ userId: 42, status: 'active' }));
  assert.equal(b.undo_kind, null);
  assert.equal(b.undo_payload, null);
});

// ---------------------------------------------------------------- reading

async function seeded() {
  const env = await makeEnvWithSchema();
  const rc = rcFor(env);
  await audit(rc, { action: 'user.status', target: { type: 'user', id: 42 }, detail: 'Suspended Bob Smith', undo: undoFor('user.status', { userId: 42, status: 'PAYLOAD-MARKER-active' }) }); // 1
  await audit(rc, { action: 'user.role', target: { type: 'user', id: 43 }, detail: 'Made Ann an auditor', undo: undoFor('user.role', { userId: 43, role_id: 2, perm_grants: '[]', perm_denies: '[]' }) }); // 2
  await audit(rc, { action: 'users_x.weird', detail: '100% sure_thing' }); // 3
  await audit(rcFor(env, { user: { id: 8, email: 'ops@acme.com' } }), { action: 'login.fail', outcome: 'failure', target: { type: 'user', id: 7 }, detail: 'Wrong password' }); // 4
  await audit(rc, { action: 'device.block', target: { type: 'device', id: 'dev_1' }, detail: 'Blocked a laptop', severity: 'warning', undo: undoFor('device.status', { deviceId: 'dev_1', status: 'approved' }) }); // 5
  await audit(rc, { action: 'audit.revert', target: { type: 'audit', id: 2 }, revertsId: 2, outcome: 'failure', detail: 'Revert refused' }); // 6
  await audit(rc, { action: 'audit.revert', target: { type: 'audit', id: 1 }, revertsId: 1, detail: 'Reverted #1' }); // 7
  return env;
}

const KINDS = new Set(UNDO_KINDS);

test('listAudit never returns undo_payload, prev_hash or hash', async () => {
  const env = await seeded();
  const out = await listAudit(env, {}, { canRevert: true, revertibleKinds: KINDS });
  const text = JSON.stringify(out);
  assert.ok(!text.includes('PAYLOAD-MARKER'), 'undo payload leaked');
  for (const r of rows(env)) {
    assert.ok(!text.includes(r.hash), 'hash leaked');
  }
  for (const k of ['undo_payload', 'prev_hash', '"hash"', 'has_undo', 'before_state', 'after_state', 'session_ref']) assert.ok(!text.includes(k), `${k} leaked`);
  assert.deepEqual(Object.keys(out.entries[0]).sort(), [
    'action', 'actor_id', 'actor_label', 'after', 'at', 'before', 'detail', 'device_id', 'error', 'id', 'ip', 'outcome',
    'reverted_by', 'reverts_id', 'revertible', 'seq', 'severity', 'target_id', 'target_type', 'undo_kind',
  ].sort());
});

test('reverted_by and revertible are derived: only from the reverter set, only once, only for success', async () => {
  const env = await seeded();
  const byId = async (opts) => Object.fromEntries((await listAudit(env, {}, opts)).entries.map((e) => [e.id, e]));
  let e = await byId({ canRevert: true, revertibleKinds: KINDS });
  assert.equal(e[1].reverted_by, 7);
  assert.equal(e[1].revertible, false, 'already reverted');
  assert.equal(e[2].reverted_by, null, 'a failed revert does not count');
  assert.equal(e[2].revertible, true);
  assert.equal(e[5].revertible, true);
  assert.equal(e[3].revertible, false, 'no undo');
  assert.equal(e[4].revertible, false);
  assert.equal(e[7].revertible, false, 'reverts are not revertible');
  assert.equal(e[7].reverts_id, 1);
  e = await byId({ canRevert: false, revertibleKinds: KINDS });
  assert.ok(Object.values(e).every((x) => x.revertible === false), 'without audit.revert nothing is offered');
  e = await byId({ canRevert: true, revertibleKinds: new Set(['user.role']) });
  assert.equal(e[2].revertible, true);
  assert.equal(e[5].revertible, false, 'offered from the reverter catalogue, not from undo_kind');
  e = await byId({ canRevert: 'yes', revertibleKinds: KINDS });
  assert.ok(Object.values(e).every((x) => x.revertible === false));
  e = await byId(undefined);
  assert.ok(Object.values(e).every((x) => x.revertible === false));
});

test('listAudit filters: prefix action (LIKE-escaped), actor, target, outcome, severity, q, cursor, limit', async () => {
  const env = await seeded();
  const ids = async (f) => (await listAudit(env, f)).entries.map((e) => e.id);
  assert.deepEqual(await ids({}), [7, 6, 5, 4, 3, 2, 1]);
  assert.deepEqual(await ids({ action: 'user.' }), [2, 1]);
  assert.deepEqual(await ids({ action: 'user' }), [3, 2, 1]);
  assert.deepEqual(await ids({ action: 'user_' }), [], "'_' is literal, not a wildcard");
  assert.deepEqual(await ids({ action: 'users_' }), [3]);
  assert.deepEqual(await ids({ action: '%' }), [], "'%' is literal");
  assert.deepEqual(await ids({ actor: '8' }), [4]);
  assert.deepEqual(await ids({ actor: 7 }), [7, 6, 5, 3, 2, 1]);
  assert.deepEqual(await ids({ target_type: 'user', target_id: '42' }), [1]);
  assert.deepEqual(await ids({ target_type: 'user', target_id: 7 }), [4]);
  assert.deepEqual(await ids({ outcome: 'failure' }), [6, 4]);
  assert.deepEqual(await ids({ severity: 'warning' }), [6, 5, 4]);
  assert.deepEqual(await ids({ q: 'bob' }), [1], 'case-insensitive substring of detail');
  assert.deepEqual(await ids({ q: '100%' }), [3]);
  assert.deepEqual(await ids({ q: '0%' }), [3]);
  assert.deepEqual(await ids({ q: '_' }), [3]);
  assert.deepEqual(await ids({ before_seq: '5' }), [4, 3, 2, 1]);
  // Blank filters are no filter; impossible ones match nothing.
  assert.deepEqual(await ids({ action: '', actor: '  ', outcome: null, q: undefined }), [7, 6, 5, 4, 3, 2, 1]);
  for (const f of [{ actor: 'abc' }, { actor: '-1' }, { outcome: 'win' }, { severity: 'loud' }, { before_seq: 'abc' }, { action: ['user'] }, { q: {} }, { target_id: {} }, { target_type: 5 }]) {
    assert.deepEqual(await ids(f), [], JSON.stringify(f));
  }
});

test('listAudit pages with next_before_seq; limit defaults to 50 and is capped at 200', async () => {
  const env = await makeEnvWithSchema();
  await fill(env, 260);
  let out = await listAudit(env, {});
  assert.equal(out.entries.length, 50);
  assert.equal(out.entries[0].seq, 260);
  assert.equal(out.next_before_seq, 211);
  out = await listAudit(env, { before_seq: out.next_before_seq, limit: '100' });
  assert.equal(out.entries[0].seq, 210);
  assert.equal(out.entries.length, 100);
  assert.equal(out.next_before_seq, 111);
  out = await listAudit(env, { limit: 1000 });
  assert.equal(out.entries.length, 200);
  out = await listAudit(env, { before_seq: 11, limit: 10 });
  assert.equal(out.entries.length, 10);
  assert.equal(out.next_before_seq, null, 'nothing left');
  for (const v of HOSTILE) {
    out = await listAudit(env, { limit: v });
    assert.equal(out.entries.length, 50, `limit ${show(v)}`);
  }
  for (const v of HOSTILE) await listAudit(env, v);
  assert.deepEqual(out.entries[0].before, { n: 259 }, 'states are parsed');
});

test('getAuditEntry returns the full row with undo_payload parsed, for the revert endpoint', async () => {
  const env = await seeded();
  const e = await getAuditEntry(env, 1);
  assert.deepEqual(e.undo_payload, { userId: 42, status: 'PAYLOAD-MARKER-active' });
  assert.equal(e.undo_kind, 'user.status');
  assert.equal(e.reverted_by, 7);
  assert.equal(e.undo_unreadable, false);
  assert.equal((await getAuditEntry(env, '2')).reverted_by, null);
  assert.equal(await getAuditEntry(env, 999), null);
  for (const v of HOSTILE) assert.equal(await getAuditEntry(env, v), null, show(v));
  env.DB.q("UPDATE audit_log SET undo_payload = '{broken' WHERE id = 2");
  const broken = await getAuditEntry(env, 2);
  assert.equal(broken.undo_payload, null);
  assert.equal(broken.undo_unreadable, true, 'present but unreadable: the revert must refuse');
});

test('listAuditForUser: what they did and what was done to them — a narrow set of columns', async () => {
  const env = await seeded();
  let out = await listAuditForUser(env, 7);
  assert.deepEqual(out.map((r) => r.id), [7, 6, 5, 4, 3, 2, 1]);
  out = await listAuditForUser(env, 42);
  assert.deepEqual(out.map((r) => r.id), [1]);
  assert.deepEqual(Object.keys(out[0]).sort(), ['action', 'at', 'detail', 'id', 'ip', 'outcome']);
  out = await listAuditForUser(env, 8, 1);
  assert.deepEqual(out.map((r) => r.id), [4]);
  assert.equal((await listAuditForUser(env, 7, 2)).length, 2);
  assert.ok(!JSON.stringify(await listAuditForUser(env, 7)).includes('PAYLOAD-MARKER'));
  for (const v of HOSTILE) {
    assert.deepEqual(await listAuditForUser(env, v), [], show(v));
    assert.equal((await listAuditForUser(env, 7, v)).length, 7, `limit ${show(v)}`);
  }
});

await run();
