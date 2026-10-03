import { test, assert, run } from '../helpers/t.js';
import { makeEnvWithSchema } from '../helpers/env.js';
import { iso, MINUTE, DAY } from '../../src/util.js';
import { audit, getAuditEntry } from '../../src/audit.js';
import { undoFor } from '../../src/undo.js';
import { beginTotp, confirmTotp, checkTotp, totpCode, base32Decode, TOTP_STEP_MS } from '../../src/mfa/totp.js';
import { consumeBackupCode, generateBackupCodes, storeBackupCodes } from '../../src/mfa/backup.js';
import { addDestination } from '../../src/mfa/otp.js';
import {
  userFactors, availableMethods, hasStrongFactor, canDropFactor, resetFactors, restoreFactors,
} from '../../src/mfa/factors.js';

const HOSTILE = [null, undefined, NaN, Infinity, '', '   ', 'abc', {}, [], true, 0, Symbol('x')];
const show = (v) => (typeof v === 'symbol' ? 'Symbol' : JSON.stringify(v) ?? String(v));
const TWILIO = { TWILIO_ACCOUNT_SID: 'test-twilio-account-sid', TWILIO_AUTH_TOKEN: 'twilio-token-secret', TWILIO_FROM: '+15005550006' };
const RESEND = { RESEND_API_KEY: 're_test_key_secret', MAIL_FROM: 'portal@acme.com' };
const stepOf = (ms) => Math.floor(ms / TOTP_STEP_MS);

async function setup(vars = { ...TWILIO, ...RESEND }) {
  const env = await makeEnvWithSchema({ vars });
  const calls = [];
  env.__fetch = async (url, init) => {
    calls.push(url);
    return new Response('{}', { status: 201 });
  };
  env.fetchCalls = calls;
  const uid = await addUser(env);
  return { env, uid, rc: () => ({ env, nowMs: env.__clock(), user: { id: 1, email: 'admin@acme.com' } }) };
}

async function addUser(env, email = 'jane@acme.com') {
  const t = iso(env.__clock());
  const r = await env.DB.prepare(
    "INSERT INTO users (email, full_name, role_id, status, created_at, updated_at) VALUES (?, 'Jane Doe', 1, 'active', ?, ?)",
  )
    .bind(email, t, t)
    .run();
  return r.meta.last_row_id;
}

function addPasskey(env, uid, id) {
  env.DB.q(
    "INSERT INTO user_passkeys (id, user_id, public_key, algorithm, sign_count, aaguid, transports, label, created_at, last_used_at) VALUES (?, ?, ?, -7, 3, 'aa', '[\"internal\"]', 'MacBook', ?, NULL)",
    id, uid, `{"kty":"EC","id":"${id}"}`, iso(env.__clock()),
  );
}

function addGrace(env, uid, device, tier = 2) {
  const t = env.__clock();
  env.DB.q('INSERT INTO mfa_grace (user_id, device_id, tier, verified_at, expires_at) VALUES (?, ?, ?, ?, ?)', uid, device, tier, iso(t), iso(t + DAY));
}

async function enrolTotp(env, uid) {
  const b = await beginTotp({ env, nowMs: env.__clock() }, uid);
  const secret = base32Decode(b.secret_b32);
  const r = await confirmTotp({ env, nowMs: env.__clock() }, uid, await totpCode(secret, stepOf(env.__clock())));
  return { secret, backup: r.backup_codes };
}

const snapshot = (env, uid) => ({
  totp: env.DB.q('SELECT * FROM user_totp WHERE user_id = ?', uid),
  passkeys: env.DB.q('SELECT * FROM user_passkeys WHERE user_id = ? ORDER BY id', uid),
  backup: env.DB.q('SELECT * FROM backup_codes WHERE user_id = ? ORDER BY id', uid),
  grace: env.DB.q('SELECT * FROM mfa_grace WHERE user_id = ? ORDER BY device_id', uid),
  dests: env.DB.q('SELECT * FROM code_destinations WHERE user_id = ? ORDER BY id', uid),
});

// ---------------------------------------------------------------- reading

test('userFactors: nothing enrolled → all zero; hostile ids → all zero', async () => {
  const { env, uid } = await setup();
  const none = { totp: false, totpUnreadable: false, passkeys: 0, backup: 0, destinations: 0 };
  assert.deepEqual(await userFactors(env, uid), none);
  for (const v of HOSTILE) assert.deepEqual(await userFactors(env, v), none, show(v));
});

test('userFactors: counts confirmed TOTP, passkeys, unused backup codes and USABLE destinations', async () => {
  const { env, uid, rc } = await setup(RESEND);
  await enrolTotp(env, uid);
  addPasskey(env, uid, 'p1');
  addPasskey(env, uid, 'p2');
  await addDestination(rc(), uid, { kind: 'sms', address: '+15550101234' }); // SMS not configured
  await addDestination(rc(), uid, { kind: 'email', address: 'jane@acme.com' });
  assert.deepEqual(await userFactors(env, uid), { totp: true, totpUnreadable: false, passkeys: 2, backup: 10, destinations: 1 });
});

test('an unconfirmed authenticator is not a factor', async () => {
  const { env, uid } = await setup({});
  await beginTotp({ env, nowMs: env.__clock() }, uid);
  assert.equal((await userFactors(env, uid)).totp, false);
  assert.deepEqual(await availableMethods(env, uid), []);
  assert.equal(await hasStrongFactor(env, uid), false);
});

test('an unreadable authenticator is flagged, never counted (decrypt failure or unreadable floor)', async () => {
  const { env, uid } = await setup({});
  await enrolTotp(env, uid);
  env.DB.q("UPDATE user_totp SET secret_enc = 'v1.junk.junk' WHERE user_id = ?", uid);
  let f = await userFactors(env, uid);
  assert.deepEqual([f.totp, f.totpUnreadable], [false, true]);
  assert.ok(!(await availableMethods(env, uid)).includes('totp'));
  assert.equal(await hasStrongFactor(env, uid), false);
  const { env: e2, uid: u2 } = await setup({});
  await enrolTotp(e2, u2);
  e2.DB.q("UPDATE user_totp SET last_counter = 'garbage' WHERE user_id = ?", u2);
  f = await userFactors(e2, u2);
  assert.deepEqual([f.totp, f.totpUnreadable], [false, true]);
});

test('availableMethods: strongest first — passkey, totp, backup, email, sms', async () => {
  const { env, uid, rc } = await setup();
  await addDestination(rc(), uid, { kind: 'sms', address: '+15550101234' });
  await addDestination(rc(), uid, { kind: 'email', address: 'jane@acme.com' });
  assert.deepEqual(await availableMethods(env, uid), ['email', 'sms']);
  await enrolTotp(env, uid);
  addPasskey(env, uid, 'p1');
  assert.deepEqual(await availableMethods(env, uid), ['passkey', 'totp', 'backup', 'email', 'sms']);
  for (const v of HOSTILE) assert.deepEqual(await availableMethods(env, v), [], show(v));
  assert.equal(env.fetchCalls.length, 0, 'listing methods never sends anything');
});

test('no provider configured → no sms/email method and zero outbound calls, even with destinations on file', async () => {
  const { env, uid, rc } = await setup({});
  await addDestination(rc(), uid, { kind: 'sms', address: '+15550101234' });
  await addDestination(rc(), uid, { kind: 'email', address: 'jane@acme.com' });
  const m = await availableMethods(env, uid);
  assert.ok(!m.includes('sms') && !m.includes('email'), JSON.stringify(m));
  assert.equal((await userFactors(env, uid)).destinations, 0);
  assert.equal(env.fetchCalls.length, 0);
});

test('hasStrongFactor: passkey or confirmed TOTP; backup codes or destinations alone do not count', async () => {
  const { env, uid, rc } = await setup();
  await storeBackupCodes(env, uid, generateBackupCodes(), env.__clock());
  await addDestination(rc(), uid, { kind: 'sms', address: '+15550101234' });
  assert.equal(await hasStrongFactor(env, uid), false);
  addPasskey(env, uid, 'p1');
  assert.equal(await hasStrongFactor(env, uid), true);
  const { env: e2, uid: u2 } = await setup();
  await enrolTotp(e2, u2);
  assert.equal(await hasStrongFactor(e2, u2), true);
  for (const v of HOSTILE) assert.equal(await hasStrongFactor(env, v), false);
});

// ---------------------------------------------------------------- canDropFactor

test('canDropFactor: something must remain; backup codes alone do NOT count (A §7.1)', async () => {
  const { env, uid, rc } = await setup();
  const { secret } = await enrolTotp(env, uid); // also issues 10 backup codes
  assert.ok(secret);
  assert.equal(await canDropFactor(env, uid, 'totp'), false, 'TOTP + backup codes only');
  addPasskey(env, uid, 'p1');
  assert.equal(await canDropFactor(env, uid, 'totp'), true);
  assert.equal(await canDropFactor(env, uid, 'passkey'), true, 'TOTP remains');
  env.DB.q('DELETE FROM user_totp WHERE user_id = ?', uid);
  assert.equal(await canDropFactor(env, uid, 'passkey'), false, 'last passkey, backup codes only besides');
  addPasskey(env, uid, 'p2');
  assert.equal(await canDropFactor(env, uid, 'passkey'), true, 'another passkey remains');
  env.DB.q('DELETE FROM user_passkeys WHERE user_id = ?', uid);
  const d = await addDestination(rc(), uid, { kind: 'sms', address: '+15550101234' });
  assert.equal(await canDropFactor(env, uid, { destinationId: d.id }), false, 'the only usable destination');
  const e = await addDestination(rc(), uid, { kind: 'email', address: 'jane@acme.com' });
  assert.equal(await canDropFactor(env, uid, { destinationId: d.id }), true);
  assert.equal(await canDropFactor(env, uid, { destinationId: e.id }), true);
  addPasskey(env, uid, 'p3');
  assert.equal(await canDropFactor(env, uid, 'passkey'), true, 'a usable destination remains');
});

test('canDropFactor: an unusable destination (provider off) does not count as remaining', async () => {
  const { env, uid, rc } = await setup(RESEND);
  await addDestination(rc(), uid, { kind: 'sms', address: '+15550101234' });
  addPasskey(env, uid, 'p1');
  assert.equal(await canDropFactor(env, uid, 'passkey'), false);
});

test('canDropFactor: hostile users or droppings → false', async () => {
  const { env, uid, rc } = await setup();
  addPasskey(env, uid, 'p1');
  addPasskey(env, uid, 'p2');
  await addDestination(rc(), uid, { kind: 'sms', address: '+15550101234' });
  for (const v of HOSTILE) {
    assert.equal(await canDropFactor(env, v, 'passkey'), false, `uid ${show(v)}`);
    assert.equal(await canDropFactor(env, uid, v), false, `dropping ${show(v)}`);
    assert.equal(await canDropFactor(env, uid, { destinationId: v }), false, `destinationId ${show(v)}`);
  }
  for (const v of ['TOTP', 'backup', 'passkeys', ['totp'], { destination: 1 }]) assert.equal(await canDropFactor(env, uid, v), false, show(v));
});

// ---------------------------------------------------------------- reset

test('resetFactors refuses (nothing_left, 409) without a usable destination — and changes nothing', async () => {
  for (const [vars, dest] of [[{ ...TWILIO, ...RESEND }, null], [RESEND, { kind: 'sms', address: '+15550101234' }], [{}, { kind: 'email', address: 'jane@acme.com' }]]) {
    const { env, uid, rc } = await setup(vars);
    await enrolTotp(env, uid);
    addPasskey(env, uid, 'p1');
    addGrace(env, uid, 'dev-1');
    if (dest) await addDestination(rc(), uid, dest);
    const before = snapshot(env, uid);
    await assert.rejects(resetFactors(rc(), uid), (e) => e.status === 409 && e.body.code === 'nothing_left' && /no way to sign in/.test(e.body.error));
    assert.deepEqual(snapshot(env, uid), before);
  }
});

test('resetFactors clears TOTP, passkeys, ALL backup codes and grace in one go; returns the exact prior rows', async () => {
  const { env, uid, rc } = await setup();
  const other = await addUser(env, 'bob@acme.com');
  const { backup } = await enrolTotp(env, uid);
  await consumeBackupCode(rc(), uid, backup[0]);
  addPasskey(env, uid, 'p1');
  addPasskey(env, uid, 'p2');
  addGrace(env, uid, 'dev-1');
  addGrace(env, uid, 'dev-2', 1);
  await addDestination(rc(), uid, { kind: 'sms', address: '+15550101234' });
  await enrolTotp(env, other);
  addPasskey(env, other, 'theirs');
  addGrace(env, other, 'dev-9');
  const before = snapshot(env, uid);
  const theirsBefore = snapshot(env, other);

  const { cleared, prior } = await resetFactors(rc(), uid);
  assert.deepEqual(cleared, { totp: true, passkeys: 2, backup: 9, grace: 2 });
  assert.deepEqual(prior, { userId: uid, totp: before.totp[0], passkeys: before.passkeys, backup: before.backup, grace: before.grace });
  assert.ok(prior.totp.secret_enc.startsWith('v1.'), 'the TOTP stays encrypted in the snapshot');
  assert.equal(prior.backup.length, 10, 'used rows included');
  const after = snapshot(env, uid);
  assert.deepEqual([after.totp, after.passkeys, after.backup, after.grace], [[], [], [], []]);
  assert.deepEqual(after.dests, before.dests, 'destinations stay — they are how the person gets back in');
  assert.deepEqual(snapshot(env, other), theirsBefore, 'nobody else touched');
  assert.deepEqual(env.DB.q('SELECT action FROM audit_log').map((r) => r.action), ['mfa.backup.used'], 'the caller audits the reset');
  assert.deepEqual(await availableMethods(env, uid), ['sms']);
});

test('resetFactors: unknown or hostile users are 404', async () => {
  const { env, rc } = await setup();
  await assert.rejects(resetFactors(rc(), 999), (e) => e.status === 404);
  for (const v of HOSTILE) await assert.rejects(resetFactors(rc(), v), (e) => e.status === 404, show(v));
  assert.equal(env.fetchCalls.length, 0);
});

test('resetFactors: the guard is evaluated inside the batch — a destination gone by then means nothing is deleted', async () => {
  const { env, uid, rc } = await setup();
  await enrolTotp(env, uid);
  addPasskey(env, uid, 'p1');
  const d = await addDestination(rc(), uid, { kind: 'sms', address: '+15550101234' });
  const before = snapshot(env, uid);
  const batch = env.DB.batch.bind(env.DB);
  env.DB.batch = async (stmts) => {
    env.DB.q('DELETE FROM code_destinations WHERE id = ?', d.id); // removed concurrently
    env.DB.batch = batch;
    return batch(stmts);
  };
  await assert.rejects(resetFactors(rc(), uid), (e) => e.body.code === 'nothing_left');
  const after = snapshot(env, uid);
  assert.deepEqual([after.totp, after.passkeys, after.backup], [before.totp, before.passkeys, before.backup]);
});

// ---------------------------------------------------------------- restore

test('restoreFactors puts back exactly what was cleared — and the restored authenticator still signs in', async () => {
  const { env, uid, rc } = await setup();
  const { secret, backup } = await enrolTotp(env, uid);
  addPasskey(env, uid, 'p1');
  addGrace(env, uid, 'dev-1');
  await addDestination(rc(), uid, { kind: 'sms', address: '+15550101234' });
  env.__advance(TOTP_STEP_MS);
  assert.equal(await checkTotp(rc(), uid, await totpCode(secret, stepOf(env.__clock()))), true);
  const before = snapshot(env, uid);

  const { prior } = await resetFactors(rc(), uid);
  env.__advance(5 * MINUTE);
  // Through the audit log exactly as the revert endpoint will see it: JSON.
  const a = await audit(rc(), { action: 'mfa.reset', target: { type: 'user', id: uid }, undo: undoFor('mfa.reset', prior) });
  const stored = (await getAuditEntry(env, a.id)).undo_payload;
  assert.deepEqual(stored, prior);
  await restoreFactors(rc(), stored);

  assert.deepEqual(snapshot(env, uid), before, 'byte-for-byte the rows that were cleared');
  // The app on their phone works again — and the replay floor came back with it.
  const spent = await totpCode(secret, stepOf(env.__clock() - 5 * MINUTE));
  assert.equal(await checkTotp(rc(), uid, spent), false);
  assert.equal(await checkTotp(rc(), uid, await totpCode(secret, stepOf(env.__clock()))), true);
  assert.equal(await consumeBackupCode(rc(), uid, backup[1]), true, 'the backup codes work again too');
});

test('restoreFactors refuses (enrolled_since) if anything was enrolled since — even a half-finished setup', async () => {
  const cases = [
    async (env, uid) => beginTotp({ env, nowMs: env.__clock() }, uid),
    async (env, uid) => addPasskey(env, uid, 'new'),
    async (env, uid) => storeBackupCodes(env, uid, generateBackupCodes(2), env.__clock()),
  ];
  for (const enrolSince of cases) {
    const { env, uid, rc } = await setup();
    await enrolTotp(env, uid);
    await addDestination(rc(), uid, { kind: 'email', address: 'jane@acme.com' });
    const { prior } = await resetFactors(rc(), uid);
    await enrolSince(env, uid);
    const now = snapshot(env, uid);
    await assert.rejects(restoreFactors(rc(), prior), (e) => e.status === 409 && e.body.code === 'enrolled_since');
    assert.deepEqual(snapshot(env, uid), now, 'nothing replaced');
  }
});

test('restoreFactors: used backup codes alone are not "enrolled since"', async () => {
  const { env, uid, rc } = await setup();
  await enrolTotp(env, uid);
  await addDestination(rc(), uid, { kind: 'email', address: 'jane@acme.com' });
  const { prior } = await resetFactors(rc(), uid);
  env.DB.q("INSERT INTO backup_codes (user_id, code_hash, salt, iters, created_at, used_at) VALUES (?, 'h', 's', 100000, 'x', 'y')", uid);
  await restoreFactors(rc(), prior);
  assert.equal(env.DB.q('SELECT COUNT(*) AS n FROM user_totp WHERE user_id = ?', uid)[0].n, 1);
});

test('restoreFactors: a TOTP row created after the check fails the whole batch rather than being overwritten', async () => {
  const { env, uid, rc } = await setup();
  await enrolTotp(env, uid);
  addPasskey(env, uid, 'p1');
  await addDestination(rc(), uid, { kind: 'email', address: 'jane@acme.com' });
  const { prior } = await resetFactors(rc(), uid);
  const batch = env.DB.batch.bind(env.DB);
  let n = 0;
  env.DB.batch = async (stmts) => {
    if (++n === 2) env.DB.q("INSERT INTO user_totp (user_id, secret_enc, created_at) VALUES (?, 'v1.new.new', 'x')", uid);
    return batch(stmts);
  };
  await assert.rejects(restoreFactors(rc(), prior), (e) => e.status === 409 && e.body.code === 'enrolled_since');
  assert.equal(env.DB.q('SELECT secret_enc FROM user_totp WHERE user_id = ?', uid)[0].secret_enc, 'v1.new.new');
  assert.equal(env.DB.q('SELECT COUNT(*) AS n FROM user_passkeys WHERE user_id = ?', uid)[0].n, 0, 'rolled back');
});

test('restoreFactors refuses unreadable snapshots without writing', async () => {
  const { env, uid, rc } = await setup();
  await enrolTotp(env, uid);
  addPasskey(env, uid, 'p1');
  await addDestination(rc(), uid, { kind: 'email', address: 'jane@acme.com' });
  const { prior } = await resetFactors(rc(), uid);
  const bad = [
    ...HOSTILE,
    { ...prior, userId: 'abc' },
    { ...prior, userId: undefined },
    { ...prior, totp: 'x' },
    { ...prior, totp: undefined },
    { ...prior, totp: { ...prior.totp, secret_enc: null } },
    { ...prior, totp: { ...prior.totp, secret_enc: { evil: true } } },
    { ...prior, totp: { ...prior.totp, user_id: uid + 1 } },
    { ...prior, passkeys: 'x' },
    { ...prior, passkeys: [null] },
    { ...prior, passkeys: [{ ...prior.passkeys[0], public_key: null }] },
    { ...prior, passkeys: [{ ...prior.passkeys[0], sign_count: Infinity }] },
    { ...prior, backup: [{ ...prior.backup[0], iters: true }] },
    { ...prior, grace: {} },
    { ...prior, grace: Array.from({ length: 2001 }, () => ({})) },
  ];
  for (const p of bad) {
    await assert.rejects(restoreFactors(rc(), p), (e) => e.status === 409 && e.body.code === 'snapshot_unreadable', show(p)?.slice(0, 80));
  }
  const s = snapshot(env, uid);
  assert.deepEqual([s.totp, s.passkeys, s.backup], [[], [], []]);
});

test('restoreFactors: a grace window earned since the reset wins over the restored one', async () => {
  const { env, uid, rc } = await setup();
  addGrace(env, uid, 'dev-1', 3);
  addGrace(env, uid, 'dev-2', 3);
  await addDestination(rc(), uid, { kind: 'email', address: 'jane@acme.com' });
  const { prior } = await resetFactors(rc(), uid);
  env.__advance(MINUTE);
  addGrace(env, uid, 'dev-1', 1);
  await restoreFactors(rc(), prior);
  const g = env.DB.q('SELECT device_id, tier FROM mfa_grace WHERE user_id = ? ORDER BY device_id', uid);
  assert.deepEqual(g.map((r) => [r.device_id, r.tier]), [['dev-1', 1], ['dev-2', 3]]);
});

await run();
