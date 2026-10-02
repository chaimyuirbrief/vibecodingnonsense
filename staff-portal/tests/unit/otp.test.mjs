import { test, assert, run } from '../helpers/t.js';
import { makeEnvWithSchema } from '../helpers/env.js';
import { iso, MINUTE, DAY, SECOND } from '../../src/util.js';
import { hmacHex } from '../../src/crypto.js';
import {
  listDestinations, primaryDestination, addDestination, removeDestination, sendCode, verifyCode, OTP_TTL_MS,
} from '../../src/mfa/otp.js';

const HOSTILE = [null, undefined, NaN, Infinity, '', '   ', 'abc', {}, [], true, 0, Symbol('x')];
const show = (v) => (typeof v === 'symbol' ? 'Symbol' : JSON.stringify(v) ?? String(v));
const TWILIO = { TWILIO_ACCOUNT_SID: 'test-twilio-account-sid', TWILIO_AUTH_TOKEN: 'twilio-token-secret', TWILIO_FROM: '+15005550006' };
const RESEND = { RESEND_API_KEY: 're_test_key_secret', MAIL_FROM: 'portal@acme.com' };

function fakeFetch(status = 201) {
  const calls = [];
  const f = async (url, init) => {
    calls.push({ url: String(url), init });
    return new Response('{}', { status: typeof status === 'function' ? status() : status });
  };
  f.calls = calls;
  return f;
}

async function setup(vars = { ...TWILIO, ...RESEND }, status) {
  const env = await makeEnvWithSchema({ vars });
  env.__fetch = fakeFetch(status);
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

function addPasskey(env, uid, id = 'cred-1') {
  const t = iso(env.__clock());
  env.DB.q("INSERT INTO user_passkeys (id, user_id, public_key, algorithm, sign_count, created_at) VALUES (?, ?, '{}', -7, 0, ?)", id, uid, t);
}

const dests = (env, uid) => env.DB.q('SELECT * FROM code_destinations WHERE user_id = ? ORDER BY id', uid);
const challenges = (env) => env.DB.q('SELECT * FROM otp_challenges ORDER BY rowid');
// The code is only ever in the outbound message; tests read it from there.
function sentCode(env, i = -1) {
  const call = env.__fetch.calls.at(i);
  const text = call.url.includes('twilio') ? new URLSearchParams(call.init.body).get('Body') : JSON.parse(call.init.body).text;
  return /\b(\d{6})\b/.exec(text)[1];
}

// ---------------------------------------------------------------- destinations

test('addDestination: E.164 and email normalised; first is primary; returns the stored row', async () => {
  const { env, uid, rc } = await setup();
  const a = await addDestination(rc(), uid, { kind: 'sms', address: ' +44 (7700) 900-123 ', label: '  Work mobile ' });
  assert.equal(a.kind, 'sms');
  assert.equal(a.address, '+447700900123');
  assert.equal(a.label, 'Work mobile');
  assert.equal(a.is_primary, 1);
  assert.equal(a.created_by, 1);
  assert.equal(a.user_id, uid);
  const b = await addDestination(rc(), uid, { kind: 'email', address: 'Jane.Doe@ACME.com' });
  assert.equal(b.address, 'jane.doe@acme.com');
  assert.equal(b.is_primary, 0);
  assert.equal(b.label, null);
});

test('addDestination refuses bad kinds and addresses — and writes nothing', async () => {
  const { env, uid, rc } = await setup();
  for (const v of [...HOSTILE, 'SMS', 'phone', 'fax']) {
    await assert.rejects(addDestination(rc(), uid, { kind: v, address: '+447700900123' }), (e) => e.status === 400 && e.body.field === 'kind', show(v));
  }
  for (const v of [...HOSTILE, '07700900123', '447700900123', '+0447700900', '+1234567', '+1234567890123456', '+44 7700 900123 ext 4', 'x'.repeat(50)]) {
    await assert.rejects(addDestination(rc(), uid, { kind: 'sms', address: v }), (e) => e.status === 400 && e.body.field === 'address', show(v));
  }
  for (const v of [...HOSTILE, 'jane', 'jane@', '@acme.com', 'a b@acme.com']) {
    await assert.rejects(addDestination(rc(), uid, { kind: 'email', address: v }), (e) => e.status === 400, show(v));
  }
  for (const v of HOSTILE) await assert.rejects(addDestination(rc(), uid, v), (e) => e.status === 400, `input ${show(v)}`);
  for (const v of HOSTILE) await assert.rejects(addDestination(rc(), v, { kind: 'sms', address: '+447700900123' }), (e) => e.status === 404);
  await assert.rejects(addDestination(rc(), 999, { kind: 'sms', address: '+447700900123' }), (e) => e.status === 404);
  assert.equal(env.DB.q('SELECT COUNT(*) AS n FROM code_destinations')[0].n, 0);
});

test('addDestination: at most five per person; duplicates refused', async () => {
  const { env, uid, rc } = await setup();
  for (let i = 0; i < 5; i++) await addDestination(rc(), uid, { kind: 'sms', address: `+4477009001${i}0` });
  await assert.rejects(addDestination(rc(), uid, { kind: 'email', address: 'x@acme.com' }), (e) => e.status === 409 && e.body.code === 'too_many');
  assert.equal(dests(env, uid).length, 5);
  assert.equal(dests(env, uid).filter((d) => d.is_primary === 1).length, 1);
  const other = await addUser(env, 'bob@acme.com');
  await addDestination(rc(), other, { kind: 'sms', address: '+447700900100' });
  await assert.rejects(addDestination(rc(), other, { kind: 'sms', address: '+44 7700 900100' }), (e) => e.status === 409 && e.body.code === 'duplicate');
});

test('listDestinations: masked hints, no address; usableOnly follows provider configuration', async () => {
  const { env, uid, rc } = await setup(TWILIO);
  await addDestination(rc(), uid, { kind: 'sms', address: '+15550101234', label: 'Mobile' });
  await addDestination(rc(), uid, { kind: 'email', address: 'jane@acme.com' });
  const all = await listDestinations(env, uid);
  assert.deepEqual(all.map((d) => [d.kind, d.hint, d.label, d.is_primary, d.usable]), [
    ['sms', '•••• 1234', 'Mobile', true, true],
    ['email', 'j•••@acme.com', null, false, false],
  ]);
  assert.ok(!JSON.stringify(all).includes('5550101234') && !JSON.stringify(all).includes('jane@'), 'no address leaves');
  assert.deepEqual((await listDestinations(env, uid, { usableOnly: true })).map((d) => d.kind), ['sms']);
  for (const v of HOSTILE) assert.deepEqual(await listDestinations(env, v), [], show(v));
});

test('primaryDestination: usable only — the primary if it is, else the oldest usable', async () => {
  const { env, uid, rc } = await setup(RESEND);
  await addDestination(rc(), uid, { kind: 'sms', address: '+15550101234' });
  assert.equal(await primaryDestination(env, uid), null, 'SMS not configured');
  const e = await addDestination(rc(), uid, { kind: 'email', address: 'jane@acme.com' });
  assert.equal((await primaryDestination(env, uid)).id, e.id);
  for (const v of HOSTILE) assert.equal(await primaryDestination(env, v), null);
  const env2 = await makeEnvWithSchema();
  assert.equal(await primaryDestination(env2, uid), null);
});

test('removeDestination: never the last usable factor; removing the primary promotes the oldest remaining', async () => {
  const { env, uid, rc } = await setup();
  const a = await addDestination(rc(), uid, { kind: 'sms', address: '+15550101234' });
  await assert.rejects(removeDestination(rc(), uid, a.id), (e) => e.status === 409 && e.body.code === 'last_factor');
  assert.equal(dests(env, uid).length, 1, 'still there');
  const b = await addDestination(rc(), uid, { kind: 'email', address: 'jane@acme.com' });
  const c = await addDestination(rc(), uid, { kind: 'sms', address: '+15550109999' });
  const { row } = await removeDestination(rc(), uid, a.id);
  assert.equal(row.address, '+15550101234', 'the removed row, for the undo payload');
  const left = dests(env, uid);
  assert.deepEqual(left.map((d) => [d.id, d.is_primary]), [[b.id, 1], [c.id, 0]]);
  await removeDestination(rc(), uid, c.id);
  await assert.rejects(removeDestination(rc(), uid, b.id), (e) => e.body.code === 'last_factor');
});

test('removeDestination: allowed when a passkey remains; refuses ids that are not theirs; kills codes sent there', async () => {
  const { env, uid, rc } = await setup();
  const other = await addUser(env, 'bob@acme.com');
  const a = await addDestination(rc(), uid, { kind: 'sms', address: '+15550101234' });
  const theirs = await addDestination(rc(), other, { kind: 'sms', address: '+15550105555' });
  addPasskey(env, uid);
  await sendCode(rc(), uid, a.id);
  assert.equal(challenges(env).length, 1);
  await assert.rejects(removeDestination(rc(), uid, theirs.id), (e) => e.status === 404);
  for (const v of HOSTILE) await assert.rejects(removeDestination(rc(), uid, v), (e) => e.status === 404, show(v));
  for (const v of HOSTILE) await assert.rejects(removeDestination(rc(), v, a.id), (e) => e.status === 404, show(v));
  await removeDestination(rc(), uid, a.id);
  assert.equal(dests(env, uid).length, 0);
  assert.equal(challenges(env).length, 0);
  assert.equal(dests(env, other).length, 1);
});

test('backup codes alone do not let the last destination go', async () => {
  const { env, uid, rc } = await setup();
  const a = await addDestination(rc(), uid, { kind: 'sms', address: '+15550101234' });
  env.DB.q("INSERT INTO backup_codes (user_id, code_hash, salt, iters, created_at) VALUES (?, 'aa', 'bb', 100000, 'x')", uid);
  await assert.rejects(removeDestination(rc(), uid, a.id), (e) => e.body.code === 'last_factor');
});

// ---------------------------------------------------------------- sendCode

test('sendCode: charges otp_send, stores only an HMAC, texts the code via Twilio, 10-minute expiry', async () => {
  const { env, uid, rc } = await setup();
  const d = await addDestination(rc(), uid, { kind: 'sms', address: '+15550101234' });
  const r = await sendCode(rc(), uid, d.id);
  assert.equal(r.sent, true);
  assert.equal(r.kind, 'sms');
  assert.equal(r.hint, '•••• 1234');
  assert.match(r.challengeId, /^[A-Za-z0-9_-]{22}$/);
  assert.equal(env.__fetch.calls.length, 1);
  assert.ok(env.__fetch.calls[0].url.startsWith('https://api.twilio.com/'));
  assert.equal(new URLSearchParams(env.__fetch.calls[0].init.body).get('To'), '+15550101234');
  const code = sentCode(env);
  const [ch] = challenges(env);
  assert.equal(ch.id, r.challengeId);
  assert.equal(ch.user_id, uid);
  assert.equal(ch.destination_id, d.id);
  assert.equal(ch.attempts, 0);
  assert.equal(ch.used_at, null);
  assert.equal(ch.expires_at, iso(env.__clock() + 10 * MINUTE));
  assert.equal(OTP_TTL_MS, 10 * MINUTE);
  assert.equal(ch.code_hash, await hmacHex(env.SESSION_SECRET, `otp.${ch.id}.${code}`));
  assert.ok(!JSON.stringify(ch).includes(code), 'the code is not stored');
  assert.equal(env.DB.q("SELECT COUNT(*) AS n FROM auth_attempts WHERE kind = 'otp_send' AND subject = ?", String(uid))[0].n, 1);
  assert.equal(env.DB.q('SELECT COUNT(*) AS n FROM audit_log')[0].n, 0, 'nothing logged here, least of all the code');
});

test('sendCode: email goes through Resend with the code in the text, not the subject', async () => {
  const { env, uid, rc } = await setup();
  const d = await addDestination(rc(), uid, { kind: 'email', address: 'jane@acme.com' });
  const r = await sendCode(rc(), uid, d.id);
  assert.deepEqual([r.sent, r.kind, r.hint], [true, 'email', 'j•••@acme.com']);
  const { url, init } = env.__fetch.calls[0];
  assert.equal(url, 'https://api.resend.com/emails');
  const body = JSON.parse(init.body);
  assert.deepEqual(body.to, ['jane@acme.com']);
  assert.match(body.text, /\b\d{6}\b/);
  assert.ok(!/\d{6}/.test(body.subject));
  assert.ok(body.subject.includes('Acme Inc.'));
});

test('sendCode: over otp_send is 429 with NO outbound call; refused sends still count (charged first)', async () => {
  const { env, uid, rc } = await setup();
  const d = await addDestination(rc(), uid, { kind: 'sms', address: '+15550101234' });
  for (let i = 0; i < 5; i++) assert.equal((await sendCode(rc(), uid, d.id)).sent, true);
  await assert.rejects(sendCode(rc(), uid, d.id), (e) => e.status === 429 && e.body.retry_after > 0);
  assert.equal(env.__fetch.calls.length, 5);
  assert.equal(challenges(env).length, 5);
  // A junk destination id is charged too — and refused.
  const { env: env2, uid: uid2, rc: rc2 } = await setup();
  for (const v of HOSTILE) await assert.rejects(sendCode(rc2(), uid2, v), (e) => e.status === 404 || e.status === 429, show(v));
  assert.equal(env2.DB.q("SELECT COUNT(*) AS n FROM auth_attempts WHERE kind = 'otp_send'")[0].n, HOSTILE.length);
  assert.equal(env2.__fetch.calls.length, 0);
  assert.equal(challenges(env2).length, 0);
});

test('sendCode: a destination whose provider is not configured → 409, zero outbound calls, no challenge', async () => {
  const { env, uid, rc } = await setup(RESEND);
  const d = await addDestination(rc(), uid, { kind: 'sms', address: '+15550101234' });
  await assert.rejects(sendCode(rc(), uid, d.id), (e) => e.status === 409 && e.body.code === 'destination_unusable');
  assert.equal(env.__fetch.calls.length, 0);
  assert.equal(challenges(env).length, 0);
  const { env: bare, uid: u2, rc: rc2 } = await setup({});
  const d2 = await addDestination(rc2(), u2, { kind: 'email', address: 'jane@acme.com' });
  await assert.rejects(sendCode(rc2(), u2, d2.id), (e) => e.status === 409);
  assert.equal(bare.__fetch.calls.length, 0);
});

test('sendCode: someone else\'s destination is 404 and nothing is sent', async () => {
  const { env, uid, rc } = await setup();
  const other = await addUser(env, 'bob@acme.com');
  const theirs = await addDestination(rc(), other, { kind: 'sms', address: '+15550105555' });
  await assert.rejects(sendCode(rc(), uid, theirs.id), (e) => e.status === 404);
  for (const v of HOSTILE) await assert.rejects(sendCode(rc(), v, theirs.id), (e) => e.status === 404);
  assert.equal(env.__fetch.calls.length, 0);
});

test('sendCode: a provider failure is { sent: false } and its challenge is withdrawn', async () => {
  const { env, uid, rc } = await setup(undefined, 500);
  const d = await addDestination(rc(), uid, { kind: 'sms', address: '+15550101234' });
  const r = await sendCode(rc(), uid, d.id);
  assert.deepEqual(r, { sent: false, kind: 'sms', hint: '•••• 1234', challengeId: null });
  assert.equal(challenges(env).length, 0);
});

test('sendCode prunes challenges expired more than a day ago, in the same batch', async () => {
  const { env, uid, rc } = await setup();
  const d = await addDestination(rc(), uid, { kind: 'sms', address: '+15550101234' });
  const t = env.__clock();
  const ins = (id, exp) => env.DB.q("INSERT INTO otp_challenges (id, user_id, destination_id, code_hash, expires_at, created_at) VALUES (?, ?, ?, 'h', ?, 'x')", id, uid, d.id, iso(exp));
  ins('old', t - DAY - SECOND);
  ins('recent', t - DAY + MINUTE);
  await sendCode(rc(), uid, d.id);
  assert.deepEqual(challenges(env).map((c) => c.id).slice(0, 1), ['recent']);
  assert.equal(challenges(env).length, 2);
});

// ---------------------------------------------------------------- verifyCode

test('verifyCode: right code once; single use; spaces forgiven', async () => {
  const { env, uid, rc } = await setup();
  const d = await addDestination(rc(), uid, { kind: 'sms', address: '+15550101234' });
  await sendCode(rc(), uid, d.id);
  const code = sentCode(env);
  assert.equal(await verifyCode(rc(), uid, d.id, `${code.slice(0, 3)} ${code.slice(3)}`), true);
  assert.equal(challenges(env)[0].used_at, iso(env.__clock()));
  assert.equal(await verifyCode(rc(), uid, d.id, code), false, 'single use');
});

test('verifyCode: five attempts per challenge — the right code fails on the sixth', async () => {
  const { env, uid, rc } = await setup();
  const d = await addDestination(rc(), uid, { kind: 'sms', address: '+15550101234' });
  await sendCode(rc(), uid, d.id);
  const code = sentCode(env);
  const wrong = code === '000000' ? '111111' : '000000';
  for (let i = 0; i < 5; i++) assert.equal(await verifyCode(rc(), uid, d.id, wrong), false);
  assert.equal(challenges(env)[0].attempts, 5);
  assert.equal(await verifyCode(rc(), uid, d.id, code), false);
  assert.equal(challenges(env)[0].attempts, 5, 'no further increments');
  assert.equal(challenges(env)[0].used_at, null);
});

test('verifyCode: expiry, latest-only, destination binding, removal, and an unreadable expiry', async () => {
  const { env, uid, rc } = await setup();
  const a = await addDestination(rc(), uid, { kind: 'sms', address: '+15550101234' });
  const b = await addDestination(rc(), uid, { kind: 'email', address: 'jane@acme.com' });
  addPasskey(env, uid);
  // Expiry.
  await sendCode(rc(), uid, a.id);
  let code = sentCode(env);
  env.__advance(10 * MINUTE);
  assert.equal(await verifyCode(rc(), uid, a.id, code), false, 'expired at exactly ten minutes');
  // Only the latest challenge for that destination counts.
  await sendCode(rc(), uid, a.id);
  const first = sentCode(env);
  env.__advance(SECOND);
  await sendCode(rc(), uid, a.id);
  const second = sentCode(env);
  if (first !== second) assert.equal(await verifyCode(rc(), uid, a.id, first), false);
  // A code sent to A is not accepted at B.
  assert.equal(await verifyCode(rc(), uid, b.id, second), false);
  assert.equal(await verifyCode(rc(), uid, a.id, second), true);
  // Removing the destination stops a code already sent there being a way in.
  await sendCode(rc(), uid, b.id);
  code = sentCode(env);
  env.DB.q('DELETE FROM code_destinations WHERE id = ?', b.id); // even without removeDestination's cleanup
  assert.equal(await verifyCode(rc(), uid, b.id, code), false);
  // 'garbage' sorts after every ISO date in SQL; the strict parse refuses it.
  await sendCode(rc(), uid, a.id);
  code = sentCode(env);
  env.DB.q("UPDATE otp_challenges SET expires_at = 'garbage' WHERE used_at IS NULL");
  assert.equal(await verifyCode(rc(), uid, a.id, code), false);
});

test('verifyCode: switching a provider off stops codes already sent through it', async () => {
  const { env, uid, rc } = await setup();
  const a = await addDestination(rc(), uid, { kind: 'sms', address: '+15550101234' });
  await sendCode(rc(), uid, a.id);
  const code = sentCode(env);
  const off = { ...env, TWILIO_AUTH_TOKEN: '' };
  assert.equal(await verifyCode({ env: off, nowMs: env.__clock() }, uid, a.id, code), false);
  assert.equal(await verifyCode(rc(), uid, a.id, code), true);
});

test('verifyCode: hostile codes and ids → false, and no attempt is spent', async () => {
  const { env, uid, rc } = await setup();
  const d = await addDestination(rc(), uid, { kind: 'sms', address: '+15550101234' });
  await sendCode(rc(), uid, d.id);
  const code = sentCode(env);
  for (const v of [...HOSTILE, '12345', '1234567', '12a456', Number(code), '0x1234']) {
    assert.equal(await verifyCode(rc(), uid, d.id, v), false, `code ${show(v)}`);
  }
  for (const v of HOSTILE) {
    assert.equal(await verifyCode(rc(), v, d.id, code), false, `uid ${show(v)}`);
    assert.equal(await verifyCode(rc(), uid, v, code), false, `did ${show(v)}`);
  }
  assert.equal(challenges(env)[0].attempts, 0);
  assert.equal(await verifyCode(rc(), uid, d.id, code), true, 'still usable afterwards');
});

test('verifyCode: parallel attempts cannot exceed five between them; the right code wins once', async () => {
  const { env, uid, rc } = await setup();
  const d = await addDestination(rc(), uid, { kind: 'sms', address: '+15550101234' });
  await sendCode(rc(), uid, d.id);
  const code = sentCode(env);
  const r = await Promise.all([verifyCode(rc(), uid, d.id, code), verifyCode(rc(), uid, d.id, code), verifyCode(rc(), uid, d.id, code)]);
  assert.equal(r.filter(Boolean).length, 1);
  const wrong = code === '000000' ? '111111' : '000000';
  await sendCode(rc(), uid, d.id);
  await Promise.all(Array.from({ length: 12 }, () => verifyCode(rc(), uid, d.id, wrong)));
  assert.equal(challenges(env).at(-1).attempts, 5);
});

await run();
