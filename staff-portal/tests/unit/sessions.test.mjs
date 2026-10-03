import { test, assert, run } from '../helpers/t.js';
import { makeEnvWithSchema } from '../helpers/env.js';
import { iso, parseCookies, MINUTE, HOUR, DAY } from '../../src/util.js';
import { sha256Hex } from '../../src/crypto.js';
import { effectivePermissions } from '../../src/rbac.js';
import * as S from '../../src/sessions.js';
import { setStatus } from '../../src/users.js';

const HOSTILE = [null, undefined, NaN, Infinity, '', '   ', 'abc', {}, [], true, 0, Symbol('x')];
const show = (v) => (typeof v === 'symbol' ? 'Symbol' : JSON.stringify(v) ?? String(v));

function roleRow(env, key) {
  return env.DB.q('SELECT * FROM roles WHERE key = ?', key)[0];
}

let seq = 0;
function addUser(env, roleKey, o = {}) {
  const n = ++seq;
  const t = iso(env.__clock());
  const email = `s${n}@acme.com`;
  env.DB.q(
    `INSERT INTO users (email, full_name, status, role_id, password_hash, must_change_password, mfa_policy, created_at, updated_at)
     VALUES (?, ?, ?, ?, 'placeholder', ?, ?, ?, ?)`,
    email,
    `S ${n}`,
    o.status ?? 'active',
    roleRow(env, roleKey).id,
    o.must_change_password ?? 0,
    o.mfa_policy ?? 'inherit',
    t,
    t,
  );
  return env.DB.q('SELECT * FROM users WHERE email = ?', email)[0];
}

function user(env, id) {
  return env.DB.q('SELECT * FROM users WHERE id = ?', id)[0];
}

function sess(env, id) {
  return env.DB.q('SELECT * FROM sessions WHERE id = ?', id)[0];
}

async function rcAs(env, u, extra = {}) {
  const nowMs = env.__clock();
  return { env, nowMs, user: u, authz: u ? await effectivePermissions(env, u, nowMs) : null, ip: '81.2.69.10', ua: 'Test UA', setCookies: [], ...extra };
}

const tokenOf = (cookie) => cookie.split(';')[0].slice(S.SESSION_COOKIE.length + 1);

// A fresh request carrying the cookie, at the current clock.
function req(env, cookie, extra = {}) {
  const pair = typeof cookie === 'string' ? cookie.split(';')[0] : '';
  return { env, nowMs: env.__clock(), cookies: parseCookies(pair), ...extra };
}

async function signedIn(env, roleKey = 'employee', opts = {}, policy) {
  const u = addUser(env, roleKey);
  const s = await S.createSession(await rcAs(env, u, { policy }), u, opts);
  return { u, s };
}

// ---------------------------------------------------------------- creating

test('createSession: the cookie holds a random token; the database holds only its SHA-256', async () => {
  const env = await makeEnvWithSchema();
  const u = addUser(env, 'employee');
  const rc = await rcAs(env, u);
  const s = await S.createSession(rc, u, { deviceId: 'dev-1', mfaMethod: 'totp' });
  assert.match(s.cookie, /^__Host-sid=[A-Za-z0-9_-]{43}; Path=\/; SameSite=Lax; Secure; HttpOnly; Max-Age=28800$/);
  const token = tokenOf(s.cookie);
  assert.equal(s.id, await sha256Hex(token));
  const row = sess(env, s.id);
  assert.ok(!Object.values(row).some((v) => typeof v === 'string' && v.includes(token)), 'token never stored');
  assert.equal(row.user_id, u.id);
  assert.equal(row.device_id, 'dev-1');
  assert.equal(row.created_at, iso(rc.nowMs));
  assert.equal(row.idle_expires_at, iso(rc.nowMs + 120 * MINUTE));
  assert.equal(row.absolute_expires_at, iso(rc.nowMs + 8 * HOUR));
  assert.equal(row.aal, 1);
  assert.equal(row.mfa_at, null);
  assert.equal(row.pinned, null);
  assert.equal(row.ip, '81.2.69.10');
  assert.equal(row.ua, 'Test UA');
  assert.notEqual((await S.createSession(rc, u, {})).id, s.id);

  const s2 = await S.createSession(await rcAs(env, u, { policy: { session_idle_minutes: 30, session_absolute_hours: 2 } }), u, { aal: 2, pinned: 'mfa_enroll' });
  const r2 = sess(env, s2.id);
  assert.match(s2.cookie, /Max-Age=7200$/);
  assert.equal(r2.idle_expires_at, iso(rc.nowMs + 30 * MINUTE));
  assert.equal(r2.aal, 2);
  assert.equal(r2.mfa_at, iso(rc.nowMs), 'a factor proved now');
  assert.equal(r2.pinned, 'mfa_enroll');

  const before = env.DB.q('SELECT COUNT(*) AS n FROM sessions')[0].n;
  for (const pin of ['admin', '', 1, {}]) await assert.rejects(S.createSession(rc, u, { pinned: pin }), /unknown pin/);
  for (const v of HOSTILE) await assert.rejects(S.createSession(rc, v, {}), /needs a user/);
  assert.equal(env.DB.q('SELECT COUNT(*) AS n FROM sessions')[0].n, before);
});

test('createSession prunes sessions absolute-expired or revoked more than 7 days ago, in the same write', async () => {
  const env = await makeEnvWithSchema();
  const { u, s: old } = await signedIn(env);
  const { s: revokedLongAgo } = await signedIn(env);
  await S.revokeSession(env, revokedLongAgo.id, 'test');
  env.__advance(9 * DAY);
  const { s: revokedRecently } = await signedIn(env);
  await S.revokeSession(env, revokedRecently.id, 'test');
  await S.createSession(await rcAs(env, u), u, {});
  assert.equal(sess(env, old.id), undefined, 'absolute expiry 8 days gone');
  assert.equal(sess(env, revokedLongAgo.id), undefined);
  assert.ok(sess(env, revokedRecently.id), 'kept for the 7-day window');
});

// ---------------------------------------------------------------- loading

test('loadSession: a valid cookie puts the session, user and authz on rc', async () => {
  const env = await makeEnvWithSchema();
  const { u, s } = await signedIn(env, 'manager');
  const rc = req(env, s.cookie);
  const out = await S.loadSession(rc);
  assert.equal(out.user.id, u.id);
  assert.equal(out.session.id, s.id);
  assert.equal(out.authz.role.key, 'manager');
  assert.equal(rc.user.id, u.id);
  assert.equal(rc.session.id, s.id);
  assert.ok(rc.authz.perms.has('users.invite'));
});

test('loadSession: a malformed cookie is refused before it is hashed or queried', async () => {
  const env = await makeEnvWithSchema();
  const { s } = await signedIn(env);
  const token = tokenOf(s.cookie);
  env.DB.failOn = /sessions|users/; // any query would throw
  const bad = [...HOSTILE, token.slice(1), token + 'A', token.slice(0, 42) + '=', token.slice(0, 42) + '.', ' ' + token.slice(1), token.toUpperCase().replace(/[^A-Z]/g, '+')];
  for (const v of bad) {
    const rc = { env, nowMs: env.__clock(), cookies: { [S.SESSION_COOKIE]: v }, session: 'stale', user: 'stale', authz: 'stale' };
    assert.equal(await S.loadSession(rc), null, show(v));
    assert.equal(rc.session, null);
    assert.equal(rc.user, null);
    assert.equal(rc.authz, null);
  }
  for (const cookies of [undefined, null, {}, { other: token }]) assert.equal(await S.loadSession({ env, nowMs: env.__clock(), cookies }), null);
  env.DB.failOn = null;
  assert.equal(await S.loadSession(req(env, `${S.SESSION_COOKIE}=${'A'.repeat(43)}`)), null, 'well-formed but unknown');
  assert.ok(await S.loadSession(req(env, s.cookie)));
});

test('loadSession: idle expiry, extended at most once a minute', async () => {
  const env = await makeEnvWithSchema();
  const { u, s } = await signedIn(env);
  const t0 = env.__clock();
  env.__advance(30 * 1000);
  await S.loadSession(req(env, s.cookie));
  assert.equal(sess(env, s.id).last_seen_at, iso(t0), 'no write within a minute');
  env.__advance(31 * 1000);
  await S.loadSession(req(env, s.cookie));
  assert.equal(sess(env, s.id).last_seen_at, iso(t0 + 61 * 1000));
  assert.equal(sess(env, s.id).idle_expires_at, iso(t0 + 61 * 1000 + 120 * MINUTE));
  assert.equal(user(env, u.id).last_seen_at, iso(t0 + 61 * 1000));
  env.__advance(119 * MINUTE);
  assert.ok(await S.loadSession(req(env, s.cookie)), 'touched an hour and more ago, still inside the window');
  env.__advance(120 * MINUTE);
  assert.equal(await S.loadSession(req(env, s.cookie)), null, 'idle for the whole window');
});

test('loadSession: the absolute expiry is never extended', async () => {
  const env = await makeEnvWithSchema();
  const { s } = await signedIn(env);
  for (let i = 0; i < 7; i++) {
    env.__advance(HOUR);
    assert.ok(await S.loadSession(req(env, s.cookie)), `hour ${i + 1}`);
  }
  env.__advance(HOUR - 1);
  assert.ok(await S.loadSession(req(env, s.cookie)));
  assert.equal(sess(env, s.id).idle_expires_at <= sess(env, s.id).absolute_expires_at, true);
  env.__advance(1);
  assert.equal(await S.loadSession(req(env, s.cookie)), null);
});

test('loadSession: revoked sessions and unreadable times are refused', async () => {
  const env = await makeEnvWithSchema();
  const { s } = await signedIn(env);
  assert.equal(await S.revokeSession(env, s.id, 'logout'), 1);
  assert.equal(await S.loadSession(req(env, s.cookie)), null);
  for (const col of ['created_at', 'last_seen_at', 'idle_expires_at', 'absolute_expires_at']) {
    for (const bad of ['garbage', '42', '2099-01-01']) {
      const { s: s2 } = await signedIn(env);
      env.DB.q(`UPDATE sessions SET ${col} = ? WHERE id = ?`, bad, s2.id);
      assert.equal(await S.loadSession(req(env, s2.cookie)), null, `${col} = ${bad}`);
    }
  }
  const { s: s3 } = await signedIn(env);
  env.DB.q("UPDATE sessions SET revoked_at = 'garbage' WHERE id = ?", s3.id);
  assert.equal(await S.loadSession(req(env, s3.cookie)), null, 'any revocation mark counts');
});

test('loadSession: a suspended or disabled person’s session is dead', async () => {
  const env = await makeEnvWithSchema();
  const admin = addUser(env, 'admin');
  const rcAdmin = await rcAs(env, admin);
  const { u, s } = await signedIn(env);
  assert.ok(await S.loadSession(req(env, s.cookie)));
  await setStatus(rcAdmin, u.id, 'suspended');
  assert.equal(await S.loadSession(req(env, s.cookie)), null);
  assert.ok(sess(env, s.id).revoked_at, 'and revoked, so reinstating does not revive it');
  await setStatus(rcAdmin, u.id, 'active');
  assert.equal(await S.loadSession(req(env, s.cookie)), null);

  // Status alone is enough, even with no revocation recorded.
  for (const status of ['suspended', 'disabled', 'invited', 'banned', '']) {
    const { u: v, s: sv } = await signedIn(env);
    env.DB.q('UPDATE users SET status = ? WHERE id = ?', status, v.id);
    assert.equal(await S.loadSession(req(env, sv.cookie)), null, status);
  }
});

test('loadSession: lockdown admits only Super Admins (by role or unexpired temporary role)', async () => {
  const env = await makeEnvWithSchema();
  const lockdown = { access_mode: 'lockdown' };
  const { s: emp } = await signedIn(env, 'employee');
  const { s: admin } = await signedIn(env, 'admin');
  const { s: sup } = await signedIn(env, 'super_admin');
  const { u: tu, s: temp } = await signedIn(env, 'admin');
  env.DB.q('INSERT INTO user_roles (user_id, role_id, expires_at, created_at) VALUES (?, ?, ?, ?)', tu.id, roleRow(env, 'super_admin').id, iso(env.__clock() + HOUR), iso(env.__clock()));
  assert.equal(await S.loadSession(req(env, emp.cookie, { policy: lockdown })), null);
  assert.equal(await S.loadSession(req(env, admin.cookie, { policy: lockdown })), null);
  assert.ok(await S.loadSession(req(env, sup.cookie, { policy: lockdown })));
  assert.ok(await S.loadSession(req(env, temp.cookie, { policy: lockdown })));
  for (const policy of [undefined, null, {}, { access_mode: 'allowlist' }]) {
    assert.ok(await S.loadSession(req(env, emp.cookie, { policy })), `policy ${show(policy)}`);
  }
});

test('loadSession: a shortened setting applies to sessions already open; an unreadable one is strict', async () => {
  const env = await makeEnvWithSchema();
  const { s } = await signedIn(env);
  env.__advance(40 * MINUTE);
  assert.ok(await S.loadSession(req(env, s.cookie)));
  env.__advance(31 * MINUTE);
  assert.equal(await S.loadSession(req(env, s.cookie, { policy: { session_idle_minutes: 30 } })), null);
  assert.equal(await S.loadSession(req(env, s.cookie, { policy: { session_idle_minutes: 'junk' } })), null, 'unreadable → 30 minutes');
  assert.ok(await S.loadSession(req(env, s.cookie)));
  env.__advance(70 * MINUTE);
  assert.equal(await S.loadSession(req(env, s.cookie, { policy: { session_absolute_hours: 2 } })), null);
});

test('loadSession: a failed touch does not refuse a valid session', async () => {
  const env = await makeEnvWithSchema();
  const { s } = await signedIn(env);
  env.__advance(5 * MINUTE);
  env.DB.failOn = /SET last_seen_at/;
  const rc = req(env, s.cookie);
  assert.ok(await S.loadSession(rc));
  assert.equal(rc.session.id, s.id);
  env.DB.failOn = null;
  const rows = env.DB.q("SELECT * FROM audit_log WHERE action = 'error'");
  assert.equal(rows.length, 1, 'the real error is recorded, not swallowed');
  assert.equal(rows[0].severity, 'critical');
  assert.match(rows[0].error, /injected failure/);
});

// ---------------------------------------------------------------- pins and step-up

test('nextPin: password change first, then enrolment only when required and nothing usable exists', async () => {
  const env = await makeEnvWithSchema();
  const required = { mfa_policy: 'required' };
  const prompt = { mfa_policy: 'prompt' };
  const t = iso(env.__clock());

  const mc = addUser(env, 'employee', { must_change_password: 1 });
  env.DB.q('INSERT INTO user_passkeys (id, user_id, public_key, algorithm, created_at) VALUES (?, ?, ?, -7, ?)', 'pk-mc', mc.id, '{}', t);
  assert.equal(await S.nextPin(env, mc, prompt), 'password_change');
  for (const v of [1, '1', 'abc', null, true]) assert.equal(await S.nextPin(env, { ...mc, must_change_password: v }, prompt), 'password_change', show(v));

  const u = addUser(env, 'employee');
  assert.equal(await S.nextPin(env, u, prompt), null);
  assert.equal(await S.nextPin(env, u, undefined), null, '§5 default is prompt');
  assert.equal(await S.nextPin(env, u, required), 'mfa_enroll');
  assert.equal(await S.nextPin(env, u, { mfa_policy: 'junk' }), 'mfa_enroll', 'unrecognised reads required');
  assert.equal(await S.nextPin(env, { ...u, mfa_policy: 'required' }, prompt), 'mfa_enroll');

  env.DB.q('INSERT INTO user_totp (user_id, secret_enc, confirmed_at, created_at) VALUES (?, ?, NULL, ?)', u.id, 'v1.x.y', t);
  assert.equal(await S.nextPin(env, u, required), 'mfa_enroll', 'an unconfirmed authenticator is not a factor');
  env.DB.q('UPDATE user_totp SET confirmed_at = ? WHERE user_id = ?', t, u.id);
  assert.equal(await S.nextPin(env, u, required), null);

  const pk = addUser(env, 'employee');
  env.DB.q('INSERT INTO user_passkeys (id, user_id, public_key, algorithm, created_at) VALUES (?, ?, ?, -7, ?)', 'pk-1', pk.id, '{}', t);
  assert.equal(await S.nextPin(env, pk, required), null);

  const sms = addUser(env, 'employee');
  env.DB.q("INSERT INTO code_destinations (user_id, kind, address, created_at) VALUES (?, 'sms', '+15550100', ?)", sms.id, t);
  assert.equal(await S.nextPin(env, sms, required), 'mfa_enroll', 'no SMS provider configured');
  env.TWILIO_ACCOUNT_SID = 'AC1';
  env.TWILIO_AUTH_TOKEN = 'tok';
  assert.equal(await S.nextPin(env, sms, required), 'mfa_enroll', 'half-configured');
  env.TWILIO_FROM = '+15550199';
  assert.equal(await S.nextPin(env, sms, required), null);

  const mail = addUser(env, 'employee');
  env.DB.q("INSERT INTO code_destinations (user_id, kind, address, created_at) VALUES (?, 'email', 'm@acme.com', ?)", mail.id, t);
  env.RESEND_API_KEY = 're_1';
  assert.equal(await S.nextPin(env, mail, required), 'mfa_enroll');
  env.MAIL_FROM = 'portal@acme.com';
  assert.equal(await S.nextPin(env, mail, required), null);

  // A Super Admin — by role or by temporary role — is always 'required'.
  const sup = addUser(env, 'super_admin');
  assert.equal(await S.nextPin(env, sup, prompt), 'mfa_enroll');
  const ts = addUser(env, 'admin', { mfa_policy: 'prompt' });
  env.DB.q('INSERT INTO user_roles (user_id, role_id, expires_at, created_at) VALUES (?, ?, NULL, ?)', ts.id, roleRow(env, 'super_admin').id, t);
  assert.equal(await S.nextPin(env, ts, prompt), 'mfa_enroll');
});

test('setPin, markStepUp and hasFreshStepUp', async () => {
  const env = await makeEnvWithSchema();
  const { s } = await signedIn(env);
  await S.setPin(env, s.id, 'mfa_enroll');
  assert.equal(sess(env, s.id).pinned, 'mfa_enroll');
  await S.setPin(env, s.id, null);
  assert.equal(sess(env, s.id).pinned, null);
  await assert.rejects(S.setPin(env, s.id, 'anything'), /unknown pin/);

  const load = async (extra) => {
    const rc = req(env, s.cookie, extra);
    await S.loadSession(rc);
    return rc;
  };
  assert.equal(S.hasFreshStepUp(await load()), false, 'password only');
  const t0 = env.__clock();
  await S.markStepUp(env, s.id, 'totp', t0);
  const row = sess(env, s.id);
  assert.equal(row.aal, 2);
  assert.equal(row.mfa_at, iso(t0));
  assert.equal(row.mfa_method, 'totp');
  assert.equal(S.hasFreshStepUp(await load()), true);
  env.__advance(15 * MINUTE);
  assert.equal(S.hasFreshStepUp(await load()), true);
  env.__advance(1);
  assert.equal(S.hasFreshStepUp(await load()), false);
  assert.equal(S.hasFreshStepUp(await load({ policy: { step_up_minutes: 60 } })), true);
  for (const v of HOSTILE) {
    await S.markStepUp(env, v, 'totp', t0);
    await S.setPin(env, v, null);
    assert.equal(S.hasFreshStepUp(v), false);
  }
  await S.revokeSession(env, s.id, 'x');
  await S.markStepUp(env, s.id, 'passkey', env.__clock());
  assert.equal(sess(env, s.id).mfa_method, 'totp', 'a revoked session is not stepped up');
});

// ---------------------------------------------------------------- listing and revoking

test('revokeUserSessions keeps the one excepted; listUserSessions shows live sessions by id_ref only', async () => {
  const env = await makeEnvWithSchema();
  const u = addUser(env, 'employee');
  const other = addUser(env, 'employee');
  const rc = await rcAs(env, u);
  const [a, b, c] = [await S.createSession(rc, u, {}), await S.createSession(rc, u, {}), await S.createSession(rc, u, {})];
  const o = await S.createSession(rc, other, {});
  const list = await S.listUserSessions(env, u.id, a.id);
  assert.equal(list.length, 3);
  for (const item of list) {
    assert.deepEqual(Object.keys(item).sort(), ['aal', 'created_at', 'current', 'id_ref', 'ip', 'last_seen_at', 'ua']);
    assert.match(item.id_ref, /^[0-9a-f]{12}$/);
    assert.ok(!JSON.stringify(item).includes(a.id) && !JSON.stringify(item).includes(b.id));
  }
  assert.deepEqual(list.filter((x) => x.current).map((x) => x.id_ref), [a.id.slice(0, 12)]);

  assert.equal(await S.revokeUserSessions(env, u.id, 'user.logout_others', { exceptId: a.id }), 2);
  assert.equal(sess(env, a.id).revoked_at, null);
  assert.equal(sess(env, b.id).revoke_reason, 'user.logout_others');
  assert.ok(sess(env, c.id).revoked_at);
  assert.equal(sess(env, o.id).revoked_at, null);
  assert.equal((await S.listUserSessions(env, u.id, a.id)).length, 1);
  env.__advance(3 * HOUR);
  assert.equal((await S.listUserSessions(env, u.id, a.id)).length, 0, 'idle-expired sessions are not live');

  assert.equal(await S.revokeUserSessions(env, other.id, 'x'), 1);
  for (const v of HOSTILE) {
    assert.equal(await S.revokeUserSessions(env, v, 'x'), 0);
    // A hostile exceptId excepts nothing; hostile options are no options.
    await S.createSession(rc, other, {});
    assert.equal(await S.revokeUserSessions(env, other.id, 'x', { exceptId: v }), 1, show(v));
    await S.createSession(rc, other, {});
    assert.equal(await S.revokeUserSessions(env, other.id, 'x', v), 1, show(v));
    assert.equal(await S.revokeSession(env, v, 'x'), 0);
    assert.deepEqual(await S.listUserSessions(env, v, null), []);
  }
});

test('findSessionByRef: exact 12-hex prefix, optionally for one person; ambiguous or malformed finds nothing', async () => {
  const env = await makeEnvWithSchema();
  const { u, s } = await signedIn(env);
  const other = addUser(env, 'employee');
  const ref = s.id.slice(0, 12);
  assert.equal((await S.findSessionByRef(env, ref)).id, s.id);
  assert.equal((await S.findSessionByRef(env, ref, { userId: u.id })).id, s.id);
  assert.equal(await S.findSessionByRef(env, ref, { userId: other.id }), null);
  const t = iso(env.__clock());
  for (const id of ['abcdef012345' + '0'.repeat(52), 'abcdef012345' + '1'.repeat(52)]) {
    env.DB.q('INSERT INTO sessions (id, user_id, created_at, last_seen_at, idle_expires_at, absolute_expires_at) VALUES (?, ?, ?, ?, ?, ?)', id, u.id, t, t, t, t);
  }
  assert.equal(await S.findSessionByRef(env, 'abcdef012345'), null, 'ambiguous');
  for (const v of [...HOSTILE, ref.toUpperCase(), ref + '0', ref.slice(1), '*', '????????????', s.id]) {
    assert.equal(await S.findSessionByRef(env, v), null, show(v));
  }
  for (const v of [NaN, 'abc', {}, true, Symbol('x')]) assert.equal(await S.findSessionByRef(env, ref, { userId: v }), null, show(v));
});

test('clearSessionCookie expires the cookie with the same attributes', () => {
  assert.equal(S.clearSessionCookie(), '__Host-sid=; Path=/; SameSite=Lax; Secure; HttpOnly; Max-Age=0');
});

await run();
