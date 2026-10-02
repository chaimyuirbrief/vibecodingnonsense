// One completion path for every way in (CONTRACTS §7.9; A §7.2, §14.8): for
// EVERY method the same things happen exactly once — a session, the device
// ledger, last_login_at, the streak, the per-account counters cleared (the
// per-IP bucket kept), and ONE login.success row.

import { test, assert, run } from '../helpers/t.js';
import {
  freshEnv, client, bootstrap, makeUser, signIn, actorRc, fakeProvider, lastCodeSent, q, count, nowIso, roleId, OWNER, OWNER_IP, PASSWORD, TWILIO,
} from '../helpers/flows.js';
import { createUser } from '../../src/users.js';
import { createInvitation } from '../../src/invitations.js';
import { addDestination } from '../../src/mfa/otp.js';
import { SoftAuthenticator } from '../helpers/authenticator.js';
import { completeSignIn } from '../../src/signin.js';

function snap(env, uid) {
  return {
    sessions: count(env, 'SELECT COUNT(*) FROM sessions WHERE user_id = ?', uid),
    ledger: count(env, 'SELECT COALESCE(SUM(sign_ins), 0) FROM device_users WHERE user_id = ?', uid),
    mine: count(env, "SELECT COUNT(*) FROM audit_log WHERE action = 'login.success' AND target_id = ?", String(uid)),
    all: count(env, "SELECT COUNT(*) FROM audit_log WHERE action = 'login.success'"),
    loginIp: count(env, "SELECT COUNT(*) FROM auth_attempts WHERE kind = 'login_ip'"),
  };
}

async function proveTail(env, uid, run, how) {
  const before = snap(env, uid);
  // Leave something in the per-account buckets for the tail to clear.
  const email = uid ? q(env, 'SELECT email FROM users WHERE id = ?', uid)[0].email : null;
  if (uid) {
    q(env, "INSERT INTO auth_attempts (kind, subject, at) VALUES ('mfa_user', ?, ?)", String(uid), nowIso(env));
    q(env, "INSERT INTO auth_attempts (kind, subject, at) VALUES ('login_id', ?, ?)", email, nowIso(env));
    q(env, 'UPDATE users SET failed_logins = 3 WHERE id = ?', uid);
  }
  const r = await run();
  assert.equal(r.status, 200, `${how}: ${r.text}`);
  assert.equal(r.body.ok, true, how);
  const id = uid ?? r.body.user.id;
  const after = snap(env, id);
  const t = nowIso(env);
  assert.equal(after.sessions, (uid ? before.sessions : 0) + 1, `${how}: one new session`);
  assert.equal(after.ledger, (uid ? before.ledger : 0) + 1, `${how}: the device ledger counted it`);
  assert.equal(after.all, before.all + 1, `${how}: exactly one login.success row`);
  assert.equal(after.mine, (uid ? before.mine : 0) + 1, `${how}: about this person`);
  assert.equal(after.loginIp, before.loginIp + (['password', 'grace', 'totp', 'backup', 'sms', 'passkey'].includes(how) ? 1 : 0), `${how}: per-IP bucket kept`);
  const row = q(env, "SELECT * FROM audit_log WHERE action = 'login.success' ORDER BY seq DESC LIMIT 1")[0];
  assert.equal(row.target_id, String(id));
  assert.equal(row.actor_id, id);
  assert.ok(row.session_ref && row.session_ref.length === 12, `${how}: the row names the session`);
  assert.equal(JSON.parse(row.after_state).method, how);
  const user = q(env, 'SELECT last_login_at, failed_logins FROM users WHERE id = ?', id)[0];
  assert.equal(user.last_login_at, t, `${how}: last_login_at`);
  assert.equal(user.failed_logins, 0, `${how}: failed logins cleared`);
  const streak = q(env, 'SELECT * FROM streaks WHERE user_id = ?', id)[0];
  assert.ok(streak, `${how}: streak touched`);
  assert.equal(streak.last_at, t, `${how}: streak last_at is this sign-in`);
  assert.equal(r.body.streak.last_at, t);
  assert.ok(count(env, 'SELECT COUNT(*) FROM streak_days WHERE user_id = ? AND day = ?', id, streak.last_day) === 1);
  const session = q(env, 'SELECT * FROM sessions WHERE user_id = ? ORDER BY rowid DESC LIMIT 1', id)[0];
  assert.equal(session.mfa_method, how);
  assert.equal(count(env, 'SELECT COUNT(*) FROM device_users WHERE user_id = ? AND device_id = ?', id, session.device_id), 1, `${how}: the session's device is in the ledger`);
  assert.equal(count(env, "SELECT COUNT(*) FROM auth_attempts WHERE kind IN ('mfa_user', 'login_id') AND subject IN (?, ?)", String(id), email ?? ''), 0, `${how}: per-account counters cleared`);
  return r;
}

test('setup', async () => {
  const env = freshEnv();
  const c = client(env, { ip: OWNER_IP });
  assert.equal((await c.get('/api/setup/status')).status, 200); // the schema exists
  await proveTail(env, null, () => c.post('/api/setup', { setup_key: env.SETUP_KEY, ...OWNER }), 'setup');
});

test('invitation', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const rc = await actorRc(env, owner.user);
  const u = await createUser(rc, { email: 'ivan@acme.com', full_name: 'Ivan', role_id: roleId(env, 'employee') });
  const { token } = await createInvitation(rc, u.id);
  const c = client(env);
  assert.equal((await c.get(`/invite?token=${token}`)).status, 200);
  await proveTail(env, u.id, () => c.post('/api/invite/accept', { token, password: PASSWORD }), 'invitation');
});

test('password only (nothing enrolled, prompt policy)', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const bob = await makeUser(env, owner.client, { email: 'bob@acme.com' });
  const r = await proveTail(env, bob.user.id, () => bob.client.post('/api/auth/login', { identifier: 'bob@acme.com', password: PASSWORD }), 'password');
  assert.equal(r.body.enroll_prompt, true);
  assert.equal(r.body.pinned, null);
});

test('authenticator app', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const amy = await makeUser(env, owner.client, { email: 'amy@acme.com', totp: true });
  await proveTail(env, amy.user.id, () => signIn(env, amy.client, 'amy@acme.com', PASSWORD), 'totp');
});

test('backup code', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const amy = await makeUser(env, owner.client, { email: 'amy@acme.com', totp: true });
  await proveTail(env, amy.user.id, async () => {
    const p = await amy.client.post('/api/auth/login', { identifier: 'amy@acme.com', password: PASSWORD });
    return amy.client.post('/api/auth/mfa/code', { token: p.body.token, code: amy.client.backupCodes[3] });
  }, 'backup');
});

test('grace window', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const amy = await makeUser(env, owner.client, { email: 'amy@acme.com', totp: true, ip: OWNER_IP });
  assert.equal((await signIn(env, amy.client, 'amy@acme.com', PASSWORD)).status, 200);
  await proveTail(env, amy.user.id, () => amy.client.post('/api/auth/login', { identifier: 'amy@acme.com', password: PASSWORD }), 'grace');
  assert.equal(count(env, 'SELECT COUNT(*) FROM mfa_grace WHERE user_id = ?', amy.user.id), 1);
});

test('texted code', async () => {
  const provider = fakeProvider();
  const env = freshEnv({ vars: { __fetch: provider.fetch, ...TWILIO } });
  const owner = await bootstrap(env);
  const amy = await makeUser(env, owner.client, { email: 'amy@acme.com' });
  await addDestination(await actorRc(env, owner.user), amy.user.id, { kind: 'sms', address: '+15555550123' });
  await proveTail(env, amy.user.id, async () => {
    const p = await amy.client.post('/api/auth/login', { identifier: 'amy@acme.com', password: PASSWORD });
    return amy.client.post('/api/auth/mfa/otp', { token: p.body.token, code: lastCodeSent(provider) });
  }, 'sms');
});

test('passkey', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const amy = await makeUser(env, owner.client, { email: 'amy@acme.com' });
  const auth = new SoftAuthenticator({ origin: env.ORIGIN, rpId: env.RP_ID });
  const o = await amy.client.post('/api/me/mfa/passkey/options', {});
  assert.equal((await amy.client.post('/api/me/mfa/passkey/register', { credential: await auth.create(o.body), label: 'Key' })).status, 200);
  await proveTail(env, amy.user.id, async () => {
    const p = await amy.client.post('/api/auth/login', { identifier: 'amy@acme.com', password: PASSWORD });
    const opts = await amy.client.post('/api/auth/mfa/passkey/options', { token: p.body.token });
    return amy.client.post('/api/auth/mfa/passkey/verify', { token: p.body.token, credential: await auth.get(opts.body) });
  }, 'passkey');
});

test('a sign-in that fails part-way leaves no partial tail behind', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const amy = await makeUser(env, owner.client, { email: 'amy@acme.com', totp: true });
  const before = snap(env, amy.user.id);
  const p = await amy.client.post('/api/auth/login', { identifier: 'amy@acme.com', password: PASSWORD });
  const r = await amy.client.post('/api/auth/mfa/code', { token: p.body.token, code: '000000' });
  assert.equal(r.status, 401);
  const after = snap(env, amy.user.id);
  assert.equal(after.sessions, before.sessions);
  assert.equal(after.ledger, before.ledger);
  assert.equal(after.all, before.all);
});

test('the tail itself refuses an account that stopped being active a moment ago', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const bob = await makeUser(env, owner.client, { email: 'bob@acme.com' });
  const before = snap(env, bob.user.id);
  q(env, "UPDATE users SET status = 'suspended' WHERE id = ?", bob.user.id);
  const rc = await actorRc(env, bob.user, { ip: OWNER_IP, device: { id: null, row: null }, cookies: {}, ipTier: 1 });
  await assert.rejects(completeSignIn(rc, bob.user, 'password', { aal: 1 }), (e) => e.status === 401);
  const after = snap(env, bob.user.id);
  assert.equal(after.sessions, before.sessions);
  assert.equal(after.all, before.all);
  assert.deepEqual(rc.setCookies, []);
  await assert.rejects(completeSignIn(rc, bob.user, 'magic', {}), /unknown method/);
});

test('the tail itself refuses an account that stopped being active a moment ago', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const bob = await makeUser(env, owner.client, { email: 'bob@acme.com' });
  const before = snap(env, bob.user.id);
  q(env, "UPDATE users SET status = 'suspended' WHERE id = ?", bob.user.id);
  const rc = await actorRc(env, bob.user, { ip: OWNER_IP, device: { id: null, row: null }, cookies: {}, ipTier: 1 });
  await assert.rejects(completeSignIn(rc, bob.user, 'password', { aal: 1 }), (e) => e.status === 401);
  const after = snap(env, bob.user.id);
  assert.equal(after.sessions, before.sessions);
  assert.equal(after.all, before.all);
  assert.deepEqual(rc.setCookies, []);
  await assert.rejects(completeSignIn(rc, bob.user, 'magic', {}), /unknown method/);
});

await run();
