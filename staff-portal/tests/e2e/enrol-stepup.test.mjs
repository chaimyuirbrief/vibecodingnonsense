// Adding a factor is not a way around step-up (SPEC §7.9; CONTRACTS §8.4 Me).
//
// Step-up exists for the stale or unattended session. If that session could
// register a passkey of its own (or confirm an authenticator app of its own)
// and then step up with it, step-up would mean "holds a live session": the
// person at the keyboard could reset passwords, open the gate and remove the
// owner's real factors. So adding a factor to an account that can already
// prove itself needs that proof first, and a factor the session just added
// never marks step-up in place of one the account already had.

import { test, assert, run } from '../helpers/t.js';
import {
  freshEnv, bootstrap, makeUser, enrollTotp, stepUp, q, count, auditRows, advance, MINUTE, totpNow, secretFromOtpauth,
} from '../helpers/flows.js';
import { SoftAuthenticator } from '../helpers/authenticator.js';

function key(env) {
  return new SoftAuthenticator({ alg: -7, origin: env.ORIGIN, rpId: env.RP_ID });
}

async function registerPasskey(c, auth, label) {
  const o = await c.post('/api/me/mfa/passkey/options', {});
  if (o.status !== 200) return o;
  return c.post('/api/me/mfa/passkey/register', { credential: await auth.create(o.body), label });
}

async function stepUpWithPasskey(c, auth) {
  const o = await c.post('/api/me/step-up/passkey/options', {});
  if (o.status !== 200) return o;
  return c.post('/api/me/step-up/passkey/verify', { credential: await auth.get(o.body) });
}

test('a stale session cannot register its own passkey and step up with it', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env); // authenticator app, step-up fresh
  const emp = await makeUser(env, owner.client, { email: 'emp@acme.com' });
  const c = owner.client;
  advance(env, 30 * MINUTE); // step-up stale, session alive (idle 120 min)

  const before = await c.post(`/api/admin/users/${emp.user.id}/reset-password`, {});
  assert.equal(before.status, 403);
  assert.equal(before.body.step_up_required, true);

  // Someone at the unattended session, holding none of the owner's factors.
  const intruder = key(env);
  const opts = await c.post('/api/me/mfa/passkey/options', {});
  assert.equal(opts.status, 403, opts.text);
  assert.equal(opts.body.step_up_required, true);
  const reg = await registerPasskey(c, intruder, 'intruder');
  assert.equal(reg.status, 403);
  assert.equal(count(env, 'SELECT COUNT(*) FROM user_passkeys WHERE user_id = ?', owner.user.id), 0, 'no passkey was added');
  assert.equal(auditRows(env, 'mfa.passkey.add').length, 0);
  assert.notEqual((await stepUpWithPasskey(c, intruder)).status, 200);

  const after = await c.post(`/api/admin/users/${emp.user.id}/reset-password`, {});
  assert.equal(after.status, 403, 'the danger write is still refused');
  assert.equal(after.body.temporary_password, undefined);
  assert.equal((await c.post('/api/admin/gate/open', { hours: 1 })).status, 403);
  assert.equal((await c.del('/api/me/mfa/totp')).status, 403, 'the owner’s authenticator stays');
  assert.equal(count(env, 'SELECT COUNT(*) FROM user_totp WHERE user_id = ?', owner.user.id), 1);
  assert.equal((await c.post('/api/me/mfa/backup/regenerate', {})).status, 403);

  // The owner, proving the factor they already have, adds a passkey as before.
  await stepUp(env, c);
  const mine = key(env);
  const ok = await registerPasskey(c, mine, 'Laptop');
  assert.equal(ok.status, 200, ok.text);
  assert.equal(count(env, 'SELECT COUNT(*) FROM user_passkeys WHERE user_id = ?', owner.user.id), 1);
  assert.equal(auditRows(env, 'mfa.passkey.add').at(-1).severity, 'notice', 'a new way in stands out in the log');
  assert.equal(auditRows(env, 'mfa.totp.enroll').at(-1).severity, 'notice');
});

test('a stale session cannot confirm its own authenticator app to mint a step-up', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const adm = await makeUser(env, owner.client, { email: 'adm@acme.com', role: 'admin' });
  // The admin's real factor, added while the account had none.
  const laptop = key(env);
  const reg = await registerPasskey(adm.client, laptop, 'Laptop');
  assert.equal(reg.status, 200, reg.text);
  const pkId = reg.body.passkey.id;

  advance(env, 20 * MINUTE);
  assert.equal((await adm.client.get('/api/me')).body.step_up_fresh, false, 'precondition: stale');
  const allow = await adm.client.post('/api/admin/network/allow', { cidr: '185.15.56.0/24', tier: 1 });
  assert.equal(allow.body.step_up_required, true, allow.text);

  const begin = await adm.client.post('/api/me/mfa/totp/begin', {});
  assert.equal(begin.status, 403, begin.text);
  assert.equal(begin.body.step_up_required, true);
  assert.equal(count(env, 'SELECT COUNT(*) FROM user_totp WHERE user_id = ?', adm.user.id), 0);
  // A confirm with no begin, or a begin left from earlier, is refused the same way.
  const confirm = await adm.client.post('/api/me/mfa/totp/confirm', { code: '123456' });
  assert.equal(confirm.status, 403);
  assert.equal(confirm.body.step_up_required, true);

  assert.equal((await adm.client.get('/api/me')).body.step_up_fresh, false);
  assert.equal((await adm.client.post('/api/admin/network/allow', { cidr: '185.15.56.0/24', tier: 1 })).status, 403);
  assert.equal((await adm.client.del(`/api/me/mfa/passkey/${encodeURIComponent(pkId)}`)).status, 403);
  assert.equal(count(env, 'SELECT COUNT(*) FROM user_passkeys WHERE user_id = ?', adm.user.id), 1);
});

test('confirming an authenticator marks step-up only for an account that had no factor', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);

  // First factor: the session is the only proof there is, so it counts.
  const amy = await makeUser(env, owner.client, { email: 'amy@acme.com' });
  assert.equal((await amy.client.get('/api/me')).body.step_up_fresh, false);
  await enrollTotp(env, amy.client);
  assert.equal((await amy.client.get('/api/me')).body.step_up_fresh, true);

  // Second factor: the step-up the passkey earned is not extended by it.
  const bob = await makeUser(env, owner.client, { email: 'bob@acme.com' });
  const laptop = key(env);
  assert.equal((await registerPasskey(bob.client, laptop, 'Laptop')).status, 200);
  assert.equal((await stepUpWithPasskey(bob.client, laptop)).status, 200);
  const steppedAt = q(env, 'SELECT mfa_at FROM sessions WHERE user_id = ? AND revoked_at IS NULL', bob.user.id)[0].mfa_at;
  advance(env, 10 * MINUTE);
  const begin = await bob.client.post('/api/me/mfa/totp/begin', {});
  assert.equal(begin.status, 200, begin.text);
  const secret = secretFromOtpauth(begin.body.otpauth);
  const conf = await bob.client.post('/api/me/mfa/totp/confirm', { code: await totpNow(secret, env) });
  assert.equal(conf.status, 200, conf.text);
  assert.equal(q(env, 'SELECT mfa_at FROM sessions WHERE user_id = ? AND revoked_at IS NULL', bob.user.id)[0].mfa_at, steppedAt);
  advance(env, 6 * MINUTE);
  assert.equal((await bob.client.get('/api/me')).body.step_up_fresh, false, 'fifteen minutes after the passkey, not after the new app');
});

test('a session pinned to enrolment adds its factor without a step-up', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  // A Super Admin is always 'required': pinned until a factor is confirmed.
  const sue = await makeUser(env, owner.client, { email: 'sue@acme.com', role: 'super_admin' });
  assert.equal((await sue.client.get('/api/me')).body.pinned, 'mfa_enroll');
  const r = await registerPasskey(sue.client, key(env), 'Laptop');
  assert.equal(r.status, 200, r.text);
  assert.equal(r.body.pinned, null);
});

await run();
