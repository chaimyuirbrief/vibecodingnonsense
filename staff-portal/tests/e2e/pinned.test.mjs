// Pinned sessions: "pin, never refuse" (B trap 3; CONTRACTS §7.7, §8.1 step
// 10, §8.3; SPEC §7.8).

import { test, assert, run } from '../helpers/t.js';
import {
  freshEnv, client, makeUser, bootstrap, enrollTotp, totpNow, pageText, q, count, auditRows, setSetting, advance, MINUTE, OWNER, OWNER_IP, PASSWORD, HOSTILE,
} from '../helpers/flows.js';
import { SoftAuthenticator } from '../helpers/authenticator.js';

async function pinnedOwner() {
  const env = freshEnv();
  const c = client(env, { ip: OWNER_IP });
  const r = await c.post('/api/setup', { setup_key: env.SETUP_KEY, ...OWNER });
  assert.equal(r.body.pinned, 'mfa_enroll');
  return { env, c };
}

test('a pinned session reaches only the routes that finish the pinned task', async () => {
  const { c } = await pinnedOwner();
  const me = await c.get('/api/me');
  assert.equal(me.status, 200);
  assert.equal(me.body.pinned, 'mfa_enroll');
  assert.equal(me.body.enroll_prompt, true);
  assert.equal((await c.get('/api/auth/whoami')).body.pinned, 'mfa_enroll');
  for (const [method, path, body] of [
    ['GET', '/api/me/streak'], ['GET', '/api/me/sessions'], ['GET', '/api/me/devices'], ['GET', '/api/me/activity'],
    ['GET', '/api/me/step-up'], ['PATCH', '/api/me', { full_name: 'X' }], ['POST', '/api/me/step-up/code', { code: '123456' }],
    ['POST', '/api/me/mfa/backup/regenerate', {}], ['POST', '/api/me/sessions/revoke-others', {}],
  ]) {
    const r = await c.request(method, path, body);
    assert.equal(r.status, 403, `${method} ${path}`);
    assert.equal(r.body.pinned, 'mfa_enroll', `${method} ${path}`);
    assert.equal(r.body.next, '/account?pin=mfa_enroll');
  }
  assert.equal((await c.post('/api/me/mfa/totp/begin', {})).status, 200, 'enrolment is pinned-ok');
  assert.equal((await c.post('/api/me/mfa/passkey/options', {})).status, 200);
});

test('pages follow the pin: / and /admin and /login go to the pinned task', async () => {
  const { c } = await pinnedOwner();
  for (const p of ['/', '/admin', '/login']) {
    const r = await c.get(p);
    assert.equal(r.status, 302, p);
    assert.equal(r.headers.get('location'), '/account?pin=mfa_enroll', p);
  }
  const acct = await c.get('/account?pin=mfa_enroll');
  assert.equal(acct.text, await pageText('account.html'));
});

test('enrolling an authenticator clears the pin and marks step-up', async () => {
  const { env, c } = await pinnedOwner();
  const begin = await c.post('/api/me/mfa/totp/begin', {});
  assert.ok(!('secret_b32' in begin.body), 'the raw secret travels only inside otpauth / grouped');
  assert.match(begin.body.qr, /^data:image\/svg\+xml;base64,/);
  const secret = new URL(begin.body.otpauth).searchParams.get('secret');
  assert.equal(begin.body.secret_grouped.replace(/ /g, ''), secret);
  for (const v of HOSTILE) {
    const bad = await c.post('/api/me/mfa/totp/confirm', { code: v });
    assert.equal(bad.status, 400, String(typeof v === 'symbol' ? 'Symbol' : JSON.stringify(v)));
  }
  const ok = await c.post('/api/me/mfa/totp/confirm', { code: await totpNow(secret, env) });
  assert.equal(ok.status, 200, ok.text);
  assert.equal(ok.body.pinned, null);
  assert.equal(ok.body.next, '/');
  assert.equal(ok.body.backup_codes.length, 10);
  assert.equal(q(env, 'SELECT pinned FROM sessions')[0].pinned, null);
  const me = await c.get('/api/me');
  assert.equal(me.body.pinned, null);
  assert.equal(me.body.step_up_fresh, true);
  assert.equal(me.body.enroll_prompt, false);
  assert.equal((await c.get('/api/me/streak')).status, 200);
  assert.equal((await c.get('/')).text, await pageText('dashboard.html'));
  assert.equal(auditRows(env, 'mfa.totp.enroll').length, 1);
  assert.equal((await c.post('/api/me/mfa/totp/begin', {})).status, 409, 'one authenticator at a time');
});

test('a forced password change pins first, and enrolling does not unpin it', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const bob = await makeUser(env, owner.client, { email: 'bob@acme.com' });
  const other = client(env, { ip: OWNER_IP });
  assert.equal((await other.post('/api/auth/login', { identifier: 'bob@acme.com', password: PASSWORD })).status, 200);
  q(env, 'UPDATE users SET must_change_password = 1 WHERE id = ?', bob.user.id);
  const r = await bob.client.post('/api/auth/login', { identifier: 'bob@acme.com', password: PASSWORD });
  assert.equal(r.body.pinned, 'password_change');
  assert.equal(r.body.next, '/account?pin=password_change');
  await enrollTotp(env, bob.client);
  assert.equal((await bob.client.get('/api/me')).body.pinned, 'password_change');
  for (const v of HOSTILE) {
    const bad = await bob.client.post('/api/me/password', { current: v, next: 'brand-new-password-1' });
    assert.ok([400, 429].includes(bad.status), String(typeof v === 'symbol' ? 'Symbol' : JSON.stringify(v)));
  }
  advance(env, 16 * MINUTE); // curpw_user: ten checks a quarter-hour
  const changed = await bob.client.post('/api/me/password', { current: PASSWORD, next: 'brand-new-password-1' });
  assert.equal(changed.status, 200, changed.text);
  assert.equal(changed.body.pinned, null);
  assert.equal(auditRows(env, 'password.change').length, 1);
  assert.equal((await other.get('/api/me')).status, 401, 'other sessions were ended');
  assert.equal((await bob.client.get('/api/me/streak')).status, 200);
});

test('mfa_policy required pins an un-enrolled person to enrolment; a passkey clears it', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  setSetting(env, 'mfa_policy', 'required');
  const bob = await makeUser(env, owner.client, { email: 'bob@acme.com' });
  assert.equal((await bob.client.get('/api/me')).body.pinned, 'mfa_enroll', 'the invitation sign-in was pinned');
  const auth = new SoftAuthenticator({ origin: env.ORIGIN, rpId: env.RP_ID });
  const o = await bob.client.post('/api/me/mfa/passkey/options', {});
  const reg = await bob.client.post('/api/me/mfa/passkey/register', { credential: await auth.create(o.body), label: 'Phone' });
  assert.equal(reg.status, 200, reg.text);
  assert.equal(reg.body.pinned, null);
  assert.equal(reg.body.backup_codes.length, 10);
  assert.equal((await bob.client.get('/api/me/sessions')).status, 200);
  assert.equal(count(env, "SELECT COUNT(*) FROM sessions WHERE user_id = ? AND pinned IS NOT NULL AND revoked_at IS NULL AND id = (SELECT id FROM sessions WHERE user_id = ? ORDER BY rowid DESC LIMIT 1)", bob.user.id, bob.user.id), 0);
});

test('logout works from a pinned session and ends it', async () => {
  const { env, c } = await pinnedOwner();
  const r = await c.post('/api/auth/logout', {});
  assert.equal(r.status, 200);
  assert.equal(q(env, 'SELECT revoke_reason FROM sessions')[0].revoke_reason, 'logout');
  assert.equal((await c.get('/api/me')).status, 401);
  assert.equal((await c.get('/api/auth/whoami')).body.authenticated, false);
  assert.equal((await c.post('/api/auth/logout', {})).status, 401);
});

await run();
