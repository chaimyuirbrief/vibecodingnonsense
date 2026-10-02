// What the browser sent, and what we say back about the session (CONTRACTS
// §8.4 diag/whoami/me; A §5, §11): names and states, never a credential.

import { test, assert, run } from '../helpers/t.js';
import { freshEnv, client, bootstrap, makeUser, setSetting, sessionToken, deviceCookie, OWNER_IP, SESSION_COOKIE, DEVICE_COOKIE } from '../helpers/flows.js';

function noSecrets(r, c, what) {
  const sid = sessionToken(c);
  const dev = deviceCookie(c);
  assert.ok(sid && dev, 'the client holds both cookies');
  assert.ok(!r.text.includes(sid), `${what}: no session token`);
  assert.ok(!r.text.includes(dev), `${what}: no device cookie value`);
  assert.ok(!r.text.includes(dev.split('.').pop()), `${what}: not even the device cookie's MAC`);
  for (const k of ['password_hash', 'password_salt', 'secret_enc', 'token_hash', 'undo_payload']) assert.ok(!r.text.includes(k), `${what}: ${k}`);
}

test('whoami, /api/me, /api/diag and /api/me/sessions never contain the session token or the device cookie', async () => {
  const env = freshEnv();
  const { client: c } = await bootstrap(env);
  for (const p of ['/api/auth/whoami', '/api/me', '/api/diag', '/api/me/sessions', '/api/me/devices', '/api/me/activity']) {
    const r = await c.get(p);
    assert.equal(r.status, 200, p);
    noSecrets(r, c, p);
  }
});

test('diag lists cookie names and states only', async () => {
  const env = freshEnv();
  const { client: c } = await bootstrap(env);
  c.jar.set('theme', 'sekrit-value-123');
  const r = await c.get('/api/diag', { 'sec-ch-ua-platform': '"macOS"', 'sec-ch-ua-mobile': '?0' });
  assert.equal(r.status, 200);
  assert.deepEqual(r.body.cookies.names.sort(), [DEVICE_COOKIE, SESSION_COOKIE, 'theme'].sort());
  assert.equal(r.body.cookies.count, 3);
  assert.ok(!r.text.includes('sekrit-value-123'));
  assert.equal(r.body.ip, OWNER_IP);
  assert.equal(r.body.country, 'US');
  assert.equal(r.body.asn, 7922);
  assert.equal(r.body.tls_version, 'TLSv1.3');
  assert.deepEqual(r.body.client_hints, { 'sec-ch-ua-mobile': '?0', 'sec-ch-ua-platform': '"macOS"' });
  assert.equal(r.body.device.present, true);
  assert.equal(r.body.device.status, 'approved');
  assert.match(r.body.device.code, /^[2-9A-Z]{4}-[2-9A-Z]{4}$/);
  assert.deepEqual(r.body.session, { present: true, valid: true });
  // A forged device cookie is present but not valid, and names no device.
  c.jar.set(DEVICE_COOKIE, 'forged.AAAA');
  c.jar.set(SESSION_COOKIE, 'x'.repeat(43));
  const forged = await client(env, { ip: OWNER_IP });
  forged.jar = new Map(c.jar);
  const f = await forged.get('/api/diag');
  assert.deepEqual(f.body.device, { present: true, valid: false, status: null, code: null });
  assert.deepEqual(f.body.session, { present: true, valid: false });
});

test('diag is reachable from the pending page, where people are when they need it', async () => {
  const env = freshEnv();
  await bootstrap(env);
  setSetting(env, 'device_gating', '1');
  const c = client(env, { ip: OWNER_IP });
  await c.get('/api/device/status');
  const r = await c.get('/api/diag');
  assert.equal(r.status, 200);
  assert.equal(r.body.device.status, 'pending');
  assert.equal(r.body.session.valid, false);
});

test('whoami tells a signed-out page the org name and the privacy notice', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const anon = client(env, { ip: OWNER_IP });
  const r = await anon.get('/api/auth/whoami');
  assert.equal(r.body.authenticated, false);
  assert.equal(r.body.org_name, 'Acme Inc.');
  assert.match(r.body.privacy_notice, /records technical details/);
  assert.equal(r.body.user, undefined);
  setSetting(env, 'privacy_notice', '0');
  assert.equal((await anon.get('/api/auth/whoami')).body.privacy_notice, null);
  const amy = await makeUser(env, owner.client, { email: 'amy@acme.com' });
  const me = await amy.client.get('/api/auth/whoami');
  assert.equal(me.body.authenticated, true);
  assert.equal(me.body.user.email, 'amy@acme.com');
  assert.equal(me.body.enroll_prompt, true);
  assert.equal(me.body.pinned, null);
  assert.deepEqual(Object.keys(me.body.user).sort(), ['created_at', 'department', 'email', 'employee_no', 'full_name', 'id', 'job_title', 'last_login_at', 'manager_id', 'mfa_policy', 'role', 'status', 'username']);
});

await run();
