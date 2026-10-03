// The gate through the worker: modes, shells, hard blocks, refusals
// (CONTRACTS §7.8, §8.1; A §2, §5; B §6; SPEC §3).

import { test, assert, run } from '../helpers/t.js';
import {
  freshEnv, client, bootstrap, makeUser, stepUp, nextTotp, pageText, rawRequest, q, count, setSetting, actorRc, advance, MINUTE, OWNER_IP, PASSWORD, HOSTILE, DEVICE_COOKIE,
} from '../helpers/flows.js';
import { DECOY_404 } from '../../src/gate.js';
import { setDeviceStatus } from '../../src/devices.js';

async function world() {
  const env = freshEnv();
  const owner = await bootstrap(env);
  return { env, owner };
}

test('allowlist mode: a stranger gets an empty 403 everywhere; the office network gets the sign-in page', async () => {
  const { env } = await world();
  const stranger = client(env);
  for (const p of ['/', '/login', '/api/auth/whoami', '/js/login.js', '/api/diag']) {
    const r = await stranger.get(p);
    assert.equal(r.status, 403, p);
    assert.equal(r.text, '', p);
  }
  assert.equal(count(env, "SELECT COUNT(*) FROM visits WHERE decision = 'none' AND reason = 'not_allowlisted'"), 5, 'every refusal is in the visit log');
  const office = client(env, { ip: OWNER_IP });
  assert.equal((await office.get('/')).text, await pageText('login.html'));
});

test('device gating: an unapproved device sees only the pending shell, until it is approved by code', async () => {
  const { env, owner } = await world();
  setSetting(env, 'device_gating', '1');
  const newcomer = client(env, { ip: OWNER_IP });
  for (const p of ['/', '/admin', '/login', '/dashboard']) {
    const r = await newcomer.get(p);
    assert.equal(r.status, 302, p);
    assert.equal(r.headers.get('location'), '/pending', p);
  }
  assert.equal((await newcomer.get('/pending')).text, await pageText('pending.html'));
  assert.equal((await newcomer.get('/js/pending.js')).status, 200);
  assert.equal((await newcomer.get('/js/login.js')).status, 403, 'outside the shell');
  for (const [m, p] of [['POST', '/api/auth/login'], ['GET', '/api/auth/whoami'], ['GET', '/api/me']]) {
    const r = await newcomer.request(m, p, m === 'POST' ? { identifier: 'x', password: 'y' } : undefined);
    assert.equal(r.status, 403, p);
    assert.equal(r.text, '', p);
  }
  const st = await newcomer.get('/api/device/status');
  assert.equal(st.status, 200);
  assert.equal(st.body.status, 'pending');
  assert.match(st.body.code, /^[2-9A-HJKMNP-Z]{4}-[2-9A-HJKMNP-Z]{4}$/);
  assert.ok(newcomer.jar.has(DEVICE_COOKIE), 'a pending device was minted');
  assert.equal((await newcomer.get('/api/device/status')).body.code, st.body.code, 'stable');
  assert.equal((await newcomer.get('/api/diag')).status, 200);

  // The owner approves it from an approved device, after a step-up (the
  // one setup's enrolment gave has gone stale).
  advance(env, 16 * MINUTE);
  const noStep = await owner.client.post('/api/me/devices/approve', { code: st.body.code });
  assert.equal(noStep.status, 403);
  assert.equal(noStep.body.step_up_required, true);
  await stepUp(env, owner.client);
  for (const v of HOSTILE) {
    const r = await owner.client.post('/api/me/devices/approve', { code: v });
    assert.ok([404, 429].includes(r.status), String(typeof v === 'symbol' ? 'Symbol' : JSON.stringify(v)));
  }
  q(env, "DELETE FROM auth_attempts WHERE kind = 'device_code_user'");
  const ok = await owner.client.post('/api/me/devices/approve', { code: st.body.code.toLowerCase().replace('-', ' ') });
  assert.equal(ok.status, 200, ok.text);
  assert.equal((await newcomer.get('/api/device/status')).body.status, 'approved');
  assert.equal((await newcomer.get('/')).text, await pageText('login.html'));
});

test('approving a device for yourself needs an approved device to approve FROM', async () => {
  const { env, owner } = await world();
  // Amy signs in from the office on a device nobody approved.
  const amy = await makeUser(env, owner.client, { email: 'amy@acme.com', totp: true });
  const office = client(env, { ip: OWNER_IP });
  const p = await office.post('/api/auth/login', { identifier: 'amy@acme.com', password: PASSWORD });
  assert.equal((await office.post('/api/auth/mfa/code', { token: p.body.token, code: await nextTotp(env, amy.totpSecret) })).status, 200);
  const r = await office.post('/api/me/devices/approve', { code: 'ABCD-EFGH' });
  assert.equal(r.status, 403);
  assert.equal(r.body.code, 'device_not_approved');
});

test('invite_only: the office network reaches only the approval queue; strangers nothing', async () => {
  const { env, owner } = await world();
  const bob = await makeUser(env, owner.client, { email: 'bob@acme.com' });
  setSetting(env, 'access_mode', 'invite_only');
  const office = client(env, { ip: OWNER_IP });
  const r = await office.get('/login');
  assert.equal(r.headers.get('location'), '/pending');
  assert.equal((await client(env).get('/')).status, 403);
  assert.equal((await bob.client.get('/api/me')).status, 200, 'an approved device still gets in');
  assert.equal((await owner.client.get('/api/me')).status, 200);
});

test('request_access: strangers get the request form and nothing else', async () => {
  const { env } = await world();
  setSetting(env, 'access_mode', 'request_access');
  const s = client(env);
  const req = await pageText('request.html');
  assert.equal((await s.get('/')).text, req);
  assert.equal((await s.get('/request-access')).text, req);
  assert.equal((await s.get('/js/request.js')).status, 200);
  assert.equal((await s.get('/login')).status, 403);
  assert.equal((await s.post('/api/auth/login', { identifier: 'x', password: 'y' })).status, 403);
});

test('fingerprint_gate: sign-in waits for a fingerprint, then the gate opens', async () => {
  const { env, owner } = await world();
  const bob = await makeUser(env, owner.client, { email: 'bob@acme.com', ip: OWNER_IP });
  setSetting(env, 'access_mode', 'fingerprint_gate');
  const s = client(env);
  assert.equal((await s.get('/')).text, await pageText('login.html'));
  assert.equal((await s.get('/js/fp.js')).status, 200);
  assert.equal((await s.get('/api/auth/whoami')).body.authenticated, false);
  const first = await s.post('/api/auth/login', { identifier: 'bob@acme.com', password: PASSWORD });
  assert.equal(first.status, 403);
  assert.equal(first.body.fingerprint_required, true);
  assert.equal(count(env, "SELECT COUNT(*) FROM auth_attempts WHERE kind = 'login_ip'"), 0, 'nothing was checked');
  assert.equal((await s.get('/api/me')).status, 403, 'outside the login shell');
  const fp = await s.post('/api/fp', { signals: { v: 1, ua: s.ua, languages: ['en-US'], tz: 'America/New_York', screen: { w: 1440, h: 900, cd: 24, dpr: 2 } } });
  assert.equal(fp.status, 200);
  assert.ok(s.jar.has('__Host-fp'));
  const second = await s.post('/api/auth/login', { identifier: 'bob@acme.com', password: PASSWORD });
  assert.equal(second.status, 200, second.text);
  assert.equal(second.body.ok, true);
  for (const v of HOSTILE) {
    const r = await client(env).post('/api/fp', { signals: v });
    assert.equal(r.status, 200, 'junk signals are dropped, not trusted');
  }
  const big = await client(env).post('/api/fp', { signals: { fonts: ['x'.repeat(20000)] } });
  assert.equal(big.status, 400);
});

test('decoy style: a refusal looks like a stock server page, still with every header', async () => {
  const { env } = await world();
  setSetting(env, 'deny_style', 'decoy');
  const r = await client(env).get('/admin');
  assert.equal(r.status, 404);
  assert.equal(r.text, DECOY_404);
  assert.match(r.headers.get('content-security-policy'), /default-src 'none'/);
});

test('hard blocks beat everything: a blocklisted address, a blocked device, no address', async () => {
  const { env, owner } = await world();
  const bob = await makeUser(env, owner.client, { email: 'bob@acme.com' });
  const dev = q(env, 'SELECT device_id FROM sessions WHERE user_id = ? ORDER BY rowid DESC LIMIT 1', bob.user.id)[0].device_id;
  await setDeviceStatus(await actorRc(env, owner.user), dev, 'blocked');
  const blocked = await bob.client.get('/api/me');
  assert.equal(blocked.status, 403);
  assert.equal(blocked.text, '');
  q(env, "INSERT INTO blocked_ips (cidr, created_at) VALUES (?, '2026-01-01T00:00:00.000Z')", `${OWNER_IP}/32`);
  const own = await owner.client.get('/api/me');
  assert.equal(own.status, 403, 'blocklisted even though allowlisted, signed in and approved');
  for (const ip of ['', 'garbage', '999.1.1.1']) {
    const r = await rawRequest(env, 'GET', '/', { ip });
    assert.equal(r.status, 403, `ip '${ip}'`);
  }
});

test('public mode: a stranger reaches the sign-in page', async () => {
  const { env } = await world();
  setSetting(env, 'access_mode', 'public');
  assert.equal((await client(env).get('/')).text, await pageText('login.html'));
  setSetting(env, 'access_mode', 'free-for-all'); // unrecognised reads as lockdown
  assert.equal((await client(env).get('/')).status, 403);
});

await run();
