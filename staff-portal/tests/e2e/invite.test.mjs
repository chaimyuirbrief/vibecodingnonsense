// Invitation links through the gate (CONTRACTS §8.3 /invite, §8.4; D11;
// SPEC §6.7): a valid link is the only thing that gets a stranger past a mode
// that would otherwise show them nothing — and only as far as the invitation.

import { test, assert, run } from '../helpers/t.js';
import {
  freshEnv, client, bootstrap, makeUser, actorRc, roleId, rawRequest, Client, worker, pageText, q, count, auditRows, advance, setSetting, DAY, MINUTE, OWNER_IP, PASSWORD, HOSTILE,
  DEVICE_COOKIE, SESSION_COOKIE,
} from '../helpers/flows.js';
import { createUser } from '../../src/users.js';
import { createInvitation, revokeInvitation } from '../../src/invitations.js';
import { PASS_COOKIE } from '../../src/gate.js';

async function world() {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const rc = await actorRc(env, owner.user);
  const ivan = await createUser(rc, { email: 'ivan@acme.com', full_name: 'Ivan Invitee', role_id: roleId(env, 'employee') });
  const inv = await createInvitation(rc, ivan.id);
  return { env, owner, rc, ivan, inv };
}

function nothing(r, what) {
  assert.equal(r.status, 403, what);
  assert.equal(r.text, '', what);
  assert.equal(r.headers.get('set-cookie'), null, `${what}: no pass cookie`);
}

test('a stranger with no link, or a bad one, sees nothing and gets no pass', async () => {
  const { env, inv } = await world();
  const s = client(env);
  nothing(await s.get('/invite'), 'no token');
  for (const t of ['', 'short', 'A'.repeat(43), `${inv.token}x`, inv.token.slice(1), encodeURIComponent('<script>')]) {
    nothing(await s.get(`/invite?token=${t}`), `token ${t.slice(0, 10)}`);
  }
  assert.equal(count(env, "SELECT COUNT(*) FROM auth_attempts WHERE kind = 'invite_ip'"), 1, 'only the well-shaped unknown token was looked up');
});

test('a valid link sets the pass and opens the invite shell — and nothing more', async () => {
  const { env, inv } = await world();
  const s = client(env);
  const page = await s.get(`/invite?token=${inv.token}`);
  assert.equal(page.status, 200);
  assert.equal(page.text, await pageText('invite.html'));
  assert.ok(s.jar.has(PASS_COOKIE));
  assert.match(page.headers.get('set-cookie'), /__Host-pass=.*Max-Age=900/);
  assert.equal((await s.get('/invite')).status, 200, 'the pass now opens /invite');
  for (const p of ['/js/invite.js', '/js/fp.js', '/js/common.js', '/css/app.css']) assert.equal((await s.get(p)).status, 200, p);
  const info = await s.post('/api/invite/lookup', { token: inv.token });
  assert.equal(info.status, 200);
  assert.deepEqual(Object.keys(info.body).sort(), ['email', 'expires_at', 'full_name', 'org_name', 'privacy_notice']);
  assert.equal(info.body.email, 'ivan@acme.com');
  for (const [m, p] of [['GET', '/'], ['GET', '/login'], ['GET', '/js/login.js'], ['GET', '/api/me'], ['GET', '/api/auth/whoami'], ['POST', '/api/auth/login']]) {
    const r = await s.request(m, p, m === 'POST' ? {} : undefined);
    assert.equal(r.status, 403, `${m} ${p}`);
  }
});

test('accepting signs in, activates, approves this device and spends the link', async () => {
  const { env, ivan, inv } = await world();
  const s = client(env);
  await s.get(`/invite?token=${inv.token}`);
  for (const v of HOSTILE) {
    const r = await s.post('/api/invite/accept', { token: inv.token, password: v });
    assert.equal(r.status, 400, `password ${String(typeof v === 'symbol' ? 'Symbol' : JSON.stringify(v))}`);
  }
  assert.equal(q(env, 'SELECT status FROM users WHERE id = ?', ivan.id)[0].status, 'invited', 'a refused accept spends nothing');
  for (const v of HOSTILE) {
    const r = await s.post('/api/invite/accept', { token: v, password: PASSWORD });
    assert.ok([404, 429].includes(r.status), `token ${String(typeof v === 'symbol' ? 'Symbol' : JSON.stringify(v))}`);
  }
  q(env, "DELETE FROM auth_attempts WHERE kind = 'invite_ip'");
  const r = await s.post('/api/invite/accept', { token: inv.token, password: PASSWORD, full_name: '  Ivan I. Invitee ' });
  assert.equal(r.status, 200, r.text);
  assert.equal(r.body.user.full_name, 'Ivan I. Invitee');
  assert.equal(r.body.pinned, null);
  assert.ok(s.jar.has(SESSION_COOKIE) && s.jar.has(DEVICE_COOKIE));
  assert.equal(s.jar.has(PASS_COOKIE), false, 'the pass is cleared');
  const u = q(env, 'SELECT status, password_hash FROM users WHERE id = ?', ivan.id)[0];
  assert.equal(u.status, 'active');
  assert.ok(u.password_hash);
  const dev = q(env, 'SELECT d.* FROM devices d JOIN sessions s ON s.device_id = d.id WHERE s.user_id = ?', ivan.id)[0];
  assert.equal(dev.status, 'approved');
  assert.equal(auditRows(env, 'invite.accept').length, 1);
  assert.equal(auditRows(env, 'device.approve').at(-1).target_id, dev.id);
  assert.ok(!r.text.includes(PASSWORD) && !JSON.stringify(auditRows(env)).includes(PASSWORD));
  // Now trusted by device: the whole portal, and the link is spent.
  assert.equal((await s.get('/')).text, await pageText('dashboard.html'));
  assert.equal((await s.post('/api/invite/accept', { token: inv.token, password: PASSWORD })).status, 404);
  nothing(await client(env).get(`/invite?token=${inv.token}`), 'a spent link');
});

test('expired and revoked links open nothing', async () => {
  const { env, rc, ivan, inv } = await world();
  advance(env, 7 * DAY + MINUTE);
  nothing(await client(env).get(`/invite?token=${inv.token}`), 'expired');
  const fresh = await createInvitation(await actorRc(env, rc.user), ivan.id);
  const id = q(env, 'SELECT id FROM invitations ORDER BY id DESC LIMIT 1')[0].id;
  await revokeInvitation(await actorRc(env, rc.user), id);
  nothing(await client(env).get(`/invite?token=${fresh.token}`), 'revoked');
});

test('a link never overrides a hard block or lockdown', async () => {
  const { env, inv } = await world();
  const s = client(env, { ip: '185.15.56.77' });
  q(env, "INSERT INTO blocked_ips (cidr, created_at) VALUES ('185.15.56.0/24', '2026-01-01T00:00:00.000Z')");
  nothing(await s.get(`/invite?token=${inv.token}`), 'blocklisted');
  setSetting(env, 'access_mode', 'lockdown');
  nothing(await client(env).get(`/invite?token=${inv.token}`), 'lockdown');
  nothing(await client(env, { cf: { country: 'T1' } }).get(`/invite?token=${inv.token}`), 'tor');
});

test('in request_access mode a link shows the invitation, not the request form', async () => {
  const { env, inv } = await world();
  setSetting(env, 'access_mode', 'request_access');
  const s = client(env);
  const r = await s.get(`/invite?token=${inv.token}`);
  assert.equal(r.text, await pageText('invite.html'));
  assert.equal((await s.post('/api/invite/accept', { token: inv.token, password: PASSWORD })).status, 200);
});

test('in fingerprint_gate a link opens the invitation inside the login shell — no pass, and accepting works', async () => {
  const { env, inv, ivan } = await world();
  setSetting(env, 'access_mode', 'fingerprint_gate');
  const s = client(env);
  const page = await s.get(`/invite?token=${inv.token}`);
  assert.equal(page.status, 200, 'the link is not a dead end');
  assert.equal(page.text, await pageText('invite.html'));
  assert.ok(!s.jar.has(PASS_COOKIE), 'fingerprint_gate never hands out a pass');
  for (const p of ['/js/invite.js', '/js/fp.js', '/js/common.js', '/css/app.css']) assert.equal((await s.get(p)).status, 200, p);
  assert.equal((await s.post('/api/invite/lookup', { token: inv.token })).status, 200);
  const accept = await s.post('/api/invite/accept', { token: inv.token, password: PASSWORD, full_name: 'Ivan Invitee' });
  assert.equal(accept.status, 200, accept.text);
  assert.equal(q(env, 'SELECT status FROM users WHERE id = ?', ivan.id)[0].status, 'active');
  assert.equal((await s.get('/')).text, await pageText('dashboard.html'), 'the accepted device is approved, so the gate lets it in');
  // Without a fingerprint, the shell still refuses everything else.
  const stranger = client(env);
  assert.equal((await stranger.get('/api/me')).status, 403);
  assert.equal((await stranger.get('/admin')).status, 403);
});

test('link lookups are limited per address, and a flood stops writing', async () => {
  const { env } = await world();
  const s = client(env);
  for (let i = 0; i < 30; i++) nothing(await s.get(`/invite?token=${'B'.repeat(42)}${'ABCDEFGHIJKLMNOPQRSTUVWXYZabcd'[i]}`), `guess ${i}`);
  assert.equal(count(env, "SELECT COUNT(*) FROM auth_attempts WHERE kind = 'invite_ip' AND subject = ?", s.ip), 20, 'peeked, not charged, past the limit');
});

// SPEC §13.6: an invitation token is a credential and is never logged. The
// page's lookup carries it in the path, and the visit log and the worker's
// "unexpected failure" audit row both record paths — which the read-only
// Auditor reads (visitors.view, audit.view) and could then redeem.
test('a refused or failed lookup leaves the token in no log an Auditor can read', async () => {
  const { env, owner, rc } = await world();
  const auditor = await makeUser(env, owner.client, { role: 'auditor', email: 'audrey@acme.com' });
  const adam = await createUser(rc, { email: 'newadmin@acme.com', full_name: 'New Admin', role_id: roleId(env, 'admin') });
  const { token } = await createInvitation(rc, adam.id);

  const home = client(env);
  assert.equal((await home.get(`/invite?token=${token}`)).status, 200);
  // Refused at the gate: the pass did not come back (a cookie-blocking
  // webview, a pass that expired, the address changed mid-load).
  home.jar.delete(PASS_COOKIE);
  // A token in a path — a mistyped or forwarded link — is refused (there is
  // no GET lookup) and still recorded only in redacted form.
  nothing(await home.get(`/api/invite/${token}`), 'a token in a path');
  // Failed in the handler: a transient database error during the lookup.
  assert.equal((await home.get(`/invite?token=${token}`)).status, 200);
  env.DB.failOn = /FROM invitations WHERE token_hash/;
  const failed = await home.post('/api/invite/lookup', { token });
  env.DB.failOn = null;
  assert.equal(failed.status, 500);

  const visits = q(env, 'SELECT path FROM visits').map((r) => r.path || '');
  assert.ok(visits.includes('/api/invite/:token'), 'the refusal is still recorded, without its token');
  assert.ok(!visits.some((p) => p.includes(token)), 'no token in visits');
  const audit = JSON.stringify(auditRows(env));
  assert.match(audit, /Unexpected failure on POST \/api\/invite\/lookup/);
  assert.ok(!audit.includes(token), 'no token in the audit log');
  const seen = await auditor.client.get('/api/admin/visits?limit=500');
  assert.equal(seen.status, 200, seen.text);
  assert.ok(!seen.text.includes(token));
  const log = await auditor.client.get('/api/admin/audit?limit=200');
  assert.equal(log.status, 200, log.text);
  assert.ok(!log.text.includes(token));
  assert.equal(q(env, 'SELECT status FROM users WHERE id = ?', adam.id)[0].status, 'invited', 'the invitation is still unredeemed');
});

// The lookup with the token in the body: no URL ever holds it, and as a POST
// it must come from our own origin.
test('POST /api/invite/lookup answers inside the invite shell, with no token in any path', async () => {
  const { env, inv } = await world();
  const s = client(env);
  assert.equal((await s.get(`/invite?token=${inv.token}`)).status, 200);
  const r = await s.post('/api/invite/lookup', { token: inv.token });
  assert.equal(r.status, 200, r.text);
  assert.equal(r.body.email, 'ivan@acme.com');
  assert.deepEqual(Object.keys(r.body).sort(), ['email', 'expires_at', 'full_name', 'org_name', 'privacy_notice']);
  for (const bad of ['', 'short', 'A'.repeat(43), null, 42, {}]) assert.equal((await s.post('/api/invite/lookup', { token: bad })).status, 404, JSON.stringify(bad));
  const cross = await s.post('/api/invite/lookup', { token: inv.token }, { origin: 'https://evil.example' });
  assert.equal(cross.status, 403);
  assert.ok(!q(env, 'SELECT path FROM visits').some((v) => (v.path || '').includes(inv.token)));
  // Without the pass it is refused like everything else in that shell.
  nothing(await client(env).post('/api/invite/lookup', { token: inv.token }), 'no pass');
});

// The token never travels in a path, so a cross-site <img> pointed at a
// lookup URL is just a refused request: no route, nothing charged, and a new
// hire behind that office address still gets in.
test('cross-site loads cannot spend the invite bucket; a new hire on that address still gets in', async () => {
  const { env, inv } = await world();
  for (let i = 0; i < 25; i++) {
    const r = await rawRequest(env, 'GET', `/api/invite/junk${i}`, {
      ip: OWNER_IP,
      headers: { 'sec-fetch-site': 'cross-site', 'sec-fetch-mode': 'no-cors', 'sec-fetch-dest': 'image' },
    });
    assert.ok(r.status === 404 || r.status === 403, `refused (${r.status})`);
  }
  const leak = await rawRequest(env, 'GET', `/api/invite/${inv.token}`, { ip: OWNER_IP, headers: { 'sec-fetch-site': 'cross-site' } });
  assert.ok(leak.status === 404 || leak.status === 403);
  // A cross-site POST is refused by the origin check before any handler.
  const xpost = await rawRequest(env, 'POST', '/api/invite/lookup', { ip: OWNER_IP, headers: { origin: 'https://evil.example', 'content-type': 'application/json' }, body: JSON.stringify({ token: inv.token }) });
  assert.equal(xpost.status, 403);
  assert.equal(count(env, "SELECT COUNT(*) FROM auth_attempts WHERE kind = 'invite_ip'"), 0, 'nothing was charged');

  const hire = new Client(worker, env, { ip: OWNER_IP });
  assert.equal((await hire.get(`/invite?token=${inv.token}`)).status, 200);
  const lookup = await hire.post('/api/invite/lookup', { token: inv.token });
  assert.equal(lookup.status, 200, lookup.text);
  assert.equal(lookup.body.email, 'ivan@acme.com');
  const accept = await hire.post('/api/invite/accept', { token: inv.token, password: PASSWORD, full_name: 'Ivan Invitee' });
  assert.equal(accept.status, 200, accept.text);
});

await run();
