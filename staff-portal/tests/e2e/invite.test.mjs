// Invitation links through the gate (CONTRACTS §8.3 /invite, §8.4; D11;
// SPEC §6.7): a valid link is the only thing that gets a stranger past a mode
// that would otherwise show them nothing — and only as far as the invitation.

import { test, assert, run } from '../helpers/t.js';
import {
  freshEnv, client, bootstrap, actorRc, roleId, pageText, q, count, auditRows, advance, setSetting, DAY, MINUTE, OWNER_IP, PASSWORD, HOSTILE, DEVICE_COOKIE, SESSION_COOKIE,
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
  const info = await s.get(`/api/invite/${inv.token}`);
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

test('in fingerprint_gate a link changes nothing, so no pass is handed out', async () => {
  const { env, inv } = await world();
  setSetting(env, 'access_mode', 'fingerprint_gate');
  nothing(await client(env).get(`/invite?token=${inv.token}`), 'fingerprint_gate');
});

test('link lookups are limited per address, and a flood stops writing', async () => {
  const { env } = await world();
  const s = client(env);
  for (let i = 0; i < 30; i++) nothing(await s.get(`/invite?token=${'B'.repeat(42)}${'ABCDEFGHIJKLMNOPQRSTUVWXYZabcd'[i]}`), `guess ${i}`);
  assert.equal(count(env, "SELECT COUNT(*) FROM auth_attempts WHERE kind = 'invite_ip' AND subject = ?", s.ip), 20, 'peeked, not charged, past the limit');
});

await run();
