// Device routes in the admin console (CONTRACTS §8.4, §8.5; SPEC §5.5, §8.2,
// §12): trust withdrawn from a device is an action on everyone who signs in
// on it, your own device is never taken from under you wherever the gate
// needs its approval, and approving is not unblocking.

import { test, assert, run } from '../helpers/t.js';
import {
  freshEnv, bootstrap, makeUser, stepUp, signIn, client, q, count, Client, worker, OWNER, OWNER_IP, DEVICE_COOKIE,
} from '../helpers/flows.js';

function devicesOf(env, uid) {
  return q(env, 'SELECT device_id FROM device_users WHERE user_id = ?', uid).map((r) => r.device_id);
}

function ownDevice(env) {
  const rows = q(env, "SELECT id FROM devices WHERE status = 'approved'");
  assert.equal(rows.length, 1);
  return rows[0].id;
}

// ---------------------------------------------------------------- GATE-1

async function ownerIn(mode) {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const c = owner.client;
  await stepUp(env, c);
  const s = await c.put('/api/admin/settings', { changes: { access_mode: mode } });
  assert.equal(s.status, 200, s.text);
  await stepUp(env, c);
  return { env, owner, c, id: ownDevice(env) };
}

for (const mode of ['lockdown', 'invite_only']) {
  test(`${mode}: the device you are using cannot be revoked or un-approved by revert — the gate needs it`, async () => {
    const { env, owner, c, id } = await ownerIn(mode);
    const del = await c.del(`/api/admin/devices/${encodeURIComponent(id)}`);
    assert.equal(del.status, 409, del.text);
    assert.equal(del.body.code, 'self_lockout');
    // Setup's own approval of this device, reverted.
    const row = q(env, "SELECT id FROM audit_log WHERE action = 'device.approve' ORDER BY seq LIMIT 1")[0];
    const rev = await c.post(`/api/admin/audit/${row.id}/revert`, {});
    assert.equal(rev.status, 409, rev.text);
    assert.equal(rev.body.code, 'self_lockout');
    assert.equal(q(env, 'SELECT status FROM devices WHERE id = ?', id)[0].status, 'approved');
    assert.equal((await c.get('/api/auth/whoami')).body.authenticated, true, 'still signed in');
    // And a fresh sign-in from this browser still works.
    const again = new Client(worker, env, { ip: OWNER_IP });
    again.jar.set(DEVICE_COOKIE, c.jar.get(DEVICE_COOKIE));
    const login = await again.post('/api/auth/login', { identifier: OWNER.email, password: owner.password });
    assert.equal(login.status, 200, login.text);
  });
}

test('allowlist mode, off the allowlist: your own device is what lets you in, so it stays', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const c = owner.client;
  const id = ownDevice(env);
  c.ip = '185.15.56.40'; // the same laptop, at home
  await stepUp(env, c);
  const del = await c.del(`/api/admin/devices/${encodeURIComponent(id)}`);
  assert.equal(del.status, 409, del.text);
  assert.equal(del.body.code, 'self_lockout');
  // Back in the office, the allowlist is what lets you in: revoking is only a sign-out.
  c.ip = OWNER_IP;
  await stepUp(env, c);
  assert.equal((await c.del(`/api/admin/devices/${encodeURIComponent(id)}`)).status, 200);
  const fresh = client(env, { ip: OWNER_IP });
  assert.equal((await fresh.post('/api/auth/login', { identifier: OWNER.email, password: owner.password })).status, 200);
});

// ---------------------------------------------------------------- AUTHZ-1 / FO-4

async function adminWorld() {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const admin = await makeUser(env, owner.client, { role: 'admin', totp: true, ip: '91.198.174.30' });
  await stepUp(env, admin.client);
  return { env, owner, admin };
}

test('an Administrator cannot block or revoke the Super Admin’s device, as they cannot sign them out directly', async () => {
  const { env, owner, admin } = await adminWorld();
  const [dev] = devicesOf(env, owner.user.id);
  const block = await admin.client.post(`/api/admin/devices/${encodeURIComponent(dev)}/block`, {});
  assert.equal(block.status, 403, block.text);
  assert.equal(block.body.code, 'rank');
  const del = await admin.client.del(`/api/admin/devices/${encodeURIComponent(dev)}`);
  assert.equal(del.status, 403);
  assert.equal(del.body.code, 'rank');
  assert.equal(q(env, 'SELECT status FROM devices WHERE id = ?', dev)[0].status, 'approved');
  assert.equal((await owner.client.get('/api/me')).status, 200, 'the Super Admin is still signed in');
  assert.equal(count(env, "SELECT COUNT(*) FROM audit_log WHERE action IN ('device.block', 'device.revoke') AND outcome = 'success'"), 0);

  // With device gating switched on (settings.manage, which an Administrator
  // holds), a revoke would strand the owner on /pending. Still refused.
  const g = await admin.client.put('/api/admin/settings', { changes: { device_gating: true } });
  assert.equal(g.status, 200, g.text);
  await stepUp(env, admin.client);
  assert.equal((await admin.client.del(`/api/admin/devices/${encodeURIComponent(dev)}`)).status, 403);
  assert.equal((await owner.client.get('/')).status, 200);

  // Someone ranked below: as before.
  const emp = await makeUser(env, owner.client, { role: 'employee' });
  await stepUp(env, admin.client);
  const [empDev] = devicesOf(env, emp.user.id);
  assert.equal((await admin.client.post(`/api/admin/devices/${encodeURIComponent(empDev)}/block`, {})).status, 200);
  assert.equal((await emp.client.get('/api/me')).status, 403);
});

test('revoking an employee’s devices leaves alone a device the Super Admin signs in on too', async () => {
  const { env, owner, admin } = await adminWorld();
  const emp = await makeUser(env, owner.client, { role: 'employee' });
  // The employee signs in once on the owner's browser.
  const shared = new Client(worker, env, { ip: OWNER_IP });
  shared.jar.set(DEVICE_COOKIE, owner.client.jar.get(DEVICE_COOKIE));
  assert.equal((await signIn(env, shared, emp.user.email, emp.password)).status, 200);
  const [dev] = devicesOf(env, owner.user.id);
  assert.ok(devicesOf(env, emp.user.id).includes(dev));
  const r = await admin.client.post(`/api/admin/users/${emp.user.id}/revoke-devices`, {});
  assert.equal(r.status, 200, r.text);
  assert.ok(r.body.skipped >= 1, 'the shared device was left alone');
  assert.equal((await owner.client.get('/api/me')).status, 200, 'the Super Admin is still signed in');
  assert.equal(q(env, 'SELECT status FROM devices WHERE id = ?', dev)[0].status, 'approved');
  assert.equal(count(env, 'SELECT COUNT(*) FROM sessions WHERE user_id = ? AND revoked_at IS NULL', emp.user.id), 0, 'the employee’s own sessions still ended');
});

test('an Administrator cannot block a network the Super Admin signs in from; a Super Admin can', async () => {
  const { env, owner, admin } = await adminWorld();
  const blk = await admin.client.post('/api/admin/network/block', { cidr: '81.2.69.0/24', reason: 'x' });
  assert.equal(blk.status, 403, blk.text);
  assert.equal(blk.body.code, 'rank');
  assert.equal(count(env, 'SELECT COUNT(*) FROM blocked_ips'), 0);
  assert.equal((await owner.client.get('/api/me')).status, 200);
  // A range nobody above the Administrator signs in from: as before.
  assert.equal((await admin.client.post('/api/admin/network/block', { cidr: '185.15.56.0/24', reason: 'spam' })).status, 200);
  // Super Admins are peers: the owner may block a range a fellow Super Admin
  // (and the Administrator) signs in from — never their own address.
  await makeUser(env, owner.client, { role: 'super_admin', ip: '91.198.174.90' });
  await stepUp(env, owner.client);
  assert.equal((await owner.client.post('/api/admin/network/block', { cidr: '91.198.174.0/24', reason: 'x' })).status, 200);
  const own = await owner.client.post('/api/admin/network/block', { cidr: '81.2.69.0/24', reason: 'x' });
  assert.equal(own.status, 409);
  assert.equal(own.body.code, 'self_lockout');
});

// ---------------------------------------------------------------- AUTHZ-5

test('a pending device’s approval code is shown only to someone who may approve devices', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const auditor = await makeUser(env, owner.client, { role: 'auditor', totp: true });
  await stepUp(env, owner.client);
  assert.equal((await owner.client.put('/api/admin/settings', { changes: { device_gating: true } })).status, 200);
  const stranger = new Client(worker, env, { ip: OWNER_IP });
  const st = await stranger.get('/api/device/status');
  assert.equal(st.status, 200);

  const seen = await auditor.client.get('/api/admin/devices?status=pending');
  assert.equal(seen.status, 200, seen.text);
  assert.ok(seen.body.devices.length >= 1);
  assert.ok(seen.body.devices.every((d) => d.code === null), 'devices.view alone never sees a code');
  assert.ok(!seen.text.includes(st.body.code));
  // Without the code the self-service route has nothing to work with.
  await stepUp(env, auditor.client);
  const guess = await auditor.client.post('/api/me/devices/approve', { code: 'AAAA-AAAA' });
  assert.equal(guess.status, 404);
  const after = await stranger.get('/');
  assert.equal(after.status, 302);
  assert.equal(after.headers.get('location'), '/pending');

  const mine = await owner.client.get('/api/admin/devices?status=pending');
  assert.ok(mine.body.devices.some((d) => d.code === st.body.code), 'an approver still sees it');
});

// ---------------------------------------------------------------- AUTHZ-6

test('devices.approve approves waiting devices; it never lifts a block (devices.manage)', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  await stepUp(env, owner.client);
  const role = await owner.client.post('/api/admin/roles', { name: 'Helpdesk', rank: 40, permissions: ['devices.view', 'devices.approve'] });
  assert.equal(role.status, 200, role.text);
  const helpdesk = await makeUser(env, owner.client, { role: 'employee', totp: true });
  await stepUp(env, owner.client);
  assert.equal((await owner.client.post(`/api/admin/users/${helpdesk.user.id}/role`, { role_id: role.body.role.id })).status, 200);
  const laptop = await makeUser(env, owner.client, { role: 'employee' });
  const [dev] = devicesOf(env, laptop.user.id);
  assert.equal((await owner.client.post(`/api/admin/devices/${dev}/block`, {})).status, 200);
  assert.equal((await laptop.client.get('/')).status, 403);

  await stepUp(env, helpdesk.client);
  assert.equal((await helpdesk.client.post(`/api/admin/devices/${dev}/unblock`, {})).status, 403);
  const approve = await helpdesk.client.post(`/api/admin/devices/${dev}/approve`, {});
  assert.equal(approve.status, 409, approve.text);
  assert.equal(approve.body.code, 'not_pending');
  assert.equal(q(env, 'SELECT status FROM devices WHERE id = ?', dev)[0].status, 'blocked');
  assert.equal((await laptop.client.get('/')).status, 403);

  // Unblocked by someone who may, it waits; then approving it is helpdesk's job.
  await stepUp(env, owner.client);
  assert.equal((await owner.client.post(`/api/admin/devices/${dev}/unblock`, {})).status, 200);
  assert.equal((await helpdesk.client.post(`/api/admin/devices/${dev}/approve`, {})).status, 200);
  assert.equal(q(env, 'SELECT status FROM devices WHERE id = ?', dev)[0].status, 'approved');
});

await run();
