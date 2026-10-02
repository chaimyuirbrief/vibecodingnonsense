// People, invitations, access requests, devices, sessions, streaks and the
// overview over HTTP (CONTRACTS §8.4; A §5, §7.5; B §4, §6; D11).

import { test, assert, run } from '../helpers/t.js';
import {
  freshEnv, bootstrap, makeUser, stepUp, signIn, client, roleId, q, count, auditRows, setSetting, fakeProvider, advance,
  OWNER_IP, PASSWORD, HOSTILE, MINUTE,
} from '../helpers/flows.js';
import { Client } from '../helpers/http.js';
import worker from '../../worker.js';
import { deviceCode } from '../../src/devices.js';

const MAIL = { RESEND_API_KEY: 're_test_key', MAIL_FROM: 'Portal <portal@acme.com>' };

function tokenOf(url) {
  return new URL(url, 'https://staff.example.com').searchParams.get('token');
}

function label(v) {
  return typeof v === 'symbol' ? 'Symbol' : JSON.stringify(v);
}

test('invite: a link always; an email only when a provider is configured; accepting signs in on an approved device', async () => {
  for (const configured of [false, true]) {
    const mail = fakeProvider();
    const env = freshEnv({ vars: { __fetch: mail.fetch, ...(configured ? MAIL : {}) } });
    const owner = await bootstrap(env);
    const r = await owner.client.post('/api/admin/users', { email: 'new.hire@acme.com', full_name: 'New Hire', job_title: 'Engineer' });
    assert.equal(r.status, 200, r.text);
    assert.equal(r.body.user.status, 'invited');
    assert.equal(r.body.user.role.key, 'employee');
    assert.match(r.body.invitation.url, /^https:\/\/staff\.example\.com\/invite\?token=[A-Za-z0-9_-]{43}$/);
    assert.equal(r.body.emailed, configured);
    assert.equal(mail.calls.length, configured ? 1 : 0, 'no outbound call without RESEND_API_KEY and MAIL_FROM');
    if (configured) {
      assert.equal(mail.calls[0].url, 'https://api.resend.com/emails');
      const sent = JSON.parse(mail.calls[0].body);
      assert.deepEqual(sent.to, ['new.hire@acme.com']);
      assert.ok(sent.text.includes(r.body.invitation.url));
    }
    const token = tokenOf(r.body.invitation.url);
    const stored = q(env, 'SELECT token_hash FROM invitations')[0].token_hash;
    assert.notEqual(stored, token, 'only the hash is stored');
    const row = auditRows(env, 'user.invite').pop();
    assert.ok(!JSON.stringify(row).includes(token), 'the token never reaches the audit log');
    assert.equal(row.undo_kind, null, 'invitations are not revertible');

    const invitee = new Client(worker, env, { ip: '185.15.56.40' });
    assert.equal((await invitee.get(`/invite?token=${token}`)).status, 200);
    const acc = await invitee.post('/api/invite/accept', { token, password: PASSWORD });
    assert.equal(acc.status, 200, acc.text);
    assert.equal(acc.body.user.email, 'new.hire@acme.com');
    const me = await invitee.get('/api/me');
    assert.equal(me.status, 200, 'signed in, from an address nobody allowlisted');
    const dev = q(env, "SELECT d.status FROM devices d JOIN device_users du ON du.device_id = d.id JOIN users u ON u.id = du.user_id WHERE u.email = 'new.hire@acme.com'");
    assert.equal(dev[0].status, 'approved', 'accepting the invitation approved the device');
  }
});

test('invite: hostile fields are 400 and create nobody; duplicates are a sentence, not a 500', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const c = owner.client;
  for (const v of HOSTILE) {
    assert.equal((await c.post('/api/admin/users', { email: v, full_name: 'X' })).status, 400, `email ${label(v)}`);
    if (v !== 'abc') assert.equal((await c.post('/api/admin/users', { email: 'h@acme.com', full_name: v })).status, 400, `full_name ${label(v)}`);
    // undefined and a Symbol vanish in JSON: an absent role_id means employee.
    if (v !== undefined && typeof v !== 'symbol') {
      const r = await c.post('/api/admin/users', { email: 'h@acme.com', full_name: 'H', role_id: v });
      assert.equal(r.status, 400, `role_id ${label(v)}: ${r.text}`);
    }
  }
  assert.equal(count(env, 'SELECT COUNT(*) FROM users'), 1);
  assert.equal(count(env, 'SELECT COUNT(*) FROM invitations'), 0);
  assert.equal((await c.post('/api/admin/users', { email: 'h@acme.com', full_name: 'H' })).status, 200);
  const dup = await c.post('/api/admin/users', { email: 'H@acme.com', full_name: 'H2' });
  assert.equal(dup.status, 409);
  assert.equal(dup.body.field, 'email');
  // Reissue: a new link, the old one dead.
  const id = q(env, "SELECT id FROM users WHERE email = 'h@acme.com'")[0].id;
  const first = q(env, 'SELECT id FROM invitations WHERE user_id = ?', id)[0].id;
  const re = await c.post(`/api/admin/users/${id}/invitation`, {});
  assert.equal(re.status, 200);
  assert.ok(re.body.url && re.body.invitation.url === re.body.url);
  assert.ok(q(env, 'SELECT revoked_at FROM invitations WHERE id = ?', first)[0].revoked_at);
  const list = (await c.get('/api/admin/invitations')).body.invitations;
  assert.equal(list.length, 2);
  assert.ok(list.every((i) => !('token_hash' in i)));
  const pending = list.find((i) => !i.revoked_at);
  assert.equal((await c.post(`/api/admin/invitations/${pending.id}/revoke`, {})).status, 200);
  assert.equal((await c.post(`/api/admin/invitations/${pending.id}/revoke`, {})).status, 409);
  assert.equal((await c.post('/api/admin/invitations/abc/revoke', {})).status, 404);
});

test('access requests: approve → an invitation; deny closes it; neither twice', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  setSetting(env, 'access_mode', 'request_access');
  await client(env).post('/api/access-request', { email: 'sam@example.org', full_name: 'Sam Stranger', reason: 'Contractor' });
  await client(env).post('/api/access-request', { email: 'eve@example.org', full_name: 'Eve' });
  const c = owner.client;
  const list = (await c.get('/api/admin/requests')).body.requests;
  assert.equal(list.length, 2);
  const sam = list.find((r) => r.email === 'sam@example.org');
  const eve = list.find((r) => r.email === 'eve@example.org');
  const a = await c.post(`/api/admin/requests/${sam.id}/approve`, { role_id: roleId(env, 'guest') });
  assert.equal(a.status, 200, a.text);
  assert.equal(a.body.user.role.key, 'guest');
  assert.equal(a.body.user.status, 'invited');
  assert.match(a.body.invitation.url, /\/invite\?token=/);
  assert.equal(q(env, 'SELECT status FROM access_requests WHERE id = ?', sam.id)[0].status, 'approved');
  assert.equal((await c.post(`/api/admin/requests/${sam.id}/approve`, {})).status, 409);
  const d = await c.post(`/api/admin/requests/${eve.id}/deny`, {});
  assert.equal(d.status, 200);
  assert.equal(q(env, 'SELECT status FROM access_requests WHERE id = ?', eve.id)[0].status, 'denied');
  assert.equal((await c.post(`/api/admin/requests/${eve.id}/deny`, {})).status, 409);
  assert.equal(count(env, "SELECT COUNT(*) FROM users WHERE email = 'eve@example.org'"), 0);
  assert.equal(auditRows(env, 'request.approve').length, 1);
  assert.equal(auditRows(env, 'request.deny').length, 1);
  // The invitation works.
  const invitee = client(env);
  await invitee.get(`/invite?token=${tokenOf(a.body.invitation.url)}`);
  assert.equal((await invitee.post('/api/invite/accept', { token: tokenOf(a.body.invitation.url), password: PASSWORD })).status, 200);
});

test('devices: approve by code; block kills the device’s sessions; unblock and revoke', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const emp = await makeUser(env, owner.client, { role: 'employee', totp: true });
  const c = owner.client;
  // Device gating on: a new browser on the office network waits on the
  // pending page with a code.
  await stepUp(env, c);
  assert.equal((await c.put('/api/admin/settings', { changes: { device_gating: true } })).status, 200);
  const phone = new Client(worker, env, { ip: OWNER_IP });
  const st = await phone.get('/api/device/status');
  assert.equal(st.status, 200);
  assert.equal(st.body.status, 'pending');
  const devId = q(env, "SELECT id FROM devices WHERE status = 'pending' ORDER BY first_seen DESC LIMIT 1")[0].id;
  assert.equal(await deviceCode(devId), st.body.code);
  const listed = (await c.get('/api/admin/devices')).body.devices.find((d) => d.id === devId);
  assert.equal(listed.code, st.body.code);
  await stepUp(env, c);
  const wrong = await c.post(`/api/admin/devices/${devId}/approve`, { code: 'AAAA-BBBB' });
  assert.equal(wrong.status, 409);
  for (const v of ['', '   ', 'abc', 0, true, {}, []]) {
    assert.equal((await c.post(`/api/admin/devices/${devId}/approve`, { code: v })).status, 409, `code ${label(v)}`);
  }
  assert.equal(q(env, 'SELECT status FROM devices WHERE id = ?', devId)[0].status, 'pending');
  const ok = await c.post(`/api/admin/devices/${devId}/approve`, { code: st.body.code.toLowerCase().replace('-', ' ') });
  assert.equal(ok.status, 200, ok.text);
  assert.equal((await phone.get('/api/device/status')).body.status, 'approved');

  // Blocking the employee's device ends their sessions there at once.
  const empDev = q(env, 'SELECT device_id FROM device_users WHERE user_id = ?', emp.user.id)[0].device_id;
  assert.equal((await emp.client.get('/api/me')).status, 200);
  const b = await c.post(`/api/admin/devices/${empDev}/block`, {});
  assert.equal(b.status, 200);
  assert.equal(count(env, 'SELECT COUNT(*) FROM sessions WHERE device_id = ? AND revoked_at IS NULL', empDev), 0);
  assert.equal((await emp.client.get('/api/me')).status, 403, 'refused at the gate');
  // Not your own.
  const ownDev = q(env, 'SELECT device_id FROM sessions WHERE user_id = ? AND revoked_at IS NULL', owner.user.id)[0].device_id;
  const own = await c.post(`/api/admin/devices/${ownDev}/block`, {});
  assert.equal(own.status, 409);
  assert.equal(own.body.code, 'self_lockout');
  assert.equal((await c.post(`/api/admin/devices/${devId}/unblock`, {})).status, 409, 'not blocked');
  assert.equal((await c.post(`/api/admin/devices/${empDev}/unblock`, {})).status, 200);
  assert.equal(q(env, 'SELECT status FROM devices WHERE id = ?', empDev)[0].status, 'pending');
  assert.equal((await c.post(`/api/admin/devices/${devId}/rename`, { label: '   ' })).status, 400);
  assert.equal((await c.post(`/api/admin/devices/${devId}/rename`, { label: 'Sam’s phone' })).status, 200);
  assert.equal((await c.del(`/api/admin/devices/${devId}`)).status, 200);
  assert.equal(q(env, 'SELECT status FROM devices WHERE id = ?', devId)[0].status, 'pending');
  assert.equal((await c.post('/api/admin/devices/nope/approve', {})).status, 404);
});

test('self-approval of a device: only from an approved device, only with a fresh step-up', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const emp = await makeUser(env, owner.client, { role: 'employee', totp: true });
  const phone = new Client(worker, env, { ip: OWNER_IP });
  const code = (await phone.get('/api/device/status')).body.code;
  // From a device that is itself pending (in through the allowlisted office network).
  const kiosk = new Client(worker, env, { ip: OWNER_IP });
  assert.equal((await signIn(env, kiosk, emp.user.email, emp.password, { totpSecret: emp.totpSecret })).status, 200);
  await stepUp(env, kiosk, emp.totpSecret);
  const fromPending = await kiosk.post('/api/me/devices/approve', { code });
  assert.equal(fromPending.status, 403);
  assert.equal(fromPending.body.code, 'device_not_approved');
  // From their approved laptop, but the step-up has gone stale.
  advance(env, 16 * MINUTE);
  const stale = await emp.client.post('/api/me/devices/approve', { code });
  assert.equal(stale.status, 403);
  assert.equal(stale.body.step_up_required, true);
  const pending = q(env, "SELECT COUNT(*) AS n FROM devices WHERE status = 'pending'")[0].n;
  await stepUp(env, emp.client);
  const ok = await emp.client.post('/api/me/devices/approve', { code });
  assert.equal(ok.status, 200, ok.text);
  assert.equal(q(env, "SELECT COUNT(*) AS n FROM devices WHERE status = 'pending'")[0].n, pending - 1);
  assert.equal(auditRows(env, 'device.self_approve').pop().undo_kind, 'device.status');
});

test('a manager sees only their direct reports — people, details and streaks', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const mgr = await makeUser(env, owner.client, { role: 'manager', totp: true });
  const r1 = await makeUser(env, owner.client, { role: 'employee' });
  const r2 = await makeUser(env, owner.client, { role: 'employee' });
  const other = await makeUser(env, owner.client, { role: 'employee' });
  for (const r of [r1, r2]) assert.equal((await owner.client.patch(`/api/admin/users/${r.user.id}`, { manager_id: mgr.user.id })).status, 200);
  const list = await mgr.client.get('/api/admin/users');
  assert.equal(list.status, 200);
  assert.equal(list.body.scope, 'team');
  assert.deepEqual(list.body.users.map((u) => u.id).sort(), [r1.user.id, r2.user.id].sort());
  // Filters cannot widen it.
  const widened = await mgr.client.get(`/api/admin/users?manager=${owner.user.id}&role=employee&limit=500`);
  assert.deepEqual(widened.body.users.map((u) => u.id).sort(), [r1.user.id, r2.user.id].sort());
  const d = await mgr.client.get(`/api/admin/users/${r1.user.id}`);
  assert.equal(d.status, 200);
  assert.ok(d.body.streak, 'their streak');
  assert.ok(!('permissions' in d.body) && !('factors' in d.body), 'not their security posture');
  assert.equal((await mgr.client.get(`/api/admin/users/${other.user.id}`)).status, 404);
  assert.equal((await mgr.client.get(`/api/admin/users/${owner.user.id}`)).status, 404);
  const s = await mgr.client.get('/api/admin/streaks');
  assert.equal(s.body.scope, 'team');
  assert.deepEqual(s.body.streaks.map((x) => x.user_id).sort(), [r1.user.id, r2.user.id].sort());
  const all = await owner.client.get('/api/admin/streaks');
  assert.equal(all.body.scope, 'all');
  assert.equal(all.body.streaks.length, 5);
  const ov = (await mgr.client.get('/api/admin/overview')).body;
  assert.equal(ov.counts.team_reports, 2);
  for (const k of ['users_active', 'devices_pending', 'audit_entries', 'sessions_active', 'allow_entries', 'requests_pending']) {
    assert.ok(!(k in ov.counts), `a manager does not see ${k}`);
  }
  assert.ok(!('recent_audit' in ov) && !('gate' in ov));
  assert.ok('invitations_pending' in ov.counts, 'they may invite');
  const auditor = await makeUser(env, owner.client, { role: 'auditor' });
  const ao = (await auditor.client.get('/api/admin/overview')).body;
  assert.equal(ao.counts.users_active, 6);
  assert.ok('audit_entries' in ao.counts && Array.isArray(ao.recent_audit));
  assert.ok(!('requests_pending' in ao.counts) && !('invitations_pending' in ao.counts));
});

test('streak adjust: reason required, hostile counts refused, prior row kept for the revert', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const emp = await makeUser(env, owner.client, { role: 'employee' });
  const c = owner.client;
  const before = q(env, 'SELECT * FROM streaks WHERE user_id = ?', emp.user.id)[0];
  for (const reason of [undefined, null, '', '   ', 7, {}, 'x'.repeat(201)]) {
    assert.equal((await c.post(`/api/admin/users/${emp.user.id}/streak`, { current: 5, reason })).status, 400, `reason ${label(reason)}`);
  }
  for (const v of [null, '', '   ', 'abc', {}, [], true, -1, 1.5, 100001]) {
    assert.equal((await c.post(`/api/admin/users/${emp.user.id}/streak`, { current: v, reason: 'Outage' })).status, 400, `current ${label(v)}`);
    assert.equal((await c.post(`/api/admin/users/${emp.user.id}/streak`, { current: 2, longest: v, reason: 'Outage' })).status, 400, `longest ${label(v)}`);
  }
  assert.deepEqual(q(env, 'SELECT * FROM streaks WHERE user_id = ?', emp.user.id)[0], before);
  assert.equal(auditRows(env, 'streak.adjust').length, 0);
  const zero = await c.post(`/api/admin/users/${emp.user.id}/streak`, { current: 0, reason: 'Testing account' });
  assert.equal(zero.status, 200, 'an explicit 0 is a legal count');
  const row = auditRows(env, 'streak.adjust').pop();
  assert.equal(JSON.parse(row.undo_payload).prior.current, before.current);
  assert.match(row.detail, /Testing account/);
  const own = await c.post(`/api/admin/users/${owner.user.id}/streak`, { current: 99, reason: 'Me' });
  assert.equal(own.status, 403, 'nobody pads their own streak');
});

test('sessions: listed by reference only; ending one signs that browser out; not your own', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const emp = await makeUser(env, owner.client, { role: 'employee' });
  const c = owner.client;
  const r = await c.get('/api/admin/sessions');
  assert.equal(r.status, 200);
  const ids = q(env, 'SELECT id FROM sessions').map((s) => s.id);
  for (const id of ids) assert.ok(!r.text.includes(id), 'the stored session hash never leaves');
  for (const v of emp.client.jar.values()) assert.ok(!r.text.includes(v), 'nor any cookie value');
  const theirs = r.body.sessions.find((s) => s.user_id === emp.user.id);
  const mine = r.body.sessions.find((s) => s.current);
  assert.match(theirs.id_ref, /^[0-9a-f]{12}$/);
  assert.equal((await c.del(`/api/admin/sessions/${mine.id_ref}`)).status, 403);
  assert.equal((await c.del(`/api/admin/sessions/${theirs.id_ref}`)).status, 200);
  assert.equal((await emp.client.get('/api/me')).status, 401);
  for (const ref of ['abc', '000000000000', theirs.id_ref.toUpperCase(), 'x'.repeat(64)]) {
    assert.equal((await c.del(`/api/admin/sessions/${ref}`)).status, 404, ref);
  }
  // Sign-out-everywhere and revoke-devices.
  await signIn(env, emp.client, emp.user.email, emp.password);
  assert.equal((await c.post(`/api/admin/users/${emp.user.id}/logout`, {})).status, 200);
  assert.equal((await emp.client.get('/api/me')).status, 401);
  await signIn(env, emp.client, emp.user.email, emp.password);
  const rd = await c.post(`/api/admin/users/${emp.user.id}/revoke-devices`, {});
  assert.equal(rd.status, 200, rd.text);
  assert.equal(rd.body.revoked, 1);
  assert.equal(count(env, "SELECT COUNT(*) FROM devices d JOIN device_users du ON du.device_id = d.id WHERE du.user_id = ? AND d.status = 'approved'", emp.user.id), 0);
});

test('people: detail and list never carry credentials; hostile ids and fields are refused', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const emp = await makeUser(env, owner.client, { role: 'employee', totp: true });
  const c = owner.client;
  const d = await c.get(`/api/admin/users/${emp.user.id}`);
  assert.equal(d.status, 200);
  for (const bad of ['password_hash', 'password_salt', 'failed_logins', 'locked_until', 'secret_enc', 'code_hash']) {
    assert.ok(!d.text.includes(bad), `detail leaks ${bad}`);
  }
  assert.equal(d.body.user.locked, false);
  assert.equal(d.body.factors.totp, true);
  assert.ok(Array.isArray(d.body.permissions) && Array.isArray(d.body.temp_roles));
  const l = await c.get('/api/admin/users?limit=abc&offset=-5&status=bogus&q=%25');
  assert.equal(l.status, 200);
  assert.ok(!l.text.includes('password_hash'));
  const dir = await c.get('/api/directory');
  assert.equal(dir.status, 200);
  assert.ok(!dir.text.includes('password') && !dir.text.includes('perm_'));
  for (const id of ['abc', '0', '-1', '1.5', '99999']) {
    assert.equal((await c.get(`/api/admin/users/${id}`)).status, 404, id);
    assert.equal((await c.patch(`/api/admin/users/${id}`, { full_name: 'X' })).status, 404, id);
  }
  for (const v of HOSTILE) {
    if (v === undefined || typeof v === 'symbol') continue; // dropped by JSON: nothing to change
    const r = await c.patch(`/api/admin/users/${emp.user.id}`, { full_name: v });
    assert.equal(r.status, v === 'abc' ? 200 : 400, `full_name ${label(v)}`);
  }
  await stepUp(env, c);
  for (const v of HOSTILE) {
    assert.equal((await c.post(`/api/admin/users/${emp.user.id}/status`, { status: v })).status, 400, `status ${label(v)}`);
    const r = await c.post(`/api/admin/users/${emp.user.id}/role`, { role_id: v, perm_grants: [], perm_denies: [] });
    assert.equal(r.status, 400, `role_id ${label(v)}`);
    const g = await c.post(`/api/admin/users/${emp.user.id}/temp-role`, { role_id: roleId(env, 'manager'), expires_at: v });
    assert.equal(g.status, 400, `expires_at ${label(v)}`);
  }
  assert.equal(q(env, 'SELECT status FROM users WHERE id = ?', emp.user.id)[0].status, 'active');
  assert.equal(count(env, 'SELECT COUNT(*) FROM user_roles'), 0);
  // A Date.parse-able but non-ISO expiry is refused too (A §14.2).
  const g42 = await c.post(`/api/admin/users/${emp.user.id}/temp-role`, { role_id: roleId(env, 'manager'), expires_at: '42' });
  assert.equal(g42.status, 400);
});

await run();
