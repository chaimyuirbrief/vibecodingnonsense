// Every undo kind, end to end (CONTRACTS §4.2.1; A §9, §14.9; B §7, trap 5):
// perform it over HTTP → revert it → the state is back → a second revert is
// refused → the hash chain still verifies. Plus the refusals: kinds with no
// reverter, failed entries, reverts of reverts, and denies on the reverter.

import { test, assert, run } from '../helpers/t.js';
import { freshEnv, bootstrap, makeUser, stepUp, signIn, signOut, roleId, q, count, auditRows, fakeProvider } from '../helpers/flows.js';
import { audit, verifyChain } from '../../src/audit.js';
import { UNDO_KINDS, undoFor } from '../../src/undo.js';

const covered = new Set();

async function world() {
  const mail = fakeProvider();
  const env = freshEnv({ vars: { RESEND_API_KEY: 're_test_key', MAIL_FROM: 'portal@acme.com', __fetch: mail.fetch } });
  const owner = await bootstrap(env);
  const emp = await makeUser(env, owner.client, { role: 'employee', totp: true });
  return { env, owner, emp, mail };
}

function lastSuccess(env, action) {
  const rows = auditRows(env, action).filter((a) => a.outcome === 'success');
  assert.ok(rows.length, `no successful ${action} row`);
  return rows[rows.length - 1];
}

// The shared tail of every round trip.
async function revertAndCheck(env, c, entry, check) {
  assert.ok(entry.undo_kind, `${entry.action} recorded no undo`);
  covered.add(entry.undo_kind);
  const list = (await c.get(`/api/admin/audit?action=${encodeURIComponent(entry.action)}`)).body.entries;
  const shown = list.find((e) => e.id === entry.id);
  assert.equal(shown.revertible, true, `${entry.action} offered for revert`);
  assert.ok(!('undo_payload' in shown));
  await stepUp(env, c);
  const r = await c.post(`/api/admin/audit/${entry.id}/revert`, {});
  assert.equal(r.status, 200, `${entry.undo_kind}: ${r.text}`);
  const rev = q(env, 'SELECT * FROM audit_log WHERE id = ?', r.body.revert_id)[0];
  assert.equal(rev.action, 'audit.revert');
  assert.equal(rev.reverts_id, entry.id);
  assert.equal(rev.undo_payload, null, 'a revert records no undo of its own');
  await check();
  const again = await c.post(`/api/admin/audit/${entry.id}/revert`, {});
  assert.equal(again.status, 409, `${entry.undo_kind} second revert: ${again.text}`);
  assert.equal(again.body.code, 'already_reverted');
  const after = (await c.get(`/api/admin/audit?action=${encodeURIComponent(entry.action)}`)).body.entries.find((e) => e.id === entry.id);
  assert.equal(after.revertible, false);
  assert.equal(after.reverted_by, rev.id);
  const v = await verifyChain(env);
  assert.equal(v.ok, true, `${entry.undo_kind}: chain ${JSON.stringify(v.broken_at)}`);
}

test('people: status, role, temporary role (grant and revoke), profile', async () => {
  const { env, owner, emp } = await world();
  const c = owner.client;
  const uid = emp.user.id;
  const user = () => q(env, 'SELECT * FROM users WHERE id = ?', uid)[0];

  await stepUp(env, c);
  assert.equal((await c.post(`/api/admin/users/${uid}/status`, { status: 'suspended' })).status, 200);
  await revertAndCheck(env, c, lastSuccess(env, 'user.status'), async () => assert.equal(user().status, 'active'));

  const before = user();
  await stepUp(env, c);
  const role = await c.post(`/api/admin/users/${uid}/role`, { role_id: roleId(env, 'manager'), perm_grants: ['devices.view'], perm_denies: ['team.view'] });
  assert.equal(role.status, 200, role.text);
  await revertAndCheck(env, c, lastSuccess(env, 'user.role'), async () => {
    const u = user();
    assert.equal(u.role_id, before.role_id);
    assert.deepEqual(JSON.parse(u.perm_grants), []);
    assert.deepEqual(JSON.parse(u.perm_denies), []);
  });

  const until = new Date(env.__clock() + 3 * 86400000).toISOString();
  await stepUp(env, c);
  assert.equal((await c.post(`/api/admin/users/${uid}/temp-role`, { role_id: roleId(env, 'auditor'), expires_at: until })).status, 200);
  await revertAndCheck(env, c, lastSuccess(env, 'user.temp_role.grant'), async () => {
    assert.equal(count(env, 'SELECT COUNT(*) FROM user_roles WHERE user_id = ?', uid), 0, 'a new grant reverts to none');
  });
  await stepUp(env, c);
  assert.equal((await c.post(`/api/admin/users/${uid}/temp-role`, { role_id: roleId(env, 'auditor'), expires_at: until })).status, 200);
  assert.equal((await c.del(`/api/admin/users/${uid}/temp-role/${roleId(env, 'auditor')}`)).status, 200);
  assert.equal(count(env, 'SELECT COUNT(*) FROM user_roles WHERE user_id = ?', uid), 0);
  await revertAndCheck(env, c, lastSuccess(env, 'user.temp_role.revoke'), async () => {
    const row = q(env, 'SELECT * FROM user_roles WHERE user_id = ?', uid)[0];
    assert.equal(row.role_id, roleId(env, 'auditor'));
    assert.equal(row.expires_at, until, 'restored with its original expiry');
  });

  const e = await c.patch(`/api/admin/users/${uid}`, { full_name: 'Renamed Person', job_title: 'Chef' });
  assert.equal(e.status, 200, e.text);
  await revertAndCheck(env, c, lastSuccess(env, 'user.edit'), async () => {
    assert.equal(user().full_name, before.full_name);
    assert.equal(user().job_title, null);
  });
});

test('devices: status and label', async () => {
  const { env, owner, emp } = await world();
  const c = owner.client;
  const devId = q(env, 'SELECT device_id FROM device_users WHERE user_id = ?', emp.user.id)[0].device_id;
  const label = q(env, 'SELECT label FROM devices WHERE id = ?', devId)[0].label;
  await stepUp(env, c);
  assert.equal((await c.post(`/api/admin/devices/${devId}/block`, {})).status, 200);
  assert.equal((await emp.client.get('/api/me')).status, 403, 'a blocked device is refused at the gate');
  await revertAndCheck(env, c, lastSuccess(env, 'device.block'), async () => {
    assert.equal(q(env, 'SELECT status FROM devices WHERE id = ?', devId)[0].status, 'approved');
    assert.equal((await emp.client.get('/api/me')).status, 401, 'the sessions it killed stay dead');
  });
  await stepUp(env, c);
  assert.equal((await c.post(`/api/admin/devices/${devId}/rename`, { label: 'Front desk iPad' })).status, 200);
  await revertAndCheck(env, c, lastSuccess(env, 'device.rename'), async () => {
    assert.equal(q(env, 'SELECT label FROM devices WHERE id = ?', devId)[0].label, label);
  });
});

test('network: allow add, remove, edit; block add, remove', async () => {
  const { env, owner } = await world();
  const c = owner.client;
  const allow = () => q(env, 'SELECT * FROM allowed_ips ORDER BY id');
  await stepUp(env, c);
  const add = await c.post('/api/admin/network/allow', { cidr: '185.15.56.0/24', tier: 2, label: 'Branch' });
  assert.equal(add.status, 200);
  await revertAndCheck(env, c, lastSuccess(env, 'network.allow.add'), async () => assert.equal(allow().length, 1));

  await stepUp(env, c);
  const add2 = await c.post('/api/admin/network/allow', { cidr: '91.198.174.0/24', tier: 3, label: 'Lab', owner: 'Ops' });
  assert.equal((await c.del(`/api/admin/network/allow/${add2.body.entry.id}`)).status, 200);
  await revertAndCheck(env, c, lastSuccess(env, 'network.allow.remove'), async () => {
    const row = allow().find((r) => r.cidr === '91.198.174.0/24');
    assert.ok(row, 're-added');
    assert.equal(row.tier, 3);
    assert.equal(row.label, 'Lab');
    assert.equal(row.owner, 'Ops');
  });

  const lab = allow().find((r) => r.cidr === '91.198.174.0/24');
  await stepUp(env, c);
  assert.equal((await c.patch(`/api/admin/network/allow/${lab.id}`, { tier: 1, label: 'Core', expires_in_hours: 48 })).status, 200);
  await revertAndCheck(env, c, lastSuccess(env, 'network.allow.edit'), async () => {
    const row = allow().find((r) => r.id === lab.id);
    assert.equal(row.tier, 3);
    assert.equal(row.label, 'Lab');
    assert.equal(row.expires_at, null);
  });

  await stepUp(env, c);
  const blk = await c.post('/api/admin/network/block', { cidr: '185.15.56.0/24', reason: 'Scanner' });
  assert.equal(blk.status, 200);
  await revertAndCheck(env, c, lastSuccess(env, 'network.block.add'), async () => assert.equal(count(env, 'SELECT COUNT(*) FROM blocked_ips'), 0));

  await stepUp(env, c);
  const blk2 = await c.post('/api/admin/network/block', { cidr: '185.15.56.0/24', reason: 'Scanner' });
  assert.equal((await c.del(`/api/admin/network/block/${blk2.body.entry.id}`)).status, 200);
  await revertAndCheck(env, c, lastSuccess(env, 'network.block.remove'), async () => {
    const row = q(env, 'SELECT * FROM blocked_ips')[0];
    assert.equal(row.cidr, '185.15.56.0/24');
    assert.equal(row.reason, 'Scanner');
  });
});

test('settings: back to the prior raw value, or the default when there was none', async () => {
  const { env, owner } = await world();
  const c = owner.client;
  const raw = (k) => q(env, 'SELECT value FROM settings WHERE key = ?', k)[0]?.value ?? null;
  await stepUp(env, c);
  assert.equal((await c.put('/api/admin/settings', { changes: { timezone: 'Europe/London' } })).status, 200);
  await revertAndCheck(env, c, lastSuccess(env, 'setting.change'), async () => assert.equal(raw('timezone'), null));
  await stepUp(env, c);
  await c.put('/api/admin/settings', { changes: { country_deny: ['KP'] } });
  await c.put('/api/admin/settings', { changes: { country_deny: ['KP', 'RU'] } });
  await revertAndCheck(env, c, lastSuccess(env, 'setting.change'), async () => assert.equal(raw('country_deny'), '["KP"]'));
});

test('second factors: an admin reset is restored, and the authenticator app works again', async () => {
  const { env, owner, emp } = await world();
  const c = owner.client;
  const uid = emp.user.id;
  await stepUp(env, c);
  // A reset needs somewhere for codes to go (A §7.5).
  const refused = await c.post(`/api/admin/users/${uid}/reset-mfa`, {});
  assert.equal(refused.status, 409);
  assert.equal(refused.body.code, 'nothing_left');
  const d = await c.post(`/api/admin/users/${uid}/destinations`, { kind: 'email', address: 'emp.personal@example.org', label: 'Personal' });
  assert.equal(d.status, 200, d.text);
  assert.equal(d.body.destination.hint, 'e•••@example.org');
  const secretBefore = q(env, 'SELECT secret_enc FROM user_totp WHERE user_id = ?', uid)[0].secret_enc;
  const r = await c.post(`/api/admin/users/${uid}/reset-mfa`, {});
  assert.equal(r.status, 200, r.text);
  assert.equal(count(env, 'SELECT COUNT(*) FROM user_totp WHERE user_id = ?', uid), 0);
  assert.equal(count(env, 'SELECT COUNT(*) FROM backup_codes WHERE user_id = ?', uid), 0);
  await revertAndCheck(env, c, lastSuccess(env, 'mfa.reset'), async () => {
    assert.equal(q(env, 'SELECT secret_enc FROM user_totp WHERE user_id = ?', uid)[0].secret_enc, secretBefore);
    assert.equal(count(env, 'SELECT COUNT(*) FROM backup_codes WHERE user_id = ?', uid), 10);
    await signOut(emp.client);
    const s = await signIn(env, emp.client, emp.user.email, emp.password, { totpSecret: emp.totpSecret });
    assert.equal(s.status, 200, `the app on their phone works again: ${s.text}`);
  });
  // A second reset, then an enrolment since: the revert is refused, not a silent replacement.
  await stepUp(env, c);
  assert.equal((await c.post(`/api/admin/users/${uid}/reset-mfa`, {})).status, 200);
  const reset2 = lastSuccess(env, 'mfa.reset');
  q(env, 'INSERT INTO user_passkeys (id, user_id, public_key, algorithm, sign_count, created_at) VALUES (?, ?, ?, ?, 0, ?)', 'pk-new', uid, '{}', -7, new Date(env.__clock()).toISOString());
  await stepUp(env, c);
  const no = await c.post(`/api/admin/audit/${reset2.id}/revert`, {});
  assert.equal(no.status, 409);
  assert.equal(no.body.code, 'enrolled_since');
});

test('destinations: add and remove', async () => {
  const { env, owner, emp } = await world();
  const c = owner.client;
  const uid = emp.user.id;
  await stepUp(env, c);
  const d = await c.post(`/api/admin/users/${uid}/destinations`, { kind: 'email', address: 'emp.home@example.org' });
  assert.equal(d.status, 200);
  const row = auditRows(env, 'user.destination.add').pop();
  assert.ok(!row.after_state.includes('emp.home@example.org') && !row.detail.includes('emp.home'), 'the audit row carries the hint, not the address');
  await revertAndCheck(env, c, lastSuccess(env, 'user.destination.add'), async () => {
    assert.equal(count(env, 'SELECT COUNT(*) FROM code_destinations WHERE user_id = ?', uid), 0);
  });
  await stepUp(env, c);
  const d2 = await c.post(`/api/admin/users/${uid}/destinations`, { kind: 'email', address: 'emp.home@example.org', label: 'Home' });
  assert.equal((await c.del(`/api/admin/users/${uid}/destinations/${d2.body.destination.id}`)).status, 200);
  await revertAndCheck(env, c, lastSuccess(env, 'user.destination.remove'), async () => {
    const back = q(env, 'SELECT * FROM code_destinations WHERE user_id = ?', uid);
    assert.equal(back.length, 1);
    assert.equal(back[0].address, 'emp.home@example.org');
    assert.equal(back[0].label, 'Home');
  });
});

test('roles: create, edit, delete', async () => {
  const { env, owner } = await world();
  const c = owner.client;
  await stepUp(env, c);
  const cr = await c.post('/api/admin/roles', { name: 'Help desk', rank: 40, permissions: ['devices.view', 'devices.approve'], description: 'Front line' });
  assert.equal(cr.status, 200, cr.text);
  const id = cr.body.role.id;
  assert.equal(cr.body.role.key, 'help_desk');
  await revertAndCheck(env, c, lastSuccess(env, 'role.create'), async () => assert.equal(count(env, 'SELECT COUNT(*) FROM roles WHERE id = ?', id), 0));

  await stepUp(env, c);
  const cr2 = await c.post('/api/admin/roles', { name: 'Help desk', rank: 40, permissions: ['devices.view'] });
  const id2 = cr2.body.role.id;
  const ed = await c.patch(`/api/admin/roles/${id2}`, { name: 'Service desk', rank: 45, permissions: ['devices.view', 'sessions.view'] });
  assert.equal(ed.status, 200, ed.text);
  await revertAndCheck(env, c, lastSuccess(env, 'role.edit'), async () => {
    const r = q(env, 'SELECT * FROM roles WHERE id = ?', id2)[0];
    assert.equal(r.name, 'Help desk');
    assert.equal(r.rank, 40);
    assert.deepEqual(JSON.parse(r.permissions), ['devices.view']);
  });

  await stepUp(env, c);
  assert.equal((await c.del(`/api/admin/roles/${id2}`)).status, 200);
  await revertAndCheck(env, c, lastSuccess(env, 'role.delete'), async () => {
    const r = q(env, 'SELECT * FROM roles WHERE key = ?', 'help_desk')[0];
    assert.ok(r, 'recreated with the same key');
    assert.equal(r.id, id2, 'and the same id, since it was free');
  });
  // Reverting a create is a delete, so it is refused while anyone holds the role.
  await stepUp(env, c);
  const cr3 = await c.post('/api/admin/roles', { name: 'Floor lead', rank: 30, permissions: [] });
  const held = await makeUser(env, c, { role: 'employee' });
  q(env, 'UPDATE users SET role_id = ? WHERE id = ?', cr3.body.role.id, held.user.id);
  await stepUp(env, c);
  const busy = await c.post(`/api/admin/audit/${lastSuccess(env, 'role.create').id}/revert`, {});
  assert.equal(busy.status, 409);
  assert.equal(busy.body.code, 'role_in_use');
});

test('streaks: an adjustment reverts to the exact prior row', async () => {
  const { env, owner, emp } = await world();
  const c = owner.client;
  const uid = emp.user.id;
  const prior = q(env, 'SELECT * FROM streaks WHERE user_id = ?', uid)[0];
  await stepUp(env, c);
  const r = await c.post(`/api/admin/users/${uid}/streak`, { current: 40, longest: 55, reason: 'Portal outage on Jan 5' });
  assert.equal(r.status, 200, r.text);
  assert.equal(r.body.streak.current, 40);
  await revertAndCheck(env, c, lastSuccess(env, 'streak.adjust'), async () => {
    const now = q(env, 'SELECT * FROM streaks WHERE user_id = ?', uid)[0];
    for (const k of ['current', 'longest', 'total_days', 'started_day', 'last_day', 'last_at']) assert.equal(now[k], prior[k], k);
  });
  // No row before: the revert deletes the row the adjustment created.
  const fresh = await makeUser(env, c, { role: 'employee' });
  q(env, 'DELETE FROM streaks WHERE user_id = ?', fresh.user.id);
  await stepUp(env, c);
  await c.post(`/api/admin/users/${fresh.user.id}/streak`, { current: 3, reason: 'Missed by a bug' });
  await revertAndCheck(env, c, lastSuccess(env, 'streak.adjust'), async () => {
    assert.equal(count(env, 'SELECT COUNT(*) FROM streaks WHERE user_id = ?', fresh.user.id), 0);
  });
});

test('every catalogued kind was exercised above', () => {
  const missing = UNDO_KINDS.filter((k) => !covered.has(k));
  assert.deepEqual(missing, []);
});

test('refusals: no reverter, failed entries, reverts of reverts, unreadable payloads, hostile ids', async () => {
  const { env, owner } = await world();
  const c = owner.client;
  await stepUp(env, c);
  const login = lastSuccess(env, 'login.success');
  const r1 = await c.post(`/api/admin/audit/${login.id}/revert`, {});
  assert.equal(r1.status, 409);
  assert.equal(r1.body.code, 'not_revertible');
  await c.put('/api/admin/settings', { changes: { timezone: 'UTC' } });
  const ch = lastSuccess(env, 'setting.change');
  const ok = await c.post(`/api/admin/audit/${ch.id}/revert`, {});
  const revRow = q(env, 'SELECT id FROM audit_log WHERE id = ?', ok.body.revert_id)[0];
  const r2 = await c.post(`/api/admin/audit/${revRow.id}/revert`, {});
  assert.equal(r2.status, 409, 'a revert is not itself revertible');
  // A denied entry never changed anything.
  await c.post('/api/admin/network/block', { cidr: '81.2.69.0/24' });
  const denied = auditRows(env, 'network.block.add').pop();
  assert.equal(denied.outcome, 'denied');
  assert.equal((await c.post(`/api/admin/audit/${denied.id}/revert`, {})).status, 409);
  // Even one that carries an undo snapshot: only a change that happened is put back.
  const emp = await makeUser(env, c, { role: 'employee' });
  const failed = await audit({ env, nowMs: env.__clock() }, {
    action: 'user.status', outcome: 'failure', target: { type: 'user', id: emp.user.id },
    undo: undoFor('user.status', { userId: emp.user.id, status: 'suspended' }),
  });
  await stepUp(env, c);
  const f = await c.post(`/api/admin/audit/${failed.id}/revert`, {});
  assert.equal(f.status, 409, f.text);
  assert.equal(f.body.code, 'not_revertible');
  assert.equal(q(env, 'SELECT status FROM users WHERE id = ?', emp.user.id)[0].status, 'active');
  // A snapshot that does not read as the prior state is refused, never guessed at.
  const odd = await audit({ env, nowMs: env.__clock() }, {
    action: 'user.status', target: { type: 'user', id: emp.user.id }, undo: undoFor('user.status', { userId: 'someone', status: 7 }),
  });
  const u = await c.post(`/api/admin/audit/${odd.id}/revert`, {});
  assert.equal(u.status, 409, u.text);
  assert.equal(u.body.code, 'undo_unreadable');
  for (const id of ['abc', '0', '-5', '1.5', '999999']) {
    assert.equal((await c.post(`/api/admin/audit/${id}/revert`, {})).status, 404, id);
  }
  assert.equal((await verifyChain(env)).ok, true);
  const n = count(env, "SELECT COUNT(*) FROM audit_log WHERE action = 'audit.revert' AND outcome = 'success'");
  assert.equal(n, 1, 'exactly one successful revert');
});

test('a revert re-runs the permission checks: denies bind the reverter too (B trap 5)', async () => {
  const { env, owner, emp } = await world();
  const second = await makeUser(env, owner.client, { role: 'admin', totp: true });
  await stepUp(env, owner.client);
  await owner.client.post(`/api/admin/users/${second.user.id}/role`, { role_id: roleId(env, 'super_admin'), perm_grants: [], perm_denies: [] });
  await owner.client.post(`/api/admin/users/${emp.user.id}/role`, { role_id: roleId(env, 'guest'), perm_grants: [], perm_denies: [] });
  const demotion = lastSuccess(env, 'user.role');
  // A Super Admin whom users.roles has been denied cannot put a role back.
  await owner.client.post(`/api/admin/users/${second.user.id}/role`, { role_id: roleId(env, 'super_admin'), perm_grants: [], perm_denies: ['users.roles'] });
  await stepUp(env, second.client);
  const r = await second.client.post(`/api/admin/audit/${demotion.id}/revert`, {});
  assert.equal(r.status, 403, r.text);
  assert.equal(q(env, 'SELECT role_id FROM users WHERE id = ?', emp.user.id)[0].role_id, roleId(env, 'guest'));
  // Demoted to administrator, they cannot revert anything at all.
  await stepUp(env, owner.client);
  await owner.client.post(`/api/admin/users/${second.user.id}/role`, { role_id: roleId(env, 'admin'), perm_grants: [], perm_denies: [] });
  const ownDemotion = lastSuccess(env, 'user.role');
  await stepUp(env, second.client);
  const self = await second.client.post(`/api/admin/audit/${ownDemotion.id}/revert`, {});
  assert.equal(self.status, 403);
  assert.equal(self.body.code, 'forbidden');
  assert.equal(q(env, 'SELECT role_id FROM users WHERE id = ?', second.user.id)[0].role_id, roleId(env, 'admin'));
});

await run();
