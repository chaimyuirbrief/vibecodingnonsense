// The rest of the console's write controls, each driven from the page into
// the REAL route and checked in the database: a person's profile, role,
// code destinations, factor reset, password reset, streak and invitation;
// devices (rename, block, unblock, revoke); custom roles; ending a session;
// the streaks table; the blocklist; the access mode; audit filters and
// paging.

import { test, assert, run } from '../helpers/t.js';
import { byText } from '../helpers/dom.js';
import { openLive, apiErrors, settle } from '../helpers/live.js';
import { freshEnv, bootstrap, makeUser, client, fakeProvider, TWILIO, q, count, OWNER_IP } from '../helpers/flows.js';

function calls(page, method, path) {
  return page.calls.fetch.filter((c) => c.method === method && (path instanceof RegExp ? path.test(c.path) : c.path === path));
}

function noFailures(page, ignore = []) {
  assert.deepEqual(apiErrors(page, { ignore }).map((c) => `${c.method} ${c.url} → ${c.status} ${JSON.stringify(c.response)}`), [], 'a live API call failed');
  assert.deepEqual(page.calls.pageErrors.map((e) => String(e && e.stack ? e.stack : e)), [], 'the page threw');
}

function openDialog(page) {
  return page.document.querySelectorAll('dialog.modal').filter((d) => d.hasAttribute('open')).at(-1) || null;
}

async function confirmWith(page, label) {
  await settle(page);
  const dlg = openDialog(page);
  assert.ok(dlg, `a dialog for “${label}”`);
  const btn = byText(dlg, '.modal-actions button', label);
  assert.ok(btn, `“${label}” in the dialog`);
  await page.click(btn);
  await settle(page);
}

async function setup() {
  const provider = fakeProvider();
  const env = freshEnv({ vars: { ...TWILIO, __fetch: provider.fetch } });
  const owner = await bootstrap(env);
  const emp = await makeUser(env, owner.client, { role: 'employee', full_name: 'Eve Employee', totp: true });
  const page = await openLive(owner.client, '/admin');
  await settle(page);
  return { env, owner, emp, page, provider };
}

async function openPerson(page, id) {
  await page.click('tab-people');
  await settle(page);
  await page.click(page.document.querySelector(`#people-list button[data-user-id="${id}"]`));
  await settle(page);
}

function card(page, title) {
  return page.$('person-detail').querySelectorAll('section.card').find((c) => c.querySelector('.card-title')?.textContent === title);
}

test('person: profile, role and per-person grants, from the detail panel', async () => {
  const { env, emp, page } = await setup();
  await openPerson(page, emp.user.id);
  page.fill('person-job_title', 'Support lead');
  page.fill('person-department', 'Support');
  await page.submit('person-profile');
  await settle(page);
  const patch = calls(page, 'PATCH', `/api/admin/users/${emp.user.id}`)[0];
  assert.equal(patch.status, 200, JSON.stringify(patch.response));
  assert.deepEqual(patch.body, { job_title: 'Support lead', department: 'Support' }, 'only what changed');
  assert.deepEqual(q(env, 'SELECT job_title, department FROM users WHERE id = ?', emp.user.id)[0], { job_title: 'Support lead', department: 'Support' });
  assert.equal(page.$('person-job_title').value, 'Support lead', 're-read');

  // Role: manager, plus a grant of streaks.view_all, minus directory.view.
  const managerId = q(env, "SELECT id FROM roles WHERE key = 'manager'")[0].id;
  page.el('person-role').value = String(managerId);
  page.check(page.document.querySelector('input[data-perm="streaks.view_all"][data-kind="grant"]'));
  page.check(page.document.querySelector('input[data-perm="directory.view"][data-kind="deny"]'));
  await page.click(byText(page.$('person-detail'), 'button[data-write="users.roles"]', 'Save role and permissions'));
  await settle(page);
  const role = calls(page, 'POST', `/api/admin/users/${emp.user.id}/role`)[0];
  assert.equal(role.status, 200, JSON.stringify(role.response));
  assert.deepEqual(role.body, { role_id: managerId, perm_grants: ['streaks.view_all'], perm_denies: ['directory.view'] });
  const detail = calls(page, 'GET', `/api/admin/users/${emp.user.id}`).at(-1).response;
  assert.equal(detail.user.role.key, 'manager');
  assert.ok(detail.permissions.includes('streaks.view_all') && !detail.permissions.includes('directory.view'));
  const row = (perm) => page.document.querySelector(`tr[data-perm="${perm}"]`);
  assert.equal(row('streaks.view_all').querySelector('.source-chip').textContent, 'Granted to them', 'sources from the API');
  assert.equal(row('directory.view').querySelector('.source-chip').textContent, 'Denied for them');
  assert.equal(row('users.invite').querySelector('.source-chip').textContent, 'Role');
  noFailures(page);
  page.dispose();
});

test('person: code destinations, factor reset (revertible), password reset (shown once), streak, sign-outs', async () => {
  const { env, emp, page, provider } = await setup();
  await openPerson(page, emp.user.id);
  const dest = card(page, 'Where sign-in codes go');
  assert.ok(dest, 'a Super Admin manages destinations');
  page.el('dest-kind').value = 'sms';
  page.fill('dest-address', '+15550001111');
  page.fill('dest-label', 'Mobile');
  await page.submit(dest.querySelector('form'));
  await settle(page);
  const add = calls(page, 'POST', `/api/admin/users/${emp.user.id}/destinations`)[0];
  assert.equal(add.status, 200, JSON.stringify(add.response));
  assert.ok(byText(card(page, 'Where sign-in codes go'), '.item-title', add.response.destination.hint), 'listed with its hint');

  // Lost phone: the factor reset (a destination remains, so it is allowed).
  await page.click(byText(page.$('person-detail'), 'button[data-write="users.reset_mfa"]', 'Reset second factors'));
  await confirmWith(page, 'Reset factors');
  const reset = calls(page, 'POST', `/api/admin/users/${emp.user.id}/reset-mfa`)[0];
  assert.equal(reset.status, 200, JSON.stringify(reset.response));
  assert.equal(count(env, 'SELECT COUNT(*) FROM user_totp WHERE user_id = ?', emp.user.id), 0);
  const facts = card(page, 'Sign-in security').querySelector('dl').textContent;
  assert.match(facts, /Authenticator appNot set up/);

  // Password reset: the temporary password shown once.
  await page.click(byText(page.$('person-detail'), 'button[data-write="users.reset_password"]', 'Reset password'));
  await confirmWith(page, 'Reset password');
  const pw = calls(page, 'POST', `/api/admin/users/${emp.user.id}/reset-password`)[0];
  assert.equal(pw.status, 200, JSON.stringify(pw.response));
  assert.equal(page.text('temp-password'), pw.response.temporary_password);
  await page.click(byText(openDialog(page), 'button', 'I’ve passed it on'));
  await settle(page);
  assert.equal(page.$('temp-password'), null, 'gone once acknowledged');
  assert.equal(q(env, 'SELECT must_change_password FROM users WHERE id = ?', emp.user.id)[0].must_change_password, 1);

  // Streak restore.
  page.fill('streak-current', '12');
  page.fill('streak-longest', '20');
  page.fill('streak-reason', 'Portal outage on Jan 5');
  await page.submit(card(page, 'Streak').querySelector('form'));
  await settle(page);
  const st = calls(page, 'POST', `/api/admin/users/${emp.user.id}/streak`)[0];
  assert.equal(st.status, 200, JSON.stringify(st.response));
  assert.deepEqual(st.body, { current: 12, reason: 'Portal outage on Jan 5', longest: 20 });
  assert.match(card(page, 'Streak').querySelector('dl').textContent, /Current12 days/);

  // Sign-outs.
  await page.click(byText(page.$('person-detail'), 'button[data-write="users.suspend"]', 'Sign out everywhere'));
  await confirmWith(page, 'Sign out');
  assert.equal(calls(page, 'POST', `/api/admin/users/${emp.user.id}/logout`)[0].status, 200);
  await page.click(byText(page.$('person-detail'), 'button[data-write="users.suspend"]', 'Revoke their devices'));
  await confirmWith(page, 'Revoke devices');
  assert.equal(calls(page, 'POST', `/api/admin/users/${emp.user.id}/revoke-devices`)[0].status, 200);
  assert.equal(count(env, "SELECT COUNT(*) FROM devices d JOIN device_users du ON du.device_id = d.id WHERE du.user_id = ? AND d.status = 'approved'", emp.user.id), 0);

  // After the reset the phone is their only way in: removing it is refused,
  // and the server's sentence is what the panel shows.
  const rm = byText(card(page, 'Where sign-in codes go'), 'button[data-write="destinations.manage"]', 'Remove');
  await page.click(rm);
  await confirmWith(page, 'Remove');
  const del = calls(page, 'DELETE', new RegExp(`^/api/admin/users/${emp.user.id}/destinations/\\d+$`))[0];
  assert.equal(del.status, 409);
  assert.equal(page.text(page.$('person-result').querySelector('.banner-body p:not(.banner-title)')), del.response.error);
  assert.equal(count(env, 'SELECT COUNT(*) FROM code_destinations WHERE user_id = ?', emp.user.id), 1);
  noFailures(page, ['DELETE /api/admin/users/']);
  assert.equal(provider.calls.length, 0, 'nothing was texted');
  page.dispose();
});

test('person: an invited account’s link reissued from the console', async () => {
  const { owner, page } = await setup();
  const inv = await owner.client.post('/api/admin/users', { email: 'later@acme.com', full_name: 'Lee Later' });
  assert.equal(inv.status, 200);
  await page.click('tab-people');
  await settle(page);
  await page.submit('people-search'); // re-read the list
  await settle(page);
  await openPerson(page, inv.body.user.id);
  const c = card(page, 'Invitation');
  assert.ok(c, 'the invitation card');
  assert.match(c.querySelector('.card-sub').textContent, /^The current link expires /);
  await page.click(byText(c, 'button', 'Reissue the link'));
  await settle(page);
  const r = calls(page, 'POST', `/api/admin/users/${inv.body.user.id}/invitation`)[0];
  assert.equal(r.status, 200, JSON.stringify(r.response));
  assert.equal(openDialog(page).querySelector('input.mono').value, r.response.invitation.url);
  assert.notEqual(r.response.invitation.url, inv.body.invitation.url);
  noFailures(page);
  page.dispose();
});

test('devices: rename, block, unblock and revoke from the console', async () => {
  const { env, emp, page } = await setup();
  const devId = q(env, 'SELECT device_id FROM device_users WHERE user_id = ?', emp.user.id)[0].device_id;
  await page.click('tab-devices');
  await settle(page);
  const rowOf = () => page.document.querySelectorAll('#devices-body tbody tr').find((tr) => tr.textContent.includes('User') || tr.textContent.includes('Eve'));
  const actionsFor = () => page.document.querySelectorAll('#devices-body tbody tr').find((tr) => tr.querySelector('td[data-label="People"]')?.textContent.includes('Eve Employee'));
  assert.ok(actionsFor(), 'Eve’s device is listed with her name');
  await page.click(byText(actionsFor(), 'button', 'Rename'));
  await settle(page);
  page.fill('device-rename', 'Eve’s laptop');
  await page.click(byText(openDialog(page), 'button', 'Save'));
  await settle(page);
  const rn = calls(page, 'POST', `/api/admin/devices/${devId}/rename`)[0];
  assert.equal(rn.status, 200, JSON.stringify(rn.response));
  assert.equal(q(env, 'SELECT label FROM devices WHERE id = ?', devId)[0].label, 'Eve’s laptop');
  await page.click(byText(actionsFor(), 'button', 'Block'));
  await confirmWith(page, 'Block');
  assert.equal(calls(page, 'POST', `/api/admin/devices/${devId}/block`)[0].status, 200);
  assert.equal(q(env, 'SELECT status FROM devices WHERE id = ?', devId)[0].status, 'blocked');
  await page.click(byText(actionsFor(), 'button', 'Unblock'));
  await settle(page);
  assert.equal(calls(page, 'POST', `/api/admin/devices/${devId}/unblock`)[0].status, 200);
  assert.equal(q(env, 'SELECT status FROM devices WHERE id = ?', devId)[0].status, 'pending');
  // Approve it again by its code, then revoke it.
  const code = page.document.querySelectorAll('#pending-devices .item-row').find((li) => li.dataset.deviceId === devId).querySelector('.code-chars').textContent;
  page.fill('device-code', code);
  await page.submit('device-code-form');
  await settle(page);
  assert.equal(q(env, 'SELECT status FROM devices WHERE id = ?', devId)[0].status, 'approved');
  await page.click(byText(actionsFor(), 'button', 'Revoke'));
  await confirmWith(page, 'Revoke');
  assert.equal(calls(page, 'DELETE', `/api/admin/devices/${devId}`)[0].status, 200);
  assert.equal(q(env, 'SELECT status FROM devices WHERE id = ?', devId)[0].status, 'pending');
  assert.ok(rowOf());
  noFailures(page);
  page.dispose();
});

test('roles: create a custom role, edit it, delete it', async () => {
  const { env, page } = await setup();
  await page.click('tab-roles');
  await settle(page);
  await page.click(byText(page.$('roles-body'), 'button[data-write="roles.manage"]', 'New role'));
  await settle(page);
  page.fill('role-name', 'Front desk');
  page.fill('role-rank', '30');
  page.fill('role-desc', 'Reception staff');
  page.check(page.document.querySelector('#role-form input[data-perm="devices.view"]'));
  page.check(page.document.querySelector('#role-form input[data-perm="devices.approve"]'));
  assert.ok(page.document.querySelector('#role-form input[data-perm="gate.open"]').disabled, 'reserved: not offered');
  await page.submit('role-form');
  await settle(page);
  const cr = calls(page, 'POST', '/api/admin/roles')[0];
  assert.equal(cr.status, 200, JSON.stringify(cr.response));
  assert.deepEqual(cr.body, { name: 'Front desk', rank: 30, description: 'Reception staff', permissions: ['devices.view', 'devices.approve'] });
  const listed = page.document.querySelectorAll('#roles-body tbody tr').find((tr) => tr.textContent.includes('Front desk'));
  assert.ok(listed, 'listed after the reload');
  assert.match(listed.textContent, /2 permissions/);
  assert.ok(byText(listed, '.badge', 'Custom'));

  await page.click(byText(listed, 'button', 'Edit'));
  await settle(page);
  page.fill('role-rank', '35');
  await page.submit('role-form');
  await settle(page);
  const ed = calls(page, 'PATCH', `/api/admin/roles/${cr.response.role.id}`)[0];
  assert.equal(ed.status, 200, JSON.stringify(ed.response));
  assert.equal(q(env, 'SELECT rank FROM roles WHERE id = ?', cr.response.role.id)[0].rank, 35);

  const again = page.document.querySelectorAll('#roles-body tbody tr').find((tr) => tr.textContent.includes('Front desk'));
  await page.click(byText(again, 'button', 'Edit'));
  await settle(page);
  await page.click(byText(page.$('role-editor'), 'button', 'Delete role'));
  await confirmWith(page, 'Delete');
  assert.equal(calls(page, 'DELETE', `/api/admin/roles/${cr.response.role.id}`)[0].status, 200);
  assert.equal(count(env, "SELECT COUNT(*) FROM roles WHERE name = 'Front desk'"), 0);
  noFailures(page);
  page.dispose();
});

test('sessions and streaks tabs: end someone’s session; adjust a streak in the table', async () => {
  const { env, emp, page } = await setup();
  await page.click('tab-sessions');
  await settle(page);
  const sessions = calls(page, 'GET', '/api/admin/sessions')[0].response.sessions;
  const hers = sessions.find((s) => s.user_id === emp.user.id);
  assert.ok(hers);
  const row = page.document.querySelectorAll('#sessions-body tbody tr').find((tr) => tr.textContent.includes('Eve Employee'));
  assert.ok(byText(page.document.querySelectorAll('#sessions-body tbody tr').find((tr) => tr.textContent.includes('This is you')), '.badge', 'This is you'));
  await page.click(byText(row, 'button', 'End'));
  await confirmWith(page, 'End session');
  assert.equal(calls(page, 'DELETE', `/api/admin/sessions/${hers.id_ref}`)[0].status, 200);
  assert.equal((await emp.client.get('/api/me')).status, 401);

  await page.click('tab-streaks');
  await settle(page);
  const tr = page.document.querySelector(`#streaks-table tr[data-user-id="${emp.user.id}"]`);
  assert.ok(tr);
  await page.click(byText(tr, 'button', 'Adjust'));
  await settle(page);
  page.fill('adjust-current', '7');
  page.fill('adjust-reason', 'Holiday closure');
  await page.click(byText(openDialog(page), 'button', 'Adjust'));
  await settle(page);
  const adj = calls(page, 'POST', `/api/admin/users/${emp.user.id}/streak`)[0];
  assert.equal(adj.status, 200, JSON.stringify(adj.response));
  assert.equal(page.document.querySelector(`#streaks-table tr[data-user-id="${emp.user.id}"] td[data-label="Current"]`).textContent, '7');
  noFailures(page);
  page.dispose();
});

test('blocklist and access mode: block a range, unblock it; switch to invite_only (the caller’s device is kept in)', async () => {
  const { env, page } = await setup();
  await page.click('tab-network');
  await settle(page);
  page.fill('block-cidr', '185.15.56.0/24');
  page.fill('block-label', 'Credential stuffing');
  await page.submit('block-form');
  await settle(page);
  const b = calls(page, 'POST', '/api/admin/network/block')[0];
  assert.equal(b.status, 200, JSON.stringify(b.response));
  assert.equal(q(env, "SELECT reason FROM blocked_ips WHERE cidr = '185.15.56.0/24'")[0].reason, 'Credential stuffing');
  const brow = page.document.querySelectorAll('#network-body tbody tr').find((tr) => tr.textContent.includes('185.15.56.0/24'));
  assert.ok(byText(brow, 'td[data-label="Reason"]', 'Credential stuffing'), 'the reason shown');
  await page.click(page.document.querySelector('button[aria-label="Unblock 185.15.56.0/24"]'));
  await confirmWith(page, 'Unblock');
  assert.equal(count(env, "SELECT COUNT(*) FROM blocked_ips WHERE cidr = '185.15.56.0/24'"), 0);
  // Blocking the caller's own address is refused, with the reason shown.
  page.fill('block-cidr', '81.2.69.0/24');
  await page.submit('block-form');
  await settle(page);
  assert.equal(calls(page, 'POST', '/api/admin/network/block')[1].status, 409);
  assert.match(page.text('network-result'), /^Refused — this would lock you out/);

  await page.click('tab-security');
  await settle(page);
  page.check('set-access_mode-invite_only');
  await page.submit('security-form');
  await settle(page);
  const put = calls(page, 'PUT', '/api/admin/settings')[0];
  assert.equal(put.status, 200, JSON.stringify(put.response));
  assert.deepEqual(put.body, { changes: { access_mode: 'invite_only' } }, 'only the mode is sent');
  assert.equal(q(env, "SELECT value FROM settings WHERE key = 'access_mode'")[0].value, 'invite_only');
  assert.match(page.text('security-result'), /Saved 1 change\./);
  for (const n of put.response.notices) assert.ok(page.text('security-result').includes(n), 'every notice shown');
  for (const n of put.response.warnings) assert.ok(page.text('security-result').includes(n), 'every warning shown');
  assert.ok(page.$('set-access_mode-invite_only').checked, 're-read shows the new mode');
  noFailures(page, ['POST /api/admin/network/block']);
  page.dispose();
});

test('settings → dashboard: an extra protected date added in the console shows in everyone’s coming-up list; a country list saves', async () => {
  const { env, owner, page } = await setup();
  await page.click('tab-settings');
  await settle(page);
  page.fill('set-streak_extra_dates-date', '2026-01-14');
  page.fill('set-streak_extra_dates-label', 'Office closed');
  await page.click(byText(page.$('settings-form'), 'button', 'Add date'));
  assert.match(page.text('rule-preview'), /Shabbos, Yom Tov \(diaspora\) and 1 extra date/);
  await page.submit('settings-form');
  await settle(page);
  const put = calls(page, 'PUT', '/api/admin/settings')[0];
  assert.equal(put.status, 200, JSON.stringify(put.response));
  assert.deepEqual(put.body, { changes: { streak_extra_dates: [{ date: '2026-01-14', label: 'Office closed' }] } });
  assert.ok(byText(page.$('settings-form'), '#set-streak_extra_dates-list li', 'Office closed'), 'listed after the re-read');

  await page.click('tab-security');
  await settle(page);
  page.fill('set-country_deny', 'kp, ru');
  await page.submit('security-form');
  await settle(page);
  const put2 = calls(page, 'PUT', '/api/admin/settings')[1];
  assert.equal(put2.status, 200, JSON.stringify(put2.response));
  assert.deepEqual(put2.body, { changes: { country_deny: ['KP', 'RU'] } });
  assert.equal(q(env, "SELECT value FROM settings WHERE key = 'country_deny'")[0].value, '["KP","RU"]');
  assert.equal(page.$('set-country_deny').value, 'KP, RU');
  noFailures(page);
  page.dispose();

  const dash = await openLive(owner.client, '/');
  await settle(dash);
  const upcoming = calls(dash, 'GET', '/api/me/streak')[0].response.upcoming;
  assert.deepEqual(upcoming.find((e) => e.day === '2026-01-14'), { day: '2026-01-14', names: ['Office closed'] });
  const li = dash.document.querySelectorAll('#upcoming li').find((x) => x.querySelector('time').getAttribute('datetime') === '2026-01-14');
  assert.ok(li, 'in the coming-up list');
  assert.equal(li.textContent.replace(/\s+/g, ' ').trim(), 'Wed Jan 14 · Office closed — the clock pauses');
  dash.dispose();
});

test('person: a temporary role granted from the console and revoked again (browser clock agreeing with the server)', async () => {
  const { env, emp, page } = await setup();
  const realNow = Date.now;
  Date.now = () => env.__clock(); // this browser's clock agrees with the server's
  try {
    await openPerson(page, emp.user.id);
    const auditorId = q(env, "SELECT id FROM roles WHERE key = 'auditor'")[0].id;
    page.el('temp-role').value = String(auditorId);
    const until = new Date(env.__clock() + 5 * 86400000);
    const local = `${until.getFullYear()}-${String(until.getMonth() + 1).padStart(2, '0')}-${String(until.getDate()).padStart(2, '0')}T${String(until.getHours()).padStart(2, '0')}:00`;
    page.fill('temp-until', local);
    await page.submit(page.$('temp-until').closest('form'));
    await settle(page);
    const g = calls(page, 'POST', `/api/admin/users/${emp.user.id}/temp-role`)[0];
    assert.ok(g, 'sent');
    assert.equal(g.status, 200, JSON.stringify(g.response));
    assert.equal(g.body.role_id, auditorId);
    assert.equal(g.body.expires_at, new Date(local).toISOString());
    const detail = calls(page, 'GET', `/api/admin/users/${emp.user.id}`).at(-1).response;
    assert.equal(detail.temp_roles.length, 1);
    assert.equal(detail.temp_roles[0].active, true);
    const row = byText(page.$('person-detail'), '.item-row', 'Auditor');
    assert.match(row.querySelector('.item-sub').textContent, /^Until /);
    assert.ok(detail.permissions.includes('audit.view'), 'the temporary role’s permissions apply');
    await page.click(byText(row, 'button', 'Revoke'));
    await confirmWith(page, 'Revoke');
    const r = calls(page, 'DELETE', `/api/admin/users/${emp.user.id}/temp-role/${auditorId}`)[0];
    assert.equal(r.status, 200, JSON.stringify(r.response));
    assert.equal(count(env, 'SELECT COUNT(*) FROM user_roles WHERE user_id = ?', emp.user.id), 0);
    assert.match(page.text('person-detail'), /No temporary roles\./);
    noFailures(page);
  } finally {
    Date.now = realNow;
  }
  page.dispose();
});

test('audit: filter by action and outcome, page back through older entries', async () => {
  const { env, page } = await setup();
  // Plenty of history: 60 failed sign-ins from a stranger on the office network.
  const s = client(env, { ip: OWNER_IP });
  for (let i = 0; i < 60; i++) await s.post('/api/auth/login', { identifier: `nobody${i}@acme.com`, password: 'not-a-real-password' });
  await page.click('tab-audit');
  await settle(page);
  const first = calls(page, 'GET', /^\/api\/admin\/audit$/)[0];
  assert.equal(first.url, '/api/admin/audit?limit=50');
  assert.equal(page.document.querySelectorAll('#audit-list tbody tr').length, 50);
  assert.ok(page.$('audit-more'), 'older entries offered');
  await page.click('audit-more');
  await settle(page);
  const second = calls(page, 'GET', /^\/api\/admin\/audit$/)[1];
  assert.equal(second.url, `/api/admin/audit?before_seq=${first.response.next_before_seq}&limit=50`);
  assert.equal(page.document.querySelectorAll('#audit-list tbody tr').length, 50 + second.response.entries.length);
  page.fill('audit-action', 'login.');
  page.el('audit-outcome').value = 'failure';
  await page.submit('audit-filters');
  await settle(page);
  const filtered = calls(page, 'GET', /^\/api\/admin\/audit$/)[2];
  assert.equal(filtered.url, '/api/admin/audit?action=login.&outcome=failure&limit=50');
  assert.ok(filtered.response.entries.length === 50);
  assert.ok(filtered.response.entries.every((e) => e.action === 'login.fail' && e.outcome === 'failure'));
  assert.equal(page.document.querySelectorAll('#audit-list tbody tr').length, 50);
  noFailures(page);
  page.dispose();
});

await run();
