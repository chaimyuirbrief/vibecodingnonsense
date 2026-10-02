// The admin console against the REAL admin API, for each system role: every
// tab the role can see loads without an error banner, and the console's own
// controls make real changes — suspend and reinstate (through the real
// step-up dialog), approve a device by its code, add and remove an allowlist
// entry, change a setting, open and close the gate, verify the audit chain,
// revert an entry. An auditor is shown no write control at all; an employee
// never gets the console.

import { test, assert, run } from '../helpers/t.js';
import { loadPage, byText, allByText } from '../helpers/dom.js';
import { openLive, navigate, apiErrors, lastNav, settle } from '../helpers/live.js';
import { freshEnv, bootstrap, makeUser, client, nextTotp, q, count, OWNER_IP, MINUTE } from '../helpers/flows.js';

const ALL_TABS = ['overview', 'people', 'invitations', 'roles', 'devices', 'network', 'security', 'settings', 'visitors', 'sessions', 'streaks', 'audit'];

// Everyone the suites need, made through the real flows.
async function world() {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const admin = await makeUser(env, owner.client, { role: 'admin', full_name: 'Ada Admin', totp: true });
  const auditor = await makeUser(env, owner.client, { role: 'auditor', full_name: 'Aud Itor' });
  const manager = await makeUser(env, owner.client, { role: 'manager', full_name: 'Max Manager' });
  const employee = await makeUser(env, owner.client, { role: 'employee', full_name: 'Eve Employee' });
  const r = await owner.client.patch(`/api/admin/users/${employee.user.id}`, { manager_id: manager.user.id });
  assert.equal(r.status, 200, r.text);
  // A browser on the office network waiting for approval, a visitor
  // fingerprint, and an access request.
  const waiting = client(env, { ip: OWNER_IP });
  const dev = await waiting.get('/api/device/status');
  assert.equal(dev.status, 200, dev.text);
  const fp = await waiting.post('/api/fp', { signals: { v: 1, ua: 'x', tz: 'America/New_York', automation: [], blocked: [] } });
  assert.equal(fp.status, 200, fp.text);
  const req = await waiting.post('/api/access-request', { email: 'newbie@example.org', full_name: 'Nina Newbie', reason: 'I start Monday.' });
  assert.equal(req.status, 200, req.text);
  return { env, owner, admin, auditor, manager, employee, waiting, deviceCode: dev.body.code };
}

function tabIds(page) {
  return page.document.querySelectorAll('#admin-tabs [role=tab]').filter((t) => !t.hidden).map((t) => t.id.replace(/^tab-/, ''));
}

function noFailures(page, ignore = []) {
  assert.deepEqual(apiErrors(page, { ignore }).map((c) => `${c.method} ${c.url} → ${c.status} ${JSON.stringify(c.response)}`), [], 'a live API call failed');
  assert.deepEqual(page.calls.pageErrors.map((e) => String(e && e.stack ? e.stack : e)), [], 'the page threw');
}

function errorBanners(page, panel) {
  return allByText(page.$(`panel-${panel}`), '.banner-danger', /./).map((b) => b.textContent.replace(/\s+/g, ' ').trim());
}

// Clicks every visible tab; each must load without an error banner.
async function visitAll(page) {
  const seen = [];
  for (const id of tabIds(page)) {
    await page.click(`tab-${id}`);
    await settle(page);
    assert.ok(page.visible(`panel-${id}`), `${id} panel shown`);
    assert.deepEqual(errorBanners(page, id), [], `${id}: error banner`);
    assert.equal(page.$(`${id}-body`).querySelector('.skeleton'), null, `${id}: still loading`);
    seen.push(id);
  }
  noFailures(page);
  return seen;
}

async function openAdmin(c) {
  const page = await openLive(c, '/admin');
  assert.equal(page.served.file, 'admin.html');
  await settle(page);
  return page;
}

// The confirm dialog the console opens before a change.
async function confirmWith(page, label) {
  await settle(page);
  const dialogs = page.document.querySelectorAll('dialog.modal').filter((d) => d.hasAttribute('open'));
  const dlg = dialogs[dialogs.length - 1];
  assert.ok(dlg, `a confirm dialog for “${label}”`);
  const btn = byText(dlg, '.modal-actions button', label);
  assert.ok(btn, `“${label}” in the dialog`);
  await page.click(btn);
  await settle(page);
}

// The step-up dialog api() opens on step_up_required.
async function stepUpWith(page, env, secret) {
  await settle(page);
  const dlg = page.document.querySelector('dialog.modal-stepup');
  assert.ok(dlg && dlg.hasAttribute('open'), 'the step-up dialog opened');
  page.fill('stepup-code', await nextTotp(env, secret));
  await page.submit(dlg.querySelector('form'));
  await settle(page);
  assert.ok(!page.document.querySelector('dialog.modal-stepup'), 'the dialog closed');
}

function calls(page, method, re) {
  return page.calls.fetch.filter((c) => c.method === method && (re instanceof RegExp ? re.test(c.path) : c.path === re));
}

// ------------------------------------------------------------ roles ----

test('Super Admin: every tab loads from the real API, with the real counts', async () => {
  const w = await world();
  const page = await openAdmin(w.owner.client);
  assert.deepEqual(tabIds(page), ALL_TABS);
  const me = calls(page, 'GET', '/api/me')[0].response;
  assert.equal(page.text('admin-sub'), `${me.user.full_name} — Super Admin.`);
  assert.deepEqual(await visitAll(page), ALL_TABS);

  // Overview tiles are the API's counts.
  await page.click('tab-overview');
  const ov = calls(page, 'GET', '/api/admin/overview')[0].response;
  assert.equal(page.document.querySelector('[data-count="users_active"] .stat-value').textContent, String(ov.counts.users_active));
  assert.equal(ov.counts.devices_pending, 1);
  assert.equal(page.document.querySelector('[data-count="devices_pending"] .stat-value').textContent, '1');
  assert.ok(ov.recent_audit.length > 0);
  assert.equal(page.$('overview-body').querySelectorAll('tbody tr').length, Math.min(10, ov.recent_audit.length));

  // People: every account the API listed, with names, roles and statuses.
  const users = calls(page, 'GET', '/api/admin/users')[0].response;
  assert.equal(users.total, 5);
  const rows = page.$('people-list').querySelectorAll('tbody tr');
  assert.equal(rows.length, users.users.length);
  assert.ok(byText(page.$('people-list'), 'td[data-label="Role"]', 'Auditor'));
  // Invitations tab: the pending access request.
  assert.ok(byText(page.$('invitations-body'), '#request-list .item-title', 'Nina Newbie'));
  // Devices: the waiting device with its code.
  assert.ok(byText(page.$('devices-body'), '#pending-devices .code-chars', w.deviceCode));
  // Network: "you are here" from the real `you`.
  const here = page.$('you-are-here');
  assert.equal(page.text(here.querySelector('.banner-title')), 'You are here: 81.2.69.142 (US)');
  assert.equal(page.text(here.querySelector('.banner-body p:not(.banner-title)')), 'Covered by 81.2.69.142/32 “Added by setup” (tier 1).');
  // Visitors: the fingerprint.
  assert.equal(page.$('visitors-body').querySelectorAll('tbody tr').length >= 1, true);
  // Roles: the six system roles.
  assert.equal(page.$('roles-body').querySelectorAll('tbody tr').length, 6);
  // Streaks: everyone active, from the API.
  const st = calls(page, 'GET', '/api/admin/streaks')[0].response;
  assert.equal(page.document.querySelectorAll('#streaks-table tbody tr').length, st.streaks.length);
  // Audit: the entries the API returned.
  const au = calls(page, 'GET', '/api/admin/audit')[0].response;
  assert.equal(page.document.querySelectorAll('#audit-list tbody tr').length, au.entries.length);
  page.dispose();
});

test('Administrator: every tab they can see loads; security policy is read-only for them', async () => {
  const w = await world();
  const page = await openAdmin(w.admin.client);
  const tabs = tabIds(page);
  assert.deepEqual(tabs, ALL_TABS, 'an Administrator sees every tab (roles and settings read-only where reserved)');
  await visitAll(page);
  // Security settings belong to Super Admins (security.manage is reserved).
  await page.click('tab-security');
  await settle(page);
  assert.equal(page.$('gate-card'), null, 'no gate controls without gate.open');
  assert.ok(page.$('set-access_mode'), 'the access mode is shown');
  assert.ok(page.$('set-access_mode-allowlist').disabled, 'read-only');
  assert.equal(page.document.querySelector('#security-form button[type=submit]'), null);
  // General settings are theirs to change.
  await page.click('tab-settings');
  await settle(page);
  assert.ok(!page.$('set-step_up_minutes').disabled);
  page.dispose();
});

test('Auditor: every tab loads and not one write control is shown — tabs, person detail, roles', async () => {
  const w = await world();
  const page = await openAdmin(w.auditor.client);
  const tabs = tabIds(page);
  assert.deepEqual(tabs, ['overview', 'people', 'roles', 'devices', 'network', 'security', 'settings', 'visitors', 'sessions', 'streaks', 'audit']);
  await visitAll(page);
  assert.match(page.text('admin-sub'), /Read-only: you can look, not change\./);
  // A person's page, and a role's.
  await page.click('tab-people');
  await page.click(page.document.querySelector(`#people-list button[data-user-id="${w.employee.user.id}"]`));
  await settle(page);
  assert.ok(page.visible('person-detail'));
  assert.equal(page.text('person-name'), 'Eve Employee');
  await page.click('tab-roles');
  await page.click(byText(page.$('roles-body'), 'button', 'View'));
  await settle(page);
  assert.deepEqual(page.document.querySelectorAll('[data-write]').map((b) => `${b.dataset.write}: ${b.textContent.trim()}`), [], 'an auditor is shown no write control');
  const controls = page.document.querySelectorAll('#settings-form input, #settings-form select, #settings-form textarea, #security-form input, #security-form select, #security-form textarea');
  assert.ok(controls.length > 20);
  assert.deepEqual(controls.filter((c) => !c.disabled).map((c) => c.id), [], 'every setting is read-only for an auditor');
  // Verifying is reading, so it is offered — and works.
  await page.click('tab-audit');
  await page.click('audit-verify');
  await settle(page);
  assert.match(page.text('verify-result'), /The audit log is intact/);
  noFailures(page);
  page.dispose();
});

test('Manager: overview, their own people, invitations and streaks — all load', async () => {
  const w = await world();
  const page = await openAdmin(w.manager.client);
  assert.deepEqual(tabIds(page), ['overview', 'people', 'invitations', 'streaks']);
  await visitAll(page);
  // Only direct reports.
  const people = calls(page, 'GET', /^\/api\/admin\/users$/)[0].response;
  assert.equal(people.scope, 'team');
  assert.deepEqual(people.users.map((u) => u.full_name), ['Eve Employee']);
  assert.ok(byText(page.$('people-body'), '.banner', 'You can see the people who report to you.'));
  const streaks = calls(page, 'GET', '/api/admin/streaks')[0].response;
  assert.equal(streaks.scope, 'team');
  assert.equal(page.document.querySelectorAll('#streaks-table tbody tr').length, 1);
  assert.equal(page.$('overview-body').querySelector('[data-count="team_reports"] .stat-value').textContent, '1');
  // A report's detail: the API's team view is { user, streak, scope } only.
  await page.click('tab-people');
  await page.click(page.document.querySelector(`#people-list button[data-user-id="${w.employee.user.id}"]`));
  await settle(page);
  const detail = calls(page, 'GET', `/api/admin/users/${w.employee.user.id}`)[0];
  assert.equal(detail.status, 200);
  assert.deepEqual(Object.keys(detail.response).sort(), ['scope', 'streak', 'user']);
  assert.equal(page.text('person-name'), 'Eve Employee');
  assert.deepEqual(errorBanners(page, 'people'), []);
  const streakCard = page.$('person-detail').querySelectorAll('section.card').find((c) => c.querySelector('.card-title')?.textContent === 'Streak');
  assert.ok(streakCard, 'their streak, from the team view');
  assert.match(streakCard.textContent, new RegExp(`Current${detail.response.streak.current} days?`));
  assert.deepEqual(page.$('person-detail').querySelectorAll('[data-write]').map((b) => b.textContent.trim()), [], 'nothing a manager may change here');
  const titles = page.$('person-detail').querySelectorAll('section.card .card-title').map((t) => t.textContent);
  assert.ok(!titles.includes('Access'), 'no permissions table built from data the team view does not carry');
  assert.ok(!/No temporary roles/.test(page.text('person-detail')));
  // A manager invites someone (no role list: the API defaults to employee).
  await page.click('tab-invitations');
  await page.click(byText(page.$('invitations-body'), 'button', 'Invite someone'));
  page.fill('invite-email', 'fresh@acme.com');
  page.fill('invite-name', 'Fresh Face');
  await page.submit('invite-form');
  await settle(page);
  const inv = calls(page, 'POST', '/api/admin/users')[0];
  assert.equal(inv.status, 200, JSON.stringify(inv.response));
  assert.equal(inv.response.user.role.key, 'employee');
  const link = page.document.querySelector('dialog.modal input.mono');
  assert.equal(link.value, inv.response.invitation.url, 'the link the API made is the one shown');
  noFailures(page);
  page.dispose();
});

test('Employee: /admin sends them home, and a stale console tab leaves at once', async () => {
  const w = await world();
  const served = await navigate(w.employee.client, '/admin');
  assert.deepEqual(served.redirects, ['/']);
  assert.equal(served.file, 'dashboard.html');
  const page = await loadPage('admin.html', { url: 'https://staff.example.com/admin', live: w.employee.client });
  await settle(page);
  assert.deepEqual(lastNav(page), { type: 'replace', url: '/' });
  assert.ok(page.visible('load-error'));
  assert.deepEqual(calls(page, 'GET', /^\/api\/admin\//), [], 'nothing admin was even asked for');
  // And the API agrees.
  assert.equal((await w.employee.client.get('/api/admin/overview')).status, 403);
  page.dispose();
});

// ------------------------------------------------------------ writes ----

test('Super Admin writes from the console hit the real routes: suspend → step-up → reinstate', async () => {
  const w = await world();
  const { env } = w;
  env.__advance(20 * MINUTE); // the step-up from setup has gone stale
  const page = await openAdmin(w.owner.client);
  await page.click('tab-people');
  await settle(page);
  await page.click(page.document.querySelector(`#people-list button[data-user-id="${w.employee.user.id}"]`));
  await settle(page);
  await page.click(byText(page.$('person-detail'), 'button[data-write="users.suspend"]', 'Suspend'));
  await confirmWith(page, 'Suspend');
  await stepUpWith(page, env, w.owner.totpSecret);
  const status = calls(page, 'POST', `/api/admin/users/${w.employee.user.id}/status`);
  assert.deepEqual(status.map((c) => c.status), [403, 200], 'refused for step-up, then retried once');
  assert.equal(status[0].response.step_up_required, true);
  assert.deepEqual(status[1].body, { status: 'suspended' });
  assert.equal(q(env, 'SELECT status FROM users WHERE id = ?', w.employee.user.id)[0].status, 'suspended');
  assert.ok(byText(page.$('person-detail'), '.badge', 'Suspended'), 'the detail re-read shows it');
  assert.equal((await w.employee.client.get('/api/me')).status, 401, 'their session ended');

  await page.click(byText(page.$('person-detail'), 'button[data-write="users.suspend"]', 'Reinstate'));
  await confirmWith(page, 'Reinstate');
  const again = calls(page, 'POST', `/api/admin/users/${w.employee.user.id}/status`);
  assert.equal(again.length, 3);
  assert.equal(again[2].status, 200, 'the step-up is fresh: no second dialog');
  assert.equal(q(env, 'SELECT status FROM users WHERE id = ?', w.employee.user.id)[0].status, 'active');
  noFailures(page, ['POST /api/admin/users/']);
  page.dispose();
});

test('Super Admin: approve a device by its code, add and remove an allowlist entry', async () => {
  const w = await world();
  const { env } = w;
  const page = await openAdmin(w.owner.client);
  await page.click('tab-devices');
  await settle(page);
  page.fill('device-code', w.deviceCode.toLowerCase().replace('-', ' '));
  await page.submit('device-code-form');
  await settle(page);
  const ap = calls(page, 'POST', /\/api\/admin\/devices\/[^/]+\/approve$/);
  assert.equal(ap.length, 1);
  assert.equal(ap[0].status, 200, JSON.stringify(ap[0].response));
  assert.equal(ap[0].body.code, w.deviceCode);
  assert.equal((await w.waiting.get('/api/device/status')).body.status, 'approved');
  assert.match(page.text('devices-body'), /Nothing waiting\./, 'the queue re-read from the API is empty');

  await page.click('tab-network');
  await settle(page);
  page.fill('allow-cidr', '91.198.174.0/24');
  page.el('allow-tier').value = '2';
  page.fill('allow-label', 'Branch office');
  await page.submit('allow-form');
  await settle(page);
  const add = calls(page, 'POST', '/api/admin/network/allow')[0];
  assert.equal(add.status, 200, JSON.stringify(add.response));
  assert.deepEqual(add.body, { cidr: '91.198.174.0/24', tier: 2, label: 'Branch office' });
  assert.equal(count(env, "SELECT COUNT(*) FROM allowed_ips WHERE cidr = '91.198.174.0/24'"), 1);
  const removeBtn = page.document.querySelector('button[aria-label="Remove 91.198.174.0/24"]');
  assert.ok(removeBtn, 'listed after the reload');
  await page.click(removeBtn);
  await confirmWith(page, 'Remove');
  const del = calls(page, 'DELETE', /^\/api\/admin\/network\/allow\/\d+$/)[0];
  assert.equal(del.status, 200, JSON.stringify(del.response));
  assert.equal(count(env, "SELECT COUNT(*) FROM allowed_ips WHERE cidr = '91.198.174.0/24'"), 0);
  // Removing the entry that covers the caller is refused, and the refusal shown.
  await page.click(page.document.querySelector('button[aria-label="Remove 81.2.69.142/32"]'));
  await confirmWith(page, 'Remove');
  const refused = calls(page, 'DELETE', /^\/api\/admin\/network\/allow\/\d+$/)[1];
  assert.equal(refused.status, 409);
  assert.match(page.text('network-result'), /^Refused — this would lock you out/);
  noFailures(page, ['DELETE /api/admin/network/allow/']);
  page.dispose();
});

test('Super Admin: change a setting, open and close the gate, verify the chain, revert an entry', async () => {
  const w = await world();
  const { env } = w;
  const page = await openAdmin(w.owner.client);

  // A setting: the streak window, with the rule preview.
  await page.click('tab-settings');
  await settle(page);
  page.fill('set-streak_window_hours', '36');
  assert.match(page.text('rule-preview'), /^Sign in at least once every 36 hours/);
  await page.submit('settings-form');
  await settle(page);
  const put = calls(page, 'PUT', '/api/admin/settings')[0];
  assert.equal(put.status, 200, JSON.stringify(put.response));
  assert.deepEqual(put.body, { changes: { streak_window_hours: 36 } }, 'only what changed is sent');
  assert.equal(q(env, "SELECT value FROM settings WHERE key = 'streak_window_hours'")[0].value, '36');
  assert.match(page.text('settings-result'), /Saved 1 change\./);

  // The gate: open for 2 hours, then close.
  await page.click('tab-security');
  await settle(page);
  page.check('gate-choice-hours');
  page.fill('gate-hours', '2');
  await page.submit('gate-form');
  await confirmWith(page, 'Open it');
  const open = calls(page, 'POST', '/api/admin/gate/open')[0];
  assert.equal(open.status, 200, JSON.stringify(open.response));
  assert.deepEqual(open.body, { hours: 2 });
  assert.match(page.text('gate-state'), /^Open to the internet until /);
  assert.match(page.text('gate-countdown'), /^[12]h \d\dm \d\ds$/, 'the countdown runs on the server’s clock');
  await page.click('gate-close');
  await settle(page);
  assert.equal(calls(page, 'POST', '/api/admin/gate/close')[0].status, 200);
  assert.match(page.text('gate-state'), /^Closed/);
  assert.equal(q(env, "SELECT value FROM settings WHERE key = 'gate_open'")[0].value, '0');

  // The audit chain, then a revert of the setting change.
  await page.click('tab-audit');
  await settle(page);
  await page.click('audit-verify');
  await settle(page);
  const v = calls(page, 'POST', '/api/admin/audit/verify')[0].response;
  assert.equal(v.ok, true);
  assert.equal(page.text(page.$('verify-result').querySelector('.banner-title')), 'The audit log is intact');
  assert.equal(page.text(page.$('verify-result').querySelector('.banner-body p:not(.banner-title)')), `Intact across ${v.checked} entries.`);
  const row = page.document.querySelectorAll('#audit-list tbody tr').find((tr) => tr.textContent.includes('setting.change') && tr.textContent.includes('streak_window_hours'));
  assert.ok(row, 'the setting change is listed');
  const revert = row.querySelector('button[data-write="audit.revert"]');
  assert.ok(revert, 'and offered for revert');
  await page.click(revert);
  await confirmWith(page, 'Revert');
  const rv = calls(page, 'POST', /^\/api\/admin\/audit\/\d+\/revert$/)[0];
  assert.equal(rv.status, 200, JSON.stringify(rv.response));
  assert.equal(count(env, "SELECT COUNT(*) FROM settings WHERE key = 'streak_window_hours' AND value IS NOT NULL AND value != '30'"), 0, 'back to the default');
  const after = page.document.querySelectorAll('#audit-list tbody tr').find((tr) => tr.dataset.id === String(rv.response.reverted));
  assert.ok(after, 'the reverted entry is listed again');
  assert.ok(byText(after, '.badge', /^Reverted by #/), 'marked as reverted');
  assert.equal(after.querySelector('button[data-write="audit.revert"]'), null, 'and no longer offered');
  noFailures(page);
  page.dispose();
});

test('Super Admin: approve an access request, see the invitation waiting, revoke it — states from the server', async () => {
  const w = await world();
  const { env } = w;
  const page = await openAdmin(w.owner.client);
  await page.click('tab-invitations');
  await settle(page);
  const item = byText(page.$('invitations-body'), '#request-list .item-row', 'Nina Newbie');
  assert.ok(item);
  await page.click(byText(item, 'button[data-write="requests.manage"]', 'Approve'));
  await settle(page);
  const ap = calls(page, 'POST', /^\/api\/admin\/requests\/\d+\/approve$/)[0];
  assert.equal(ap.status, 200, JSON.stringify(ap.response));
  assert.equal(ap.body.role_id, q(env, "SELECT id FROM roles WHERE key = 'employee'")[0].id, 'the employee role preselected');
  const link = page.document.querySelector('dialog.modal input.mono');
  assert.equal(link.value, ap.response.invitation.url);
  await page.click(byText(page.document.querySelector('dialog.modal'), 'button', 'Done'));
  await settle(page);
  // The list re-read: the new invitation is waiting (the server's `state`),
  // whatever this browser's clock says.
  const listed = calls(page, 'GET', '/api/admin/invitations').at(-1).response.invitations;
  const mine = listed.find((i) => i.email === 'newbie@example.org');
  assert.equal(mine.state, 'pending');
  const row = page.document.querySelectorAll('#invitations-body tbody tr').find((tr) => tr.textContent.includes('newbie@example.org'));
  assert.ok(byText(row, '.badge', 'Waiting'), 'shown as waiting');
  await page.click(byText(row, 'button[data-write="users.invite"]', 'Revoke'));
  await confirmWith(page, 'Revoke');
  const rv = calls(page, 'POST', `/api/admin/invitations/${mine.id}/revoke`)[0];
  assert.equal(rv.status, 200, JSON.stringify(rv.response));
  const after = page.document.querySelectorAll('#invitations-body tbody tr').find((tr) => tr.textContent.includes('newbie@example.org'));
  assert.ok(byText(after, '.badge', 'Revoked'));
  assert.match(page.text('invitations-body'), /No requests waiting\./);
  noFailures(page);
  page.dispose();
});

test('Administrator: suspends an employee and is refused acting on a Super Admin, with the server’s reason shown', async () => {
  const w = await world();
  const { env } = w;
  env.__advance(20 * MINUTE);
  const page = await openAdmin(w.admin.client);
  await page.click('tab-people');
  await settle(page);
  await page.click(page.document.querySelector(`#people-list button[data-user-id="${w.employee.user.id}"]`));
  await settle(page);
  await page.click(byText(page.$('person-detail'), 'button[data-write="users.suspend"]', 'Suspend'));
  await confirmWith(page, 'Suspend');
  await stepUpWith(page, env, w.admin.totpSecret);
  assert.equal(q(env, 'SELECT status FROM users WHERE id = ?', w.employee.user.id)[0].status, 'suspended');
  // The owner outranks them: the console offers the buttons, the server says no.
  await page.click(page.document.querySelector(`#people-list button[data-user-id="${w.owner.user.id}"]`));
  await settle(page);
  await page.click(byText(page.$('person-detail'), 'button[data-write="users.suspend"]', 'Suspend'));
  await confirmWith(page, 'Suspend');
  const last = calls(page, 'POST', `/api/admin/users/${w.owner.user.id}/status`).at(-1);
  assert.equal(last.status, 403);
  assert.ok(page.visible('person-result'));
  assert.equal(page.text(page.$('person-result').querySelector('.banner-title')), 'That didn’t work');
  assert.equal(page.text(page.$('person-result').querySelector('.banner-body p:not(.banner-title)')), last.response.error);
  noFailures(page, ['POST /api/admin/users/']);
  page.dispose();
});

await run();
