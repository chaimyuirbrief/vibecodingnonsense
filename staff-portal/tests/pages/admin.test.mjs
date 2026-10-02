// public/admin.html + js/admin.js — the admin console (CONTRACTS §8.3, §8.4
// Admin, §5, §8.5; A §9 hide what they can't use, §14.1/§14.11 blank vs 0;
// B trap 8 self-lockout refusals; B §7 verify + revert).
//
// Permission sets come from the real catalogue and the settings metadata
// from the real registry, so these fixtures can't drift from the server.

import { test, assert, run } from '../helpers/t.js';
import { loadPage, reply, byText, texts } from '../helpers/dom.js';
import { PERMISSIONS, PERMISSION_KEYS, SYSTEM_ROLES } from '../../src/catalog.js';
import { SETTINGS } from '../../src/policy.js';

const ORIGIN = 'https://staff.example.com';
const NOW = Date.now();
const iso = (offsetMs) => new Date(NOW + offsetMs).toISOString();
const HOUR = 3600000;

const ROLES = [
  ...SYSTEM_ROLES.map((r, i) => ({ id: i + 1, key: r.key, name: r.name, rank: r.rank, permissions: [...r.permissions], description: r.description, system: true, holders: 1 })),
  { id: 7, key: 'helpdesk', name: 'Helpdesk', rank: 40, permissions: ['users.view', 'users.reset_mfa'], description: 'Phones and resets.', system: false, holders: 0 },
];
const role = (key) => ROLES.find((r) => r.key === key);
const permsOf = (key) => (key === 'super_admin' ? [...PERMISSION_KEYS] : [...role(key).permissions]);

function meAs(key, perms = permsOf(key)) {
  const r = role(key);
  return {
    user: { id: 1, full_name: 'Ada Admin', email: 'ada@acme.com', role: { id: r.id, key: r.key, name: r.name, rank: r.rank }, status: 'active' },
    permissions: perms,
    sources: {},
    pinned: null,
    enroll_prompt: false,
    step_up_fresh: true,
    factors: { totp: true, totpUnreadable: false, passkeys: 1, backup: 8, destinations: 1 },
    org_name: 'Acme Inc.',
    timezone: 'America/New_York',
    privacy_notice: null,
  };
}

function settingsFor(perms) {
  return {
    settings: Object.values(SETTINGS).map((s) => ({
      key: s.key,
      label: s.label,
      value: s.key === 'gate_open' ? { open: false, until: null, forever: false } : JSON.parse(JSON.stringify(s.default ?? null)),
      raw: null,
      default: s.key === 'gate_open' ? '0' : s.default,
      perm: s.perm,
      type: s.type,
      options: s.options ? [...s.options] : null,
      min: s.min ?? null,
      max: s.max ?? null,
      description: s.description,
      can_edit: s.key !== 'gate_open' && perms.includes(s.perm),
    })),
  };
}

const JANE = { id: 2, full_name: 'Jane Doe', email: 'jane@acme.com', username: 'jane', employee_no: 'ACME000002', role: { id: 5, key: 'employee', name: 'Employee', rank: 20 }, status: 'active', last_login_at: iso(-HOUR) };
const SAM = { id: 3, full_name: 'Sam Levi', email: 'sam@acme.com', role: { id: 5, key: 'employee', name: 'Employee', rank: 20 }, status: 'suspended', last_login_at: iso(-30 * 24 * HOUR) };

const JANE_DETAIL = {
  user: { ...JANE, perm_grants: ['directory.view'], perm_denies: ['team.view'], locked: false },
  permissions: ['directory.view'],
  sources: { 'directory.view': 'flag' },
  denied: ['team.view'],
  temp_roles: [{ role_id: 3, role: { id: 3, name: 'Auditor' }, expires_at: iso(5 * 24 * HOUR) }],
  factors: { totp: true, totpUnreadable: false, passkeys: 1, backup: 5, destinations: 1 },
  streak: { state: 'active', current: 5, longest: 9, last_day: '2026-10-02' },
  invitation: null,
};

const AUDIT = {
  entries: [
    { id: 101, seq: 57, at: iso(-HOUR), actor_id: 1, actor_label: 'Ada Admin', action: 'network.allow.remove', target_type: 'allow', target_id: '3', outcome: 'success', severity: 'notice', detail: 'Removed 91.198.174.0/24 (Coworking)', before: { cidr: '91.198.174.0/24' }, after: null, undo_kind: 'network.allow.remove', revertible: true, reverted_by: null },
    { id: 100, seq: 56, at: iso(-2 * HOUR), actor_id: 2, actor_label: 'Jane Doe', action: 'login.success', target_type: 'user', target_id: '2', outcome: 'success', severity: 'info', detail: 'Signed in with passkey', revertible: false, reverted_by: null },
    { id: 99, seq: 55, at: iso(-3 * HOUR), actor_id: 1, actor_label: 'Ada Admin', action: 'user.status', target_type: 'user', target_id: '3', outcome: 'success', severity: 'notice', detail: 'Suspended sam@acme.com', undo_kind: 'user.status', revertible: false, reverted_by: 120 },
  ],
  next_before_seq: 55,
};

const NETWORK = {
  allow: [
    { id: 1, cidr: '81.2.69.0/24', tier: 2, label: 'Office', owner: 'IT', expires_at: null, active: true, covers_ip: true },
    { id: 2, cidr: '91.198.174.0/24', tier: 3, label: 'Coworking', owner: null, expires_at: iso(48 * HOUR), active: true, covers_ip: false },
  ],
  block: [{ id: 9, cidr: '185.15.56.0/24', label: 'Credential stuffing', expires_at: null, active: true, covers_ip: false }],
  you: { ip: '81.2.69.10', country: 'GB', asn: 20712, tier: 2, covered_by: { id: 1, cidr: '81.2.69.0/24', label: 'Office', tier: 2 } },
};

function routes(perms, extra = {}) {
  return {
    'GET /api/admin/overview': reply(200, { counts: { users_active: 12, devices_pending: 1, requests_pending: 1 }, recent_audit: AUDIT.entries.slice(0, 2) }),
    'GET /api/admin/users': reply(200, { users: [JANE, SAM], total: 2 }),
    'GET /api/admin/users/2': reply(200, JANE_DETAIL),
    'GET /api/admin/users/2/destinations': reply(200, { destinations: [{ id: 4, kind: 'sms', hint: '•••• 1234', label: 'Mobile', is_primary: true }] }),
    'GET /api/admin/roles': reply(200, { roles: ROLES }),
    'GET /api/admin/permissions': reply(200, { permissions: PERMISSIONS }),
    'GET /api/admin/invitations': reply(200, { invitations: [{ id: 1, email: 'new@acme.com', full_name: 'New Person', created_at: iso(-HOUR), expires_at: iso(6 * 24 * HOUR), used_at: null, revoked_at: null }] }),
    'GET /api/admin/requests': reply(200, { requests: [{ id: 5, email: 'req@acme.com', full_name: 'Rae Quest', reason: 'Starting Monday', status: 'pending', created_at: iso(-HOUR), ip: '81.2.69.40', country: 'GB', risk: 12 }] }),
    'GET /api/admin/devices': reply(200, {
      devices: [
        { id: 'dv1', code: 'K7F3-9QX2', status: 'pending', label: 'Safari on iPhone', ip: '81.2.69.50', created_at: iso(-HOUR), users: [] },
        { id: 'dv2', code: 'AB12-CD34', status: 'approved', label: 'Chrome on macOS', ip: '81.2.69.10', last_seen_at: iso(-60000), users: [{ id: 2, full_name: 'Jane Doe' }] },
      ],
    }),
    'GET /api/admin/network': reply(200, NETWORK),
    'GET /api/admin/settings': reply(200, settingsFor(perms)),
    'GET /api/admin/gate': reply(200, { open: false, until: null, forever: false }),
    'GET /api/admin/visitors': reply(200, {
      visitors: [{ visitor_id: 'a1b2c3d4e5f6a7b8c9', last_seen: iso(-60000), ip: '185.15.56.7', country: 'NL', as_org: 'Hosting BV', risk: { score: 82, flags: [{ key: 'webdriver', weight: 60, reason: 'The browser says automation software is driving it (WebDriver).' }, { key: 'datacenter', weight: 22, reason: 'The network belongs to a hosting provider.' }] } }],
      threshold: 70,
    }),
    'GET /api/admin/visits': reply(200, { visits: [{ at: iso(-60000), decision: 'deny', reason: 'risk', method: 'GET', path: '/', ip: '185.15.56.7', country: 'NL', risk: 82 }] }),
    'GET /api/admin/sessions': reply(200, {
      sessions: [
        { id_ref: 'aaaaaaaaaaaa', user: { id: 1, full_name: 'Ada Admin' }, created_at: iso(-HOUR), last_seen_at: iso(-60000), ip: '81.2.69.10', aal: 2, current: true },
        { id_ref: 'bbbbbbbbbbbb', user: { id: 2, full_name: 'Jane Doe' }, created_at: iso(-2 * HOUR), last_seen_at: iso(-HOUR), ip: '81.2.69.11', aal: 1, current: false },
      ],
    }),
    'GET /api/admin/streaks': reply(200, {
      streaks: [
        { user_id: 2, full_name: 'Jane Doe', state: 'active', current: 5, longest: 9, last_day: '2026-10-02' },
        { user_id: 3, full_name: 'Sam Levi', state: 'lapsed', current: 0, longest: 30, last_day: '2026-09-01' },
        { user_id: 4, full_name: 'Avi Cohen', state: 'at_risk', current: 12, longest: 12, last_day: '2026-10-01' },
      ],
      scope: 'all',
    }),
    'GET /api/admin/audit': reply(200, AUDIT),
    ...extra,
  };
}

async function open(key = 'super_admin', { perms = permsOf(key), fetch = {}, url = `${ORIGIN}/admin`, me } = {}) {
  return loadPage('admin.html', { url, fetch: { 'GET /api/me': reply(200, me || meAs(key, perms)), ...routes(perms, fetch) } });
}

const tabIds = (page) => page.document.querySelectorAll('[role=tab]').map((t) => t.id.replace('tab-', ''));
const writes = (root) => root.querySelectorAll('[data-write]');
const dialogBtn = (page, cls) => page.document.querySelector(`dialog.modal .${cls}`);

async function visit(page, tab) {
  await page.click(`tab-${tab}`);
  await page.drain();
  return page.$(`${tab}-body`);
}

const firstCells = (page, sel) => page.document.querySelectorAll(`${sel} tbody tr`).map((tr) => tr.querySelector('td').textContent.trim());

const ALL_TABS = ['overview', 'people', 'invitations', 'roles', 'devices', 'network', 'security', 'settings', 'visitors', 'sessions', 'streaks', 'audit'];

// ---------------------------------------------------------- the tabs ----

test('tabs follow permissions: super admin and administrator see all twelve', async () => {
  for (const key of ['super_admin', 'admin']) {
    const page = await open(key);
    assert.deepEqual(tabIds(page), ALL_TABS, key);
    assert.ok(page.visible('admin-tabs'));
    assert.equal(page.document.title, 'Admin console · Acme Inc.');
    assert.deepEqual(page.calls.unmatched, []);
    page.dispose();
  }
});

test('tabs follow permissions: an auditor gets no invitations tab, a manager only four — and the hidden panels are gone', async () => {
  const auditor = await open('auditor');
  assert.deepEqual(tabIds(auditor), ALL_TABS.filter((t) => t !== 'invitations'));
  assert.equal(auditor.$('panel-invitations'), null, 'not hidden: removed');
  assert.match(auditor.text('admin-sub'), /Read-only: you can look, not change\./);
  auditor.dispose();
  const manager = await open('manager');
  assert.deepEqual(tabIds(manager), ['overview', 'people', 'invitations', 'streaks']);
  for (const t of ['roles', 'devices', 'network', 'security', 'settings', 'visitors', 'sessions', 'audit']) assert.equal(manager.$(`panel-${t}`), null, t);
  manager.dispose();
  const one = await open('employee', { perms: ['devices.view'] });
  assert.deepEqual(tabIds(one), ['overview', 'devices'], 'a single grant opens exactly its tab');
  one.dispose();
});

test('an employee (no admin-console permission) is sent home and nothing admin is fetched', async () => {
  const page = await open('employee');
  assert.deepEqual(page.calls.nav, [{ type: 'replace', url: '/' }]);
  assert.ok(page.visible('load-error'));
  assert.ok(!page.visible('admin-tabs'));
  assert.deepEqual(page.calls.fetch.map((r) => r.path), ['/api/me']);
  assert.ok(!page.document.querySelectorAll('.topnav-link').some((a) => a.getAttribute('href') === '/admin'));
  page.dispose();
});

test('a pinned session is sent to the account page', async () => {
  const page = await open('super_admin', { me: { ...meAs('super_admin'), pinned: 'mfa_enroll' } });
  assert.deepEqual(page.calls.nav, [{ type: 'replace', url: '/account?pin=mfa_enroll' }]);
  page.dispose();
});

test('deep link: /admin#tab-audit opens the audit tab first', async () => {
  const page = await open('super_admin', { url: `${ORIGIN}/admin#tab-audit` });
  assert.equal(page.$('tab-audit').getAttribute('aria-selected'), 'true');
  assert.ok(page.visible('panel-audit'));
  assert.equal(page.requests('/api/admin/audit').length, 1);
  assert.equal(page.requests('/api/admin/overview').length, 0, 'tabs load on first view, not all at once');
  page.dispose();
});

// ------------------------------------------------------ write controls ----

test('an auditor is shown no write control on any tab, even inside a person', async () => {
  const page = await open('auditor');
  for (const tab of tabIds(page)) {
    const body = await visit(page, tab);
    assert.ok(body.childNodes.length, `${tab} rendered`);
    assert.deepEqual(writes(page.document).map((b) => `${tab}:${b.dataset.write}`), [], `${tab}: write controls shown to an auditor`);
  }
  await visit(page, 'people');
  await page.click(byText(page.document, '#people-list button', 'Jane Doe'));
  assert.ok(page.visible('person-detail'));
  assert.equal(page.text('person-name'), 'Jane Doe');
  assert.deepEqual(writes(page.document), []);
  assert.equal(page.document.querySelectorAll('#person-detail input[type=checkbox]').length, 0, 'no grant/deny boxes');
  await visit(page, 'settings');
  const inputs = page.document.querySelectorAll('#settings-form input, #settings-form select, #settings-form textarea');
  assert.ok(inputs.length > 10);
  assert.ok(inputs.every((i) => i.disabled), 'every setting read-only');
  assert.equal(page.$('settings-form-save'), null, 'no save button');
  await visit(page, 'audit');
  assert.ok(page.$('audit-verify'), 'verifying is reading, so an auditor may');
  assert.equal(page.document.querySelectorAll('#audit-list [data-write]').length, 0, 'no Revert even on a revertible entry');
  assert.deepEqual(page.calls.unmatched, []);
  assert.deepEqual(page.calls.pageErrors, []);
  page.dispose();
});

test('a super admin gets the write controls each tab needs', async () => {
  const page = await open('super_admin');
  const seen = new Set();
  for (const tab of ALL_TABS) {
    await visit(page, tab);
    for (const b of writes(page.$(`panel-${tab}`))) seen.add(b.dataset.write);
  }
  for (const p of ['users.invite', 'requests.manage', 'roles.manage', 'devices.approve', 'devices.manage', 'network.manage', 'gate.open', 'security.manage', 'settings.manage', 'sessions.revoke', 'streaks.manage', 'audit.revert']) {
    assert.ok(seen.has(p), `missing a ${p} control`);
  }
  assert.deepEqual(page.calls.unmatched, []);
  assert.deepEqual(page.calls.pageErrors, []);
  page.dispose();
});

test('an administrator: no gate controls, no reserved security settings, no revert', async () => {
  const page = await open('admin');
  await visit(page, 'security');
  assert.equal(page.$('gate-form'), null);
  assert.match(page.text('gate-state'), /Closed\./);
  assert.ok(page.document.querySelectorAll('#security-form input').every((i) => i.disabled), 'security.manage is reserved');
  assert.equal(page.$('security-form-save'), null);
  await visit(page, 'settings');
  assert.ok(page.$('settings-form-save'), 'settings.manage is not reserved');
  assert.ok(!page.$('set-streak_window_hours').disabled);
  await visit(page, 'audit');
  assert.equal(page.document.querySelectorAll('#audit-list [data-write]').length, 0);
  page.dispose();
});

// ---------------------------------------------------------------- audit ----

test('audit: Revert only where entry.revertible; it confirms, steps up, retries once and reloads', async () => {
  const page = await open('super_admin', {
    fetch: {
      'POST /api/admin/audit/101/revert': [reply(403, { step_up_required: true, error: 'Confirm it’s you to continue.' }), reply(200, { ok: true })],
      'GET /api/me/step-up': reply(200, { methods: ['totp'], destinations: [] }),
      'POST /api/me/step-up/code': reply(200, { ok: true }),
    },
  });
  await visit(page, 'audit');
  const rows = page.document.querySelectorAll('#audit-list tbody tr');
  assert.deepEqual(rows.map((r) => r.dataset.seq), ['57', '56', '55']);
  assert.deepEqual(rows.map((r) => !!r.querySelector('[data-write="audit.revert"]')), [true, false, false], 'from revertible, never from undo_kind (#55 has one but is already reverted)');
  assert.match(rows[2].textContent, /Reverted by #120/);
  await page.click(rows[0].querySelector('[data-write="audit.revert"]'));
  assert.equal(page.document.querySelector('dialog.modal .modal-title').textContent, 'Revert entry #57?');
  await page.click(dialogBtn(page, 'btn-danger'));
  page.fill('stepup-code', '123456');
  page.document.querySelector('dialog.modal-stepup form').requestSubmit();
  await page.drain();
  assert.equal(page.requests('/api/admin/audit/101/revert', 'POST').length, 2, 'one retry after step-up');
  assert.equal(page.requests('/api/admin/audit', 'GET').length, 2, 'reloaded');
  page.dispose();
});

test('audit: a refused revert says why, verbatim', async () => {
  const page = await open('super_admin', { fetch: { 'POST /api/admin/audit/101/revert': reply(409, { error: 'They have enrolled a new factor since; reverting would replace it.', code: 'guard' }) } });
  await visit(page, 'audit');
  await page.click(page.document.querySelector('#audit-list [data-write="audit.revert"]'));
  await page.click(dialogBtn(page, 'btn-danger'));
  assert.deepEqual(texts(page.document, '#audit-result .banner-body p'), ['Not reverted', 'They have enrolled a new factor since; reverting would replace it.']);
  page.dispose();
});

test('audit: Verify integrity → "Intact across N entries", or the exact broken entry', async () => {
  const ok = await open('auditor', { fetch: { 'POST /api/admin/audit/verify': reply(200, { ok: true, checked: 1234, head_seq: 1234, broken_at: null }) } });
  await visit(ok, 'audit');
  await ok.click('audit-verify');
  assert.deepEqual(texts(ok.document, '#verify-result .banner-body p'), ['The audit log is intact', 'Intact across 1,234 entries.']);
  assert.ok(ok.$('verify-result').querySelector('.banner-ok'));
  ok.dispose();
  const bad = await open('auditor', { fetch: { 'POST /api/admin/audit/verify': reply(200, { ok: false, checked: 56, head_seq: 90, broken_at: { seq: 57, id: 101, reason: 'hash_mismatch' } }) } });
  await visit(bad, 'audit');
  await bad.click('audit-verify');
  assert.deepEqual(texts(bad.document, '#verify-result .banner-body p'), ['The audit log has been tampered with', 'Broken at entry #57 — its contents don’t match its hash — it was edited. 56 entries before it check out.']);
  assert.ok(bad.$('verify-result').querySelector('.banner-danger'));
  bad.dispose();
});

test('audit: filters and paging send the contract’s query parameters', async () => {
  const page = await open('auditor');
  await visit(page, 'audit');
  await page.click('audit-more');
  assert.equal(page.requests('/api/admin/audit')[1].url, '/api/admin/audit?before_seq=55&limit=50');
  page.fill('audit-action', 'network.');
  page.fill('audit-actor', 'x1');
  await page.submit('audit-filters');
  assert.equal(page.requests('/api/admin/audit').length, 2, 'a junk actor is caught first');
  page.fill('audit-actor', '1');
  page.$('audit-outcome').value = 'denied';
  await page.submit('audit-filters');
  assert.equal(page.requests('/api/admin/audit')[2].url, '/api/admin/audit?action=network.&outcome=denied&actor=1&limit=50');
  page.dispose();
});

// ------------------------------------------------------------ settings ----

test('settings: a blank number is refused in the browser; an explicit 0 is sent as 0', async () => {
  const page = await open('super_admin', {
    fetch: {
      'PUT /api/admin/settings': reply(200, {
        ok: true,
        applied: ['streak_reentry_grace_hours'],
        warnings: ['3 active people have no approved device and no allowlisted address — they will see the pending page at their next sign-in.'],
        notices: ['Your current device was approved, so you keep access.'],
      }),
    },
  });
  await visit(page, 'settings');
  assert.equal(page.text('rule-preview'), 'Sign in at least once every 30 hours to keep your streak; Shabbos and Yom Tov (diaspora) don’t count against you — each one adds a day to the window, up to 4 days, and after a protected stretch you get 12 hours to sign back in.');
  page.fill('set-streak_reentry_grace_hours', '   ');
  assert.equal(page.text('rule-preview'), 'Fix the highlighted numbers to see the rule.');
  await page.submit('settings-form');
  assert.equal(page.requests('/api/admin/settings', 'PUT').length, 0, 'blank never reaches the server');
  assert.equal(page.text('set-streak_reentry_grace_hours-error'), 'Enter a whole number from 0 to 24.');
  assert.match(page.text('settings-result'), /Nothing was saved/);
  page.fill('set-streak_reentry_grace_hours', '0');
  assert.match(page.text('rule-preview'), /up to 4 days\.$/, 'no grace clause at 0');
  await page.submit('settings-form');
  const put = page.requests('/api/admin/settings', 'PUT');
  assert.equal(put.length, 1);
  assert.deepEqual(put[0].body, { changes: { streak_reentry_grace_hours: 0 } }, 'only the change, and 0 is a number');
  assert.match(page.text('settings-result'), /3 active people have no approved device/);
  assert.match(page.text('settings-result'), /Your current device was approved, so you keep access\./);
  page.dispose();
});

test('settings: weekly days, Hebrew holidays and extra dates feed the rule sentence and the request', async () => {
  const page = await open('super_admin', { fetch: { 'PUT /api/admin/settings': reply(200, { ok: true, applied: [], warnings: [], notices: [] }) } });
  await visit(page, 'settings');
  page.$('set-streak_weekly_days-0').click();
  page.$('set-streak_hebrew_holidays').click();
  await page.drain();
  assert.match(page.text('rule-preview'), /; Sundays and Saturdays don’t count against you/);
  page.fill('set-streak_extra_dates-date', '2026-12-25');
  page.fill('set-streak_extra_dates-label', 'Office closed');
  await page.click(byText(page.$('set-streak_extra_dates'), 'button', 'Add date'));
  assert.match(page.text('rule-preview'), /Sundays, Saturdays and 1 extra date don’t count/);
  page.fill('set-streak_window_hours', 'abc');
  await page.submit('settings-form');
  assert.equal(page.requests('/api/admin/settings', 'PUT').length, 0);
  assert.equal(page.text('set-streak_window_hours-error'), 'Streak window must be a whole number.');
  page.fill('set-streak_window_hours', '30');
  await page.submit('settings-form');
  assert.deepEqual(page.requests('/api/admin/settings', 'PUT')[0].body.changes, {
    streak_weekly_days: [0, 6],
    streak_hebrew_holidays: false,
    streak_extra_dates: [{ date: '2026-12-25', label: 'Office closed' }],
  });
  page.dispose();
});

test('security: a self-lockout refusal (409) is shown verbatim and nothing else changes', async () => {
  const words = 'You are connecting from GB, which this change would refuse. Add your address to the allowlist first.';
  const page = await open('super_admin', { fetch: { 'PUT /api/admin/settings': reply(409, { code: 'self_lockout', error: words }) } });
  await visit(page, 'security');
  page.fill('set-country_deny', 'gb, kp');
  await page.submit('security-form');
  assert.deepEqual(page.requests('/api/admin/settings', 'PUT')[0].body, { changes: { country_deny: ['GB', 'KP'] } });
  assert.deepEqual(texts(page.document, '#security-result .banner-body p'), ['Refused — this would lock you out', words]);
  assert.equal(page.$('security-result').querySelector('.banner-danger p:not(.banner-title)').textContent, words, 'verbatim');
  page.fill('set-country_deny', 'GBR');
  await page.submit('security-form');
  assert.equal(page.requests('/api/admin/settings', 'PUT').length, 1);
  assert.equal(page.text('set-country_deny-error'), '“GBR” isn’t a two-letter country code.');
  page.dispose();
});

test('security: every access mode is described', async () => {
  const page = await open('super_admin');
  await visit(page, 'security');
  const modes = page.document.querySelectorAll('#set-access_mode .mode-option');
  assert.equal(modes.length, 6);
  assert.match(modes.find((m) => m.querySelector('input').value === 'lockdown').textContent, /Super Admin on an approved device from an allowlisted network/);
  assert.ok(page.document.querySelector('#set-access_mode input[value=allowlist]').checked, 'the current mode is selected');
  page.dispose();
});

// ---------------------------------------------------------------- gate ----

test('gate: opening needs an explicit choice; hours are validated, never defaulted', async () => {
  const page = await open('super_admin', {
    fetch: {
      'POST /api/admin/gate/open': reply(200, { ok: true }),
      'GET /api/admin/gate': [reply(200, { open: false, until: null, forever: false }), reply(200, { open: true, until: iso(6 * HOUR), forever: false })],
    },
  });
  await visit(page, 'security');
  await page.submit('gate-form');
  assert.equal(page.text('gate-error'), 'Choose how long: a number of hours, or until you close it.');
  page.check('gate-choice-hours');
  await page.submit('gate-form');
  assert.equal(page.text('gate-error'), 'Enter how many hours: a whole number from 1 to 168.', 'blank is not a duration');
  page.fill('gate-hours', '0');
  await page.submit('gate-form');
  assert.equal(page.text('gate-error'), 'Use a number from 1 to 168.');
  page.fill('gate-hours', '169');
  await page.submit('gate-form');
  assert.equal(page.requests('/api/admin/gate/open').length, 0);
  page.fill('gate-hours', '6');
  await page.submit('gate-form');
  assert.match(page.document.querySelector('dialog.modal').textContent, /for the next 6 hours/);
  await page.click(dialogBtn(page, 'btn-danger'));
  assert.deepEqual(page.requests('/api/admin/gate/open')[0].body, { hours: 6 });
  assert.match(page.text('gate-state'), /^Open to the internet until .* — closes in 5h 59m/);
  assert.ok(page.$('gate-close'), 'and it can be closed');
  page.dispose();
});

test('gate: "until I close it" sends { forever: true }; cancelling the confirmation sends nothing', async () => {
  const page = await open('super_admin', { fetch: { 'POST /api/admin/gate/open': reply(200, { ok: true }) } });
  await visit(page, 'security');
  page.check('gate-choice-forever');
  await page.submit('gate-form');
  await page.click(dialogBtn(page, 'btn-secondary'));
  assert.equal(page.requests('/api/admin/gate/open').length, 0);
  await page.submit('gate-form');
  assert.match(page.document.querySelector('dialog.modal').textContent, /until you close it/);
  await page.click(dialogBtn(page, 'btn-danger'));
  assert.deepEqual(page.requests('/api/admin/gate/open')[0].body, { forever: true });
  page.dispose();
});

// ------------------------------------------------------------- network ----

test('network: "you are here", tier help, and a 409 self_lockout shown verbatim', async () => {
  const words = 'That would leave no live allowlist entry covering your address, 81.2.69.10. Add your new address first.';
  const page = await open('super_admin', { fetch: { 'DELETE /api/admin/network/allow/1': reply(409, { code: 'self_lockout', error: words }) } });
  await visit(page, 'network');
  assert.deepEqual(texts(page.document, '#you-are-here p'), ['You are here: 81.2.69.10 (GB)', 'Covered by 81.2.69.0/24 “Office” (tier 2).']);
  assert.match(page.text('allow-form'), /Tier 1, core admin network: nobody else is on it — a second factor every 7 days/);
  await page.click(page.document.querySelector('[aria-label="Remove 81.2.69.0/24"]'));
  assert.match(page.document.querySelector('dialog.modal').textContent, /would remove your cover/, 'warned before sending');
  await page.click(dialogBtn(page, 'btn-danger'));
  assert.equal(page.requests('/api/admin/network/allow/1', 'DELETE').length, 1);
  const msg = page.$('network-result').querySelector('.banner-danger p:not(.banner-title)');
  assert.equal(msg.textContent, words, 'verbatim');
  page.dispose();
});

test('network: removing an entry that is not your cover gets the ordinary warning; adding validates first', async () => {
  const page = await open('super_admin', { fetch: { 'DELETE /api/admin/network/allow/2': reply(200, { ok: true }), 'POST /api/admin/network/allow': reply(200, { id: 3 }) } });
  await visit(page, 'network');
  await page.click(page.document.querySelector('[aria-label="Remove 91.198.174.0/24"]'));
  assert.doesNotMatch(page.document.querySelector('dialog.modal').textContent, /your cover/);
  await page.click(dialogBtn(page, 'btn-danger'));
  assert.equal(page.requests('/api/admin/network/allow/2', 'DELETE').length, 1);
  await page.submit('allow-form');
  assert.equal(page.text('allow-cidr-error'), 'Enter an address or range.');
  page.fill('allow-cidr', '185.15.56.0/24');
  page.$('allow-tier').value = '4';
  page.fill('allow-expires', '0');
  await page.submit('allow-form');
  assert.equal(page.text('allow-expires-error'), 'Use a number from 1 to 8760.');
  page.fill('allow-expires', '');
  await page.submit('allow-form');
  assert.deepEqual(page.requests('/api/admin/network/allow', 'POST')[0].body, { cidr: '185.15.56.0/24', tier: 4 }, 'no expiry sent: the server gives tier 4 its 24 hours');
  page.dispose();
});

// -------------------------------------------------------------- people ----

test('people: the detail shows each permission’s source; grants and denies are sent together with the role', async () => {
  const page = await open('super_admin', { fetch: { 'POST /api/admin/users/2/role': reply(200, { ok: true }) } });
  await visit(page, 'people');
  assert.deepEqual(firstCells(page, '#people-list'), ['Jane Doe', 'Sam Levi']);
  await page.click(byText(page.document, '#people-list button', 'Jane Doe'));
  const row = (k) => page.document.querySelector(`#person-detail tr[data-perm="${k}"]`);
  assert.match(row('directory.view').textContent, /Yes/);
  assert.equal(row('directory.view').querySelector('.source-chip').textContent, 'Granted to them');
  assert.ok(row('directory.view').querySelector('.source-flag'));
  assert.equal(row('team.view').querySelector('.source-chip').textContent, 'Denied for them');
  assert.ok(row('users.reset_password').querySelector('input[data-kind=grant]').disabled, 'reserved: can’t be granted');
  const temp = byText(page.document, '#person-detail .item-row', 'Auditor');
  assert.match(temp.querySelector('.item-sub').textContent, /^Until /, 'temporary role with expiry');
  row('users.view').querySelector('input[data-kind=grant]').click();
  await page.click(byText(page.document, '#person-detail [data-write="users.roles"]', 'Save role and permissions'));
  const body = page.requests('/api/admin/users/2/role')[0].body;
  assert.deepEqual(body, { role_id: 5, perm_grants: ['directory.view', 'users.view'], perm_denies: ['team.view'] });
  page.dispose();
});

test('people: suspend asks first; reset password shows the temporary password once', async () => {
  const page = await open('super_admin', {
    fetch: {
      'POST /api/admin/users/2/status': reply(200, { ok: true }),
      'POST /api/admin/users/2/reset-password': reply(200, { temporary_password: 'pale-otter-lamp-91' }),
    },
  });
  await visit(page, 'people');
  await page.click(byText(page.document, '#people-list button', 'Jane Doe'));
  await page.click(byText(page.document, '#person-detail button', 'Suspend'));
  assert.equal(page.document.querySelector('dialog.modal .modal-title').textContent, 'Suspend Jane Doe?');
  await page.click(dialogBtn(page, 'btn-danger'));
  assert.deepEqual(page.requests('/api/admin/users/2/status')[0].body, { status: 'suspended' });
  await page.click(byText(page.document, '#person-detail button', 'Reset password'));
  await page.click(dialogBtn(page, 'btn-danger'));
  assert.equal(page.text('temp-password'), 'pale-otter-lamp-91');
  await page.click(byText(page.document, 'dialog.modal button', 'I’ve passed it on'));
  assert.ok(!page.document.body.textContent.includes('pale-otter-lamp-91'), 'gone once dismissed');
  page.dispose();
});

test('people: an administrator gets no reserved controls (password reset, code destinations)', async () => {
  const page = await open('admin');
  await visit(page, 'people');
  await page.click(byText(page.document, '#people-list button', 'Jane Doe'));
  assert.equal(byText(page.document, '#person-detail button', 'Reset password'), null);
  assert.ok(byText(page.document, '#person-detail button', 'Reset second factors'), 'users.reset_mfa is grantable');
  assert.ok(!page.document.body.textContent.includes('Where sign-in codes go'));
  assert.equal(page.requests('/api/admin/users/2/destinations').length, 0);
  page.dispose();
});

test('people: a streak adjustment needs a reason, keeps an explicit 0', async () => {
  const page = await open('super_admin', { fetch: { 'POST /api/admin/users/2/streak': reply(200, { ok: true }) } });
  await visit(page, 'people');
  await page.click(byText(page.document, '#people-list button', 'Jane Doe'));
  page.fill('streak-current', '0');
  page.fill('streak-longest', '');
  const form = page.$('streak-current').closest('form');
  await page.submit(form);
  assert.equal(page.text('streak-reason-error'), 'Say why — it goes in the audit log.');
  page.fill('streak-reason', 'Clock fault on Oct 1');
  await page.submit(form);
  assert.deepEqual(page.requests('/api/admin/users/2/streak')[0].body, { current: 0, reason: 'Clock fault on Oct 1' });
  page.dispose();
});

test('invite: creates the account and shows the link to copy', async () => {
  const page = await open('manager', { fetch: { 'POST /api/admin/users': reply(200, { user: { id: 9 }, invitation: { url: 'https://staff.example.com/invite?token=abc', expires_at: iso(7 * 24 * HOUR) } }) } });
  await visit(page, 'invitations');
  await page.click(byText(page.document, '#invitations-body button', 'Invite someone'));
  page.fill('invite-email', 'new@acme.com');
  page.fill('invite-name', 'New Person');
  await page.submit('invite-form');
  assert.deepEqual(page.requests('/api/admin/users', 'POST')[0].body, { email: 'new@acme.com', full_name: 'New Person' }, 'a manager without roles.view leaves the role to the server');
  assert.match(page.document.querySelector('dialog.modal').textContent, /Send this link to New Person yourself/);
  await page.click(byText(page.document, 'dialog.modal button', 'Copy'));
  assert.deepEqual(page.calls.clipboard, ['https://staff.example.com/invite?token=abc']);
  page.dispose();
});

test('requests: approve with a role shows the invitation link; deny confirms', async () => {
  const page = await open('super_admin', {
    fetch: {
      'POST /api/admin/requests/5/approve': reply(200, { user: { id: 10 }, invitation: { url: 'https://staff.example.com/invite?token=xyz', expires_at: iso(HOUR) } }),
      'POST /api/admin/requests/5/deny': reply(200, { ok: true }),
    },
  });
  await visit(page, 'invitations');
  assert.equal(page.document.querySelector('#request-list .item-title').textContent, 'Rae Quest req@acme.com');
  assert.deepEqual(texts(page.document, '#request-list .item-sub'), ['“Starting Monday”', '1 hour ago · 81.2.69.40 · GB · risk 12']);
  await page.click(byText(page.document, '#request-list button', 'Approve'));
  assert.deepEqual(page.requests('/api/admin/requests/5/approve')[0].body, { role_id: 5 }, 'defaults to Employee');
  assert.equal(page.document.querySelector('dialog.modal input').value, 'https://staff.example.com/invite?token=xyz');
  await page.click(byText(page.document, 'dialog.modal button', 'Done'));
  await page.click(byText(page.document, '#request-list button', 'Deny'));
  assert.equal(page.requests('/api/admin/requests/5/deny').length, 0, 'not before confirming');
  await page.click(dialogBtn(page, 'btn-danger'));
  assert.equal(page.requests('/api/admin/requests/5/deny', 'POST').length, 1);
  page.dispose();
});

// ------------------------------------------------------ devices, streaks ----

test('devices: the waiting queue comes first; approve by typing the code the person reads out', async () => {
  const page = await open('super_admin', { fetch: { 'POST /api/admin/devices/dv1/approve': reply(200, { ok: true }) } });
  await visit(page, 'devices');
  const body = page.$('devices-body');
  assert.match(body.querySelector('.card').textContent, /^Waiting for approval \(1\)/);
  assert.match(page.text('pending-devices'), /K7F3-9QX2/);
  page.fill('device-code', 'zzzz-zzzz');
  await page.submit('device-code-form');
  assert.match(page.text('device-code-error'), /^No device waiting for approval shows ZZZZ-ZZZZ/);
  page.fill('device-code', 'AB12CD34');
  await page.submit('device-code-form');
  assert.match(page.text('device-code-error'), /^No device waiting/, 'an approved device is not in the queue');
  page.fill('device-code', ' k7f3 9qx2 ');
  await page.submit('device-code-form');
  assert.equal(page.requests('/api/admin/devices/dv1/approve', 'POST').length, 1);
  assert.equal(page.requests('/api/admin/devices', 'GET').length, 2, 'reloaded');
  page.dispose();
});

test('streaks: sortable by any column, with aria-sort', async () => {
  const page = await open('auditor');
  await visit(page, 'streaks');
  const names = () => firstCells(page, '#streaks-table');
  assert.deepEqual(names(), ['Avi Cohen', 'Jane Doe', 'Sam Levi'], 'current, high to low');
  await page.click(page.document.querySelector('#streaks-table [data-sort=longest]'));
  assert.deepEqual(names(), ['Sam Levi', 'Avi Cohen', 'Jane Doe']);
  assert.equal(page.document.querySelector('#streaks-table [data-sort=longest]').closest('th').getAttribute('aria-sort'), 'descending');
  await page.click(page.document.querySelector('#streaks-table [data-sort=longest]'));
  assert.deepEqual(names(), ['Jane Doe', 'Avi Cohen', 'Sam Levi']);
  await page.click(page.document.querySelector('#streaks-table [data-sort=state]'));
  assert.deepEqual(names(), ['Avi Cohen', 'Jane Doe', 'Sam Levi'], 'at risk first');
  assert.match(page.text('streaks-table'), /At risk/);
  page.dispose();
});

test('visitors: risk chips with the reasons behind them; the visit log filters by decision', async () => {
  const page = await open('auditor');
  await visit(page, 'visitors');
  const chip = page.document.querySelector('#visitors-body .risk-chip');
  assert.equal(chip.textContent, '82');
  assert.ok(chip.classList.contains('badge-danger'), 'at or over the threshold');
  assert.match(page.text('visitors-body'), /The browser says automation software is driving it \(WebDriver\)\.\+60/);
  page.$('visit-decision').value = 'deny';
  page.$('visit-decision').dispatchEvent(new page.window.Event('change'));
  await page.drain();
  assert.equal(page.requests('/api/admin/visits').at(-1).url, '/api/admin/visits?decision=deny');
  page.dispose();
});

test('sessions: your own has no End button; ending another confirms first', async () => {
  const page = await open('super_admin', { fetch: { 'DELETE /api/admin/sessions/bbbbbbbbbbbb': reply(200, { ok: true }) } });
  await visit(page, 'sessions');
  const ends = page.document.querySelectorAll('#sessions-body [data-write="sessions.revoke"]');
  assert.equal(ends.length, 1);
  assert.equal(ends[0].getAttribute('aria-label'), 'End session for Jane Doe');
  await page.click(ends[0]);
  await page.click(dialogBtn(page, 'btn-danger'));
  assert.equal(page.requests('/api/admin/sessions/bbbbbbbbbbbb', 'DELETE').length, 1);
  page.dispose();
});

test('overview: counts become links to their tab', async () => {
  const page = await open('super_admin');
  const tile = page.document.querySelector('#overview-tiles [data-count=devices_pending]');
  assert.match(tile.textContent, /1Devices waiting for approval/);
  await page.click(tile);
  assert.equal(page.$('tab-devices').getAttribute('aria-selected'), 'true');
  assert.equal(page.requests('/api/admin/devices').length, 1);
  page.dispose();
});

test('pure helpers', async () => {
  const page = await open('auditor');
  const m = page.module;
  assert.deepEqual(m.allowedTabs([]), []);
  assert.deepEqual(m.allowedTabs(['*']), ALL_TABS);
  assert.deepEqual(m.allowedTabs(['gate.open']), ['security'], 'the gate alone opens Security (overview needs a console permission)');
  assert.deepEqual(m.verifyText({ ok: true, checked: 1 }), { ok: true, text: 'Intact across 1 entry.' });
  assert.equal(m.verifyText(null).ok, false);
  assert.equal(m.verifyText({ checked: 3, broken_at: null }).ok, false, 'only an explicit ok: true is intact');
  assert.equal(m.verifyText({ ok: false, checked: 0, broken_at: { seq: 1, reason: 'seq_gap' } }).text, 'Broken at entry #1 — a sequence number is missing or out of order there. 0 entries before it check out.');
  page.dispose();
});

await run();
