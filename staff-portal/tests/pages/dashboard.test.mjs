// public/dashboard.html + js/dashboard.js — the streak dashboard (CONTRACTS
// §7.4 status, §8.4 Me, §10; SPEC §10.17). Canned /api/me/streak payloads for
// every state; the 84-cell history strip; coming up; rules; leaderboard;
// the security summary and enrolment prompt; recent sign-ins.

import { test, assert, run } from '../helpers/t.js';
import { loadPage, reply, texts } from '../helpers/dom.js';

const ORIGIN = 'https://staff.example.com';
const TODAY = '2026-10-02'; // a Friday
const DAY = 86400000;

function dayAt(offset) {
  const [y, m, d] = TODAY.split('-').map(Number);
  return new Date(Date.UTC(y, m - 1, d) + offset * DAY).toISOString().slice(0, 10);
}

function weekday(day) {
  const [y, m, d] = day.split('-').map(Number);
  return new Date(Date.UTC(y, m - 1, d)).getUTCDay();
}

const MISSED = new Set(['2026-09-30', '2026-08-05']);

// 84 days ending today, oldest first, as streak.streakHistory returns them:
// every Saturday protected (Shabbos), every other day counted except two.
function makeHistory() {
  const out = [];
  for (let i = 83; i >= 0; i--) {
    const day = dayAt(-i);
    const sat = weekday(day) === 6;
    out.push({ day, counted: !sat && !MISSED.has(day), protected: sat, names: sat ? ['Shabbos'] : [], today: i === 0, future: false });
  }
  return out;
}

const UPCOMING = [
  { day: '2026-10-03', names: ['Shemini Atzeres', 'Shabbos'] },
  { day: '2026-10-04', names: ['Simchas Torah'] },
  { day: '2026-10-10', names: ['Shabbos'] },
  { day: '2026-10-17', names: ['Shabbos'] },
];

const RULES = { window_hours: 30, reentry_grace_hours: 12, max_leeway_days: 4, calendar: 'Shabbos and Yom Tov (diaspora)' };

const BASE = {
  state: 'active',
  current: 12,
  stored_current: 12,
  longest: 30,
  total_days: 140,
  counted_today: true,
  last_at: '2026-10-02T13:00:00.000Z',
  last_day: TODAY,
  started_day: '2026-09-21',
  deadline: '2026-10-03T19:00:00.000Z',
  deadline_local: 'Sat, Oct 3, 3:00 PM',
  hours_left: 26.5,
  protected_today: null,
  timezone: 'America/New_York',
};

const STATUS = {
  none: { ...BASE, state: 'none', current: 0, stored_current: 0, longest: 0, total_days: 0, counted_today: false, last_at: null, last_day: null, started_day: null, deadline: null, deadline_local: null, hours_left: null },
  active: BASE,
  at_risk: { ...BASE, state: 'at_risk', counted_today: false, last_day: '2026-10-01', last_at: '2026-10-01T07:30:00.000Z', deadline: '2026-10-02T13:30:00.000Z', deadline_local: 'Fri, Oct 2, 9:30 AM', hours_left: 4.5 },
  paused: { ...BASE, state: 'paused', counted_today: false, last_day: '2026-10-01', protected_today: { names: ['Shabbos'] }, hours_left: 40 },
  lapsed: { ...BASE, state: 'lapsed', current: 0, stored_current: 12, counted_today: false, last_day: '2026-09-28', deadline: '2026-09-29T19:00:00.000Z', deadline_local: 'Tue, Sep 29, 3:00 PM', hours_left: null },
  held: { ...BASE, state: 'held', counted_today: false, deadline: null, deadline_local: null, hours_left: null },
};

const ME = {
  user: { id: 7, email: 'jane@acme.com', full_name: 'Jane Doe', role: { id: 5, key: 'employee', name: 'Employee', rank: 20 }, status: 'active' },
  permissions: [],
  sources: {},
  rank: 20,
  is_super: false,
  pinned: null,
  enroll_prompt: false,
  step_up_fresh: false,
  factors: { totp: true, totpUnreadable: false, passkeys: 1, backup: 8, destinations: 1 },
  passkeys: [{ id: 'pk1', label: 'MacBook Touch ID', created_at: '2026-09-01T10:00:00.000Z', last_used_at: '2026-10-02T13:00:00.000Z' }],
  org_name: 'Acme Inc.',
  timezone: 'America/New_York',
  privacy_notice: null,
};

const ACTIVITY = {
  entries: [
    { id: 9, at: '2026-10-02T13:00:00.000Z', action: 'login.success', outcome: 'success', detail: 'Signed in with passkey', ip: '81.2.69.10' },
    { id: 8, at: '2026-10-02T12:58:00.000Z', action: 'setting.change', outcome: 'success', detail: 'Changed timezone', ip: '81.2.69.10' },
    { id: 7, at: '2026-10-01T09:00:00.000Z', action: 'login.fail', outcome: 'failure', detail: null, ip: '91.198.174.2' },
  ],
};

function streak(status, extra = {}) {
  return { enabled: true, status, history: makeHistory(), upcoming: UPCOMING, rules: RULES, leaderboard: null, ...extra };
}

async function open({ me = ME, streakBody = streak(STATUS.active), streakReply, activity = ACTIVITY, fetch = {} } = {}) {
  return loadPage('dashboard.html', {
    url: `${ORIGIN}/`,
    fetch: {
      'GET /api/me': reply(200, me),
      'GET /api/me/streak': streakReply || reply(200, streakBody),
      'GET /api/me/activity': reply(200, activity),
      'POST /api/auth/logout': reply(200, { ok: true }),
      ...fetch,
    },
  });
}

const cls = (page, id) => page.$(id).getAttribute('class').split(/\s+/);

// ---------------------------------------------------------------- hero ----

const EXPECT = {
  none: { words: 'No streak yet — your next sign-in starts one', out: true, meter: false, count: '0' },
  active: { words: 'Keep it going — sign in by Sat, Oct 3, 3:00 PM', out: false, meter: true, count: '12' },
  at_risk: { words: 'At risk — 4.5 hours left', out: false, meter: true, count: '12' },
  paused: { words: 'Paused for Shabbos — the clock isn’t running', out: false, meter: true, count: '12' },
  lapsed: { words: 'Lapsed — your next sign-in starts a new streak', out: true, meter: false, count: '0' },
  held: { words: 'Held — your record is safe while the clock is checked', out: false, meter: false, count: '12' },
};

for (const [state, want] of Object.entries(EXPECT)) {
  test(`hero, state ${state}: the words, the classes, the flame, the meter, the badge`, async () => {
    const page = await open({ streakBody: streak(STATUS[state]) });
    assert.ok(cls(page, 'streak').includes(`state-${state}`), `hero has state-${state}`);
    assert.ok(!cls(page, 'streak').includes('state-loading'), 'loading class removed');
    assert.ok(cls(page, 'streak-state').includes(`state-${state}`));
    assert.equal(page.text('streak-state'), want.words);
    assert.equal(page.text('streak-count'), want.count);
    assert.equal(page.$('hero-flame').classList.contains('is-out'), want.out, 'flame dims when lapsed/none');
    assert.equal(page.visible('window-row'), want.meter, 'meter for time left');
    assert.equal(page.visible('counted-badge'), STATUS[state].counted_today === true, 'badge only when counted today');
    assert.equal(page.$('streak').getAttribute('aria-busy'), null);
    assert.deepEqual(page.calls.unmatched, []);
    assert.deepEqual(page.calls.pageErrors, []);
    page.dispose();
  });
}

test('hero: the meter measures the real window and names the time zone', async () => {
  const page = await open({ streakBody: streak(STATUS.at_risk) });
  const m = page.$('window-meter');
  assert.equal(m.getAttribute('max'), '30', 'deadline − last sign-in');
  assert.equal(m.getAttribute('value'), '4.5');
  assert.equal(m.getAttribute('low'), '6', 'below 6 h is the at-risk band');
  assert.equal(page.text('window-caption'), '4h 30m left of a 30-hour window');
  assert.equal(page.text('streak-zone'), 'Times are New York time.');
  assert.equal(page.text('streak-detail'), 'Sign in by Fri, Oct 2, 9:30 AM to keep your 12 days.');
  page.dispose();
});

test('hero: active shows longest, total and the start of the run; lapsed keeps the longest', async () => {
  const page = await open();
  assert.equal(page.text('streak-longest'), '30 days');
  assert.equal(page.text('streak-total'), '140');
  assert.equal(page.text('streak-since'), 'Mon Sep 21, 2026');
  assert.equal(page.text('counted-badge'), 'Counted today');
  page.dispose();
  const lapsed = await open({ streakBody: streak(STATUS.lapsed) });
  assert.equal(lapsed.text('streak-longest'), '30 days');
  assert.ok(!lapsed.visible('since-stat'), 'no "since" for a lapsed run');
  assert.match(lapsed.text('streak-detail'), /The window closed Tue, Sep 29, 3:00 PM\. Your longest run, 30 days, is safe\./);
  lapsed.dispose();
});

test('hero: paused names every festival, and a nameless protected day still reads well', async () => {
  const page = await open({ streakBody: streak({ ...STATUS.paused, protected_today: { names: ['Shemini Atzeres', 'Shabbos'] } }) });
  assert.equal(page.text('streak-state'), 'Paused for Shemini Atzeres and Shabbos — the clock isn’t running');
  page.dispose();
  const bare = await open({ streakBody: streak({ ...STATUS.paused, protected_today: { names: [] } }) });
  assert.equal(bare.text('streak-state'), 'Paused — the clock isn’t running');
  bare.dispose();
});

test('streaks disabled: the hero says so and the rest of the dashboard still works', async () => {
  const page = await open({ streakBody: { enabled: false, status: null, history: [], upcoming: [], rules: RULES, leaderboard: null } });
  assert.ok(cls(page, 'streak').includes('state-off'));
  assert.equal(page.text('streak-state'), 'Streaks are turned off');
  assert.ok(page.$('hero-flame').classList.contains('is-out'));
  assert.ok(!page.visible('window-row'));
  for (const id of ['history-card', 'upcoming-card', 'rules-card', 'leaderboard-card']) assert.ok(!page.visible(id), `${id} hidden`);
  assert.ok(page.visible('security-card'));
  assert.equal(texts(page.document, '#signins li').length, 2, 'recent sign-ins still render');
  assert.equal(page.document.querySelector('.topbar-streak'), null, 'no streak chip when streaks are off');
  page.dispose();
});

test('a streak that will not load: an explanation in the hero, everything else works', async () => {
  const page = await open({ streakReply: reply(500, { error: 'Something went wrong.' }) });
  assert.ok(cls(page, 'streak').includes('state-error'));
  assert.equal(page.text('streak-state'), 'Your streak couldn’t be loaded');
  assert.match(page.text('streak-detail'), /Something went wrong\. The rest of your dashboard still works\./);
  assert.ok(!page.visible('history-card'));
  assert.ok(page.visible('security-card'));
  assert.equal(page.document.querySelectorAll('#quick-links a').length, 4);
  page.dispose();
});

test('/api/me failing shows a page-level error, not a blank page', async () => {
  const page = await open({ me: null, fetch: { 'GET /api/me': reply(503, { error: 'Down for maintenance.' }) } });
  assert.ok(page.visible('load-error'));
  assert.equal(page.text('load-error'), 'Down for maintenance.');
  assert.ok(cls(page, 'streak').includes('state-error'));
  page.dispose();
});

// --------------------------------------------------------------- strip ----

test('history strip: 84 cells, Sunday→Saturday weeks, oldest first, today outlined, the rest of this week to come', async () => {
  const page = await open();
  const cells = page.document.querySelectorAll('#strip .strip-day');
  assert.equal(cells.length, 84);
  assert.equal(cells[0].dataset.day, '2026-07-12', 'first column starts on a Sunday');
  assert.equal(weekday(cells[0].dataset.day), 0);
  assert.equal(cells[83].dataset.day, '2026-10-03', 'last column ends on Saturday');
  for (let i = 1; i < 84; i++) assert.ok(cells[i].dataset.day > cells[i - 1].dataset.day, 'chronological, column by column');
  const today = cells.filter((c) => c.classList.contains('is-today'));
  assert.equal(today.length, 1);
  assert.equal(today[0].dataset.day, TODAY);
  assert.ok(today[0].classList.contains('is-counted'));
  assert.equal(today[0].getAttribute('aria-label'), 'Fri Oct 2 (today): signed in');
  const future = cells.filter((c) => c.classList.contains('is-future'));
  assert.deepEqual(future.map((c) => c.dataset.day), ['2026-10-03']);
  assert.equal(future[0].getAttribute('aria-label'), 'Sat Oct 3: still to come');
  assert.deepEqual([...future[0].classList], ['strip-day', 'is-future'], 'a future day is empty');
  page.dispose();
});

test('history strip: protected, missed and counted cells carry the right classes, labels and glyph', async () => {
  const page = await open();
  const cell = (d) => page.document.querySelector(`#strip [data-day="${d}"]`);
  const sat = cell('2026-09-26');
  assert.ok(sat.classList.contains('is-protected'));
  assert.ok(!sat.classList.contains('is-missed'));
  assert.equal(sat.getAttribute('aria-label'), 'Sat Sep 26: protected (Shabbos)');
  assert.equal(sat.getAttribute('title'), 'Sat Sep 26: protected (Shabbos)', 'names in the tooltip');
  assert.equal(sat.getAttribute('role'), 'img');
  assert.ok(sat.querySelector('svg.strip-glyph'), 'a small moon glyph');
  const missed = cell('2026-09-30');
  assert.ok(missed.classList.contains('is-missed'));
  assert.equal(missed.getAttribute('aria-label'), 'Wed Sep 30: missed');
  assert.equal(missed.querySelector('svg'), null);
  // The flame scale: a long run is hot, a run restarted after a miss is warm.
  assert.ok(cell('2026-09-29').classList.contains('lvl-4'), '7+ weeks of signing in');
  assert.ok(cell('2026-10-01').classList.contains('lvl-1'), 'first day after the miss');
  assert.ok(cell('2026-08-06').classList.contains('lvl-1'));
  assert.ok(cell('2026-08-10').classList.contains('lvl-2'), 'Shabbos bridges the run: 6th, 7th, (8th), 9th, 10th');
  assert.equal(cell('2026-08-14').getAttribute('aria-label'), 'Fri Aug 14: signed in');
  page.dispose();
});

test('history strip: a text alternative — "Signed in on N of the last M open days"', async () => {
  const page = await open();
  assert.equal(page.text('strip-summary'), 'Signed in on 70 of the last 72 open days. 11 protected days didn’t count against you.');
  assert.equal(page.$('strip').getAttribute('aria-describedby'), 'strip-summary');
  assert.deepEqual(texts(page.document, '#strip-months span').filter(Boolean), ['Jul', 'Aug', 'Sep'], 'months labelled where they change');
  assert.equal(page.document.querySelectorAll('#strip-months span').length, 12, 'one slot per column');
  page.dispose();
});

test('history strip: today not yet counted is "not counted yet", not missed; protected today is protected', async () => {
  const h1 = makeHistory();
  h1[83] = { ...h1[83], counted: false };
  const page = await open({ streakBody: streak(STATUS.at_risk, { history: h1 }) });
  const t = page.document.querySelector(`#strip [data-day="${TODAY}"]`);
  assert.deepEqual([...t.classList], ['strip-day', 'is-today']);
  assert.equal(t.getAttribute('aria-label'), 'Fri Oct 2 (today): not counted yet');
  assert.equal(page.text('strip-summary'), 'Signed in on 69 of the last 71 open days. 11 protected days didn’t count against you.', 'an open today is not held against you');
  page.dispose();
  const h2 = makeHistory();
  h2[83] = { ...h2[83], counted: false, protected: true, names: ['Hoshana Rabbah'] };
  const p2 = await open({ streakBody: streak(STATUS.paused, { history: h2 }) });
  assert.equal(p2.document.querySelector(`#strip [data-day="${TODAY}"]`).getAttribute('aria-label'), 'Fri Oct 2 (today): protected (Hoshana Rabbah)');
  p2.dispose();
});

test('history strip: junk history does not break the page', async () => {
  const page = await open({ streakBody: streak(STATUS.active, { history: [null, 7, { day: 'nope' }, { day: '2026-02-30' }] }) });
  assert.equal(page.document.querySelectorAll('#strip .strip-day').length, 0);
  assert.equal(page.text('strip-summary'), 'No history yet — your first sign-in starts it.');
  assert.deepEqual(page.calls.pageErrors, []);
  page.dispose();
});

// ------------------------------------------------- upcoming, rules, board ----

test('coming up: consecutive protected days become one run with every name', async () => {
  const page = await open();
  assert.deepEqual(texts(page.document, '#upcoming li'), [
    'Sat–Sun Oct 3–4 · Shemini Atzeres, Shabbos, Simchas Torah — the clock pauses',
    'Sat Oct 10 · Shabbos — the clock pauses',
    'Sat Oct 17 · Shabbos — the clock pauses',
  ]);
  assert.ok(!page.visible('upcoming-empty'));
  const m = page.module;
  assert.equal(m.runLabel(m.groupRuns([{ day: '2026-10-31', names: [] }, { day: '2026-11-01', names: [] }])[0]), 'Sat Oct 31–Sun Nov 1', 'across a month boundary');
  assert.equal(m.groupRuns([{ day: '2026-10-02', names: ['A'] }, { day: '2026-10-02', names: ['A'] }]).length, 1, 'a duplicate day is not a second run');
  page.dispose();
  const none = await open({ streakBody: streak(STATUS.active, { upcoming: [] }) });
  assert.ok(none.visible('upcoming-empty'));
  none.dispose();
});

test('the rules in one plain sentence, from the configuration', async () => {
  const page = await open();
  assert.equal(page.text('rules'), 'Sign in at least once every 30 hours to keep your streak; Shabbos and Yom Tov (diaspora) don’t count against you — each one adds a day to the window, up to 4 days, and after a protected stretch you get 12 hours to sign back in.');
  page.dispose();
  const plain = await open({ streakBody: streak(STATUS.active, { rules: { window_hours: 48, reentry_grace_hours: 0, max_leeway_days: 0, calendar: 'No protected days' } }) });
  assert.equal(plain.text('rules'), 'Sign in at least once every 48 hours to keep your streak.');
  plain.dispose();
});

test('leaderboard: shown when the setting allows, the viewer highlighted; hidden when null', async () => {
  const board = [
    { user_id: 3, full_name: 'Sam Levi', current: 40, longest: 41 },
    { user_id: 7, full_name: 'Jane Doe', current: 12, longest: 30 },
    { user_id: 9, full_name: '', current: 3, longest: 3 },
  ];
  const page = await open({ streakBody: streak(STATUS.active, { leaderboard: board }) });
  assert.ok(page.visible('leaderboard-card'));
  const rows = page.document.querySelectorAll('#leaderboard li');
  assert.equal(rows.length, 3);
  assert.deepEqual(rows.map((r) => r.classList.contains('is-me')), [false, true, false]);
  assert.equal(rows[1].querySelector('.sr-only').textContent, '2. Jane Doe (you): 12 days, longest 30 days');
  assert.equal(rows[0].querySelector('.rank').textContent, '1');
  assert.equal(rows[0].querySelector('.lb-count').textContent, '40');
  assert.equal(rows[2].querySelector('.lb-name').textContent, 'A colleague');
  page.dispose();
  const hidden = await open();
  assert.ok(!hidden.visible('leaderboard-card'), 'leaderboard: null → no card');
  hidden.dispose();
});

// -------------------------------------------------- security, nav, misc ----

test('security: no strong factor → the enrolment banner links to /account#security', async () => {
  const page = await open({ me: { ...ME, factors: { totp: false, totpUnreadable: false, passkeys: 0, backup: 0, destinations: 1 } } });
  assert.ok(page.visible('enroll-banner'));
  assert.equal(page.$('enroll-link').getAttribute('href'), '/account#security');
  assert.equal(page.text('security-summary'), 'Password only — anyone with your password can sign in.');
  page.dispose();
  const ok = await open();
  assert.ok(!ok.visible('enroll-banner'));
  assert.deepEqual(texts(ok.document, '#factor-list .badge'), ['1 passkey', 'On', '8 left', '1 destination']);
  ok.dispose();
  const prompted = await open({ me: { ...ME, enroll_prompt: true } });
  assert.ok(prompted.visible('enroll-banner'), 'the server’s enroll_prompt flag is honoured too');
  prompted.dispose();
});

test('top bar: Admin link only for an admin-console permission; streak chip shows the count', async () => {
  const page = await open();
  const hrefs = page.document.querySelectorAll('.topnav-link').map((a) => a.getAttribute('href'));
  assert.deepEqual(hrefs, ['/', '/account']);
  assert.equal(page.document.querySelector('.topbar-streak').getAttribute('aria-label'), 'Streak: 12 days');
  assert.equal(page.document.querySelector('.topnav-link[aria-current=page]').textContent, 'Dashboard');
  assert.equal(page.document.title, 'Dashboard · Acme Inc.');
  assert.ok(!page.document.querySelectorAll('#quick-links a').some((a) => a.getAttribute('href') === '/admin'));
  page.dispose();
  const auditor = await open({ me: { ...ME, permissions: ['audit.view', 'audit.verify'] } });
  assert.deepEqual(auditor.document.querySelectorAll('.topnav-link').map((a) => a.getAttribute('href')), ['/', '/account', '/admin']);
  assert.ok(auditor.document.querySelectorAll('#quick-links a').some((a) => a.getAttribute('href') === '/admin'));
  auditor.dispose();
  const lapsed = await open({ streakBody: streak(STATUS.lapsed) });
  assert.equal(lapsed.document.querySelector('.topbar-streak').getAttribute('aria-label'), 'Streak: 0 days', 'the chip shows what the hero shows');
  lapsed.dispose();
});

test('a pinned session is sent to the account page and loads nothing else', async () => {
  const page = await open({ me: { ...ME, pinned: 'mfa_enroll' } });
  assert.deepEqual(page.calls.nav, [{ type: 'replace', url: '/account?pin=mfa_enroll' }]);
  assert.equal(page.requests('/api/me/streak').length, 0);
  page.dispose();
});

test('recent sign-ins: only sign-ins, newest first, failures marked', async () => {
  const page = await open();
  const rows = page.document.querySelectorAll('#signins li');
  assert.equal(rows.length, 2, 'the settings change is not a sign-in');
  assert.match(rows[0].textContent, /^Signed in with passkey/);
  assert.match(rows[0].textContent, /81\.2\.69\.10/);
  assert.ok(rows[0].querySelector('.dot-ok'));
  assert.match(rows[1].textContent, /^Failed sign-in attempt/);
  assert.ok(rows[1].querySelector('.dot-danger'));
  assert.equal(rows[0].querySelector('time').getAttribute('datetime'), '2026-10-02T13:00:00.000Z');
  page.dispose();
  const failing = await open({ fetch: { 'GET /api/me/activity': reply(500, { error: 'Nope.' }) } });
  assert.ok(failing.visible('signins-error'));
  assert.equal(failing.text('signins-error'), 'Nope.');
  failing.dispose();
});

test('sign out from the top bar posts logout and goes to the login page', async () => {
  const page = await open();
  await page.click(page.document.querySelector('button[aria-label="Sign out"]'));
  assert.equal(page.requests('/api/auth/logout', 'POST').length, 1);
  assert.deepEqual(page.calls.nav, [{ type: 'replace', url: '/login' }]);
  page.dispose();
});

test('pure helpers survive junk', async () => {
  const page = await open();
  const m = page.module;
  for (const junk of [null, undefined, NaN, Infinity, '', '   ', 'abc', {}, [], true, 0]) {
    const v = m.heroView(junk);
    assert.ok(typeof v.sentence === 'string' && v.sentence, `heroView(${String(junk)})`);
    assert.equal(m.buildStrip(junk), null);
    assert.deepEqual(m.groupRuns(junk), []);
    assert.deepEqual(m.recentSignIns(junk), []);
    assert.equal(m.hoursLeftText(junk), junk === 0 ? 'a few minutes' : '');
  }
  assert.equal(m.heroView({ enabled: true, status: { state: 'weird', current: -4 } }).state, 'none', 'an unknown state is "none"');
  assert.equal(m.hoursLeftText(1), '1 hour');
  assert.equal(m.hoursLeftText(0.4), '24 minutes');
  assert.equal(m.hoursLeftText(29.96), '29.9 hours', 'never rounds up');
  assert.equal(m.zoneLabel('UTC'), 'UTC');
  assert.equal(m.zoneLabel('Asia/Jerusalem'), 'Jerusalem time');
  page.dispose();
});

await run();
