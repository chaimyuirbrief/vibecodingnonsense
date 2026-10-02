// The dashboard against the REAL GET /api/me and GET /api/me/streak, with the
// env clock driven through real sign-ins: consecutive days, across Shabbos,
// a skipped day, a window that lapses while a session is still open, and a
// Saturday viewed from Friday night's session. Every assertion compares what
// the page shows with what the API returned on the same load.
//
// The clock starts Tue 2026-01-06 10:00 America/New_York (the portal zone);
// Sat 2026-01-10 is the first Shabbos.

import { test, assert, run } from '../helpers/t.js';
import { openLive, apiErrors, settle } from '../helpers/live.js';
import { freshEnv, bootstrap, makeUser, signIn, setNow, setSetting, q, PASSWORD } from '../helpers/flows.js';

// Local New York wall time in January (UTC−5) → the instant.
function ny(day, hh, mm = 0) {
  return Date.UTC(2026, 0, day, hh + 5, mm);
}

async function signInAt(env, u, ms) {
  setNow(env, ms);
  const r = await signIn(env, u.client, u.user.email, PASSWORD);
  assert.equal(r.status, 200, r.text);
  assert.equal(r.body.ok, true);
  return r.body.streak;
}

async function openDashboard(c) {
  const page = await openLive(c, '/');
  assert.equal(page.served.file, 'dashboard.html');
  await settle(page);
  assert.deepEqual(apiErrors(page).map((x) => `${x.method} ${x.url} ${x.status}`), []);
  assert.deepEqual(page.calls.pageErrors.map(String), []);
  const streak = page.requests('/api/me/streak')[0].response;
  const me = page.requests('/api/me', 'GET').find((x) => x.path === '/api/me').response;
  return { page, streak, status: streak.status, me };
}

const SENTENCE = {
  none: () => 'No streak yet — your next sign-in starts one',
  active: (s) => `Keep it going — sign in by ${s.deadline_local}`,
  at_risk: (s) => new RegExp(`^At risk — ${String(Math.floor(s.hours_left * 10) / 10).replace('.', '\\.')} hours left$`),
  paused: (s) => `Paused for ${s.protected_today.names.join(' and ')} — the clock isn’t running`,
  lapsed: () => 'Lapsed — your next sign-in starts a new streak',
};

// The hero against the status the API sent.
function assertHero(page, s, state) {
  assert.equal(s.state, state, `the API says ${s.state}`);
  assert.ok(page.$('streak').classList.contains(`state-${state}`));
  const want = SENTENCE[state](s);
  if (want instanceof RegExp) assert.match(page.text('streak-state'), want);
  else assert.equal(page.text('streak-state'), want);
  const shown = state === 'lapsed' ? 0 : s.current;
  assert.equal(page.text('streak-count'), String(shown), 'the count');
  assert.equal(page.visible('counted-badge'), s.counted_today === true);
  assert.equal(page.text('streak-longest'), `${Math.max(s.longest, shown)} ${Math.max(s.longest, shown) === 1 ? 'day' : 'days'}`);
  assert.equal(page.text('streak-total'), String(s.total_days));
  if (s.deadline_local) {
    assert.ok(page.visible('streak-zone'));
    assert.equal(page.text('streak-zone'), 'Times are New York time.');
  }
  assert.equal(page.visible('window-row'), ['active', 'at_risk', 'paused'].includes(state) && typeof s.hours_left === 'number');
  assert.equal(page.$('hero-flame').classList.contains('is-out'), state === 'none' || state === 'lapsed');
  // The top bar's chip shows the same number.
  const chip = page.document.querySelector('.topbar-streak .num');
  assert.ok(chip, 'streak chip in the top bar');
  assert.equal(chip.textContent, String(shown));
}

// The 84-cell strip against `history`.
function assertStrip(page, history) {
  const cells = page.document.querySelectorAll('#strip .strip-day');
  assert.equal(cells.length, 84, '12 weeks × 7 days');
  assert.equal(history.length, 84, 'the API sends 84 days');
  const byDay = new Map(history.map((e) => [e.day, e]));
  const today = history.find((e) => e.today).day;
  let checked = 0;
  for (const cell of cells) {
    const day = cell.dataset.day;
    const cls = cell.classList;
    if (day > today) {
      assert.ok(cls.contains('is-future'), `${day} is still to come`);
      continue;
    }
    const e = byDay.get(day);
    assert.ok(e, `${day} is in the API history`);
    assert.equal(cls.contains('is-counted'), e.counted, `${day} counted`);
    assert.equal(cls.contains('is-protected'), e.protected, `${day} protected`);
    assert.equal(cls.contains('is-today'), e.today, `${day} today`);
    assert.equal(cls.contains('is-missed'), !e.counted && !e.protected && !e.today, `${day} missed`);
    if (e.protected && e.names.length) assert.ok(cell.getAttribute('aria-label').includes(e.names.join(', ')), `${day} names its protection`);
    checked++;
  }
  assert.ok(checked >= 78, 'nearly every cell is a past day from the API');
  return cells;
}

function counted(page) {
  return page.document.querySelectorAll('#strip .strip-day.is-counted').map((c) => c.dataset.day);
}

// The coming-up list against `upcoming`.
function assertUpcoming(page, upcoming) {
  const { groupRuns, runLabel } = page.module; // the page's own exports
  const runs = groupRuns(upcoming);
  const items = page.document.querySelectorAll('#upcoming li');
  assert.equal(items.length, runs.length);
  runs.forEach((r, i) => {
    assert.equal(items[i].querySelector('time').getAttribute('datetime'), r.from);
    assert.equal(items[i].querySelector('time').textContent, runLabel(r));
    assert.equal(items[i].querySelector('.upcoming-names').textContent, r.names.join(', '));
  });
  assert.equal(page.visible('upcoming-empty'), runs.length === 0);
}

test('none: no streak row → "No streak yet", 0, an empty strip, the rules and coming-up list', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const u = await makeUser(env, owner.client);
  // Every sign-in starts a streak, so "none" is a person whose row is gone.
  q(env, 'DELETE FROM streak_days WHERE user_id = ?', u.user.id);
  q(env, 'DELETE FROM streaks WHERE user_id = ?', u.user.id);
  const { page, streak, status } = await openDashboard(u.client);
  assert.equal(streak.enabled, true);
  assertHero(page, status, 'none');
  assertStrip(page, streak.history);
  assert.deepEqual(counted(page), []);
  assert.equal(page.text('strip-summary').startsWith('Signed in on 0 of the last'), true);
  assertUpcoming(page, streak.upcoming);
  assert.deepEqual(streak.upcoming.map((e) => e.day), ['2026-01-10', '2026-01-17', '2026-01-24']);
  assert.equal(page.document.querySelectorAll('#upcoming li')[0].textContent.replace(/\s+/g, ' ').trim(), 'Sat Jan 10 · Shabbos — the clock pauses');
  assert.match(page.text('rules'), /^Sign in at least once every 30 hours to keep your streak; Shabbos and Yom Tov \(diaspora\) don’t count against you/);
  page.dispose();
});

test('active: consecutive days then across Shabbos — count, words, strip and coming-up from the API', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const u = await makeUser(env, owner.client); // Tue Jan 6: day 1 (accepting the invitation signs in)
  assert.equal((await signInAt(env, u, ny(7, 9))).current, 2); // Wed
  assert.equal((await signInAt(env, u, ny(8, 8))).current, 3); // Thu
  assert.equal((await signInAt(env, u, ny(9, 10))).current, 4); // Fri
  const sun = await signInAt(env, u, ny(11, 9, 30)); // Sun: 47.5 h after Friday, inside the 54 h Shabbos window
  assert.equal(sun.current, 5);

  const { page, streak, status, me } = await openDashboard(u.client);
  assertHero(page, status, 'active');
  assert.equal(status.current, 5);
  assert.equal(page.text('streak-count'), '5');
  assert.equal(status.counted_today, true);
  assert.equal(page.text('streak-since'), 'Tue Jan 6, 2026');
  assertStrip(page, streak.history);
  assert.deepEqual(counted(page), ['2026-01-06', '2026-01-07', '2026-01-08', '2026-01-09', '2026-01-11']);
  const sat = page.document.querySelector('#strip .strip-day[data-day="2026-01-10"]');
  assert.ok(sat.classList.contains('is-protected') && !sat.classList.contains('is-counted'));
  assert.equal(sat.getAttribute('aria-label'), 'Sat Jan 10: protected (Shabbos)');
  assert.equal(page.text('strip-summary'), page.module.stripSummary(page.module.buildStrip(streak.history)));
  assert.match(page.text('strip-summary'), /^Signed in on 5 of the last \d+ open days\. \d+ protected days didn’t count against you\.$/);
  assertUpcoming(page, streak.upcoming);
  assert.deepEqual(streak.upcoming.map((e) => e.day), ['2026-01-17', '2026-01-24', '2026-01-31']);
  // Leaderboard (setting 'all'): this person, marked as you.
  assert.ok(page.visible('leaderboard-card'));
  const mine = page.document.querySelector('#leaderboard li.is-me');
  assert.ok(mine, 'my row is marked');
  assert.equal(mine.dataset.userId, String(me.user.id));
  assert.equal(mine.querySelector('.lb-count').textContent, '5');
  // Security card from GET /api/me factors.
  assert.equal(page.text('security-summary'), 'Password only — anyone with your password can sign in.');
  assert.ok(page.visible('enroll-banner'));
  // Recent sign-ins from GET /api/me/activity.
  const signins = page.document.querySelectorAll('#signins li');
  assert.equal(signins.length, 5);
  assert.match(signins[0].textContent, /Signed in with a password/);
  page.dispose();
});

test('paused: Friday night’s session viewed on Shabbos — "Paused for Shabbos", the clock stopped', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const u = await makeUser(env, owner.client);
  assert.equal((await signInAt(env, u, ny(7, 15))).current, 2); // Wed 3pm (29 h)
  assert.equal((await signInAt(env, u, ny(8, 19))).current, 3); // Thu 7pm (28 h)
  assert.equal((await signInAt(env, u, ny(9, 23))).current, 4); // Fri 11pm (28 h)
  setNow(env, ny(10, 0, 40)); // Sat 00:40, 100 minutes later — the session is still alive
  const { page, streak, status } = await openDashboard(u.client);
  assertHero(page, status, 'paused');
  assert.deepEqual(status.protected_today, { names: ['Shabbos'] });
  assert.equal(page.text('streak-state'), 'Paused for Shabbos — the clock isn’t running');
  assert.equal(page.text('streak-detail'), `Today is protected, so nothing is lost. Your window now runs until ${status.deadline_local}.`);
  assert.equal(status.current, 4);
  assert.equal(page.text('streak-count'), '4');
  const cells = assertStrip(page, streak.history);
  const today = cells.find((c) => c.classList.contains('is-today'));
  assert.equal(today.dataset.day, '2026-01-10');
  assert.ok(today.classList.contains('is-protected'));
  assert.equal(today.getAttribute('aria-label'), 'Sat Jan 10 (today): protected (Shabbos)');
  assertUpcoming(page, streak.upcoming);
  page.dispose();
});

test('at risk, lapsed, then a skipped day restarts at 1 with the longest kept', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  // Long sessions so one browser stays signed in across the deadline.
  setSetting(env, 'session_idle_minutes', '1440');
  setSetting(env, 'session_absolute_hours', '72');
  const u = await makeUser(env, owner.client); // Tue: 1
  await signInAt(env, u, ny(7, 10)); // Wed: 2
  await signInAt(env, u, ny(8, 10)); // Thu 10am: 3 → deadline Fri 4pm (30 h)

  setNow(env, ny(9, 8)); // Fri 8am: the browser is still in use (idle limit 24 h)
  assert.equal((await u.client.get('/api/me')).status, 200);
  setNow(env, ny(9, 11)); // Fri 11am: 5 h left, Friday not counted
  let v = await openDashboard(u.client);
  assertHero(v.page, v.status, 'at_risk');
  assert.equal(v.status.hours_left, 5);
  assert.equal(v.page.text('streak-state'), 'At risk — 5 hours left');
  assert.equal(v.page.text('streak-detail'), `Sign in by ${v.status.deadline_local} to keep your 3 days.`);
  assert.equal(v.page.text('window-caption'), '5h left of a 30-hour window');
  v.page.dispose();

  setNow(env, ny(9, 17)); // Fri 5pm: the window closed at 4pm, the same session still open
  v = await openDashboard(u.client);
  assertHero(v.page, v.status, 'lapsed');
  assert.equal(v.status.stored_current, 3, 'read-only: the row still says 3');
  assert.equal(v.status.current, 0);
  assert.equal(v.page.text('streak-count'), '0');
  assert.equal(v.page.text('streak-detail'), `The window closed ${v.status.deadline_local}. Your longest run, 3 days, is safe.`);
  assert.equal(v.page.text('streak-longest'), '3 days');
  assert.ok(!v.page.visible('since-stat'));
  assert.ok(!v.page.visible('leaderboard') || !v.page.document.querySelector('#leaderboard li.is-me'), 'a lapsed streak is off the board');
  assertStrip(v.page, v.streak.history);
  v.page.dispose();

  // Skipped Friday; Saturday is Shabbos; Sunday's sign-in starts again.
  await signInAt(env, u, ny(11, 10));
  v = await openDashboard(u.client);
  assertHero(v.page, v.status, 'active');
  assert.equal(v.status.current, 1);
  assert.equal(v.status.longest, 3);
  assert.equal(v.page.text('streak-count'), '1');
  assert.equal(v.page.text('streak-longest'), '3 days');
  assert.equal(v.page.text('streak-since'), 'Sun Jan 11, 2026');
  assertStrip(v.page, v.streak.history);
  assert.deepEqual(counted(v.page), ['2026-01-06', '2026-01-07', '2026-01-08', '2026-01-11']);
  const fri = v.page.document.querySelector('#strip .strip-day[data-day="2026-01-09"]');
  assert.ok(fri.classList.contains('is-missed'), 'Friday shows as missed');
  assert.equal(fri.getAttribute('aria-label'), 'Fri Jan 9: missed');
  v.page.dispose();
});

test('streaks off: the hero says so and the streak cards hide', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  setSetting(env, 'streak_enabled', '0');
  const { page, streak } = await openDashboard(owner.client);
  assert.equal(streak.enabled, false);
  assert.equal(page.text('streak-state'), 'Streaks are turned off');
  for (const id of ['history-card', 'upcoming-card', 'rules-card', 'leaderboard-card']) assert.ok(!page.visible(id), `${id} hidden`);
  page.dispose();
});

await run();
