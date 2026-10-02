// The streak, driven through sign-ins and GET /api/me/streak (CONTRACTS §9,
// §8.4; A §10; B §8). The clock starts Tue 2026-01-06 10:00 New York.

import { test, assert, run } from '../helpers/t.js';
import { freshEnv, bootstrap, makeUser, q, count, auditRows, advance, setSetting, HOUR, DAY, PASSWORD } from '../helpers/flows.js';

async function world() {
  const env = freshEnv();
  const owner = await bootstrap(env);
  // Sessions that outlive a night, so the streak can be READ without signing in.
  setSetting(env, 'session_absolute_hours', '72');
  setSetting(env, 'session_idle_minutes', '1440');
  const bob = await makeUser(env, owner.client, { email: 'bob@acme.com' }); // Tue: day 1 (the invitation sign-in)
  return { env, owner, bob };
}

async function signInBob(bob) {
  const r = await bob.client.post('/api/auth/login', { identifier: 'bob@acme.com', password: PASSWORD });
  assert.equal(r.status, 200, r.text);
  assert.equal(r.body.ok, true);
  return r;
}

const row = (env, uid) => q(env, 'SELECT * FROM streaks WHERE user_id = ?', uid)[0];

test('consecutive days count, a missed day reads as lapsed without rewriting, the next sign-in restarts at 1', async () => {
  const { env, bob } = await world();
  assert.equal(row(env, bob.user.id).current, 1);
  advance(env, DAY); // Wed 10:00
  assert.equal((await signInBob(bob)).body.streak.current, 2);
  const wed = await bob.client.get('/api/me/streak');
  assert.equal(wed.status, 200);
  assert.equal(wed.body.enabled, true);
  assert.equal(wed.body.status.state, 'active');
  assert.equal(wed.body.status.current, 2);
  assert.equal(wed.body.status.counted_today, true);
  assert.equal(wed.body.history.length, 84);
  assert.deepEqual(wed.body.history.slice(-2).map((d) => [d.day, d.counted, d.today]), [['2026-01-06', true, false], ['2026-01-07', true, true]]);
  assert.equal(wed.body.rules.window_hours, 30);
  assert.ok(Array.isArray(wed.body.upcoming) && wed.body.upcoming.some((d) => d.names.includes('Shabbos')));

  // Thursday: no sign-in (a read keeps the session alive; reads never count).
  advance(env, 23 * HOUR); // Thu 09:00
  assert.equal((await bob.client.get('/api/me')).status, 200);
  assert.equal(row(env, bob.user.id).current, 2);
  advance(env, 23 * HOUR); // Fri 08:00 — the window closed Thu 16:00
  const stored = row(env, bob.user.id);
  const fri = await bob.client.get('/api/me/streak');
  assert.equal(fri.status, 200, fri.text);
  assert.equal(fri.body.status.state, 'lapsed');
  assert.equal(fri.body.status.current, 0);
  assert.equal(fri.body.status.stored_current, 2);
  assert.equal(fri.body.status.longest, 2);
  assert.deepEqual(row(env, bob.user.id), stored, 'reading a lapsed streak does not rewrite it (A §10)');

  advance(env, 2 * HOUR); // Fri 10:00
  const again = await signInBob(bob);
  assert.equal(again.body.streak.current, 1);
  const after = row(env, bob.user.id);
  assert.equal(after.current, 1);
  assert.equal(after.longest, 2);
  assert.equal(after.started_day, '2026-01-09');
  assert.equal(after.total_days, 3);
});

test('Friday to Sunday survives Shabbos, which reads as paused', async () => {
  const { env, bob } = await world();
  advance(env, 3 * DAY); // Fri 10:00 — the Tuesday streak lapsed Wed 16:00
  assert.equal((await signInBob(bob)).body.streak.current, 1);
  advance(env, 23 * HOUR); // Sat 09:00
  const sat = await bob.client.get('/api/me/streak');
  assert.equal(sat.body.status.state, 'paused');
  assert.deepEqual(sat.body.status.protected_today, { names: ['Shabbos'] });
  assert.equal(sat.body.status.current, 1);
  assert.match(sat.body.status.deadline_local, /^Sun/);
  advance(env, 25 * HOUR); // Sun 10:00 — 48 hours after Friday's sign-in
  const sun = await signInBob(bob);
  assert.equal(sun.body.streak.current, 2, 'the window ran from Friday across Shabbos');
  assert.equal(row(env, bob.user.id).started_day, '2026-01-09');
});

test('two sign-ins on one day count once', async () => {
  const { env, bob } = await world();
  advance(env, HOUR);
  await signInBob(bob);
  advance(env, 4 * HOUR);
  await signInBob(bob);
  const r = row(env, bob.user.id);
  assert.equal(r.current, 1);
  assert.equal(r.total_days, 1);
  assert.equal(count(env, 'SELECT COUNT(*) FROM streak_days WHERE user_id = ?', bob.user.id), 1);
});

test('a streak can never block a sign-in: the table is dropped and sign-in still succeeds (A §10)', async () => {
  const { env, bob } = await world();
  env.DB.sqlite.exec('DROP TABLE streaks');
  advance(env, DAY);
  const sessions = count(env, 'SELECT COUNT(*) FROM sessions WHERE user_id = ?', bob.user.id);
  const r = await signInBob(bob);
  assert.equal(r.body.streak, null);
  assert.equal(count(env, 'SELECT COUNT(*) FROM sessions WHERE user_id = ?', bob.user.id), sessions + 1);
  assert.equal(auditRows(env, 'login.success').at(-1).target_id, String(bob.user.id));
  assert.equal((await bob.client.get('/api/me')).status, 200, 'the rest of the account works');
});

test('an unreadable stored streak restarts at 1 and is audited, and the sign-in succeeds', async () => {
  const { env, bob } = await world();
  q(env, "UPDATE streaks SET last_at = 'garbage', current = 7, longest = 9 WHERE user_id = ?", bob.user.id);
  advance(env, DAY);
  const r = await signInBob(bob);
  assert.equal(r.body.streak.current, 1);
  assert.equal(r.body.streak.longest, 9);
  const err = auditRows(env, 'streak.error');
  assert.equal(err.length, 1);
  assert.match(err[0].detail, /unreadable_last_at/);
});

test('streaks switched off: nothing is recorded and the page says so', async () => {
  const { env, bob } = await world();
  setSetting(env, 'streak_enabled', '0');
  advance(env, DAY);
  const r = await signInBob(bob);
  assert.equal(r.body.streak, null);
  assert.equal(row(env, bob.user.id).current, 1, 'Tuesday’s row untouched');
  const s = await bob.client.get('/api/me/streak');
  assert.equal(s.body.enabled, false);
  assert.equal(s.body.status, null);
  assert.equal(s.body.leaderboard, null);
});

test('the leaderboard follows streak_leaderboard', async () => {
  const { env, owner, bob } = await world();
  const mia = await makeUser(env, owner.client, { email: 'mia@acme.com', role: 'manager' });
  const all = await bob.client.get('/api/me/streak');
  assert.ok(Array.isArray(all.body.leaderboard));
  assert.ok(all.body.leaderboard.some((e) => e.user_id === bob.user.id));
  assert.ok(all.body.leaderboard.every((e) => Object.keys(e).sort().join() === 'current,full_name,longest,user_id'), 'names and counts only');
  setSetting(env, 'streak_leaderboard', 'managers');
  assert.equal((await bob.client.get('/api/me/streak')).body.leaderboard, null);
  assert.ok(Array.isArray((await mia.client.get('/api/me/streak')).body.leaderboard));
  setSetting(env, 'streak_leaderboard', 'off');
  assert.equal((await mia.client.get('/api/me/streak')).body.leaderboard, null);
  setSetting(env, 'streak_leaderboard', 'everyone!'); // unrecognised reads as off
  assert.equal((await mia.client.get('/api/me/streak')).body.leaderboard, null);
});

await run();
