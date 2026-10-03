// The streak, driven through sign-ins and GET /api/me/streak (CONTRACTS §9,
// §8.4; A §10; B §8). The clock starts Tue 2026-01-06 10:00 New York.

import { test, assert, run } from '../helpers/t.js';
import { freshEnv, bootstrap, makeUser, stepUp, signIn, q, count, auditRows, advance, setSetting, HOUR, DAY, PASSWORD, OWNER } from '../helpers/flows.js';

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
  const { env, owner, bob } = await world();
  env.DB.sqlite.exec('DROP TABLE streaks');
  advance(env, DAY);
  const sessions = count(env, 'SELECT COUNT(*) FROM sessions WHERE user_id = ?', bob.user.id);
  const r = await signInBob(bob);
  assert.equal(r.body.streak, null);
  assert.equal(count(env, 'SELECT COUNT(*) FROM sessions WHERE user_id = ?', bob.user.id), sessions + 1);
  assert.equal(auditRows(env, 'login.success').at(-1).target_id, String(bob.user.id));
  assert.equal((await bob.client.get('/api/me')).status, 200, 'the rest of the account works');
  // FO-9, CONTRACTS §0.4: the real exception reaches the audit log — a
  // broken table that stops every sign-in counting is not silent.
  const errs = auditRows(env, 'streak.error');
  assert.equal(errs.length, 1, 'exactly one row for the one failed touch');
  assert.equal(errs[0].severity, 'critical');
  assert.equal(errs[0].target_id, String(bob.user.id));
  assert.match(errs[0].error, /no such table: streaks/);

  // STREAK-2, SPEC §16.38: nor does it take the console down. The overview and
  // the person panel — suspend, reset factors, sign out — still load.
  assert.equal((await signIn(env, owner.client, OWNER.email, OWNER.password)).status, 200);
  const overview = await owner.client.get('/api/admin/overview');
  assert.equal(overview.status, 200, overview.text);
  assert.equal(overview.body.counts.streaks_active, null);
  const person = await owner.client.get(`/api/admin/users/${bob.user.id}`);
  assert.equal(person.status, 200, person.text);
  assert.equal(person.body.streak, null);
  assert.equal(person.body.user.email, 'bob@acme.com');
  await stepUp(env, owner.client);
  assert.equal((await owner.client.post(`/api/admin/users/${bob.user.id}/status`, { status: 'suspended' })).status, 200);
  assert.ok(auditRows(env, 'streak.error').some((e) => /no such table: streaks/.test(e.error) && /served without it/.test(e.detail)), 'the console read is recorded too');
});

// STREAK-4: an administrator's restore claims today without logging it, so
// the person's own sign-in that day must be logged — not drawn as missed in
// the middle of an unbroken run.
test('a restore claims today; the person’s own sign-in that day is still logged and counted', async () => {
  const { env, owner, bob } = await world();
  advance(env, 22 * HOUR); // Wed 08:00
  assert.equal((await signIn(env, owner.client, OWNER.email, OWNER.password)).status, 200);
  await stepUp(env, owner.client);
  assert.equal((await owner.client.post(`/api/admin/users/${bob.user.id}/streak`, { current: 5, reason: 'Portal outage' })).status, 200);
  const totalBefore = row(env, bob.user.id).total_days;
  advance(env, HOUR); // Wed 09:00
  const wed = (await signInBob(bob)).body.streak;
  assert.equal(wed.current, 5, 'today was already counted by the restore');
  assert.equal(row(env, bob.user.id).total_days, totalBefore + 1, 'but the day itself is now on record');
  advance(env, 2 * HOUR); // a second sign-in that day adds nothing
  await signInBob(bob);
  assert.equal(row(env, bob.user.id).total_days, totalBefore + 1);
  advance(env, 22 * HOUR); // Thu 09:00
  assert.equal((await signInBob(bob)).body.streak.current, 6);
  assert.deepEqual(q(env, 'SELECT day FROM streak_days WHERE user_id = ? ORDER BY day', bob.user.id).map((r) => r.day), ['2026-01-06', '2026-01-07', '2026-01-08']);
  const hist = (await bob.client.get('/api/me/streak')).body.history.slice(-3);
  assert.deepEqual(hist.map((d) => [d.day, d.counted]), [['2026-01-06', true], ['2026-01-07', true], ['2026-01-08', true]]);
});

test('set to 0, then a sign-in the same day starts the new streak the page promises', async () => {
  const { env, owner, bob } = await world();
  advance(env, 23 * HOUR); // Wed 09:00
  assert.equal((await signInBob(bob)).body.streak.current, 2);
  advance(env, HOUR);
  assert.equal((await signIn(env, owner.client, OWNER.email, OWNER.password)).status, 200);
  await stepUp(env, owner.client);
  assert.equal((await owner.client.post(`/api/admin/users/${bob.user.id}/streak`, { current: 0, reason: 'Shared account, reset' })).status, 200);
  const zero = (await bob.client.get('/api/me/streak')).body.status;
  assert.equal(zero.state, 'lapsed');
  advance(env, HOUR); // Wed 11:00
  const s = (await signInBob(bob)).body.streak;
  assert.deepEqual([s.state, s.current, s.counted_today, s.started_day], ['active', 1, true, '2026-01-07']);
  assert.equal(row(env, bob.user.id).total_days, 2, 'Wednesday was already on record: not counted twice');
  advance(env, DAY);
  assert.equal((await signInBob(bob)).body.streak.current, 2);
});

// STREAK-1: undoing an old adjustment must not silently replace the days the
// person has earned since (total_days included, which nothing else can set
// back); and the audit.revert row says what it overwrote.
test('reverting an adjustment: refused once they have signed in since; recorded in full when it goes ahead', async () => {
  const { env, owner, bob } = await world();
  const uid = bob.user.id;
  await stepUp(env, owner.client);
  assert.equal((await owner.client.post(`/api/admin/users/${uid}/streak`, { current: 5, reason: 'Portal outage' })).status, 200);
  const adj = auditRows(env, 'streak.adjust').at(-1);
  for (let i = 0; i < 10; i++) {
    advance(env, DAY);
    await signInBob(bob);
  }
  const earned = row(env, uid);
  assert.deepEqual([earned.current, earned.longest, earned.total_days], [15, 15, 11]);
  assert.equal((await signIn(env, owner.client, OWNER.email, OWNER.password)).status, 200);
  await stepUp(env, owner.client);
  const rev = await owner.client.post(`/api/admin/audit/${adj.id}/revert`, {});
  assert.equal(rev.status, 409, rev.text);
  assert.equal(rev.body.code, 'changed_since');
  assert.deepEqual(row(env, uid), earned, 'nothing was overwritten');
  assert.equal(auditRows(env, 'audit.revert').at(-1).outcome, 'denied');

  // An adjustment nobody has signed in after reverts as before, and the
  // revert row records what it replaced and what it left.
  assert.equal((await owner.client.post(`/api/admin/users/${uid}/streak`, { current: 30, reason: 'Typo test' })).status, 200);
  const adj2 = auditRows(env, 'streak.adjust').at(-1);
  const ok = await owner.client.post(`/api/admin/audit/${adj2.id}/revert`, {});
  assert.equal(ok.status, 200, ok.text);
  assert.deepEqual([row(env, uid).current, row(env, uid).total_days], [15, 11]);
  const revRow = auditRows(env, 'audit.revert').at(-1);
  assert.equal(JSON.parse(revRow.before_state).current, 30);
  assert.equal(JSON.parse(revRow.after_state).current, 15);
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
