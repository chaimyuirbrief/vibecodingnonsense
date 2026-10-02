// The streak engine (CONTRACTS §9). Real weeks in America/New_York for A's
// table, real D1 semantics (node:sqlite) for the atomic writes, and absurd
// calendars for the caps real data never reaches (A §13.7).
//
// Wall-clock times are converted to instants here with a brute-force search
// over offsets — independent of protected.js — so an expectation cannot
// inherit a bug from the code under test (A §13.8).

import { test, assert, run } from '../helpers/t.js';
import { makeEnvWithSchema } from '../helpers/env.js';
import * as s from '../../src/streak.js';
import { fixedFromGregorian } from '../../src/calendar/hebrew.js';
import { dayString } from '../../src/calendar/protected.js';
import { ValidationError, HttpError } from '../../src/errors.js';

const NY = 'America/New_York';
const MIN = 60000;
const H = 60 * MIN;
const D = 24 * H;
const CFG = s.streakConfig({}); // defaults: New York, 30 h, 12 h grace, cap 4, Shabbos + diaspora Yom Tov
const iso = (ms) => new Date(ms).toISOString();

const HOSTILE = [null, undefined, NaN, Infinity, -Infinity, '', '   ', 'abc', {}, [], true, false, 0, Symbol('x'), 10n, () => 1];
const label = (v) => (typeof v === 'symbol' ? 'Symbol' : typeof v === 'bigint' ? `${v}n` : JSON.stringify(v) ?? String(v));

const partsFmt = new Map();
function wallParts(t, tz) {
  if (!partsFmt.has(tz)) {
    partsFmt.set(tz, new Intl.DateTimeFormat('en-US', { timeZone: tz, hourCycle: 'h23', year: 'numeric', month: 'numeric', day: 'numeric', hour: 'numeric', minute: 'numeric' }));
  }
  const o = {};
  for (const p of partsFmt.get(tz).formatToParts(t)) o[p.type] = p.value;
  return `${o.year}-${o.month}-${o.day} ${Number(o.hour)}:${o.minute}`;
}

// The earliest instant whose wall clock in `tz` reads y-m-d hh:mm.
function at(y, m, d, hh = 0, mm = 0, tz = NY) {
  const want = `${y}-${m}-${d} ${hh}:${String(mm).padStart(2, '0')}`;
  let best = null;
  for (let off = -15 * 60; off <= 15 * 60; off += 15) {
    const t = Date.UTC(y, m - 1, d, hh, mm) - off * MIN;
    if (wallParts(t, tz) === want && (best === null || t < best)) best = t;
  }
  if (best === null) throw new Error(`no instant reads ${want} in ${tz}`);
  return best;
}

const cfgOf = (policy) => s.streakConfig(policy);
const withCal = (cfg, isProtected) => ({ ...cfg, isProtected });

async function newEnv() {
  return makeEnvWithSchema();
}

async function addUser(env, { email, status = 'active', full_name = '' }) {
  const t = '2026-01-01T00:00:00.000Z';
  const r = await env.DB.prepare('INSERT INTO users (email, role_id, status, created_at, updated_at, full_name) VALUES (?, 1, ?, ?, ?, ?)')
    .bind(email, status, t, t, full_name)
    .run();
  return r.meta.last_row_id;
}

const rowOf = (env, uid) => env.DB.q('SELECT * FROM streaks WHERE user_id = ?', uid)[0] ?? null;
const daysOf = (env, uid) => env.DB.q('SELECT day FROM streak_days WHERE user_id = ? ORDER BY day', uid).map((r) => r.day);
const snapshot = (env) => ({ streaks: env.DB.q('SELECT * FROM streaks ORDER BY user_id'), days: env.DB.q('SELECT * FROM streak_days ORDER BY user_id, day') });

function putRow(env, uid, r) {
  env.DB.q(
    'INSERT INTO streaks (user_id, current, longest, total_days, started_day, last_day, last_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    uid, r.current ?? 0, r.longest ?? 0, r.total_days ?? 0, r.started_day ?? null, r.last_day ?? null, r.last_at ?? null, r.updated_at ?? '2026-01-01T00:00:00.000Z',
  );
}

// ---------------------------------------------------------------- config

test('streakConfig: a missing or partial policy falls back to the §5 defaults', () => {
  for (const policy of [undefined, null, {}, { unrelated: 1 }, { streak_window_hours: 36 }]) {
    const c = s.streakConfig(policy);
    assert.equal(c.enabled, true);
    assert.equal(c.tz, NY);
    assert.equal(c.baseHours, policy && policy.streak_window_hours ? 36 : 30);
    assert.equal(c.graceHours, 12);
    assert.equal(c.maxLeewayDays, 4);
    assert.deepEqual([...c.weeklyDays], [6]);
    assert.equal(c.hebrew, true);
    assert.equal(c.israel, false);
    assert.deepEqual([...c.extraDates], []);
    assert.equal(c.leaderboard, 'all');
    assert.equal(typeof c.isProtected, 'function');
    assert.ok(Object.isFrozen(c));
  }
});

test('streakConfig: hostile and unrecognised values take §5\'s unrecognised column; an explicit 0 stays legal', () => {
  for (const v of [...HOSTILE, 'nope', 999, -1, 4.5, '4.5', { valueOf() { throw new Error('boom'); } }]) {
    const absent = v === undefined || v === null;
    const c = s.streakConfig({
      streak_enabled: v, streak_window_hours: v, streak_reentry_grace_hours: v, streak_max_leeway_days: v, streak_weekly_days: v,
      streak_hebrew_holidays: v, streak_region: v, streak_extra_dates: v, streak_leaderboard: v, timezone: v,
    });
    const L = label(v);
    assert.equal(c.enabled, !(v === false || v === 0), `enabled ${L}`);
    assert.equal(c.baseHours, 30, `window ${L}`);
    assert.equal(c.graceHours, v === 0 ? 0 : 12, `grace ${L}`);
    assert.equal(c.maxLeewayDays, v === 0 ? 0 : 4, `leeway ${L}`);
    assert.deepEqual([...c.weeklyDays], Array.isArray(v) ? [] : [6], `weekly ${L}`); // [] is legal: no weekly day
    assert.equal(c.hebrew, !(v === false || v === 0), `hebrew ${L}`);
    assert.equal(c.israel, false, `region ${L}`);
    assert.deepEqual([...c.extraDates], [], `extra ${L}`);
    assert.equal(c.leaderboard, absent ? 'all' : 'off', `leaderboard ${L}`);
    assert.equal(c.tz, absent ? NY : 'UTC', `timezone ${L}`);
  }
  // Blank is not zero (A §14.11); explicit zero is.
  assert.equal(s.streakConfig({ streak_reentry_grace_hours: '' }).graceHours, 12);
  assert.equal(s.streakConfig({ streak_reentry_grace_hours: '   ' }).graceHours, 12);
  assert.equal(s.streakConfig({ streak_reentry_grace_hours: '0' }).graceHours, 0);
  assert.equal(s.streakConfig({ streak_max_leeway_days: '0' }).maxLeewayDays, 0);
  // Ranges: window 24–72, grace 0–24, leeway 0–7.
  assert.equal(s.streakConfig({ streak_window_hours: 23 }).baseHours, 30);
  assert.equal(s.streakConfig({ streak_window_hours: 73 }).baseHours, 30);
  assert.equal(s.streakConfig({ streak_window_hours: '72' }).baseHours, 72);
  assert.equal(s.streakConfig({ streak_reentry_grace_hours: 25 }).graceHours, 12);
  assert.equal(s.streakConfig({ streak_max_leeway_days: 8 }).maxLeewayDays, 4);
  assert.equal(s.streakConfig({ streak_max_leeway_days: 7 }).maxLeewayDays, 7);
  // Weekly days: an empty list is legal; any bad member makes the whole value unrecognised.
  assert.deepEqual([...s.streakConfig({ streak_weekly_days: [] }).weeklyDays], []);
  assert.deepEqual([...s.streakConfig({ streak_weekly_days: [6, 5, 6] }).weeklyDays], [5, 6]);
  for (const bad of [[7], [-1], ['6'], [6.5], [6, null], [0, 1, 2, 3, 4, 5, 6, 0]]) assert.deepEqual([...s.streakConfig({ streak_weekly_days: bad }).weeklyDays], [6], JSON.stringify(bad));
  // Timezones: kept as the operator spelled them (ICU would say Asia/Calcutta); invalid → UTC.
  assert.equal(s.streakConfig({ timezone: 'Asia/Kolkata' }).tz, 'Asia/Kolkata');
  assert.equal(s.streakConfig({ timezone: 'US/Eastern' }).tz, 'US/Eastern');
  for (const tz of ['Foo/Bar', ' UTC', 'x'.repeat(100)]) assert.equal(s.streakConfig({ timezone: tz }).tz, 'UTC');
  assert.equal(s.streakConfig({ streak_region: 'israel' }).israel, true);
  assert.equal(s.streakConfig({ streak_region: 'Israel' }).israel, false);
  for (const lb of ['all', 'managers', 'off']) assert.equal(s.streakConfig({ streak_leaderboard: lb }).leaderboard, lb);
  // A policy whose reads throw, or that is not an object at all.
  const trap = new Proxy({}, { get() { throw new Error('boom'); } });
  for (const pol of [trap, 'abc', 42, Symbol('x'), [], () => 1]) assert.equal(s.streakConfig(pol).baseHours, 30);
});

test('streakConfig reads raw setting strings and a nested policy.streak', () => {
  const c = s.streakConfig({
    streak_enabled: '1', streak_window_hours: '36', streak_reentry_grace_hours: '6', streak_max_leeway_days: '3',
    streak_weekly_days: '[0,6]', streak_hebrew_holidays: '0', streak_region: 'israel',
    streak_extra_dates: '[{"date":"2026-12-25","label":"Closed"},{"date":"nope","label":"x"}]', streak_leaderboard: 'managers', timezone: 'UTC',
  });
  assert.deepEqual(
    { enabled: c.enabled, tz: c.tz, b: c.baseHours, g: c.graceHours, l: c.maxLeewayDays, w: [...c.weeklyDays], h: c.hebrew, i: c.israel, e: c.extraDates.map((x) => ({ ...x })), lb: c.leaderboard },
    { enabled: true, tz: 'UTC', b: 36, g: 6, l: 3, w: [0, 6], h: false, i: true, e: [{ date: '2026-12-25', label: 'Closed' }], lb: 'managers' },
  );
  assert.deepEqual(c.isProtected(fixedFromGregorian(2026, 12, 25)), { protected: true, names: ['Closed'] });
  assert.deepEqual(c.isProtected(fixedFromGregorian(2026, 12, 27)), { protected: true, names: ['Sunday'] });
  assert.deepEqual(c.isProtected(fixedFromGregorian(2026, 12, 26)), { protected: true, names: ['Saturday'] });
  assert.equal(s.streakConfig({ streak_weekly_days: '[6' }).weeklyDays[0], 6, 'unparseable JSON → default');
  const nested = s.streakConfig({ timezone: 'UTC', streak: { window_hours: 48, enabled: false } });
  assert.equal(nested.baseHours, 48);
  assert.equal(nested.enabled, false);
});

// ---------------------------------------------------------------- the window

test("A's table on real New York weeks: 30 h, 54 h, 78 h, 102 h", () => {
  const cases = [
    // [label, last sign-in, deadline, hours, blocks, leeway, rounds]
    ['regular Tuesday', at(2026, 1, 6, 10), at(2026, 1, 7, 16), 30, [], 0, 1],
    ['Friday across Shabbos', at(2026, 1, 9, 10), at(2026, 1, 11, 16), 54, [['2026-01-10', '2026-01-10', ['Shabbos']]], 1, 2],
    ['two-day Yom Tov, Wed–Thu (last days of Pesach 5786)', at(2026, 4, 7, 10), at(2026, 4, 10, 16), 78, [['2026-04-08', '2026-04-09', ['Pesach']]], 2, 3],
    ['Thu–Fri Yom Tov into Shabbos (Rosh Hashanah 5785)', at(2024, 10, 2, 10), at(2024, 10, 6, 16), 102, [['2024-10-03', '2024-10-05', ['Rosh Hashanah', 'Shabbos']]], 3, 4],
    ['Thu–Fri Yom Tov into Shabbos (Pesach 5786)', at(2026, 4, 1, 10), at(2026, 4, 5, 16), 102, [['2026-04-02', '2026-04-04', ['Pesach', 'Shabbos']]], 3, 4],
  ];
  for (const [name, last, deadline, hours, blocks, leeway, rounds] of cases) {
    const r = s.computeDeadline(last, CFG);
    assert.equal(iso(r.deadline), iso(deadline), name);
    assert.equal((r.deadline - last) / H, hours, name);
    assert.equal(r.base, last + 30 * H);
    assert.deepEqual(r.blocks, blocks.map(([from, to, names]) => ({ from, to, names })), name);
    assert.equal(r.leewayDays, leeway, name);
    assert.equal(r.graceApplied, false, name);
    assert.equal(r.rounds, rounds, name);
  }
  // The "regular" and "two-day" weeks really are clear of anything else.
  for (const d of [[2026, 1, 6], [2026, 1, 7], [2026, 4, 7], [2026, 4, 10]]) assert.equal(CFG.isProtected(fixedFromGregorian(...d)).protected, false);
});

test('a sign-in inside a protected block opens the window when the block ends (the clock does not run in protected time)', () => {
  const cases = [
    // [label, last sign-in, window opens, deadline, opening block]
    ['Saturday night after Shabbos', at(2026, 1, 10, 21), at(2026, 1, 11, 0), at(2026, 1, 12, 6), ['2026-01-10', '2026-01-10', ['Shabbos']]],
    ['early Shabbos morning', at(2026, 1, 10, 0, 10), at(2026, 1, 11, 0), at(2026, 1, 12, 6), ['2026-01-10', '2026-01-10', ['Shabbos']]],
    ['second day of Rosh Hashanah 5785, then Shabbos', at(2024, 10, 4, 10), at(2024, 10, 6, 0), at(2024, 10, 7, 6), ['2024-10-04', '2024-10-05', ['Rosh Hashanah', 'Shabbos']]],
    ['first day of Rosh Hashanah 5785: three days, one block', at(2024, 10, 3, 0, 30), at(2024, 10, 6, 0), at(2024, 10, 7, 6), ['2024-10-03', '2024-10-05', ['Rosh Hashanah', 'Shabbos']]],
  ];
  for (const [name, last, opens, deadline, [from, to, names]] of cases) {
    const r = s.computeDeadline(last, CFG);
    assert.equal(iso(r.anchor), iso(opens), name);
    assert.equal(iso(r.deadline), iso(deadline), name);
    assert.equal(r.base, r.anchor + 30 * H, name);
    assert.deepEqual(r.opening, { from, to, names }, name);
    assert.deepEqual(r.blocks, [], name);
    assert.equal(r.leewayDays, 0, name);
  }
  // The trap this closes: Fri 11:30 PM gives Mon 5:30 AM; a further sign-in
  // at 12:10 AM on Shabbos used to give Sun 6:10 AM — earlier.
  const fri = s.computeDeadline(at(2026, 1, 9, 23, 30), CFG).deadline;
  const sat = s.computeDeadline(at(2026, 1, 10, 0, 10), CFG).deadline;
  assert.equal(iso(fri), iso(at(2026, 1, 12, 5, 30)));
  assert.ok(sat >= fri, 'a later sign-in never shortens the deadline');
  // With max_leeway_days 0 nothing is protected, including the sign-in's own day.
  const flat = s.computeDeadline(at(2026, 1, 10, 21), s.streakConfig({ streak_max_leeway_days: 0 }));
  assert.equal(flat.deadline, at(2026, 1, 10, 21) + 30 * H);
  assert.equal(flat.opening, null);
});

test('monotone: a later sign-in never gets an earlier deadline — every 30 minutes, Sep 2025 to Dec 2027, three calendars', () => {
  const [from, to] = [at(2025, 9, 1, 0), at(2028, 1, 1, 0)];
  for (const cfg of [CFG, s.streakConfig({ streak_region: 'israel' }), s.streakConfig({ timezone: 'Asia/Kolkata', streak_weekly_days: [5] })]) {
    let prev = s.computeDeadline(from, cfg).deadline;
    for (let t = from + 30 * 60000; t < to; t += 30 * 60000) {
      const d = s.computeDeadline(t, cfg).deadline;
      assert.ok(d >= prev, `${cfg.tz}: ${iso(t)} → ${iso(d)} is earlier than ${iso(prev)}`);
      prev = d;
    }
  }
});

test('re-entry grace: 11 pm Thursday → noon Sunday, not 5 am; Friday 11 pm already reaches Monday 5 am', () => {
  const thu = at(2026, 1, 8, 23);
  const r = s.computeDeadline(thu, CFG);
  assert.equal(iso(r.deadline), iso(at(2026, 1, 11, 12)));
  assert.equal(r.graceApplied, true);
  assert.equal(r.leewayDays, 1);
  const noGrace = s.computeDeadline(thu, s.streakConfig({ streak_reentry_grace_hours: 0 }));
  assert.equal(iso(noGrace.deadline), iso(at(2026, 1, 11, 5)));
  assert.equal(noGrace.graceApplied, false);
  // CONTRACTS §9's prose uses "11pm Friday" for this example, but its own
  // algorithm (which is binding) gives Friday 11 pm 54 h: Shabbos lies inside
  // the 30 h window, so the leeway day already carries it to Monday 5 am.
  const fri = s.computeDeadline(at(2026, 1, 9, 23), CFG);
  assert.equal(iso(fri.deadline), iso(at(2026, 1, 12, 5)));
  assert.equal(fri.graceApplied, false);
  // After a Yom Tov block: Tuesday 11 pm before Rosh Hashanah 5785 + Shabbos.
  const rh = s.computeDeadline(at(2024, 10, 1, 23), CFG);
  assert.equal(iso(rh.deadline), iso(at(2024, 10, 6, 12)));
  assert.equal(rh.graceApplied, true);
  assert.equal(rh.rounds, 5);
});

test('re-entry grace only ever lengthens, by at most the grace — every hour of 2026', () => {
  const g0 = s.streakConfig({ streak_reentry_grace_hours: 0 });
  let lengthened = 0;
  const [from, to] = [at(2026, 1, 1, 0), at(2027, 1, 1, 0)];
  for (let t = from; t < to; t += H) {
    const a = s.computeDeadline(t, CFG).deadline;
    const b = s.computeDeadline(t, g0).deadline;
    assert.ok(a >= b && a - b <= 12 * H, iso(t));
    if (a > b) lengthened++;
  }
  assert.ok(lengthened > 100, `grace mattered ${lengthened} times`);
});

test('the deadline is a fixed point: the leeway equals the protected days inside the final window — every hour of 2026', () => {
  const [from, to] = [at(2026, 1, 1, 0), at(2027, 1, 1, 0)];
  for (const cfg of [CFG, s.streakConfig({ streak_region: 'israel' }), s.streakConfig({ timezone: 'Asia/Kolkata' })]) {
    for (let t = from; t < to; t += H) {
      const r = s.computeDeadline(t, cfg);
      const counted = r.blocks.reduce((n, b) => n + (Date.parse(b.to) - Date.parse(b.from)) / D + 1, 0);
      assert.equal(r.leewayDays, Math.min(counted, cfg.maxLeewayDays), iso(t));
      assert.ok(r.deadline >= r.base + r.leewayDays * D);
      assert.ok(r.deadline <= r.base + cfg.maxLeewayDays * D + cfg.graceHours * H);
      assert.ok(r.rounds < 8, 'converged well inside the round bound');
      assert.ok(r.leewayDays <= 3, 'real calendars never exceed three days');
    }
  }
});

test('DST weeks: the window is absolute hours; the local deadline moves with the clocks', () => {
  // Spring forward Sun 2026-03-08 02:00 EST → EDT.
  const spring = s.computeDeadline(at(2026, 3, 6, 10), CFG);
  assert.equal(spring.deadline - at(2026, 3, 6, 10), 54 * H);
  assert.equal(iso(spring.deadline), '2026-03-08T21:00:00.000Z');
  assert.equal(s.streakStatus({ current: 1, last_at: iso(at(2026, 3, 6, 10)), last_day: '2026-03-06' }, at(2026, 3, 7, 12), CFG).deadline_local, 'Sun, Mar 8, 5:00 PM');
  // Fall back Sun 2026-11-01 02:00 EDT → EST.
  const fall = s.computeDeadline(at(2026, 10, 30, 10), CFG);
  assert.equal(fall.deadline - at(2026, 10, 30, 10), 54 * H);
  assert.equal(iso(fall.deadline), '2026-11-01T20:00:00.000Z');
  assert.equal(s.streakStatus({ current: 1, last_at: iso(at(2026, 10, 30, 10)), last_day: '2026-10-30' }, at(2026, 10, 31, 12), CFG).deadline_local, 'Sun, Nov 1, 3:00 PM');
  // Grace counts from the real local midnight: 12 h after Sun 00:00 EST is 1 pm EDT.
  const thu = s.computeDeadline(at(2026, 3, 5, 23), CFG);
  assert.equal(iso(thu.deadline), '2026-03-08T17:00:00.000Z');
  assert.equal(thu.graceApplied, true);
  // A regular day across the change is still 30 real hours.
  assert.equal(s.computeDeadline(at(2026, 3, 8, 1), CFG).deadline - at(2026, 3, 8, 1), 30 * H);
});

test('leeway cap: a calendar that protects every day stops at max_leeway_days (A §13.7)', () => {
  const always = () => ({ protected: true, names: ['Everything'] });
  const last = at(2026, 1, 6, 10);
  for (const [lee, grace] of [[4, 12], [0, 12], [7, 24], [2, 0]]) {
    const cfg = withCal(s.streakConfig({ streak_max_leeway_days: lee, streak_reentry_grace_hours: grace }), always);
    const r = s.computeDeadline(last, cfg);
    // The sign-in's own day is protected too, so the window would open late
    // AND count leeway — the hard cap (from the sign-in) is what stops it.
    const cap = last + 30 * H + lee * D + (lee > 0 ? grace * H : 0);
    assert.equal(r.deadline, lee > 0 ? cap : last + 30 * H, `leeway ${lee}`);
    assert.ok(r.deadline <= last + 30 * H + lee * D + grace * H, 'never past the hard cap');
    assert.ok(r.leewayDays <= lee);
    assert.equal(r.graceApplied, false, 'no block ever ends, so no re-entry grace');
    assert.equal(r.blocks.length, 1);
    assert.equal(r.opening === null, lee === 0);
  }
});

test('hard cap: a calendar that changes its answers between rounds can never pass base + leeway + grace', () => {
  const last = at(2026, 1, 6, 12);
  const lastDay = fixedFromGregorian(2026, 1, 6);
  const base = s.streakConfig({ streak_window_hours: 48, streak_reentry_grace_hours: 24, streak_max_leeway_days: 0 });
  // A block that grows by a day every time the window is re-examined: each
  // round its end sits just inside the window, so re-entry grace chases it.
  let rounds = 0;
  const growing = withCal(base, (d) => {
    if (d === lastDay + 1) rounds++;
    return { protected: d >= lastDay + 1 && d <= lastDay + rounds, names: ['Bug'] };
  });
  const r = s.computeDeadline(last, growing);
  assert.ok(r.deadline <= last + 48 * H + 24 * H, `deadline ${(r.deadline - last) / H} h`);
  assert.ok(r.deadline >= last + 48 * H);
  // Random answers on every call, seeded: never past the cap, and the cap
  // genuinely binds in some trials (so this test measures it).
  let seed = 42;
  const rand = () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  let capped = 0;
  const jan1 = at(2026, 1, 1, 0);
  for (let i = 0; i < 2000; i++) {
    const cfg = withCal(
      s.streakConfig({ streak_window_hours: 24 + Math.floor(rand() * 49), streak_reentry_grace_hours: Math.floor(rand() * 25), streak_max_leeway_days: Math.floor(rand() * 8) }),
      () => ({ protected: rand() < 0.6, names: [] }),
    );
    const t = jan1 + Math.floor(rand() * 365 * 24) * H;
    const x = s.computeDeadline(t, cfg);
    const cap = x.base + cfg.maxLeewayDays * D + cfg.graceHours * H;
    assert.ok(x.deadline >= x.base && x.deadline <= cap, `trial ${i}`);
    if (x.deadline === cap) capped++;
  }
  assert.ok(capped > 0, 'the hard cap bound at least once');
  // A calendar that throws protects nothing.
  const thrower = withCal(CFG, () => { throw new Error('calendar down'); });
  assert.equal(s.computeDeadline(last, thrower).deadline, last + 30 * H);
});

test('computeDeadline is total', () => {
  for (const v of HOSTILE) {
    if (v === 0) continue; // 1970-01-01 is a real instant
    const r = s.computeDeadline(v, CFG);
    assert.ok(Number.isNaN(r.deadline), label(v));
    assert.deepEqual(r.blocks, []);
  }
  const last = at(2026, 1, 9, 10);
  for (const v of HOSTILE) assert.equal(s.computeDeadline(last, v).deadline, at(2026, 1, 11, 16), `cfg ${label(v)} → defaults`);
  assert.equal(s.computeDeadline(last, { ...CFG, baseHours: 1000 }).deadline, at(2026, 1, 11, 16), 'out-of-range cfg → defaults');
});

// ---------------------------------------------------------------- touchStreak

test('first sign-in: one row, one history cell, status active', async () => {
  const env = await newEnv();
  const uid = await addUser(env, { email: 'a@acme.com' });
  const now = at(2026, 1, 6, 10);
  const st = await s.touchStreak(env, uid, now, CFG);
  assert.deepEqual(st, {
    state: 'active', current: 1, stored_current: 1, longest: 1, total_days: 1, counted_today: true,
    last_at: iso(now), last_day: '2026-01-06', started_day: '2026-01-06',
    deadline: iso(now + 30 * H), deadline_local: 'Wed, Jan 7, 4:00 PM', hours_left: 30, protected_today: null, timezone: NY,
  });
  const row = rowOf(env, uid);
  assert.deepEqual({ ...row, updated_at: undefined }, {
    user_id: uid, current: 1, longest: 1, total_days: 1, started_day: '2026-01-06', last_day: '2026-01-06', last_at: iso(now), updated_at: undefined,
  });
  assert.deepEqual(env.DB.q('SELECT * FROM streak_days'), [{ user_id: uid, day: '2026-01-06', first_at: iso(now) }]);
  assert.equal(st.repaired, undefined);
});

test('same local day: counts once, and last_at only ever moves forward', async () => {
  const env = await newEnv();
  const uid = await addUser(env, { email: 'a@acme.com' });
  await s.touchStreak(env, uid, at(2026, 1, 6, 9), CFG);
  const st = await s.touchStreak(env, uid, at(2026, 1, 6, 15), CFG);
  assert.equal(st.current, 1);
  assert.equal(st.total_days, 1);
  assert.equal(rowOf(env, uid).last_at, iso(at(2026, 1, 6, 15)));
  // An isolate with a slightly earlier clock must not drag it back.
  await s.touchStreak(env, uid, at(2026, 1, 6, 12), CFG);
  assert.equal(rowOf(env, uid).last_at, iso(at(2026, 1, 6, 15)));
  // 11:59 pm local is still the same day (the UTC date has already changed).
  await s.touchStreak(env, uid, at(2026, 1, 6, 23, 59), CFG);
  assert.equal(rowOf(env, uid).current, 1);
  assert.equal(rowOf(env, uid).total_days, 1);
  assert.deepEqual(daysOf(env, uid), ['2026-01-06']);
  assert.equal(env.DB.q('SELECT first_at FROM streak_days')[0].first_at, iso(at(2026, 1, 6, 9)), 'the cell records the first sign-in');
  // The window runs from the most recent sign-in (D13).
  assert.equal(rowOf(env, uid).last_at, iso(at(2026, 1, 6, 23, 59)));
  const next = await s.touchStreak(env, uid, at(2026, 1, 8, 5, 59), CFG);
  assert.equal(next.current, 2, 'Tue 11:59 pm + 30 h = Thu 5:59 am');
});

test('a later day inside the window counts; at the deadline still counts; one ms past restarts with longest kept', async () => {
  const env = await newEnv();
  const a = await addUser(env, { email: 'a@acme.com' });
  const b = await addUser(env, { email: 'b@acme.com' });
  for (const uid of [a, b]) await s.touchStreak(env, uid, at(2026, 1, 6, 10), CFG);
  const deadline = at(2026, 1, 7, 16);
  const sa = await s.touchStreak(env, a, deadline, CFG);
  assert.deepEqual([sa.current, sa.longest, sa.total_days, sa.started_day, sa.last_day], [2, 2, 2, '2026-01-06', '2026-01-07']);
  const sb = await s.touchStreak(env, b, deadline + 1, CFG);
  assert.deepEqual([sb.current, sb.longest, sb.total_days, sb.started_day], [1, 1, 2, '2026-01-07']);
  // a: Wed 4 pm + 30 h = Thu 10 pm, which counts. Then Thu 10 pm + 30 h = Sat
  // 4 am, + Shabbos = Sun 4 am, + re-entry grace = Sun noon: 12:01 is too late.
  assert.equal((await s.touchStreak(env, a, at(2026, 1, 8, 22), CFG)).current, 3);
  assert.equal(s.streakStatus(rowOf(env, a), at(2026, 1, 10, 12), CFG).deadline_local, 'Sun, Jan 11, 12:00 PM');
  const late = await s.touchStreak(env, a, at(2026, 1, 11, 12, 1), CFG);
  assert.deepEqual([late.current, late.longest, late.total_days, late.started_day], [1, 3, 4, '2026-01-11']);
  assert.deepEqual(daysOf(env, a), ['2026-01-06', '2026-01-07', '2026-01-08', '2026-01-11']);
});

test('the streak survives Shabbos and a Thursday–Friday Yom Tov, and re-entry grace saves a Sunday-morning sign-in', async () => {
  const env = await newEnv();
  const ids = [];
  for (let i = 0; i < 5; i++) ids.push(await addUser(env, { email: `u${i}@acme.com` }));
  const [shab, shabLate, rh, grace, noGrace] = ids;
  for (const uid of [shab, shabLate]) await s.touchStreak(env, uid, at(2026, 1, 9, 10), CFG);
  assert.equal((await s.touchStreak(env, shab, at(2026, 1, 11, 15, 59), CFG)).current, 2);
  assert.equal((await s.touchStreak(env, shabLate, at(2026, 1, 11, 16, 1), CFG)).current, 1);
  await s.touchStreak(env, rh, at(2024, 10, 2, 10), CFG);
  assert.equal((await s.touchStreak(env, rh, at(2024, 10, 6, 15), CFG)).current, 2, 'Wed → Sun across Rosh Hashanah 5785 and Shabbos');
  const g0 = s.streakConfig({ streak_reentry_grace_hours: 0 });
  await s.touchStreak(env, grace, at(2026, 1, 8, 23), CFG);
  await s.touchStreak(env, noGrace, at(2026, 1, 8, 23), g0);
  assert.equal((await s.touchStreak(env, grace, at(2026, 1, 11, 11, 30), CFG)).current, 2, 'grace: until noon Sunday');
  assert.equal((await s.touchStreak(env, noGrace, at(2026, 1, 11, 11, 30), g0)).current, 1, 'without grace it ended at 5 am');
});

test('two concurrent sign-ins on a new day count once (A §11)', async () => {
  const env = await newEnv();
  const uid = await addUser(env, { email: 'a@acme.com' });
  // First ever, concurrently.
  const t0 = at(2026, 1, 6, 10);
  const [x, y] = await Promise.all([s.touchStreak(env, uid, t0 + 1000, CFG), s.touchStreak(env, uid, t0, CFG)]);
  assert.ok(x && y);
  assert.deepEqual([rowOf(env, uid).current, rowOf(env, uid).total_days], [1, 1]);
  assert.equal(rowOf(env, uid).last_at, iso(t0 + 1000));
  // Next day, concurrently — the later clock first, so a lost race that
  // wrote anyway would also drag last_at backwards.
  const t1 = at(2026, 1, 7, 9);
  const both = await Promise.all([s.touchStreak(env, uid, t1 + 5000, CFG), s.touchStreak(env, uid, t1, CFG)]);
  assert.ok(both.every((st) => st && st.current === 2));
  const row = rowOf(env, uid);
  assert.deepEqual([row.current, row.longest, row.total_days, row.last_day], [2, 2, 2, '2026-01-07']);
  assert.equal(row.last_at, iso(t1 + 5000));
  assert.deepEqual(daysOf(env, uid), ['2026-01-06', '2026-01-07']);
  // Five at once on a third day.
  const t2 = at(2026, 1, 8, 9);
  await Promise.all([0, 1, 2, 3, 4].map((i) => s.touchStreak(env, uid, t2 + i * 1000, CFG)));
  assert.deepEqual([rowOf(env, uid).current, rowOf(env, uid).total_days], [3, 3]);
  assert.equal(env.DB.q('SELECT COUNT(*) AS n FROM streak_days')[0].n, 3);
});

test('a race across local midnight: the losing sign-in is same-day and leaves no history cell it did not count', async () => {
  const env = await newEnv();
  const uid = await addUser(env, { email: 'a@acme.com' });
  await s.touchStreak(env, uid, at(2026, 1, 6, 20), CFG); // window until Thu 2 am
  // Both read the Jan 6 row; 23:59:59 on the 7th wins, 00:00:01 on the 8th loses.
  const lateWed = at(2026, 1, 7, 23, 59) + 59000;
  const earlyThu = at(2026, 1, 8, 0, 0) + 1000;
  await Promise.all([s.touchStreak(env, uid, lateWed, CFG), s.touchStreak(env, uid, earlyThu, CFG)]);
  const row = rowOf(env, uid);
  assert.deepEqual([row.current, row.total_days, row.last_day, row.last_at], [2, 2, '2026-01-07', iso(earlyThu)]);
  assert.deepEqual(daysOf(env, uid), ['2026-01-06', '2026-01-07'], 'no cell for a day the counter did not count');
  // The next sign-in on the 8th counts it.
  assert.equal((await s.touchStreak(env, uid, at(2026, 1, 8, 9), CFG)).current, 3);
  assert.deepEqual(daysOf(env, uid), ['2026-01-06', '2026-01-07', '2026-01-08']);
});

test('a last_at more than 5 minutes in the future holds: nothing changes (A §11)', async () => {
  const env = await newEnv();
  const uid = await addUser(env, { email: 'a@acme.com' });
  const now = at(2026, 1, 7, 10);
  putRow(env, uid, { current: 4, longest: 6, total_days: 9, started_day: '2026-01-03', last_day: '2026-01-06', last_at: iso(now + H) });
  const before = snapshot(env);
  const st = await s.touchStreak(env, uid, now, CFG);
  assert.equal(st.state, 'held');
  assert.equal(st.current, 4, 'held shows the stored count');
  assert.deepEqual(snapshot(env), before);
  // Within the slack it is an ordinary (same-day) sign-in, not a hold.
  const env2 = await newEnv();
  const u2 = await addUser(env2, { email: 'b@acme.com' });
  putRow(env2, u2, { current: 4, longest: 6, total_days: 9, started_day: '2026-01-03', last_day: '2026-01-07', last_at: iso(now + 4 * MIN) });
  const st2 = await s.touchStreak(env2, u2, now, CFG);
  assert.equal(st2.state, 'active');
  assert.equal(rowOf(env2, u2).last_at, iso(now + 4 * MIN), 'max(last_at, now) keeps the later one');
});

test('an unreadable last_at restarts at 1, keeps longest, and reports repaired', async () => {
  const now = at(2026, 1, 7, 10);
  for (const bad of ['garbage', '42', '2026-01-06', '2026-01-06 10:00:00', 12345, '', 'Tue Jan 06 2026']) {
    const env = await newEnv();
    const uid = await addUser(env, { email: 'a@acme.com' });
    putRow(env, uid, { current: 7, longest: 9, total_days: 20, started_day: '2026-01-01', last_day: '2026-01-06', last_at: bad });
    const st = await s.touchStreak(env, uid, now, CFG);
    assert.equal(st.repaired, 'unreadable_last_at', label(bad));
    const row = rowOf(env, uid);
    assert.deepEqual([row.current, row.longest, row.total_days, row.started_day, row.last_day, row.last_at], [1, 9, 21, '2026-01-07', '2026-01-07', iso(now)], label(bad));
    assert.deepEqual(daysOf(env, uid), ['2026-01-07']);
  }
  // Unreadable on a day already counted: restart, but today is not counted twice.
  const env = await newEnv();
  const uid = await addUser(env, { email: 'a@acme.com' });
  putRow(env, uid, { current: 7, longest: 9, total_days: 20, last_day: '2026-01-07', last_at: 'garbage' });
  const st = await s.touchStreak(env, uid, now, CFG);
  assert.equal(st.repaired, 'unreadable_last_at');
  assert.deepEqual([rowOf(env, uid).current, rowOf(env, uid).total_days], [1, 20]);
  // A zeroed row with no last_at is a plain restart, not a repair; a count
  // with no last_at is present-but-unreadable.
  const e2 = await newEnv();
  const u2 = await addUser(e2, { email: 'b@acme.com' });
  const u3 = await addUser(e2, { email: 'c@acme.com' });
  putRow(e2, u2, { current: 0, longest: 5, total_days: 5 });
  putRow(e2, u3, { current: 5, longest: 5, total_days: 5 });
  const s2 = await s.touchStreak(e2, u2, now, CFG);
  assert.equal(s2.repaired, undefined);
  assert.deepEqual([s2.current, s2.longest, s2.total_days], [1, 5, 6]);
  assert.equal((await s.touchStreak(e2, u3, now, CFG)).repaired, 'unreadable_last_at');
});

test('touchStreak never throws: a dropped table, a failing write or no database resolves null', async () => {
  const env = await newEnv();
  const uid = await addUser(env, { email: 'a@acme.com' });
  await s.touchStreak(env, uid, at(2026, 1, 6, 10), CFG);
  // The history table fails mid-batch: the whole write rolls back (atomic).
  const before = snapshot(env);
  env.DB.failOn = /streak_days/;
  assert.equal(await s.touchStreak(env, uid, at(2026, 1, 7, 10), CFG), null);
  env.DB.failOn = null;
  assert.deepEqual(snapshot(env), before, 'the counter did not move without its history cell');
  env.DB.sqlite.exec('DROP TABLE streak_days');
  assert.equal(await s.touchStreak(env, uid, at(2026, 1, 7, 10), CFG), null);
  assert.deepEqual(env.DB.q('SELECT * FROM streaks'), before.streaks);
  env.DB.sqlite.exec('DROP TABLE streaks');
  assert.equal(await s.touchStreak(env, uid, at(2026, 1, 7, 10), CFG), null);
  for (const e of [null, undefined, {}, { DB: null }, { DB: {} }, 'env']) assert.equal(await s.touchStreak(e, uid, at(2026, 1, 7, 10), CFG), null);
});

test('touchStreak with hostile arguments writes nothing', async () => {
  const env = await newEnv();
  const uid = await addUser(env, { email: 'a@acme.com' });
  const now = at(2026, 1, 6, 10);
  for (const v of [...HOSTILE, -1, 1.5, '1.5', '0']) assert.equal(await s.touchStreak(env, v, now, CFG), null, `userId ${label(v)}`);
  for (const v of [...HOSTILE.filter((x) => x !== 0), '2026-01-06T15:00:00Z', String(now)]) assert.equal(await s.touchStreak(env, uid, v, CFG), null, `now ${label(v)}`);
  assert.deepEqual(snapshot(env), { streaks: [], days: [] });
  // A hostile cfg falls back to the defaults rather than failing the sign-in.
  const st = await s.touchStreak(env, uid, now, Symbol('cfg'));
  assert.equal(st.timezone, NY);
  assert.equal(st.current, 1);
});

test('with streaks disabled a sign-in records nothing', async () => {
  const env = await newEnv();
  const uid = await addUser(env, { email: 'a@acme.com' });
  assert.equal(await s.touchStreak(env, uid, at(2026, 1, 6, 10), s.streakConfig({ streak_enabled: '0' })), null);
  assert.deepEqual(snapshot(env), { streaks: [], days: [] });
});

test('streak_days older than 400 days are pruned for that user in the same write (§11)', async () => {
  const env = await newEnv();
  const a = await addUser(env, { email: 'a@acme.com' });
  const b = await addUser(env, { email: 'b@acme.com' });
  const T = fixedFromGregorian(2026, 1, 6);
  for (const k of [401, 400, 399]) env.DB.q('INSERT INTO streak_days (user_id, day, first_at) VALUES (?, ?, ?)', a, dayString(T - k), '2024-12-01T00:00:00.000Z');
  env.DB.q('INSERT INTO streak_days (user_id, day, first_at) VALUES (?, ?, ?)', b, dayString(T - 500), '2024-12-01T00:00:00.000Z');
  await s.touchStreak(env, a, at(2026, 1, 6, 10), CFG);
  assert.deepEqual(daysOf(env, a), [dayString(T - 400), dayString(T - 399), '2026-01-06']);
  assert.deepEqual(daysOf(env, b), [dayString(T - 500)], "another user's history is theirs to prune");
  await s.touchStreak(env, a, at(2026, 1, 7, 10), CFG);
  assert.deepEqual(daysOf(env, a), [dayString(T - 399), '2026-01-06', '2026-01-07']);
  // A same-day sign-in writes nothing at all, prune included.
  env.DB.q('INSERT INTO streak_days (user_id, day, first_at) VALUES (?, ?, ?)', a, dayString(T - 450), '2024-12-01T00:00:00.000Z');
  await s.touchStreak(env, a, at(2026, 1, 7, 11), CFG);
  assert.ok(daysOf(env, a).includes(dayString(T - 450)));
});

test('a zone change that puts today behind last_day does not count a day', async () => {
  const env = await newEnv();
  const uid = await addUser(env, { email: 'a@acme.com' });
  const now = at(2026, 1, 6, 10);
  putRow(env, uid, { current: 3, longest: 3, total_days: 3, started_day: '2026-01-05', last_day: '2026-01-07', last_at: iso(now - H) });
  const st = await s.touchStreak(env, uid, now, CFG);
  assert.deepEqual([st.current, st.total_days], [3, 3]);
  assert.equal(rowOf(env, uid).last_at, iso(now));
  assert.deepEqual(daysOf(env, uid), []);
});

// ---------------------------------------------------------------- status

test('streakStatus states: none, active, at_risk, paused, lapsed, held', () => {
  const tue10 = at(2026, 1, 6, 10);
  const none = s.streakStatus(null, tue10, CFG);
  assert.deepEqual(none, {
    state: 'none', current: 0, stored_current: 0, longest: 0, total_days: 0, counted_today: false, last_at: null, last_day: null,
    started_day: null, deadline: null, deadline_local: null, hours_left: null, protected_today: null, timezone: NY,
  });
  assert.deepEqual(s.streakStatus(null, at(2026, 1, 10, 12), CFG).protected_today, { names: ['Shabbos'] });

  const row = (lastAt, lastDay, current = 5) => ({ user_id: 1, current, longest: 8, total_days: 30, started_day: '2026-01-01', last_day: lastDay, last_at: iso(lastAt) });
  const active = s.streakStatus(row(tue10 - H, '2026-01-06'), tue10, CFG);
  assert.equal(active.state, 'active');
  assert.equal(active.counted_today, true);
  assert.equal(active.hours_left, 29);

  // Yesterday 10 am; deadline today 4 pm.
  const mon10 = at(2026, 1, 5, 10);
  assert.equal(s.streakStatus(row(mon10, '2026-01-05'), tue10, CFG).state, 'active', 'exactly 6 h left is not yet at risk');
  const risk = s.streakStatus(row(mon10, '2026-01-05'), tue10 + 1, CFG);
  assert.equal(risk.state, 'at_risk');
  assert.equal(risk.hours_left, 5.9, 'rounded down, never up');
  assert.equal(risk.deadline_local, 'Tue, Jan 6, 4:00 PM');
  assert.equal(s.streakStatus(row(mon10, '2026-01-05'), at(2026, 1, 6, 15, 54), CFG).hours_left, 0.1);

  // Shabbos, not counted: paused, with the exact deadline.
  const paused = s.streakStatus(row(at(2026, 1, 9, 10), '2026-01-09'), at(2026, 1, 10, 12), CFG);
  assert.equal(paused.state, 'paused');
  assert.deepEqual(paused.protected_today, { names: ['Shabbos'] });
  assert.equal(paused.deadline_local, 'Sun, Jan 11, 4:00 PM');
  assert.equal(paused.hours_left, 28);
  // Counted on a protected day (someone who does not observe it): active.
  assert.equal(s.streakStatus(row(at(2026, 1, 10, 9), '2026-01-10'), at(2026, 1, 10, 12), CFG).state, 'active');
  // Re-entry grace deadline formatting.
  assert.equal(s.streakStatus(row(at(2026, 1, 8, 23), '2026-01-08'), at(2026, 1, 10, 12), CFG).deadline_local, 'Sun, Jan 11, 12:00 PM');

  const lapsed = s.streakStatus(row(tue10, '2026-01-06'), at(2026, 1, 8, 10), CFG);
  assert.deepEqual([lapsed.state, lapsed.current, lapsed.stored_current, lapsed.longest, lapsed.hours_left], ['lapsed', 0, 5, 8, null]);
  assert.equal(lapsed.deadline, iso(at(2026, 1, 7, 16)), 'the deadline that was missed');
  assert.equal(s.streakStatus(row(tue10, '2026-01-06'), at(2026, 1, 7, 16), CFG).state, 'at_risk', 'at the deadline it has not lapsed');
  assert.equal(s.streakStatus(row(tue10, '2026-01-06'), at(2026, 1, 7, 16) + 1, CFG).state, 'lapsed');

  const held = s.streakStatus(row(tue10 + H, '2026-01-06'), tue10, CFG);
  assert.deepEqual([held.state, held.current, held.deadline], ['held', 5, null]);

  for (const bad of [{ ...row(tue10, '2026-01-06'), last_at: 'garbage' }, { ...row(tue10, '2026-01-06'), last_at: null }, row(tue10, '2026-01-06', 0)]) {
    const st = s.streakStatus(bad, tue10 + H, CFG);
    assert.deepEqual([st.state, st.current, st.longest], ['lapsed', 0, 8], 'unreadable or zero reads as lapsed');
  }
});

test('streakStatus is pure and total', () => {
  const now = at(2026, 1, 6, 10);
  const row = { user_id: 1, current: 5, longest: 8, total_days: 30, started_day: '2026-01-01', last_day: '2026-01-05', last_at: iso(at(2026, 1, 5, 10)) };
  const copy = JSON.parse(JSON.stringify(row));
  s.streakStatus(row, now, CFG);
  assert.deepEqual(row, copy);
  for (const v of HOSTILE) {
    // No row is 'none'; an object that is not a readable row is present but unreadable → 'lapsed', showing 0.
    const st = s.streakStatus(v, now, CFG);
    assert.equal(st.state, v && typeof v === 'object' ? 'lapsed' : 'none', `row ${label(v)}`);
    assert.equal(st.current, 0);
    assert.equal(s.streakStatus(row, v === 0 ? NaN : v, CFG).current, 0, `now ${label(v)}`);
    assert.equal(s.streakStatus(row, now, v).timezone, NY, `cfg ${label(v)}`);
  }
  const junk = { current: 'abc', longest: {}, total_days: -4, last_day: '2026-13-01', started_day: 5, last_at: Symbol('x') };
  const st = s.streakStatus(junk, now, CFG);
  assert.deepEqual([st.state, st.current, st.longest, st.total_days, st.last_day, st.started_day, st.last_at], ['lapsed', 0, 0, 0, null, null, null]);
});

test('reading a lapsed streak shows 0 and never rewrites it (A §10)', async () => {
  const env = await newEnv();
  const uid = await addUser(env, { email: 'a@acme.com', full_name: 'Ann' });
  for (const [d, h] of [[5, 10], [6, 10], [7, 10]]) await s.touchStreak(env, uid, at(2026, 1, d, h), CFG);
  const later = at(2026, 1, 12, 9);
  const before = snapshot(env);
  const st = await s.getStreak(env, uid, later, CFG);
  assert.deepEqual([st.state, st.current, st.stored_current, st.longest], ['lapsed', 0, 3, 3]);
  assert.equal(s.streakStatus(rowOf(env, uid), later, CFG).current, 0);
  await s.streakHistory(env, uid, later, CFG);
  await s.leaderboard(env, later, CFG);
  assert.deepEqual(snapshot(env), before, 'byte-identical after every read');
  // The next sign-in reconciles it.
  assert.equal((await s.touchStreak(env, uid, later, CFG)).current, 1);
  assert.equal(rowOf(env, uid).longest, 3);
  assert.equal((await s.getStreak(env, 'abc', later, CFG)).state, 'none');
});

// ---------------------------------------------------------------- history, upcoming, leaderboard

test('streakHistory marks counted, protected, missed and today', async () => {
  const env = await newEnv();
  const uid = await addUser(env, { email: 'a@acme.com' });
  for (const [d, h] of [[5, 10], [6, 10], [8, 10]]) await s.touchStreak(env, uid, at(2026, 1, d, h), CFG);
  const now = at(2026, 1, 12, 9);
  const hist = await s.streakHistory(env, uid, now, CFG, 14);
  assert.equal(hist.length, 14);
  assert.equal(hist[0].day, '2025-12-30');
  assert.equal(hist[13].day, '2026-01-12');
  const pick = (f) => hist.filter(f).map((c) => c.day);
  assert.deepEqual(pick((c) => c.counted), ['2026-01-05', '2026-01-06', '2026-01-08']);
  assert.deepEqual(pick((c) => c.protected), ['2026-01-03', '2026-01-10']);
  assert.deepEqual(pick((c) => c.today), ['2026-01-12']);
  assert.deepEqual(pick((c) => !c.counted && !c.protected && !c.today), ['2025-12-30', '2025-12-31', '2026-01-01', '2026-01-02', '2026-01-04', '2026-01-07', '2026-01-09', '2026-01-11']);
  assert.ok(hist.every((c) => c.future === false));
  assert.deepEqual(hist.find((c) => c.day === '2026-01-10').names, ['Shabbos']);
  assert.deepEqual(hist.find((c) => c.day === '2026-01-07').names, []);
  assert.equal((await s.streakHistory(env, uid, now, CFG)).length, 84, 'default 84');
  for (const v of [...HOSTILE, 401, -3]) assert.equal((await s.streakHistory(env, uid, now, CFG, v)).length, 84, `days ${label(v)}`);
  assert.equal((await s.streakHistory(env, uid, now, CFG, 400)).length, 400);
  for (const v of HOSTILE) assert.ok((await s.streakHistory(env, v, now, CFG, 14)).every((c) => !c.counted), `user ${label(v)}`);
});

test('upcomingProtected: the next three weeks, starting tomorrow', () => {
  const up = s.upcomingProtected(CFG, at(2026, 9, 10, 12));
  assert.deepEqual(up, [
    { day: '2026-09-12', names: ['Shabbos', 'Rosh Hashanah'] },
    { day: '2026-09-13', names: ['Rosh Hashanah'] },
    { day: '2026-09-19', names: ['Shabbos'] },
    { day: '2026-09-21', names: ['Yom Kippur'] },
    { day: '2026-09-26', names: ['Shabbos', 'Sukkos'] },
    { day: '2026-09-27', names: ['Sukkos'] },
  ]);
  assert.equal(s.upcomingProtected(CFG, at(2026, 9, 12, 12))[0].day, '2026-09-13', 'today is not upcoming');
  assert.deepEqual(s.upcomingProtected(CFG, at(2026, 9, 10, 12), 2), [{ day: '2026-09-12', names: ['Shabbos', 'Rosh Hashanah'] }]);
  const israel = s.upcomingProtected(s.streakConfig({ streak_region: 'israel' }), at(2026, 9, 10, 12));
  assert.ok(!israel.some((u) => u.day === '2026-09-27'), 'second day of Sukkos is diaspora-only');
  for (const v of HOSTILE) {
    assert.equal(s.upcomingProtected(CFG, at(2026, 9, 10, 12), v).length, 6, `days ${label(v)}`);
    assert.deepEqual(s.upcomingProtected(CFG, v === 0 ? NaN : v), [], `now ${label(v)}`);
  }
});

test('leaderboard: active people only, lapsed excluded, ordered by current, longest, name', async () => {
  const env = await newEnv();
  const now = at(2026, 1, 6, 12);
  const fresh = iso(now - 2 * H);
  const people = [
    ['Ann', 'active', { current: 5, longest: 5, last_at: fresh }],
    ['Bea', 'active', { current: 5, longest: 9, last_at: fresh }],
    ['aaron', 'active', { current: 5, longest: 9, last_at: fresh }],
    ['Cy', 'active', { current: 3, longest: 3, last_at: fresh }],
    ['Dee', 'suspended', { current: 50, longest: 50, last_at: fresh }],
    ['Eve', 'active', { current: 40, longest: 40, last_at: iso(now - 5 * D) }],
    ['Fay', 'active', { current: 0, longest: 12, last_at: fresh }],
    ['Gus', 'invited', { current: 7, longest: 7, last_at: fresh }],
    ['Hal', 'disabled', { current: 9, longest: 9, last_at: fresh }],
    ['Ivy', 'active', { current: 2, longest: 2, last_at: 'garbage' }],
  ];
  const id = {};
  for (const [name, status, r] of people) {
    id[name] = await addUser(env, { email: `${name.toLowerCase()}@acme.com`, status, full_name: name });
    putRow(env, id[name], { ...r, last_day: '2026-01-06', total_days: r.current });
  }
  const before = snapshot(env);
  const lb = await s.leaderboard(env, now, CFG);
  assert.deepEqual(lb, [
    { user_id: id.aaron, full_name: 'aaron', current: 5, longest: 9 },
    { user_id: id.Bea, full_name: 'Bea', current: 5, longest: 9 },
    { user_id: id.Ann, full_name: 'Ann', current: 5, longest: 5 },
    { user_id: id.Cy, full_name: 'Cy', current: 3, longest: 3 },
  ]);
  assert.deepEqual((await s.leaderboard(env, now, CFG, 2)).map((x) => x.full_name), ['aaron', 'Bea']);
  for (const v of HOSTILE) assert.equal((await s.leaderboard(env, now, CFG, v)).length, 4, `limit ${label(v)}`);
  assert.deepEqual(snapshot(env), before);
});

// ---------------------------------------------------------------- admin

test('adjustStreak validates, restores, and opens a fresh window from now', async () => {
  const env = await newEnv();
  const uid = await addUser(env, { email: 'a@acme.com' });
  const now = at(2026, 1, 6, 10);
  for (const v of [null, NaN, Infinity, '', '   ', 'abc', {}, [], true, Symbol('x'), 10n, -1, 100001, 1.5, '1.5', undefined]) {
    await assert.rejects(s.adjustStreak(env, uid, { current: v, longest: 3 }, now, CFG), ValidationError, `current ${label(v)}`);
    if (v !== undefined) await assert.rejects(s.adjustStreak(env, uid, { current: 3, longest: v }, now, CFG), ValidationError, `longest ${label(v)}`);
  }
  for (const v of HOSTILE) await assert.rejects(s.adjustStreak(env, v, { current: 3 }, now, CFG), ValidationError, `user ${label(v)}`);
  for (const v of [null, undefined, 'x', 42, Symbol('x')]) await assert.rejects(s.adjustStreak(env, uid, v, now, CFG), ValidationError);
  await assert.rejects(s.adjustStreak(env, 9999, { current: 3 }, now, CFG), (e) => e instanceof HttpError && e.status === 404);
  assert.deepEqual(snapshot(env), { streaks: [], days: [] }, 'nothing written by a refusal');

  const first = await s.adjustStreak(env, uid, { current: '12', longest: 3 }, now, CFG);
  assert.equal(first.prior, null);
  assert.deepEqual({ ...first.row, updated_at: undefined }, {
    user_id: uid, current: 12, longest: 12, total_days: 0, started_day: '2025-12-26', last_day: '2026-01-06', last_at: iso(now), updated_at: undefined,
  });
  assert.deepEqual(daysOf(env, uid), [], 'an adjustment is not a sign-in');
  // Today counts as done; tomorrow continues the restored run.
  assert.equal((await s.touchStreak(env, uid, now + H, CFG)).current, 12);
  assert.equal((await s.touchStreak(env, uid, at(2026, 1, 7, 9), CFG)).current, 13);

  const zero = await s.adjustStreak(env, uid, { current: 0 }, at(2026, 1, 7, 12), CFG);
  assert.equal(zero.prior.current, 13);
  assert.deepEqual([zero.row.current, zero.row.longest, zero.row.last_at, zero.row.last_day], [0, 13, zero.prior.last_at, '2026-01-07'], 'longest kept; window untouched');
  assert.equal((await s.getStreak(env, uid, at(2026, 1, 7, 13), CFG)).state, 'lapsed');
  const lower = await s.adjustStreak(env, uid, { current: 2, longest: 1 }, at(2026, 1, 7, 12), CFG);
  assert.equal(lower.row.longest, 2, 'longest = max(longest, current)');
  assert.equal((await s.adjustStreak(env, uid, { current: 100000, longest: 0 }, now, CFG)).row.current, 100000);
});

test('restoreStreak puts the prior row back, or deletes it when there was none', async () => {
  const env = await newEnv();
  const uid = await addUser(env, { email: 'a@acme.com' });
  const now = at(2026, 1, 6, 10);
  await s.touchStreak(env, uid, now, CFG);
  const { prior } = await s.adjustStreak(env, uid, { current: 40 }, now, CFG);
  const back = await s.restoreStreak(env, uid, prior, now + MIN);
  assert.equal(back.prior.current, 40);
  assert.deepEqual({ ...back.row, updated_at: undefined }, { ...prior, updated_at: undefined });
  const gone = await s.restoreStreak(env, uid, null, now + MIN);
  assert.equal(gone.row, null);
  assert.equal(rowOf(env, uid), null);
  for (const bad of [{ ...prior, last_at: 'garbage' }, { ...prior, current: -1 }, { ...prior, last_day: '2026-02-30' }, 'row', 42]) {
    await assert.rejects(s.restoreStreak(env, uid, bad, now), ValidationError);
  }
  assert.equal(rowOf(env, uid), null, 'a refused restore writes nothing');
});

test('streakRules: the window and the calendar in one phrase', () => {
  assert.deepEqual(s.streakRules(CFG), { window_hours: 30, reentry_grace_hours: 12, max_leeway_days: 4, calendar: 'Shabbos and Yom Tov (diaspora)' });
  const cases = [
    [{ streak_region: 'israel' }, 'Shabbos and Yom Tov (Israel)'],
    [{ streak_weekly_days: [0], streak_hebrew_holidays: '0' }, 'Sundays'],
    [{ streak_weekly_days: [6], streak_hebrew_holidays: '0' }, 'Saturdays'],
    [{ streak_weekly_days: [5, 6] }, 'Fridays, Shabbos and Yom Tov (diaspora)'],
    [{ streak_weekly_days: [], streak_hebrew_holidays: '0' }, 'No protected days'],
    [{ streak_extra_dates: [{ date: '2026-12-25', label: 'Closed' }, { date: '2026-12-31', label: 'Closed' }] }, 'Shabbos, Yom Tov (diaspora) and 2 extra dates'],
    [{ streak_weekly_days: [], streak_hebrew_holidays: '0', streak_extra_dates: [{ date: '2026-12-25', label: 'Closed' }] }, '1 extra date'],
  ];
  for (const [policy, calendar] of cases) assert.equal(s.streakRules(s.streakConfig(policy)).calendar, calendar);
  assert.deepEqual(s.streakRules(s.streakConfig({ streak_window_hours: 48, streak_reentry_grace_hours: 0, streak_max_leeway_days: 2 })).window_hours, 48);
  for (const v of HOSTILE) assert.equal(s.streakRules(v).calendar, 'Shabbos and Yom Tov (diaspora)');
});

await run();
