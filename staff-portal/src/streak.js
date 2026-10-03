// Calendar-aware login streaks (CONTRACTS §9; A §10, B §8).
//
// One algorithm: A's day-counting fixed point, B's merged blocks and
// re-entry grace, a hard cap no calendar bug can exceed, and A's rule that
// reading a streak never rewrites it. The window runs from the MOST RECENT
// sign-in; a new portal-local day counts once (D13).
//
// This module never imports audit.js (§4.2): touchStreak reports a repair in
// status.repaired for completeSignIn to audit, and adjustStreak returns
// { prior, row } for the API handler to audit.

import { toInt, iso, parseIsoStrict, safeJsonParse, MINUTE, HOUR, DAY } from './util.js';
import { ValidationError, GuardError, notFound } from './errors.js';
import {
  dayString,
  parseDayString,
  localDay,
  zonedMidnightUtc,
  makeProtectedDayFn,
  cleanExtraDates,
  isValidTimeZone,
  WEEKDAY_NAMES,
} from './calendar/protected.js';

export const DEFAULT_TIMEZONE = 'America/New_York';
const MAX_ROUNDS = 8;
const MAX_SPAN_DAYS = 31; // valid settings span ≤ 13 days; a bound, not a rule
export const FUTURE_HOLD_MS = 5 * MINUTE;
export const AT_RISK_HOURS = 6;
export const RETAIN_DAYS = 400;
export const MAX_ADJUST = 100000;
const MAX_STORED = 10000000; // a stored count above this is corrupt, not a streak

const LEADERBOARD = ['all', 'managers', 'off'];
const COLS = 'user_id, current, longest, total_days, started_day, last_day, last_at, updated_at';

// ---------------------------------------------------------------- config

// resolvePolicy gives the §5 keys flat (streak_window_hours) and again grouped
// under policy.streak without the prefix (window_hours); flat wins.
function pick(policy, key) {
  if (!policy || typeof policy !== 'object') return undefined;
  try {
    const v = policy[key];
    if (v !== undefined) return v;
    const s = policy.streak;
    return s && typeof s === 'object' ? s[key.replace(/^streak_/, '')] : undefined;
  } catch {
    return undefined;
  }
}

const absent = (v) => v === undefined || v === null;

// Both streak flags read '1' when unrecognised (§5).
function flag(v) {
  if (v === false || v === 0 || v === '0') return false;
  return true;
}

function int(v, min, max, dflt) {
  if (absent(v)) return dflt;
  const n = toInt(v, min, max);
  return Number.isNaN(n) ? dflt : n; // '' is NaN, never 0 (A §14.11)
}

function weeklyDays(v) {
  if (absent(v)) return [6];
  const a = typeof v === 'string' ? safeJsonParse(v, null) : v;
  if (!Array.isArray(a) || a.length > 7 || !a.every((d) => Number.isInteger(d) && d >= 0 && d <= 6)) return [6];
  return [...new Set(a)].sort((x, y) => x - y);
}

// Maps resolvePolicy's streak_* keys and timezone (§5) to the engine's
// config. Missing keys take the §5 default; present-but-unrecognised values
// take the §5 "unrecognised" column. Total: any input yields a usable cfg.
export function streakConfig(policy) {
  const extraRaw = pick(policy, 'streak_extra_dates');
  const extra = typeof extraRaw === 'string' ? safeJsonParse(extraRaw, null) : extraRaw;
  const lb = pick(policy, 'streak_leaderboard');
  const tzIn = pick(policy, 'timezone');
  const tzRaw = absent(tzIn) ? DEFAULT_TIMEZONE : tzIn;
  const cfg = {
    enabled: flag(pick(policy, 'streak_enabled')),
    tz: isValidTimeZone(tzRaw) ? tzRaw : 'UTC',
    baseHours: int(pick(policy, 'streak_window_hours'), 24, 72, 30),
    graceHours: int(pick(policy, 'streak_reentry_grace_hours'), 0, 24, 12),
    maxLeewayDays: int(pick(policy, 'streak_max_leeway_days'), 0, 7, 4),
    weeklyDays: Object.freeze(weeklyDays(pick(policy, 'streak_weekly_days'))),
    hebrew: flag(pick(policy, 'streak_hebrew_holidays')),
    israel: pick(policy, 'streak_region') === 'israel',
    extraDates: Object.freeze(cleanExtraDates(extra).map((e) => Object.freeze(e))),
    leaderboard: absent(lb) ? 'all' : LEADERBOARD.includes(lb) ? lb : 'off',
  };
  cfg.isProtected = makeProtectedDayFn(cfg);
  return Object.freeze(cfg);
}

function inRange(n, lo, hi) {
  return Number.isInteger(n) && n >= lo && n <= hi;
}

let defaultCfg = null;

// Every entry point accepts only a cfg shaped like streakConfig's output
// (tests may swap isProtected); anything else gets the defaults.
function asCfg(cfg) {
  try {
    if (
      cfg &&
      typeof cfg === 'object' &&
      typeof cfg.isProtected === 'function' &&
      typeof cfg.enabled === 'boolean' &&
      isValidTimeZone(cfg.tz) &&
      inRange(cfg.baseHours, 24, 72) &&
      inRange(cfg.graceHours, 0, 24) &&
      inRange(cfg.maxLeewayDays, 0, 7) &&
      Array.isArray(cfg.weeklyDays) &&
      Array.isArray(cfg.extraDates) &&
      typeof cfg.hebrew === 'boolean' &&
      typeof cfg.israel === 'boolean' &&
      LEADERBOARD.includes(cfg.leaderboard)
    ) {
      return cfg;
    }
  } catch {
    /* fall through */
  }
  if (!defaultCfg) defaultCfg = streakConfig(null);
  return defaultCfg;
}

// A calendar that throws or answers nonsense protects nothing.
function prot(c, d) {
  try {
    const r = c.isProtected(d);
    if (r === true) return { protected: true, names: [] };
    if (r && typeof r === 'object' && r.protected === true) {
      return { protected: true, names: Array.isArray(r.names) ? r.names.filter((n) => typeof n === 'string') : [] };
    }
  } catch {
    /* fall through */
  }
  return { protected: false, names: [] };
}

const finite = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : NaN);

function stored(v) {
  const n = toInt(v, 0, MAX_STORED);
  return Number.isNaN(n) ? 0 : n;
}

// ---------------------------------------------------------------- the window

// §9 exactly. Returns ms values; `rounds` (how many rounds ran) is extra, for
// tests and diagnostics. blocks are the protected runs inside the final
// window, lastDay < d ≤ endDay, with their names merged.
export function computeDeadline(lastAtMs, cfg) {
  const c = asCfg(cfg);
  const lastAt = finite(lastAtMs);
  const lastDay = localDay(lastAt, c.tz);
  if (Number.isNaN(lastDay)) return { deadline: NaN, base: NaN, leewayDays: 0, graceApplied: false, blocks: [], rounds: 0 };

  // Signed in DURING a protected block: the clock does not run in protected
  // time (B §8), so the window opens when the block ends. Without this, a
  // sign-in early on Shabbos (Fri 11:30 PM → Mon 5:30 AM, then Sat 12:10 AM →
  // Sun 6:10 AM) moves the deadline EARLIER — a later sign-in must never cost
  // time. The block's own days are consumed here and not counted again below.
  let anchor = lastAt;
  let fromDay = lastDay;
  if (c.maxLeewayDays > 0 && prot(c, lastDay).protected) {
    let end = lastDay;
    while (end - lastDay < c.maxLeewayDays - 1 && prot(c, end + 1).protected) end++;
    const reopen = zonedMidnightUtc(end + 1, c.tz);
    if (Number.isFinite(reopen) && reopen > lastAt) {
      anchor = reopen;
      fromDay = end;
    }
  }

  const base = anchor + c.baseHours * HOUR;
  // A calendar bug can never hand out more than this (A §10 "Cap the leeway"),
  // measured from the sign-in itself so the anchor shift cannot widen it.
  const hardCap = lastAt + c.baseHours * HOUR + c.maxLeewayDays * DAY + c.graceHours * HOUR;
  let deadline = base;
  let leewayDays = 0;
  let graceApplied = false;
  let rounds = 0;
  while (rounds < MAX_ROUNDS) {
    rounds++;
    const endDay = localDay(deadline, c.tz);
    const span = Number.isNaN(endDay) ? 0 : Math.min(endDay - fromDay, MAX_SPAN_DAYS);
    // One answer per day per round, so `count` and `closed` agree.
    const p = [];
    for (let i = 1; i <= span; i++) p[i] = prot(c, fromDay + i).protected;
    let count = 0;
    let closed = null;
    // Each leeway day adds its REAL length — 23 or 25 hours across a clock
    // change — so a sign-in just before a block and one just inside it (whose
    // window opens at the block's real end, above) agree to the minute: the
    // clock does not run in protected time, whatever the clocks do (B §8).
    let leewayMs = 0;
    for (let i = 1; i <= span; i++) {
      if (!p[i]) continue;
      count++;
      if (count <= c.maxLeewayDays) leewayMs += dayLength(fromDay + i, c.tz);
      if (i < span && !p[i + 1]) closed = fromDay + i; // a block that ends inside the window
    }
    const byCount = base + leewayMs;
    let next = byCount;
    if (closed !== null && c.graceHours > 0) {
      // Re-entry grace (B §8): nobody loses a run because a block ended just
      // before their window did. It only ever lengthens the window.
      const reopen = zonedMidnightUtc(closed + 1, c.tz);
      if (Number.isFinite(reopen)) next = Math.max(next, reopen + c.graceHours * HOUR);
    }
    next = Math.min(next, hardCap);
    leewayDays = Math.min(count, c.maxLeewayDays);
    graceApplied = next > byCount;
    if (next === deadline) break; // converged
    deadline = next;
  }
  // `blocks` are the leeway runs after the window opened; `opening` is the run
  // the sign-in itself fell inside (why the window opened late), or null.
  const opening = anchor > lastAt ? blocksIn(c, lastDay - 1, fromDay)[0] || null : null;
  return { deadline, base, leewayDays, graceApplied, blocks: blocksIn(c, fromDay, localDay(deadline, c.tz)), opening, anchor, rounds };
}

// The real length of local day `rd` in ms; a day whose midnights cannot be
// read is a plain 24 hours.
function dayLength(rd, tz) {
  const len = zonedMidnightUtc(rd + 1, tz) - zonedMidnightUtc(rd, tz);
  return Number.isFinite(len) && len > 0 ? len : DAY;
}

function blocksIn(c, lastDay, endDay) {
  const out = [];
  if (Number.isNaN(endDay)) return out;
  let cur = null;
  for (let d = lastDay + 1; d <= Math.min(endDay, lastDay + MAX_SPAN_DAYS); d++) {
    const r = prot(c, d);
    if (!r.protected) {
      cur = null;
      continue;
    }
    if (!cur) {
      cur = { from: dayString(d), to: dayString(d), names: [] };
      out.push(cur);
    }
    cur.to = dayString(d);
    for (const n of r.names) if (!cur.names.includes(n)) cur.names.push(n);
  }
  return out;
}

// ---------------------------------------------------------------- status (pure)

const localFormatters = new Map();

// 'Sun, Jan 11, 12:00 PM' in the portal's zone, with plain spaces (newer ICU
// puts U+202F before AM/PM).
function formatLocal(ms, tz) {
  let f = localFormatters.get(tz);
  if (!f) {
    f = new Intl.DateTimeFormat('en-US', { timeZone: tz, weekday: 'short', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
    if (localFormatters.size >= 64) localFormatters.clear();
    localFormatters.set(tz, f);
  }
  return f.format(ms).replace(/[  ]/g, ' ');
}

function dayOrNull(v) {
  return typeof v === 'string' && !Number.isNaN(parseDayString(v)) ? v : null;
}

// PURE: never writes (A §10 "Read a lapsed streak without rewriting it").
// held (last_at in the future) · lapsed (now past the deadline, or the row is
// unreadable: display 0, longest intact) · paused (today protected, not yet
// counted) · at_risk (not counted today, < 6 h left) · active.
export function streakStatus(row, nowMs, cfg) {
  const c = asCfg(cfg);
  const now = finite(nowMs);
  const todayRd = localDay(now, c.tz);
  const today = dayString(todayRd);
  const pt = today ? prot(c, todayRd) : null;
  const s = {
    state: 'none',
    current: 0,
    stored_current: 0,
    longest: 0,
    total_days: 0,
    counted_today: false,
    last_at: null,
    last_day: null,
    started_day: null,
    deadline: null,
    deadline_local: null,
    hours_left: null,
    protected_today: pt && pt.protected ? { names: pt.names } : null,
    timezone: c.tz,
  };
  if (!row || typeof row !== 'object') return s;

  const lastAt = parseIsoStrict(row.last_at);
  s.stored_current = stored(row.current);
  s.current = s.stored_current;
  s.longest = stored(row.longest);
  s.total_days = stored(row.total_days);
  s.last_at = Number.isNaN(lastAt) ? null : row.last_at;
  s.last_day = dayOrNull(row.last_day);
  s.started_day = dayOrNull(row.started_day);
  s.counted_today = today !== '' && s.last_day === today;

  // Neither expired nor valid forever: hold it where it is (A §11).
  if (lastAt > now + FUTURE_HOLD_MS) {
    s.state = 'held';
    return s;
  }
  const d = computeDeadline(lastAt, c);
  if (Number.isNaN(now) || s.stored_current <= 0 || !Number.isFinite(d.deadline) || now > d.deadline) {
    s.state = 'lapsed';
    s.current = 0;
    if (Number.isFinite(d.deadline)) {
      s.deadline = iso(d.deadline);
      s.deadline_local = formatLocal(d.deadline, c.tz);
    }
    return s;
  }
  s.deadline = iso(d.deadline);
  s.deadline_local = formatLocal(d.deadline, c.tz);
  // Rounded down: never promise time that is not there.
  s.hours_left = Math.floor(((d.deadline - now) / HOUR) * 10) / 10;
  if (!s.counted_today && pt && pt.protected) s.state = 'paused';
  else if (!s.counted_today && d.deadline - now < AT_RISK_HOURS * HOUR) s.state = 'at_risk';
  else s.state = 'active';
  return s;
}

// ---------------------------------------------------------------- touch (sign-in)

function readRow(db, uid) {
  return db.prepare(`SELECT ${COLS} FROM streaks WHERE user_id = ?`).bind(uid).first();
}

// History cell for today — only if the streaks row now carries this very
// sign-in, so a write that lost a race never leaves a cell it did not count.
function dayInsert(db, uid, today, nowIso) {
  return db
    .prepare(
      `INSERT INTO streak_days (user_id, day, first_at)
       SELECT ?, ?, ? WHERE EXISTS (SELECT 1 FROM streaks WHERE user_id = ? AND last_day = ? AND last_at = ?)
       ON CONFLICT(user_id, day) DO NOTHING`,
    )
    .bind(uid, today, nowIso, uid, today, nowIso);
}

// §11: that user's rows older than RETAIN_DAYS, in the same batch as the insert.
function dayPrune(db, uid, todayRd) {
  return db.prepare('DELETE FROM streak_days WHERE user_id = ? AND day < ?').bind(uid, dayString(todayRd - RETAIN_DAYS));
}

function changes(res) {
  return res && res.meta && typeof res.meta.changes === 'number' ? res.meta.changes : 0;
}

// Same local day: last_at = max(last_at, now) and nothing else. Compare-and-
// set on the value read, so a newer last_at written meanwhile never moves back.
async function bumpLastAt(db, row, now, nowIso) {
  const prev = parseIsoStrict(row.last_at);
  if (Number.isNaN(prev) || prev >= now) return;
  await db
    .prepare('UPDATE streaks SET last_at = ?, updated_at = ? WHERE user_id = ? AND last_at IS ?')
    .bind(nowIso, nowIso, row.user_id, row.last_at)
    .run();
}

// Another sign-in won the conditional write: re-read and treat this one as
// same-day, so two sign-ins at once count once (A §11).
async function afterLostRace(db, uid, now, nowIso) {
  const row = await readRow(db, uid);
  if (row) await bumpLastAt(db, row, now, nowIso);
}

// Called by completeSignIn only. NEVER throws: a streak is decoration and
// must not block a sign-in (A §10) — any failure resolves to null. Returns
// null too when streaks are disabled (nothing is recorded). The failure is
// handed to opts.onError, so the caller records the REAL exception in the
// audit log (CONTRACTS §0.4) — this module never imports audit.js.
export async function touchStreak(env, userId, nowMs, cfg, opts = {}) {
  try {
    const uid = toInt(userId, 1);
    const now = finite(nowMs);
    if (Number.isNaN(uid) || Number.isNaN(now)) return null;
    const c = asCfg(cfg);
    if (!c.enabled) return null;
    const db = env.DB;
    const todayRd = localDay(now, c.tz);
    const today = dayString(todayRd);
    if (!today) return null;
    const nowIso = iso(now);
    let repaired = null;

    const row = await readRow(db, uid);
    if (!row) {
      const [ins] = await db.batch([
        db
          .prepare(`INSERT INTO streaks (${COLS}) VALUES (?, 1, 1, 1, ?, ?, ?, ?) ON CONFLICT(user_id) DO NOTHING`)
          .bind(uid, today, today, nowIso, nowIso),
        dayInsert(db, uid, today, nowIso),
        dayPrune(db, uid, todayRd),
      ]);
      if (changes(ins) === 0) await afterLostRace(db, uid, now, nowIso);
    } else {
      const lastAt = parseIsoStrict(row.last_at);
      const lastDayRd = parseDayString(row.last_day);
      const cur = stored(row.current);
      if (Number.isNaN(lastAt)) {
        // No window to continue from. A NULL last_at on a zeroed row is just a
        // restart; anything else is a stored value we cannot read — present
        // but unreadable, so restart (never extend) and report it (§9).
        const unreadable = row.last_at !== null || cur > 0;
        const alreadyCounted = lastDayRd >= todayRd;
        const res = await db.batch([
          db
            .prepare(
              `UPDATE streaks SET current = 1, longest = ?, total_days = ?, started_day = ?, last_day = ?, last_at = ?, updated_at = ?
               WHERE user_id = ? AND last_at IS ?`,
            )
            .bind(Math.max(stored(row.longest), 1), stored(row.total_days) + (alreadyCounted ? 0 : 1), today, today, nowIso, nowIso, uid, row.last_at),
          dayInsert(db, uid, today, nowIso),
          dayPrune(db, uid, todayRd),
        ]);
        if (changes(res[0]) === 0) await afterLostRace(db, uid, now, nowIso);
        else if (unreadable) repaired = 'unreadable_last_at';
      } else if (lastAt > now + FUTURE_HOLD_MS) {
        return streakStatus(row, now, c); // held: change nothing (A §11)
      } else if (lastDayRd > todayRd) {
        await bumpLastAt(db, row, now, nowIso); // a zone change put today behind last_day
      } else if (lastDayRd === todayRd) {
        // Same day. Usually last_at moves and nothing else — but a real
        // sign-in is always LOGGED: an administrator's adjustment claims today
        // without a streak_days row, so the first sign-in of the day writes it
        // and counts it in total_days. And a stored current of 0 (set to 0
        // today) restarts at 1, as "your next sign-in starts a new streak" says.
        const restart = cur <= 0 ? 1 : 0;
        const res = await db.batch([
          db
            .prepare(
              `UPDATE streaks SET
                 total_days = total_days + (NOT EXISTS (SELECT 1 FROM streak_days WHERE user_id = ? AND day = ?)),
                 current = CASE WHEN ? THEN 1 ELSE current END,
                 longest = CASE WHEN ? THEN MAX(longest, 1) ELSE longest END,
                 started_day = CASE WHEN ? THEN ? ELSE started_day END,
                 last_at = CASE WHEN last_at < ? THEN ? ELSE last_at END,
                 updated_at = ?
               WHERE user_id = ? AND last_day IS ? AND last_at IS ? AND current IS ?`,
            )
            .bind(uid, today, restart, restart, restart, today, nowIso, nowIso, nowIso, uid, row.last_day, row.last_at, row.current),
          db
            .prepare(
              `INSERT INTO streak_days (user_id, day, first_at)
               SELECT ?, ?, ? WHERE EXISTS (SELECT 1 FROM streaks WHERE user_id = ? AND last_day = ?)
               ON CONFLICT(user_id, day) DO NOTHING`,
            )
            .bind(uid, today, nowIso, uid, today),
        ]);
        if (changes(res[0]) === 0) await afterLostRace(db, uid, now, nowIso);
      } else {
        const continues = now <= computeDeadline(lastAt, c).deadline;
        const current = continues ? cur + 1 : 1;
        const started = continues && cur > 0 && dayOrNull(row.started_day) ? row.started_day : today;
        const res = await db.batch([
          db
            .prepare(
              `UPDATE streaks SET current = ?, longest = ?, total_days = ?, started_day = ?, last_day = ?, last_at = ?, updated_at = ?
               WHERE user_id = ? AND last_day IS ?`,
            )
            .bind(current, Math.max(stored(row.longest), current), stored(row.total_days) + 1, started, today, nowIso, nowIso, uid, row.last_day),
          dayInsert(db, uid, today, nowIso),
          dayPrune(db, uid, todayRd),
        ]);
        if (changes(res[0]) === 0) await afterLostRace(db, uid, now, nowIso);
      }
    }

    const after = await readRow(db, uid);
    if (!after) return null;
    const status = streakStatus(after, now, c);
    if (repaired) status.repaired = repaired;
    return status;
  } catch (e) {
    console.error('[streak] touch failed:', e && e.message ? e.message : e);
    if (typeof opts?.onError === 'function') {
      try {
        await opts.onError(e);
      } catch {
        /* the reporter must not turn a swallowed failure into a thrown one */
      }
    }
    return null;
  }
}

// ---------------------------------------------------------------- reads

export async function getStreak(env, userId, nowMs, cfg) {
  const c = asCfg(cfg);
  const uid = toInt(userId, 1);
  const row = Number.isNaN(uid) ? null : await readRow(env.DB, uid);
  return streakStatus(row, nowMs, c);
}

// `days` cells ending today, oldest first. "Missed" is derived by the page:
// not counted, not protected, not today.
export async function streakHistory(env, userId, nowMs, cfg, days = 84) {
  const c = asCfg(cfg);
  const uid = toInt(userId, 1);
  const n = toInt(days, 1, RETAIN_DAYS);
  const len = Number.isNaN(n) ? 84 : n;
  const todayRd = localDay(finite(nowMs), c.tz);
  if (Number.isNaN(todayRd)) return [];
  const from = todayRd - (len - 1);
  const counted = new Set();
  if (!Number.isNaN(uid)) {
    const rs = await env.DB.prepare('SELECT day FROM streak_days WHERE user_id = ? AND day >= ? AND day <= ?')
      .bind(uid, dayString(from), dayString(todayRd))
      .all();
    for (const r of rs.results || []) counted.add(r.day);
  }
  const out = [];
  for (let d = from; d <= todayRd; d++) {
    const day = dayString(d);
    const p = prot(c, d);
    out.push({ day, counted: counted.has(day), protected: p.protected, names: p.names, today: d === todayRd, future: false });
  }
  return out;
}

// Protected days in the next `days` days, starting tomorrow.
export function upcomingProtected(cfg, nowMs, days = 21) {
  const c = asCfg(cfg);
  const n = toInt(days, 1, 366);
  const len = Number.isNaN(n) ? 21 : n;
  const todayRd = localDay(finite(nowMs), c.tz);
  if (Number.isNaN(todayRd)) return [];
  const out = [];
  for (let d = todayRd + 1; d <= todayRd + len; d++) {
    const p = prot(c, d);
    if (p.protected) out.push({ day: dayString(d), names: p.names });
  }
  return out;
}

const collator = new Intl.Collator('en', { sensitivity: 'base' });

// Active people only, ranked by what they would SEE (a lapsed streak is 0
// and left off), then longest, then name. Whether to show it at all
// (cfg.leaderboard) is the caller's decision.
export async function leaderboard(env, nowMs, cfg, limit = 10) {
  const c = asCfg(cfg);
  const n = toInt(limit, 1, 100);
  const max = Number.isNaN(n) ? 10 : n;
  const rs = await env.DB.prepare(
    `SELECT s.user_id, s.current, s.longest, s.total_days, s.started_day, s.last_day, s.last_at, s.updated_at, u.full_name
     FROM streaks s JOIN users u ON u.id = s.user_id
     WHERE u.status = 'active' AND s.current > 0`,
  ).all();
  const out = [];
  for (const r of rs.results || []) {
    const st = streakStatus(r, nowMs, c);
    if (st.current > 0) {
      out.push({
        user_id: r.user_id,
        full_name: typeof r.full_name === 'string' ? r.full_name : '',
        current: st.current,
        longest: Math.max(st.longest, st.current),
      });
    }
  }
  out.sort(
    (a, b) =>
      b.current - a.current ||
      b.longest - a.longest ||
      collator.compare(a.full_name, b.full_name) ||
      (a.full_name < b.full_name ? -1 : a.full_name > b.full_name ? 1 : 0) ||
      a.user_id - b.user_id,
  );
  return out.slice(0, max);
}

// ---------------------------------------------------------------- admin

// Restore or adjust (e.g. after an outage). current > 0 opens a fresh window
// from now with today counted; current 0 leaves the window fields alone.
// Guards only — the API handler audits, with undoFor('streak', { userId, prior }).
export async function adjustStreak(env, userId, input, nowMs, cfg) {
  const c = asCfg(cfg);
  const uid = toInt(userId, 1);
  if (Number.isNaN(uid)) throw new ValidationError('Choose a person.', 'user_id');
  const body = input && typeof input === 'object' ? input : {};
  const current = toInt(body.current, 0, MAX_ADJUST);
  if (Number.isNaN(current)) throw new ValidationError(`Current streak must be a whole number from 0 to ${MAX_ADJUST}.`, 'current');
  const longestIn = body.longest === undefined ? undefined : toInt(body.longest, 0, MAX_ADJUST);
  if (Number.isNaN(longestIn)) throw new ValidationError(`Longest streak must be a whole number from 0 to ${MAX_ADJUST}.`, 'longest');
  const now = finite(nowMs);
  const todayRd = localDay(now, c.tz);
  if (Number.isNaN(todayRd)) throw new Error('adjustStreak: unusable clock');

  const db = env.DB;
  const user = await db.prepare('SELECT id FROM users WHERE id = ?').bind(uid).first();
  if (!user) throw notFound('No such person.');
  const prior = await readRow(db, uid);
  const longest = Math.max(longestIn === undefined ? (prior ? stored(prior.longest) : 0) : longestIn, current);
  const nowIso = iso(now);
  let started = prior ? prior.started_day : null;
  let lastDay = prior ? prior.last_day : null;
  let lastAt = prior ? prior.last_at : null;
  if (current > 0) {
    lastAt = nowIso;
    lastDay = dayString(todayRd);
    started = dayString(todayRd - (current - 1)) || null;
  }
  await db
    .prepare(
      `INSERT INTO streaks (${COLS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(user_id) DO UPDATE SET current = excluded.current, longest = excluded.longest,
         started_day = excluded.started_day, last_day = excluded.last_day, last_at = excluded.last_at,
         updated_at = excluded.updated_at`,
    )
    .bind(uid, current, longest, prior ? stored(prior.total_days) : 0, started, lastDay, lastAt, nowIso)
    .run();
  return { prior: prior || null, row: await readRow(db, uid) };
}

function isoOrNull(v) {
  return v === null || (typeof v === 'string' && !Number.isNaN(parseIsoStrict(v)));
}

function dayOrNullOk(v) {
  return v === null || dayOrNull(v) !== null;
}

// The columns an adjustment writes and a restore compares.
export const STREAK_FIELDS = Object.freeze(['current', 'longest', 'total_days', 'started_day', 'last_day', 'last_at']);

function changedSince() {
  return new GuardError(
    'changed_since',
    'Their streak has changed since then — they signed in, or it was adjusted again — so putting the old one back would wipe what they earned. Adjust it by hand instead.',
    409,
  );
}

// Matches the live row exactly as read, so a sign-in landing between the
// read and the write makes the write change nothing.
const UNCHANGED = STREAK_FIELDS.map((k) => `${k} IS ?`).join(' AND ');

// The reverter for undo kind 'streak' (§4.2.1): put the prior row back, or
// delete the row when there was none. The snapshot is re-validated because it
// came out of storage. Returns { prior: the row it replaced, row }.
//
// opts.expect: the columns the adjustment being undone wrote. Unless the live
// row still holds exactly those, the person has signed in (or been adjusted)
// since, and the snapshot would silently overwrite the days they earned —
// total_days included, which nothing else can set back (SPEC §10.18). So the
// restore is refused (409 changed_since), as an 'mfa.reset' revert is when
// they have enrolled since.
export async function restoreStreak(env, userId, prior, nowMs, opts = {}) {
  const uid = toInt(userId, 1);
  if (Number.isNaN(uid)) throw new ValidationError('Choose a person.', 'user_id');
  const now = finite(nowMs);
  if (Number.isNaN(now)) throw new Error('restoreStreak: unusable clock');
  const db = env.DB;
  const before = await readRow(db, uid);
  const expect = opts && typeof opts.expect === 'object' && opts.expect !== null ? opts.expect : null;
  if (expect && (!before || STREAK_FIELDS.some((k) => expect[k] !== undefined && expect[k] !== before[k]))) throw changedSince();
  const asRead = before ? STREAK_FIELDS.map((k) => before[k]) : null;
  if (prior === null || prior === undefined) {
    const del = before
      ? await db.prepare(`DELETE FROM streaks WHERE user_id = ? AND ${UNCHANGED}`).bind(uid, ...asRead).run()
      : null;
    if (expect && changes(del) !== 1) throw changedSince();
    return { prior: before || null, row: null };
  }
  const p = typeof prior === 'object' && !Array.isArray(prior) ? prior : {};
  const cur = toInt(p.current, 0, MAX_STORED);
  const lon = toInt(p.longest, 0, MAX_STORED);
  const tot = toInt(p.total_days, 0, MAX_STORED);
  const started = p.started_day ?? null;
  const lastDay = p.last_day ?? null;
  const lastAt = p.last_at ?? null;
  if (Number.isNaN(cur) || Number.isNaN(lon) || Number.isNaN(tot) || !dayOrNullOk(started) || !dayOrNullOk(lastDay) || !isoOrNull(lastAt)) {
    throw new ValidationError('That streak snapshot is unreadable.');
  }
  const t = iso(now);
  const res = asRead
    ? await db
        .prepare(
          `UPDATE streaks SET current = ?, longest = ?, total_days = ?, started_day = ?, last_day = ?, last_at = ?, updated_at = ?
           WHERE user_id = ? AND ${UNCHANGED}`,
        )
        .bind(cur, lon, tot, started, lastDay, lastAt, t, uid, ...asRead)
        .run()
    : await db
        .prepare(`INSERT INTO streaks (${COLS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(user_id) DO NOTHING`)
        .bind(uid, cur, lon, tot, started, lastDay, lastAt, t)
        .run();
  if (changes(res) !== 1) throw changedSince();
  return { prior: before || null, row: await readRow(db, uid) };
}

// ---------------------------------------------------------------- rules

function describeCalendar(c) {
  const parts = c.weeklyDays.map((d) => (d === 6 && c.hebrew ? 'Shabbos' : `${WEEKDAY_NAMES[d]}s`));
  if (c.hebrew) parts.push(`Yom Tov (${c.israel ? 'Israel' : 'diaspora'})`);
  if (c.extraDates.length) parts.push(`${c.extraDates.length} extra date${c.extraDates.length === 1 ? '' : 's'}`);
  if (!parts.length) return 'No protected days';
  return parts.length === 1 ? parts[0] : `${parts.slice(0, -1).join(', ')} and ${parts[parts.length - 1]}`;
}

export function streakRules(cfg) {
  const c = asCfg(cfg);
  return {
    window_hours: c.baseHours,
    reentry_grace_hours: c.graceHours,
    max_leeway_days: c.maxLeewayDays,
    calendar: describeCalendar(c),
  };
}
