// Local calendar days, time zones, and the "is this day protected?" function
// the streak window stretches around (A §10, B §8).
//
// Days are fixed day numbers (RD, see hebrew.js) in the portal's zone. An
// instant becomes a local day through Intl with an explicit timeZone, then
// arithmetic — never Date objects with local offsets, which DST eats
// (A §10 "Use the portal's timezone, not UTC").

import { fixedFromGregorian, gregorianFromFixed, weekday, yomTovName } from './hebrew.js';
import { toInt, strStrict, SECOND, MINUTE, HOUR, DAY } from '../util.js';

const UNIX_EPOCH_RD = 719163; // fixedFromGregorian(1970, 1, 1)

// Years 1–9999 only: four-digit day strings, and formatToParts drops the era
// so a BCE year would read as CE. The margins keep any UTC offset (≤ ±15h,
// counting historical local mean time) inside the range.
const MIN_RD = fixedFromGregorian(1, 1, 3);
const MAX_RD = fixedFromGregorian(9999, 12, 29);
const MIN_MS = (MIN_RD - UNIX_EPOCH_RD) * DAY;
const MAX_MS = (MAX_RD - UNIX_EPOCH_RD) * DAY;

// ---------------------------------------------------------------- day strings

export function dayString(rd) {
  if (!Number.isSafeInteger(rd)) return '';
  const { year, month, day } = gregorianFromFixed(rd);
  if (!(year >= 1 && year <= 9999)) return '';
  return `${String(year).padStart(4, '0')}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
}

const DAY_RE = /^(\d{4})-(\d{2})-(\d{2})$/;

// Strict: exactly YYYY-MM-DD naming a real date ('2026-02-30' is NaN).
export function parseDayString(s) {
  if (typeof s !== 'string') return NaN;
  const m = DAY_RE.exec(s);
  if (!m) return NaN;
  const y = toInt(m[1], 1, 9999);
  const mo = toInt(m[2], 1, 12);
  const d = toInt(m[3], 1, 31);
  if (Number.isNaN(y) || Number.isNaN(mo) || Number.isNaN(d)) return NaN;
  const rd = fixedFromGregorian(y, mo, d);
  const back = gregorianFromFixed(rd);
  return back.year === y && back.month === mo && back.day === d ? rd : NaN;
}

// ---------------------------------------------------------------- time zones

// tz → { tz, day, wall } (formatters) or null when Intl refuses the name.
// Bounded: the zone comes from a setting, but nothing here should grow forever.
const zones = new Map();

function zone(tz) {
  if (typeof tz !== 'string' || tz.length === 0 || tz.length > 64) return null;
  let z = zones.get(tz);
  if (z === undefined) {
    try {
      z = {
        tz,
        day: new Intl.DateTimeFormat('en-US', { timeZone: tz, year: 'numeric', month: 'numeric', day: 'numeric' }),
        wall: null,
      };
    } catch {
      z = null;
    }
    if (zones.size >= 64) zones.clear();
    zones.set(tz, z);
  }
  return z;
}

// Whatever Intl accepts. The name is kept as given, not canonicalised: ICU's
// canonical ids are sometimes the legacy ones (Asia/Kolkata → Asia/Calcutta).
export function isValidTimeZone(tz) {
  return zone(tz) !== null;
}

function partsOf(dtf, ms) {
  const o = {};
  for (const p of dtf.formatToParts(ms)) o[p.type] = p.value;
  return o;
}

export function localDay(ms, tz) {
  if (typeof ms !== 'number' || !(ms >= MIN_MS && ms <= MAX_MS)) return NaN;
  const z = zone(tz);
  if (!z) return NaN;
  const p = partsOf(z.day, ms);
  return fixedFromGregorian(toInt(p.year), toInt(p.month), toInt(p.day));
}

// The wall-clock reading at instant t, expressed as if it were UTC, to the
// second. wallMs(t) − t is the zone's offset at t.
function wallMs(z, t) {
  if (!z.wall) {
    z.wall = new Intl.DateTimeFormat('en-US', {
      timeZone: z.tz,
      hourCycle: 'h23',
      year: 'numeric',
      month: 'numeric',
      day: 'numeric',
      hour: 'numeric',
      minute: 'numeric',
      second: 'numeric',
    });
  }
  const p = partsOf(z.wall, t);
  const rd = fixedFromGregorian(toInt(p.year), toInt(p.month), toInt(p.day));
  // % 24: engines that ignore hourCycle print midnight as "24" on the same date.
  return (rd - UNIX_EPOCH_RD) * DAY + (toInt(p.hour) % 24) * HOUR + toInt(p.minute) * MINUTE + toInt(p.second) * SECOND;
}

// The first instant of local day rd: the earliest instant whose wall clock
// reads 00:00:00 on rd, tried with each offset in force within a day either
// side (so a DST change on the day itself, or the day before, is covered).
//
// When no instant reads midnight — the zone skips it, e.g. America/Santiago
// on 2025-09-07 jumps 23:59:59 → 01:00 — the day began at the transition, so
// bisect for the first whole second whose local day is ≥ rd. The same search
// gives a local day that never happened (Pacific/Apia skipped 2011-12-30) the
// first instant of the next day that did: the instant the skipped day would
// have begun, and therefore the moment the day before it ended. Never NaN for
// a valid zone inside the supported range.
export function zonedMidnightUtc(rd, tz) {
  if (!Number.isSafeInteger(rd) || rd < MIN_RD + 1 || rd > MAX_RD - 1) return NaN;
  const z = zone(tz);
  if (!z) return NaN;
  const wall = (rd - UNIX_EPOCH_RD) * DAY;
  let best = NaN;
  for (const probe of [wall - DAY, wall, wall + DAY]) {
    const t = wall - (wallMs(z, probe) - probe);
    if (wallMs(z, t) === wall && (Number.isNaN(best) || t < best)) best = t;
  }
  if (!Number.isNaN(best)) return best;
  let lo = wall - 16 * HOUR;
  let hi = wall + 16 * HOUR;
  if (!(localDay(lo, tz) < rd && localDay(hi, tz) >= rd)) return NaN;
  while (hi - lo > SECOND) {
    const mid = lo + Math.floor((hi - lo) / 2 / SECOND) * SECOND;
    if (localDay(mid, tz) >= rd) hi = mid;
    else lo = mid;
  }
  return hi;
}

// ---------------------------------------------------------------- protected days

export const WEEKDAY_NAMES = Object.freeze(['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']);
export const MAX_EXTRA_DATES = 366;

const NOT_PROTECTED = Object.freeze({ protected: false, names: Object.freeze([]) });

// [{ date: 'YYYY-MM-DD', label }] with every unusable entry dropped: a date
// that is not strictly a real day, or a label that is not 1–100 characters.
// At most MAX_EXTRA_DATES entries are read.
export function cleanExtraDates(list) {
  if (!Array.isArray(list)) return [];
  const out = [];
  for (const e of list.slice(0, MAX_EXTRA_DATES)) {
    if (!e || typeof e !== 'object' || Array.isArray(e)) continue;
    const date = typeof e.date === 'string' && !Number.isNaN(parseDayString(e.date)) ? e.date : null;
    const label = strStrict(e.label, 1, 100);
    if (date && label) out.push({ date, label });
  }
  return out;
}

// cfg: { weeklyDays: number[], hebrew: bool, israel: bool, extraDates }.
// Anything malformed protects nothing rather than everything: the hard cap in
// streak.js bounds the damage either way, but a calendar that silently
// protects every day reads as a streak nobody can lose.
export function makeProtectedDayFn(cfg) {
  const c = cfg && typeof cfg === 'object' ? cfg : {};
  const weekly = new Set(Array.isArray(c.weeklyDays) ? c.weeklyDays.filter((d) => Number.isInteger(d) && d >= 0 && d <= 6) : []);
  const hebrew = c.hebrew === true;
  const opts = { israel: c.israel === true };
  const extras = new Map();
  for (const { date, label } of cleanExtraDates(c.extraDates)) {
    const rd = parseDayString(date);
    if (!extras.has(rd)) extras.set(rd, []);
    extras.get(rd).push(label);
  }
  const memo = new Map();
  return function isProtected(rd) {
    if (!Number.isSafeInteger(rd)) return NOT_PROTECTED;
    let v = memo.get(rd);
    if (v) return v;
    const names = [];
    const wd = weekday(rd);
    if (weekly.has(wd)) names.push(wd === 6 && hebrew ? 'Shabbos' : WEEKDAY_NAMES[wd]);
    if (hebrew) {
      const yt = yomTovName(rd, opts);
      if (yt) names.push(yt);
    }
    if (extras.has(rd)) names.push(...extras.get(rd));
    const unique = [...new Set(names)];
    v = unique.length ? Object.freeze({ protected: true, names: Object.freeze(unique) }) : NOT_PROTECTED;
    if (memo.size >= 4096) memo.clear();
    memo.set(rd, v);
    return v;
  };
}
