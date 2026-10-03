// The settings registry (CONTRACTS §5). Every knob has a default for when the
// row is absent and a separate value for when it is present but unreadable —
// always the RESTRICTIVE choice (A §3, §14.1–14.3). A corrupt row, a
// half-written value or a string from a future release must never widen
// access.
//
// parse(raw) reads a stored string; serialize(input) validates a submitted
// value and returns the string to store. Blank strings, null, booleans and
// objects are validation errors, never defaults (A §14.1); an explicit 0
// stays legal where the range allows it (A §14.11).

import { ValidationError } from './errors.js';
import { now, iso, toInt, strStrict, parseIsoStrict, HOUR } from './util.js';

export const DEFAULT_PRIVACY_NOTICE =
  'To keep staff accounts safe, this portal records technical details of each visit: your IP address and approximate location, and characteristics of your device and browser.';

const COUNTRY_RE = /^[A-Z]{2}$/;
const DAY_RE = /^(\d{4})-(\d{2})-(\d{2})$/;
const INT_RE = /^-?\d{1,9}$/;
const MAX_COUNTRIES = 300;
const MAX_EXTRA_DATES = 366;
// The gate endpoint takes 1–168 hours; refuse a longer instant here too, so
// no caller can store "open for sixteen years" (A §14.2).
const GATE_MAX_MS = 168 * HOUR;

// A present row whose value is not a string: unreadable, not absent.
const UNREADABLE = Symbol('unreadable');

function deepFreeze(v) {
  if (v && typeof v === 'object') {
    for (const k of Object.keys(v)) deepFreeze(v[k]);
    Object.freeze(v);
  }
  return v;
}

// Callers get their own copy; the registry's values are frozen.
function copy(v) {
  return v && typeof v === 'object' ? JSON.parse(JSON.stringify(v)) : v;
}

function missing(raw) {
  return raw === undefined || raw === null;
}

function isPlainObject(v) {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

function define(key, spec) {
  const entry = { key, ...spec, default: deepFreeze(spec.default), unrecognised: deepFreeze(spec.unrecognised) };
  if (entry.options) entry.options = Object.freeze([...entry.options]);
  return Object.freeze(entry);
}

// ---------------------------------------------------------------- types

function enumSetting(key, { label, options, def, unrec, perm, description }) {
  return define(key, {
    type: 'enum',
    label,
    options,
    default: def,
    unrecognised: unrec,
    perm,
    description,
    parse(raw) {
      if (missing(raw)) return def;
      return typeof raw === 'string' && options.includes(raw) ? raw : unrec;
    },
    serialize(input) {
      if (typeof input === 'string' && options.includes(input)) return input;
      throw new ValidationError(`${label} must be one of: ${options.join(', ')}.`, key);
    },
  });
}

function flagSetting(key, { label, def, unrec, perm, description }) {
  return define(key, {
    type: 'flag',
    label,
    default: def,
    unrecognised: unrec,
    perm,
    description,
    parse(raw) {
      if (missing(raw)) return def;
      if (raw === '1') return true;
      if (raw === '0') return false;
      return unrec;
    },
    serialize(input) {
      if (input === true || input === 1 || input === '1') return '1';
      if (input === false || input === 0 || input === '0') return '0';
      throw new ValidationError(`${label} must be on or off.`, key);
    },
  });
}

function intSetting(key, { label, min, max, def, unrec, perm, description }) {
  return define(key, {
    type: 'int',
    label,
    min,
    max,
    default: def,
    unrecognised: unrec,
    perm,
    description,
    parse(raw) {
      if (missing(raw)) return def;
      if (typeof raw !== 'string' || !INT_RE.test(raw)) return unrec;
      const n = toInt(raw, min, max);
      return Number.isFinite(n) ? n : unrec;
    },
    serialize(input) {
      // toInt already refuses null, '', whitespace, booleans and objects.
      const n = typeof input === 'number' || typeof input === 'string' ? toInt(input, min, max) : NaN;
      if (!Number.isFinite(n)) throw new ValidationError(`${label} must be a whole number from ${min} to ${max}.`, key);
      return String(n);
    },
  });
}

// A json-list setting: `check(list, strict)` returns the canonical list or
// null. strict = reading a stored value, which serialize wrote canonically.
function listSetting(key, { label, def, unrec, perm, description, check, read = (l) => l }) {
  return define(key, {
    type: 'json-list',
    label,
    default: def,
    unrecognised: unrec,
    perm,
    description,
    parse(raw) {
      if (missing(raw)) return copy(def);
      if (typeof raw !== 'string') return copy(unrec);
      let v;
      try {
        v = JSON.parse(raw);
      } catch {
        return copy(unrec);
      }
      const list = check(v, true);
      return list ? read(list) : copy(unrec);
    },
    serialize(input) {
      // A JSON string is not accepted: the caller sends the array itself.
      const list = check(input, false);
      if (!list) throw new ValidationError(`${label}: ${description}`, key);
      return JSON.stringify(list);
    },
  });
}

function checkCountries(v, strict) {
  if (!Array.isArray(v) || v.length > MAX_COUNTRIES) return null;
  const out = new Set();
  for (const x of v) {
    if (typeof x !== 'string') return null;
    const c = strict ? x : x.trim().toUpperCase();
    if (!COUNTRY_RE.test(c)) return null;
    out.add(c);
  }
  return [...out].sort();
}

function checkWeekdays(v, strict) {
  if (!Array.isArray(v) || v.length > 64) return null;
  const out = new Set();
  for (const x of v) {
    const d = strict ? (Number.isInteger(x) && x >= 0 && x <= 6 ? x : NaN) : toInt(x, 0, 6);
    if (!Number.isFinite(d)) return null;
    out.add(d);
  }
  return [...out].sort((a, b) => a - b);
}

export function isRealDate(s) {
  const m = typeof s === 'string' ? DAY_RE.exec(s) : null;
  if (!m) return false;
  const y = toInt(m[1]);
  const mo = toInt(m[2]);
  const d = toInt(m[3]);
  if (y < 1 || mo < 1 || mo > 12 || d < 1) return false;
  const leap = (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
  const dim = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1];
  return d <= dim;
}

function checkExtraDates(v) {
  if (!Array.isArray(v) || v.length > MAX_EXTRA_DATES) return null;
  const out = [];
  for (const x of v) {
    if (!isPlainObject(x) || !isRealDate(x.date)) return null;
    const label = strStrict(x.label, 1, 60);
    if (label === null) return null;
    out.push({ date: x.date, label });
  }
  return out.sort((a, b) => (a.date < b.date ? -1 : a.date > b.date ? 1 : 0));
}

const tzCache = new Map();

// The zone's canonical name, or null if Intl refuses it.
export function canonicalTimeZone(tz) {
  if (typeof tz !== 'string' || !tz || tz.length > 64) return null;
  if (tzCache.has(tz)) return tzCache.get(tz);
  let out = null;
  try {
    out = new Intl.DateTimeFormat('en-US', { timeZone: tz }).resolvedOptions().timeZone || null;
  } catch {
    out = null;
  }
  if (tzCache.size > 256) tzCache.clear();
  tzCache.set(tz, out);
  return out;
}

// ---------------------------------------------------------------- the gate

// '0' closed · '1' open until closed · a strict ISO instant in the future →
// open until then · ANYTHING else closed. Date.parse('42') is 2042, so the
// shape is checked first (A §14.2), and a falsy value never opens (§14.1).
export function gateOpenState(raw, nowMs) {
  if (raw === '1') return { open: true, until: null, forever: true };
  if (typeof raw === 'string' && raw !== '0') {
    const until = parseIsoStrict(raw);
    if (Number.isFinite(until) && typeof nowMs === 'number' && Number.isFinite(nowMs) && until > nowMs) {
      return { open: true, until, forever: false };
    }
  }
  return { open: false, until: null, forever: false };
}

function gateSetting(key, { label, perm, description }) {
  const closed = { open: false, until: null, forever: false, raw: null };
  return define(key, {
    type: 'gate',
    label,
    default: closed,
    unrecognised: closed,
    perm,
    description,
    // Unlike the others this needs the time: parse(raw, nowMs).
    parse(raw, nowMs) {
      return { ...gateOpenState(raw, nowMs), raw: typeof raw === 'string' ? raw : null };
    },
    serialize(input) {
      if (input === '0' || input === '1') return input;
      const ms = parseIsoStrict(input);
      if (Number.isFinite(ms)) return iso(ms);
      throw new ValidationError(`${label} must be '0', '1' or an ISO-8601 instant.`, key);
    },
  });
}

// ---------------------------------------------------------------- registry

const SEC = 'security.manage';
const GEN = 'settings.manage';

export const SETTINGS = Object.freeze({
  access_mode: enumSetting('access_mode', {
    label: 'Access mode',
    options: ['public', 'fingerprint_gate', 'request_access', 'allowlist', 'invite_only', 'lockdown'],
    def: 'allowlist',
    unrec: 'lockdown',
    perm: SEC,
    description: 'Who may reach the portal at all: anyone, fingerprinted browsers, requesters, known networks and devices, invitees, or Super Admins only.',
  }),
  deny_style: enumSetting('deny_style', {
    label: 'Refusal style',
    options: ['empty', 'decoy'],
    def: 'empty',
    unrec: 'empty',
    perm: SEC,
    description: 'What a refused visitor sees: an empty 403, or a decoy 404 that looks like a stock server page.',
  }),
  gate_open: gateSetting('gate_open', {
    label: 'Open to the internet',
    perm: 'gate.open',
    description: 'Lets everyone past the network gate until a set time or until closed. Changed only from the gate controls.',
  }),
  country_allow: listSetting('country_allow', {
    label: 'Allowed countries',
    def: null,
    unrec: [],
    perm: SEC,
    description: 'A list of two-letter country codes; an empty list means no restriction.',
    check: checkCountries,
    // [] stored means "no restriction"; the resolved value says so with null,
    // keeping [] for the unrecognised case, which allows nobody.
    read: (l) => (l.length ? l : null),
  }),
  country_deny: listSetting('country_deny', {
    label: 'Blocked countries',
    def: [],
    unrec: ['*'],
    perm: SEC,
    description: 'A list of two-letter country codes to refuse.',
    check: checkCountries,
  }),
  block_tor: flagSetting('block_tor', {
    label: 'Block Tor',
    def: true,
    unrec: true,
    perm: SEC,
    description: 'Refuse visitors arriving through Tor exit nodes.',
  }),
  block_datacenter: flagSetting('block_datacenter', {
    label: 'Block datacenters',
    def: false,
    unrec: true,
    perm: SEC,
    description: 'Refuse visitors whose network belongs to a hosting or cloud provider.',
  }),
  block_automation: flagSetting('block_automation', {
    label: 'Block automation',
    def: true,
    unrec: true,
    perm: SEC,
    description: 'Refuse browsers that show signs of being driven by a script (WebDriver, headless).',
  }),
  risk_threshold: intSetting('risk_threshold', {
    label: 'Risk threshold',
    min: 1,
    max: 100,
    def: 70,
    unrec: 50,
    perm: SEC,
    description: 'Refuse a visitor whose risk score is at or above this number.',
  }),
  mfa_policy: enumSetting('mfa_policy', {
    label: 'Second factor policy',
    options: ['prompt', 'required'],
    def: 'prompt',
    unrec: 'required',
    perm: SEC,
    description: 'Whether people without a second factor are prompted to add one, or pinned to enrolment until they do.',
  }),
  mfa_grace: flagSetting('mfa_grace', {
    label: 'Second factor grace windows',
    def: true,
    unrec: false,
    perm: SEC,
    description: 'Skip the second factor on a device that recently passed one from a trusted network.',
  }),
  device_gating: flagSetting('device_gating', {
    label: 'Device approval',
    def: false,
    unrec: true,
    perm: GEN,
    description: 'Require each browser to be approved before it can be used.',
  }),
  step_up_minutes: intSetting('step_up_minutes', {
    label: 'Step-up window',
    min: 1,
    max: 120,
    def: 15,
    unrec: 5,
    perm: GEN,
    description: 'Minutes a second-factor check stays fresh for dangerous actions.',
  }),
  session_idle_minutes: intSetting('session_idle_minutes', {
    label: 'Idle timeout',
    min: 5,
    max: 1440,
    def: 120,
    unrec: 30,
    perm: GEN,
    description: 'Minutes without activity before a session ends.',
  }),
  session_absolute_hours: intSetting('session_absolute_hours', {
    label: 'Session length',
    min: 1,
    max: 72,
    def: 8,
    unrec: 8,
    perm: GEN,
    description: 'Hours after sign-in when a session ends regardless of activity.',
  }),
  timezone: define('timezone', {
    type: 'timezone',
    label: 'Time zone',
    default: 'America/New_York',
    unrecognised: 'UTC',
    perm: GEN,
    description: 'The IANA time zone for dates, streak days and deadlines.',
    parse(raw) {
      if (missing(raw)) return 'America/New_York';
      return canonicalTimeZone(raw) || 'UTC';
    },
    serialize(input) {
      const tz = canonicalTimeZone(strStrict(input, 1, 64));
      if (!tz) throw new ValidationError('Time zone must be an IANA zone name such as America/New_York.', 'timezone');
      return tz;
    },
  }),
  privacy_notice: flagSetting('privacy_notice', {
    label: 'Privacy notice',
    def: true,
    unrec: true,
    perm: GEN,
    description: 'Show a one-line notice that visits are fingerprinted.',
  }),
  privacy_notice_text: define('privacy_notice_text', {
    type: 'string',
    label: 'Privacy notice text',
    max: 500,
    default: DEFAULT_PRIVACY_NOTICE,
    unrecognised: DEFAULT_PRIVACY_NOTICE,
    perm: GEN,
    description: 'The wording of the privacy notice, up to 500 characters.',
    parse(raw) {
      if (missing(raw)) return DEFAULT_PRIVACY_NOTICE;
      return strStrict(raw, 1, 500) ?? DEFAULT_PRIVACY_NOTICE;
    },
    serialize(input) {
      const s = strStrict(input, 1, 500);
      if (s === null) throw new ValidationError('Privacy notice text must be 1 to 500 characters.', 'privacy_notice_text');
      return s;
    },
  }),
  streak_enabled: flagSetting('streak_enabled', {
    label: 'Streaks',
    def: true,
    unrec: true,
    perm: GEN,
    description: 'Count consecutive sign-in days on the dashboard.',
  }),
  streak_window_hours: intSetting('streak_window_hours', {
    label: 'Streak window',
    min: 24,
    max: 72,
    def: 30,
    unrec: 30,
    perm: GEN,
    description: 'Hours after a sign-in within which the next one keeps the streak.',
  }),
  streak_reentry_grace_hours: intSetting('streak_reentry_grace_hours', {
    label: 'Re-entry grace',
    min: 0,
    max: 24,
    def: 12,
    unrec: 12,
    perm: GEN,
    description: 'Hours after a protected stretch ends before a missed day counts.',
  }),
  streak_max_leeway_days: intSetting('streak_max_leeway_days', {
    label: 'Maximum leeway',
    min: 0,
    max: 7,
    def: 4,
    unrec: 4,
    perm: GEN,
    description: 'The most protected days that can extend one streak window.',
  }),
  streak_weekly_days: listSetting('streak_weekly_days', {
    label: 'Weekly protected days',
    def: [6],
    unrec: [6],
    perm: GEN,
    description: 'Weekday numbers 0 to 6 (0 is Sunday) that never break a streak.',
    check: checkWeekdays,
  }),
  streak_hebrew_holidays: flagSetting('streak_hebrew_holidays', {
    label: 'Jewish holidays',
    def: true,
    unrec: true,
    perm: GEN,
    description: 'Treat Yom Tov as protected days.',
  }),
  streak_region: enumSetting('streak_region', {
    label: 'Holiday calendar',
    options: ['diaspora', 'israel'],
    def: 'diaspora',
    unrec: 'diaspora',
    perm: GEN,
    description: 'Which Yom Tov schedule applies.',
  }),
  streak_extra_dates: listSetting('streak_extra_dates', {
    label: 'Extra protected dates',
    def: [],
    unrec: [],
    perm: GEN,
    description: 'Up to 366 entries of { date: "YYYY-MM-DD", label } (label 1 to 60 characters).',
    check: checkExtraDates,
  }),
  streak_leaderboard: enumSetting('streak_leaderboard', {
    label: 'Streak leaderboard',
    options: ['all', 'managers', 'off'],
    def: 'all',
    unrec: 'off',
    perm: GEN,
    description: 'Who sees the streak leaderboard.',
  }),
});

export const SETTING_KEYS = Object.freeze(Object.keys(SETTINGS));

function isSettingKey(key) {
  return typeof key === 'string' && Object.hasOwn(SETTINGS, key);
}

// ---------------------------------------------------------------- reading

function assemble(valueOf) {
  const p = {};
  for (const key of SETTING_KEYS) p[key] = valueOf(key);
  // The streak keys again, grouped, for streak.streakConfig (§5 lists them flat).
  p.streak = {
    enabled: p.streak_enabled,
    window_hours: p.streak_window_hours,
    reentry_grace_hours: p.streak_reentry_grace_hours,
    max_leeway_days: p.streak_max_leeway_days,
    weekly_days: p.streak_weekly_days,
    hebrew_holidays: p.streak_hebrew_holidays,
    region: p.streak_region,
    extra_dates: p.streak_extra_dates,
    leaderboard: p.streak_leaderboard,
  };
  return p;
}

// Every key at its restrictive value: what an unreadable settings table means.
export function restrictivePolicy() {
  return assemble((key) => copy(SETTINGS[key].unrecognised));
}

// One query per request. Never throws.
export async function resolvePolicy(env) {
  try {
    const nowMs = now(env);
    const { results } = await env.DB.prepare('SELECT key, value FROM settings').all();
    const stored = new Map();
    for (const row of results || []) {
      if (isSettingKey(row?.key)) stored.set(row.key, typeof row.value === 'string' ? row.value : UNREADABLE);
    }
    return assemble((key) => SETTINGS[key].parse(stored.get(key), nowMs));
  } catch (e) {
    console.error('policy: settings unreadable; every key resolves to its restrictive value:', e && e.message);
    return restrictivePolicy();
  }
}

// The stored string, or null when absent. A present non-string reads as ''
// so every parser treats it as unrecognised rather than as absent.
export async function getSettingRaw(env, key) {
  if (!isSettingKey(key)) return null;
  const row = await env.DB.prepare('SELECT value FROM settings WHERE key = ?').bind(key).first();
  if (!row) return null;
  return typeof row.value === 'string' ? row.value : '';
}

// ---------------------------------------------------------------- writing

// Validates and stores. NO guards and NO audit: the settings API (and the
// reverter) run the self-lockout guards and write the audit row.
export async function writeSetting(rc, key, input, { allowGate = false } = {}) {
  if (!isSettingKey(key)) throw new ValidationError('Unknown setting.', 'key');
  if (key === 'gate_open' && allowGate !== true) {
    throw new ValidationError('Opening to the internet is changed only from the gate controls.', key);
  }
  const env = rc.env;
  const nowMs = typeof rc.nowMs === 'number' && Number.isFinite(rc.nowMs) ? rc.nowMs : now(env);
  const def = SETTINGS[key];
  const raw = def.serialize(input);
  if (key === 'gate_open' && raw !== '0' && raw !== '1') {
    const until = parseIsoStrict(raw);
    if (!(until > nowMs && until <= nowMs + GATE_MAX_MS)) {
      throw new ValidationError('The gate can be opened for 1 to 168 hours, or until closed.', key);
    }
  }
  const prior = await getSettingRaw(env, key);
  const by = toInt(rc.user?.id, 1);
  await env.DB.prepare(
    `INSERT INTO settings (key, value, updated_at, updated_by) VALUES (?, ?, ?, ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
  )
    .bind(key, raw, iso(nowMs), Number.isFinite(by) ? by : null)
    .run();
  return { prior, value: def.parse(raw, nowMs), raw };
}
