import { test, assert, run } from '../helpers/t.js';
import { makeEnvWithSchema } from '../helpers/env.js';
import { HOUR, MINUTE, iso } from '../../src/util.js';
import { ValidationError } from '../../src/errors.js';
import {
  SETTINGS,
  SETTING_KEYS,
  DEFAULT_PRIVACY_NOTICE,
  resolvePolicy,
  restrictivePolicy,
  getSettingRaw,
  writeSetting,
  gateOpenState,
  isRealDate,
} from '../../src/policy.js';

const HOSTILE = [null, undefined, NaN, Infinity, -Infinity, '', '   ', 'abc', {}, [], true, false, 0, Symbol('x'), 10n, () => 1];
const show = (v) => (typeof v === 'symbol' ? 'Symbol' : typeof v === 'function' ? 'fn' : typeof v === 'bigint' ? `${v}n` : JSON.stringify(v) ?? String(v));

const CLOSED = { open: false, until: null, forever: false };

// CONTRACTS §5, transcribed by hand — the registry must match it exactly.
const TABLE = {
  access_mode: { type: 'enum', def: 'allowlist', unrec: 'lockdown', perm: 'security.manage' },
  deny_style: { type: 'enum', def: 'empty', unrec: 'empty', perm: 'security.manage' },
  gate_open: { type: 'gate', def: CLOSED, unrec: CLOSED, perm: 'gate.open' },
  country_allow: { type: 'json-list', def: null, unrec: [], perm: 'security.manage' },
  country_deny: { type: 'json-list', def: [], unrec: ['*'], perm: 'security.manage' },
  block_tor: { type: 'flag', def: true, unrec: true, perm: 'security.manage' },
  block_datacenter: { type: 'flag', def: false, unrec: true, perm: 'security.manage' },
  block_automation: { type: 'flag', def: true, unrec: true, perm: 'security.manage' },
  risk_threshold: { type: 'int', def: 70, unrec: 50, perm: 'security.manage', min: 1, max: 100 },
  mfa_policy: { type: 'enum', def: 'prompt', unrec: 'required', perm: 'security.manage' },
  mfa_grace: { type: 'flag', def: true, unrec: false, perm: 'security.manage' },
  device_gating: { type: 'flag', def: false, unrec: true, perm: 'settings.manage' },
  step_up_minutes: { type: 'int', def: 15, unrec: 5, perm: 'settings.manage', min: 1, max: 120 },
  session_idle_minutes: { type: 'int', def: 120, unrec: 30, perm: 'settings.manage', min: 5, max: 1440 },
  session_absolute_hours: { type: 'int', def: 8, unrec: 8, perm: 'settings.manage', min: 1, max: 72 },
  timezone: { type: 'timezone', def: 'America/New_York', unrec: 'UTC', perm: 'settings.manage' },
  privacy_notice: { type: 'flag', def: true, unrec: true, perm: 'settings.manage' },
  privacy_notice_text: { type: 'string', def: DEFAULT_PRIVACY_NOTICE, unrec: DEFAULT_PRIVACY_NOTICE, perm: 'settings.manage' },
  streak_enabled: { type: 'flag', def: true, unrec: true, perm: 'settings.manage' },
  streak_window_hours: { type: 'int', def: 30, unrec: 30, perm: 'settings.manage', min: 24, max: 72 },
  streak_reentry_grace_hours: { type: 'int', def: 12, unrec: 12, perm: 'settings.manage', min: 0, max: 24 },
  streak_max_leeway_days: { type: 'int', def: 4, unrec: 4, perm: 'settings.manage', min: 0, max: 7 },
  streak_weekly_days: { type: 'json-list', def: [6], unrec: [6], perm: 'settings.manage' },
  streak_hebrew_holidays: { type: 'flag', def: true, unrec: true, perm: 'settings.manage' },
  streak_region: { type: 'enum', def: 'diaspora', unrec: 'diaspora', perm: 'settings.manage' },
  streak_extra_dates: { type: 'json-list', def: [], unrec: [], perm: 'settings.manage' },
  streak_leaderboard: { type: 'enum', def: 'all', unrec: 'off', perm: 'settings.manage' },
};

// Garbage that is unrecognised for every key except free text.
const GARBAGE = ['garbage', '', '   ', 'null', '{}', '[', '[1', 'TRUE', 'true', '1.5', ' 1', '1 ', 'Infinity', 'NaN', '0x10', '١', '99999999999', '-1', '"allowlist"'];
// Garbage specific to a key (values valid for other keys).
const KEY_GARBAGE = {
  access_mode: ['Allowlist', 'ALLOWLIST', ' allowlist', 'open', 'none'],
  deny_style: ['Decoy', 'none'],
  gate_open: ['42', '2', '2026-01-07', '2026-01-07T00:00:00', 'Infinity', '9999'],
  country_allow: ['["us"]', '["USA"]', '[1]', '[null]', '"US"', '{"0":"US"}', '["U S"]'],
  country_deny: ['["us"]', '["USA"]', '[1]', '"US"', '["*"]'],
  block_tor: ['2', 'yes', 'on'],
  block_datacenter: ['2', 'yes', 'on'],
  block_automation: ['2', 'yes', 'on'],
  risk_threshold: ['0', '101', '7e1', '070.0', '+70'],
  mfa_policy: ['Required', 'off'],
  mfa_grace: ['2', 'yes'],
  device_gating: ['2', 'no'],
  step_up_minutes: ['0', '121'],
  session_idle_minutes: ['4', '1441', '0'],
  session_absolute_hours: ['0', '73'],
  timezone: ['Mars/Phobos', 'America/Nowhere', '+99:00'],
  privacy_notice: ['2'],
  streak_enabled: ['2'],
  streak_window_hours: ['23', '73'],
  streak_reentry_grace_hours: ['25'],
  streak_max_leeway_days: ['8'],
  streak_weekly_days: ['[7]', '[-1]', '["6"]', '[6.5]', '6', '[true]'],
  streak_hebrew_holidays: ['2'],
  streak_region: ['Israel', 'usa'],
  streak_extra_dates: [
    '[{"date":"2026-02-30","label":"x"}]',
    '[{"date":"2026-1-01","label":"x"}]',
    '[{"date":"2026-01-01"}]',
    '[{"date":"2026-01-01","label":""}]',
    '["2026-01-01"]',
    '{"date":"2026-01-01","label":"x"}',
  ],
  streak_leaderboard: ['All', 'none'],
};

async function storeRaw(env, key, value) {
  env.DB.q('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value', key, value);
}

function pickGate(v) {
  return { open: v.open, until: v.until, forever: v.forever };
}

// ---------------------------------------------------------------- registry

test('the registry is exactly the §5 table: keys, types, perms, defaults, unrecognised values', () => {
  assert.deepEqual([...SETTING_KEYS].sort(), Object.keys(TABLE).sort());
  for (const [key, spec] of Object.entries(TABLE)) {
    const s = SETTINGS[key];
    assert.equal(s.type, spec.type, key);
    assert.equal(s.perm, spec.perm, key);
    assert.equal(typeof s.description, 'string', key);
    assert.ok(s.description.length > 10, key);
    assert.equal(typeof s.parse, 'function', key);
    assert.equal(typeof s.serialize, 'function', key);
    if (spec.type === 'gate') {
      assert.deepEqual(pickGate(s.default), CLOSED);
      assert.deepEqual(pickGate(s.unrecognised), CLOSED);
    } else {
      assert.deepEqual(s.default, spec.def, `${key} default`);
      assert.deepEqual(s.unrecognised, spec.unrec, `${key} unrecognised`);
    }
    if (spec.type === 'int') {
      assert.equal(s.min, spec.min, key);
      assert.equal(s.max, spec.max, key);
    }
    if (spec.type === 'enum') assert.ok(Array.isArray(s.options) && s.options.includes(spec.def), key);
  }
  assert.deepEqual([...SETTINGS.access_mode.options], ['public', 'fingerprint_gate', 'request_access', 'allowlist', 'invite_only', 'lockdown']);
  assert.ok(Object.isFrozen(SETTINGS));
  assert.ok(Object.isFrozen(SETTINGS.streak_weekly_days.default));
});

test('every key resolves to its default when no row exists', async () => {
  const env = await makeEnvWithSchema();
  const p = await resolvePolicy(env);
  for (const [key, spec] of Object.entries(TABLE)) {
    if (spec.type === 'gate') assert.deepEqual(pickGate(p.gate_open), CLOSED);
    else assert.deepEqual(p[key], spec.def, key);
  }
  assert.equal(p.country_allow, null, 'unrestricted is null');
  assert.equal(p.gate_open.raw, null);
});

test('table-driven: every unrecognised stored value resolves to the RESTRICTIVE value, for every key', async () => {
  for (const [key, spec] of Object.entries(TABLE)) {
    const cases = key === 'privacy_notice_text' ? ['', '   ', 'x'.repeat(501)] : [...GARBAGE, ...(KEY_GARBAGE[key] || [])];
    for (const raw of cases) {
      const env = await makeEnvWithSchema();
      await storeRaw(env, key, raw);
      const p = await resolvePolicy(env);
      if (spec.type === 'gate') {
        assert.deepEqual(pickGate(p.gate_open), CLOSED, `gate_open ${JSON.stringify(raw)}`);
        assert.equal(p.gate_open.raw, raw);
      } else {
        assert.deepEqual(p[key], spec.unrec, `${key} = ${JSON.stringify(raw)}`);
      }
      // Parse directly too, so the registry and resolvePolicy agree.
      const direct = SETTINGS[key].parse(raw, env.__clock());
      if (spec.type === 'gate') assert.deepEqual(pickGate(direct), CLOSED);
      else assert.deepEqual(direct, spec.unrec, `${key} parse ${JSON.stringify(raw)}`);
    }
  }
});

test('a present row whose value is not text reads as unrecognised, not absent', async () => {
  const env = await makeEnvWithSchema();
  for (const key of SETTING_KEYS) env.DB.q('INSERT INTO settings (key, value) VALUES (?, ?)', key, new Uint8Array([49]));
  const p = await resolvePolicy(env);
  for (const [key, spec] of Object.entries(TABLE)) {
    if (spec.type === 'gate') assert.deepEqual(pickGate(p.gate_open), CLOSED);
    else assert.deepEqual(p[key], spec.unrec, key);
  }
  assert.equal(await getSettingRaw(env, 'access_mode'), '');
});

test('parse never throws and treats hostile non-strings as unrecognised', () => {
  for (const [key, spec] of Object.entries(TABLE)) {
    for (const v of HOSTILE) {
      if (v === null || v === undefined) continue;
      const out = SETTINGS[key].parse(v, Date.UTC(2026, 0, 6));
      if (spec.type === 'string' && v === 'abc') assert.equal(out, 'abc');
      else if (spec.type === 'gate') assert.deepEqual(pickGate(out), CLOSED, `${key} ${show(v)}`);
      else assert.deepEqual(out, spec.unrec, `${key} ${show(v)}`);
    }
    // null / undefined are "absent".
    if (spec.type !== 'gate') assert.deepEqual(SETTINGS[key].parse(undefined), spec.def, key);
  }
});

test('valid stored values parse to typed values', async () => {
  const env = await makeEnvWithSchema();
  const rows = {
    access_mode: 'public',
    deny_style: 'decoy',
    country_allow: '["CA","US"]',
    country_deny: '["RU"]',
    block_tor: '0',
    block_datacenter: '1',
    risk_threshold: '1',
    mfa_policy: 'required',
    mfa_grace: '0',
    step_up_minutes: '120',
    session_idle_minutes: '5',
    timezone: 'Europe/London',
    privacy_notice_text: 'We log visits.',
    streak_reentry_grace_hours: '0',
    streak_max_leeway_days: '0',
    streak_weekly_days: '[]',
    streak_extra_dates: '[{"date":"2026-12-25","label":"Office closed"}]',
    streak_region: 'israel',
    streak_leaderboard: 'managers',
  };
  for (const [k, v] of Object.entries(rows)) await storeRaw(env, k, v);
  const p = await resolvePolicy(env);
  assert.equal(p.access_mode, 'public');
  assert.equal(p.deny_style, 'decoy');
  assert.deepEqual(p.country_allow, ['CA', 'US']);
  assert.deepEqual(p.country_deny, ['RU']);
  assert.equal(p.block_tor, false);
  assert.equal(p.block_datacenter, true);
  assert.equal(p.risk_threshold, 1);
  assert.equal(p.mfa_policy, 'required');
  assert.equal(p.mfa_grace, false);
  assert.equal(p.step_up_minutes, 120);
  assert.equal(p.session_idle_minutes, 5);
  assert.equal(p.timezone, 'Europe/London');
  assert.equal(p.privacy_notice_text, 'We log visits.');
  assert.equal(p.streak_reentry_grace_hours, 0, 'an explicit 0 is honoured');
  assert.equal(p.streak_max_leeway_days, 0);
  assert.deepEqual(p.streak_weekly_days, []);
  assert.deepEqual(p.streak_extra_dates, [{ date: '2026-12-25', label: 'Office closed' }]);
  assert.equal(p.streak_region, 'israel');
  assert.equal(p.streak_leaderboard, 'managers');
  // The grouped streak view carries the same values.
  assert.deepEqual(p.streak, {
    enabled: true,
    window_hours: 30,
    reentry_grace_hours: 0,
    max_leeway_days: 0,
    weekly_days: [],
    hebrew_holidays: true,
    region: 'israel',
    extra_dates: [{ date: '2026-12-25', label: 'Office closed' }],
    leaderboard: 'managers',
  });
});

test("country_allow: stored '[]' means no restriction (null); unrecognised means allow NONE ([])", async () => {
  const env = await makeEnvWithSchema();
  await storeRaw(env, 'country_allow', '[]');
  assert.equal((await resolvePolicy(env)).country_allow, null);
  await storeRaw(env, 'country_allow', 'oops');
  assert.deepEqual((await resolvePolicy(env)).country_allow, []);
});

test('resolvePolicy makes exactly one query', async () => {
  const env = await makeEnvWithSchema();
  const seen = [];
  const orig = env.DB.prepare.bind(env.DB);
  env.DB.prepare = (sql) => {
    seen.push(sql);
    return orig(sql);
  };
  await resolvePolicy(env);
  assert.equal(seen.length, 1);
  assert.match(seen[0], /SELECT key, value FROM settings/);
});

test('resolvePolicy never throws: an unreadable settings table resolves every key restrictively', async () => {
  for (const breakIt of [(env) => (env.DB.failOn = /settings/), (env) => env.DB.q('DROP TABLE settings')]) {
    const env = await makeEnvWithSchema();
    await storeRaw(env, 'access_mode', 'public');
    await storeRaw(env, 'gate_open', '1');
    breakIt(env);
    const origErr = console.error;
    let logged = 0;
    console.error = () => logged++;
    let p;
    try {
      p = await resolvePolicy(env);
    } finally {
      console.error = origErr;
    }
    assert.ok(logged >= 1, 'the failure is logged');
    for (const [key, spec] of Object.entries(TABLE)) {
      if (spec.type === 'gate') assert.deepEqual(pickGate(p.gate_open), CLOSED);
      else assert.deepEqual(p[key], spec.unrec, key);
    }
    assert.equal(p.access_mode, 'lockdown');
    assert.deepEqual(p, restrictivePolicy());
  }
  // A broken env object too.
  const p = await resolvePolicy({});
  assert.equal(p.access_mode, 'lockdown');
});

test('resolved values are copies: mutating them cannot corrupt the registry', async () => {
  const env = await makeEnvWithSchema();
  const p = await resolvePolicy(env);
  p.streak_weekly_days.push(0);
  p.country_deny.push('US');
  const q = await resolvePolicy(env);
  assert.deepEqual(q.streak_weekly_days, [6]);
  assert.deepEqual(q.country_deny, []);
});

// ---------------------------------------------------------------- serialize

function rejects(key, v) {
  assert.throws(() => SETTINGS[key].serialize(v), (e) => e instanceof ValidationError && e.status === 400 && e.body.field === key, `${key} must reject ${show(v)}`);
}

test('hostile inputs: blanks, null, booleans and objects are validation errors, never defaults (A §14.1)', () => {
  // The few hostile values that are genuinely legal for a type.
  const legal = {
    flag: new Set([true, false, 0]),
    'json-list': new Set(),
    string: new Set(['abc']),
  };
  for (const [key, spec] of Object.entries(TABLE)) {
    for (const v of HOSTILE) {
      const ok = (legal[spec.type] && legal[spec.type].has(v)) || (spec.type === 'int' && v === 0 && spec.min === 0) || (spec.type === 'json-list' && Array.isArray(v));
      if (ok) {
        assert.equal(typeof SETTINGS[key].serialize(v), 'string', `${key} accepts ${show(v)}`);
      } else {
        rejects(key, v);
      }
    }
  }
});

test('flags accept exactly true/false/1/0/"1"/"0"', () => {
  for (const key of SETTING_KEYS.filter((k) => SETTINGS[k].type === 'flag')) {
    for (const v of [true, 1, '1']) assert.equal(SETTINGS[key].serialize(v), '1');
    for (const v of [false, 0, '0']) assert.equal(SETTINGS[key].serialize(v), '0');
    for (const v of ['true', 'false', 'on', 'yes', 2, -1, '01', ' 1', 1.0000001, [1], { v: 1 }]) rejects(key, v);
  }
});

test('ints: number or numeric string in range; explicit 0 only where the range includes it (A §14.11)', () => {
  assert.equal(SETTINGS.risk_threshold.serialize(70), '70');
  assert.equal(SETTINGS.risk_threshold.serialize('70'), '70');
  assert.equal(SETTINGS.risk_threshold.serialize(' 70 '), '70');
  assert.equal(SETTINGS.risk_threshold.serialize(1), '1');
  assert.equal(SETTINGS.risk_threshold.serialize(100), '100');
  for (const v of [0, '0', 101, -5, 70.5, '70.5', '7O', '', '  ', null, true, [70], { n: 70 }]) rejects('risk_threshold', v);
  assert.equal(SETTINGS.streak_reentry_grace_hours.serialize(0), '0');
  assert.equal(SETTINGS.streak_reentry_grace_hours.serialize('0'), '0');
  assert.equal(SETTINGS.streak_max_leeway_days.serialize(0), '0');
  for (const v of ['', '  ', null, undefined, false]) {
    rejects('streak_reentry_grace_hours', v);
    rejects('streak_max_leeway_days', v);
  }
  rejects('streak_max_leeway_days', 8);
  rejects('streak_window_hours', 23);
  assert.equal(SETTINGS.streak_window_hours.serialize(72), '72');
  assert.equal(SETTINGS.session_idle_minutes.serialize('1440'), '1440');
  rejects('session_idle_minutes', 1441);
  rejects('step_up_minutes', 0);
});

test('enums accept exact option strings only', () => {
  for (const key of SETTING_KEYS.filter((k) => SETTINGS[k].type === 'enum')) {
    for (const o of SETTINGS[key].options) assert.equal(SETTINGS[key].serialize(o), o);
    for (const o of SETTINGS[key].options) {
      rejects(key, o.toUpperCase());
      rejects(key, ` ${o}`);
      rejects(key, [o]);
    }
  }
});

test('country lists: an ARRAY of alpha-2 codes, uppercased, deduplicated; a JSON string is refused', () => {
  for (const key of ['country_allow', 'country_deny']) {
    assert.equal(SETTINGS[key].serialize(['us', ' gb ', 'US']), '["GB","US"]');
    assert.equal(SETTINGS[key].serialize([]), '[]');
    for (const v of ['["US"]', 'US', ['USA'], ['U'], [1], [null], ['*'], ['U1'], [['US']], [{ c: 'US' }], new Array(301).fill('US')]) rejects(key, v);
  }
});

test('weekly days: integers 0–6, deduplicated and sorted', () => {
  assert.equal(SETTINGS.streak_weekly_days.serialize([6, 0, 6]), '[0,6]');
  assert.equal(SETTINGS.streak_weekly_days.serialize([]), '[]');
  assert.equal(SETTINGS.streak_weekly_days.serialize(['5']), '[5]');
  for (const v of ['[6]', [7], [-1], [1.5], ['x'], [true], [null], [''], [[6]], 6]) rejects('streak_weekly_days', v);
});

test('extra dates: strict real calendar dates, labels 1–60, at most 366', () => {
  const s = SETTINGS.streak_extra_dates;
  assert.equal(
    s.serialize([
      { date: '2026-12-31', label: ' Year end ', extra: 'dropped' },
      { date: '2028-02-29', label: 'Leap' },
    ]),
    '[{"date":"2026-12-31","label":"Year end"},{"date":"2028-02-29","label":"Leap"}]',
  );
  assert.equal(
    s.serialize([
      { date: '2027-01-02', label: 'B' },
      { date: '2027-01-01', label: 'A' },
    ]),
    '[{"date":"2027-01-01","label":"A"},{"date":"2027-01-02","label":"B"}]',
    'sorted by date',
  );
  assert.equal(s.serialize([]), '[]');
  const bad = [
    [{ date: '2026-02-29', label: 'x' }],
    [{ date: '1900-02-29', label: 'x' }],
    [{ date: '2026-02-30', label: 'x' }],
    [{ date: '2026-13-01', label: 'x' }],
    [{ date: '2026-00-10', label: 'x' }],
    [{ date: '2026-1-01', label: 'x' }],
    [{ date: ' 2026-01-01', label: 'x' }],
    [{ date: '2026-01-01T00:00:00Z', label: 'x' }],
    [{ date: '2026-01-01', label: '' }],
    [{ date: '2026-01-01', label: '   ' }],
    [{ date: '2026-01-01', label: 'x'.repeat(61) }],
    [{ date: '2026-01-01' }],
    [{ date: '2026-01-01', label: 5 }],
    ['2026-01-01'],
    [null],
    [[]],
    '[{"date":"2026-01-01","label":"x"}]',
    new Array(367).fill({ date: '2026-01-01', label: 'x' }),
  ];
  for (const v of bad) rejects('streak_extra_dates', v);
  assert.equal(JSON.parse(s.serialize(new Array(366).fill({ date: '2026-01-01', label: 'x' }))).length, 366);
  assert.ok(isRealDate('2000-02-29'));
  assert.ok(!isRealDate('2100-02-29'));
  assert.ok(isRealDate('2026-04-30'));
  assert.ok(!isRealDate('2026-04-31'));
});

test('timezone must be accepted by Intl; stored in canonical form', () => {
  assert.equal(SETTINGS.timezone.serialize('Europe/London'), 'Europe/London');
  assert.equal(SETTINGS.timezone.serialize(' Asia/Jerusalem '), 'Asia/Jerusalem');
  assert.equal(SETTINGS.timezone.serialize('utc'), 'UTC');
  for (const v of ['Mars/Phobos', 'America/Nowhere', 'x'.repeat(65), '../etc/passwd']) rejects('timezone', v);
});

test('privacy notice text: 1–500 characters, trimmed', () => {
  assert.equal(SETTINGS.privacy_notice_text.serialize('  We log visits.  '), 'We log visits.');
  assert.equal(SETTINGS.privacy_notice_text.serialize('x'.repeat(500)).length, 500);
  for (const v of ['x'.repeat(501), '', '   ', ['x']]) rejects('privacy_notice_text', v);
});

test('round trip: parse(serialize(v)) gives the typed value for every type', () => {
  const now = Date.UTC(2026, 0, 6, 15);
  const cases = [
    ['access_mode', 'invite_only', 'invite_only'],
    ['block_datacenter', 1, true],
    ['mfa_grace', '0', false],
    ['risk_threshold', '42', 42],
    ['streak_reentry_grace_hours', 0, 0],
    ['country_allow', ['de'], ['DE']],
    ['country_allow', [], null],
    ['country_deny', ['cn', 'ru'], ['CN', 'RU']],
    ['streak_weekly_days', [5, 6], [5, 6]],
    ['streak_extra_dates', [{ date: '2026-07-04', label: 'Fourth' }], [{ date: '2026-07-04', label: 'Fourth' }]],
    ['timezone', 'Asia/Tokyo', 'Asia/Tokyo'],
    ['privacy_notice_text', 'Hello.', 'Hello.'],
  ];
  for (const [key, input, want] of cases) assert.deepEqual(SETTINGS[key].parse(SETTINGS[key].serialize(input), now), want, key);
});

// ---------------------------------------------------------------- the gate

test("gateOpenState: '42' is closed — Date.parse('42') is 2042 (A §14.2)", () => {
  const now = Date.UTC(2026, 0, 6, 15);
  assert.equal(Date.parse('42'), Date.UTC(2042, 0, 1), 'the trap is real');
  assert.deepEqual(gateOpenState('42', now), CLOSED);
});

test('gateOpenState: every case in §5', () => {
  const now = Date.UTC(2026, 0, 6, 15);
  const future = iso(now + 3 * HOUR);
  assert.deepEqual(gateOpenState('0', now), CLOSED);
  assert.deepEqual(gateOpenState('1', now), { open: true, until: null, forever: true });
  assert.deepEqual(gateOpenState(future, now), { open: true, until: now + 3 * HOUR, forever: false });
  assert.deepEqual(gateOpenState('2026-01-06T13:00:00-05:00', now), { open: true, until: Date.UTC(2026, 0, 6, 18), forever: false }, 'offsets are fine');
  assert.deepEqual(gateOpenState(iso(now - MINUTE), now), CLOSED, 'past');
  assert.deepEqual(gateOpenState(iso(now), now), CLOSED, 'exactly now is no longer open');
  assert.deepEqual(gateOpenState('2026-01-07T00:00:00', now), CLOSED, 'ISO without Z or offset');
  assert.deepEqual(gateOpenState('2026-01-07', now), CLOSED, 'date only');
  assert.deepEqual(gateOpenState('Wed Jan 07 2026 00:00:00 GMT', now), CLOSED);
  for (const v of ['', ' 1', '1 ', '01', 'true', 'open', 'garbage', '2099', '9999-12-31', ...HOSTILE, 1, -1]) {
    assert.deepEqual(gateOpenState(v, now), CLOSED, show(v));
  }
  // Without a usable clock a timed opening cannot be confirmed, so closed.
  for (const n of [NaN, undefined, null, '1767711600000', Infinity]) assert.deepEqual(gateOpenState(future, n), CLOSED);
  assert.deepEqual(gateOpenState('1', NaN), { open: true, until: null, forever: true });
});

test('resolvePolicy evaluates gate_open at the env clock', async () => {
  const env = await makeEnvWithSchema();
  const now = env.__clock();
  await storeRaw(env, 'gate_open', iso(now + HOUR));
  let p = await resolvePolicy(env);
  assert.deepEqual(p.gate_open, { open: true, until: now + HOUR, forever: false, raw: iso(now + HOUR) });
  env.__advance(HOUR + 1);
  p = await resolvePolicy(env);
  assert.equal(p.gate_open.open, false);
});

test('the gate serializer accepts only "0", "1" or an ISO instant', () => {
  const s = SETTINGS.gate_open;
  assert.equal(s.serialize('0'), '0');
  assert.equal(s.serialize('1'), '1');
  assert.equal(s.serialize('2026-01-06T13:00:00-05:00'), '2026-01-06T18:00:00.000Z');
  for (const v of [0, 1, true, false, '42', '', ' 1', 'open', '2026-01-07', ...HOSTILE]) rejects('gate_open', v);
});

// ---------------------------------------------------------------- writing

function rc(env, user = { id: 7, email: 'ops@acme.com' }) {
  return { env, nowMs: env.__clock(), user };
}

test('writeSetting validates, upserts with updated_at/updated_by, and returns prior/value/raw', async () => {
  const env = await makeEnvWithSchema();
  let r = await writeSetting(rc(env), 'risk_threshold', '55');
  assert.deepEqual(r, { prior: null, value: 55, raw: '55' });
  r = await writeSetting(rc(env, { id: 9 }), 'risk_threshold', 60);
  assert.deepEqual(r, { prior: '55', value: 60, raw: '60' });
  const rows = env.DB.q('SELECT * FROM settings WHERE key = ?', 'risk_threshold');
  assert.equal(rows.length, 1);
  assert.equal(rows[0].value, '60');
  assert.equal(rows[0].updated_by, 9);
  assert.equal(rows[0].updated_at, iso(env.__clock()));
  assert.equal(await getSettingRaw(env, 'risk_threshold'), '60');
  assert.equal(await getSettingRaw(env, 'deny_style'), null);
  assert.equal((await resolvePolicy(env)).risk_threshold, 60);
  // A context with no user (a migration, a test) records no author.
  await writeSetting({ env, nowMs: env.__clock() }, 'deny_style', 'decoy');
  assert.equal(env.DB.q("SELECT updated_by FROM settings WHERE key = 'deny_style'")[0].updated_by, null);
  r = await writeSetting(rc(env), 'country_allow', []);
  assert.deepEqual(r, { prior: null, value: null, raw: '[]' });
});

test('writeSetting refuses unknown keys and bad values, and writes nothing', async () => {
  const env = await makeEnvWithSchema();
  for (const key of ['nope', '__proto__', 'constructor', 'toString', 'hasOwnProperty', '', ...HOSTILE]) {
    await assert.rejects(writeSetting(rc(env), key, '1'), ValidationError, show(key));
  }
  await assert.rejects(writeSetting(rc(env), 'risk_threshold', ''), ValidationError);
  await assert.rejects(writeSetting(rc(env), 'access_mode', null), ValidationError);
  await assert.rejects(writeSetting(rc(env), 'block_tor', 'yes'), ValidationError);
  assert.equal(env.DB.q('SELECT COUNT(*) AS n FROM settings')[0].n, 0, 'no row written');
});

test('writeSetting refuses gate_open unless allowGate, and bounds a timed opening to 168 hours', async () => {
  const env = await makeEnvWithSchema();
  const now = env.__clock();
  await assert.rejects(writeSetting(rc(env), 'gate_open', '1'), ValidationError);
  await assert.rejects(writeSetting(rc(env), 'gate_open', '1', { allowGate: 'yes' }), ValidationError, 'only true opens it');
  assert.equal(await getSettingRaw(env, 'gate_open'), null);
  let r = await writeSetting(rc(env), 'gate_open', iso(now + 168 * HOUR), { allowGate: true });
  assert.equal(r.value.open, true);
  assert.equal(r.value.until, now + 168 * HOUR);
  for (const bad of [iso(now + 168 * HOUR + 1000), iso(now), iso(now - HOUR), '42', '2042-01-01T00:00:00Z']) {
    await assert.rejects(writeSetting(rc(env), 'gate_open', bad, { allowGate: true }), ValidationError, bad);
  }
  r = await writeSetting(rc(env), 'gate_open', '1', { allowGate: true });
  assert.deepEqual(r.value, { open: true, until: null, forever: true, raw: '1' });
  r = await writeSetting(rc(env), 'gate_open', '0', { allowGate: true });
  assert.equal(r.prior, '1');
  assert.equal(r.value.open, false);
});

await run();
