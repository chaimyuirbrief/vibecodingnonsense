// Local days, zone midnights and protected days. Expectations are computed
// independently of protected.js where it matters: a separate Intl formatter
// for local dates, and real tzdb transitions checked against the zone's own
// wall clock (A §14.10 — verify date arithmetic against an independent
// implementation).

import { test, assert, run } from '../helpers/t.js';
import * as p from '../../src/calendar/protected.js';
import { fixedFromGregorian, weekday, fixedFromHebrew, hebrewNewYear, SIVAN, NISAN, TISHREI } from '../../src/calendar/hebrew.js';

const SEC = 1000;
const MIN = 60 * SEC;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;
const rd = (y, m, d) => fixedFromGregorian(y, m, d);
const Z = (s) => Date.parse(s); // test literals only

const HOSTILE = [null, undefined, NaN, Infinity, -Infinity, '', '   ', 'abc', {}, [], true, false, 0.5, Symbol('x'), 10n, () => 1];

// Independent local date: 'YYYY-MM-DD' straight from an en-CA formatter.
const isoFmt = new Map();
function localIso(ms, tz) {
  if (!isoFmt.has(tz)) isoFmt.set(tz, new Intl.DateTimeFormat('en-CA', { timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit' }));
  return isoFmt.get(tz).format(ms);
}
const wallFmt = new Map();
function wallClock(ms, tz) {
  if (!wallFmt.has(tz)) wallFmt.set(tz, new Intl.DateTimeFormat('en-GB', { timeZone: tz, hourCycle: 'h23', hour: '2-digit', minute: '2-digit', second: '2-digit' }));
  return wallFmt.get(tz).format(ms);
}

// ---------------------------------------------------------------- day strings

test('dayString / parseDayString round-trip and are strict', () => {
  for (let d = rd(1899, 12, 25); d <= rd(2101, 1, 5); d++) {
    const s = p.dayString(d);
    assert.equal(s, new Date((d - 719163) * DAY).toISOString().slice(0, 10));
    assert.equal(p.parseDayString(s), d);
  }
  assert.equal(p.dayString(rd(1, 1, 3)), '0001-01-03');
  assert.equal(p.dayString(rd(9999, 12, 31)), '9999-12-31');
  assert.equal(p.dayString(rd(10000, 1, 1)), '');
  assert.equal(p.dayString(rd(0, 12, 31)), '');
  assert.equal(p.parseDayString('2024-02-29'), rd(2024, 2, 29));
  for (const bad of ['2026-02-29', '2026-02-30', '2026-13-01', '2026-00-10', '2026-01-00', '2026-01-32', '0000-01-01', '2026-1-05', '26-01-05',
    ' 2026-01-05', '2026-01-05 ', '2026-01-05T00:00', '+2026-01-05', '2026/01/05', '２０２６-01-05', '2026-01-05\n']) {
    assert.ok(Number.isNaN(p.parseDayString(bad)), bad);
  }
  for (const v of HOSTILE) {
    assert.ok(Number.isNaN(p.parseDayString(v)));
    assert.equal(p.dayString(v), '');
  }
});

// ---------------------------------------------------------------- zones

test('isValidTimeZone accepts what Intl accepts and refuses the rest', () => {
  for (const tz of ['UTC', 'utc', 'US/Eastern', 'America/New_York', 'Asia/Kolkata', 'Australia/Lord_Howe', 'Pacific/Apia', 'Etc/GMT+5']) assert.ok(p.isValidTimeZone(tz), tz);
  for (const tz of ['Foo/Bar', ' UTC', 'UTC ', 'America/New York', 'x'.repeat(65), ...HOSTILE]) {
    assert.equal(p.isValidTimeZone(tz), false, String(typeof tz === 'symbol' ? 'Symbol' : tz));
  }
});

test('localDay just before and after local midnight (New York, Kolkata, Lord Howe)', () => {
  const cases = [
    ['America/New_York', '2026-01-06T04:59:59.999Z', [2026, 1, 5]],
    ['America/New_York', '2026-01-06T05:00:00.000Z', [2026, 1, 6]],
    ['America/New_York', '2026-07-06T03:59:59.999Z', [2026, 7, 5]],
    ['America/New_York', '2026-07-06T04:00:00.000Z', [2026, 7, 6]],
    ['Asia/Kolkata', '2025-12-31T18:29:59.999Z', [2025, 12, 31]],
    ['Asia/Kolkata', '2025-12-31T18:30:00.000Z', [2026, 1, 1]],
    ['Australia/Lord_Howe', '2026-01-05T12:59:59.999Z', [2026, 1, 5]], // +11
    ['Australia/Lord_Howe', '2026-01-05T13:00:00.000Z', [2026, 1, 6]],
    ['Australia/Lord_Howe', '2026-07-05T13:29:59.999Z', [2026, 7, 5]], // +10:30
    ['Australia/Lord_Howe', '2026-07-05T13:30:00.000Z', [2026, 7, 6]],
    ['UTC', '2026-01-05T23:59:59.999Z', [2026, 1, 5]],
  ];
  for (const [tz, at, [y, m, d]] of cases) {
    assert.equal(p.localDay(Z(at), tz), rd(y, m, d), `${tz} ${at}`);
    assert.equal(p.dayString(p.localDay(Z(at), tz)), localIso(Z(at), tz));
  }
  // The trap A §10 names: 11pm on the 17th in New York is the 18th in UTC.
  assert.equal(p.localDay(Z('2026-03-18T03:00:00Z'), 'America/New_York'), rd(2026, 3, 17));
  assert.equal(p.localDay(Z('2026-03-18T03:00:00Z'), 'UTC'), rd(2026, 3, 18));
});

test('localDay is total', () => {
  for (const v of HOSTILE) {
    if (!Number.isFinite(v)) assert.ok(Number.isNaN(p.localDay(v, 'UTC'))); // 0.5 ms is a real instant
    assert.ok(Number.isNaN(p.localDay(Z('2026-01-01T00:00:00Z'), v)));
  }
  assert.equal(p.localDay(0.5, 'UTC'), rd(1970, 1, 1));
  assert.ok(Number.isNaN(p.localDay('1767225600000', 'UTC')), 'a numeric string is not an instant');
  assert.ok(Number.isNaN(p.localDay(8.64e15, 'UTC')), 'outside years 1–9999');
  assert.ok(Number.isNaN(p.localDay(-8.64e15, 'UTC')));
});

test('zonedMidnightUtc across DST in New York: 23- and 25-hour days', () => {
  const tz = 'America/New_York';
  const m = (y, mo, d) => p.zonedMidnightUtc(rd(y, mo, d), tz);
  assert.equal(m(2026, 1, 6), Z('2026-01-06T05:00:00Z'));
  assert.equal(m(2026, 3, 8), Z('2026-03-08T05:00:00Z')); // spring forward at 2am: midnight is still EST
  assert.equal(m(2026, 3, 9) - m(2026, 3, 8), 23 * HOUR);
  assert.equal(m(2026, 11, 1), Z('2026-11-01T04:00:00Z')); // fall back at 2am: midnight is still EDT
  assert.equal(m(2026, 11, 2) - m(2026, 11, 1), 25 * HOUR);
  assert.equal(m(2026, 11, 3) - m(2026, 11, 2), 24 * HOUR);
});

test('zonedMidnightUtc in Kolkata (+5:30) and Lord Howe (half-hour DST)', () => {
  assert.equal(p.zonedMidnightUtc(rd(2026, 1, 1), 'Asia/Kolkata'), Z('2025-12-31T18:30:00Z'));
  const lh = (y, mo, d) => p.zonedMidnightUtc(rd(y, mo, d), 'Australia/Lord_Howe');
  assert.equal(lh(2026, 4, 5), Z('2026-04-04T13:00:00Z')); // +11 until 2am
  assert.equal(lh(2026, 4, 6) - lh(2026, 4, 5), 24.5 * HOUR);
  assert.equal(lh(2026, 10, 4), Z('2026-10-03T13:30:00Z')); // +10:30 until 2am
  assert.equal(lh(2026, 10, 5) - lh(2026, 10, 4), 23.5 * HOUR);
});

test('zonedMidnightUtc where midnight itself is skipped: the day begins at the transition', () => {
  // [zone, local date, first instant of that day, its wall clock]
  const cases = [
    ['America/Santiago', [2025, 9, 7], '2025-09-07T04:00:00Z', '01:00:00'], // 23:59:59 → 01:00
    ['America/Havana', [2026, 3, 8], '2026-03-08T05:00:00Z', '01:00:00'],
    ['Africa/Cairo', [2026, 4, 24], '2026-04-23T22:00:00Z', '01:00:00'],
    ['America/Sao_Paulo', [2018, 11, 4], '2018-11-04T03:00:00Z', '01:00:00'],
  ];
  for (const [tz, [y, m, d], first, clock] of cases) {
    const t = p.zonedMidnightUtc(rd(y, m, d), tz);
    assert.equal(t, Z(first), `${tz} ${y}-${m}-${d}`);
    assert.equal(wallClock(t, tz), clock);
    assert.equal(localIso(t, tz), p.dayString(rd(y, m, d)));
    assert.equal(localIso(t - SEC, tz), p.dayString(rd(y, m, d) - 1), 'one second earlier is the day before');
  }
  // Santiago falls back at midnight (00:00 → 23:00 the evening before): the
  // repeated hour belongs to Saturday; Sunday starts once, after it.
  const sun = p.zonedMidnightUtc(rd(2026, 4, 5), 'America/Santiago');
  assert.equal(sun, Z('2026-04-05T04:00:00Z'));
  assert.equal(wallClock(sun, 'America/Santiago'), '00:00:00');
  assert.equal(localIso(sun - 30 * MIN, 'America/Santiago'), '2026-04-04');
  assert.equal(localIso(sun - 90 * MIN, 'America/Santiago'), '2026-04-04');
});

test('zonedMidnightUtc where midnight happens twice: the first one', () => {
  // Jordan fell back 01:00 → 00:00 (+3 → +2): 29 Oct 2021 read 00:00 at
  // 21:00Z and again at 22:00Z. The day began at the first; probing only the
  // offset in force at 00:00Z would find the second.
  const amman = p.zonedMidnightUtc(rd(2021, 10, 29), 'Asia/Amman');
  assert.equal(amman, Z('2021-10-28T21:00:00Z'));
  assert.equal(localIso(amman - SEC, 'Asia/Amman'), '2021-10-28');
  assert.equal(p.zonedMidnightUtc(rd(2021, 10, 30), 'Asia/Amman') - amman, 25 * HOUR);
  // Syria fell back 00:00 → 23:00 the evening before: Friday began once, after the repeat.
  assert.equal(p.zonedMidnightUtc(rd(2021, 10, 29), 'Asia/Damascus'), Z('2021-10-28T22:00:00Z'));
  assert.equal(localIso(Z('2021-10-28T21:30:00Z'), 'Asia/Damascus'), '2021-10-28');
});

test('zonedMidnightUtc for a day that never happened: Pacific/Apia 2011-12-30', () => {
  const tz = 'Pacific/Apia';
  const d29 = p.zonedMidnightUtc(rd(2011, 12, 29), tz);
  const d30 = p.zonedMidnightUtc(rd(2011, 12, 30), tz);
  const d31 = p.zonedMidnightUtc(rd(2011, 12, 31), tz);
  assert.equal(d29, Z('2011-12-29T10:00:00Z')); // UTC−10
  // The skipped day "begins" when it would have — the instant the 29th ends
  // and the 31st (UTC+14) begins — so a window reopening "at midnight after
  // the 29th" opens exactly when the clocks say the 31st.
  assert.equal(d30, Z('2011-12-30T10:00:00Z'));
  assert.equal(d31, d30);
  assert.equal(d30 - d29, DAY);
  assert.equal(p.localDay(d30, tz), rd(2011, 12, 31));
  assert.equal(p.localDay(d30 - SEC, tz), rd(2011, 12, 29));
  for (let t = d29; t < d30 + DAY; t += 15 * MIN) assert.notEqual(p.localDay(t, tz), rd(2011, 12, 30));
});

test('zonedMidnightUtc is the first second of the local day — every day of 2025–2026 in twelve zones', () => {
  const zones = ['UTC', 'America/New_York', 'Europe/London', 'Asia/Kolkata', 'Asia/Kathmandu', 'Australia/Lord_Howe', 'Pacific/Chatham',
    'America/Santiago', 'America/Havana', 'Africa/Cairo', 'Asia/Beirut', 'Pacific/Kiritimati'];
  for (const tz of zones) {
    for (let d = rd(2025, 1, 1); d <= rd(2026, 12, 31); d++) {
      const t = p.zonedMidnightUtc(d, tz);
      assert.ok(Number.isFinite(t), `${tz} ${p.dayString(d)}`);
      assert.equal(t % SEC, 0);
      assert.equal(localIso(t, tz), p.dayString(d), `${tz} ${p.dayString(d)} starts in its own day`);
      assert.equal(localIso(t - SEC, tz), p.dayString(d - 1), `${tz} ${p.dayString(d)}: the second before is the day before`);
      const c = wallClock(t, tz);
      assert.ok(c === '00:00:00' || c === '01:00:00', `${tz} ${p.dayString(d)} starts at ${c}`);
    }
  }
});

test('zonedMidnightUtc is total', () => {
  for (const v of HOSTILE) {
    assert.ok(Number.isNaN(p.zonedMidnightUtc(v, 'UTC')));
    assert.ok(Number.isNaN(p.zonedMidnightUtc(rd(2026, 1, 1), v)));
  }
  assert.ok(Number.isNaN(p.zonedMidnightUtc(1e12, 'UTC')));
});

// ---------------------------------------------------------------- protected days

const DIASPORA = { weeklyDays: [6], hebrew: true, israel: false, extraDates: [] };
const ISRAEL = { weeklyDays: [6], hebrew: true, israel: true, extraDates: [] };

test('Shabbos and Yom Tov: names merged, weekly name depends on the Hebrew switch', () => {
  const f = p.makeProtectedDayFn(DIASPORA);
  assert.deepEqual(f(rd(2026, 1, 10)), { protected: true, names: ['Shabbos'] });
  assert.deepEqual(f(rd(2026, 1, 9)), { protected: false, names: [] });
  assert.deepEqual(f(rd(2026, 9, 12)), { protected: true, names: ['Shabbos', 'Rosh Hashanah'] }); // RH 5787 on Shabbos
  assert.deepEqual(f(rd(2026, 9, 13)), { protected: true, names: ['Rosh Hashanah'] });
  assert.deepEqual(f(rd(2026, 9, 21)), { protected: true, names: ['Yom Kippur'] });
  assert.deepEqual(f(rd(2026, 9, 28)), { protected: false, names: [] }); // chol hamoed Sukkos
  const plain = p.makeProtectedDayFn({ weeklyDays: [6], hebrew: false });
  assert.deepEqual(plain(rd(2026, 1, 10)), { protected: true, names: ['Saturday'] });
  assert.deepEqual(plain(rd(2026, 9, 21)), { protected: false, names: [] }, 'no Yom Tov with the switch off');
});

test('weekly [0] and [5] variants', () => {
  const sun = p.makeProtectedDayFn({ weeklyDays: [0], hebrew: false });
  const fri = p.makeProtectedDayFn({ weeklyDays: [5], hebrew: true });
  for (let d = rd(2026, 1, 4); d < rd(2026, 1, 11); d++) {
    assert.equal(sun(d).protected, weekday(d) === 0);
    if (weekday(d) === 0) assert.deepEqual(sun(d).names, ['Sunday']);
    assert.equal(fri(d).protected, weekday(d) === 5);
    if (weekday(d) === 5) assert.deepEqual(fri(d).names, ['Friday']);
  }
  assert.deepEqual(fri(rd(2026, 9, 21)).names, ['Yom Kippur'], 'Yom Tov still protected with a Friday weekly day');
  const two = p.makeProtectedDayFn({ weeklyDays: [5, 6], hebrew: true });
  assert.deepEqual(two(rd(2026, 1, 9)).names, ['Friday']);
  assert.deepEqual(two(rd(2026, 1, 10)).names, ['Shabbos']);
  const none = p.makeProtectedDayFn({ weeklyDays: [], hebrew: false });
  for (let d = rd(2026, 1, 1); d < rd(2027, 1, 1); d++) assert.equal(none(d).protected, false);
});

test('Israel vs diaspora: the second days are protected only in the diaspora', () => {
  const dia = p.makeProtectedDayFn(DIASPORA);
  const isr = p.makeProtectedDayFn(ISRAEL);
  const y = 5785; // Shavuos 6–7 Sivan = Mon–Tue 2025-06-02/03, away from Shabbos
  const shav2 = fixedFromHebrew(y, SIVAN, 7);
  assert.equal(p.dayString(shav2), '2025-06-03');
  assert.deepEqual(dia(shav2), { protected: true, names: ['Shavuos'] });
  assert.deepEqual(isr(shav2), { protected: false, names: [] });
  assert.equal(isr(fixedFromHebrew(y, SIVAN, 6)).protected, true);
  for (const [m, d] of [[NISAN, 16], [NISAN, 22]]) {
    const day = fixedFromHebrew(y, m, d);
    if (weekday(day) === 6) continue;
    assert.equal(dia(day).protected, true);
    assert.equal(isr(day).protected, false, `${m}/${d}`);
  }
  const y2 = 5786;
  for (const d of [16, 23]) {
    const day = fixedFromHebrew(y2, TISHREI, d);
    if (weekday(day) === 6) continue;
    assert.equal(dia(day).protected, true);
    assert.equal(isr(day).protected, false, `Tishrei ${d}`);
  }
  const sa = fixedFromHebrew(y2, TISHREI, 22);
  assert.ok(isr(sa).names.includes('Shemini Atzeres / Simchas Torah'));
  assert.ok(dia(sa).names.includes('Shemini Atzeres'));
  assert.ok(dia(sa + 1).names.includes('Simchas Torah'));
  // Rosh Hashanah is two days in Israel too.
  const rh = hebrewNewYear(y2);
  assert.equal(isr(rh + 1).protected, true);
});

test('longest protected run 1900–2300: exactly 3 days in the diaspora and in Israel', () => {
  const runs = (f) => {
    const out = [];
    let start = null;
    for (let d = rd(1900, 1, 1); d <= rd(2300, 12, 31) + 1; d++) {
      if (f(d).protected) {
        if (start === null) start = d;
      } else if (start !== null) {
        out.push({ start, len: d - start });
        start = null;
      }
    }
    return out;
  };
  // Diaspora: every festival day comes in pairs except Yom Kippur, and no
  // pair touches another, so the longest stretch is a pair beside Shabbos —
  // Thu–Fri–Sat or Sat–Sun–Mon. Yom Kippur never falls on Friday or Sunday,
  // so it never lengthens Shabbos.
  const dia = p.makeProtectedDayFn(DIASPORA);
  const dr = runs(dia);
  assert.equal(Math.max(...dr.map((r) => r.len)), 3);
  const threes = dr.filter((r) => r.len === 3);
  assert.ok(threes.length > 100, `${threes.length} three-day runs`);
  for (const r of threes) {
    const shape = [0, 1, 2].map((i) => weekday(r.start + i)).join('');
    assert.ok(shape === '456' || shape === '601', `diaspora run starting ${p.dayString(r.start)} is ${shape}`);
  }
  assert.ok(threes.some((r) => p.dayString(r.start) === '2024-10-03'), 'Rosh Hashanah 5785 Thu–Fri + Shabbos');
  assert.ok(threes.some((r) => p.dayString(r.start) === '2026-04-02'), 'Pesach 5786 Thu–Fri + Shabbos');
  // Israel: every festival is one day except Rosh Hashanah, which is two days
  // everywhere and may begin on Thursday (lo ADU forbids only Sun/Wed/Fri) —
  // so Thursday–Friday Rosh Hashanah into Shabbos is the only 3-day stretch.
  const isr = p.makeProtectedDayFn(ISRAEL);
  const ir = runs(isr);
  assert.equal(Math.max(...ir.map((r) => r.len)), 3);
  const ithrees = ir.filter((r) => r.len === 3);
  assert.ok(ithrees.length > 20);
  for (const r of ithrees) {
    assert.deepEqual([0, 1, 2].map((i) => weekday(r.start + i)), [4, 5, 6]);
    assert.deepEqual(isr(r.start).names, ['Rosh Hashanah']);
  }
  // The streak's leeway cap (4) is therefore never reached by real data;
  // only the absurd-calendar tests in streak.test.mjs exercise it (A §13.7).
});

test('extra dates: strict, invalid entries ignored, labels merged and deduped', () => {
  const extraDates = [
    { date: '2026-01-07', label: 'Office closed' },
    { date: '2026-01-07', label: 'Snow day' },
    { date: '2026-01-07', label: 'Office closed' },
    { date: '2026-01-10', label: 'Shabbos' }, // same as the weekly name → once
    { date: '2026-01-10', label: 'Retreat' },
    { date: '2026-02-30', label: 'Not a day' },
    { date: '2026-1-8', label: 'Bad shape' },
    { date: '2026-01-09', label: '   ' },
    { date: '2026-01-09', label: 'x'.repeat(101) },
    { date: '2026-01-09' },
    { label: 'No date' },
    ['2026-01-09', 'array'],
    null,
    'string',
    Symbol('x'),
    { date: 20260109, label: 'number' },
    { date: '2026-01-12', label: '  Trimmed  ' },
  ];
  const f = p.makeProtectedDayFn({ weeklyDays: [6], hebrew: true, extraDates });
  assert.deepEqual(f(rd(2026, 1, 7)), { protected: true, names: ['Office closed', 'Snow day'] });
  assert.deepEqual(f(rd(2026, 1, 10)), { protected: true, names: ['Shabbos', 'Retreat'] });
  assert.deepEqual(f(rd(2026, 1, 9)), { protected: false, names: [] });
  assert.deepEqual(f(rd(2026, 1, 8)), { protected: false, names: [] });
  assert.deepEqual(f(rd(2026, 1, 12)), { protected: true, names: ['Trimmed'] });
  assert.deepEqual(p.cleanExtraDates(extraDates).map((e) => e.date), ['2026-01-07', '2026-01-07', '2026-01-07', '2026-01-10', '2026-01-10', '2026-01-12']);
  const many = Array.from({ length: 400 }, (_, i) => ({ date: p.dayString(rd(2030, 1, 1) + i), label: `d${i}` }));
  assert.equal(p.cleanExtraDates(many).length, p.MAX_EXTRA_DATES);
  const g = p.makeProtectedDayFn({ weeklyDays: [], hebrew: false, extraDates: many });
  assert.equal(g(rd(2030, 1, 1) + 365).protected, true);
  assert.equal(g(rd(2030, 1, 1) + 366).protected, false, 'entries past the cap are not read');
  for (const v of HOSTILE) assert.deepEqual(p.cleanExtraDates(v), []);
});

test('makeProtectedDayFn is memoised, frozen and total', () => {
  const f = p.makeProtectedDayFn(DIASPORA);
  const a = f(rd(2026, 9, 12));
  assert.equal(f(rd(2026, 9, 12)), a, 'same object from the memo');
  assert.ok(Object.isFrozen(a) && Object.isFrozen(a.names));
  assert.throws(() => a.names.push('x'));
  for (const v of HOSTILE) {
    assert.deepEqual(f(v), { protected: false, names: [] });
    const g = p.makeProtectedDayFn(v);
    for (let d = rd(2026, 1, 1); d < rd(2026, 12, 31); d++) assert.equal(g(d).protected, false, 'a malformed config protects nothing');
  }
  const loose = p.makeProtectedDayFn({ weeklyDays: ['6', 6.5, 7, -1, null, 0], hebrew: 'yes', israel: 1 });
  assert.equal(loose(rd(2026, 1, 10)).protected, false, "'6' is not 6");
  assert.deepEqual(loose(rd(2026, 1, 11)).names, ['Sunday']);
  assert.equal(loose(rd(2026, 9, 21)).protected, false, "hebrew must be true, not 'yes'");
});

await run();
