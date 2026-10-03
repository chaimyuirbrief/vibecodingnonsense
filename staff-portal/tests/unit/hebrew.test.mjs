// The Hebrew calendar against INDEPENDENT implementations, never against
// itself (A §10, §14.10; B trap 7): an epoch two days out is internally
// consistent, round-trips perfectly and is wrong about every date.
//
// Two independent references:
//   1. ICU, through Intl's hebrew calendar — every day 1900–2200.
//   2. A from-scratch model in this file: molad arithmetic in parts and the
//      four postponements stated as the traditional rules (Rambam, Kiddush
//      HaChodesh 7), anchored to ICU's Rosh Hashanah 5787 — it shares no
//      code and no constant with hebrew.js.
//
// ICU 77 (Node 22) has a bug the model reproduces exactly: it applies
// BeTUTaKPaT (molad on MONDAY ≥ 15h 589p after a leap year → Tuesday) to
// the weekday AFTER lo ADU has already moved a SUNDAY molad to Monday, so in
// those years its Rosh Hashanah is one day late. Within 5000–6500 that is
// 5137, 5215, 5462, 5560, 5807, 6054, 6399; within 1900–2200 only 5807
// (ICU: Tue 2046-10-02; correct: Mon 2046-10-01). hebrew.js must match the
// traditional rules on every day with no exceptions, and ICU on every day
// outside the window those years disturb.

import { test, assert, run } from '../helpers/t.js';
import * as h from '../../src/calendar/hebrew.js';

const DAY = 86400000;
const UNIX_RD = 719163; // R.D. of 1970-01-01, as published by Dershowitz & Reingold
const msOf = (rd) => (rd - UNIX_RD) * DAY;
const rdOfUtc = (y, m, d) => Date.UTC(y, m - 1, d) / DAY + UNIX_RD;
const FIRST = rdOfUtc(1900, 1, 1);
const LAST = rdOfUtc(2200, 12, 31);

const HOSTILE = [null, undefined, NaN, Infinity, -Infinity, '', '   ', 'abc', {}, [], true, false, 0.5, 1e300, Symbol('x'), 10n, () => 1];

// ---------------------------------------------------------------- ICU

const ICU = new Intl.DateTimeFormat('en-u-ca-hebrew', { timeZone: 'UTC', year: 'numeric', month: 'long', day: 'numeric' });
// ICU's English month names, mapped to D&R numbering. Leap years say
// "Adar I" (12) and "Adar II" (13); common years say plain "Adar" (12).
const ICU_MONTHS = {
  Tishri: 7, Heshvan: 8, Kislev: 9, Tevet: 10, Shevat: 11, 'Adar I': 12, Adar: 12, 'Adar II': 13,
  Nisan: 1, Iyar: 2, Sivan: 3, Tamuz: 4, Av: 5, Elul: 6,
};

function icu(rd) {
  const o = {};
  for (const p of ICU.formatToParts(msOf(rd))) o[p.type] = p.value;
  return { year: Number(o.year), month: ICU_MONTHS[o.month], day: Number(o.day), name: o.month };
}

const same = (a, b) => a.year === b.year && a.month === b.month && a.day === b.day;

// ---------------------------------------------------------------- the traditional model

const PARTS_DAY = 25920;
const HOUR_PARTS = 1080;
const LUNATION = 29 * PARTS_DAY + 12 * HOUR_PARTS + 793; // 29d 12h 793p
// Molad of Tishrei, year 1 ("BaHaRaD"): day 2 (Monday) 5h 204p. Day indices
// count from a Sunday that starts at 6 pm Saturday, so index % 7 is the
// weekday with 0 = Sunday.
const BAHARAD = 1 * PARTS_DAY + 5 * HOUR_PARTS + 204;
const LEAP_POSITIONS = [3, 6, 8, 11, 14, 17, 19];

const tLeap = (y) => LEAP_POSITIONS.includes(((y - 1) % 19) + 1);

function monthsBefore(y) {
  const cycles = Math.floor((y - 1) / 19);
  const r = (y - 1) % 19;
  let m = 235 * cycles + 12 * r;
  for (const p of LEAP_POSITIONS) if (p <= r) m++;
  return m;
}

function molad(y) {
  const p = BAHARAD + monthsBefore(y) * LUNATION;
  return { day: Math.floor(p / PARTS_DAY), parts: p % PARTS_DAY };
}

const HP = (hours, parts) => hours * HOUR_PARTS + parts;

// Day index of 1 Tishrei by the four postponements, as the rules state them.
function tRoshIndex(y) {
  const { day, parts } = molad(y);
  let d = day;
  if (parts >= HP(18, 0)) d += 1; // molad zaken: at or after noon
  else if (day % 7 === 2 && parts >= HP(9, 204) && !tLeap(y)) d += 2; // GaTaRaD → Thursday
  else if (day % 7 === 1 && parts >= HP(15, 589) && tLeap(y - 1)) d += 1; // BeTUTaKPaT → Tuesday
  if ([0, 3, 5].includes(d % 7)) d += 1; // lo ADU Rosh: never Sunday, Wednesday, Friday
  return d;
}

// ICU's startOfYear, transcribed: the day counts from the previous noon (so
// molad zaken is a day rollover), lo ADU first, and then the GaTaRaD /
// BeTUTaKPaT tests against the POSTPONED weekday — the bug.
function icuRoshIndex(y) {
  const { day, parts } = molad(y);
  let d = day;
  let frac = parts + HP(6, 0);
  if (frac >= PARTS_DAY) {
    d += 1;
    frac -= PARTS_DAY;
  }
  if ([0, 3, 5].includes(d % 7)) d += 1;
  if (d % 7 === 2 && frac > HP(15, 204) && !tLeap(y)) d += 2;
  else if (d % 7 === 1 && frac > HP(21, 589) && tLeap(y - 1)) d += 1;
  return d;
}

const icuBugYear = (y) => tRoshIndex(y) !== icuRoshIndex(y);

// Anchor the model's day indices to R.D. through ICU's Rosh Hashanah 5787
// (5787 is not a bug year) — independent of HEBREW_EPOCH.
function icuRosh(y, nearRd) {
  for (let rd = nearRd - 10; rd <= nearRd + 10; rd++) {
    const x = icu(rd);
    if (x.year === y && x.month === 7 && x.day === 1) return rd;
  }
  throw new Error(`ICU has no 1 Tishri ${y} near ${nearRd}`);
}
const ANCHOR = icuRosh(5787, rdOfUtc(2026, 9, 12)) - tRoshIndex(5787);

function makeModel(roshIndex) {
  const ny = (y) => ANCHOR + roshIndex(y);
  const months = (y) => {
    const len = ny(y + 1) - ny(y);
    const leap = tLeap(y);
    // Heshvan is 30 in a "complete" year (355/385), Kislev 29 in a "deficient" one (353/383).
    const out = [[7, 30], [8, len % 10 === 5 ? 30 : 29], [9, len % 10 === 3 ? 29 : 30], [10, 29], [11, 30]];
    if (leap) out.push([12, 30], [13, 29]);
    else out.push([12, 29]);
    out.push([1, 30], [2, 29], [3, 30], [4, 29], [5, 30], [6, 29]);
    return { len, months: out };
  };
  // Sequential walk over a contiguous range.
  return function* walk(fromRd, toRd) {
    let y = 5000;
    while (ny(y + 1) <= fromRd) y++;
    let start = ny(y);
    let { months: ms } = months(y);
    let mi = 0;
    let mStart = start;
    for (let rd = start; rd <= toRd; rd++) {
      while (rd >= mStart + ms[mi][1]) {
        mStart += ms[mi][1];
        mi++;
        if (mi === ms.length) {
          y++;
          ms = months(y).months;
          mi = 0;
        }
      }
      if (rd >= fromRd) yield { rd, year: y, month: ms[mi][0], day: rd - mStart + 1 };
    }
  };
}

const traditional = makeModel(tRoshIndex);
const icuModel = makeModel(icuRoshIndex);

// ---------------------------------------------------------------- tests

test('ICU month names in this runtime (sample) map to D&R month numbers, with leap-year naming', () => {
  const sample = [];
  for (const y of [5784, 5785]) {
    const names = [];
    for (let rd = ANCHOR + tRoshIndex(y); icu(rd).year === y; rd++) {
      if (names[names.length - 1] !== icu(rd).name) names.push(icu(rd).name);
    }
    sample.push(`${y}${tLeap(y) ? ' (leap)' : ''}: ${names.join(', ')}`);
  }
  console.log(`  ICU ${process.versions.icu} month names — ${sample.join(' | ')}`);
  assert.match(sample[0], /Adar I, Adar II/);
  assert.doesNotMatch(sample[1], /Adar I/);
  assert.match(sample[1], /Shevat, Adar, Nisan/);
});

test('every day 1900-01-01..2200-12-31 matches ICU (outside the ICU-bug window) and the traditional rules (always)', () => {
  const t = traditional(FIRST, LAST);
  const m = icuModel(FIRST, LAST);
  const icuNames = new Set();
  let checked = 0;
  let exempt = 0;
  const firstDiff = [];
  for (let rd = FIRST; rd <= LAST; rd++) {
    const mine = h.hebrewFromFixed(rd);
    const trad = t.next().value;
    const im = m.next().value;
    const i = icu(rd);
    icuNames.add(`${i.name}|${h.isHebrewLeapYear(i.year) ? 'leap' : 'common'}`);
    assert.ok(i.month, `ICU month name '${i.name}' is not mapped`);
    // The model is right about ICU on every single day, bug included…
    assert.ok(same(i, im), `ICU model diverges from ICU at ${rd}: ${JSON.stringify(i)} vs ${JSON.stringify(im)}`);
    // …hebrew.js is right about the traditional rules on every single day…
    if (!same(mine, trad) && firstDiff.length < 3) firstDiff.push({ rd, mine, trad });
    // …and agrees with ICU wherever ICU's bug does not reach.
    if (same(trad, im)) {
      if (!same(mine, i) && firstDiff.length < 3) firstDiff.push({ rd, mine, icu: i });
    } else exempt++;
    checked++;
  }
  assert.deepEqual(firstDiff, [], 'hebrew.js disagrees with an independent implementation');
  assert.equal(checked, LAST - FIRST + 1);
  // ICU's late 5807 lengthens 5806 to 385 days and shortens 5807 to 354:
  // the two disagree from 1 Kislev 5806 to 30 Heshvan 5807, 385 days.
  assert.equal(exempt, h.fixedFromHebrew(5807, h.KISLEV, 1) - h.fixedFromHebrew(5806, h.KISLEV, 1));
  assert.equal(exempt, 385);
  const bugYears = [];
  for (let y = 5660; y <= 5962; y++) if (icuBugYear(y)) bugYears.push(y);
  assert.deepEqual(bugYears, [5807]);
  for (const n of ['Adar I|leap', 'Adar II|leap', 'Adar|common']) assert.ok(icuNames.has(n), n);
  for (const n of ['Adar|leap', 'Adar I|common', 'Adar II|common']) assert.ok(!icuNames.has(n), n);
});

test('Rosh Hashanah 5000–6500: traditional rules always; ICU except exactly its BeTUTaKPaT-after-ADU years', () => {
  const late = [];
  for (let y = 5000; y <= 6500; y++) {
    const ny = h.hebrewNewYear(y);
    assert.equal(ny, ANCHOR + tRoshIndex(y), `new year ${y}`);
    const i = icu(ny);
    if (icuBugYear(y)) {
      // The bug's signature: molad on Sunday, after 15h 589p, after a leap year.
      const { day, parts } = molad(y);
      assert.equal(day % 7, 0);
      assert.ok(parts >= HP(15, 589) && parts < HP(18, 0));
      assert.ok(h.isHebrewLeapYear(y - 1));
      assert.equal(h.weekday(ny), 1, `${y} is Monday by the rules`);
      const next = icu(ny + 1);
      assert.ok(next.year === y && next.month === 7 && next.day === 1, `ICU puts ${y} a day late`);
      late.push(y);
    } else {
      assert.ok(i.year === y && i.month === 7 && i.day === 1, `ICU 1 Tishri ${y}: got ${JSON.stringify(i)}`);
    }
  }
  assert.deepEqual(late, [5137, 5215, 5462, 5560, 5807, 6054, 6399]);
});

test('HEBREW_EPOCH is pinned by ICU and the molad model, not by itself', () => {
  // Molad BaHaRaD (day index 1, a Monday) is 1 Tishrei AM 1.
  assert.equal(h.HEBREW_EPOCH, ANCHOR + 1);
  assert.equal(h.HEBREW_EPOCH, -1373427);
  assert.equal(((ANCHOR % 7) + 7) % 7, 0, 'day index 0 must fall on an R.D. Sunday');
  assert.equal(h.weekday(h.HEBREW_EPOCH), 1);
  assert.equal(h.hebrewNewYear(1), h.HEBREW_EPOCH);
});

test('anchors: 1 Tishrei 5787 = Sat 2026-09-12; 15 Nisan 5786 = 2026-04-02; 10 Tishrei 5787 = 2026-09-21 — and ICU agrees', () => {
  const anchors = [
    [5787, h.TISHREI, 1, [2026, 9, 12], 6, 'Tishri'],
    [5786, h.NISAN, 15, [2026, 4, 2], 4, 'Nisan'],
    [5787, h.TISHREI, 10, [2026, 9, 21], 1, 'Tishri'],
    [5785, h.TISHREI, 1, [2024, 10, 3], 4, 'Tishri'],
  ];
  for (const [y, m, d, [gy, gm, gd], wd, icuName] of anchors) {
    const rd = h.fixedFromHebrew(y, m, d);
    assert.equal(rd, rdOfUtc(gy, gm, gd), `${d}/${m}/${y}`);
    assert.deepEqual(h.gregorianFromFixed(rd), { year: gy, month: gm, day: gd });
    assert.deepEqual(h.hebrewFromFixed(rd), { year: y, month: m, day: d });
    assert.equal(h.weekday(rd), wd);
    assert.equal(new Date(Date.UTC(gy, gm - 1, gd)).getUTCDay(), wd);
    const i = icu(rd);
    assert.deepEqual([i.year, i.name, i.day], [y, icuName, d]);
  }
  assert.equal(h.yomTovName(h.fixedFromGregorian(2026, 9, 12)), 'Rosh Hashanah');
  assert.equal(h.yomTovName(h.fixedFromGregorian(2026, 9, 21)), 'Yom Kippur');
  assert.equal(h.yomTovName(h.fixedFromGregorian(2026, 4, 2)), 'Pesach');
});

test('round trip fixedFromHebrew(hebrewFromFixed(rd)) with every day in its month, 1900–2200 and sampled years 1–9999', () => {
  const check = (rd) => {
    const x = h.hebrewFromFixed(rd);
    assert.ok(x.day >= 1 && x.day <= h.lastDayOfHebrewMonth(x.month, x.year), `day in range at ${rd}: ${JSON.stringify(x)}`);
    assert.ok(x.month >= 1 && x.month <= h.lastMonthOfHebrewYear(x.year));
    assert.ok(rd >= h.hebrewNewYear(x.year) && rd < h.hebrewNewYear(x.year + 1));
    assert.equal(h.fixedFromHebrew(x.year, x.month, x.day), rd);
  };
  for (let rd = FIRST; rd <= LAST; rd++) check(rd);
  for (let rd = 1; rd <= h.fixedFromGregorian(9999, 12, 31); rd += 997) check(rd);
});

test('gregorianFromFixed / fixedFromGregorian / weekday agree with Date for every day 1900–2200 and sampled years 1–9999', () => {
  assert.equal(h.fixedFromGregorian(1, 1, 1), 1);
  assert.equal(h.fixedFromGregorian(1970, 1, 1), UNIX_RD);
  assert.equal(h.weekday(1), 1, 'R.D. 1 is a Monday');
  const d = new Date(0);
  const check = (rd) => {
    d.setTime(msOf(rd));
    const want = { year: d.getUTCFullYear(), month: d.getUTCMonth() + 1, day: d.getUTCDate() };
    assert.deepEqual(h.gregorianFromFixed(rd), want, `rd ${rd}`);
    assert.equal(h.fixedFromGregorian(want.year, want.month, want.day), rd);
    assert.equal(h.weekday(rd), d.getUTCDay());
  };
  for (let rd = FIRST; rd <= LAST; rd++) check(rd);
  for (let rd = 1; rd <= h.fixedFromGregorian(9999, 12, 31); rd += 89) check(rd);
  for (const [y, m, dd] of [[1600, 2, 29], [2000, 2, 29], [2024, 2, 29], [1900, 3, 1], [2100, 3, 1], [4, 2, 29]]) {
    const rd = h.fixedFromGregorian(y, m, dd);
    assert.deepEqual(h.gregorianFromFixed(rd), { year: y, month: m, day: dd });
  }
  assert.equal(h.fixedFromGregorian(1900, 3, 1) - h.fixedFromGregorian(1900, 2, 28), 1, '1900 is not a leap year');
});

test('structural invariants over Hebrew years 5000–6500 (B trap 7)', () => {
  const lengths = new Set();
  for (let y = 5000; y <= 6500; y++) {
    const len = h.daysInHebrewYear(y);
    lengths.add(len);
    assert.ok([353, 354, 355, 383, 384, 385].includes(len), `${y} has ${len} days`);
    assert.equal(len > 360, h.isHebrewLeapYear(y), `${y} length vs leap`);
    const rh = h.hebrewNewYear(y);
    assert.equal(rh, h.fixedFromHebrew(y, h.TISHREI, 1));
    assert.ok(![0, 3, 5].includes(h.weekday(rh)), `lo ADU Rosh: 1 Tishrei ${y} on ${h.weekday(rh)}`);
    const yk = h.fixedFromHebrew(y, h.TISHREI, 10);
    assert.equal(yk, rh + 9);
    assert.ok(![0, 5].includes(h.weekday(yk)), `Yom Kippur ${y} on ${h.weekday(yk)}`);
    const pesach = h.fixedFromHebrew(y, h.NISAN, 15);
    assert.ok(![1, 3, 5].includes(h.weekday(pesach)), `lo BaDU Pesach: ${y} on ${h.weekday(pesach)}`);
    assert.equal(h.hebrewNewYear(y + 1) - pesach, 163, `15 Nisan ${y} → 1 Tishrei ${y + 1}`);
    assert.equal(h.fixedFromHebrew(y, h.SIVAN, 6) - pesach, 50, 'Shavuos is the fiftieth day');
    assert.equal(h.lastDayOfHebrewMonth(h.MARHESHVAN, y), len % 10 === 5 ? 30 : 29);
    assert.equal(h.lastDayOfHebrewMonth(h.KISLEV, y), len % 10 === 3 ? 29 : 30);
  }
  assert.equal(lengths.size, 6, 'all six lengths occur');
  for (let c = 5000; c + 19 <= 6500; c += 19) {
    let leap = 0;
    for (let y = c; y < c + 19; y++) if (h.isHebrewLeapYear(y)) leap++;
    assert.equal(leap, 7, `cycle from ${c}`);
  }
  for (let y = 5701; y <= 5719; y++) assert.equal(h.isHebrewLeapYear(y), [3, 6, 8, 11, 14, 17, 0].includes(y % 19));
  assert.equal(h.lastMonthOfHebrewYear(5784), h.ADAR_II);
  assert.equal(h.lastMonthOfHebrewYear(5785), h.ADAR);
});

test('yomTovName: diaspora and Israel for 5787, and working days are not Yom Tov', () => {
  const names = (y, israel) => {
    const out = [];
    for (let rd = h.hebrewNewYear(y); rd < h.hebrewNewYear(y + 1); rd++) {
      const n = h.yomTovName(rd, { israel });
      if (n) {
        const x = h.hebrewFromFixed(rd);
        out.push(`${x.month}/${x.day} ${n}`);
      }
    }
    return out;
  };
  assert.deepEqual(names(5787, false), [
    '7/1 Rosh Hashanah', '7/2 Rosh Hashanah', '7/10 Yom Kippur', '7/15 Sukkos', '7/16 Sukkos',
    '7/22 Shemini Atzeres', '7/23 Simchas Torah', '1/15 Pesach', '1/16 Pesach', '1/21 Pesach', '1/22 Pesach',
    '3/6 Shavuos', '3/7 Shavuos',
  ]);
  assert.deepEqual(names(5787, true), [
    '7/1 Rosh Hashanah', '7/2 Rosh Hashanah', '7/10 Yom Kippur', '7/15 Sukkos',
    '7/22 Shemini Atzeres / Simchas Torah', '1/15 Pesach', '1/21 Pesach', '3/6 Shavuos',
  ]);
  for (let y = 5000; y <= 6500; y += 7) {
    assert.equal(names(y, false).length, 13);
    assert.equal(names(y, true).length, 8);
  }
  // Chol hamoed, Hoshana Rabbah, Chanukah, Purim (both Adars), the fasts, Tu B'Av, Lag BaOmer: working days.
  const y = 5784; // a leap year
  for (const [m, d] of [[7, 3], [7, 17], [7, 21], [9, 25], [10, 10], [12, 14], [13, 14], [1, 17], [1, 20], [2, 18], [4, 17], [5, 9], [5, 15], [6, 29]]) {
    assert.equal(h.yomTovName(h.fixedFromHebrew(y, m, d)), null, `${m}/${d}`);
  }
  // Options other than { israel: true } mean the diaspora calendar, and never throw.
  const shavuos2 = h.fixedFromHebrew(5785, h.SIVAN, 7);
  for (const o of [undefined, null, {}, { israel: 'yes' }, { israel: 1 }, 'israel', Symbol('x')]) assert.equal(h.yomTovName(shavuos2, o), 'Shavuos');
  assert.equal(h.yomTovName(shavuos2, { israel: true }), null);
});

test('hostile input: nothing throws, nothing loops, results are NaN / null', () => {
  for (const v of HOSTILE) {
    assert.ok(Number.isNaN(h.fixedFromGregorian(v, 1, 1)));
    assert.ok(Number.isNaN(h.fixedFromGregorian(2026, v, 1)));
    assert.ok(Number.isNaN(h.fixedFromGregorian(2026, 1, v)));
    assert.ok(Number.isNaN(h.gregorianFromFixed(v).year));
    assert.ok(Number.isNaN(h.weekday(v)));
    assert.equal(h.isHebrewLeapYear(v), false);
    assert.ok(Number.isNaN(h.lastMonthOfHebrewYear(v)));
    assert.ok(Number.isNaN(h.daysInHebrewYear(v)));
    assert.ok(Number.isNaN(h.lastDayOfHebrewMonth(v, 5786)));
    assert.ok(Number.isNaN(h.lastDayOfHebrewMonth(1, v)));
    assert.ok(Number.isNaN(h.hebrewNewYear(v)));
    assert.ok(Number.isNaN(h.fixedFromHebrew(v, 1, 1)));
    assert.ok(Number.isNaN(h.fixedFromHebrew(5786, v, 1)));
    assert.ok(Number.isNaN(h.fixedFromHebrew(5786, 1, v)));
    assert.ok(Number.isNaN(h.hebrewFromFixed(v).year));
    assert.equal(h.yomTovName(v), null);
    assert.equal(h.yomTovName(v, { israel: true }), null);
  }
  // Out of range: month 13 in a common year, month 0, R.D. beyond ±1e8.
  assert.ok(Number.isNaN(h.fixedFromHebrew(5785, 13, 1)));
  assert.ok(Number.isNaN(h.fixedFromHebrew(5785, 0, 1)));
  assert.ok(Number.isNaN(h.lastDayOfHebrewMonth(13, 5785)));
  assert.ok(Number.isNaN(h.hebrewFromFixed(1e9).year));
  assert.ok(Number.isNaN(h.gregorianFromFixed(-1e9).year));
  assert.equal(h.yomTovName(1e15), null);
});

await run();
