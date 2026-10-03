// The arithmetic Hebrew calendar, after Dershowitz & Reingold, "Calendrical
// Calculations". Pure arithmetic on fixed day numbers (RD): no lookup table to
// run out and no API to lapse (A §10, B §8). An epoch two days out produces a
// calendar that is internally consistent and wrong about every date, so the
// tests check every day of three centuries against ICU (B trap 7, A §14.10).
//
// Domain: integer day numbers within ±MAX_RD (about 270,000 years). Outside
// it, or for non-integers, the date functions return NaN fields and
// yomTovName returns null — nothing here throws or loops on bad input.

const MAX_RD = 1e8;

function mod(a, n) {
  return a - n * Math.floor(a / n);
}

function okRd(rd) {
  return Number.isSafeInteger(rd) && Math.abs(rd) <= MAX_RD;
}

function okYear(y) {
  return Number.isSafeInteger(y) && Math.abs(y) <= 300000;
}

const NAN_DATE = Object.freeze({ year: NaN, month: NaN, day: NaN });

// ---------------------------------------------------------------- Gregorian

// RD 1 = Monday 1 January 1 CE, proleptic Gregorian.
function isGregorianLeapYear(y) {
  return mod(y, 4) === 0 && ![100, 200, 300].includes(mod(y, 400));
}

export function fixedFromGregorian(y, m, d) {
  if (!okYear(y) || !Number.isInteger(m) || m < 1 || m > 12 || !Number.isSafeInteger(d)) return NaN;
  return (
    365 * (y - 1) +
    Math.floor((y - 1) / 4) -
    Math.floor((y - 1) / 100) +
    Math.floor((y - 1) / 400) +
    Math.floor((367 * m - 362) / 12) +
    (m <= 2 ? 0 : isGregorianLeapYear(y) ? -1 : -2) +
    d
  );
}

function gregorianYearFromFixed(rd) {
  const d0 = rd - 1;
  const n400 = Math.floor(d0 / 146097);
  const d1 = mod(d0, 146097);
  const n100 = Math.floor(d1 / 36524);
  const d2 = mod(d1, 36524);
  const n4 = Math.floor(d2 / 1461);
  const d3 = mod(d2, 1461);
  const n1 = Math.floor(d3 / 365);
  const year = 400 * n400 + 100 * n100 + 4 * n4 + n1;
  return n100 === 4 || n1 === 4 ? year : year + 1;
}

export function gregorianFromFixed(rd) {
  if (!okRd(rd)) return NAN_DATE;
  const year = gregorianYearFromFixed(rd);
  const priorDays = rd - fixedFromGregorian(year, 1, 1);
  const correction = rd < fixedFromGregorian(year, 3, 1) ? 0 : isGregorianLeapYear(year) ? 1 : 2;
  const month = Math.floor((12 * (priorDays + correction) + 373) / 367);
  const day = rd - fixedFromGregorian(year, month, 1) + 1;
  return { year, month, day };
}

// 0 = Sunday. RD 0 was a Sunday.
export function weekday(rd) {
  return okRd(rd) ? mod(rd, 7) : NaN;
}

// ---------------------------------------------------------------- Hebrew

// fixed-from-julian(3761 BCE, October 7): Julian year -3761 is a Julian leap
// year, so -2 + 365·(-3761) + ⌊-3761/4⌋ + ⌊(367·10 - 362)/12⌋ - 1 + 7.
// The constant B trap 7 got two days wrong; the ICU test pins it.
export const HEBREW_EPOCH = -1373427;

export const NISAN = 1;
export const IYYAR = 2;
export const SIVAN = 3;
export const TAMMUZ = 4;
export const AV = 5;
export const ELUL = 6;
export const TISHREI = 7;
export const MARHESHVAN = 8;
export const KISLEV = 9;
export const TEVET = 10;
export const SHEVAT = 11;
export const ADAR = 12; // Adar I in a leap year
export const ADAR_II = 13;

export function isHebrewLeapYear(y) {
  return okYear(y) && mod(7 * y + 1, 19) < 7;
}

export function lastMonthOfHebrewYear(y) {
  if (!okYear(y)) return NaN;
  return isHebrewLeapYear(y) ? ADAR_II : ADAR;
}

// Days from the epoch to the molad of Tishrei, with the "molad zaken" and
// weekday postponements (lo ADU Rosh) applied.
function hebrewCalendarElapsedDays(y) {
  const monthsElapsed = Math.floor((235 * y - 234) / 19);
  const partsElapsed = 12084 + 13753 * monthsElapsed;
  const days = 29 * monthsElapsed + Math.floor(partsElapsed / 25920);
  return mod(3 * (days + 1), 7) < 3 ? days + 1 : days;
}

// The remaining two postponements, which keep every year one of six lengths.
function hebrewYearLengthCorrection(y) {
  const ny0 = hebrewCalendarElapsedDays(y - 1);
  const ny1 = hebrewCalendarElapsedDays(y);
  const ny2 = hebrewCalendarElapsedDays(y + 1);
  if (ny2 - ny1 === 356) return 2;
  if (ny1 - ny0 === 382) return 1;
  return 0;
}

// Pure function of y, called many times per conversion: memoise, bounded.
const newYearCache = new Map();

export function hebrewNewYear(y) {
  if (!okYear(y)) return NaN;
  let v = newYearCache.get(y);
  if (v === undefined) {
    v = HEBREW_EPOCH + hebrewCalendarElapsedDays(y) + hebrewYearLengthCorrection(y);
    if (newYearCache.size >= 4096) newYearCache.clear();
    newYearCache.set(y, v);
  }
  return v;
}

export function daysInHebrewYear(y) {
  if (!okYear(y)) return NaN;
  return hebrewNewYear(y + 1) - hebrewNewYear(y);
}

function longMarheshvan(y) {
  const n = daysInHebrewYear(y);
  return n === 355 || n === 385;
}

function shortKislev(y) {
  const n = daysInHebrewYear(y);
  return n === 353 || n === 383;
}

export function lastDayOfHebrewMonth(m, y) {
  if (!okYear(y) || !Number.isInteger(m) || m < 1 || m > lastMonthOfHebrewYear(y)) return NaN;
  if (
    m === IYYAR ||
    m === TAMMUZ ||
    m === ELUL ||
    m === TEVET ||
    m === ADAR_II ||
    (m === MARHESHVAN && !longMarheshvan(y)) ||
    (m === KISLEV && shortKislev(y)) ||
    (m === ADAR && !isHebrewLeapYear(y))
  ) {
    return 29;
  }
  return 30;
}

// The year begins in Tishrei (7) and runs 7, 8, …, last, 1, 2, …, 6.
export function fixedFromHebrew(y, m, d) {
  if (!okYear(y) || !Number.isInteger(m) || m < 1 || m > lastMonthOfHebrewYear(y) || !Number.isSafeInteger(d)) return NaN;
  let days = hebrewNewYear(y) + d - 1;
  if (m < TISHREI) {
    const last = lastMonthOfHebrewYear(y);
    for (let mm = TISHREI; mm <= last; mm++) days += lastDayOfHebrewMonth(mm, y);
    for (let mm = NISAN; mm < m; mm++) days += lastDayOfHebrewMonth(mm, y);
  } else {
    for (let mm = TISHREI; mm < m; mm++) days += lastDayOfHebrewMonth(mm, y);
  }
  return days;
}

// D&R's year search, then a walk through the months in year order (the same
// result as their MIN-search over fixedFromHebrew, without the quadratic cost).
export function hebrewFromFixed(rd) {
  if (!okRd(rd)) return NAN_DATE;
  // 35975351/98496 is the mean year length; approx − 1 never overshoots.
  const approx = Math.floor((rd - HEBREW_EPOCH) / (35975351 / 98496)) + 1;
  let year = approx - 1;
  while (hebrewNewYear(year + 1) <= rd) year++;
  const last = lastMonthOfHebrewYear(year);
  let start = hebrewNewYear(year);
  // A wrong estimate would otherwise yield a negative day that still
  // round-trips through fixedFromHebrew — refuse rather than look plausible.
  if (start > rd) return NAN_DATE;
  for (let i = 0; i < last; i++) {
    const month = ((TISHREI - 1 + i) % last) + 1;
    const len = lastDayOfHebrewMonth(month, year);
    if (rd < start + len) return { year, month, day: rd - start + 1 };
    start += len;
  }
  return NAN_DATE; // unreachable: the year search guarantees rd < next new year
}

// Days on which work — and so signing in — is impossible. Chol hamoed, Purim,
// Chanukah and the fasts are working days and return null (A §10 "only count
// days on which the activity is genuinely impossible").
// Called as yomTovName(rd, { israel }); anything but israel === true is the
// diaspora calendar (and a null options object must not throw).
export function yomTovName(rd, opts) {
  if (!okRd(rd)) return null;
  const diaspora = !(opts && typeof opts === 'object' && opts.israel === true);
  const { month, day } = hebrewFromFixed(rd);
  if (month === TISHREI) {
    if (day === 1 || day === 2) return 'Rosh Hashanah';
    if (day === 10) return 'Yom Kippur';
    if (day === 15 || (day === 16 && diaspora)) return 'Sukkos';
    if (day === 22) return diaspora ? 'Shemini Atzeres' : 'Shemini Atzeres / Simchas Torah';
    if (day === 23 && diaspora) return 'Simchas Torah';
    return null;
  }
  if (month === NISAN) {
    if (day === 15 || day === 21 || (diaspora && (day === 16 || day === 22))) return 'Pesach';
    return null;
  }
  if (month === SIVAN) {
    if (day === 6 || (day === 7 && diaspora)) return 'Shavuos';
    return null;
  }
  return null;
}
