// dashboard.js — the signed-in home page. It leads with the streak
// (SPEC §10.17, CONTRACTS §10): the flame and the count, the state in words —
// never only a colour — the exact deadline in the portal's time zone, a
// twelve-week history strip, the protected days coming up, the rules in one
// sentence and, when the setting allows, the leaderboard. Below it: the
// account's security posture, recent sign-ins and quick links.
//
// Sources: GET /api/me, GET /api/me/streak (§7.4 status + history, upcoming,
// rules, leaderboard), GET /api/me/activity. A pinned session never sees this
// page (the server redirects), but if /api/me says pinned we follow it too.
//
// The pure helpers are exported for the tests: heroView, buildStrip,
// stripSummary, groupRuns, runLabel, recentSignIns, hoursLeftText, zoneLabel.

import {
  $,
  h,
  icon,
  flameIcon,
  api,
  ApiError,
  showError,
  errorMessage,
  mountTopBar,
  canSeeAdmin,
  plural,
  fmtNumber,
  fmtRelative,
  fmtDateTime,
  dayLabel,
  parseDay,
  streakRulesSentence,
  go,
  WEEKDAYS,
} from './common.js';

const DAY_MS = 86400000;
const HOUR_MS = 3600000;
const GRID_DAYS = 84; // 12 weeks × 7 days
const STATES = ['none', 'active', 'at_risk', 'paused', 'lapsed', 'held'];
const OUT_STATES = new Set(['none', 'lapsed', 'off', 'error']);
const METER_STATES = new Set(['active', 'at_risk', 'paused']);
const ALL_HERO_STATES = [...STATES, 'off', 'error', 'loading'];

// ------------------------------------------------------------ helpers ----

function isoDay(ms) {
  const d = new Date(ms);
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())}`;
}

function cleanNames(names) {
  return Array.isArray(names) ? names.filter((n) => typeof n === 'string' && n.trim()).map((n) => n.trim()) : [];
}

function count(v) {
  return typeof v === 'number' && Number.isFinite(v) && v >= 0 ? Math.floor(v) : 0;
}

function joinAnd(list) {
  if (list.length <= 1) return list.join('');
  return `${list.slice(0, -1).join(', ')} and ${list[list.length - 1]}`;
}

// 4.5 → '4.5 hours', 1 → '1 hour', 0.4 → '24 minutes'. Never rounds up: the
// server already rounded down so the page never promises time that is not
// there.
// The server floors to 0.1 h, so 0 means "under six minutes".
export function hoursLeftText(hours) {
  if (typeof hours !== 'number' || !Number.isFinite(hours) || hours < 0) return '';
  if (hours < 0.1) return 'a few minutes';
  if (hours < 1) return plural(Math.floor(hours * 60), 'minute');
  const n = Math.floor(hours * 10) / 10;
  return `${new Intl.NumberFormat('en-US', { maximumFractionDigits: 1 }).format(n)} ${n === 1 ? 'hour' : 'hours'}`;
}

// 'America/New_York' → 'New York time'; 'UTC' stays 'UTC'.
export function zoneLabel(tz) {
  if (typeof tz !== 'string' || !tz.trim()) return '';
  const t = tz.trim();
  if (/^(UTC|GMT|Etc\/UTC|Etc\/GMT)$/i.test(t)) return 'UTC';
  const city = t.split('/').pop().replace(/_/g, ' ');
  return city ? `${city} time` : t;
}

// 26.5 → '26h 30m' (hours, not days: it sits next to an "N-hour window").
function fmtLeft(hours) {
  const total = Math.floor(hours * 60);
  const hh = Math.floor(total / 60);
  const mm = total % 60;
  if (!hh) return `${mm}m`;
  return mm ? `${hh}h ${mm}m` : `${hh}h`;
}

function windowHours(status, rules) {
  const last = typeof status.last_at === 'string' ? Date.parse(status.last_at) : NaN;
  const end = typeof status.deadline === 'string' ? Date.parse(status.deadline) : NaN;
  if (Number.isFinite(last) && Number.isFinite(end) && end > last) return (end - last) / HOUR_MS;
  const w = rules && typeof rules.window_hours === 'number' ? rules.window_hours : NaN;
  return Number.isFinite(w) && w > 0 ? w : 30;
}

// ---------------------------------------------------------------- hero ----

// Everything the hero shows, decided in one place so every state's words and
// classes can be tested without a DOM.
export function heroView(data) {
  if (!data || typeof data !== 'object') {
    return { state: 'error', count: null, sentence: 'Your streak couldn’t be loaded', detail: 'The rest of your dashboard still works. Reload the page to try again.', out: true, meter: null, zone: '', counted: false, meta: null };
  }
  if (data.enabled === false) {
    return { state: 'off', count: null, sentence: 'Streaks are turned off', detail: 'An administrator has turned sign-in streaks off for this portal. Everything else works as usual.', out: true, meter: null, zone: '', counted: false, meta: null };
  }
  const s = data.status && typeof data.status === 'object' ? data.status : {};
  const state = STATES.includes(s.state) ? s.state : 'none';
  const current = count(s.current);
  const longest = Math.max(count(s.longest), current);
  const when = typeof s.deadline_local === 'string' && s.deadline_local.trim() ? s.deadline_local.trim() : '';
  const left = hoursLeftText(s.hours_left);
  const counted = s.counted_today === true;
  const names = cleanNames(s.protected_today && s.protected_today.names);
  let sentence = '';
  let detail = '';
  switch (state) {
    case 'active':
      sentence = when ? `Keep it going — sign in by ${when}` : 'Keep it going';
      detail = counted
        ? 'Today counts. Your next sign-in keeps the streak alive — the window runs from your most recent sign-in.'
        : 'Today isn’t counted yet — your next sign-in today adds it.';
      break;
    case 'at_risk':
      sentence = left ? `At risk — ${left} left` : 'At risk';
      detail = when ? `Sign in by ${when} to keep your ${plural(current, 'day')}.` : `Sign in soon to keep your ${plural(current, 'day')}.`;
      break;
    case 'paused':
      sentence = names.length ? `Paused for ${joinAnd(names)} — the clock isn’t running` : 'Paused — the clock isn’t running';
      detail = when ? `Today is protected, so nothing is lost. Your window now runs until ${when}.` : 'Today is protected, so nothing is lost.';
      break;
    case 'lapsed':
      sentence = 'Lapsed — your next sign-in starts a new streak';
      detail = `${when ? `The window closed ${when}. ` : ''}${longest ? `Your longest run, ${plural(longest, 'day')}, is safe.` : ''}`.trim();
      break;
    case 'held':
      sentence = 'Held — your record is safe while the clock is checked';
      detail = 'Your last sign-in is timestamped in the future, so the portal is holding your streak exactly where it is rather than guessing. Nothing is lost.';
      break;
    default:
      sentence = 'No streak yet — your next sign-in starts one';
      detail = 'Sign in on consecutive days to build a streak. Days nobody can sign in never count against you.';
  }
  let meter = null;
  if (METER_STATES.has(state) && typeof s.hours_left === 'number' && Number.isFinite(s.hours_left)) {
    const max = Math.max(windowHours(s, data.rules), 1);
    const value = Math.min(Math.max(s.hours_left, 0), max);
    const len = new Intl.NumberFormat('en-US', { maximumFractionDigits: 1 }).format(Math.round(max * 10) / 10);
    meter = { value, max, caption: `${fmtLeft(value)} left of a ${len}-hour window` };
  }
  const zone = when ? zoneLabel(s.timezone) : '';
  return {
    state,
    count: state === 'lapsed' ? 0 : current,
    sentence,
    detail,
    out: OUT_STATES.has(state),
    meter,
    zone,
    counted,
    meta: { longest, total: count(s.total_days), since: state === 'lapsed' || state === 'none' ? null : s.started_day || null },
  };
}

function setStateClass(el, state) {
  for (const st of ALL_HERO_STATES) el.classList.remove(`state-${st}`);
  el.classList.add(`state-${state}`);
}

function renderHero(view) {
  const hero = $('streak');
  setStateClass(hero, view.state);
  setStateClass($('streak-state'), view.state);
  hero.removeAttribute('aria-busy');
  const flame = $('hero-flame');
  if (view.out) flame.classList.add('is-out');
  else flame.classList.remove('is-out');

  const headline = hero.querySelector('.streak-headline');
  headline.hidden = view.count === null;
  $('streak-count').textContent = view.count === null ? '' : fmtNumber(view.count);
  $('counted-badge').hidden = !view.counted;
  $('streak-state').textContent = view.sentence;
  $('streak-detail').textContent = view.detail;
  $('streak-detail').hidden = !view.detail;

  const meter = $('window-meter');
  $('window-row').hidden = !view.meter;
  if (view.meter) {
    const { value, max } = view.meter;
    meter.setAttribute('min', '0');
    meter.setAttribute('max', String(max));
    meter.setAttribute('low', String(Math.min(6, max)));
    meter.setAttribute('high', String(Math.min(12, max)));
    meter.setAttribute('optimum', String(max));
    meter.setAttribute('value', String(value));
    $('window-caption').textContent = view.meter.caption;
  }
  $('streak-zone').hidden = !view.zone;
  $('streak-zone').textContent = view.zone ? `Times are ${view.zone}.` : '';

  $('streak-meta').hidden = !view.meta;
  if (view.meta) {
    $('streak-longest').textContent = plural(view.meta.longest, 'day');
    $('streak-total').textContent = fmtNumber(view.meta.total);
    $('since-stat').hidden = !view.meta.since;
    $('streak-since').textContent = view.meta.since ? dayLabel(view.meta.since, { year: true }) : '';
  }
}

// --------------------------------------------------------------- strip ----

function levelFor(run) {
  if (run >= 14) return 4;
  if (run >= 7) return 3;
  if (run >= 3) return 2;
  return 1;
}

// 84 cells, GitHub-style: 12 columns of Sunday→Saturday weeks, oldest on the
// left, the current week last, so the days after today are still to come.
// A counted day's warmth follows the length of the run it belongs to;
// protected days bridge a run, as they do in the streak itself.
export function buildStrip(history) {
  const list = (Array.isArray(history) ? history : []).filter((e) => e && typeof e === 'object' && parseDay(e.day));
  if (!list.length) return null;
  list.sort((a, b) => (a.day < b.day ? -1 : a.day > b.day ? 1 : 0));
  const byDay = new Map(list.map((e) => [e.day, e]));
  const todayEntry = list.find((e) => e.today === true) || list[list.length - 1];
  const today = parseDay(todayEntry.day);
  const startMs = today.ms - (today.weekday + 77) * DAY_MS;
  const firstMs = Math.min(parseDay(list[0].day).ms, startMs);

  const cells = [];
  let run = 0;
  for (let ms = firstMs; ms < startMs + GRID_DAYS * DAY_MS; ms += DAY_MS) {
    const day = isoDay(ms);
    const e = byDay.get(day) || null;
    const isToday = ms === today.ms;
    const future = ms > today.ms;
    const counted = !future && !!e && e.counted === true;
    const prot = !future && !!e && e.protected === true;
    if (counted) run += 1;
    else if (!prot && !isToday && !future) run = 0;
    if (ms < startMs) continue;

    const names = e ? cleanNames(e.names) : [];
    const date = `${dayLabel(day)}${isToday ? ' (today)' : ''}`;
    const named = names.length ? ` (${names.join(', ')})` : '';
    const classes = ['strip-day'];
    let label;
    let kind;
    if (future) {
      classes.push('is-future');
      label = `${date}: still to come`;
      kind = 'future';
    } else {
      if (counted) classes.push('is-counted', `lvl-${levelFor(run)}`);
      if (prot) classes.push('is-protected');
      if (isToday) classes.push('is-today');
      if (counted) {
        kind = 'counted';
        label = `${date}: signed in${prot ? ` on a protected day${named}` : ''}`;
      } else if (prot) {
        kind = 'protected';
        label = `${date}: protected${named}`;
      } else if (isToday) {
        kind = 'today';
        label = `${date}: not counted yet`;
      } else {
        classes.push('is-missed');
        kind = 'missed';
        label = `${date}: missed`;
      }
    }
    cells.push({ day, kind, classes, label, names, today: isToday, protected: prot, counted, future });
  }
  return { today: todayEntry.day, start: isoDay(startMs), cells };
}

export function stripSummary(strip) {
  if (!strip) return 'No history yet.';
  let signed = 0;
  let open = 0;
  let protectedDays = 0;
  for (const c of strip.cells) {
    if (c.future) continue;
    if (c.counted) {
      signed += 1;
      open += 1;
    } else if (c.protected) protectedDays += 1;
    else if (!c.today) open += 1;
  }
  const head = `Signed in on ${fmtNumber(signed)} of the last ${plural(open, 'open day')}`;
  return protectedDays ? `${head}. ${plural(protectedDays, 'protected day')} didn’t count against you.` : `${head}.`;
}

function monthLabels(strip) {
  const out = [];
  let prev = -1;
  for (let col = 0; col < 12; col++) {
    const p = parseDay(strip.cells[col * 7].day);
    out.push(p.month !== prev ? WEEKDAYS.months[p.month] : '');
    prev = p.month;
  }
  // Two labels side by side would collide: the first column gives way.
  if (out[0] && out[1]) out[0] = '';
  return out;
}

function renderStrip(history) {
  const strip = buildStrip(history);
  const grid = $('strip');
  if (!strip) {
    grid.replaceChildren();
    $('strip-months').replaceChildren();
    $('strip-summary').textContent = 'No history yet — your first sign-in starts it.';
    return;
  }
  grid.replaceChildren(
    ...strip.cells.map((c) =>
      h(
        'span',
        { class: c.classes, role: 'img', 'aria-label': c.label, title: c.label, dataset: { day: c.day } },
        c.protected && !c.counted ? icon('rest', { size: 10, className: 'strip-glyph' }) : null,
      ),
    ),
  );
  $('strip-months').replaceChildren(...monthLabels(strip).map((m) => h('span', null, m)));
  $('strip-summary').textContent = stripSummary(strip);
}

// ------------------------------------------------------------ upcoming ----

// Consecutive protected days become one run: 'Thu–Sat Oct 2–4'.
export function groupRuns(upcoming) {
  const list = (Array.isArray(upcoming) ? upcoming : []).filter((e) => e && typeof e === 'object' && parseDay(e.day));
  list.sort((a, b) => (a.day < b.day ? -1 : a.day > b.day ? 1 : 0));
  const runs = [];
  for (const e of list) {
    const last = runs[runs.length - 1];
    const names = cleanNames(e.names);
    if (last && parseDay(e.day).ms - parseDay(last.to).ms === DAY_MS) {
      last.to = e.day;
      last.days.push(e.day);
      for (const n of names) if (!last.names.includes(n)) last.names.push(n);
    } else if (!last || last.to !== e.day) {
      runs.push({ from: e.day, to: e.day, days: [e.day], names: [...names] });
    }
  }
  return runs;
}

export function runLabel(run) {
  const a = parseDay(run.from);
  const b = parseDay(run.to);
  if (!a || !b) return '';
  const W = WEEKDAYS.short;
  const M = WEEKDAYS.months;
  if (run.from === run.to) return `${W[a.weekday]} ${M[a.month]} ${a.date}`;
  if (a.month === b.month && a.year === b.year) return `${W[a.weekday]}–${W[b.weekday]} ${M[a.month]} ${a.date}–${b.date}`;
  return `${W[a.weekday]} ${M[a.month]} ${a.date}–${W[b.weekday]} ${M[b.month]} ${b.date}`;
}

function renderUpcoming(upcoming) {
  const runs = groupRuns(upcoming);
  $('upcoming').replaceChildren(
    ...runs.map((r) =>
      h(
        'li',
        { class: 'upcoming-day' },
        icon('rest', { size: 18 }),
        h(
          'span',
          { class: 'upcoming-text' },
          h('time', { datetime: r.from }, runLabel(r)),
          ' · ',
          h('span', { class: 'upcoming-names' }, r.names.length ? r.names.join(', ') : 'Protected'),
          h('span', { class: 'upcoming-note' }, ' — the clock pauses'),
        ),
      ),
    ),
  );
  $('upcoming-empty').hidden = runs.length > 0;
}

// --------------------------------------------------------- leaderboard ----

function renderLeaderboard(list, meId) {
  const card = $('leaderboard-card');
  card.hidden = !Array.isArray(list);
  if (!Array.isArray(list)) return;
  const rows = list.filter((r) => r && typeof r === 'object');
  if (!rows.length) {
    $('leaderboard').replaceChildren(h('li', { class: 'muted' }, 'Nobody has a streak going right now — yours could be first.'));
    return;
  }
  $('leaderboard').replaceChildren(
    ...rows.map((r, i) => {
      const mine = meId !== null && meId !== undefined && r.user_id === meId;
      const name = typeof r.full_name === 'string' && r.full_name.trim() ? r.full_name.trim() : 'A colleague';
      const cur = count(r.current);
      const best = Math.max(count(r.longest), cur);
      return h(
        'li',
        { class: mine ? 'is-me' : null, dataset: { userId: r.user_id } },
        h('span', { class: 'sr-only' }, `${i + 1}. ${name}${mine ? ' (you)' : ''}: ${plural(cur, 'day')}, longest ${plural(best, 'day')}`),
        h('span', { class: 'rank', 'aria-hidden': 'true' }, String(i + 1)),
        h('span', { class: 'lb-name', 'aria-hidden': 'true' }, name, mine ? h('span', { class: 'lb-you' }, ' (you)') : null),
        h('span', { class: 'lb-count', 'aria-hidden': 'true' }, flameIcon({ size: 16 }), fmtNumber(cur)),
        h('span', { class: 'lb-longest', 'aria-hidden': 'true' }, `best ${fmtNumber(best)}`),
      );
    }),
  );
}

// ----------------------------------------------------- security, links ----

export function hasStrongFactor(factors) {
  const f = factors && typeof factors === 'object' ? factors : null;
  return !!f && ((typeof f.passkeys === 'number' && f.passkeys > 0) || f.totp === true);
}

function factorRow(iconName, label, value, kind) {
  return h('li', null, icon(iconName, { size: 20 }), h('span', { class: 'factor-label' }, label), h('span', { class: `badge badge-${kind}` }, value));
}

function renderSecurity(me) {
  const f = me.factors && typeof me.factors === 'object' ? me.factors : {};
  const strong = hasStrongFactor(f);
  $('enroll-banner').hidden = !(me.enroll_prompt === true || (me.factors && !strong));
  $('security-summary').textContent = strong ? 'Your sign-in has a second step.' : 'Password only — anyone with your password can sign in.';
  const passkeys = count(f.passkeys);
  const backup = count(f.backup);
  const dests = count(f.destinations);
  $('factor-list').replaceChildren(
    factorRow('passkey', 'Passkeys', passkeys ? plural(passkeys, 'passkey') : 'None', passkeys ? 'ok' : 'neutral'),
    factorRow('app', 'Authenticator app', f.totpUnreadable ? 'Needs attention' : f.totp ? 'On' : 'Not set up', f.totpUnreadable ? 'danger' : f.totp ? 'ok' : 'neutral'),
    factorRow('backup', 'Backup codes', backup ? `${fmtNumber(backup)} left` : 'None', backup === 0 ? (strong ? 'warn' : 'neutral') : backup <= 2 ? 'warn' : 'ok'),
    factorRow('sms', 'Codes by text or email', dests ? plural(dests, 'destination') : 'None', dests ? 'ok' : 'neutral'),
  );
}

function renderLinks(me) {
  const links = [
    ['/account', 'user', 'Your profile and password'],
    ['/account#security', 'shield', 'Sign-in methods'],
    ['/account#sessions', 'device', 'Sessions and devices'],
    ['/account#browser', 'eye', 'What this portal knows about this browser'],
  ];
  if (canSeeAdmin(me.permissions)) links.push(['/admin', 'settings', 'Admin console']);
  $('quick-links').replaceChildren(...links.map(([href, ic, label]) => h('li', null, h('a', { href }, icon(ic, { size: 18 }), label))));
}

const SIGNIN_ACTIONS = new Set(['login.success', 'login.fail', 'login.denied']);

export function recentSignIns(activity, limit = 5) {
  const rows = Array.isArray(activity)
    ? activity
    : activity && typeof activity === 'object'
      ? activity.entries || activity.activity || activity.items || []
      : [];
  return (Array.isArray(rows) ? rows : []).filter((r) => r && typeof r === 'object' && SIGNIN_ACTIONS.has(r.action)).slice(0, limit);
}

function renderSignIns(activity) {
  const rows = recentSignIns(activity);
  const list = $('signins');
  list.removeAttribute('aria-busy');
  if (!rows.length) {
    list.replaceChildren(h('li', { class: 'muted' }, 'No sign-ins recorded yet.'));
    return;
  }
  list.replaceChildren(
    ...rows.map((r) => {
      const ok = r.action === 'login.success' && r.outcome !== 'failure' && r.outcome !== 'denied';
      const what = typeof r.detail === 'string' && r.detail.trim() ? r.detail.trim() : ok ? 'Signed in' : r.action === 'login.denied' ? 'Sign-in refused' : 'Failed sign-in attempt';
      return h(
        'li',
        { class: ok ? null : 'is-failed' },
        h('span', { class: ['dot', ok ? 'dot-ok' : 'dot-danger'], 'aria-hidden': 'true' }),
        h(
          'span',
          { class: 'activity-main' },
          h('span', null, what),
          h(
            'span',
            { class: 'activity-when' },
            h('time', { datetime: typeof r.at === 'string' ? r.at : null, title: fmtDateTime(r.at) }, fmtRelative(r.at)),
            typeof r.ip === 'string' && r.ip ? ` · ${r.ip}` : '',
          ),
        ),
      );
    }),
  );
}

// ----------------------------------------------------------------- main ----

function renderStreak(data, me) {
  const view = heroView(data);
  renderHero(view);
  const on = !!data && typeof data === 'object' && data.enabled !== false;
  $('history-card').hidden = !on;
  $('upcoming-card').hidden = !on;
  $('rules-card').hidden = !on;
  if (!on) {
    $('leaderboard-card').hidden = true;
    return;
  }
  renderStrip(data.history);
  renderUpcoming(data.upcoming);
  $('rules').textContent = streakRulesSentence(data.rules) || 'The rules couldn’t be read.';
  renderLeaderboard(data.leaderboard, me && me.user ? me.user.id : null);
}

async function main() {
  let me;
  try {
    me = await api('GET', '/api/me');
  } catch (err) {
    showError('load-error', err);
    renderHero(heroView(null));
    return;
  }
  if (!me || typeof me !== 'object') me = {};
  if (typeof me.pinned === 'string' && me.pinned) {
    go(`/account?pin=${encodeURIComponent(me.pinned)}`, { replace: true });
    return;
  }
  const org = typeof me.org_name === 'string' && me.org_name ? me.org_name : '';
  document.title = org ? `Dashboard · ${org}` : 'Dashboard';
  mountTopBar('topbar-slot', { me, active: 'dashboard' });
  renderSecurity(me);
  renderLinks(me);

  const [streakRes, activityRes] = await Promise.allSettled([api('GET', '/api/me/streak'), api('GET', '/api/me/activity')]);

  if (streakRes.status === 'fulfilled') {
    const data = streakRes.value;
    renderStreak(data, me);
    const status = data && data.enabled !== false && data.status && typeof data.status === 'object' ? data.status : null;
    if (status) mountTopBar('topbar-slot', { me, active: 'dashboard', streak: { ...status, current: heroView(data).count } });
  } else if (!(streakRes.reason instanceof ApiError && streakRes.reason.redirected)) {
    const view = heroView(null);
    view.detail = `${errorMessage(streakRes.reason)} The rest of your dashboard still works.`;
    renderHero(view);
    for (const id of ['history-card', 'upcoming-card', 'rules-card', 'leaderboard-card']) $(id).hidden = true;
  }

  if (activityRes.status === 'fulfilled') renderSignIns(activityRes.value);
  else {
    $('signins').removeAttribute('aria-busy');
    $('signins').replaceChildren();
    showError('signins-error', activityRes.reason);
  }
}

main();
