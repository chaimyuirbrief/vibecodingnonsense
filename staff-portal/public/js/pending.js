// pending.js — the device-approval waiting room (CONTRACTS §7.8 pending
// shell, §8.4: GET /api/device/status, GET /api/diag).
//
// Shows the device code large and letter-spaced for reading aloud, the
// status, a "Check again" button and a gentle auto-poll: every 15 s while the
// tab is visible (paused when hidden, re-checked on return), slowing to once a
// minute after ten minutes, stopping for good once approved or blocked.
// "What did my browser send?" renders GET /api/diag — names and counts only
// (A §5). The pending shell allows this script and common.js only.

import { $, h, api, showError, copyText, toast, busy, fmtTime } from './common.js';

const POLL_MS = 15000;
const SLOW_POLL_MS = 60000;
const SLOW_AFTER = 40;

const el = {
  title: $('title'),
  paneLoading: $('pane-loading'),
  paneCode: $('pane-code'),
  paneApproved: $('pane-approved'),
  paneBlocked: $('pane-blocked'),
  code: $('device-code'),
  codeSr: $('device-code-sr'),
  label: $('device-label'),
  status: $('device-status'),
  copy: $('copy-code'),
  check: $('check-now'),
  checkedAt: $('checked-at'),
  checkError: $('check-error'),
  continueLink: $('continue'),
  diagToggle: $('diag-toggle'),
  diagPanel: $('diag-panel'),
  diagLoading: $('diag-loading'),
  diagError: $('diag-error'),
  diagList: $('diag-list'),
};

const state = { code: '', status: '', timer: null, polls: 0, stopped: false, inFlight: false };

const STATUS = {
  pending: { text: 'Waiting for approval', badge: 'badge-warn' },
  approved: { text: 'Approved', badge: 'badge-ok' },
  blocked: { text: 'Blocked', badge: 'badge-danger' },
};

function spell(code) {
  return code
    .split('')
    .map((c) => (c === '-' ? 'dash' : c))
    .join(' ');
}

function render(data) {
  const code = typeof data.code === 'string' ? data.code : '';
  const status = Object.hasOwn(STATUS, data.status) ? data.status : 'pending';
  state.code = code;
  state.status = status;
  el.code.textContent = code || '—';
  el.codeSr.textContent = code ? `Your device code is ${spell(code)}.` : '';
  el.copy.hidden = !code;
  if (typeof data.label === 'string' && data.label) {
    el.label.textContent = data.label;
    el.label.hidden = false;
  }
  const s = STATUS[status];
  el.status.textContent = s.text;
  el.status.className = `badge ${s.badge}`;
  el.paneLoading.hidden = true;
  el.paneCode.hidden = false;
  el.paneApproved.hidden = status !== 'approved';
  el.paneBlocked.hidden = status !== 'blocked';
  el.check.hidden = status !== 'pending';
  if (status === 'approved') {
    el.title.textContent = 'You’re approved';
    el.continueLink.focus();
  } else if (status === 'blocked') {
    el.title.textContent = 'This browser is blocked';
  }
}

function clearTimer() {
  if (state.timer !== null) clearTimeout(state.timer);
  state.timer = null;
}

function schedule() {
  clearTimer();
  if (state.stopped || document.visibilityState === 'hidden') return;
  state.timer = setTimeout(() => check(), state.polls >= SLOW_AFTER ? SLOW_POLL_MS : POLL_MS);
}

async function check() {
  if (state.inFlight || state.stopped) return;
  state.inFlight = true;
  clearTimer();
  state.polls += 1;
  try {
    const data = await api('GET', '/api/device/status');
    showError(el.checkError, null);
    render(data || {});
    el.checkedAt.textContent = `Last checked ${fmtTime(Date.now())}`;
    if (state.status === 'approved' || state.status === 'blocked') state.stopped = true;
  } catch (err) {
    el.paneLoading.hidden = true;
    el.paneCode.hidden = false;
    showError(el.checkError, err);
  } finally {
    state.inFlight = false;
  }
  schedule();
}

function onVisibility() {
  if (document.visibilityState === 'hidden') clearTimer();
  else if (!state.stopped) check();
}

// ---------------------------------------------------------------- diag ----

function row(label, value) {
  return [h('dt', null, label), h('dd', null, value === null || value === undefined || value === '' ? '—' : value)];
}

function yesNo(v) {
  return v === true ? 'yes' : v === false ? 'no' : '—';
}

function renderDiag(d) {
  const cookies = d.cookies && typeof d.cookies === 'object' ? d.cookies : {};
  const names = Array.isArray(cookies.names) ? cookies.names.filter((n) => typeof n === 'string') : [];
  const count = typeof cookies.count === 'number' ? cookies.count : names.length;
  const hints = d.client_hints && typeof d.client_hints === 'object' ? Object.entries(d.client_hints) : [];
  const device = d.device && typeof d.device === 'object' ? d.device : {};
  const session = d.session && typeof d.session === 'object' ? d.session : {};
  const conn = [d.tls_version, d.http_protocol].filter((v) => typeof v === 'string' && v).join(' · ');
  el.diagList.replaceChildren(
    ...row('Cookies sent', `${count}${names.length ? ` — ${names.join(', ')}` : ''}`),
    ...row('Browser', typeof d.ua === 'string' ? h('span', { class: 'mono small' }, d.ua) : null),
    ...row(
      'Client hints',
      hints.length
        ? h('ul', { class: 'stack-sm' }, hints.map(([k, v]) => h('li', { class: 'mono small' }, `${k}: ${typeof v === 'string' ? v : JSON.stringify(v)}`)))
        : 'none (normal outside Chrome, Edge and other Chromium browsers)',
    ),
    ...row('IP address', typeof d.ip === 'string' ? d.ip : null),
    ...row('Country', typeof d.country === 'string' ? d.country : null),
    ...row('Network', d.asn !== undefined && d.asn !== null ? `AS${d.asn}` : null),
    ...row('Connection', conn),
    ...row('Device cookie', device.present ? `present · ${device.status || 'unknown'}${device.code ? ` · ${device.code}` : ''}` : 'not sent'),
    ...row('Session', session.present ? (session.valid ? 'signed in' : 'present but not valid') : 'not signed in'),
    ...row('Cookies on', yesNo(navigator.cookieEnabled)),
  );
}

async function toggleDiag() {
  const open = el.diagToggle.getAttribute('aria-expanded') !== 'true';
  el.diagToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
  el.diagPanel.hidden = !open;
  if (!open) return;
  el.diagLoading.hidden = false;
  showError(el.diagError, null);
  try {
    renderDiag((await api('GET', '/api/diag')) || {});
  } catch (err) {
    showError(el.diagError, err);
  } finally {
    el.diagLoading.hidden = true;
  }
}

// --------------------------------------------------------------- start ----

el.check.addEventListener('click', () => busy(el.check, check()));
el.copy.addEventListener('click', async () => {
  if (state.code && (await copyText(state.code))) toast('Code copied.', 'ok');
});
el.diagToggle.addEventListener('click', toggleDiag);
document.addEventListener('visibilitychange', onVisibility);
check();
