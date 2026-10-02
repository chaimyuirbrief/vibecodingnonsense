// account.js — the self-service account page (CONTRACTS §8.4 Me; A §7.3,
// §7.5; B §6; SPEC §7.8, §8.2).
//
// Everything here acts on the caller's OWN account: no route carries a user
// id, so nobody can add a passkey to someone else's login.
//
// Pinned sessions (?pin=password_change | mfa_enroll, from GET /api/me
// `pinned`): one section is usable, every other nav item is inert and says
// why, and nothing else is fetched (those routes answer 403 while pinned).
// When the step is done we follow the response's `pinned` (another step) or
// `next`/?next= (through safeNext — A §7.5's open-redirect list).
//
// Backup codes are shown exactly once, with copy, print and download, and
// leave the page when the person says they've saved them. Dangerous changes
// (removing a factor, new backup codes, approving a device) go through
// api(), whose step-up dialog satisfies `step_up_required` and retries once.
//
// Exports for the tests: guessDeviceLabel, groupSecret, explainRisk.

import {
  $,
  h,
  icon,
  api,
  ApiError,
  busy,
  showError,
  setFieldError,
  toast,
  copyText,
  confirmDialog,
  mountTopBar,
  fmtDateTime,
  fmtRelative,
  fmtNumber,
  plural,
  safeNext,
  param,
  go,
  bindPasswordStrength,
  passwordFeedback,
  dataTable,
  emptyState,
  badge,
  downloadText,
} from './common.js';
import { supportsPasskeys, createPasskey } from './webauthn.js';

const SECTIONS = ['profile', 'password', 'security', 'sessions', 'devices', 'activity', 'browser'];
const PIN_SECTION = { password_change: 'password', mfa_enroll: 'security' };

const state = {
  me: null,
  pinned: null,
  codes: null, // the backup codes on screen right now, or null
  afterCodes: null, // what to do once they're acknowledged (a pinned step finishing)
};

// ------------------------------------------------------------ helpers ----

function listOf(r, key) {
  if (Array.isArray(r)) return r;
  if (r && typeof r === 'object' && Array.isArray(r[key])) return r[key];
  return [];
}

function n(v) {
  return typeof v === 'number' && Number.isFinite(v) && v >= 0 ? Math.floor(v) : 0;
}

function announce(text) {
  $('security-status').textContent = text;
}

function redirected(err) {
  return err instanceof ApiError && err.redirected;
}

// 'Chrome on macOS' — the same shape the server's deviceLabelFromUa gives.
export function guessDeviceLabel(ua) {
  const s = typeof ua === 'string' ? ua : '';
  let browser = '';
  if (/Edg(e|A|iOS)?\//.test(s)) browser = 'Edge';
  else if (/OPR\/|Opera/.test(s)) browser = 'Opera';
  else if (/SamsungBrowser\//.test(s)) browser = 'Samsung Internet';
  else if (/Firefox\/|FxiOS\//.test(s)) browser = 'Firefox';
  else if (/Chrome\/|CriOS\/|Chromium\//.test(s)) browser = 'Chrome';
  else if (/Safari\//.test(s) && /Version\//.test(s)) browser = 'Safari';
  let os = '';
  if (/iPhone/.test(s)) os = 'iPhone';
  else if (/iPad/.test(s)) os = 'iPad';
  else if (/Android/.test(s)) os = 'Android';
  else if (/Windows/.test(s)) os = 'Windows';
  else if (/CrOS/.test(s)) os = 'ChromeOS';
  else if (/Mac OS X|Macintosh/.test(s)) os = 'macOS';
  else if (/Linux/.test(s)) os = 'Linux';
  if (browser && os) return `${browser} on ${os}`;
  return browser || os || 'This device';
}

// 'JBSWY3DPEHPK3PXP' → 'JBSW Y3DP EHPK 3PXP' (A §7.3: grouped in fours).
export function groupSecret(b32) {
  if (typeof b32 !== 'string') return '';
  const clean = b32.replace(/[^A-Za-z2-7]/g, '').toUpperCase();
  return (clean.match(/.{1,4}/g) || []).join(' ');
}

// ------------------------------------------------------------- pinning ----

function strong(factors) {
  const f = factors && typeof factors === 'object' ? factors : {};
  return n(f.passkeys) > 0 || f.totp === true;
}

const PIN_COPY = {
  password_change: {
    title: 'Choose a new password to continue',
    body: 'Your password was reset, or it has to be changed before you carry on. Until you choose a new one, this is the only part of the portal you can use. You’re still signed in — nothing is lost.',
    extra: '',
    nav: 'The other sections open once you’ve chosen a new password.',
  },
  mfa_enroll: {
    title: 'Set up a second step to continue',
    body: 'Your organisation requires a passkey or an authenticator app on your account. Until one is confirmed, this is the only page you can use. You’re still signed in, and it takes about a minute.',
    extra: 'This is required for your account, not just recommended — so there’s no “Not now”. Sign out and come back later if now isn’t a good time.',
    nav: 'The other sections open once a passkey or authenticator app is confirmed.',
  },
};

function applyPin() {
  const pin = state.pinned;
  const allowed = pin ? PIN_SECTION[pin] : null;
  for (const id of SECTIONS) $(id).hidden = !!allowed && id !== allowed;
  for (const a of $('account-nav').querySelectorAll('a[data-section]')) {
    const sec = a.dataset.section;
    if (allowed && sec !== allowed) {
      a.removeAttribute('href');
      a.setAttribute('aria-disabled', 'true');
      a.setAttribute('title', PIN_COPY[pin].nav);
    } else {
      a.setAttribute('href', `#${sec}`);
      a.removeAttribute('aria-disabled');
      a.removeAttribute('title');
    }
    if (allowed && sec === allowed) a.classList.add('is-current');
    else a.classList.remove('is-current');
  }
  $('nav-locked').hidden = !allowed;
  $('nav-locked').textContent = allowed ? PIN_COPY[pin].nav : '';
  $('pin-banner').hidden = !allowed;
  if (allowed) {
    $('pin-title').textContent = PIN_COPY[pin].title;
    $('pin-body').textContent = PIN_COPY[pin].body;
    $('pin-extra').textContent = PIN_COPY[pin].extra;
    $('pin-extra').hidden = !PIN_COPY[pin].extra;
  }
  const me = state.me || {};
  $('enroll-prompt').hidden = !!allowed || !(me.enroll_prompt === true || (me.factors && !strong(me.factors)));
  // The skip button is an open-redirect candidate (A §7.5): same host only.
  $('enroll-skip').setAttribute('href', safeNext(param('next'), '/'));
}

// The pinned step is done: follow the server to the next step, or on to
// where the person was going.
async function afterPinStep(r) {
  let next = r && typeof r === 'object' && Object.hasOwn(r, 'pinned') ? r.pinned : undefined;
  if (next === undefined) {
    try {
      next = (await api('GET', '/api/me')).pinned;
    } catch {
      next = null;
    }
  }
  const carry = param('next');
  if (typeof next === 'string' && PIN_SECTION[next]) {
    const keep = carry && safeNext(carry, '') ? `&next=${encodeURIComponent(safeNext(carry))}` : '';
    go(`/account?pin=${encodeURIComponent(next)}${keep}`, { replace: true });
    return;
  }
  const serverNext = r && typeof r.next === 'string' ? r.next : null;
  go(safeNext(carry || serverNext, '/'), { replace: true });
}

function finishedPinnedStep(r, codes) {
  if (!state.pinned) return;
  if (Array.isArray(codes) && codes.length) state.afterCodes = () => afterPinStep(r);
  else afterPinStep(r);
}

// ------------------------------------------------------------- profile ----

function renderProfile() {
  const u = (state.me && state.me.user) || {};
  $('profile-name').value = typeof u.full_name === 'string' ? u.full_name : '';
  $('pw-username').value = u.email || u.username || '';
  const facts = [
    ['Email', u.email],
    ['Username', u.username],
    ['Employee number', u.employee_no],
    ['Job title', u.job_title],
    ['Department', u.department],
    ['Role', u.role && u.role.name],
  ];
  $('profile-facts').replaceChildren(...facts.flatMap(([k, v]) => [h('dt', null, k), h('dd', null, typeof v === 'string' && v ? v : '—')]));
}

async function saveProfile(e) {
  e.preventDefault();
  const input = $('profile-name');
  const name = input.value.trim();
  setFieldError(input, '');
  showError('profile-error', null);
  if (!name) return setFieldError(input, 'Enter your name.');
  if (name.length > 100) return setFieldError(input, 'Use at most 100 characters.');
  await busy($('profile-save'), async () => {
    try {
      const r = await api('PATCH', '/api/me', { full_name: name });
      const user = r && r.user && typeof r.user === 'object' ? r.user : { ...state.me.user, full_name: name };
      state.me.user = user;
      renderProfile();
      mountTopBar('topbar-slot', { me: state.me, active: 'account', locked: !!state.pinned });
      toast('Your name is saved.', 'ok');
    } catch (err) {
      showError('profile-error', err);
    }
  });
}

// ------------------------------------------------------------ password ----

function pwContext() {
  const u = (state.me && state.me.user) || {};
  return { email: u.email || '', username: u.username || '', name: u.full_name || '' };
}

async function changePassword(e) {
  e.preventDefault();
  const cur = $('pw-current');
  const nw = $('pw-new');
  const conf = $('pw-confirm');
  for (const i of [cur, nw, conf]) setFieldError(i, '');
  showError('pw-error', null);
  if (!cur.value) return setFieldError(cur, 'Enter your current password.');
  const f = passwordFeedback(nw.value, pwContext());
  if (!f.ok) return setFieldError(nw, f.message);
  if (nw.value === cur.value) return setFieldError(nw, 'Choose a password different from your current one.');
  if (conf.value !== nw.value) return setFieldError(conf, 'The passwords don’t match.');
  await busy($('pw-submit'), async () => {
    let r;
    try {
      r = await api('POST', '/api/me/password', { current: cur.value, next: nw.value });
    } catch (err) {
      if (err instanceof ApiError && err.status === 401 && !err.redirected) {
        cur.value = '';
        setFieldError(cur, err.message);
        cur.focus();
      } else showError('pw-error', err);
      return;
    }
    $('password-form').reset();
    for (const i of [cur, nw, conf]) i.value = '';
    toast('Password changed. Your other sessions were signed out.', 'ok');
    if (state.pinned) await afterPinStep(r);
  });
}

// ------------------------------------------------- two-step: rendering ----

function renderSecurity() {
  const me = state.me || {};
  const f = me.factors && typeof me.factors === 'object' ? me.factors : {};
  const pinned = !!state.pinned;
  $('mfa-summary').textContent = strong(f) ? 'Signing in takes your password and a second step.' : 'Right now your password alone signs you in.';

  // Passkeys
  const can = supportsPasskeys();
  $('passkey-form').hidden = !can;
  $('passkey-unsupported').hidden = can;
  if (can && !$('passkey-label').value) $('passkey-label').value = guessDeviceLabel(navigator.userAgent);
  const list = Array.isArray(me.passkeys) ? me.passkeys.filter((p) => p && typeof p === 'object') : null;
  const count = list ? list.length : n(f.passkeys);
  if (list) $('passkey-list').replaceChildren(...list.map((p) => passkeyRow(p, { pinned })));
  else $('passkey-list').replaceChildren(...(count ? [h('li', { class: 'item-row' }, h('span', { class: 'item-icon' }, icon('passkey')), h('span', { class: 'item-main' }, h('span', { class: 'item-title' }, plural(count, 'passkey'))))] : []));
  if (!count) $('passkey-list').replaceChildren(h('li', { class: 'item-row muted' }, 'No passkeys yet.'));

  // Authenticator app
  const totpOn = f.totp === true;
  if (f.totpUnreadable) {
    $('totp-state').replaceChildren(badge('Needs attention', 'danger'), ' Your authenticator can’t be read. Ask an administrator to reset it, then set it up again.');
  } else {
    $('totp-state').replaceChildren(totpOn ? badge('On', 'ok') : badge('Not set up', 'neutral'));
  }
  $('totp-start').hidden = totpOn || !!f.totpUnreadable;
  $('totp-remove').hidden = !totpOn || pinned;

  // Backup codes
  const b = n(f.backup);
  $('backup-state').replaceChildren(
    b ? badge(`${fmtNumber(b)} unused`, b <= 2 ? 'warn' : 'ok') : badge('None', 'neutral'),
    b && b <= 2 ? ' Running low — get a new set.' : '',
  );
  const rg = $('backup-regenerate');
  rg.hidden = pinned || !strong(f);
  rg.textContent = b ? 'Get new backup codes' : 'Get backup codes';

  // Destinations (admin-managed, A §9: adding one hands out a second factor)
  const d = n(f.destinations);
  $('dest-state').textContent = d
    ? `${plural(d, 'phone number or email address', 'phone numbers or email addresses')} can receive sign-in codes. An administrator manages these — ask one to add or change them.`
    : 'None. An administrator can add a phone number or email address that receives sign-in codes.';
}

function passkeyRow(p, { pinned }) {
  const label = typeof p.label === 'string' && p.label.trim() ? p.label.trim() : 'Passkey';
  const sub = [p.created_at ? `Added ${fmtRelative(p.created_at)}` : '', p.last_used_at ? `last used ${fmtRelative(p.last_used_at)}` : 'not used yet'].filter(Boolean).join(' · ');
  const title = h('span', { class: 'item-title' }, label);
  const main = h('span', { class: 'item-main' }, title, h('span', { class: 'item-sub' }, sub));
  const row = h('li', { class: 'item-row', dataset: { passkeyId: p.id } }, h('span', { class: 'item-icon' }, icon('passkey')), main);
  if (pinned) return row;
  const rename = h('button', { type: 'button', class: 'btn btn-ghost btn-sm', 'aria-label': `Rename ${label}` }, 'Rename');
  const remove = h('button', { type: 'button', class: 'btn btn-ghost btn-sm', 'aria-label': `Remove ${label}` }, 'Remove');
  rename.addEventListener('click', () => editPasskeyLabel(row, p, label));
  remove.addEventListener('click', () => removePasskey(remove, p, label));
  row.appendChild(h('span', { class: 'item-actions' }, rename, remove));
  return row;
}

function editPasskeyLabel(row, p, label) {
  const id = `passkey-rename-${p.id}`;
  const input = h('input', { id, type: 'text', maxlength: 60, value: label, 'aria-label': 'New name for this passkey', autocomplete: 'off' });
  const save = h('button', { type: 'submit', class: 'btn btn-primary btn-sm' }, 'Save');
  const cancel = h('button', { type: 'button', class: 'btn btn-ghost btn-sm' }, 'Cancel');
  const form = h('form', { class: 'item-edit', novalidate: true }, input, save, cancel);
  const actions = row.querySelector('.item-actions');
  if (actions) actions.hidden = true;
  row.appendChild(form);
  input.focus();
  cancel.addEventListener('click', () => {
    form.remove();
    if (actions) actions.hidden = false;
  });
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const v = input.value.trim();
    if (!v) return setFieldError(input, 'Give it a name you’ll recognise.');
    busy(save, async () => {
      try {
        await api('PATCH', `/api/me/mfa/passkey/${encodeURIComponent(p.id)}`, { label: v });
        toast('Renamed.', 'ok');
        await refreshMe();
      } catch (err) {
        setFieldError(input, err instanceof ApiError ? err.message : String(err));
      }
    });
  });
}

async function removePasskey(button, p, label) {
  showError('passkey-error', null);
  const ok = await confirmDialog({
    title: 'Remove this passkey?',
    body: `“${label}” will stop working for signing in here. The portal won’t let you remove your last way to confirm it’s you.`,
    confirmLabel: 'Remove passkey',
    danger: true,
  });
  if (!ok) return;
  await busy(button, async () => {
    try {
      await api('DELETE', `/api/me/mfa/passkey/${encodeURIComponent(p.id)}`);
      toast('Passkey removed.', 'ok');
      announce(`${label} removed.`);
      await refreshMe();
    } catch (err) {
      showError('passkey-error', err);
    }
  });
}

async function refreshMe() {
  try {
    const me = await api('GET', '/api/me');
    if (me && typeof me === 'object') state.me = me;
  } catch {
    // Keep what we have; the action itself already reported its result.
  }
  renderSecurity();
  applyPin();
}

// ----------------------------------------------------- passkey: adding ----

async function addPasskey(e) {
  e.preventDefault();
  showError('passkey-error', null);
  const input = $('passkey-label');
  const label = input.value.trim() || guessDeviceLabel(navigator.userAgent);
  if (label.length > 60) return setFieldError(input, 'Use at most 60 characters.');
  setFieldError(input, '');
  await busy($('passkey-add'), async () => {
    let r;
    try {
      const options = await api('POST', '/api/me/mfa/passkey/options', {});
      const cred = await createPasskey(options);
      if (cred && cred.cancelled) {
        announce('Cancelled — no passkey was added.');
        return;
      }
      if (!cred || cred.error) {
        showError('passkey-error', `Your browser couldn’t create a passkey${cred && cred.error ? `: ${cred.error}` : '.'}`);
        return;
      }
      r = await api('POST', '/api/me/mfa/passkey/register', { credential: cred, label });
    } catch (err) {
      showError('passkey-error', err);
      return;
    }
    input.value = '';
    toast(`Passkey “${label}” added.`, 'ok');
    announce('Passkey added.');
    await refreshMe();
    const codes = r && Array.isArray(r.backup_codes) ? r.backup_codes : null;
    if (codes && codes.length) showCodes(codes);
    finishedPinnedStep(r, codes);
  });
}

// ---------------------------------------------------- authenticator app ----

function clearTotpSetup() {
  $('totp-setup').hidden = true;
  $('totp-qr').removeAttribute('src');
  $('totp-secret').textContent = '';
  $('totp-link').setAttribute('href', '#totp-setup');
  $('totp-link').hidden = true;
  $('totp-code').value = '';
  showError('totp-error', null);
}

async function startTotp() {
  showError('totp-error', null);
  await busy($('totp-start'), async () => {
    let r;
    try {
      r = await api('POST', '/api/me/mfa/totp/begin', {});
    } catch (err) {
      showError('totp-error', err);
      $('totp-setup').hidden = true;
      return;
    }
    const qr = r && typeof r.qr === 'string' && /^data:image\/(svg\+xml|png);base64,/.test(r.qr) ? r.qr : null;
    if (qr) $('totp-qr').setAttribute('src', qr);
    else $('totp-qr').removeAttribute('src');
    const grouped = r && typeof r.secret_grouped === 'string' && r.secret_grouped.trim() ? r.secret_grouped.trim() : groupSecret(r && r.secret_b32);
    $('totp-secret').textContent = grouped;
    const uri = r && typeof r.otpauth === 'string' && /^otpauth:\/\/totp\//.test(r.otpauth) ? r.otpauth : null;
    $('totp-link').hidden = !uri;
    if (uri) $('totp-link').setAttribute('href', uri);
    $('totp-setup').hidden = false;
    $('totp-code').value = '';
    $('totp-code').focus();
  });
}

async function confirmTotp(e) {
  e.preventDefault();
  const input = $('totp-code');
  const code = input.value.replace(/\s+/g, '');
  showError('totp-error', null);
  if (!/^\d{6}$/.test(code)) {
    showError('totp-error', 'Enter the 6-digit code your app shows right now.');
    input.focus();
    return;
  }
  await busy($('totp-confirm'), async () => {
    let r;
    try {
      r = await api('POST', '/api/me/mfa/totp/confirm', { code });
    } catch (err) {
      input.value = '';
      showError('totp-error', err);
      input.focus();
      return;
    }
    clearTotpSetup();
    toast('Authenticator app added.', 'ok');
    announce('Authenticator app added.');
    await refreshMe();
    const codes = r && Array.isArray(r.backup_codes) ? r.backup_codes : null;
    if (codes && codes.length) showCodes(codes);
    finishedPinnedStep(r, codes);
  });
}

async function removeTotp() {
  const ok = await confirmDialog({
    title: 'Remove your authenticator app?',
    body: 'Codes from the app will stop working here. The portal won’t let you remove your last way to confirm it’s you.',
    confirmLabel: 'Remove app',
    danger: true,
  });
  if (!ok) return;
  await busy($('totp-remove'), async () => {
    try {
      await api('DELETE', '/api/me/mfa/totp');
      toast('Authenticator app removed.', 'ok');
      await refreshMe();
    } catch (err) {
      showError('totp-error', err);
    }
  });
}

// --------------------------------------------------------- backup codes ----

function codesText() {
  const me = state.me || {};
  const who = (me.user && (me.user.email || me.user.username)) || '';
  const org = typeof me.org_name === 'string' && me.org_name ? me.org_name : 'the staff portal';
  return [`Backup codes for ${org}${who ? ` — ${who}` : ''}`, `Saved ${new Date().toISOString().slice(0, 10)}. Each code works once.`, '', ...(state.codes || []), ''].join('\n');
}

// Shown once. Nothing keeps a copy: acknowledging removes them from the page.
function showCodes(codes) {
  const clean = codes.filter((c) => typeof c === 'string' && c.trim()).map((c) => c.trim());
  if (!clean.length) return;
  state.codes = clean;
  $('codes-list').replaceChildren(...clean.map((c) => h('li', { class: 'code-chars' }, c)));
  $('codes-panel').hidden = false;
  $('codes-panel').focus();
  try {
    $('codes-panel').scrollIntoView({ block: 'center' });
  } catch {
    // Old browsers without scroll options: never mind.
  }
}

function doneWithCodes() {
  state.codes = null;
  $('codes-list').replaceChildren();
  $('codes-panel').hidden = true;
  const then = state.afterCodes;
  state.afterCodes = null;
  if (then) then();
  else announce('Backup codes put away.');
}

async function regenerateCodes() {
  const ok = await confirmDialog({
    title: 'Get a new set of backup codes?',
    body: 'Your current backup codes stop working as soon as the new ones are made.',
    confirmLabel: 'Make new codes',
  });
  if (!ok) return;
  await busy($('backup-regenerate'), async () => {
    try {
      const r = await api('POST', '/api/me/mfa/backup/regenerate', {});
      await refreshMe();
      if (r && Array.isArray(r.backup_codes)) showCodes(r.backup_codes);
    } catch (err) {
      if (!redirected(err)) toast(err.message || String(err), 'danger');
    }
  });
}

function printCodes() {
  const body = document.body;
  body.classList.add('print-codes');
  const cleanup = () => body.classList.remove('print-codes');
  addEventListener('afterprint', cleanup, { once: true });
  try {
    window.print();
  } catch {
    cleanup();
  }
}

// ------------------------------------------------------------- sessions ----

async function loadSessions() {
  const list = $('session-list');
  showError('sessions-error', null);
  try {
    const rows = listOf(await api('GET', '/api/me/sessions'), 'sessions').filter((s) => s && typeof s === 'object');
    list.removeAttribute('aria-busy');
    $('sessions-others').hidden = !rows.some((s) => !s.current);
    if (!rows.length) {
      list.replaceChildren(h('li', { class: 'item-row muted' }, 'No sessions.'));
      return;
    }
    list.replaceChildren(
      ...rows.map((s) => {
        const ref = typeof s.id_ref === 'string' ? s.id_ref : '';
        const sub = [s.created_at ? `Signed in ${fmtRelative(s.created_at)}` : '', s.last_seen_at ? `active ${fmtRelative(s.last_seen_at)}` : '', typeof s.ip === 'string' ? s.ip : '', s.aal === 2 ? 'confirmed with a second step' : ''].filter(Boolean).join(' · ');
        let action = null;
        if (!s.current && ref) {
          action = h('button', { type: 'button', class: 'btn btn-ghost btn-sm' }, 'Sign out');
          action.addEventListener('click', () =>
            busy(action, async () => {
              try {
                await api('DELETE', `/api/me/sessions/${encodeURIComponent(ref)}`);
                toast('Signed out of that session.', 'ok');
                await loadSessions();
              } catch (err) {
                showError('sessions-error', err);
              }
            }),
          );
        }
        return h(
          'li',
          { class: 'item-row', dataset: { ref } },
          h('span', { class: 'item-icon' }, icon('device')),
          h('span', { class: 'item-main' }, h('span', { class: 'item-title' }, guessDeviceLabel(s.ua), s.current ? [' ', badge('This browser', 'accent')] : null), h('span', { class: 'item-sub' }, sub)),
          action ? h('span', { class: 'item-actions' }, action) : null,
        );
      }),
    );
  } catch (err) {
    list.removeAttribute('aria-busy');
    list.replaceChildren();
    showError('sessions-error', err);
  }
}

async function signOutOthers() {
  const ok = await confirmDialog({ title: 'Sign out everywhere else?', body: 'Every other browser signed in to your account is signed out. This one stays signed in.', confirmLabel: 'Sign out others' });
  if (!ok) return;
  await busy($('sessions-others'), async () => {
    try {
      const r = await api('POST', '/api/me/sessions/revoke-others', {});
      const k = r && typeof r.revoked === 'number' ? r.revoked : null;
      toast(k === null ? 'Signed out everywhere else.' : `Signed out of ${plural(k, 'other session')}.`, 'ok');
      await loadSessions();
    } catch (err) {
      showError('sessions-error', err);
    }
  });
}

// -------------------------------------------------------------- devices ----

const DEVICE_STATUS = { approved: ['Approved', 'ok'], pending: ['Waiting for approval', 'warn'], blocked: ['Blocked', 'danger'] };

async function loadDevices() {
  const list = $('device-list');
  showError('devices-error', null);
  let rows;
  try {
    rows = listOf(await api('GET', '/api/me/devices'), 'devices').filter((d) => d && typeof d === 'object');
  } catch (err) {
    list.removeAttribute('aria-busy');
    list.replaceChildren();
    showError('devices-error', err);
    return;
  }
  list.removeAttribute('aria-busy');
  list.replaceChildren(
    ...(rows.length
      ? rows.map((d) => {
          const [statusText, kind] = DEVICE_STATUS[d.status] || [String(d.status || 'Unknown'), 'neutral'];
          const label = typeof d.label === 'string' && d.label.trim() ? d.label.trim() : 'Unnamed device';
          const forget = h('button', { type: 'button', class: 'btn btn-ghost btn-sm', 'aria-label': `Forget ${label}` }, 'Forget');
          forget.addEventListener('click', () => forgetDevice(forget, d, label));
          const sub = [d.last_seen_at ? `Last used ${fmtRelative(d.last_seen_at)}` : '', typeof d.ip === 'string' ? d.ip : ''].filter(Boolean).join(' · ');
          return h(
            'li',
            { class: 'item-row', dataset: { deviceId: d.id } },
            h('span', { class: 'item-icon' }, icon('device')),
            h('span', { class: 'item-main' }, h('span', { class: 'item-title' }, label, ' ', badge(statusText, kind), d.current ? [' ', badge('This device', 'accent')] : null), h('span', { class: 'item-sub' }, sub)),
            h('span', { class: 'item-actions' }, forget),
          );
        })
      : [h('li', { class: 'item-row muted' }, 'No devices yet.')]),
  );
  // Approving needs an approved device to approve FROM (SPEC §8.2).
  const here = rows.find((d) => d.current === true);
  const blocked = !!here && here.status !== 'approved';
  $('approve-code').disabled = blocked;
  $('approve-submit').disabled = blocked;
  $('approve-note').textContent = blocked
    ? 'This browser isn’t an approved device yet, so it can’t approve others. Ask an administrator to approve it, or do this from a device that is approved.'
    : 'On the new device, open the portal: it shows a code like K7F3-9QX2. Type it here to approve that device for your account. This works only from a device that is itself approved, and asks you to confirm it’s you first.';
}

async function forgetDevice(button, d, label) {
  const ok = await confirmDialog({
    title: `Forget ${label}?`,
    body: d.current ? 'This is the browser you’re using: forgetting it signs you out here, and it will have to confirm it’s you next time.' : 'It is signed out, and it will have to confirm it’s you the next time it signs in.',
    confirmLabel: 'Forget device',
    danger: true,
  });
  if (!ok) return;
  await busy(button, async () => {
    try {
      await api('DELETE', `/api/me/devices/${encodeURIComponent(d.id)}`);
      toast(`${label} forgotten.`, 'ok');
      await loadDevices();
    } catch (err) {
      showError('devices-error', err);
    }
  });
}

async function approveDevice(e) {
  e.preventDefault();
  const input = $('approve-code');
  showError('approve-error', null);
  const code = input.value.trim().toUpperCase().replace(/\s+/g, '');
  if (!code) return showError('approve-error', 'Enter the code shown on the other device.');
  if (!/^[A-Z0-9][A-Z0-9-]{3,15}$/.test(code)) return showError('approve-error', 'That doesn’t look like a device code. They look like K7F3-9QX2.');
  await busy($('approve-submit'), async () => {
    try {
      await api('POST', '/api/me/devices/approve', { code });
      input.value = '';
      toast('Approved. That device can sign in now.', 'ok');
      await loadDevices();
    } catch (err) {
      showError('approve-error', err);
    }
  });
}

// ------------------------------------------------------------- activity ----

const OUTCOME_KIND = { success: 'ok', failure: 'warn', denied: 'danger' };

async function loadActivity() {
  const box = $('activity-list');
  try {
    const rows = listOf(await api('GET', '/api/me/activity'), 'entries').filter((r) => r && typeof r === 'object');
    box.removeAttribute('aria-busy');
    box.replaceChildren(
      dataTable({
        caption: 'Your recent activity',
        columns: [
          { key: 'at', label: 'When', render: (r) => h('time', { datetime: typeof r.at === 'string' ? r.at : null, title: fmtRelative(r.at) }, fmtDateTime(r.at)) },
          { key: 'detail', label: 'What', render: (r) => (typeof r.detail === 'string' && r.detail ? r.detail : String(r.action || '')) },
          { key: 'outcome', label: 'Outcome', render: (r) => badge(String(r.outcome || 'success'), OUTCOME_KIND[r.outcome] || 'neutral') },
          { key: 'ip', label: 'From', render: (r) => (typeof r.ip === 'string' ? h('span', { class: 'mono' }, r.ip) : '') },
        ],
        rows,
        empty: emptyState({ icon: 'clock', title: 'Nothing yet', body: 'Your sign-ins and changes to your account will show here.' }),
      }),
    );
  } catch (err) {
    box.removeAttribute('aria-busy');
    showError('activity-error', err);
  }
}

// ---------------------------------------------------------- fingerprint ----

// Turns GET /api/me/fingerprint into { score, flags, threshold, facts } —
// tolerant of shape, because the point is to explain, not to crash (B §6).
export function explainRisk(r) {
  const body = r && typeof r === 'object' ? r : {};
  const fp = body.fingerprint && typeof body.fingerprint === 'object' ? body.fingerprint : body.fingerprint === null ? null : body;
  const risk = (body.risk && typeof body.risk === 'object' && body.risk) || (fp && fp.risk && typeof fp.risk === 'object' && fp.risk) || {};
  const rawScore = typeof risk.score === 'number' ? risk.score : typeof body.score === 'number' ? body.score : fp && typeof fp.risk === 'number' ? fp.risk : null;
  const score = rawScore === null || !Number.isFinite(rawScore) ? null : Math.max(0, Math.min(100, Math.round(rawScore)));
  const flagsIn = Array.isArray(risk.flags) ? risk.flags : Array.isArray(body.flags) ? body.flags : fp && Array.isArray(fp.flags) ? fp.flags : [];
  const flags = flagsIn
    .filter((f) => f && typeof f === 'object')
    .map((f) => ({ key: typeof f.key === 'string' ? f.key : '', weight: typeof f.weight === 'number' && Number.isFinite(f.weight) ? f.weight : 0, reason: typeof f.reason === 'string' && f.reason ? f.reason : typeof f.key === 'string' ? f.key : 'Unexplained signal' }))
    .sort((a, b) => b.weight - a.weight);
  const threshold = typeof body.threshold === 'number' && Number.isFinite(body.threshold) ? body.threshold : null;
  const sum = flags.reduce((t, f) => t + f.weight, 0);
  const src = fp || {};
  const pick = (...keys) => {
    for (const k of keys) if (typeof src[k] === 'string' && src[k]) return src[k];
    return '';
  };
  const facts = [
    ['Visitor id', pick('visitor_id').slice(0, 12)],
    ['First seen', src.first_seen ? fmtDateTime(src.first_seen) : ''],
    ['Last seen', src.last_seen ? fmtDateTime(src.last_seen) : ''],
    ['IP address', pick('ip')],
    ['Country', pick('country')],
    ['Network', pick('as_org') || (typeof src.asn === 'number' ? `AS${src.asn}` : pick('asn'))],
    ['Browser', src.ua ? guessDeviceLabel(src.ua) : ''],
    ['Time zone', pick('tz', 'timezone')],
  ].filter(([, v]) => v);
  return { present: fp !== null && (score !== null || flags.length > 0 || facts.length > 0), score, flags, threshold, capped: sum > 100, facts };
}

function riskLevel(score, threshold) {
  const t = threshold || 70;
  if (score >= t) return ['High', 'danger'];
  if (score >= Math.min(30, t - 1)) return ['Medium', 'warn'];
  return ['Low', 'ok'];
}

async function loadFingerprint() {
  const body = $('fp-body');
  const notice = state.me && typeof state.me.privacy_notice === 'string' && state.me.privacy_notice ? state.me.privacy_notice : '';
  $('fp-notice').hidden = !notice;
  $('fp-notice').replaceChildren(...(notice ? [icon('info', { size: 16 }), h('span', null, notice)] : []));
  let r;
  try {
    r = await api('GET', '/api/me/fingerprint');
  } catch (err) {
    body.removeAttribute('aria-busy');
    showError('fp-error', err);
    return;
  }
  body.removeAttribute('aria-busy');
  const x = explainRisk(r);
  if (!x.present) {
    body.replaceChildren(emptyState({ icon: 'eye', title: 'Nothing recorded yet', body: 'This browser reports its details in the background when you open the sign-in page. Sign out and back in to see them here.' }));
    return;
  }
  const parts = [];
  if (x.score !== null) {
    const [word, kind] = riskLevel(x.score, x.threshold);
    const meter = h('meter', { id: 'fp-meter', class: 'risk-meter', min: 0, max: 100, low: 30, high: x.threshold || 70, optimum: 0, 'aria-label': 'Risk score' });
    meter.setAttribute('value', String(x.score));
    parts.push(
      h('p', { id: 'fp-score', class: 'risk-score' }, h('strong', null, String(x.score)), ' ', h('span', { class: 'muted' }, 'out of 100'), ' ', badge(`${word} risk`, kind)),
      meter,
      h('p', { class: 'muted' }, x.threshold !== null ? `Browsers scoring ${x.threshold} or more are refused. ${x.flags.length ? 'Here is what added up to yours:' : ''}` : x.flags.length ? 'Here is what added up to your score:' : ''),
    );
  }
  parts.push(
    x.flags.length
      ? h(
          'ul',
          { id: 'fp-flags', class: 'flag-list' },
          x.flags.map((f) => h('li', { dataset: { flag: f.key } }, h('span', null, f.reason), h('span', { class: 'flag-weight', 'aria-label': `${f.weight} points` }, `+${f.weight}`))),
        )
      : h('p', { id: 'fp-flags', class: 'banner banner-ok' }, 'Nothing about this browser raised the score.'),
  );
  if (x.capped) parts.push(h('p', { class: 'hint' }, 'The reasons add up to more than 100; the score stops at 100.'));
  if (x.facts.length) parts.push(h('dl', { id: 'fp-facts', class: 'kv' }, x.facts.flatMap(([k, v]) => [h('dt', null, k), h('dd', null, v)])));
  body.replaceChildren(...parts);
}

// ----------------------------------------------------------------- main ----

let bound = false;

function bind() {
  if (bound) return;
  bound = true;
  $('profile-form').addEventListener('submit', saveProfile);
  $('password-form').addEventListener('submit', changePassword);
  $('passkey-form').addEventListener('submit', addPasskey);
  $('totp-start').addEventListener('click', startTotp);
  $('totp-form').addEventListener('submit', confirmTotp);
  $('totp-cancel').addEventListener('click', clearTotpSetup);
  $('totp-remove').addEventListener('click', removeTotp);
  $('totp-copy').addEventListener('click', async () => {
    const ok = await copyText($('totp-secret').textContent.replace(/\s+/g, ''));
    toast(ok ? 'Key copied.' : 'Couldn’t copy — select the key and copy it by hand.', ok ? 'ok' : 'warn');
  });
  $('backup-regenerate').addEventListener('click', regenerateCodes);
  $('codes-copy').addEventListener('click', async () => {
    const ok = await copyText((state.codes || []).join('\n'));
    toast(ok ? 'Codes copied.' : 'Couldn’t copy — print or download them instead.', ok ? 'ok' : 'warn');
  });
  $('codes-print').addEventListener('click', printCodes);
  $('codes-download').addEventListener('click', () => {
    if (!downloadText('backup-codes.txt', codesText())) toast('Your browser blocked the download — copy or print the codes instead.', 'warn');
  });
  $('codes-done').addEventListener('click', doneWithCodes);
  $('sessions-others').addEventListener('click', signOutOthers);
  $('approve-form').addEventListener('submit', approveDevice);
  bindPasswordStrength({ input: $('pw-new'), confirm: $('pw-confirm'), meter: $('pw-meter'), hint: $('pw-hint'), context: pwContext });
  // Leaving with the codes still unsaved loses them for good.
  addEventListener('beforeunload', (e) => {
    if (state.codes) {
      e.preventDefault();
      e.returnValue = '';
    }
  });
}

async function main() {
  bind();
  let me;
  try {
    me = await api('GET', '/api/me');
  } catch (err) {
    showError('load-error', err);
    return;
  }
  state.me = me && typeof me === 'object' ? me : {};
  state.pinned = typeof state.me.pinned === 'string' && PIN_SECTION[state.me.pinned] ? state.me.pinned : null;
  const org = typeof state.me.org_name === 'string' && state.me.org_name ? state.me.org_name : '';
  document.title = org ? `Your account · ${org}` : 'Your account';
  mountTopBar('topbar-slot', { me: state.me, active: 'account', locked: !!state.pinned });
  applyPin();
  renderProfile();
  renderSecurity();
  if (state.pinned) {
    const sec = $(PIN_SECTION[state.pinned]);
    try {
      sec.scrollIntoView({ block: 'start' });
    } catch {
      // Not essential.
    }
    return;
  }
  await Promise.allSettled([loadSessions(), loadDevices(), loadActivity(), loadFingerprint()]);
}

main();
