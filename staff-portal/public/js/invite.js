// invite.js — accept an invitation (CONTRACTS §8.4 Public; D11).
//
// Reads ?token=, looks it up (POST /api/invite/lookup { token } → { email, full_name,
// org_name, expires_at }) and, only if it is valid, shows the form. Accepting
// (POST /api/invite/accept { token, password, full_name }) signs the person
// in and approves this browser; we go to response.next or '/'. An invalid or
// expired link gets a clear sentence and no form. The invite shell allows
// this script, common.js and fp.js only.

import { $, api, ApiError, busy, showError, setFieldError, bindPasswordStrength, passwordFeedback, confirmSignedIn, safeNext, go, param, fmtDateTime, fmtRelative, errorMessage } from './common.js';
import { reportFingerprint } from './fp.js';

const el = {
  org: $('org-name'),
  title: $('title'),
  paneLoading: $('pane-loading'),
  paneInvalid: $('pane-invalid'),
  paneForm: $('pane-form'),
  paneCookie: $('pane-cookie'),
  invalidDetail: $('invalid-detail'),
  inviteOrgLine: $('invite-org-line'),
  inviteOrg: $('invite-org'),
  inviteEmail: $('invite-email'),
  inviteExpires: $('invite-expires'),
  form: $('form-invite'),
  name: $('full_name'),
  password: $('password'),
  confirm: $('confirm'),
  meter: $('password-meter'),
  hint: $('password-hint'),
  error: $('invite-error'),
  submit: $('invite-submit'),
  privacy: $('privacy'),
  privacyText: $('privacy-text'),
};

const FIELDS = { full_name: el.name, password: el.password, confirm: el.confirm };
const state = { token: '', email: '' };

function showOnly(pane) {
  for (const p of [el.paneLoading, el.paneInvalid, el.paneForm, el.paneCookie]) p.hidden = p !== pane;
}

function invalid(detail) {
  if (detail) el.invalidDetail.textContent = detail;
  el.title.textContent = 'Invitation not valid';
  showOnly(el.paneInvalid);
}

function validate() {
  const problems = {};
  if (!el.name.value.trim()) problems.full_name = 'Enter your name.';
  const pw = passwordFeedback(el.password.value, { email: state.email, name: el.name.value });
  if (!pw.ok) problems.password = pw.message;
  if (!problems.password && el.confirm.value !== el.password.value) problems.confirm = 'The passwords don’t match.';
  for (const [k, input] of Object.entries(FIELDS)) setFieldError(input, problems[k] || '');
  const first = Object.keys(FIELDS).find((k) => problems[k]);
  if (first) FIELDS[first].focus();
  return !first;
}

async function onSubmit(e) {
  e.preventDefault();
  showError(el.error, null);
  if (!validate()) return;
  await busy(el.submit, async () => {
    let resp;
    try {
      resp = await api('POST', '/api/invite/accept', { token: state.token, password: el.password.value, full_name: el.name.value.trim() });
    } catch (err) {
      if (err instanceof ApiError && (err.status === 404 || err.status === 410)) {
        invalid('This invitation stopped working while you were filling in the form — it may have expired or been replaced.');
        return;
      }
      const field = err instanceof ApiError && err.body && typeof err.body.field === 'string' ? FIELDS[err.body.field] : null;
      if (field) {
        setFieldError(field, err.message);
        field.focus();
      } else showError(el.error, err);
      return;
    }
    if ((await confirmSignedIn()) === false) {
      showOnly(el.paneCookie);
      return;
    }
    go(safeNext(resp && resp.next), { replace: true });
  });
}

async function init() {
  // Invitation visitors are fingerprinted like everyone else (B §6); never awaited.
  reportFingerprint();
  el.form.addEventListener('submit', onSubmit);
  bindPasswordStrength({ input: el.password, confirm: el.confirm, meter: el.meter, hint: el.hint, context: () => ({ email: state.email, name: el.name.value }) });

  const token = (param('token') || '').trim();
  if (!token || token.length > 512) {
    invalid('This page needs the full link from your invitation. Open the link exactly as you received it.');
    return;
  }
  state.token = token;
  let info;
  try {
    // In the body, never a path: no URL anywhere — proxy, edge log, history —
    // ever holds the token (SPEC §13.6).
    info = await api('POST', '/api/invite/lookup', { token });
  } catch (err) {
    if (err instanceof ApiError && (err.status === 404 || err.status === 410)) invalid();
    else invalid(`We couldn’t check this invitation. ${errorMessage(err)}`);
    return;
  }
  state.email = typeof info.email === 'string' ? info.email : '';
  if (typeof info.org_name === 'string' && info.org_name) {
    el.org.textContent = info.org_name;
    el.inviteOrg.textContent = info.org_name;
    el.inviteOrgLine.hidden = false;
    document.title = `Join ${info.org_name}`;
  }
  el.inviteEmail.textContent = state.email || '—';
  el.inviteExpires.textContent = info.expires_at ? `${fmtDateTime(info.expires_at)} (${fmtRelative(info.expires_at)})` : '—';
  if (typeof info.full_name === 'string') el.name.value = info.full_name;
  // The markup carries the default notice (the invite shell has no whoami);
  // a response that names the setting wins: text → shown, null → turned off.
  if (typeof info.privacy_notice === 'string' && info.privacy_notice.trim()) el.privacyText.textContent = info.privacy_notice.trim();
  else if (info.privacy_notice === null) el.privacy.hidden = true;
  showOnly(el.paneForm);
  (el.name.value ? el.password : el.name).focus();
}

init();
