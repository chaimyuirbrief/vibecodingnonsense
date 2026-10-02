// setup.js — first-run bootstrap (CONTRACTS §8.4 Public: /api/setup).
//
// GET /api/setup/status → { needed, org_name }. The form posts
// { setup_key, email, full_name, password } to POST /api/setup, which signs
// the new Super Admin in pinned to `mfa_enroll`; we then go to response.next
// (normally /account?pin=mfa_enroll). The setup shell allows only this script
// and common.js (CONTRACTS §7.8), so nothing else is imported.

import { $, api, ApiError, busy, showError, setFieldError, bindPasswordStrength, passwordFeedback, confirmSignedIn, safeNext, go } from './common.js';

const el = {
  org: $('org-name'),
  statusError: $('status-error'),
  paneForm: $('pane-form'),
  paneDone: $('pane-done'),
  paneCookie: $('pane-cookie'),
  form: $('form-setup'),
  key: $('setup_key'),
  name: $('full_name'),
  email: $('email'),
  password: $('password'),
  confirm: $('confirm'),
  meter: $('password-meter'),
  hint: $('password-hint'),
  error: $('setup-error'),
  submit: $('setup-submit'),
};

const FIELDS = { setup_key: el.key, full_name: el.name, email: el.email, password: el.password, confirm: el.confirm };
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function showOnly(pane) {
  for (const p of [el.paneForm, el.paneDone, el.paneCookie]) p.hidden = p !== pane;
}

function validate() {
  const problems = {};
  if (!el.key.value.trim()) problems.setup_key = 'Enter the setup key.';
  if (!el.name.value.trim()) problems.full_name = 'Enter your name.';
  if (!EMAIL_RE.test(el.email.value.trim())) problems.email = 'Enter a valid email address.';
  const pw = passwordFeedback(el.password.value, { email: el.email.value.trim(), name: el.name.value });
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
      resp = await api('POST', '/api/setup', {
        setup_key: el.key.value.trim(),
        email: el.email.value.trim(),
        full_name: el.name.value.trim(),
        password: el.password.value,
      });
    } catch (err) {
      const field = err instanceof ApiError && err.body && typeof err.body.field === 'string' ? FIELDS[err.body.field] : null;
      if (field) {
        setFieldError(field, err.message);
        field.focus();
      } else {
        showError(el.error, err);
      }
      if (err instanceof ApiError && err.status === 403) {
        el.key.value = '';
        el.key.focus();
      }
      return;
    }
    if ((await confirmSignedIn()) === false) {
      showOnly(el.paneCookie);
      return;
    }
    go(safeNext(resp && resp.next, '/account?pin=mfa_enroll'), { replace: true });
  });
}

async function init() {
  el.form.addEventListener('submit', onSubmit);
  bindPasswordStrength({
    input: el.password,
    confirm: el.confirm,
    meter: el.meter,
    hint: el.hint,
    context: () => ({ email: el.email.value.trim(), name: el.name.value }),
  });
  let status;
  try {
    status = await api('GET', '/api/setup/status');
  } catch (err) {
    // 403/404: the route is gone because setup already ran (or the gate has
    // moved on). Anything else: keep the form and say what happened.
    if (err instanceof ApiError && (err.status === 403 || err.status === 404 || err.status === 410)) showOnly(el.paneDone);
    else showError(el.statusError, err);
    return;
  }
  if (status && typeof status.org_name === 'string' && status.org_name) {
    el.org.textContent = status.org_name;
    document.title = `Set up · ${status.org_name}`;
  }
  if (status && status.needed === false) {
    showOnly(el.paneDone);
    return;
  }
  el.key.focus();
}

init();
