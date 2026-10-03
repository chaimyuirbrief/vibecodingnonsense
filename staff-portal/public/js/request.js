// request.js — request access (CONTRACTS §8.4 Public: POST /api/access-request).
//
// Whatever the server answers — accepted, already known, rate-limited,
// refused — the visitor sees the SAME thank-you, so the form cannot be used
// to learn whether an email belongs to someone here (no enumeration). The one
// exception is a request that never reached the server (network failure):
// we say so, because "thanks" would be a lie and they would not retry.
// The request shell allows this script, common.js and fp.js only.

import { $, api, ApiError, busy, showError, setFieldError } from './common.js';
import { reportFingerprint } from './fp.js';

const el = {
  title: $('title'),
  intro: $('intro'),
  paneForm: $('pane-form'),
  paneThanks: $('pane-thanks'),
  form: $('form-request'),
  name: $('full_name'),
  email: $('email'),
  reason: $('reason'),
  reasonCount: $('reason-count'),
  error: $('request-error'),
  submit: $('request-submit'),
  privacy: $('privacy'),
  privacyText: $('privacy-text'),
};

const FIELDS = { full_name: el.name, email: el.email, reason: el.reason };
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function validate() {
  const problems = {};
  if (!el.name.value.trim()) problems.full_name = 'Enter your name.';
  if (!EMAIL_RE.test(el.email.value.trim())) problems.email = 'Enter a valid email address.';
  const reason = el.reason.value.trim();
  if (!reason) problems.reason = 'Tell us briefly why you need access.';
  else if (reason.length > 500) problems.reason = 'Keep it to 500 characters.';
  for (const [k, input] of Object.entries(FIELDS)) setFieldError(input, problems[k] || '');
  const first = Object.keys(FIELDS).find((k) => problems[k]);
  if (first) FIELDS[first].focus();
  return !first;
}

function thanks() {
  el.paneForm.hidden = true;
  el.intro.hidden = true;
  el.title.textContent = 'Request sent';
  el.paneThanks.hidden = false;
  el.paneThanks.focus();
}

async function onSubmit(e) {
  e.preventDefault();
  showError(el.error, null);
  if (!validate()) return;
  await busy(el.submit, async () => {
    try {
      await api('POST', '/api/access-request', { email: el.email.value.trim(), full_name: el.name.value.trim(), reason: el.reason.value.trim() });
    } catch (err) {
      if (err instanceof ApiError && err.status === 0) {
        showError(el.error, err);
        return;
      }
      // Any answer from the server — including a refusal — gets the same page.
    }
    thanks();
  });
}

function updateCount() {
  el.reasonCount.textContent = `${el.reason.value.length} / 500`;
}

el.form.addEventListener('submit', onSubmit);
el.reason.addEventListener('input', updateCount);
updateCount();
// Never awaited: the form works whether or not the report gets through. The
// markup carries the default notice; the reply names the real setting — text
// replaces it, null (turned off) hides it.
reportFingerprint().then((r) => {
  if (typeof r?.privacy_notice === 'string' && r.privacy_notice.trim()) el.privacyText.textContent = r.privacy_notice.trim();
  else if (r && r.privacy_notice === null) el.privacy.hidden = true;
});
