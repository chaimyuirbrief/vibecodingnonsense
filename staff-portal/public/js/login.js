// login.js — the sign-in page (CONTRACTS §8.4 Auth, §10; A §7.6; B §6, §10).
//
// The state machine, after the password is accepted (A §7.6):
//
//   server already sent a code ─────────────▶ code box, "We sent a code to …"
//   exactly one method THIS BROWSER can use ─▶ open it directly (no list of one)
//   two or more ────────────────────────────▶ chooser, strongest first,
//                                              nothing fired until a click
//   none this browser can use ──────────────▶ an explanation — never an empty list
//
// "Use a different method" appears only when this browser can offer two or
// more. A dismissed passkey dialog returns quietly to the chooser. A passkey
// assertion that the server refused has spent its challenge, so the button
// turns into "Start over". After any success we ask whoami before navigating:
// if the cookie did not stick we say so instead of looping (A §5).
//
// Fingerprinting runs in the background from page load (B §6). In
// fingerprint_gate mode the login API answers 403 { fingerprint_required };
// then we wait for the report and retry once.

import { $, h, icon, api, ApiError, busy, showError, safeNext, param, go, confirmSignedIn, errorMessage } from './common.js';
import { supportsPasskeys, getPasskey } from './webauthn.js';
import { reportFingerprint } from './fp.js';

const el = {
  org: $('org-name'),
  title: $('title'),
  subtitle: $('subtitle'),
  status: $('status'),
  privacy: $('privacy'),
  paneChoose: $('pane-choose'),
  panePassword: $('pane-password'),
  paneCode: $('pane-code'),
  paneOtp: $('pane-otp'),
  panePasskey: $('pane-passkey'),
  paneNone: $('pane-none'),
  paneCookie: $('pane-cookie'),
  paneEnroll: $('pane-enroll'),
  formPassword: $('form-password'),
  identifier: $('identifier'),
  password: $('password'),
  passwordError: $('password-error'),
  passwordSubmit: $('password-submit'),
  choices: $('choices'),
  chooseError: $('choose-error'),
  formCode: $('form-code'),
  code: $('code'),
  codeLabel: $('code-label'),
  codeHint: $('code-hint'),
  codeError: $('code-error'),
  codeSubmit: $('code-submit'),
  codeToggle: $('code-toggle'),
  formOtp: $('form-otp'),
  otp: $('otp'),
  otpSent: $('otp-sent'),
  otpError: $('otp-error'),
  otpSubmit: $('otp-submit'),
  otpResend: $('otp-resend'),
  passkeyGo: $('passkey-go'),
  passkeyError: $('passkey-error'),
  noneDetail: $('none-detail'),
  noneAdvice: $('none-advice'),
  cookieRetry: $('cookie-retry'),
  enrollSetup: $('enroll-setup'),
  enrollSkip: $('enroll-skip'),
  footer: $('mfa-footer'),
  otherMethod: $('other-method'),
  startOver: $('start-over'),
};

const PANES = [el.panePassword, el.paneChoose, el.paneCode, el.paneOtp, el.panePasskey, el.paneNone, el.paneCookie, el.paneEnroll];
const METHOD_PANES = [el.paneCode, el.paneOtp, el.panePasskey];
const MFA_PANES = [el.paneChoose, el.paneCode, el.paneOtp, el.panePasskey, el.paneNone];

const state = {
  token: null,
  methods: [],
  destinations: [],
  options: [],
  destId: null,
  codeMode: 'app',
  passkeySpent: false,
  fp: null,
};

function announce(text) {
  el.status.textContent = text;
}

function showPane(pane, title) {
  for (const p of PANES) p.hidden = p !== pane;
  if (title) el.title.textContent = title;
  el.subtitle.hidden = pane !== el.panePassword;
  const inMfa = MFA_PANES.includes(pane);
  el.footer.hidden = !inMfa;
  el.otherMethod.hidden = !(METHOD_PANES.includes(pane) && state.options.length >= 2);
}

// ------------------------------------------------------------ options ----

// What THIS browser can offer, strongest first (D8: passkey > TOTP > backup
// code > texted/emailed code). The authenticator app and backup codes share
// one box, so they are one option.
function browserOptions(methods, destinations) {
  const out = [];
  if (methods.includes('passkey') && supportsPasskeys()) out.push({ kind: 'passkey' });
  if (methods.includes('totp')) out.push({ kind: 'app' });
  else if (methods.includes('backup')) out.push({ kind: 'backup' });
  for (const d of destinations) out.push({ kind: 'send', dest: d });
  return out;
}

function optionView(opt) {
  if (opt.kind === 'passkey') return { icon: 'passkey', title: 'Use a passkey', sub: 'Fingerprint, face, screen lock or security key' };
  if (opt.kind === 'app') return { icon: 'app', title: 'Authenticator app', sub: 'Enter the 6-digit code — or a backup code' };
  if (opt.kind === 'backup') return { icon: 'backup', title: 'Backup code', sub: 'One of the codes you saved when you set up' };
  const d = opt.dest;
  const email = d.kind === 'email';
  return {
    icon: email ? 'mail' : 'sms',
    title: `${email ? 'Email' : 'Text'} a code to ${d.hint || (email ? 'your email' : 'your phone')}`,
    sub: d.label ? String(d.label) : email ? 'We’ll email you a 6-digit code' : 'We’ll text you a 6-digit code',
  };
}

function renderChoices() {
  el.choices.replaceChildren(
    ...state.options.map((opt) => {
      const v = optionView(opt);
      return h(
        'li',
        null,
        h(
          'button',
          {
            type: 'button',
            class: 'choice',
            'data-kind': opt.kind,
            'data-dest': opt.dest ? String(opt.dest.id) : null,
            onclick: () => openOption(opt, { auto: false }),
          },
          h('span', { class: 'choice-icon' }, icon(v.icon)),
          h('span', { class: 'choice-text' }, h('span', { class: 'choice-title' }, v.title), h('span', { class: 'choice-sub' }, v.sub)),
          h('span', { class: 'choice-chevron' }, icon('chevron-right', { size: 18 })),
        ),
      );
    }),
  );
}

function openChooser() {
  showError(el.chooseError, null);
  renderChoices();
  showPane(el.paneChoose, 'Confirm it’s you');
  const first = el.choices.querySelector('button');
  if (first) first.focus();
}

function openOption(opt, { auto }) {
  if (opt.kind === 'passkey') return openPasskey({ autoStart: true });
  if (opt.kind === 'app' || opt.kind === 'backup') return openCode(opt.kind);
  return sendCode(opt.dest, { auto });
}

function openNone() {
  const accountHasPasskey = state.methods.includes('passkey');
  el.noneDetail.textContent = accountHasPasskey
    ? 'Your account confirms sign-ins with a passkey, and this browser can’t use passkeys.'
    : 'Your account doesn’t have a second step this page can use yet.';
  el.noneAdvice.textContent = accountHasPasskey
    ? 'Passkeys work in current versions of Chrome, Edge, Safari and Firefox on a device with a screen lock or a security key — open this page in one of those. Or ask an administrator to add a phone number or email address to your account so we can send you a code instead.'
    : 'Ask an administrator to add a phone number or email address to your account so we can send you a code, or to reset your sign-in methods.';
  showPane(el.paneNone, 'Confirm it’s you');
}

// --------------------------------------------------------------- code ----

function setCodeMode(mode) {
  state.codeMode = mode;
  const backup = mode === 'backup';
  el.codeLabel.textContent = backup ? 'Backup code' : 'Code from your authenticator app';
  el.code.setAttribute('inputmode', backup ? 'text' : 'numeric');
  el.code.placeholder = backup ? 'ABCDE-FGHJK' : '123456';
  el.codeHint.textContent = backup
    ? 'Each backup code works once. Capitals, spaces and dashes don’t matter.'
    : 'Open your authenticator app and enter the 6-digit code for this portal.';
  // The toggle only offers what the account has: the app needs TOTP.
  const canSwitch = backup ? state.methods.includes('totp') : state.methods.includes('backup');
  el.codeToggle.hidden = !canSwitch;
  el.codeToggle.textContent = backup ? 'Use your authenticator app instead' : 'Use a backup code instead';
}

function openCode(kind) {
  setCodeMode(kind === 'backup' ? 'backup' : 'app');
  el.code.value = '';
  showError(el.codeError, null);
  showPane(el.paneCode, 'Confirm it’s you');
  el.code.focus();
}

async function onCodeSubmit(e) {
  e.preventDefault();
  const code = el.code.value.trim();
  if (!code) {
    showError(el.codeError, 'Enter the code first.');
    el.code.focus();
    return;
  }
  showError(el.codeError, null);
  await busy(el.codeSubmit, async () => {
    let resp;
    try {
      resp = await api('POST', '/api/auth/mfa/code', { token: state.token, code });
    } catch (err) {
      el.code.value = '';
      showError(el.codeError, err);
      el.code.focus();
      return;
    }
    await finish(resp);
  });
}

// ---------------------------------------------------------------- otp ----

function findDest(sent) {
  if (!sent) return null;
  const same = state.destinations.filter((d) => d.kind === sent.kind && (!sent.hint || d.hint === sent.hint));
  if (same.length) return same[0].id;
  return state.destinations.length === 1 ? state.destinations[0].id : null;
}

function openOtpSent(sent) {
  el.otpSent.textContent = `We sent a code to ${(sent && sent.hint) || 'you'}.`;
  el.otpResend.hidden = state.destId === null;
  el.otpResend.textContent = 'Send a new code';
  el.otp.disabled = false;
  el.otpSubmit.disabled = false;
  el.otp.value = '';
  showPane(el.paneOtp, 'Enter the code');
  el.otp.focus();
}

async function sendCode(dest, { resend = false } = {}) {
  showError(el.otpError, null);
  showPane(el.paneOtp, 'Enter the code');
  const label = dest.hint || (dest.kind === 'email' ? 'your email' : 'your phone');
  el.otpSent.textContent = `Sending a code to ${label}…`;
  announce(`Sending a code to ${label}`);
  el.otp.disabled = true;
  el.otpSubmit.disabled = true;
  el.otpResend.hidden = true;
  let resp;
  try {
    resp = await api('POST', '/api/auth/mfa/send', { token: state.token, destination_id: dest.id });
  } catch (err) {
    el.otpSent.textContent = `We couldn’t send a code to ${label}.`;
    showError(el.otpError, err);
    state.destId = dest.id;
    el.otpResend.hidden = false;
    el.otpResend.textContent = resend ? 'Try sending again' : 'Try again';
    return;
  }
  // The new token is bound to this destination; the old one is not.
  if (resp && typeof resp.token === 'string' && resp.token) state.token = resp.token;
  state.destId = dest.id;
  openOtpSent((resp && resp.sent) || { kind: dest.kind, hint: dest.hint });
  announce(el.otpSent.textContent);
}

async function onOtpSubmit(e) {
  e.preventDefault();
  const code = el.otp.value.trim();
  if (!code) {
    showError(el.otpError, 'Enter the code first.');
    el.otp.focus();
    return;
  }
  showError(el.otpError, null);
  await busy(el.otpSubmit, async () => {
    let resp;
    try {
      resp = await api('POST', '/api/auth/mfa/otp', { token: state.token, code });
    } catch (err) {
      el.otp.value = '';
      showError(el.otpError, err);
      el.otp.focus();
      return;
    }
    await finish(resp);
  });
}

function onResend() {
  const dest = state.destinations.find((d) => d.id === state.destId);
  if (dest) sendCode(dest, { resend: true });
}

// ------------------------------------------------------------ passkey ----

function openPasskey({ autoStart }) {
  showError(el.passkeyError, null);
  el.passkeyGo.textContent = state.passkeySpent ? 'Start over' : 'Use passkey';
  showPane(el.panePasskey, 'Use your passkey');
  if (autoStart && !state.passkeySpent) startPasskey();
  else el.passkeyGo.focus();
}

async function startPasskey() {
  if (state.passkeySpent) {
    startOver();
    return;
  }
  showError(el.passkeyError, null);
  let refocus = false;
  await busy(el.passkeyGo, async () => {
    let options;
    try {
      options = await api('POST', '/api/auth/mfa/passkey/options', { token: state.token });
    } catch (err) {
      showError(el.passkeyError, err);
      return;
    }
    const cred = await getPasskey(options);
    if (cred.cancelled) {
      // Not an error: usually someone reaching for a different method.
      if (state.options.length >= 2) openChooser();
      else refocus = true;
      return;
    }
    if (cred.error) {
      showError(el.passkeyError, `Your browser couldn’t use a passkey: ${cred.error}`);
      return;
    }
    let resp;
    try {
      resp = await api('POST', '/api/auth/mfa/passkey/verify', { token: state.token, credential: cred });
    } catch (err) {
      // The server deleted the challenge whether or not this succeeded: the
      // same ceremony cannot be retried (A §7.6).
      state.passkeySpent = true;
      showError(el.passkeyError, `${errorMessage(err)} This attempt can’t be retried — start over to sign in again.`);
      return;
    }
    await finish(resp);
  });
  if (state.passkeySpent) el.passkeyGo.textContent = 'Start over';
  if (refocus) el.passkeyGo.focus();
}

// ------------------------------------------------------------- flow ----

function startOver() {
  state.token = null;
  state.options = [];
  state.methods = [];
  state.destinations = [];
  state.destId = null;
  state.passkeySpent = false;
  el.password.value = '';
  el.code.value = '';
  el.otp.value = '';
  showError(el.passwordError, null);
  showPane(el.panePassword, 'Sign in');
  if (el.identifier.value) el.password.focus();
  else el.identifier.focus();
}

function startMfa(resp) {
  state.token = typeof resp.token === 'string' ? resp.token : null;
  state.methods = Array.isArray(resp.methods) ? resp.methods.filter((m) => typeof m === 'string') : [];
  state.destinations = (Array.isArray(resp.destinations) ? resp.destinations : []).filter(
    (d) => d && d.id !== undefined && d.id !== null && (d.kind === 'sms' || d.kind === 'email'),
  );
  state.options = browserOptions(state.methods, state.destinations);
  state.passkeySpent = false;
  state.destId = null;

  if (resp.sent && typeof resp.sent === 'object') {
    state.destId = findDest(resp.sent);
    openOtpSent(resp.sent);
    return;
  }
  if (state.options.length === 0) {
    openNone();
    return;
  }
  if (state.options.length === 1) {
    openOption(state.options[0], { auto: true });
    return;
  }
  openChooser();
}

async function login(identifier, password) {
  try {
    return await api('POST', '/api/auth/login', { identifier, password });
  } catch (err) {
    if (!(err instanceof ApiError && err.status === 403 && err.body && err.body.fingerprint_required === true)) throw err;
  }
  // fingerprint_gate: the browser must report a fingerprint first. Wait for
  // the report already in flight; send another if it failed; retry ONCE.
  announce('Checking this browser…');
  const first = state.fp ? await state.fp : null;
  if (!first || !first.ok) await reportFingerprint();
  try {
    return await api('POST', '/api/auth/login', { identifier, password });
  } catch (err) {
    if (err instanceof ApiError && err.status === 403 && err.body && err.body.fingerprint_required === true) {
      throw new Error('This portal checks your browser before you sign in, and that check didn’t go through. If you block scripts or cookies for this site, allow them and try again.');
    }
    throw err;
  }
}

async function onPasswordSubmit(e) {
  e.preventDefault();
  showError(el.passwordError, null);
  const identifier = el.identifier.value.trim();
  const password = el.password.value;
  if (!identifier || !password) {
    showError(el.passwordError, 'Enter your email or username and your password.');
    (identifier ? el.password : el.identifier).focus();
    return;
  }
  await busy(el.passwordSubmit, async () => {
    let resp;
    try {
      resp = await login(identifier, password);
    } catch (err) {
      el.password.value = '';
      showError(el.passwordError, err);
      el.password.focus();
      return;
    }
    if (resp && resp.mfa_required) startMfa(resp);
    else await finish(resp);
  });
}

function destinationAfter(resp) {
  if (resp && resp.pinned && typeof resp.next === 'string') return safeNext(resp.next);
  return safeNext(param('next'));
}

async function finish(resp) {
  announce('Signing you in…');
  const signedIn = await confirmSignedIn();
  if (signedIn === false) {
    showPane(el.paneCookie, 'Almost there');
    el.cookieRetry.focus();
    return;
  }
  const dest = destinationAfter(resp);
  if (resp && resp.enroll_prompt === true && !resp.pinned) {
    el.enrollSetup.href = `/account?enroll=1&next=${encodeURIComponent(dest)}`;
    el.enrollSkip.href = dest;
    showPane(el.paneEnroll, 'You’re signed in');
    el.enrollSetup.focus();
    return;
  }
  announce('Signed in.');
  go(dest, { replace: true });
}

// ------------------------------------------------------------- start ----

async function init() {
  el.formPassword.addEventListener('submit', onPasswordSubmit);
  el.formCode.addEventListener('submit', onCodeSubmit);
  el.formOtp.addEventListener('submit', onOtpSubmit);
  el.otpResend.addEventListener('click', onResend);
  el.codeToggle.addEventListener('click', () => {
    setCodeMode(state.codeMode === 'backup' ? 'app' : 'backup');
    el.code.value = '';
    el.code.focus();
  });
  el.passkeyGo.addEventListener('click', () => startPasskey());
  el.otherMethod.addEventListener('click', openChooser);
  el.startOver.addEventListener('click', startOver);
  el.cookieRetry.addEventListener('click', startOver);

  // Background fingerprint report: never awaited here, never blocks sign-in.
  state.fp = reportFingerprint();

  let who = null;
  try {
    who = await api('GET', '/api/auth/whoami', undefined, { redirect: false, stepUp: false });
  } catch {
    who = null;
  }
  if (!who) return;
  if (typeof who.org_name === 'string' && who.org_name) {
    el.org.textContent = who.org_name;
    document.title = `Sign in · ${who.org_name}`;
  }
  if (typeof who.privacy_notice === 'string' && who.privacy_notice.trim()) {
    el.privacy.replaceChildren(icon('info', { size: 16 }), h('span', null, who.privacy_notice.trim()));
    el.privacy.hidden = false;
  }
  if (who.authenticated === true) {
    announce('You’re already signed in.');
    go(safeNext(param('next')), { replace: true });
  }
}

init();
