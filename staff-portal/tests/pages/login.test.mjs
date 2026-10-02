// public/login.html + js/login.js — the sign-in state machine (A §7.6
// exactly; A §5 cookie detection; B §6 fingerprint + notice; B §10).

import { test, assert, run } from '../helpers/t.js';
import { loadPage, reply, drain } from '../helpers/dom.js';

const ORIGIN = 'https://staff.example.com';
const PANES = ['pane-password', 'pane-choose', 'pane-code', 'pane-otp', 'pane-passkey', 'pane-none', 'pane-cookie', 'pane-enroll'];
const DONE = { ok: true, user: { id: 1 }, pinned: null, enroll_prompt: false, next: '/', streak: null };
// As POST /api/auth/login lists them (src/api/auth.js afterPassword).
const SMS = { id: 4, kind: 'sms', hint: '•••• 1234', label: null };
const EMAIL = { id: 9, kind: 'email', hint: 'j•••@acme.com', label: 'Work' };

const assertion = () => ({
  id: 'ignored',
  rawId: new Uint8Array([0xfb, 0xff, 0xbe, 0x01]).buffer,
  type: 'public-key',
  response: {
    clientDataJSON: new TextEncoder().encode('{"type":"webauthn.get"}').buffer,
    authenticatorData: new Uint8Array(37).buffer,
    signature: new Uint8Array([0x30, 0x06]).buffer,
    userHandle: null,
  },
});

function notAllowed() {
  const e = new Error('The operation either timed out or was not allowed.');
  e.name = 'NotAllowedError';
  return e;
}

// whoami: signed out on load, signed in after the sign-in completes.
async function open({ url = `${ORIGIN}/login`, fetch = {}, webauthn, whoami } = {}) {
  return loadPage('login.html', {
    url,
    webauthn,
    fetch: {
      'GET /api/auth/whoami': whoami || [reply(200, { authenticated: false, org_name: 'Acme Inc.', privacy_notice: 'We record browser details for security.' }), reply(200, { authenticated: true })],
      'POST /api/fp': reply(200, { ok: true }),
      ...fetch,
    },
  });
}

function shown(page) {
  return PANES.filter((id) => page.visible(id));
}

async function signIn(page, identifier = 'jane@acme.com', password = 'correct horse battery') {
  page.fill('identifier', identifier);
  page.fill('password', password);
  await page.submit('form-password');
}

function mfa(extra) {
  return reply(200, { mfa_required: true, token: 't1', methods: [], destinations: [], sent: null, ...extra });
}

function choiceKinds(page) {
  return page.document.querySelectorAll('#choices .choice').map((b) => b.dataset.kind + (b.dataset.dest ? `:${b.dataset.dest}` : ''));
}

function noNativeSubmit(page) {
  assert.deepEqual(page.calls.nav.filter((n) => n.type === 'form'), [], 'a form submitted natively (missing preventDefault)');
}

// ------------------------------------------------------------- load ----

test('load: asks whoami, shows the org name and privacy notice, reports a fingerprint without blocking', async () => {
  const page = await open();
  assert.equal(page.requests('/api/auth/whoami')[0].method, 'GET');
  assert.equal(page.text('org-name'), 'Acme Inc.');
  assert.equal(page.document.title, 'Sign in · Acme Inc.');
  assert.ok(page.visible('privacy'));
  assert.equal(page.text('privacy'), 'We record browser details for security.');
  const fp = page.requests('/api/fp');
  assert.equal(fp.length, 1);
  assert.equal(fp[0].body.signals.v, 1);
  assert.deepEqual(shown(page), ['pane-password'], 'the form is usable from the start (no flash, no wait)');
  assert.ok(!page.visible('mfa-footer'));
  assert.deepEqual(page.calls.unmatched, []);
  assert.deepEqual(page.calls.pageErrors, []);
  page.dispose();
});

test('load: no privacy notice when the setting is off', async () => {
  const page = await open({ whoami: reply(200, { authenticated: false, org_name: 'Acme Inc.', privacy_notice: null }) });
  assert.ok(!page.visible('privacy'));
  page.dispose();
});

test('load: already signed in → straight to safeNext(?next)', async () => {
  const page = await open({ url: `${ORIGIN}/login?next=%2Fadmin%3Ftab%3Daudit`, whoami: reply(200, { authenticated: true, org_name: 'Acme' }) });
  assert.deepEqual(page.calls.nav, [{ type: 'replace', url: '/admin?tab=audit' }]);
  page.dispose();
  for (const evil of ['https://evil.example/', '//evil.example', '/\\evil.example', 'javascript:alert(1)', `http://staff.example.com/admin`]) {
    const p2 = await open({ url: `${ORIGIN}/login?next=${encodeURIComponent(evil)}`, whoami: reply(200, { authenticated: true }) });
    assert.deepEqual(p2.calls.nav, [{ type: 'replace', url: '/' }], evil);
    p2.dispose();
  }
});

test('load: whoami failing leaves a working form', async () => {
  const page = await open({ whoami: reply(200, null, { networkError: true }) });
  assert.deepEqual(shown(page), ['pane-password']);
  assert.equal(page.text('org-name'), 'Staff portal');
  page.dispose();
});

// --------------------------------------------------------- password ----

test('password only: signs in, checks whoami, goes to ?next', async () => {
  const page = await open({ url: `${ORIGIN}/login?next=/admin`, fetch: { 'POST /api/auth/login': reply(200, DONE) } });
  await signIn(page);
  assert.deepEqual(page.requests('/api/auth/login')[0].body, { identifier: 'jane@acme.com', password: 'correct horse battery' });
  assert.equal(page.requests('/api/auth/whoami').length, 2, 'asked whoami again before navigating');
  assert.deepEqual(page.calls.nav, [{ type: 'replace', url: '/admin' }]);
  noNativeSubmit(page);
  page.dispose();
});

test('cookie refused: login 200 but whoami still signed out → say so plainly, no loop', async () => {
  for (const after of [reply(200, { authenticated: false }), reply(401, { error: 'no' })]) {
    const page = await open({
      url: `${ORIGIN}/login?next=/admin`,
      whoami: [reply(200, { authenticated: false, org_name: 'Acme' }), after],
      fetch: { 'POST /api/auth/login': reply(200, DONE) },
    });
    await signIn(page);
    assert.deepEqual(shown(page), ['pane-cookie']);
    assert.match(page.text('pane-cookie'), /private or incognito window/);
    assert.match(page.text('pane-cookie'), /cookies are blocked/);
    assert.match(page.text('pane-cookie'), /app’s built-in browser/);
    assert.deepEqual(page.calls.nav, [], 'did not navigate into a login loop');
    await page.click('cookie-retry');
    assert.deepEqual(shown(page), ['pane-password']);
    page.dispose();
  }
});

test('pinned sign-in goes to response.next, not ?next', async () => {
  const page = await open({ url: `${ORIGIN}/login?next=/admin`, fetch: { 'POST /api/auth/login': reply(200, { ...DONE, pinned: 'mfa_enroll', next: '/account?pin=mfa_enroll' }) } });
  await signIn(page);
  assert.deepEqual(page.calls.nav, [{ type: 'replace', url: '/account?pin=mfa_enroll' }]);
  page.dispose();
});

test('a pinned next that is not ours is still refused', async () => {
  const page = await open({ fetch: { 'POST /api/auth/login': reply(200, { ...DONE, pinned: 'password_change', next: '//evil.example' }) } });
  await signIn(page);
  assert.deepEqual(page.calls.nav, [{ type: 'replace', url: '/' }]);
  page.dispose();
});

test('enroll prompt: a banner with "set it up" and "not now", both carrying the destination', async () => {
  const page = await open({ url: `${ORIGIN}/login?next=/admin`, fetch: { 'POST /api/auth/login': reply(200, { ...DONE, enroll_prompt: true }) } });
  await signIn(page);
  assert.deepEqual(shown(page), ['pane-enroll']);
  assert.equal(page.$('enroll-skip').getAttribute('href'), '/admin');
  assert.equal(page.$('enroll-setup').getAttribute('href'), '/account?enroll=1&next=%2Fadmin');
  assert.deepEqual(page.calls.nav, [], 'a prompt, not a redirect — and not a wall');
  page.dispose();
});

test('wrong password: the server sentence, password cleared, nothing else happens', async () => {
  const page = await open({ fetch: { 'POST /api/auth/login': reply(401, { error: 'Invalid credentials.' }) } });
  await signIn(page);
  assert.deepEqual(shown(page), ['pane-password']);
  assert.ok(page.visible('password-error'));
  assert.equal(page.text('password-error'), 'Invalid credentials.');
  assert.equal(page.$('password').value, '');
  assert.equal(page.$('identifier').value, 'jane@acme.com');
  assert.equal(page.document.activeElement, page.$('password'));
  assert.equal(page.$('password-submit').disabled, false, 'button usable again');
  assert.deepEqual(page.calls.nav, []);
  page.dispose();
});

test('empty fields: an inline error and no request', async () => {
  const page = await open();
  page.fill('identifier', '  ');
  await page.submit('form-password');
  assert.ok(page.visible('password-error'));
  assert.equal(page.requests('/api/auth/login').length, 0);
  noNativeSubmit(page);
  page.dispose();
});

test('429: "Too many attempts. Try again in 5 minutes."', async () => {
  const page = await open({ fetch: { 'POST /api/auth/login': reply(429, { error: 'Too many attempts. Try again later.', retry_after: 300 }) } });
  await signIn(page);
  assert.equal(page.text('password-error'), 'Too many attempts. Try again in 5 minutes.');
  page.dispose();
});

test('fingerprint_gate: 403 fingerprint_required → report the fingerprint, retry ONCE, succeed', async () => {
  const page = await open({
    fetch: {
      'POST /api/auth/login': [reply(403, { error: 'Checking your browser.', fingerprint_required: true }), reply(200, DONE)],
      'POST /api/fp': [reply(503, null), reply(200, { ok: true })],
    },
  });
  await signIn(page);
  const order = page.calls.fetch.map((c) => `${c.method} ${c.path}`);
  assert.deepEqual(order, ['GET /api/auth/whoami', 'POST /api/fp', 'POST /api/auth/login', 'POST /api/fp', 'POST /api/auth/login', 'GET /api/auth/whoami']);
  assert.deepEqual(page.calls.nav, [{ type: 'replace', url: '/' }]);
  page.dispose();
});

test('fingerprint_gate: if the background report already landed, retry without sending another', async () => {
  const page = await open({ fetch: { 'POST /api/auth/login': [reply(403, { fingerprint_required: true }), reply(200, DONE)] } });
  await signIn(page);
  assert.equal(page.requests('/api/fp').length, 1);
  assert.equal(page.requests('/api/auth/login').length, 2);
  assert.deepEqual(page.calls.nav, [{ type: 'replace', url: '/' }]);
  page.dispose();
});

test('fingerprint_gate: still refused after the retry → an explanation, not a loop', async () => {
  const page = await open({ fetch: { 'POST /api/auth/login': reply(403, { fingerprint_required: true }) } });
  await signIn(page);
  assert.equal(page.requests('/api/auth/login').length, 2, 'exactly one retry');
  assert.match(page.text('password-error'), /checks your browser before you sign in/);
  assert.deepEqual(page.calls.nav, []);
  page.dispose();
});

// ------------------------------------------------------ state machine ----

test('server already sent a code → code box, "We sent a code to <hint>", nothing sent again', async () => {
  const page = await open({
    fetch: {
      'POST /api/auth/login': mfa({ methods: ['sms'], destinations: [SMS], sent: { kind: 'sms', hint: '•••• 1234' } }),
      'POST /api/auth/mfa/otp': reply(200, DONE),
    },
  });
  await signIn(page);
  assert.deepEqual(shown(page), ['pane-otp']);
  assert.equal(page.text('otp-sent'), 'We sent a code to •••• 1234.');
  assert.equal(page.requests('/api/auth/mfa/send').length, 0);
  assert.ok(!page.visible('other-method'), 'one usable method: no "different method"');
  assert.ok(page.visible('otp-resend'));
  assert.equal(page.$('otp').getAttribute('autocomplete'), 'one-time-code');
  assert.equal(page.$('otp').getAttribute('inputmode'), 'numeric');
  page.fill('otp', '123456');
  await page.submit('form-otp');
  assert.deepEqual(page.requests('/api/auth/mfa/otp')[0].body, { token: 't1', code: '123456' });
  assert.deepEqual(page.calls.nav, [{ type: 'replace', url: '/' }]);
  noNativeSubmit(page);
  page.dispose();
});

test('exactly one method this browser can offer → opened directly, no list of one', async () => {
  const page = await open({ fetch: { 'POST /api/auth/login': mfa({ methods: ['totp'] }), 'POST /api/auth/mfa/code': reply(200, DONE) } });
  await signIn(page);
  assert.deepEqual(shown(page), ['pane-code']);
  assert.ok(!page.visible('pane-choose'));
  assert.ok(!page.visible('other-method'));
  assert.ok(!page.visible('code-toggle'), 'no backup codes → no backup toggle');
  assert.equal(page.document.activeElement, page.$('code'));
  page.fill('code', ' 123 456 ');
  await page.submit('form-code');
  assert.deepEqual(page.requests('/api/auth/mfa/code')[0].body, { token: 't1', code: '123 456' });
  assert.deepEqual(page.calls.nav, [{ type: 'replace', url: '/' }]);
  page.dispose();
});

test('authenticator + backup codes are ONE option (one box), opened directly, with a backup toggle', async () => {
  const page = await open({ fetch: { 'POST /api/auth/login': mfa({ methods: ['totp', 'backup'] }) } });
  await signIn(page);
  assert.deepEqual(shown(page), ['pane-code']);
  assert.ok(page.visible('code-toggle'));
  assert.equal(page.$('code').getAttribute('inputmode'), 'numeric');
  await page.click('code-toggle');
  assert.equal(page.text('code-label'), 'Backup code');
  assert.equal(page.$('code').getAttribute('inputmode'), 'text');
  await page.click('code-toggle');
  assert.equal(page.text('code-label'), 'Code from your authenticator app');
  page.dispose();
});

test('backup codes only → the box opens in backup mode', async () => {
  const page = await open({ fetch: { 'POST /api/auth/login': mfa({ methods: ['backup'] }) } });
  await signIn(page);
  assert.deepEqual(shown(page), ['pane-code']);
  assert.equal(page.text('code-label'), 'Backup code');
  assert.ok(!page.visible('code-toggle'));
  page.dispose();
});

test('"one method" is what the BROWSER can offer: passkey + app without WebAuthn → app directly', async () => {
  const page = await open({ fetch: { 'POST /api/auth/login': mfa({ methods: ['passkey', 'totp'] }) } });
  await signIn(page);
  assert.deepEqual(shown(page), ['pane-code']);
  assert.ok(!page.visible('other-method'), '"use a different method" would lead to a list of one');
  assert.equal(page.requests('/api/auth/mfa/passkey/options').length, 0);
  page.dispose();
});

test('two or more → chooser, strongest first, nothing auto-fired', async () => {
  let gets = 0;
  const page = await open({
    webauthn: { get: async () => (gets++, assertion()) },
    fetch: { 'POST /api/auth/login': mfa({ methods: ['passkey', 'totp', 'backup', 'sms', 'email'], destinations: [SMS, EMAIL] }) },
  });
  await signIn(page);
  assert.deepEqual(shown(page), ['pane-choose']);
  assert.deepEqual(choiceKinds(page), ['passkey', 'app', 'send:4', 'send:9']);
  const titles = page.document.querySelectorAll('#choices .choice-title').map((t) => t.textContent);
  assert.deepEqual(titles, ['Use a passkey', 'Authenticator app', 'Text a code to •••• 1234', 'Email a code to j•••@acme.com']);
  assert.equal(gets, 0, 'no passkey prompt');
  assert.equal(page.requests('/api/auth/mfa/').length, 0, 'no factor endpoint called');
  assert.ok(page.visible('start-over'));
  assert.ok(!page.visible('other-method'), 'already on the chooser');
  assert.equal(page.document.activeElement, page.document.querySelector('#choices .choice'));
  page.dispose();
});

test('dead end: passkey-only account, browser without WebAuthn → explanation, never an empty list', async () => {
  const page = await open({ fetch: { 'POST /api/auth/login': mfa({ methods: ['passkey'] }) } });
  await signIn(page);
  assert.deepEqual(shown(page), ['pane-none']);
  assert.ok(!page.visible('pane-choose'));
  const text = page.text('pane-none');
  assert.match(text, /can’t use passkeys/);
  assert.match(text, /Chrome, Edge, Safari and Firefox/);
  assert.match(text, /ask an administrator to add a phone number or email address/);
  assert.ok(page.visible('start-over'));
  assert.ok(!page.visible('other-method'));
  assert.equal(page.requests('/api/auth/mfa/').length, 0);
  page.dispose();
});

test('dead end: no methods at all → still an explanation', async () => {
  const page = await open({ fetch: { 'POST /api/auth/login': mfa({ methods: [] }) } });
  await signIn(page);
  assert.deepEqual(shown(page), ['pane-none']);
  assert.match(page.text('none-advice'), /administrator/);
  assert.ok(page.text('none-detail').length > 10);
  page.dispose();
});

test('"use a different method" goes back to the chooser, and only when the browser has 2+', async () => {
  const page = await open({ fetch: { 'POST /api/auth/login': mfa({ methods: ['totp', 'sms'], destinations: [SMS] }) } });
  await signIn(page);
  assert.deepEqual(choiceKinds(page), ['app', 'send:4']);
  page.document.querySelector('.choice[data-kind=app]').click();
  await drain();
  assert.deepEqual(shown(page), ['pane-code']);
  assert.ok(page.visible('other-method'));
  await page.click('other-method');
  assert.deepEqual(shown(page), ['pane-choose']);
  page.dispose();
});

test('send a code from the chooser → the NEW token is used to verify', async () => {
  const page = await open({
    fetch: {
      'POST /api/auth/login': mfa({ methods: ['totp', 'sms'], destinations: [SMS] }),
      'POST /api/auth/mfa/send': reply(200, { token: 't2', sent: { kind: 'sms', hint: '•••• 1234' } }),
      'POST /api/auth/mfa/otp': reply(200, DONE),
    },
  });
  await signIn(page);
  page.document.querySelector('.choice[data-kind=send]').click();
  await drain();
  assert.deepEqual(page.requests('/api/auth/mfa/send')[0].body, { token: 't1', destination_id: 4 });
  assert.deepEqual(shown(page), ['pane-otp']);
  assert.equal(page.text('otp-sent'), 'We sent a code to •••• 1234.');
  page.fill('otp', '654321');
  await page.submit('form-otp');
  assert.deepEqual(page.requests('/api/auth/mfa/otp')[0].body, { token: 't2', code: '654321' });
  page.dispose();
});

test('send failure (429) is shown nicely with a retry; resend keeps the newest token', async () => {
  const page = await open({
    fetch: {
      'POST /api/auth/login': mfa({ methods: ['totp', 'sms'], destinations: [SMS] }),
      'POST /api/auth/mfa/send': [reply(429, { retry_after: 120 }), reply(200, { token: 't3', sent: { kind: 'sms', hint: '•••• 1234' } })],
    },
  });
  await signIn(page);
  page.document.querySelector('.choice[data-kind=send]').click();
  await drain();
  assert.equal(page.text('otp-error'), 'Too many attempts. Try again in 2 minutes.');
  assert.match(page.text('otp-sent'), /couldn’t send/);
  assert.ok(page.visible('otp-resend'));
  await page.click('otp-resend');
  assert.equal(page.text('otp-sent'), 'We sent a code to •••• 1234.');
  assert.ok(!page.visible('otp-error'));
  page.fill('otp', '1');
  page.setRoute('POST /api/auth/mfa/otp', reply(200, DONE));
  await page.submit('form-otp');
  assert.equal(page.requests('/api/auth/mfa/otp')[0].body.token, 't3');
  page.dispose();
});

test('a single destination with nothing sent yet is sent straight away (one method → open it)', async () => {
  const page = await open({ fetch: { 'POST /api/auth/login': mfa({ methods: ['passkey', 'sms'], destinations: [SMS] }), 'POST /api/auth/mfa/send': reply(200, { token: 't2', sent: { kind: 'sms', hint: '•••• 1234' } }) } });
  await signIn(page);
  assert.equal(page.requests('/api/auth/mfa/send').length, 1);
  assert.deepEqual(shown(page), ['pane-otp']);
  page.dispose();
});

test('wrong code: inline error, field cleared, the box stays', async () => {
  const page = await open({ fetch: { 'POST /api/auth/login': mfa({ methods: ['totp'] }), 'POST /api/auth/mfa/code': [reply(401, { error: 'That code didn’t work.' }), reply(200, DONE)] } });
  await signIn(page);
  page.fill('code', '000000');
  await page.submit('form-code');
  assert.equal(page.text('code-error'), 'That code didn’t work.');
  assert.equal(page.$('code').value, '');
  assert.deepEqual(shown(page), ['pane-code']);
  page.fill('code', '123456');
  await page.submit('form-code');
  assert.ok(!page.visible('code-error'));
  assert.deepEqual(page.calls.nav, [{ type: 'replace', url: '/' }]);
  page.dispose();
});

// ------------------------------------------------------------ passkey ----

test('passkey as the only method: the ceremony starts directly and signs in', async () => {
  let seen = null;
  const page = await open({
    url: `${ORIGIN}/login?next=/account`,
    webauthn: { get: async (o) => ((seen = o), assertion()) },
    fetch: {
      'POST /api/auth/login': mfa({ methods: ['passkey'] }),
      'POST /api/auth/mfa/passkey/options': reply(200, { challenge: '-_--AQ', rpId: 'staff.example.com', allowCredentials: [{ type: 'public-key', id: '-_--AQ' }], userVerification: 'preferred', timeout: 60000 }),
      'POST /api/auth/mfa/passkey/verify': reply(200, DONE),
    },
  });
  await signIn(page);
  assert.deepEqual(page.requests('/api/auth/mfa/passkey/options')[0].body, { token: 't1' });
  assert.deepEqual([...new Uint8Array(seen.publicKey.challenge)], [0xfb, 0xff, 0xbe, 0x01]);
  const verify = page.requests('/api/auth/mfa/passkey/verify')[0].body;
  assert.equal(verify.token, 't1');
  assert.equal(verify.credential.rawId, '-_--AQ');
  assert.equal(verify.credential.id, '-_--AQ');
  assert.deepEqual(page.calls.nav, [{ type: 'replace', url: '/account' }]);
  page.dispose();
});

test('a cancelled passkey dialog returns to the chooser silently', async () => {
  const page = await open({
    webauthn: { get: async () => Promise.reject(notAllowed()) },
    fetch: {
      'POST /api/auth/login': mfa({ methods: ['passkey', 'totp'] }),
      'POST /api/auth/mfa/passkey/options': reply(200, { challenge: 'AQID', allowCredentials: [] }),
    },
  });
  await signIn(page);
  assert.deepEqual(choiceKinds(page), ['passkey', 'app']);
  page.document.querySelector('.choice[data-kind=passkey]').click();
  await drain();
  assert.deepEqual(shown(page), ['pane-choose'], 'back on the chooser');
  assert.ok(!page.visible('passkey-error'), 'not in the red box');
  assert.ok(!page.visible('choose-error'));
  assert.equal(page.requests('/api/auth/mfa/passkey/verify').length, 0);
  page.dispose();
});

test('a cancelled passkey with no other method stays on the passkey step, quietly', async () => {
  const page = await open({
    webauthn: { get: async () => Promise.reject(notAllowed()) },
    fetch: { 'POST /api/auth/login': mfa({ methods: ['passkey'] }), 'POST /api/auth/mfa/passkey/options': reply(200, { challenge: 'AQID' }) },
  });
  await signIn(page);
  assert.deepEqual(shown(page), ['pane-passkey']);
  assert.ok(!page.visible('passkey-error'));
  assert.equal(page.text('passkey-go'), 'Use passkey');
  assert.equal(page.document.activeElement, page.$('passkey-go'), 'ready to try again');
  page.dispose();
});

test('a spent challenge: after a failed verify, Retry becomes "Start over"', async () => {
  let gets = 0;
  const page = await open({
    webauthn: { get: async () => (gets++, assertion()) },
    fetch: {
      'POST /api/auth/login': mfa({ methods: ['passkey', 'totp'] }),
      'POST /api/auth/mfa/passkey/options': reply(200, { challenge: 'AQID' }),
      'POST /api/auth/mfa/passkey/verify': reply(400, { error: 'That passkey couldn’t be verified.' }),
    },
  });
  await signIn(page);
  page.document.querySelector('.choice[data-kind=passkey]').click();
  await drain();
  assert.deepEqual(shown(page), ['pane-passkey']);
  assert.ok(page.visible('passkey-error'));
  assert.match(page.text('passkey-error'), /That passkey couldn’t be verified\./);
  assert.match(page.text('passkey-error'), /can’t be retried/);
  assert.equal(page.text('passkey-go'), 'Start over');
  await page.click('passkey-go');
  assert.equal(page.requests('/api/auth/mfa/passkey/options').length, 1, 'the spent ceremony is not re-run');
  assert.equal(gets, 1);
  assert.deepEqual(shown(page), ['pane-password']);
  assert.equal(page.$('password').value, '');
  assert.equal(page.$('identifier').value, 'jane@acme.com');
  page.dispose();
});

test('a browser-side passkey failure is an error, but the challenge was not spent', async () => {
  const e = new Error('The relying party ID is not a registrable domain suffix.');
  e.name = 'SecurityError';
  const page = await open({
    webauthn: { get: async () => Promise.reject(e) },
    fetch: { 'POST /api/auth/login': mfa({ methods: ['passkey', 'totp'] }), 'POST /api/auth/mfa/passkey/options': reply(200, { challenge: 'AQID' }) },
  });
  await signIn(page);
  page.document.querySelector('.choice[data-kind=passkey]').click();
  await drain();
  assert.ok(page.visible('passkey-error'));
  assert.match(page.text('passkey-error'), /registrable domain/);
  assert.equal(page.text('passkey-go'), 'Use passkey', 'still retryable');
  assert.equal(page.requests('/api/auth/mfa/passkey/verify').length, 0);
  page.dispose();
});

test('start over from any factor step returns to the password step', async () => {
  const page = await open({ fetch: { 'POST /api/auth/login': mfa({ methods: ['totp', 'sms'], destinations: [SMS] }) } });
  await signIn(page);
  assert.deepEqual(shown(page), ['pane-choose']);
  await page.click('start-over');
  assert.deepEqual(shown(page), ['pane-password']);
  assert.ok(!page.visible('mfa-footer'));
  assert.equal(page.text('title'), 'Sign in');
  page.dispose();
});

test('MFA success also checks the cookie before navigating', async () => {
  const page = await open({
    whoami: [reply(200, { authenticated: false }), reply(200, { authenticated: false })],
    fetch: { 'POST /api/auth/login': mfa({ methods: ['totp'] }), 'POST /api/auth/mfa/code': reply(200, DONE) },
  });
  await signIn(page);
  page.fill('code', '123456');
  await page.submit('form-code');
  assert.deepEqual(shown(page), ['pane-cookie']);
  assert.deepEqual(page.calls.nav, []);
  page.dispose();
});

await run();
