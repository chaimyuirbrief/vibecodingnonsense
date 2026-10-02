// public/account.html + js/account.js — self-service (CONTRACTS §8.4 Me;
// A §7.3 QR plate, grouped secret, backup codes once; A §7.5 prompt vs
// required, ?next= open-redirect list; B §6 explain the risk number;
// SPEC §7.9 step-up, §8.2 approve from an approved device).

import { test, assert, run } from '../helpers/t.js';
import { loadPage, reply, byText, texts } from '../helpers/dom.js';

const ORIGIN = 'https://staff.example.com';
const CODES = ['ABCDE-FGHJK', 'MNPQR-STUVW', 'XYZ23-45678', '9ABCD-EFGHJ', 'KMNPQ-RSTUV', 'WXYZ2-3456A', 'B789C-DEFGH', 'JKMNP-QRSTU', 'VWXYZ-23456', '789AB-CDEFG'];
const QR = 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciLz4=';
const OTPAUTH = 'otpauth://totp/Acme%20Inc.:jane%40acme.com?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Acme%20Inc.';

const USER = { id: 7, email: 'jane@acme.com', username: 'jane', full_name: 'Jane Doe', employee_no: 'ACME000007', job_title: 'Engineer', department: 'R&D', role: { id: 5, key: 'employee', name: 'Employee', rank: 20 }, status: 'active' };

const ME = {
  user: USER,
  permissions: [],
  sources: {},
  pinned: null,
  enroll_prompt: false,
  step_up_fresh: false,
  factors: { totp: false, totpUnreadable: false, passkeys: 1, backup: 6, destinations: 0 },
  passkeys: [{ id: 41, label: 'MacBook Touch ID', created_at: '2026-09-01T10:00:00Z', last_used_at: '2026-10-01T10:00:00Z' }],
  org_name: 'Acme Inc.',
  timezone: 'America/New_York',
  privacy_notice: 'We record browser details to keep accounts safe.',
};

const SESSIONS = {
  sessions: [
    { id_ref: 'aaaaaaaaaaaa', created_at: '2026-10-02T08:00:00Z', last_seen_at: '2026-10-02T12:59:00Z', ip: '81.2.69.10', ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36', aal: 2, current: true },
    { id_ref: 'bbbbbbbbbbbb', created_at: '2026-10-01T08:00:00Z', last_seen_at: '2026-10-01T09:00:00Z', ip: '91.198.174.2', ua: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1', aal: 1, current: false },
  ],
};

const DEVICES = (status = 'approved') => ({
  devices: [
    { id: 'd1', label: 'Chrome on macOS', status, last_seen_at: '2026-10-02T12:59:00Z', ip: '81.2.69.10', current: true },
    { id: 'd2', label: 'Safari on iPhone', status: 'approved', last_seen_at: '2026-10-01T09:00:00Z', ip: '91.198.174.2', current: false },
  ],
});

const FP = {
  fingerprint: { visitor_id: 'a1b2c3d4e5f6a7b8', first_seen: '2026-09-01T10:00:00Z', last_seen: '2026-10-02T12:59:00Z', ip: '81.2.69.10', country: 'GB', as_org: 'Example Hosting Ltd', ua: USER.ua, tz: 'Europe/London' },
  risk: {
    score: 35,
    flags: [
      { key: 'datacenter', weight: 25, reason: 'Your network belongs to a hosting provider, which people rarely browse from.' },
      { key: 'tz_mismatch', weight: 10, reason: 'Your browser’s time zone doesn’t match where your IP address is.' },
    ],
  },
  threshold: 70,
};

const ACTIVITY = [{ id: 3, at: '2026-10-02T13:00:00Z', action: 'login.success', outcome: 'success', detail: 'Signed in with passkey', ip: '81.2.69.10' }];

function routes(extra = {}) {
  return {
    'GET /api/me': reply(200, ME),
    'GET /api/me/sessions': reply(200, SESSIONS),
    'GET /api/me/devices': reply(200, DEVICES()),
    'GET /api/me/activity': reply(200, ACTIVITY),
    'GET /api/me/fingerprint': reply(200, FP),
    ...extra,
  };
}

async function open({ url = `${ORIGIN}/account`, fetch = {}, webauthn } = {}) {
  return loadPage('account.html', { url, webauthn, fetch: routes(fetch) });
}

const SECTIONS = ['profile', 'password', 'security', 'sessions', 'devices', 'activity', 'browser'];
const shown = (page) => SECTIONS.filter((id) => page.visible(id));
const navState = (page) => page.document.querySelectorAll('#account-nav a[data-section]').map((a) => `${a.dataset.section}:${a.getAttribute('href') ? 'on' : 'off'}${a.getAttribute('aria-disabled') === 'true' ? '/disabled' : ''}`);
const modalButton = (page, cls) => page.document.querySelector(`dialog.modal .${cls}`);
const pageText = (page) => page.document.body.textContent;
const meGets = (page) => page.calls.fetch.filter((r) => r.method === 'GET' && r.path === '/api/me').length;

// ---------------------------------------------------------------- load ----

test('load: every section, the lists and the browser report; nothing unstubbed', async () => {
  const page = await open();
  assert.deepEqual(shown(page), SECTIONS);
  assert.equal(page.document.title, 'Your account · Acme Inc.');
  assert.equal(page.$('profile-name').value, 'Jane Doe');
  assert.deepEqual(texts(page.document, '#profile-facts dd'), ['jane@acme.com', 'jane', 'ACME000007', 'Engineer', 'R&D', 'Employee']);
  assert.ok(!page.visible('pin-banner'));
  assert.ok(!page.visible('enroll-prompt'), 'a passkey is a strong factor');
  assert.equal(page.document.querySelectorAll('#session-list .item-row').length, 2);
  assert.equal(page.document.querySelectorAll('#device-list .item-row').length, 2);
  assert.equal(page.document.querySelectorAll('#activity-list tbody tr').length, 1);
  assert.deepEqual(page.calls.unmatched, []);
  assert.deepEqual(page.calls.pageErrors, []);
  assert.equal(page.document.querySelector('.topnav-link[aria-current=page]').textContent, 'Account');
  page.dispose();
});

// ------------------------------------------------------------- TOTP ----

const ME_AFTER_TOTP = { ...ME, factors: { ...ME.factors, totp: true, backup: 10 } };

test('TOTP enrolment: QR on its own white plate, the secret grouped in fours, then backup codes exactly once', async () => {
  const page = await open({
    fetch: {
      'GET /api/me': [reply(200, ME), reply(200, ME_AFTER_TOTP)],
      'POST /api/me/mfa/totp/begin': reply(200, { secret_grouped: 'JBSW Y3DP EHPK 3PXP JBSW Y3DP EHPK 3PXP', otpauth: OTPAUTH, qr: QR }),
      'POST /api/me/mfa/totp/confirm': reply(200, { backup_codes: CODES, pinned: null }),
    },
  });
  assert.ok(!page.visible('totp-setup'));
  await page.click('totp-start');
  assert.ok(page.visible('totp-setup'));
  const img = page.$('totp-qr');
  assert.equal(img.getAttribute('src'), QR, 'the server-rendered data: URI (img-src data:)');
  assert.ok(img.closest('.qr-plate'), 'on the white plate');
  assert.equal(page.text('totp-secret'), 'JBSW Y3DP EHPK 3PXP JBSW Y3DP EHPK 3PXP');
  assert.equal(page.$('totp-link').getAttribute('href'), OTPAUTH);
  await page.click('totp-copy');
  assert.deepEqual(page.calls.clipboard, ['JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'], 'the key copies without spaces');

  page.fill('totp-code', '123 456');
  await page.submit('totp-form');
  assert.deepEqual(page.requests('/api/me/mfa/totp/confirm')[0].body, { code: '123456' });
  assert.ok(!page.visible('totp-setup'), 'setup closes');
  assert.equal(page.$('totp-qr').getAttribute('src'), null, 'the QR (which contains the secret) leaves the page');
  assert.equal(page.text('totp-secret'), '');

  assert.ok(page.visible('codes-panel'));
  assert.deepEqual(texts(page.document, '#codes-list li'), CODES);
  for (const c of CODES) assert.equal(pageText(page).split(c).length - 1, 1, `${c} on the page once`);
  assert.equal(page.text('totp-state'), 'On', 'the factor list was refreshed');

  await page.click('codes-copy');
  assert.equal(page.calls.clipboard[1], CODES.join('\n'));
  await page.click('codes-print');
  assert.ok(page.calls.nav.some((n) => n.type === 'print'));
  assert.ok(page.document.body.classList.contains('print-codes'), 'print shows only the codes');
  page.window.dispatchEvent(new page.window.Event('afterprint'));
  assert.ok(!page.document.body.classList.contains('print-codes'));
  await page.click('codes-download');
  const dl = page.calls.nav.find((n) => n.type === 'link');
  assert.ok(dl && dl.url.startsWith('blob:'), 'downloaded through a blob URL');

  await page.click('codes-done');
  assert.ok(!page.visible('codes-panel'));
  assert.equal(page.document.querySelectorAll('#codes-list li').length, 0);
  for (const c of CODES) assert.ok(!pageText(page).includes(c), `${c} gone from the page`);
  assert.equal(page.requests('/api/me/mfa/totp/confirm').length, 1);
  assert.deepEqual(page.calls.nav.filter((n) => n.type === 'replace' || n.type === 'assign'), [], 'not pinned: stays here');
  assert.deepEqual(page.calls.pageErrors, []);
  page.dispose();
});

test('TOTP: a wrong code is explained and shows no codes; a malformed one is never sent', async () => {
  const page = await open({
    fetch: {
      'POST /api/me/mfa/totp/begin': reply(200, { secret_grouped: 'ABCD EFGH', otpauth: OTPAUTH, qr: QR }),
      'POST /api/me/mfa/totp/confirm': reply(400, { error: 'That code didn’t match. Check the time on your phone and try again.' }),
    },
  });
  await page.click('totp-start');
  page.fill('totp-code', '12ab');
  await page.submit('totp-form');
  assert.equal(page.requests('/api/me/mfa/totp/confirm').length, 0);
  assert.equal(page.text('totp-error'), 'Enter the 6-digit code your app shows right now.');
  page.fill('totp-code', '000000');
  await page.submit('totp-form');
  assert.equal(page.text('totp-error'), 'That code didn’t match. Check the time on your phone and try again.');
  assert.ok(page.visible('totp-setup'), 'still set up — try again');
  assert.ok(!page.visible('codes-panel'));
  await page.click('totp-cancel');
  assert.ok(!page.visible('totp-setup'));
  assert.equal(page.$('totp-qr').getAttribute('src'), null);
  page.dispose();
});

test('TOTP: secret_b32 alone is grouped in fours by the page; a QR that is not a data: image is not shown', async () => {
  const page = await open({ fetch: { 'POST /api/me/mfa/totp/begin': reply(200, { secret_b32: 'jbswy3dpehpk3pxpjb', otpauth: 'javascript:alert(1)', qr: 'https://qr.example/x.png' }) } });
  await page.click('totp-start');
  assert.equal(page.text('totp-secret'), 'JBSW Y3DP EHPK 3PXP JB');
  assert.equal(page.$('totp-qr').getAttribute('src'), null);
  assert.ok(!page.visible('totp-link'), 'only otpauth://totp/ links');
  assert.equal(page.module.groupSecret(null), '');
  page.dispose();
});

// ---------------------------------------------------------- step-up ----

test('step-up: removing a passkey asks to confirm, then satisfies step_up_required and retries once', async () => {
  const page = await open({
    fetch: {
      'GET /api/me': [reply(200, { ...ME, factors: { ...ME.factors, totp: true } }), reply(200, { ...ME, factors: { ...ME.factors, totp: true, passkeys: 0 }, passkeys: [] })],
      'DELETE /api/me/mfa/passkey/41': [reply(403, { error: 'Confirm it’s you to continue.', step_up_required: true }), reply(200, { ok: true })],
      'GET /api/me/step-up': reply(200, { methods: ['totp', 'backup'], destinations: [] }),
      'POST /api/me/step-up/code': reply(200, { ok: true }),
    },
  });
  const remove = byText(page.document, '#passkey-list button', 'Remove');
  assert.ok(remove, 'a Remove button per passkey');
  assert.equal(remove.getAttribute('aria-label'), 'Remove MacBook Touch ID');
  await page.click(remove);
  assert.equal(page.document.querySelector('dialog.modal .modal-title').textContent, 'Remove this passkey?');
  await page.click(modalButton(page, 'btn-danger'));
  assert.equal(page.text('stepup-title'), 'Confirm it’s you', 'the step-up dialog opened');
  page.fill('stepup-code', '123456');
  page.document.querySelector('dialog.modal-stepup form').requestSubmit();
  await page.drain();
  const calls = page.calls.fetch.map((r) => `${r.method} ${r.path}`).filter((c) => !/sessions|devices|activity|fingerprint/.test(c));
  assert.deepEqual(calls, ['GET /api/me', 'DELETE /api/me/mfa/passkey/41', 'GET /api/me/step-up', 'POST /api/me/step-up/code', 'DELETE /api/me/mfa/passkey/41', 'GET /api/me']);
  assert.equal(page.document.querySelector('dialog'), null, 'dialogs closed');
  assert.equal(page.text('passkey-list'), 'No passkeys yet.');
  assert.ok(!page.visible('passkey-error'));
  page.dispose();
});

test('step-up: cancelling it leaves the passkey and says why nothing happened', async () => {
  const page = await open({
    fetch: {
      'DELETE /api/me/mfa/passkey/41': reply(403, { error: 'Confirm it’s you to continue.', step_up_required: true }),
      'GET /api/me/step-up': reply(200, { methods: ['totp'], destinations: [] }),
    },
  });
  await page.click(byText(page.document, '#passkey-list button', 'Remove'));
  await page.click(modalButton(page, 'btn-danger'));
  await page.click('stepup-cancel');
  assert.equal(page.requests('/api/me/mfa/passkey/41', 'DELETE').length, 1, 'no retry after cancel');
  assert.match(page.text('passkey-error'), /^Cancelled/);
  assert.equal(page.document.querySelectorAll('#passkey-list [data-passkey-id]').length, 1);
  page.dispose();
});

test('removing the last factor: the server refusal is shown, not swallowed', async () => {
  const page = await open({ fetch: { 'DELETE /api/me/mfa/passkey/41': reply(409, { error: 'That’s your last way to confirm it’s you — add another first.' }) } });
  await page.click(byText(page.document, '#passkey-list button', 'Remove'));
  await page.click(modalButton(page, 'btn-danger'));
  assert.equal(page.text('passkey-error'), 'That’s your last way to confirm it’s you — add another first.');
  page.dispose();
});

test('new backup codes need step-up and are shown once', async () => {
  const page = await open({
    fetch: {
      'GET /api/me': reply(200, { ...ME, factors: { ...ME.factors, totp: true } }),
      'POST /api/me/mfa/backup/regenerate': [reply(403, { step_up_required: true }), reply(200, { backup_codes: CODES })],
      'GET /api/me/step-up': reply(200, { methods: ['totp'], destinations: [] }),
      'POST /api/me/step-up/code': reply(200, { ok: true }),
    },
  });
  assert.ok(page.visible('backup-regenerate'));
  await page.click('backup-regenerate');
  await page.click(modalButton(page, 'btn-primary'));
  page.fill('stepup-code', '654321');
  page.document.querySelector('dialog.modal-stepup form').requestSubmit();
  await page.drain();
  assert.equal(page.requests('/api/me/mfa/backup/regenerate').length, 2);
  assert.deepEqual(texts(page.document, '#codes-list li'), CODES);
  await page.click('codes-done');
  assert.ok(!pageText(page).includes(CODES[0]));
  page.dispose();
});

// ------------------------------------------------------------ pinned ----

test('pinned password_change: one section, every other nav item disabled with a reason, nothing else fetched', async () => {
  const page = await open({ url: `${ORIGIN}/account?pin=password_change&next=%2Fadmin`, fetch: { 'GET /api/me': reply(200, { ...ME, pinned: 'password_change' }) } });
  assert.deepEqual(shown(page), ['password']);
  assert.ok(page.visible('pin-banner'));
  assert.equal(page.text('pin-title'), 'Choose a new password to continue');
  assert.deepEqual(navState(page), ['profile:off/disabled', 'password:on', 'security:off/disabled', 'sessions:off/disabled', 'devices:off/disabled', 'activity:off/disabled', 'browser:off/disabled']);
  assert.ok(page.visible('nav-locked'));
  assert.equal(page.text('nav-locked'), 'The other sections open once you’ve chosen a new password.');
  assert.equal(page.document.querySelector('#account-nav a[data-section=profile]').getAttribute('title'), 'The other sections open once you’ve chosen a new password.');
  assert.deepEqual(page.document.querySelectorAll('.topnav .topnav-link.is-disabled').map((e) => e.textContent), ['Dashboard'], 'the top bar is inert too');
  assert.equal(page.document.querySelector('.topbar-streak'), null);
  assert.ok(!page.visible('enroll-prompt'));
  assert.deepEqual(page.calls.fetch.map((r) => `${r.method} ${r.path}`), ['GET /api/me'], 'pinned routes only');
  page.dispose();
});

test('pinned password_change: done → follow ?next (same-origin only); another pin → that pin, carrying next', async () => {
  const pw = 'correct horse battery staple';
  const fill = (page) => {
    page.fill('pw-current', 'the old one, long enough');
    page.fill('pw-new', pw);
    page.fill('pw-confirm', pw);
  };
  const p1 = await open({ url: `${ORIGIN}/account?pin=password_change&next=%2Fadmin`, fetch: { 'GET /api/me': reply(200, { ...ME, pinned: 'password_change' }), 'POST /api/me/password': reply(200, { ok: true, pinned: null, next: '/' }) } });
  fill(p1);
  await p1.submit('password-form');
  assert.deepEqual(p1.requests('/api/me/password')[0].body, { current: 'the old one, long enough', next: pw });
  assert.deepEqual(p1.calls.nav, [{ type: 'replace', url: '/admin' }]);
  p1.dispose();

  const p2 = await open({ url: `${ORIGIN}/account?pin=password_change&next=%2Fadmin`, fetch: { 'GET /api/me': reply(200, { ...ME, pinned: 'password_change' }), 'POST /api/me/password': reply(200, { ok: true, pinned: 'mfa_enroll', next: '/account?pin=mfa_enroll' }) } });
  fill(p2);
  await p2.submit('password-form');
  assert.deepEqual(p2.calls.nav, [{ type: 'replace', url: '/account?pin=mfa_enroll&next=%2Fadmin' }]);
  p2.dispose();

  for (const evil of ['https://evil.example/', '//evil.example', 'javascript:alert(1)', 'http://staff.example.com/admin', '/\\evil.example']) {
    const p3 = await open({ url: `${ORIGIN}/account?pin=password_change&next=${encodeURIComponent(evil)}`, fetch: { 'GET /api/me': reply(200, { ...ME, pinned: 'password_change' }), 'POST /api/me/password': reply(200, { ok: true, pinned: null, next: '/' }) } });
    fill(p3);
    await p3.submit('password-form');
    assert.deepEqual(p3.calls.nav, [{ type: 'replace', url: '/' }], evil);
    p3.dispose();
  }
});

test('pinned password_change: no `pinned` in the response → ask /api/me', async () => {
  const pw = 'correct horse battery staple';
  const page = await open({ url: `${ORIGIN}/account?pin=password_change`, fetch: { 'GET /api/me': [reply(200, { ...ME, pinned: 'password_change' }), reply(200, ME)], 'POST /api/me/password': reply(204, null) } });
  page.fill('pw-current', 'the old one, long enough');
  page.fill('pw-new', pw);
  page.fill('pw-confirm', pw);
  await page.submit('password-form');
  assert.equal(meGets(page), 2);
  assert.deepEqual(page.calls.nav, [{ type: 'replace', url: '/' }]);
  page.dispose();
});

test('pinned mfa_enroll: explains it is required, only two-step is usable; codes first, then on to next', async () => {
  const pinnedMe = { ...ME, pinned: 'mfa_enroll', enroll_prompt: true, factors: { totp: false, totpUnreadable: false, passkeys: 0, backup: 0, destinations: 0 }, passkeys: [] };
  const page = await open({
    url: `${ORIGIN}/account?pin=mfa_enroll&next=%2Fadmin%3Ftab%3Daudit`,
    fetch: {
      'GET /api/me': [reply(200, pinnedMe), reply(200, { ...pinnedMe, pinned: null, factors: { ...pinnedMe.factors, totp: true, backup: 10 } })],
      'POST /api/me/mfa/totp/begin': reply(200, { secret_grouped: 'ABCD EFGH', otpauth: OTPAUTH, qr: QR }),
      'POST /api/me/mfa/totp/confirm': reply(200, { backup_codes: CODES, pinned: null }),
    },
  });
  assert.deepEqual(shown(page), ['security']);
  assert.equal(page.text('pin-title'), 'Set up a second step to continue');
  assert.match(page.text('pin-extra'), /required for your account, not just recommended/);
  assert.ok(!page.visible('enroll-prompt'), 'the soft prompt is for prompt mode, not required mode');
  assert.deepEqual(navState(page), ['profile:off/disabled', 'password:off/disabled', 'security:on', 'sessions:off/disabled', 'devices:off/disabled', 'activity:off/disabled', 'browser:off/disabled']);
  assert.ok(!page.visible('backup-regenerate'), 'session-only actions are hidden while pinned');
  await page.click('totp-start');
  page.fill('totp-code', '123456');
  await page.submit('totp-form');
  assert.ok(page.visible('codes-panel'));
  assert.deepEqual(page.calls.nav, [], 'the codes come before navigating away');
  await page.click('codes-done');
  assert.deepEqual(page.calls.nav, [{ type: 'replace', url: '/admin?tab=audit' }]);
  page.dispose();
});

test('a stale ?pin= with no pin on the session changes nothing', async () => {
  const page = await open({ url: `${ORIGIN}/account?pin=mfa_enroll` });
  assert.deepEqual(shown(page), SECTIONS);
  assert.ok(!page.visible('pin-banner'));
  page.dispose();
});

// ------------------------------------------------------ prompt mode ----

test('prompt mode: the soft banner, and its "Not now" goes to ?next only when same-origin', async () => {
  const weak = { ...ME, enroll_prompt: true, factors: { totp: false, totpUnreadable: false, passkeys: 0, backup: 0, destinations: 1 }, passkeys: [] };
  const cases = [
    ['%2Fadmin', '/admin'],
    [encodeURIComponent('https://evil.example/'), '/'],
    [encodeURIComponent('//evil.example'), '/'],
    [encodeURIComponent('javascript:alert(1)'), '/'],
    [encodeURIComponent('http://staff.example.com/'), '/'],
    ['junk%00', '/'],
  ];
  for (const [raw, want] of cases) {
    const page = await open({ url: `${ORIGIN}/account?next=${raw}`, fetch: { 'GET /api/me': reply(200, weak) } });
    assert.ok(page.visible('enroll-prompt'));
    assert.match(page.text('enroll-prompt'), /Recommended, not required/);
    assert.equal(page.$('enroll-skip').getAttribute('href'), want, raw);
    page.dispose();
  }
});

// ---------------------------------------------------------- passkeys ----

const credential = () => ({
  id: 'x',
  rawId: new Uint8Array([0xfb, 0xff, 0xbe, 0x01]).buffer,
  type: 'public-key',
  response: { clientDataJSON: new Uint8Array([1, 2, 3]).buffer, attestationObject: new Uint8Array([4, 5]).buffer },
});
const REG_OPTIONS = { challenge: 'AQID', rp: { id: 'staff.example.com', name: 'Acme' }, user: { id: 'Bw', name: 'jane@acme.com', displayName: 'Jane Doe' }, pubKeyCredParams: [{ type: 'public-key', alg: -7 }], excludeCredentials: [] };

test('passkeys: the label is guessed from the browser, the ceremony runs, the wire format is sent', async () => {
  const page = await open({
    webauthn: { get: async () => null, create: async () => credential() },
    fetch: {
      'POST /api/me/mfa/passkey/options': reply(200, REG_OPTIONS),
      'POST /api/me/mfa/passkey/register': reply(200, { passkey: { id: 42, label: 'Chrome on macOS' }, backup_codes: null, pinned: null }),
    },
  });
  assert.ok(page.visible('passkey-form'));
  assert.equal(page.$('passkey-label').value, 'Chrome on macOS');
  await page.submit('passkey-form');
  const body = page.requests('/api/me/mfa/passkey/register')[0].body;
  assert.equal(body.label, 'Chrome on macOS');
  assert.deepEqual(body.credential, { id: '-_--AQ', rawId: '-_--AQ', type: 'public-key', response: { clientDataJSON: 'AQID', attestationObject: 'BAU' } });
  assert.equal(meGets(page), 2, 'refreshed after adding');
  page.dispose();
});

test('passkeys: a dismissed dialog is not an error; a browser without passkeys is told so', async () => {
  const cancelled = Object.assign(new Error('not allowed'), { name: 'NotAllowedError' });
  const page = await open({ webauthn: { get: async () => null, create: async () => Promise.reject(cancelled) }, fetch: { 'POST /api/me/mfa/passkey/options': reply(200, REG_OPTIONS) } });
  await page.submit('passkey-form');
  assert.equal(page.requests('/api/me/mfa/passkey/register').length, 0);
  assert.ok(!page.visible('passkey-error'));
  assert.equal(page.text('security-status'), 'Cancelled — no passkey was added.');
  page.dispose();
  const none = await open();
  assert.ok(!none.visible('passkey-form'));
  assert.ok(none.visible('passkey-unsupported'));
  none.dispose();
});

test('passkeys: rename in place', async () => {
  const page = await open({ fetch: { 'PATCH /api/me/mfa/passkey/41': reply(200, { ok: true }) } });
  await page.click(byText(page.document, '#passkey-list button', 'Rename'));
  page.fill('passkey-rename-41', '  Work laptop ');
  page.document.querySelector('#passkey-list form').requestSubmit();
  await page.drain();
  assert.deepEqual(page.requests('/api/me/mfa/passkey/41', 'PATCH')[0].body, { label: 'Work laptop' });
  page.dispose();
});

// --------------------------------------------------- sessions, devices ----

test('sessions: this browser is marked; end one; end all others after a confirmation', async () => {
  const page = await open({ fetch: { 'DELETE /api/me/sessions/bbbbbbbbbbbb': reply(200, { ok: true }), 'POST /api/me/sessions/revoke-others': reply(200, { revoked: 1 }) } });
  const rows = page.document.querySelectorAll('#session-list .item-row');
  assert.match(rows[0].textContent, /Chrome on macOS This browser/);
  assert.equal(rows[0].querySelector('button'), null, 'you cannot end the session you are using from here');
  assert.match(rows[1].textContent, /Safari on iPhone/);
  await page.click(byText(rows[1], 'button', 'Sign out'));
  assert.equal(page.requests('/api/me/sessions/bbbbbbbbbbbb', 'DELETE').length, 1);
  assert.ok(page.visible('sessions-others'));
  await page.click('sessions-others');
  await page.click(modalButton(page, 'btn-primary'));
  assert.equal(page.requests('/api/me/sessions/revoke-others', 'POST').length, 1);
  assert.equal(page.requests('/api/me/sessions', 'GET').length, 3, 'reloaded after each');
  page.dispose();
});

test('devices: approving another device is explained, and impossible from an unapproved one', async () => {
  const pending = await open({ fetch: { 'GET /api/me/devices': reply(200, DEVICES('pending')) } });
  assert.ok(pending.$('approve-code').disabled);
  assert.ok(pending.$('approve-submit').disabled);
  assert.match(pending.text('approve-note'), /isn’t an approved device yet/);
  pending.dispose();

  const page = await open({ fetch: { 'POST /api/me/devices/approve': reply(200, { ok: true }) } });
  assert.ok(!page.$('approve-submit').disabled);
  assert.match(page.text('approve-note'), /only from a device that is itself approved/);
  await page.submit('approve-form');
  assert.equal(page.text('approve-error'), 'Enter the code shown on the other device.');
  page.fill('approve-code', ' k7f3-9qx2 ');
  await page.submit('approve-form');
  assert.deepEqual(page.requests('/api/me/devices/approve')[0].body, { code: 'K7F3-9QX2' });
  page.dispose();
});

test('devices: forget asks first', async () => {
  const page = await open({ fetch: { 'DELETE /api/me/devices/d2': reply(200, { ok: true }) } });
  await page.click(byText(page.document, '#device-list button', 'Forget'));
  const forgetBtn = page.document.querySelectorAll('#device-list button')[1];
  await page.click(modalButton(page, 'btn-secondary'));
  assert.equal(page.requests('/api/me/devices', 'DELETE').length, 0, 'cancelled');
  await page.click(forgetBtn);
  await page.click(modalButton(page, 'btn-danger'));
  assert.equal(page.requests('/api/me/devices/d2', 'DELETE').length, 1);
  page.dispose();
});

// ------------------------------------------------------- browser, forms ----

test('this browser: the score, each flag’s plain-English reason and weight, the notice', async () => {
  const page = await open();
  assert.match(page.text('fp-score'), /^35 out of 100 Medium risk$/);
  assert.equal(page.$('fp-meter').getAttribute('value'), '35');
  assert.deepEqual(texts(page.document, '#fp-flags li'), [
    'Your network belongs to a hosting provider, which people rarely browse from.+25',
    'Your browser’s time zone doesn’t match where your IP address is.+10',
  ]);
  assert.match(page.text('fp-body'), /Browsers scoring 70 or more are refused/);
  assert.ok(page.visible('fp-notice'));
  assert.equal(page.text('fp-notice'), 'We record browser details to keep accounts safe.');
  assert.match(page.text('fp-facts'), /Example Hosting Ltd/);
  page.dispose();
  const clean = await open({ fetch: { 'GET /api/me/fingerprint': reply(200, { fingerprint: { visitor_id: 'x' }, risk: { score: 0, flags: [] }, threshold: 70 }) } });
  assert.equal(clean.text('fp-flags'), 'Nothing about this browser raised the score.');
  clean.dispose();
  const none = await open({ fetch: { 'GET /api/me/fingerprint': reply(200, { fingerprint: null }) } });
  assert.match(none.text('fp-body'), /Nothing recorded yet/);
  none.dispose();
});

test('password: checked client-side first; a wrong current password lands on that field', async () => {
  const page = await open({ fetch: { 'POST /api/me/password': reply(401, { error: 'Your current password is wrong.' }), 'GET /api/auth/whoami': reply(200, { authenticated: true }) } });
  page.fill('pw-current', 'whatever it was');
  page.fill('pw-new', 'short');
  page.fill('pw-confirm', 'short');
  await page.submit('password-form');
  assert.equal(page.requests('/api/me/password').length, 0);
  assert.equal(page.$('pw-new').getAttribute('aria-invalid'), 'true');
  page.fill('pw-new', 'correct horse battery staple');
  page.fill('pw-confirm', 'correct horse battery stapl');
  await page.submit('password-form');
  assert.equal(page.requests('/api/me/password').length, 0, 'mismatch caught');
  page.fill('pw-confirm', 'correct horse battery staple');
  await page.submit('password-form');
  assert.equal(page.requests('/api/me/password').length, 1);
  assert.equal(page.text('pw-current-error'), 'Your current password is wrong.');
  assert.equal(page.$('pw-current').value, '');
  assert.deepEqual(page.calls.nav, [], 'a wrong password never signs anyone out');
  page.dispose();
});

test('profile: blank refused; a name is saved and the top bar follows', async () => {
  const page = await open({ fetch: { 'PATCH /api/me': reply(200, { user: { ...USER, full_name: 'Jane Q Doe' } }) } });
  page.fill('profile-name', '   ');
  await page.submit('profile-form');
  assert.equal(page.requests('/api/me', 'PATCH').length, 0);
  assert.equal(page.text('profile-name-error'), 'Enter your name.');
  page.fill('profile-name', ' Jane Q Doe ');
  await page.submit('profile-form');
  assert.deepEqual(page.requests('/api/me', 'PATCH')[0].body, { full_name: 'Jane Q Doe' });
  assert.equal(page.document.querySelector('.topbar .avatar').textContent, 'JD');
  assert.equal(page.document.querySelector('.topbar-name').textContent, 'Jane Q Doe');
  page.dispose();
});

test('guessDeviceLabel', async () => {
  const page = await open();
  const g = page.module.guessDeviceLabel;
  assert.equal(g(SESSIONS.sessions[0].ua), 'Chrome on macOS');
  assert.equal(g(SESSIONS.sessions[1].ua), 'Safari on iPhone');
  assert.equal(g('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0'), 'Edge on Windows');
  assert.equal(g('Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36'), 'Chrome on Android');
  assert.equal(g('Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0'), 'Firefox on Linux');
  for (const junk of [null, undefined, '', 42, {}]) assert.equal(g(junk), 'This device');
  page.dispose();
});

await run();
