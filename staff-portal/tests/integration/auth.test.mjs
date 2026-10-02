// The sign-in, setup and account pages against the REAL worker
// (tests/helpers/live.js): every fetch the page makes goes through
// worker.fetch with a real cookie jar, IP and cf, on a real SQLite env.
// What the page shows is compared with what the API really answered.

import { test, assert, run } from '../helpers/t.js';
import { byText, loadPage } from '../helpers/dom.js';
import { openLive, browserCredentials, apiErrors, lastNav, settle } from '../helpers/live.js';
import { SoftAuthenticator } from '../helpers/authenticator.js';
import { freshEnv, bootstrap, makeUser, client, nextTotp, totpNow, signOut, q, count, OWNER_IP, OWNER, PASSWORD, worker, Client } from '../helpers/flows.js';

const ORIGIN = 'https://staff.example.com';

function authenticator(env) {
  return new SoftAuthenticator({ origin: env.ORIGIN, rpId: env.RP_ID });
}

async function submit(page, form) {
  await page.submit(form);
  await settle(page);
}

async function click(page, el) {
  await page.click(el);
  await settle(page);
}

async function typePassword(page, identifier, password) {
  page.fill('identifier', identifier);
  page.fill('password', password);
  await submit(page, 'form-password');
}

// Exact path (dom.js requests() matches a prefix).
function calls(page, method, path) {
  return page.calls.fetch.filter((c) => c.method === method && c.path === path);
}

function noErrors(page, ignore = []) {
  const bad = apiErrors(page, { ignore });
  assert.deepEqual(bad.map((c) => `${c.method} ${c.url} → ${c.status} ${JSON.stringify(c.response)}`), [], 'a live API call failed');
  assert.deepEqual(page.calls.pageErrors.map((e) => String(e && e.stack ? e.stack : e)), [], 'the page threw');
}

// A passkey registered over the API (the page flow is tested separately).
async function registerPasskeyApi(c, a, label = 'Laptop') {
  const o = await c.post('/api/me/mfa/passkey/options', {});
  assert.equal(o.status, 200, o.text);
  const r = await c.post('/api/me/mfa/passkey/register', { credential: await a.create(o.body), label });
  assert.equal(r.status, 200, r.text);
  return r.body;
}

// ------------------------------------------------------------ login ----

test('login: password then an authenticator code signs in and navigates to ?next', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const c = client(env, { ip: OWNER_IP }); // a new browser on the office network
  const page = await openLive(c, '/login?next=/admin');
  assert.equal(page.served.file, 'login.html');
  await settle(page);
  assert.equal(page.text('org-name'), 'Acme Inc.', 'org name from the real whoami');
  assert.ok(page.visible('privacy'), 'the privacy notice the real whoami sent');
  assert.match(page.text('privacy'), /records technical details/);

  await typePassword(page, OWNER.email, OWNER.password);
  const login = page.requests('/api/auth/login')[0];
  assert.equal(login.status, 200);
  assert.equal(login.response.mfa_required, true);
  assert.deepEqual(login.response.methods, ['totp', 'backup']);
  assert.ok(page.visible('pane-code'), 'one method this browser can use → the code box opens directly');
  assert.equal(page.text('code-label'), 'Code from your authenticator app');

  page.fill('code', await nextTotp(env, owner.totpSecret));
  await submit(page, 'form-code');
  const code = page.requests('/api/auth/mfa/code')[0];
  assert.equal(code.status, 200, JSON.stringify(code.response));
  assert.equal(code.body.token, login.response.token, 'the token from the login reply');
  assert.deepEqual(lastNav(page), { type: 'replace', url: '/admin' });
  noErrors(page);

  const next = await openLive(c, '/admin');
  assert.equal(next.served.file, 'admin.html', 'the session cookie the page got is real');
  next.dispose();
});

test('login: a backup code works in the same box as the authenticator code', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const c = client(env, { ip: OWNER_IP });
  const page = await openLive(c, '/login');
  await settle(page);
  await typePassword(page, OWNER.email, OWNER.password);
  assert.ok(page.visible('pane-code'));
  page.fill('code', owner.backupCodes[0].toLowerCase());
  await submit(page, 'form-code');
  assert.equal(page.requests('/api/auth/mfa/code')[0].status, 200);
  assert.deepEqual(lastNav(page), { type: 'replace', url: '/' });
  assert.equal(count(env, 'SELECT COUNT(*) FROM backup_codes WHERE user_id = ? AND used_at IS NOT NULL', owner.user.id), 1);
  noErrors(page);
});

test('login: a wrong code says so and keeps the box; a wrong password shows the server’s sentence', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const c = client(env, { ip: OWNER_IP });
  const page = await openLive(c, '/login');
  await settle(page);
  await typePassword(page, OWNER.email, 'not-the-password-0000');
  const r = page.requests('/api/auth/login')[0];
  assert.equal(r.status, 401);
  assert.ok(page.visible('password-error'));
  assert.equal(page.text('password-error'), r.response.error);
  assert.equal(page.text('password-error'), 'Invalid credentials.');
  assert.equal(page.$('password').value, '', 'the password box is cleared');
  assert.ok(page.visible('pane-password'));
  assert.deepEqual(lastNav(page), null);

  await typePassword(page, OWNER.email, OWNER.password);
  page.fill('code', '000000');
  await submit(page, 'form-code');
  assert.equal(page.requests('/api/auth/mfa/code')[0].status, 401);
  assert.ok(page.visible('code-error'));
  assert.match(page.text('code-error'), /didn’t work/);
  assert.ok(page.visible('pane-code'));
  page.fill('code', await nextTotp(env, owner.totpSecret));
  await submit(page, 'form-code');
  assert.deepEqual(lastNav(page), { type: 'replace', url: '/' });
});

test('login: a passkey through SoftAuthenticator as navigator.credentials (chooser → passkey)', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const u = await makeUser(env, owner.client, { role: 'employee' });
  const a = authenticator(env);
  const reg = await registerPasskeyApi(u.client, a, 'Work laptop');
  assert.equal(reg.backup_codes.length, 10, 'first strong factor → backup codes');
  await signOut(u.client);

  const creds = browserCredentials(a);
  const page = await openLive(u.client, '/login', { webauthn: creds });
  await settle(page);
  await typePassword(page, u.user.email, PASSWORD);
  const login = page.requests('/api/auth/login')[0].response;
  assert.deepEqual(login.methods, ['passkey', 'backup']);
  assert.ok(page.visible('pane-choose'), 'two methods → the chooser');
  assert.deepEqual(page.document.querySelectorAll('#choices .choice').map((b) => b.dataset.kind), ['passkey', 'backup']);

  await click(page, page.document.querySelector('#choices .choice[data-kind="passkey"]'));
  assert.equal(creds.calls.length, 1, 'navigator.credentials.get was called once');
  assert.equal(creds.calls[0].kind, 'get');
  assert.equal(creds.calls[0].options.rpId, env.RP_ID, 'the rpId from the real options');
  const verify = page.requests('/api/auth/mfa/passkey/verify')[0];
  assert.equal(verify.status, 200, JSON.stringify(verify.response));
  assert.equal(verify.body.credential.id, verify.body.credential.rawId, 'id re-derived from rawId, url-safe');
  assert.deepEqual(lastNav(page), { type: 'replace', url: '/' });
  noErrors(page);
  assert.ok(q(env, 'SELECT last_used_at FROM user_passkeys WHERE user_id = ?', u.user.id)[0].last_used_at, 'the server recorded the use');
});

test('login: a dismissed passkey dialog returns to the chooser; a backup code then works', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const u = await makeUser(env, owner.client, { role: 'employee' });
  const a = authenticator(env);
  const reg = await registerPasskeyApi(u.client, a);
  await signOut(u.client);
  // Another authenticator: it holds no credential the server allows → NotAllowedError.
  const page = await openLive(u.client, '/login', { webauthn: browserCredentials(authenticator(env)) });
  await settle(page);
  await typePassword(page, u.user.email, PASSWORD);
  await click(page, page.document.querySelector('#choices .choice[data-kind="passkey"]'));
  assert.ok(page.visible('pane-choose'), 'cancelled → back to the chooser, no error');
  assert.equal(page.requests('/api/auth/mfa/passkey/verify').length, 0);
  await click(page, page.document.querySelector('#choices .choice[data-kind="backup"]'));
  assert.ok(page.visible('pane-code'));
  assert.equal(page.text('code-label'), 'Backup code');
  page.fill('code', reg.backup_codes[3]);
  await submit(page, 'form-code');
  assert.deepEqual(lastNav(page), { type: 'replace', url: '/' });
  noErrors(page);
});

test('login: no factor enrolled → signed in, with the enroll prompt (a prompt, never a wall)', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const u = await makeUser(env, owner.client, { role: 'employee' });
  await signOut(u.client);
  const page = await openLive(u.client, '/');
  assert.equal(page.served.file, 'login.html', 'signed out: / is the sign-in page');
  await settle(page);
  await typePassword(page, u.user.email, PASSWORD);
  const r = page.requests('/api/auth/login')[0];
  assert.equal(r.status, 200);
  assert.equal(r.response.enroll_prompt, true);
  assert.equal(r.response.pinned, null);
  assert.ok(page.visible('pane-enroll'));
  assert.equal(page.$('enroll-setup').getAttribute('href'), '/account?enroll=1&next=%2F');
  assert.equal(page.$('enroll-skip').getAttribute('href'), '/');
  assert.deepEqual(lastNav(page), null, 'the page waits for a choice');
  noErrors(page);

  const account = await openLive(u.client, page.$('enroll-setup').getAttribute('href'));
  await settle(account);
  assert.equal(account.served.file, 'account.html');
  assert.ok(account.visible('enroll-prompt'), 'the account page repeats the prompt');
  assert.equal(account.$('enroll-skip').getAttribute('href'), '/');
  noErrors(account);
  account.dispose();
});

test('login: already signed in → the server sends /login home; the page itself follows ?next', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  // CONTRACTS §8.3: /login with a session redirects to /.
  const served = await openLive(owner.client, '/login?next=/account');
  assert.deepEqual(served.served.redirects, ['/']);
  assert.equal(served.served.file, 'dashboard.html');
  served.dispose();
  // A login page already open in a tab (no navigation): whoami says signed in.
  const page = await loadPage('login.html', { url: `${ORIGIN}/login?next=/account`, live: owner.client });
  await settle(page);
  assert.equal(page.requests('/api/auth/whoami')[0].response.authenticated, true);
  assert.deepEqual(lastNav(page), { type: 'replace', url: '/account' });
  page.dispose();
});

// ------------------------------------------------------------ setup ----

test('setup: the setup page creates the owner and lands pinned on /account?pin=mfa_enroll', async () => {
  const env = freshEnv();
  const c = new Client(worker, env, { ip: OWNER_IP });
  const page = await openLive(c, '/');
  assert.equal(page.served.file, 'setup.html', 'no accounts yet: / is the setup page');
  await settle(page);
  assert.equal(page.requests('/api/setup/status')[0].status, 200);
  assert.equal(page.text('org-name'), 'Acme Inc.');
  assert.ok(page.visible('pane-form'));

  page.fill('setup_key', env.SETUP_KEY);
  page.fill('full_name', OWNER.full_name);
  page.fill('email', OWNER.email);
  page.fill('password', OWNER.password);
  page.fill('confirm', OWNER.password);
  await submit(page, 'form-setup');
  const r = calls(page, 'POST', '/api/setup')[0];
  assert.equal(r.status, 200, JSON.stringify(r.response));
  assert.equal(r.response.pinned, 'mfa_enroll');
  assert.deepEqual(lastNav(page), { type: 'replace', url: '/account?pin=mfa_enroll' });
  noErrors(page);

  // Anywhere else is pinned back to the account page.
  const home = await openLive(c, '/');
  assert.deepEqual(home.served.redirects, ['/account?pin=mfa_enroll']);
  assert.equal(home.served.file, 'account.html');
  home.dispose();

  // Setup is gone for good.
  const again = await openLive(c, '/login').catch(() => null);
  assert.ok(again === null || again.served.file !== 'setup.html');
  again?.dispose();
});

test('setup: a wrong key is marked on the key field and cleared', async () => {
  const env = freshEnv();
  const c = new Client(worker, env, { ip: OWNER_IP });
  const page = await openLive(c, '/setup');
  await settle(page);
  page.fill('setup_key', 'x'.repeat(40));
  page.fill('full_name', OWNER.full_name);
  page.fill('email', OWNER.email);
  page.fill('password', OWNER.password);
  page.fill('confirm', OWNER.password);
  await submit(page, 'form-setup');
  assert.equal(calls(page, 'POST', '/api/setup')[0].status, 403);
  assert.ok(page.visible('setup_key-error'));
  assert.equal(page.text('setup_key-error'), 'That setup key isn’t right.');
  assert.equal(page.$('setup_key').value, '');
  assert.equal(count(env, 'SELECT COUNT(*) FROM users'), 0);
});

// ------------------------------------------------------------ account ----

async function setupPinned(env) {
  const c = new Client(worker, env, { ip: OWNER_IP });
  const r = await c.post('/api/setup', { setup_key: env.SETUP_KEY, email: OWNER.email, full_name: OWNER.full_name, password: OWNER.password });
  assert.equal(r.status, 200, r.text);
  return c;
}

test('account (pinned mfa_enroll): TOTP from the page — QR, grouped secret, code, backup codes once, then home', async () => {
  const env = freshEnv();
  const c = await setupPinned(env);
  const page = await openLive(c, '/account?pin=mfa_enroll');
  await settle(page);
  const me = page.requests('/api/me')[0];
  assert.equal(me.status, 200);
  assert.equal(me.response.pinned, 'mfa_enroll');
  assert.ok(page.visible('pin-banner'));
  assert.equal(page.text('pin-title'), 'Set up a second step to continue');
  assert.ok(page.visible('security'));
  for (const id of ['profile', 'password', 'sessions', 'devices', 'activity', 'browser']) assert.ok(!page.visible(id), `${id} hidden while pinned`);
  assert.deepEqual(page.requests('/api/me/sessions'), [], 'nothing else fetched while pinned');

  await click(page, 'totp-start');
  const begin = page.requests('/api/me/mfa/totp/begin')[0];
  assert.equal(begin.status, 200);
  assert.ok(page.visible('totp-setup'));
  const img = page.$('totp-qr');
  assert.equal(img.localName, 'img');
  assert.equal(img.getAttribute('src'), begin.response.qr);
  assert.match(img.getAttribute('src'), /^data:image\/svg\+xml;base64,/);
  assert.equal(page.text('totp-secret'), begin.response.secret_grouped);
  assert.match(page.text('totp-secret'), /^([A-Z2-7]{4} )+[A-Z2-7]{1,4}$/, 'grouped in fours');
  assert.equal(page.$('totp-link').getAttribute('href'), begin.response.otpauth);
  const secret = page.text('totp-secret').replace(/\s+/g, '');
  assert.equal(new URL(begin.response.otpauth).searchParams.get('secret'), secret);

  page.fill('totp-code', await totpNow(secret, env));
  await submit(page, 'totp-form');
  const confirm = page.requests('/api/me/mfa/totp/confirm')[0];
  assert.equal(confirm.status, 200, JSON.stringify(confirm.response));
  assert.equal(confirm.response.pinned, null);
  assert.ok(page.visible('codes-panel'), 'backup codes shown');
  const shown = page.document.querySelectorAll('#codes-list li').map((li) => li.textContent);
  assert.deepEqual(shown, confirm.response.backup_codes);
  assert.equal(shown.length, 10);
  assert.deepEqual(lastNav(page), null, 'nothing moves until the codes are put away');

  await click(page, 'codes-done');
  assert.ok(!page.visible('codes-panel'));
  assert.equal(page.document.querySelectorAll('#codes-list li').length, 0, 'gone from the page');
  assert.deepEqual(lastNav(page), { type: 'replace', url: '/' });
  noErrors(page);

  // Shown ONCE: a fresh load of the account page has no codes, just a count.
  const again = await openLive(c, '/account');
  await settle(again);
  assert.equal(again.served.file, 'account.html');
  assert.ok(!again.visible('pin-banner'));
  assert.ok(!again.visible('codes-panel'));
  assert.match(again.text('backup-state'), /^10 unused/);
  assert.match(again.text('totp-state'), /On/);
  assert.equal(again.text('mfa-summary'), 'Signing in takes your password and a second step.');
  noErrors(again);
  again.dispose();
});

test('account (pinned mfa_enroll): passkey registration from the page finishes the pinned step', async () => {
  const env = freshEnv();
  const c = await setupPinned(env);
  const a = authenticator(env);
  const creds = browserCredentials(a);
  const page = await openLive(c, '/account?pin=mfa_enroll', { webauthn: creds });
  await settle(page);
  assert.ok(page.visible('passkey-form'), 'this browser can make passkeys');
  page.fill('passkey-label', 'Owner laptop');
  await submit(page, 'passkey-form');
  assert.equal(creds.calls[0]?.kind, 'create');
  assert.equal(creds.calls[0].options.rp.id, env.RP_ID);
  const reg = page.requests('/api/me/mfa/passkey/register')[0];
  assert.equal(reg.status, 200, JSON.stringify(reg.response));
  assert.equal(reg.body.label, 'Owner laptop');
  assert.equal(reg.response.passkey.label, 'Owner laptop');
  assert.ok(page.visible('codes-panel'));
  assert.deepEqual(page.document.querySelectorAll('#codes-list li').map((li) => li.textContent), reg.response.backup_codes);
  assert.ok(byText(page.document, '#passkey-list .item-title', 'Owner laptop'), 'the list re-read from GET /api/me shows it');
  await click(page, 'codes-done');
  assert.deepEqual(lastNav(page), { type: 'replace', url: '/' });
  noErrors(page);
  assert.equal(count(env, 'SELECT COUNT(*) FROM user_passkeys'), 1);
});

test('account: an employee adds a passkey (not pinned) — listed from GET /api/me passkeys, then renamed', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const u = await makeUser(env, owner.client, { role: 'employee' });
  const a = authenticator(env);
  const page = await openLive(u.client, '/account', { webauthn: browserCredentials(a) });
  await settle(page);
  noErrors(page);
  assert.ok(page.visible('enroll-prompt'));
  assert.equal(page.text('passkey-list'), 'No passkeys yet.');
  page.fill('passkey-label', 'Phone');
  await submit(page, 'passkey-form');
  const reg = page.requests('/api/me/mfa/passkey/register')[0];
  assert.equal(reg.status, 200);
  assert.equal(reg.response.backup_codes.length, 10);
  assert.ok(page.visible('codes-panel'));
  await click(page, 'codes-done');
  assert.deepEqual(lastNav(page), null, 'not pinned: the page stays');
  const me = page.requests('/api/me').at(-1).response;
  assert.equal(me.passkeys.length, 1);
  assert.deepEqual(Object.keys(me.passkeys[0]).sort(), ['created_at', 'id', 'label', 'last_used_at']);
  const row = page.document.querySelector('#passkey-list .item-row');
  assert.equal(row.dataset.passkeyId, String(me.passkeys[0].id));
  assert.ok(!page.visible('enroll-prompt'), 'prompt gone once a strong factor exists');

  await click(page, byText(row, 'button', 'Rename'));
  page.fill(`passkey-rename-${me.passkeys[0].id}`, 'Pixel');
  await page.submit(row.querySelector('form'));
  await settle(page);
  assert.equal(page.requests(`/api/me/mfa/passkey/${me.passkeys[0].id}`, 'PATCH')[0].status, 200);
  assert.ok(byText(page.document, '#passkey-list .item-title', 'Pixel'));
  noErrors(page);
});

test('account: sessions, devices, activity and browser sections render the real replies', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const page = await openLive(owner.client, '/account');
  await settle(page);
  noErrors(page);
  const sessions = page.requests('/api/me/sessions')[0].response.sessions;
  assert.equal(page.document.querySelectorAll('#session-list .item-row').length, sessions.length);
  assert.ok(byText(page.document, '#session-list .item-title', 'This browser'));
  const devices = page.requests('/api/me/devices')[0].response.devices;
  assert.ok(devices.length >= 1);
  assert.ok(byText(page.document, '#device-list .item-title', 'Approved'));
  assert.ok(byText(page.document, '#device-list .item-title', 'This device'));
  assert.ok(!page.$('approve-code').disabled, 'an approved device may approve others');
  const entries = page.requests('/api/me/activity')[0].response.entries;
  assert.ok(entries.length > 0);
  const rows = page.document.querySelectorAll('#activity-list tbody tr');
  assert.equal(rows.length, entries.length);
  assert.equal(rows[0].querySelector('td[data-label="What"]').textContent, entries[0].detail);
  assert.notEqual(rows[0].querySelector('td[data-label="When"]').textContent, '—', 'the `at` field was read');
  assert.equal(page.text('profile-facts').includes(owner.user.employee_no), true);
});

test('account: device approval by code from the page (step-up through the real dialog)', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  // A new browser on the office network can be minted a device and read its
  // code (what the pending page shows).
  const laptop2 = client(env, { ip: OWNER_IP });
  const st = await laptop2.get('/api/device/status');
  assert.equal(st.status, 200, st.text);
  assert.equal(st.body.status, 'pending');

  env.__advance(20 * 60 * 1000); // the step-up from bootstrap is stale now
  const page = await openLive(owner.client, '/account');
  await settle(page);
  page.fill('approve-code', st.body.code.toLowerCase());
  await page.submit('approve-form');
  await settle(page);
  // step_up_required → the dialog
  const dialog = page.document.querySelector('dialog.modal-stepup');
  assert.ok(dialog, 'the step-up dialog opened');
  page.fill('stepup-code', await nextTotp(env, owner.totpSecret));
  await page.submit(dialog.querySelector('form'));
  await settle(page);
  const approves = page.requests('/api/me/devices/approve');
  assert.deepEqual(approves.map((r) => r.status), [403, 200]);
  assert.equal(approves[1].body.code, st.body.code, 'the code is normalised to upper case');
  assert.equal((await laptop2.get('/api/device/status')).body.status, 'approved');
  assert.ok(!page.visible('approve-error'));
  noErrors(page, ['POST /api/me/devices/approve']);
});

await run();
