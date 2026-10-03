// Second factors and passwords, page against the REAL API: changing a
// password (a wrong current one lands on its field), the password_change pin
// after an administrator's reset, the step-up dialog satisfied by a passkey
// and by a texted code, and signing in with a texted code — sent unasked,
// then sent again.

import { test, assert, run } from '../helpers/t.js';
import { byText } from '../helpers/dom.js';
import { openLive, browserCredentials, apiErrors, lastNav, settle } from '../helpers/live.js';
import { SoftAuthenticator } from '../helpers/authenticator.js';
import { freshEnv, bootstrap, makeUser, stepUp, signOut, fakeProvider, lastCodeSent, TWILIO, count, PASSWORD, MINUTE } from '../helpers/flows.js';

function calls(page, method, path) {
  return page.calls.fetch.filter((c) => c.method === method && (path instanceof RegExp ? path.test(c.path) : c.path === path));
}

function noFailures(page, ignore = []) {
  assert.deepEqual(apiErrors(page, { ignore }).map((c) => `${c.method} ${c.url} → ${c.status} ${JSON.stringify(c.response)}`), [], 'a live API call failed');
  assert.deepEqual(page.calls.pageErrors.map((e) => String(e && e.stack ? e.stack : e)), [], 'the page threw');
}

async function confirmWith(page, label) {
  await settle(page);
  const dlg = page.document.querySelectorAll('dialog.modal').filter((d) => d.hasAttribute('open')).at(-1);
  assert.ok(dlg, `a confirm dialog for “${label}”`);
  await page.click(byText(dlg, '.modal-actions button', label));
  await settle(page);
}

// ------------------------------------------------------------ passwords ----

test('account: a wrong current password is marked on that field; the right one changes it and ends other sessions', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const u = await makeUser(env, owner.client);
  const other = await makeUser(env, owner.client, { email: 'second@acme.com' }); // a second account, untouched
  const page = await openLive(u.client, '/account');
  await settle(page);
  page.fill('pw-current', 'not-my-password-at-all');
  page.fill('pw-new', 'a-brand-new-passphrase');
  page.fill('pw-confirm', 'a-brand-new-passphrase');
  await page.submit('password-form');
  await settle(page);
  const bad = calls(page, 'POST', '/api/me/password')[0];
  assert.equal(bad.status, 400);
  assert.equal(bad.response.field, 'current');
  assert.equal(page.text('pw-current-error'), bad.response.error);
  assert.equal(page.$('pw-current').getAttribute('aria-invalid'), 'true');
  assert.ok(!page.visible('pw-error'));
  assert.deepEqual(lastNav(page), null, 'a wrong password never signs anyone out');

  page.fill('pw-current', PASSWORD);
  page.fill('pw-new', 'a-brand-new-passphrase');
  page.fill('pw-confirm', 'a-brand-new-passphrase');
  await page.submit('password-form');
  await settle(page);
  const good = calls(page, 'POST', '/api/me/password')[1];
  assert.equal(good.status, 200, JSON.stringify(good.response));
  assert.equal(page.$('pw-current').value, '');
  assert.ok(byText(page.document, '.toast', 'Password changed.'));
  noFailures(page, ['POST /api/me/password']);
  assert.equal((await u.client.get('/api/me')).status, 200, 'this session stays');
  assert.equal((await other.client.get('/api/me')).status, 200);
});

test('password_change pin: an administrator’s reset → the login page sends them to choose a new one → then home', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const u = await makeUser(env, owner.client);
  await stepUp(env, owner.client);
  const reset = await owner.client.post(`/api/admin/users/${u.user.id}/reset-password`, {});
  assert.equal(reset.status, 200, reset.text);
  const temp = reset.body.temporary_password;

  const login = await openLive(u.client, '/login');
  await settle(login);
  login.fill('identifier', u.user.email);
  login.fill('password', temp);
  await login.submit('form-password');
  await settle(login);
  const r = calls(login, 'POST', '/api/auth/login')[0];
  assert.equal(r.status, 200, JSON.stringify(r.response));
  assert.equal(r.response.pinned, 'password_change');
  assert.deepEqual(lastNav(login), { type: 'replace', url: r.response.next });
  assert.equal(r.response.next, '/account?pin=password_change');

  const home = await openLive(u.client, '/');
  assert.deepEqual(home.served.redirects, ['/account?pin=password_change'], 'pinned: every page leads back');
  const page = home;
  await settle(page);
  assert.ok(page.visible('pin-banner'));
  assert.equal(page.text('pin-title'), 'Choose a new password to continue');
  assert.ok(page.visible('password') && !page.visible('security'));
  page.fill('pw-current', temp);
  page.fill('pw-new', 'my-own-choice-again-1');
  page.fill('pw-confirm', 'my-own-choice-again-1');
  await page.submit('password-form');
  await settle(page);
  const ch = calls(page, 'POST', '/api/me/password')[0];
  assert.equal(ch.status, 200, JSON.stringify(ch.response));
  assert.equal(ch.response.pinned, null);
  assert.deepEqual(lastNav(page), { type: 'replace', url: '/' });
  noFailures(page);
  const dash = await openLive(u.client, '/');
  assert.equal(dash.served.file, 'dashboard.html', 'unpinned');
  dash.dispose();
});

// ------------------------------------------------------------ step-up ----

test('step-up by passkey: new backup codes from the account page, confirmed with the passkey in the dialog', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const u = await makeUser(env, owner.client);
  const a = new SoftAuthenticator({ origin: env.ORIGIN, rpId: env.RP_ID });
  const o = await u.client.post('/api/me/mfa/passkey/options', {});
  const reg = await u.client.post('/api/me/mfa/passkey/register', { credential: await a.create(o.body), label: 'Laptop' });
  assert.equal(reg.status, 200, reg.text);
  const old = reg.body.backup_codes;

  const page = await openLive(u.client, '/account', { webauthn: browserCredentials(a) });
  await settle(page);
  await page.click('backup-regenerate');
  await confirmWith(page, 'Make new codes');
  const dlg = page.document.querySelector('dialog.modal-stepup');
  assert.ok(dlg, 'step-up asked for');
  assert.deepEqual(calls(page, 'GET', '/api/me/step-up')[0].response.methods, ['passkey', 'backup']);
  assert.ok(page.$('stepup-passkey'), 'the passkey button');
  await page.click('stepup-passkey');
  await settle(page);
  const v = calls(page, 'POST', '/api/me/step-up/passkey/verify')[0];
  assert.equal(v.status, 200, JSON.stringify(v.response));
  const regen = calls(page, 'POST', '/api/me/mfa/backup/regenerate');
  assert.deepEqual(regen.map((c) => c.status), [403, 200]);
  assert.ok(page.visible('codes-panel'));
  const shown = page.document.querySelectorAll('#codes-list li').map((li) => li.textContent);
  assert.deepEqual(shown, regen[1].response.backup_codes);
  assert.notDeepEqual(shown, old);
  noFailures(page, ['POST /api/me/mfa/backup/regenerate']);
});

test('step-up by texted code: removing a passkey, confirmed with a code sent to a phone an admin added', async () => {
  const provider = fakeProvider();
  const env = freshEnv({ vars: { ...TWILIO, __fetch: provider.fetch } });
  const owner = await bootstrap(env);
  const u = await makeUser(env, owner.client, { totp: true });
  await stepUp(env, owner.client);
  const add = await owner.client.post(`/api/admin/users/${u.user.id}/destinations`, { kind: 'sms', address: '+15551234567', label: 'Work phone' });
  assert.equal(add.status, 200, add.text);
  const a = new SoftAuthenticator({ origin: env.ORIGIN, rpId: env.RP_ID });
  const o = await u.client.post('/api/me/mfa/passkey/options', {});
  assert.equal((await u.client.post('/api/me/mfa/passkey/register', { credential: await a.create(o.body), label: 'Old key' })).status, 200);
  env.__advance(20 * MINUTE); // stale step-up

  const page = await openLive(u.client, '/account'); // this browser can't use passkeys
  await settle(page);
  const row = byText(page.document, '#passkey-list .item-row', 'Old key');
  await page.click(byText(row, 'button', 'Remove'));
  await confirmWith(page, 'Remove passkey');
  const dlg = page.document.querySelector('dialog.modal-stepup');
  assert.ok(dlg);
  assert.equal(page.$('stepup-passkey'), null, 'no passkey button in a browser without passkeys');
  const send = byText(dlg, 'button', 'Text a code to');
  assert.ok(send, 'the destination is offered');
  assert.equal(send.textContent.trim(), `Text a code to ${add.body.destination.hint}`);
  await page.click(send);
  await settle(page);
  const sent = calls(page, 'POST', '/api/me/step-up/send')[0];
  assert.equal(sent.status, 200, JSON.stringify(sent.response));
  assert.deepEqual(sent.body, { destination_id: add.body.destination.id });
  page.fill('stepup-otp', lastCodeSent(provider));
  await page.submit(page.$('stepup-otp').closest('form'));
  await settle(page);
  const otp = calls(page, 'POST', '/api/me/step-up/otp')[0];
  assert.equal(otp.status, 200, JSON.stringify(otp.response));
  const del = calls(page, "DELETE", /^\/api\/me\/mfa\/passkey\/[^/]+$/);
  assert.deepEqual(del.map((c) => c.status), [403, 200]);
  assert.equal(count(env, 'SELECT COUNT(*) FROM user_passkeys WHERE user_id = ?', u.user.id), 0);
  assert.equal(page.text('passkey-list'), 'No passkeys yet.');
  noFailures(page, [/^DELETE \/api\/me\/mfa\/passkey\//]);
});

// ------------------------------------------------------------ sign-in by code ----

test('login by texted code: sent unasked when it is the only way, sent again on request, then signed in', async () => {
  const provider = fakeProvider();
  const env = freshEnv({ vars: { ...TWILIO, __fetch: provider.fetch } });
  const owner = await bootstrap(env);
  const u = await makeUser(env, owner.client);
  await stepUp(env, owner.client);
  const add = await owner.client.post(`/api/admin/users/${u.user.id}/destinations`, { kind: 'sms', address: '+15557654321' });
  assert.equal(add.status, 200, add.text);
  await signOut(u.client);

  const page = await openLive(u.client, '/login');
  await settle(page);
  page.fill('identifier', u.user.email);
  page.fill('password', PASSWORD);
  await page.submit('form-password');
  await settle(page);
  const login = calls(page, 'POST', '/api/auth/login')[0].response;
  assert.deepEqual(login.methods, ['sms']);
  assert.deepEqual(login.sent, { kind: 'sms', hint: add.body.destination.hint });
  assert.equal(provider.calls.length, 1, 'texted without asking: it is the only way in');
  assert.ok(page.visible('pane-otp'));
  assert.equal(page.text('otp-sent'), `We sent a code to ${add.body.destination.hint}.`);
  assert.ok(page.visible('otp-resend'), 'the destination was matched, so it can be sent again');

  await page.click('otp-resend');
  await settle(page);
  const again = calls(page, 'POST', '/api/auth/mfa/send')[0];
  assert.equal(again.status, 200, JSON.stringify(again.response));
  assert.deepEqual(again.body, { token: login.token, destination_id: add.body.destination.id });
  assert.equal(provider.calls.length, 2);
  page.fill('otp', lastCodeSent(provider));
  await page.submit('form-otp');
  await settle(page);
  const otp = calls(page, 'POST', '/api/auth/mfa/otp')[0];
  assert.equal(otp.status, 200, JSON.stringify(otp.response));
  assert.equal(otp.body.token, again.response.token, 'the new token, bound to the destination');
  assert.ok(page.visible('pane-enroll'), 'signed in; a texted code is not a strong factor, so the prompt follows');
  noFailures(page);
});

await run();
