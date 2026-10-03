// Session plumbing across the real pages and API: a session that dies under
// an open page (401 → whoami → /login?next=…), signing out from the top bar,
// the account page's own sessions, devices and authenticator controls, and
// the "this browser" section after the login page really reported a
// fingerprint.

import { test, assert, run } from '../helpers/t.js';
import { byText } from '../helpers/dom.js';
import { openLive, apiErrors, lastNav, settle } from '../helpers/live.js';
import { freshEnv, bootstrap, makeUser, client, stepUp, signIn, nextTotp, count, OWNER_IP, PASSWORD, MINUTE } from '../helpers/flows.js';

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
  assert.ok(dlg, `a dialog for “${label}”`);
  await page.click(byText(dlg, '.modal-actions button', label));
  await settle(page);
}

test('a session ended elsewhere: the next action asks whoami and goes to /login?next=…', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const u = await makeUser(env, owner.client);
  const page = await openLive(u.client, '/account');
  await settle(page);
  await stepUp(env, owner.client);
  assert.equal((await owner.client.post(`/api/admin/users/${u.user.id}/logout`, {})).status, 200);
  page.fill('profile-name', 'Renamed Person');
  await page.submit('profile-form');
  await settle(page);
  assert.equal(calls(page, 'PATCH', '/api/me')[0].status, 401);
  assert.equal(calls(page, 'GET', '/api/auth/whoami')[0].response.authenticated, false);
  assert.deepEqual(lastNav(page), { type: 'replace', url: '/login?next=%2Faccount' });
  assert.ok(!page.visible('profile-error'), 'no error sentence on the way out');
  const login = await openLive(u.client, lastNav(page).url);
  assert.equal(login.served.file, 'login.html');
  login.dispose();
});

test('sign out from the top bar ends the session and lands on the sign-in page', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const page = await openLive(owner.client, '/');
  await settle(page);
  const btn = page.document.querySelector('.topbar button[aria-label="Sign out"]');
  assert.ok(btn);
  await page.click(btn);
  await settle(page);
  assert.equal(calls(page, 'POST', '/api/auth/logout')[0].status, 200);
  assert.deepEqual(lastNav(page), { type: 'replace', url: '/login' });
  assert.equal((await owner.client.get('/api/me')).status, 401);
});

test('account: sign out one other session, then all the others; forget another device', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  // Two more browsers for the owner, both on the office network.
  const b2 = client(env, { ip: OWNER_IP });
  const b3 = client(env, { ip: OWNER_IP });
  for (const b of [b2, b3]) assert.equal((await signIn(env, b, owner.user.email, owner.password, { totpSecret: owner.totpSecret })).status, 200);
  const page = await openLive(owner.client, '/account');
  await settle(page);
  const sessions = calls(page, 'GET', '/api/me/sessions')[0].response.sessions;
  assert.equal(sessions.length, 3);
  assert.equal(page.document.querySelectorAll('#session-list .item-row').length, 3);
  const other = page.document.querySelectorAll('#session-list .item-row').find((li) => byText(li, 'button', 'Sign out'));
  await page.click(byText(other, 'button', 'Sign out'));
  await settle(page);
  assert.equal(calls(page, 'DELETE', `/api/me/sessions/${other.dataset.ref}`)[0].status, 200);
  assert.equal(page.document.querySelectorAll('#session-list .item-row').length, 2);
  await page.click('sessions-others');
  await confirmWith(page, 'Sign out others');
  const r = calls(page, 'POST', '/api/me/sessions/revoke-others')[0];
  assert.equal(r.status, 200);
  assert.equal(r.response.revoked, 1);
  assert.ok(byText(page.document, '.toast', 'Signed out of 1 other session.'));
  assert.equal(page.document.querySelectorAll('#session-list .item-row').length, 1);
  assert.ok(!page.visible('sessions-others'));

  // Forget b2's device: its trust in this account goes.
  const devices = calls(page, 'GET', '/api/me/devices').at(-1).response.devices;
  const notHere = devices.find((d) => !d.current);
  assert.ok(notHere);
  const row = page.document.querySelector(`#device-list .item-row[data-device-id="${notHere.id}"]`);
  await page.click(byText(row, 'button', 'Forget'));
  await confirmWith(page, 'Forget device');
  assert.equal(calls(page, 'DELETE', `/api/me/devices/${notHere.id}`)[0].status, 200);
  assert.equal(count(env, 'SELECT COUNT(*) FROM device_users WHERE user_id = ? AND device_id = ?', owner.user.id, notHere.id), 0);
  noFailures(page);
});

test('account: removing the authenticator app — step-up through the dialog, refused (visibly) while it is the last factor, then removed', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const u = await makeUser(env, owner.client, { totp: true });
  env.__advance(20 * MINUTE);
  const page = await openLive(u.client, '/account');
  await settle(page);
  assert.ok(page.visible('totp-remove'));
  await page.click('totp-remove');
  await confirmWith(page, 'Remove app');
  const dlg = page.document.querySelector('dialog.modal-stepup');
  assert.ok(dlg);
  page.fill('stepup-code', await nextTotp(env, u.totpSecret));
  await page.submit(dlg.querySelector('form'));
  await settle(page);
  let del = calls(page, 'DELETE', '/api/me/mfa/totp');
  assert.deepEqual(del.map((c) => c.status), [403, 409]);
  assert.equal(del[1].response.code, 'last_factor');
  assert.ok(page.visible('totp-action-error'), 'the refusal is on screen, not in the hidden setup panel');
  assert.equal(page.text('totp-action-error'), del[1].response.error);
  assert.equal(count(env, 'SELECT COUNT(*) FROM user_totp WHERE user_id = ?', u.user.id), 1);

  // With a passkey as well, the app can go.
  const { SoftAuthenticator } = await import('../helpers/authenticator.js');
  const a = new SoftAuthenticator({ origin: env.ORIGIN, rpId: env.RP_ID });
  const o = await u.client.post('/api/me/mfa/passkey/options', {});
  assert.equal((await u.client.post('/api/me/mfa/passkey/register', { credential: await a.create(o.body), label: 'Key' })).status, 200);
  await page.click('totp-remove');
  await confirmWith(page, 'Remove app');
  del = calls(page, 'DELETE', '/api/me/mfa/totp');
  assert.equal(del.length, 3);
  assert.equal(del[2].status, 200, 'the step-up is still fresh');
  assert.ok(!page.visible('totp-action-error'), 'the old refusal is cleared');
  assert.equal(count(env, 'SELECT COUNT(*) FROM user_totp WHERE user_id = ?', u.user.id), 0);
  assert.match(page.text('totp-state'), /Not set up/);
  assert.ok(page.visible('totp-start'));
  noFailures(page, ['DELETE /api/me/mfa/totp']);
});

test('account “this browser”: the fingerprint the login page reported, its score and reasons, as the API explains them', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const u = await makeUser(env, owner.client);
  await u.client.post('/api/auth/logout', {});
  const login = await openLive(u.client, '/login');
  await settle(login);
  login.fill('identifier', u.user.email);
  login.fill('password', PASSWORD);
  await login.submit('form-password');
  await settle(login);
  assert.equal(calls(login, 'POST', '/api/fp')[0]?.status, 200, 'reported');
  const page = await openLive(u.client, '/account');
  await settle(page);
  const fp = calls(page, 'GET', '/api/me/fingerprint')[0].response;
  assert.ok(fp.fingerprint, 'the API has this browser');
  assert.equal(page.text(page.$('fp-score').querySelector('strong')), String(fp.risk.score));
  const flags = page.document.querySelectorAll('#fp-flags li');
  assert.equal(flags.length, fp.risk.flags.length);
  const sorted = [...fp.risk.flags].sort((a, b) => b.weight - a.weight);
  flags.forEach((li, i) => {
    assert.equal(li.dataset.flag, sorted[i].key);
    assert.equal(li.querySelector('span').textContent, sorted[i].reason);
  });
  const facts = Object.fromEntries(page.$('fp-facts').querySelectorAll('dt').map((dt) => [dt.textContent, dt.nextElementSibling.textContent]));
  assert.equal(facts['IP address'], fp.fingerprint.ip);
  assert.equal(facts.Country, fp.fingerprint.country);
  assert.equal(facts.Network, fp.fingerprint.as_org);
  assert.equal(facts['Time zone'], fp.fingerprint.tz);
  assert.equal(facts['Visitor id'], fp.fingerprint.visitor_id.slice(0, 12));
  assert.ok(page.visible('fp-notice'), 'the privacy notice from GET /api/me');
  noFailures(page);
});

await run();
