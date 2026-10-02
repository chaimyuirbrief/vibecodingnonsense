// public/invite.html + js/invite.js — accepting an invitation (CONTRACTS §8.4, D11).

import { test, assert, run } from '../helpers/t.js';
import { loadPage, reply } from '../helpers/dom.js';

const ORIGIN = 'https://staff.example.com';
const TOKEN = 'abc.DEF_ghi-123';
const INFO = { email: 'sam@acme.com', full_name: 'Sam Example', org_name: 'Acme Inc.', expires_at: '2026-10-09T12:00:00Z' };
const DONE = { ok: true, user: { id: 2 }, pinned: null, enroll_prompt: true, next: '/', streak: null };

async function open({ token = TOKEN, fetch = {} } = {}) {
  const url = token === null ? `${ORIGIN}/invite` : `${ORIGIN}/invite?token=${encodeURIComponent(token)}`;
  return loadPage('invite.html', {
    url,
    fetch: {
      [`GET /api/invite/${encodeURIComponent(TOKEN)}`]: reply(200, INFO),
      'POST /api/fp': reply(200, { ok: true }),
      'GET /api/auth/whoami': reply(200, { authenticated: true }),
      ...fetch,
    },
  });
}

test('a valid link shows who it is for, prefills the name, and reports a fingerprint', async () => {
  const page = await open();
  assert.ok(page.visible('pane-form'));
  assert.ok(!page.visible('pane-invalid'));
  assert.ok(!page.visible('pane-loading'));
  assert.equal(page.text('invite-email'), 'sam@acme.com');
  assert.equal(page.text('invite-org'), 'Acme Inc.');
  assert.ok(page.visible('invite-org-line'));
  assert.equal(page.text('org-name'), 'Acme Inc.');
  assert.match(page.text('invite-expires'), /2026/);
  assert.equal(page.$('full_name').value, 'Sam Example');
  assert.equal(page.document.activeElement, page.$('password'));
  assert.equal(page.requests('/api/fp').length, 1);
  assert.equal(page.requests('/api/invite/')[0].url, `/api/invite/${encodeURIComponent(TOKEN)}`);
  assert.ok(page.visible('privacy'), 'the default notice shows');
  assert.deepEqual(page.calls.unmatched, []);
  page.dispose();
});

test('the token is URL-encoded into the lookup path', async () => {
  const weird = 'a/b?c=d#e';
  const page = await open({ token: weird, fetch: { [`GET /api/invite/${encodeURIComponent(weird)}`]: reply(200, INFO) } });
  assert.equal(page.requests('/api/invite/')[0].path, `/api/invite/${encodeURIComponent(weird)}`);
  assert.ok(page.visible('pane-form'));
  page.dispose();
});

test('no token → a clear message, no form, no lookup', async () => {
  const page = await open({ token: null });
  assert.ok(page.visible('pane-invalid'));
  assert.ok(!page.visible('pane-form'));
  assert.match(page.text('invalid-detail'), /full link/);
  assert.equal(page.requests('/api/invite/').length, 0);
  page.dispose();
});

test('invalid or expired → a clear message and NO form', async () => {
  for (const r of [reply(404, { error: 'Not found.' }), reply(410, { error: 'Expired.' })]) {
    const page = await open({ fetch: { [`GET /api/invite/${encodeURIComponent(TOKEN)}`]: r } });
    assert.ok(page.visible('pane-invalid'));
    assert.ok(!page.visible('pane-form'));
    assert.match(page.text('pane-invalid'), /expired, been used already, or been replaced/);
    assert.equal(page.text('title'), 'Invitation not valid');
    page.dispose();
  }
});

test('lookup rate-limited → still no form, and the reason is readable', async () => {
  const page = await open({ fetch: { [`GET /api/invite/${encodeURIComponent(TOKEN)}`]: reply(429, { retry_after: 600 }) } });
  assert.ok(!page.visible('pane-form'));
  assert.match(page.text('invalid-detail'), /Try again in 10 minutes/);
  page.dispose();
});

test('accept: posts token, password and name; confirms the cookie; goes to response.next', async () => {
  const page = await open({ fetch: { 'POST /api/invite/accept': reply(200, { ...DONE, next: '/account?pin=mfa_enroll', pinned: 'mfa_enroll' }) } });
  page.fill('full_name', 'Sam Q Example');
  page.fill('password', 'harbour lantern meadow 7');
  page.fill('confirm', 'harbour lantern meadow 7');
  await page.submit('form-invite');
  assert.deepEqual(page.requests('/api/invite/accept')[0].body, { token: TOKEN, password: 'harbour lantern meadow 7', full_name: 'Sam Q Example' });
  assert.equal(page.requests('/api/auth/whoami').length, 1);
  assert.deepEqual(page.calls.nav, [{ type: 'replace', url: '/account?pin=mfa_enroll' }]);
  page.dispose();
});

test('accept without next → "/"', async () => {
  const page = await open({ fetch: { 'POST /api/invite/accept': reply(200, { ok: true }) } });
  page.fill('password', 'harbour lantern meadow 7');
  page.fill('confirm', 'harbour lantern meadow 7');
  await page.submit('form-invite');
  assert.deepEqual(page.calls.nav, [{ type: 'replace', url: '/' }]);
  page.dispose();
});

test('client checks stop a bad submit: mismatch, too short, the email as password', async () => {
  for (const [pw, confirm, errId] of [
    ['harbour lantern meadow 7', 'harbour lantern meadow 8', 'confirm-error'],
    ['short', 'short', 'password-error'],
    ['sam@acme.com', 'sam@acme.com', 'password-error'],
  ]) {
    const page = await open({ fetch: { 'POST /api/invite/accept': reply(200, DONE) } });
    page.fill('password', pw);
    page.fill('confirm', confirm);
    await page.submit('form-invite');
    assert.ok(page.visible(errId), `${pw}/${confirm}`);
    assert.equal(page.requests('/api/invite/accept').length, 0);
    page.dispose();
  }
});

test('the link dying mid-form (404 on accept) → the invalid message', async () => {
  const page = await open({ fetch: { 'POST /api/invite/accept': reply(404, { error: 'Not found.' }) } });
  page.fill('password', 'harbour lantern meadow 7');
  page.fill('confirm', 'harbour lantern meadow 7');
  await page.submit('form-invite');
  assert.ok(page.visible('pane-invalid'));
  assert.ok(!page.visible('pane-form'));
  page.dispose();
});

test('other accept failures stay on the form with the sentence', async () => {
  const page = await open({ fetch: { 'POST /api/invite/accept': reply(400, { error: 'Choose a longer password.', field: 'password' }) } });
  page.fill('password', 'harbour lantern meadow 7');
  page.fill('confirm', 'harbour lantern meadow 7');
  await page.submit('form-invite');
  assert.ok(page.visible('pane-form'));
  assert.equal(page.text('password-error'), 'Choose a longer password.');
  page.dispose();
});

test('cookie refused after accepting → explained, no loop', async () => {
  const page = await open({ fetch: { 'POST /api/invite/accept': reply(200, DONE), 'GET /api/auth/whoami': reply(200, { authenticated: false }) } });
  page.fill('password', 'harbour lantern meadow 7');
  page.fill('confirm', 'harbour lantern meadow 7');
  await page.submit('form-invite');
  assert.ok(page.visible('pane-cookie'));
  assert.deepEqual(page.calls.nav, []);
  page.dispose();
});

test('privacy notice follows the response when it names one', async () => {
  const on = await open({ fetch: { [`GET /api/invite/${encodeURIComponent(TOKEN)}`]: reply(200, { ...INFO, privacy_notice: 'Custom notice.' }) } });
  assert.equal(on.text('privacy-text'), 'Custom notice.');
  on.dispose();
  const off = await open({ fetch: { [`GET /api/invite/${encodeURIComponent(TOKEN)}`]: reply(200, { ...INFO, privacy_notice: null }) } });
  assert.ok(!off.visible('privacy'));
  off.dispose();
});

test('a hostile name or email is shown as text, never parsed', async () => {
  const page = await open({ fetch: { [`GET /api/invite/${encodeURIComponent(TOKEN)}`]: reply(200, { ...INFO, email: '<img src=x onerror=alert(1)>@x.y', org_name: '<b>Org</b>' }) } });
  assert.equal(page.text('invite-email'), '<img src=x onerror=alert(1)>@x.y');
  assert.equal(page.$('invite-email').children.length, 0);
  assert.equal(page.text('invite-org'), '<b>Org</b>');
  page.dispose();
});

await run();
