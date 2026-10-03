// public/setup.html + js/setup.js — first-run bootstrap (CONTRACTS §8.4).

import { test, assert, run } from '../helpers/t.js';
import { loadPage, reply } from '../helpers/dom.js';

const ORIGIN = 'https://staff.example.com';
const SIGNED_IN = { ok: true, user: { id: 1 }, pinned: 'mfa_enroll', enroll_prompt: false, next: '/account?pin=mfa_enroll', streak: null };

async function open(fetch = {}) {
  return loadPage('setup.html', {
    url: `${ORIGIN}/setup`,
    fetch: {
      'GET /api/setup/status': reply(200, { needed: true, org_name: 'Acme Inc.' }),
      'GET /api/auth/whoami': reply(200, { authenticated: true }),
      ...fetch,
    },
  });
}

function fillValid(page, overrides = {}) {
  const v = { setup_key: 'k'.repeat(40), full_name: 'Ada Admin', email: 'ada@acme.com', password: 'violet tractor sunrise 42', confirm: 'violet tractor sunrise 42', ...overrides };
  for (const [id, value] of Object.entries(v)) page.fill(id, value);
}

test('needed: the form is shown with the org name, focus on the key', async () => {
  const page = await open();
  assert.ok(page.visible('pane-form'));
  assert.ok(!page.visible('pane-done'));
  assert.equal(page.text('org-name'), 'Acme Inc.');
  assert.equal(page.document.activeElement, page.$('setup_key'));
  assert.equal(page.$('setup_key').type, 'password');
  assert.equal(page.$('password').getAttribute('autocomplete'), 'new-password');
  assert.deepEqual(page.calls.unmatched, []);
  page.dispose();
});

test('happy path: posts exactly the four fields, confirms the cookie, goes to the enrolment pin', async () => {
  const page = await open({ 'POST /api/setup': reply(200, SIGNED_IN) });
  fillValid(page, { email: '  ada@acme.com ', full_name: ' Ada Admin ' });
  await page.submit('form-setup');
  assert.deepEqual(page.requests('/api/setup', 'POST')[0].body, { setup_key: 'k'.repeat(40), email: 'ada@acme.com', full_name: 'Ada Admin', password: 'violet tractor sunrise 42' });
  assert.equal(page.requests('/api/auth/whoami').length, 1);
  assert.deepEqual(page.calls.nav, [{ type: 'replace', url: '/account?pin=mfa_enroll' }]);
  assert.deepEqual(page.calls.nav.filter((n) => n.type === 'form'), []);
  page.dispose();
});

test('without response.next it still lands on /account?pin=mfa_enroll; an off-site next is refused', async () => {
  for (const next of [undefined, '//evil.example/x']) {
    const page = await open({ 'POST /api/setup': reply(200, { ...SIGNED_IN, next }) });
    fillValid(page);
    await page.submit('form-setup');
    assert.deepEqual(page.calls.nav, [{ type: 'replace', url: '/account?pin=mfa_enroll' }], String(next));
    page.dispose();
  }
});

test('already set up → a clear message, no form', async () => {
  for (const status of [reply(200, { needed: false, org_name: 'Acme' }), reply(404, { error: 'Not found.' }), reply(403, null)]) {
    const page = await open({ 'GET /api/setup/status': status });
    assert.ok(page.visible('pane-done'));
    assert.ok(!page.visible('pane-form'));
    page.dispose();
  }
});

test('status unreachable: the form stays, with a warning', async () => {
  const page = await open({ 'GET /api/setup/status': reply(200, null, { networkError: true }) });
  assert.ok(page.visible('pane-form'));
  assert.ok(page.visible('status-error'));
  page.dispose();
});

test('client checks: short password, mismatch, bad email, missing key — nothing is sent', async () => {
  const cases = [
    [{ password: 'short', confirm: 'short' }, 'password-error', /at least 12 characters/],
    [{ confirm: 'something else entirely' }, 'confirm-error', /don’t match/],
    [{ email: 'not-an-email' }, 'email-error', /valid email/],
    [{ setup_key: '   ' }, 'setup_key-error', /setup key/],
    [{ full_name: '' }, 'full_name-error', /your name/],
    [{ password: 'ada@acme.com', confirm: 'ada@acme.com' }, 'password-error', /email address/],
  ];
  for (const [overrides, errId, re] of cases) {
    const page = await open({ 'POST /api/setup': reply(200, SIGNED_IN) });
    fillValid(page, overrides);
    await page.submit('form-setup');
    assert.ok(page.visible(errId), `${errId} for ${JSON.stringify(overrides)}`);
    assert.match(page.text(errId), re);
    assert.equal(page.$(errId.replace('-error', '')).getAttribute('aria-invalid'), 'true');
    assert.equal(page.requests('/api/setup', 'POST').length, 0);
    page.dispose();
  }
});

test('password strength hint updates as you type', async () => {
  const page = await open();
  page.fill('password', 'abc');
  assert.match(page.text('password-hint'), /9 more characters to go/);
  assert.equal(page.$('password-meter').dataset.score, '0');
  page.fill('password', 'violet tractor sunrise 42');
  assert.match(page.text('password-hint'), /^(Good|Strong)\./);
  page.dispose();
});

test('server refusals: wrong key clears the key; a field error lands on its field; 429 is readable', async () => {
  const p1 = await open({ 'POST /api/setup': reply(403, { error: 'That setup key is not right.' }) });
  fillValid(p1);
  await p1.submit('form-setup');
  assert.equal(p1.text('setup-error'), 'That setup key is not right.');
  assert.equal(p1.$('setup_key').value, '');
  assert.deepEqual(p1.calls.nav, []);
  p1.dispose();

  const p2 = await open({ 'POST /api/setup': reply(400, { error: 'That email address is not valid.', field: 'email' }) });
  fillValid(p2);
  await p2.submit('form-setup');
  assert.equal(p2.text('email-error'), 'That email address is not valid.');
  assert.ok(!p2.visible('setup-error'));
  p2.dispose();

  const p3 = await open({ 'POST /api/setup': reply(429, { retry_after: 3600 }) });
  fillValid(p3);
  await p3.submit('form-setup');
  assert.equal(p3.text('setup-error'), 'Too many attempts. Try again in about 1 hour.');
  p3.dispose();
});

test('cookie refused after setup → explained, no redirect loop', async () => {
  const page = await open({ 'POST /api/setup': reply(200, SIGNED_IN), 'GET /api/auth/whoami': reply(200, { authenticated: false }) });
  fillValid(page);
  await page.submit('form-setup');
  assert.ok(page.visible('pane-cookie'));
  assert.ok(!page.visible('pane-form'));
  assert.deepEqual(page.calls.nav, []);
  page.dispose();
});

await run();
