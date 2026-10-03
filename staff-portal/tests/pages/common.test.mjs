// public/js/common.js — the shared kit (CONTRACTS §10; A §7.5).

import { test, assert, run } from '../helpers/t.js';
import { loadPage, importFresh, reply, drain } from '../helpers/dom.js';

const ORIGIN = 'https://staff.example.com';

// A page with the kit loaded but no page script running. `page` names which
// HTML supplies the body (and so body[data-page]).
async function kit({ page = 'pending.html', url = `${ORIGIN}/account?tab=security`, fetch = {}, webauthn, navigator } = {}) {
  const p = await loadPage(page, { url, fetch, webauthn, navigator, import: false });
  const c = await importFresh('js/common.js');
  return { p, c };
}

// ------------------------------------------------------------ safeNext ----

test('safeNext: refuses everything that is not a same-origin path', async () => {
  const { p, c } = await kit();
  const refused = [
    'https://evil.example/x',
    '//evil.example/x',
    '//staff.example.com/admin',
    '/\\evil.example/x',
    '\\\\evil.example',
    '\\/evil.example',
    '/\t/evil.example',
    '/\n/evil.example',
    'javascript:alert(1)',
    'JaVaScRiPt:alert(1)',
    ' javascript:alert(1)',
    'java\tscript:alert(1)',
    'java\nscript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    'vbscript:msgbox(1)',
    'http://staff.example.com/admin',
    'https://staff.example.com.evil.example/',
    'https://staff.example.com@evil.example/',
    'https://user:pw@staff.example.com/admin',
    'https://staff.example.com:8443/admin',
    '/.//evil.example',
    '/..//evil.example',
    '/./\u0000/evil',
    ' /admin',
    '/admin ',
    'admin',
    '../admin',
    '?next=/x',
    '%2F%2Fevil.example',
    'mailto:a@b.c',
    '',
    'x'.repeat(3000),
    null,
    undefined,
    42,
    {},
    [],
    true,
    NaN,
  ];
  for (const raw of refused) assert.equal(c.safeNext(raw), '/', `should refuse ${JSON.stringify(raw)}`);
  assert.equal(c.safeNext('//evil.example', '/home'), '/home', 'custom fallback');
  p.dispose();
});

test('safeNext: keeps same-origin paths, query and hash', async () => {
  const { p, c } = await kit();
  assert.equal(c.safeNext('/admin'), '/admin');
  assert.equal(c.safeNext('/account?pin=mfa_enroll'), '/account?pin=mfa_enroll');
  assert.equal(c.safeNext('/admin?tab=people#audit'), '/admin?tab=people#audit');
  assert.equal(c.safeNext('https://staff.example.com/admin?x=1'), '/admin?x=1', 'our own origin, absolute');
  assert.equal(c.safeNext('/a/../b'), '/b', 'normalised');
  assert.equal(c.safeNext('/'), '/');
  p.dispose();
});

test('safeNext: the http: downgrade check is relative to the CURRENT origin', async () => {
  const { p, c } = await kit({ url: 'http://localhost:8787/login' });
  assert.equal(c.safeNext('http://localhost:8787/admin'), '/admin', 'same origin in local dev');
  assert.equal(c.safeNext('https://localhost:8787/admin'), '/', 'different scheme is a different origin');
  p.dispose();
});

test('go() routes through safeNext; param() reads the query', async () => {
  const { p, c } = await kit({ url: `${ORIGIN}/login?next=%2Fadmin&x=1` });
  assert.equal(c.param('next'), '/admin');
  assert.equal(c.param('nope'), null);
  c.go('//evil.example');
  c.go('/admin', { replace: true });
  assert.deepEqual(p.calls.nav, [
    { type: 'assign', url: '/' },
    { type: 'replace', url: '/admin' },
  ]);
  p.dispose();
});

// ------------------------------------------------------------------- h ----

test('h(): attributes, class, for, data-*, aria-*, booleans, listeners and children', async () => {
  const { p, c } = await kit();
  let clicks = 0;
  const el = c.h(
    'button',
    { class: ['btn', null, 'btn-primary'], id: 'b1', 'data-kind': 'passkey', 'aria-label': 'Go', disabled: false, hidden: true, type: 'button', onclick: () => clicks++, title: null },
    'Hello ',
    ['nested ', ['deep ', null], false],
    7,
    undefined,
  );
  assert.equal(el.tagName, 'BUTTON');
  assert.equal(el.className, 'btn btn-primary');
  assert.equal(el.id, 'b1');
  assert.equal(el.dataset.kind, 'passkey');
  assert.equal(el.getAttribute('aria-label'), 'Go');
  assert.equal(el.hasAttribute('disabled'), false, 'false omits the attribute');
  assert.equal(el.hidden, true);
  assert.equal(el.hasAttribute('title'), false, 'null omits the attribute');
  assert.equal(el.textContent, 'Hello nested deep 7');
  assert.ok(el.childNodes.every((n) => n.nodeType === 3), 'strings become text nodes');
  p.document.body.appendChild(el);
  el.hidden = false;
  el.click();
  assert.equal(clicks, 1, 'on* functions become listeners');
  const label = c.h('label', { for: 'b1' }, 'Label');
  assert.equal(label.getAttribute('for'), 'b1');
  const input = c.h('input', { value: 'x', checked: true, readonly: true, maxlength: 5 });
  assert.equal(input.value, 'x');
  assert.equal(input.checked, true);
  assert.equal(input.getAttribute('maxlength'), '5');
  const withDataset = c.h('div', { dataset: { userId: 4 } });
  assert.equal(withDataset.getAttribute('data-user-id'), '4');
  assert.equal(c.h('p', 'just text').textContent, 'just text', 'a string second argument is a child');
  p.dispose();
});

test('h(): markup in strings stays text; style and HTML keys are refused', async () => {
  const { p, c } = await kit();
  const evil = '<img src=x onerror=alert(1)>';
  const el = c.h('p', null, evil);
  assert.equal(el.textContent, evil);
  assert.equal(el.children.length, 0, 'no element was parsed out of the string');
  assert.throws(() => c.h('p', { style: 'color:red' }), /not allowed/);
  assert.throws(() => c.h('p', { innerHTML: '<b>x</b>' }), /not allowed/);
  assert.throws(() => c.h('p', { onclick: 'alert(1)' }), /must be a function/);
  p.dispose();
});

test('svg() and icon() build SVG-namespaced nodes', async () => {
  const { p, c } = await kit();
  const s = c.svg('svg', { class: 'icon', viewBox: '0 0 24 24' }, c.svg('path', { d: 'M0 0' }));
  assert.equal(s.namespaceURI, 'http://www.w3.org/2000/svg');
  assert.equal(s.getAttribute('class'), 'icon');
  assert.equal(s.getAttribute('viewBox'), '0 0 24 24');
  assert.equal(s.firstChild.namespaceURI, 'http://www.w3.org/2000/svg');
  const i = c.icon('passkey');
  assert.equal(i.getAttribute('aria-hidden'), 'true');
  const labelled = c.icon('alert', { label: 'Warning' });
  assert.equal(labelled.getAttribute('role'), 'img');
  assert.equal(labelled.getAttribute('aria-label'), 'Warning');
  const f1 = c.flameIcon();
  const f2 = c.flameIcon({ out: true });
  const gid = (f) => f.querySelector('linearGradient').getAttribute('id');
  assert.notEqual(gid(f1), gid(f2), 'each flame has its own gradient id');
  assert.ok(f2.classList.contains('is-out'));
  assert.equal(f1.querySelector('.flame-body').getAttribute('fill'), `url(#${gid(f1)})`);
  p.dispose();
});

// ----------------------------------------------------------------- api ----

test('api(): JSON in and out, same-origin credentials', async () => {
  const { p, c } = await kit({ fetch: { 'POST /api/me/password': reply(200, { ok: true }), 'GET /api/me': reply(200, { user: { id: 1 } }), 'DELETE /api/me/sessions/x': reply(204, null) } });
  assert.deepEqual(await c.api('GET', '/api/me'), { user: { id: 1 } });
  assert.deepEqual(await c.api('POST', '/api/me/password', { current: 'a', next: 'b' }), { ok: true });
  assert.deepEqual(await c.api('DELETE', '/api/me/sessions/x'), {}, '204 → {}');
  const [get, post] = p.calls.fetch;
  assert.equal(get.init.credentials, 'same-origin');
  assert.equal(get.init.body, undefined);
  assert.equal(post.headers['content-type'], 'application/json');
  assert.deepEqual(post.body, { current: 'a', next: 'b' });
  p.dispose();
});

test('api(): errors become ApiError with a sentence', async () => {
  const { p, c } = await kit({
    fetch: {
      'POST /api/a': reply(400, { error: 'Name is required.', field: 'full_name' }),
      'POST /api/b': reply(429, { error: 'Too many attempts. Try again later.', retry_after: 300 }),
      'POST /api/c': reply(500, 'not json'),
      'POST /api/d': reply(200, null, { networkError: true }),
      'POST /api/e': reply(429, { retry_after: 20 }),
      'POST /api/f': reply(429, { retry_after: 7200 }),
    },
  });
  const err = async (path) => {
    try {
      await c.api('POST', path, {});
    } catch (e) {
      return e;
    }
    throw new Error('expected a throw');
  };
  const a = await err('/api/a');
  assert.ok(a instanceof c.ApiError);
  assert.equal(a.status, 400);
  assert.equal(a.message, 'Name is required.');
  assert.equal(a.body.field, 'full_name');
  assert.equal((await err('/api/b')).message, 'Too many attempts. Try again in 5 minutes.');
  assert.equal((await err('/api/e')).message, 'Too many attempts. Try again in 20 seconds.');
  assert.equal((await err('/api/f')).message, 'Too many attempts. Try again in about 2 hours.');
  const cErr = await err('/api/c');
  assert.equal(cErr.status, 500);
  assert.match(cErr.message, /went wrong/);
  const d = await err('/api/d');
  assert.equal(d.status, 0);
  assert.match(d.message, /couldn’t reach the server/);
  assert.equal(c.errorMessage(d), d.message);
  assert.equal(c.errorMessage('plain'), 'plain');
  assert.equal(c.errorMessage(null), '');
  p.dispose();
});

test('api(): 401 on a session route sends the user to /login?next=<here>', async () => {
  const { p, c } = await kit({ fetch: { 'GET /api/me': reply(401, { error: 'Signed out.' }), 'GET /api/auth/whoami': reply(200, { authenticated: false }) } });
  let e;
  try {
    await c.api('GET', '/api/me');
  } catch (err) {
    e = err;
  }
  assert.equal(e.status, 401);
  assert.equal(e.redirected, true);
  assert.deepEqual(p.calls.nav, [{ type: 'replace', url: '/login?next=%2Faccount%3Ftab%3Dsecurity' }]);
  p.dispose();
});

test('api(): a 401 while still signed in (wrong current password) is an error, not a redirect', async () => {
  const { p, c } = await kit({ fetch: { 'POST /api/me/password': reply(401, { error: 'Your current password is wrong.' }), 'GET /api/auth/whoami': reply(200, { authenticated: true }) } });
  await assert.rejects(c.api('POST', '/api/me/password', { current: 'x', next: 'y' }), (e) => e.status === 401 && !e.redirected && e.message === 'Your current password is wrong.');
  assert.deepEqual(p.calls.nav, []);
  p.dispose();
});

test('api(): 401 never redirects on the login page itself, nor for non-session routes', async () => {
  const { p, c } = await kit({ page: 'login.html', url: `${ORIGIN}/login`, fetch: { 'GET /api/me': reply(401, {}), 'GET /api/auth/whoami': reply(200, { authenticated: false }) } });
  await assert.rejects(c.api('GET', '/api/me'), (e) => e.status === 401 && !e.redirected);
  assert.deepEqual(p.calls.nav, []);
  p.dispose();
  const k = await kit({ fetch: { 'POST /api/auth/mfa/code': reply(401, { error: 'That code didn’t work.' }), 'GET /api/me': reply(401, {}), 'GET /api/auth/whoami': reply(200, { authenticated: false }) } });
  await assert.rejects(k.c.api('POST', '/api/auth/mfa/code', { token: 't', code: '1' }), (e) => e.message === 'That code didn’t work.');
  await assert.rejects(k.c.api('GET', '/api/me', undefined, { redirect: false }));
  assert.deepEqual(k.p.calls.nav, [], 'auth routes and redirect:false never navigate');
  k.p.dispose();
});

test('api(): 403 step_up_required opens the step-up dialog, then retries ONCE', async () => {
  const { p, c } = await kit({
    fetch: {
      'DELETE /api/me/mfa/totp': [reply(403, { error: 'Confirm it’s you to continue.', step_up_required: true }), reply(200, { ok: true })],
      'GET /api/me/step-up': reply(200, { methods: ['totp', 'backup'], destinations: [] }),
      'POST /api/me/step-up/code': [reply(401, { error: 'That code didn’t work.' }), reply(200, { ok: true })],
      'GET /api/auth/whoami': reply(200, { authenticated: true }),
    },
  });
  const pending = c.api('DELETE', '/api/me/mfa/totp');
  await drain();
  const dlg = p.document.querySelector('dialog.modal');
  assert.ok(dlg && dlg.hasAttribute('open'), 'dialog shown');
  assert.equal(p.text('stepup-title'), 'Confirm it’s you');
  assert.ok(!p.$('stepup-passkey'), 'no passkey button: the account has none');
  const form = dlg.querySelector('form');
  p.fill('stepup-code', '000000');
  form.requestSubmit();
  await drain();
  assert.ok(p.visible('stepup-error'), 'wrong code shown in the dialog');
  assert.equal(p.text('stepup-error'), 'That code didn’t work.');
  p.fill('stepup-code', '123456');
  form.requestSubmit();
  assert.deepEqual(await pending, { ok: true });
  assert.ok(!dlg.isConnected, 'dialog removed');
  const calls = p.calls.fetch.map((r) => `${r.method} ${r.path}`);
  assert.deepEqual(calls, ['DELETE /api/me/mfa/totp', 'GET /api/me/step-up', 'POST /api/me/step-up/code', 'GET /api/auth/whoami', 'POST /api/me/step-up/code', 'DELETE /api/me/mfa/totp']);
  assert.deepEqual(p.calls.nav, [], 'a wrong code never signs anyone out');
  assert.deepEqual(p.requests('/api/me/step-up/code')[1].body, { code: '123456' });
  p.dispose();
});

test('api(): a second step_up_required after the retry is an error, not a loop', async () => {
  const { p, c } = await kit({
    fetch: {
      'POST /api/admin/x': reply(403, { step_up_required: true, error: 'Confirm it’s you to continue.' }),
      'GET /api/me/step-up': reply(200, { methods: ['totp'], destinations: [] }),
      'POST /api/me/step-up/code': reply(200, { ok: true }),
    },
  });
  const pending = c.api('POST', '/api/admin/x', {});
  await drain();
  p.fill('stepup-code', '123456');
  p.document.querySelector('dialog form').requestSubmit();
  await assert.rejects(pending, (e) => e.status === 403);
  assert.equal(p.requests('/api/admin/x').length, 2, 'exactly one retry');
  assert.equal(p.requests('/api/me/step-up', 'GET').length, 1, 'one dialog');
  p.dispose();
});

test('stepUp(): Cancel resolves false and the original call fails', async () => {
  const { p, c } = await kit({
    fetch: {
      'POST /api/admin/y': reply(403, { step_up_required: true }),
      'GET /api/me/step-up': reply(200, { methods: ['totp'], destinations: [] }),
    },
  });
  const pending = c.api('POST', '/api/admin/y', {});
  const rejected = assert.rejects(pending, (e) => e.status === 403 && /Cancelled/.test(e.message));
  await drain();
  await p.click('stepup-cancel');
  await rejected;
  assert.equal(p.requests('/api/admin/y').length, 1, 'no retry after cancel');
  assert.equal(p.document.querySelector('dialog'), null);
  p.dispose();
});

test('stepUp(): passkey, and a sent code, both satisfy it', async () => {
  const assertion = { id: 'x', rawId: new Uint8Array([0xfb, 0xff]).buffer, type: 'public-key', response: { clientDataJSON: new Uint8Array([1]).buffer, authenticatorData: new Uint8Array([2]).buffer, signature: new Uint8Array([3]).buffer, userHandle: null } };
  const k = await kit({
    webauthn: { get: async () => assertion },
    fetch: {
      'GET /api/me/step-up': reply(200, { methods: ['passkey', 'sms'], destinations: [{ id: 3, kind: 'sms', hint: '•••• 9876' }] }),
      'POST /api/me/step-up/passkey/options': reply(200, { challenge: 'AQID', allowCredentials: [] }),
      'POST /api/me/step-up/passkey/verify': reply(200, { ok: true }),
    },
  });
  const r1 = k.c.stepUp();
  await drain();
  assert.ok(k.p.$('stepup-passkey'), 'passkey offered when the browser supports it');
  await k.p.click('stepup-passkey');
  assert.equal(await r1, true);
  assert.equal(k.p.requests('/api/me/step-up/passkey/verify')[0].body.credential.rawId, '-_8');
  k.p.dispose();

  const s = await kit({
    fetch: {
      'GET /api/me/step-up': reply(200, { methods: ['sms'], destinations: [{ id: 3, kind: 'sms', hint: '•••• 9876' }] }),
      'POST /api/me/step-up/send': reply(200, { sent: { kind: 'sms', hint: '•••• 9876' } }),
      'POST /api/me/step-up/otp': reply(200, { ok: true }),
    },
  });
  const r2 = s.c.stepUp();
  await drain();
  const sendBtn = s.p.document.querySelectorAll('dialog button').find((b) => /Text a code/.test(b.textContent));
  assert.ok(sendBtn, 'a send-a-code button per destination');
  assert.equal(s.p.requests('/api/me/step-up/send').length, 0, 'nothing sent until clicked');
  sendBtn.click();
  await drain();
  assert.match(s.p.document.querySelector('dialog').textContent, /We sent a code to •••• 9876\./);
  s.p.fill('stepup-otp', '123456');
  s.p.$('stepup-otp').closest('form').requestSubmit();
  assert.equal(await r2, true);
  assert.deepEqual(s.p.requests('/api/me/step-up/otp')[0].body, { code: '123456', destination_id: 3 });
  s.p.dispose();
});

test('stepUp(): passkey-only account in a browser without WebAuthn gets an explanation', async () => {
  const { p, c } = await kit({ fetch: { 'GET /api/me/step-up': reply(200, { methods: ['passkey'], destinations: [] }) } });
  const r = c.stepUp();
  await drain();
  const dlg = p.document.querySelector('dialog');
  assert.match(dlg.textContent, /can’t use passkeys/);
  assert.match(dlg.textContent, /phone number or email/);
  assert.ok(!p.$('stepup-passkey') && !p.$('stepup-code'));
  await p.click('stepup-cancel');
  assert.equal(await r, false);
  p.dispose();
});

test('confirmSignedIn(): true, false (cookie refused / 401) or null (cannot tell)', async () => {
  for (const [r, want] of [
    [reply(200, { authenticated: true }), true],
    [reply(200, { authenticated: false }), false],
    [reply(401, { error: 'no' }), false],
    [reply(403, null), null],
    [reply(200, null, { networkError: true }), null],
  ]) {
    const { p, c } = await kit({ fetch: { 'GET /api/auth/whoami': r } });
    assert.equal(await c.confirmSignedIn(), want, JSON.stringify(r));
    assert.deepEqual(p.calls.nav, []);
    p.dispose();
  }
});

// ------------------------------------------------------------ feedback ----

test('showError / setFieldError / toast / busy', async () => {
  const { p, c } = await kit();
  const box = p.$('check-error');
  c.showError(box, new c.ApiError(400, { error: 'Nope.' }, 'Nope.'));
  assert.ok(p.visible(box) || box.hidden === false);
  assert.equal(box.textContent, 'Nope.');
  c.showError('check-error', null);
  assert.equal(box.hidden, true);
  c.showError(box, new c.ApiError(401, {}, 'x', { redirected: true }));
  assert.equal(box.hidden, true, 'a redirect is not shown as an error');

  const input = c.h('input', { id: 'nm' });
  p.document.body.appendChild(input);
  c.setFieldError(input, 'Enter your name.');
  assert.equal(input.getAttribute('aria-invalid'), 'true');
  assert.equal(p.text('nm-error'), 'Enter your name.');
  assert.match(input.getAttribute('aria-describedby'), /nm-error/);
  c.setFieldError(input, '');
  assert.equal(input.hasAttribute('aria-invalid'), false);
  assert.equal(p.$('nm-error').hidden, true);

  const t = c.toast('Saved.', 'success');
  assert.ok(t.classList.contains('toast-ok'));
  const region = p.$('toasts');
  assert.equal(region.getAttribute('role'), 'status');
  assert.equal(region.getAttribute('aria-live'), 'polite');
  assert.match(p.text('toasts'), /Saved\./);
  assert.ok(p.calls.timers.some((x) => x.delay === 5000), 'auto-dismiss timer');
  assert.equal(t.getAttribute('role'), null, 'a confirmation waits its turn in the polite region');
  const bad = c.toast('Second', 'danger');
  assert.equal(bad.getAttribute('role'), 'alert', 'a failure is announced at once (FE-6)');
  assert.equal(p.document.querySelectorAll('#toasts').length, 1, 'one region');
  await p.fireTimers(5000);
  assert.equal(region.children.length, 0, 'dismissed');

  const btn = c.h('button', { type: 'button' }, 'Go');
  let release;
  const work = c.busy(btn, new Promise((r) => (release = r)));
  assert.equal(btn.disabled, true);
  assert.equal(btn.getAttribute('aria-busy'), 'true');
  assert.ok(btn.classList.contains('is-busy'));
  release(5);
  assert.equal(await work, 5);
  assert.equal(btn.disabled, false);
  assert.equal(btn.hasAttribute('aria-busy'), false);
  await assert.rejects(c.busy(btn, async () => {
    throw new Error('x');
  }));
  assert.equal(btn.disabled, false, 'restored after a throw');
  p.dispose();
});

test('copyText: clipboard API, then the selection fallback', async () => {
  const a = await kit();
  assert.equal(await a.c.copyText('K7F3-9QX2'), true);
  assert.deepEqual(a.p.calls.clipboard, ['K7F3-9QX2']);
  a.p.dispose();
  const b = await kit({ navigator: { clipboard: { writeText: async () => Promise.reject(new Error('denied')) } } });
  assert.equal(await b.c.copyText('abc'), true);
  assert.deepEqual(b.p.calls.execCommand, ['copy']);
  assert.equal(b.p.document.querySelectorAll('textarea').length, 0, 'fallback textarea removed');
  b.p.dispose();
});

// ---------------------------------------------------------- formatting ----

test('formatting: dates in a time zone, relative times, hours, plurals', async () => {
  const { p, c } = await kit();
  const iso = '2026-03-01T12:00:00Z';
  assert.match(c.fmtDate(iso, 'America/New_York'), /Mar 1, 2026/);
  assert.match(c.fmtDateTime(iso, 'Asia/Tokyo'), /9:00\s?PM/);
  assert.match(c.fmtDateTime(iso, { tz: 'America/New_York' }), /7:00\s?AM/);
  assert.match(c.fmtTime(Date.parse(iso), 'UTC'), /12:00\s?PM/);
  assert.match(c.fmtDate(iso, 'Not/AZone'), /2026/, 'an unknown zone falls back, never throws');
  for (const junk of [null, undefined, '', 'yesterday-ish', NaN, {}, []]) assert.equal(c.fmtDate(junk), '—');
  const now = Date.parse(iso);
  assert.equal(c.fmtRelative(now - 5 * 60000, { now }), '5 minutes ago');
  assert.equal(c.fmtRelative(now + 3 * 3600000, { now }), 'in 3 hours');
  assert.equal(c.fmtRelative(now - 86400000, { now }), 'yesterday');
  assert.equal(c.fmtRelative(now - 10000, { now }), 'just now');
  assert.equal(c.fmtHours(18.5), '18h 30m');
  assert.equal(c.fmtHours(0.4), '24m');
  assert.equal(c.fmtHours(50), '2d 2h');
  assert.equal(c.fmtHours(-1), '—');
  assert.equal(c.plural(1, 'day'), '1 day');
  assert.equal(c.plural(12, 'day'), '12 days');
  assert.equal(c.fmtNumber(1234567), '1,234,567');
  assert.equal(c.retryText(undefined), 'Try again later.');
  p.dispose();
});

test('passwordFeedback mirrors the server rules', async () => {
  const { p, c } = await kit();
  assert.equal(c.passwordFeedback('short').ok, false);
  assert.equal(c.passwordFeedback('').ok, false);
  assert.equal(c.passwordFeedback(null).ok, false);
  assert.equal(c.passwordFeedback('jane@acme.com', { email: 'jane@acme.com' }).ok, false, 'not the email');
  assert.equal(c.passwordFeedback('JANE@ACME.COM', { email: 'jane@acme.com' }).ok, false, 'case-insensitively');
  assert.equal(c.passwordFeedback('aaaaaaaaaaaaaaaa').ok, false, 'not one repeated character');
  assert.equal(c.passwordFeedback('x'.repeat(1025)).ok, false);
  const good = c.passwordFeedback('correct horse battery staple');
  assert.equal(good.ok, true);
  assert.ok(good.score >= 3);
  const weak = c.passwordFeedback('password1234');
  assert.equal(weak.ok, true, 'allowed by the server rules');
  assert.ok(weak.score <= 1, 'but flagged weak');
  p.dispose();
});

// ----------------------------------------------------------- builders ----

test('topBar(): brand, nav with aria-current, admin link only when allowed, streak chip, sign out', async () => {
  const { p, c } = await kit({ fetch: { 'POST /api/auth/logout': reply(200, { ok: true }) } });
  const bar = c.topBar({ user: { full_name: 'Jane Q Doe', email: 'jane@acme.com' }, active: 'account', orgName: 'Acme Inc.', streak: { current: 12, state: 'active' } });
  p.document.body.prepend(bar);
  assert.equal(bar.querySelector('.brand-name').textContent, 'Acme Inc.');
  const links = bar.querySelectorAll('.topnav-link');
  assert.deepEqual(links.map((a) => a.getAttribute('href')), ['/', '/account']);
  assert.equal(bar.querySelector('[aria-current=page]').textContent, 'Account');
  assert.equal(bar.querySelector('.avatar').textContent, 'JD');
  const chip = bar.querySelector('.topbar-streak');
  assert.equal(chip.getAttribute('aria-label'), 'Streak: 12 days');
  assert.equal(chip.querySelector('.num').textContent, '12');
  const adminBar = c.topBar({ user: null, active: 'admin', admin: true });
  assert.deepEqual(adminBar.querySelectorAll('.topnav-link').map((a) => a.getAttribute('href')), ['/', '/account', '/admin']);
  const lapsed = c.topBar({ streak: { current: 0, state: 'lapsed' } });
  assert.ok(lapsed.querySelector('.topbar-streak .flame').classList.contains('is-out'));
  assert.ok(!lapsed.querySelector('.brand .flame').classList.contains('is-out'), 'the brand flame never goes out');
  bar.querySelector('button[aria-label="Sign out"]').click();
  await drain();
  assert.equal(p.requests('/api/auth/logout', 'POST').length, 1);
  assert.deepEqual(p.calls.nav, [{ type: 'replace', url: '/login' }]);
  p.dispose();
});

test('emptyState, skeleton, badge, dataTable', async () => {
  const { p, c } = await kit();
  const e = c.emptyState({ title: 'No devices', body: 'Nothing has signed in yet.' });
  assert.ok(e.classList.contains('empty'));
  assert.equal(e.querySelector('.empty-title').textContent, 'No devices');
  assert.equal(c.skeleton(4).querySelectorAll('.skeleton-line').length, 4);
  assert.equal(c.skeleton('junk').querySelectorAll('.skeleton-line').length, 3);
  assert.equal(c.badge('Approved', 'ok').className, 'badge badge-ok');
  const t = c.dataTable({
    columns: [{ key: 'name', label: 'Name' }, { key: 'n', label: 'Sign-ins', num: true }, { key: 'x', label: 'Note', render: (r) => c.h('em', null, r.x) }],
    rows: [{ name: '<b>Jane</b>', n: 4, x: 'hi' }, { name: 'Sam', n: null, x: '' }],
  });
  const tds = t.querySelectorAll('td');
  assert.equal(tds[0].getAttribute('data-label'), 'Name');
  assert.equal(tds[0].textContent, '<b>Jane</b>', 'cells are text');
  assert.ok(tds[1].classList.contains('num'));
  assert.equal(tds[2].querySelector('em').textContent, 'hi');
  assert.equal(tds[4].textContent, '—', 'empty → dash');
  assert.ok(t.querySelector('table').classList.contains('table-cards'));
  assert.ok(c.dataTable({ columns: [], rows: [] }).classList.contains('empty'));
  p.dispose();
});

test('tabs(): click and arrow keys move selection and panels', async () => {
  const { p, c } = await kit();
  const root = c.h(
    'div',
    { class: 'tabs' },
    c.h('div', { role: 'tablist' }, c.h('button', { role: 'tab', id: 'tab-a', 'aria-controls': 'panel-a', type: 'button' }, 'A'), c.h('button', { role: 'tab', id: 'tab-b', 'aria-controls': 'panel-b', type: 'button' }, 'B')),
    c.h('div', { role: 'tabpanel', id: 'panel-a' }, 'a'),
    c.h('div', { role: 'tabpanel', id: 'panel-b' }, 'b'),
  );
  p.document.body.appendChild(root);
  const seen = [];
  c.tabs(root, { onChange: (id) => seen.push(id) });
  assert.equal(p.$('tab-a').getAttribute('aria-selected'), 'true');
  assert.equal(p.$('panel-b').hidden, true);
  await p.click('tab-b');
  assert.equal(p.$('tab-b').getAttribute('aria-selected'), 'true');
  assert.equal(p.$('panel-a').hidden, true);
  assert.equal(p.$('panel-b').hidden, false);
  await p.key('tab-b', 'ArrowRight');
  assert.equal(p.$('tab-a').getAttribute('aria-selected'), 'true', 'wraps around');
  assert.equal(p.document.activeElement, p.$('tab-a'));
  assert.deepEqual(seen, ['tab-b', 'tab-a']);
  p.dispose();
});

test('confirmDialog(): resolves true on confirm, false on cancel', async () => {
  const { p, c } = await kit();
  const yes = c.confirmDialog({ title: 'Disable Jane?', body: 'She will be signed out.', confirmLabel: 'Disable', danger: true });
  const dlg = p.document.querySelector('dialog.modal');
  assert.ok(dlg.hasAttribute('open'));
  const ok = dlg.querySelectorAll('button').find((b) => b.textContent === 'Disable');
  assert.ok(ok.classList.contains('btn-danger'));
  ok.click();
  assert.equal(await yes, true);
  assert.equal(p.document.querySelector('dialog'), null);
  const no = c.confirmDialog({ title: 'Sure?' });
  p.document.querySelectorAll('dialog button').find((b) => b.textContent === 'Cancel').click();
  assert.equal(await no, false);
  p.dispose();
});

await run();
