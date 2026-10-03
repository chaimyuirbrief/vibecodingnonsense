// public/request.html + js/request.js — request access (CONTRACTS §8.4).
// The thank-you is identical whatever the server says: no enumeration.

import { test, assert, run } from '../helpers/t.js';
import { loadPage, reply } from '../helpers/dom.js';

const ORIGIN = 'https://staff.example.com';

async function open(answer = reply(200, { ok: true })) {
  return loadPage('request.html', {
    url: `${ORIGIN}/request-access`,
    fetch: { 'POST /api/access-request': answer, 'POST /api/fp': reply(200, { ok: true }) },
  });
}

function fill(page, v = {}) {
  page.fill('full_name', v.full_name ?? 'Robin Newstarter');
  page.fill('email', v.email ?? 'robin@acme.com');
  page.fill('reason', v.reason ?? 'I joined the finance team on Monday; my manager is Ada.');
}

test('load: the form, the privacy notice, and a background fingerprint report', async () => {
  const page = await open();
  assert.ok(page.visible('pane-form'));
  assert.ok(!page.visible('pane-thanks'));
  assert.ok(page.visible('privacy'));
  assert.match(page.text('privacy'), /records technical details/);
  assert.equal(page.requests('/api/fp').length, 1);
  assert.equal(page.text('reason-count'), '0 / 500');
  page.dispose();
});

test('happy path: posts the three fields and thanks the visitor', async () => {
  const page = await open();
  fill(page, { email: ' robin@acme.com ' });
  assert.equal(page.text('reason-count'), '55 / 500');
  await page.submit('form-request');
  assert.deepEqual(page.requests('/api/access-request')[0].body, { email: 'robin@acme.com', full_name: 'Robin Newstarter', reason: 'I joined the finance team on Monday; my manager is Ada.' });
  assert.ok(page.visible('pane-thanks'));
  assert.ok(!page.visible('pane-form'));
  assert.equal(page.document.activeElement, page.$('pane-thanks'));
  assert.deepEqual(page.calls.nav, [], 'no native submit, no navigation');
  page.dispose();
});

test('the same thank-you whatever the server answers (no enumeration)', async () => {
  const texts = new Set();
  for (const r of [reply(200, { ok: true }), reply(409, { error: 'That email already has an account.' }), reply(400, { error: 'Bad email.' }), reply(429, { retry_after: 3600 }), reply(500, { error: 'boom' }), reply(403, null)]) {
    const page = await open(r);
    fill(page);
    await page.submit('form-request');
    assert.ok(page.visible('pane-thanks'), `status ${r.status}`);
    assert.ok(!page.visible('request-error'), `no error shown for ${r.status}`);
    texts.add(`${page.text('title')}|${page.text('pane-thanks')}`);
    page.dispose();
  }
  assert.equal(texts.size, 1, 'byte-identical page for every answer');
});

test('a request that never reached the server says so (and offers a retry)', async () => {
  const page = await open(reply(200, null, { networkError: true }));
  fill(page);
  await page.submit('form-request');
  assert.ok(!page.visible('pane-thanks'));
  assert.ok(page.visible('request-error'));
  assert.match(page.text('request-error'), /couldn’t reach the server/);
  assert.equal(page.$('request-submit').disabled, false);
  page.dispose();
});

test('client checks: missing name, bad email, empty reason — nothing is sent', async () => {
  for (const [v, errId] of [
    [{ full_name: ' ' }, 'full_name-error'],
    [{ email: 'robin' }, 'email-error'],
    [{ reason: '   ' }, 'reason-error'],
  ]) {
    const page = await open();
    fill(page, v);
    await page.submit('form-request');
    assert.ok(page.visible(errId), JSON.stringify(v));
    assert.equal(page.requests('/api/access-request').length, 0);
    page.dispose();
  }
});

test('the form works even when the fingerprint report fails', async () => {
  const page = await loadPage('request.html', {
    url: `${ORIGIN}/request-access`,
    fetch: { 'POST /api/access-request': reply(200, { ok: true }), 'POST /api/fp': reply(200, null, { networkError: true }) },
  });
  fill(page);
  await page.submit('form-request');
  assert.ok(page.visible('pane-thanks'));
  assert.deepEqual(page.calls.pageErrors, []);
  page.dispose();
});

test('the privacy notice follows the setting carried by the fingerprint reply', async () => {
  const custom = await loadPage('request.html', { url: 'https://staff.example.com/request-access', fetch: { 'POST /api/fp': reply(200, { ok: true, privacy_notice: 'Custom words.' }) } });
  await custom.drain();
  assert.equal(custom.text('privacy-text'), 'Custom words.');
  assert.ok(custom.visible('privacy'));
  custom.dispose();
  const off = await loadPage('request.html', { url: 'https://staff.example.com/request-access', fetch: { 'POST /api/fp': reply(200, { ok: true, privacy_notice: null }) } });
  await off.drain();
  assert.ok(!off.visible('privacy'), 'turned off → hidden');
  off.dispose();
  const failed = await loadPage('request.html', { url: 'https://staff.example.com/request-access', fetch: { 'POST /api/fp': reply(500, {}) } });
  await failed.drain();
  assert.ok(failed.visible('privacy'), 'no answer → the default stays (say so rather than go quiet)');
  failed.dispose();
});

await run();
