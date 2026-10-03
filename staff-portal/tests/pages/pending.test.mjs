// public/pending.html + js/pending.js — waiting for device approval
// (CONTRACTS §7.8 pending shell, §8.4 /api/device/status, /api/diag; A §5).

import { test, assert, run } from '../helpers/t.js';
import { loadPage, reply } from '../helpers/dom.js';

const ORIGIN = 'https://staff.example.com';
const PENDING = { code: 'K7F3-9QX2', status: 'pending', label: 'Chrome on macOS' };
const APPROVED = { ...PENDING, status: 'approved' };
const DIAG = {
  cookies: { names: ['__Host-dev', '__Host-fp'], count: 2 },
  ua: 'Mozilla/5.0 (Macintosh) Chrome/129',
  client_hints: { 'sec-ch-ua-platform': '"macOS"', 'sec-ch-ua-mobile': '?0' },
  ip: '81.2.69.142',
  country: 'GB',
  asn: 20712,
  tls_version: 'TLSv1.3',
  http_protocol: 'HTTP/2',
  device: { present: true, valid: true, status: 'pending', code: 'K7F3-9QX2' },
  session: { present: false, valid: false },
};

async function open(status = reply(200, PENDING), extra = {}) {
  return loadPage('pending.html', { url: `${ORIGIN}/pending`, fetch: { 'GET /api/device/status': status, 'GET /api/diag': reply(200, DIAG), ...extra } });
}

const polls = (page) => page.pendingTimers(15000).length;

// The diagnostic list as { label: value }.
function diagRows(page) {
  const dts = page.document.querySelectorAll('#diag-list dt');
  const dds = page.document.querySelectorAll('#diag-list dd');
  assert.equal(dts.length, dds.length);
  return Object.fromEntries(dts.map((dt, i) => [page.text(dt), page.text(dds[i])]));
}

test('shows the device code large, spelled out for screen readers, with status and next steps', async () => {
  const page = await open();
  assert.ok(page.visible('pane-code'));
  assert.ok(!page.visible('pane-loading'));
  assert.equal(page.text('device-code'), 'K7F3-9QX2');
  assert.ok(page.$('device-code').classList.contains('device-code'));
  assert.equal(page.text('device-code-sr'), 'Your device code is K 7 F 3 dash 9 Q X 2.');
  assert.equal(page.text('device-status'), 'Waiting for approval');
  assert.ok(page.$('device-status').classList.contains('badge-warn'));
  assert.equal(page.text('device-label'), 'Chrome on macOS');
  assert.match(page.text('pane-code'), /Read this code to an administrator/);
  assert.match(page.text('checked-at'), /Last checked/);
  assert.ok(!page.visible('pane-approved'));
  assert.equal(polls(page), 1, 'one gentle poll scheduled');
  assert.deepEqual(page.calls.unmatched, []);
  page.dispose();
});

test('auto-poll every 15 s; approval stops polling and links to "/"', async () => {
  const page = await open([reply(200, PENDING), reply(200, PENDING), reply(200, APPROVED)]);
  assert.equal(page.pendingTimers(15000)[0].delay, 15000);
  await page.fireTimers(15000);
  assert.equal(page.requests('/api/device/status').length, 2);
  assert.equal(polls(page), 1);
  await page.fireTimers(15000);
  assert.equal(page.requests('/api/device/status').length, 3);
  assert.ok(page.visible('pane-approved'));
  assert.equal(page.$('continue').getAttribute('href'), '/');
  assert.equal(page.text('device-status'), 'Approved');
  assert.ok(!page.visible('check-now'));
  assert.equal(polls(page), 0, 'polling stopped');
  assert.equal(page.document.activeElement, page.$('continue'));
  page.dispose();
});

test('a hidden tab stops polling; coming back checks at once and resumes', async () => {
  const page = await open();
  assert.equal(polls(page), 1);
  await page.setVisibility('hidden');
  assert.equal(polls(page), 0, 'no polling while hidden');
  await page.setVisibility('visible');
  assert.equal(page.requests('/api/device/status').length, 2, 'checked on return');
  assert.equal(polls(page), 1, 'resumed');
  page.dispose();
});

test('a check that finishes while the tab is hidden does not schedule a poll', async () => {
  const page = await open([reply(200, PENDING), reply(200, PENDING, { delayMs: 30 })]);
  page.$('check-now').click();
  await page.setVisibility('hidden');
  await new Promise((r) => setTimeout(r, 60));
  await page.drain();
  assert.equal(page.requests('/api/device/status').length, 2, 'the in-flight check completed');
  assert.equal(polls(page), 0, 'nothing scheduled while hidden');
  page.dispose();
});

test('"Check again" checks now and keeps a single poll scheduled', async () => {
  const page = await open();
  await page.click('check-now');
  assert.equal(page.requests('/api/device/status').length, 2);
  assert.equal(polls(page), 1);
  assert.equal(page.$('check-now').disabled, false);
  page.dispose();
});

test('blocked: says so and stops', async () => {
  const page = await open(reply(200, { ...PENDING, status: 'blocked' }));
  assert.ok(page.visible('pane-blocked'));
  assert.equal(page.text('device-status'), 'Blocked');
  assert.equal(polls(page), 0);
  page.dispose();
});

test('blocked while waiting: the gate’s bare refusal (the real reply — empty 403, or the decoy 404) shows the blocked pane and stops', async () => {
  const DECOY = '<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx</center></body></html>';
  for (const refusal of [reply(403, null), reply(404, DECOY, { headers: { 'content-type': 'text/html' } })]) {
    const page = await open([reply(200, PENDING), refusal]);
    assert.ok(page.visible('pane-code'));
    await page.fireTimers(15000);
    assert.ok(page.visible('pane-blocked'), 'refused → blocked');
    assert.ok(!page.visible('check-error'), 'not “You don’t have access to that.”');
    assert.equal(page.text('device-code'), 'K7F3-9QX2', 'the code stays, to quote to an administrator');
    assert.equal(page.text('device-status'), 'Blocked');
    assert.ok(!page.visible('check-now'));
    assert.equal(polls(page), 0, 'no more polling');
    page.dispose();
  }
});

test('an API error with a body is not mistaken for the gate: it is shown and polling continues', async () => {
  const page = await open([reply(200, PENDING), reply(403, { error: 'Not allowed here.', code: 'forbidden' })]);
  await page.fireTimers(15000);
  assert.ok(!page.visible('pane-blocked'));
  assert.equal(page.text('check-error'), 'Not allowed here.');
  assert.equal(polls(page), 1);
  page.dispose();
});

test('a failed check shows the error and keeps trying', async () => {
  const page = await open([reply(500, { error: 'Something broke.' }), reply(200, PENDING)]);
  assert.ok(page.visible('check-error'));
  assert.equal(page.text('check-error'), 'Something broke.');
  assert.equal(polls(page), 1);
  await page.fireTimers(15000);
  assert.ok(!page.visible('check-error'));
  assert.equal(page.text('device-code'), 'K7F3-9QX2');
  page.dispose();
});

test('polling slows down after ten minutes', async () => {
  const page = await open();
  for (let i = 0; i < 40; i++) await page.fireTimers(15000);
  assert.deepEqual(page.pendingTimers(15000).map((t) => t.delay), [60000]);
  page.dispose();
});

test('copy code puts exactly the code on the clipboard', async () => {
  const page = await open();
  await page.click('copy-code');
  assert.deepEqual(page.calls.clipboard, ['K7F3-9QX2']);
  page.dispose();
});

test('"What did my browser send?" renders /api/diag — names and counts, never values', async () => {
  const page = await open();
  assert.ok(!page.visible('diag-panel'));
  assert.equal(page.requests('/api/diag').length, 0, 'nothing fetched until asked');
  await page.click('diag-toggle');
  assert.equal(page.$('diag-toggle').getAttribute('aria-expanded'), 'true');
  assert.ok(page.visible('diag-panel'));
  const rows = diagRows(page);
  assert.equal(rows['Cookies sent'], '2 — __Host-dev, __Host-fp');
  assert.match(rows['Client hints'], /sec-ch-ua-platform: "macOS"/);
  assert.equal(rows['IP address'], '81.2.69.142');
  assert.equal(rows.Country, 'GB');
  assert.equal(rows.Network, 'AS20712');
  assert.equal(rows.Connection, 'TLSv1.3 · HTTP/2');
  assert.equal(rows['Device cookie'], 'present · pending · K7F3-9QX2');
  assert.equal(rows.Session, 'not signed in');
  await page.click('diag-toggle');
  assert.ok(!page.visible('diag-panel'));
  assert.equal(page.$('diag-toggle').getAttribute('aria-expanded'), 'false');
  assert.equal(page.requests('/api/diag').length, 1, 'collapsing does not refetch');
  page.dispose();
});

test('diag: hostile values are text; a failure is shown in the panel', async () => {
  const page = await open(reply(200, PENDING), { 'GET /api/diag': [reply(200, { ...DIAG, ua: '<script>alert(1)</script>', cookies: { names: ['<b>x</b>'], count: 1 }, client_hints: {} }), reply(500, { error: 'Diag down.' })] });
  await page.click('diag-toggle');
  const rows = diagRows(page);
  assert.equal(rows.Browser, '<script>alert(1)</script>');
  assert.equal(rows['Cookies sent'], '1 — <b>x</b>');
  assert.equal(page.document.querySelectorAll('#diag-list script, #diag-list b').length, 0);
  assert.match(rows['Client hints'], /^none/);
  await page.click('diag-toggle');
  await page.click('diag-toggle');
  assert.equal(page.text('diag-error'), 'Diag down.');
  page.dispose();
});

await run();
