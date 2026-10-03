// The shell pages — invite, request access, pending, and the login shell of
// fingerprint_gate — against the REAL gate and API. A shell lets a stranger
// reach exactly one page, its scripts and a handful of routes (CONTRACTS
// §7.8); openLive also fetches every script the page imports through the
// worker, so a shell that forgot one fails here rather than in production.

import { test, assert, run } from '../helpers/t.js';
import { openLive, navigate, apiErrors, lastNav, settle, liveFetch } from '../helpers/live.js';
import { freshEnv, bootstrap, makeUser, client, setSetting, advance, q, count, OWNER_IP, PASSWORD, HOUR } from '../helpers/flows.js';

function noFailures(page, ignore = []) {
  assert.deepEqual(apiErrors(page, { ignore }).map((c) => `${c.method} ${c.url} → ${c.status} ${JSON.stringify(c.response)}`), [], 'a live API call failed');
  assert.deepEqual(page.calls.pageErrors.map((e) => String(e && e.stack ? e.stack : e)), [], 'the page threw');
}

function calls(page, method, path) {
  return page.calls.fetch.filter((c) => c.method === method && (path instanceof RegExp ? path.test(c.path) : c.path === path));
}

async function invite(env, owner, extra = {}) {
  const r = await owner.client.post('/api/admin/users', { email: 'ivy@acme.com', full_name: 'Ivy Invitee', ...extra });
  assert.equal(r.status, 200, r.text);
  const url = new URL(r.body.invitation.url);
  return { url, token: url.searchParams.get('token'), user: r.body.user };
}

// ------------------------------------------------------------ invite ----

test('invite: a stranger opens the real link, sets a password, is signed in and their browser approved', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const { url, token, user } = await invite(env, owner);
  const c = client(env); // off the allowlist, no device: the link is the only way in
  assert.equal((await navigate(c, '/')).status, 403, 'without the link: nothing');
  const page = await openLive(c, url.pathname + url.search);
  assert.equal(page.served.file, 'invite.html');
  assert.deepEqual(Object.keys(page.served.assets).sort(), ['/css/app.css', '/favicon.svg', '/js/common.js', '/js/fp.js', '/js/invite.js']);
  await settle(page);
  const info = calls(page, 'GET', `/api/invite/${token}`)[0];
  assert.equal(info.status, 200, JSON.stringify(info.response));
  assert.ok(page.visible('pane-form'));
  assert.equal(page.text('invite-email'), info.response.email);
  assert.equal(page.text('invite-org'), 'Acme Inc.');
  assert.equal(page.$('full_name').value, 'Ivy Invitee');
  assert.match(page.text('invite-expires'), /\(in 7 days\)$|\(in \d+ (days|months)\)$|ago\)$/);
  assert.equal(page.text('privacy-text'), info.response.privacy_notice);

  page.fill('password', 'ivy-chooses-a-long-one');
  page.fill('confirm', 'ivy-chooses-a-long-one');
  await page.submit('form-invite');
  await settle(page);
  const acc = calls(page, 'POST', '/api/invite/accept')[0];
  assert.equal(acc.status, 200, JSON.stringify(acc.response));
  assert.deepEqual(acc.body, { token, password: 'ivy-chooses-a-long-one', full_name: 'Ivy Invitee' });
  assert.equal(calls(page, 'GET', '/api/auth/whoami')[0].response.authenticated, true, 'the cookie came home');
  assert.deepEqual(lastNav(page), { type: 'replace', url: acc.response.next });
  noFailures(page);
  assert.equal(q(env, 'SELECT status FROM users WHERE id = ?', user.id)[0].status, 'active');

  const home = await openLive(c, '/');
  assert.equal(home.served.file, 'dashboard.html', 'the accepted browser is approved: the gate lets it in');
  home.dispose();
});

test('invite: a used or bogus link says so plainly (shown to a visitor the gate admits)', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const office = client(env, { ip: OWNER_IP });
  const page = await openLive(office, `/invite?token=${'A'.repeat(43)}`);
  await settle(page);
  assert.equal(calls(page, 'GET', `/api/invite/${'A'.repeat(43)}`)[0].status, 404);
  assert.ok(page.visible('pane-invalid'));
  assert.ok(!page.visible('pane-form'));
  assert.equal(page.text('title'), 'Invitation not valid');
  noFailures(page, ['GET /api/invite/']);
  // A stranger with a dead link gets nothing at all (no pass cookie).
  const stranger = client(env);
  assert.equal((await navigate(stranger, `/invite?token=${'A'.repeat(43)}`)).status, 403);
});

// ------------------------------------------------------------ request ----

test('request access: a stranger sees the form, sends it, gets the same thanks; the request is stored', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  setSetting(env, 'access_mode', 'request_access');
  const c = client(env);
  const page = await openLive(c, '/');
  assert.equal(page.served.file, 'request.html', 'a stranger in request_access mode');
  assert.deepEqual(Object.keys(page.served.assets).sort(), ['/css/app.css', '/favicon.svg', '/js/common.js', '/js/fp.js', '/js/request.js']);
  await settle(page);
  page.fill('full_name', 'Rita Requester');
  page.fill('email', 'rita@example.org');
  page.fill('reason', 'Joining the support team.');
  await page.submit('form-request');
  await settle(page);
  const r = calls(page, 'POST', '/api/access-request')[0];
  assert.equal(r.status, 200, JSON.stringify(r.response));
  assert.deepEqual(r.body, { email: 'rita@example.org', full_name: 'Rita Requester', reason: 'Joining the support team.' });
  assert.ok(page.visible('pane-thanks'));
  assert.equal(page.text('title'), 'Request sent');
  noFailures(page);
  const row = q(env, "SELECT * FROM access_requests WHERE email = 'rita@example.org'")[0];
  assert.ok(row);
  assert.equal(row.ip, c.ip);
  assert.equal(row.status, 'pending');
  // /request-access is the same page.
  const again = await openLive(client(env), '/request-access');
  assert.equal(again.served.file, 'request.html');
  again.dispose();
});

// ------------------------------------------------------------ pending ----

test('pending: device gating on — an unknown browser on the office network gets its code, the diagnostics, and moves on once approved', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  setSetting(env, 'device_gating', '1');
  const c = client(env, { ip: OWNER_IP }); // allowlisted network, unapproved device
  const served = await navigate(c, '/admin');
  assert.deepEqual(served.redirects, ['/pending'], 'any navigation shows /pending');
  const page = await openLive(c, '/');
  assert.equal(page.served.file, 'pending.html');
  assert.deepEqual(Object.keys(page.served.assets).sort(), ['/css/app.css', '/favicon.svg', '/js/common.js', '/js/pending.js']);
  await settle(page);
  const st = calls(page, 'GET', '/api/device/status')[0];
  assert.equal(st.status, 200, JSON.stringify(st.response));
  assert.equal(st.response.status, 'pending');
  assert.equal(page.text('device-code'), st.response.code);
  assert.match(st.response.code, /^[A-Z0-9]{4}-[A-Z0-9]{4}$/);
  assert.equal(page.text('device-status'), 'Waiting for approval');
  assert.ok(page.visible('check-now'));

  await page.click('diag-toggle');
  await settle(page);
  const diag = calls(page, 'GET', '/api/diag')[0];
  assert.equal(diag.status, 200);
  const dl = page.$('diag-list');
  const facts = Object.fromEntries(dl.querySelectorAll('dt').map((dt) => [dt.textContent, dt.nextElementSibling.textContent.replace(/\s+/g, ' ').trim()]));
  assert.equal(facts['IP address'], OWNER_IP);
  assert.equal(facts.Country, 'US');
  assert.equal(facts.Network, 'AS7922');
  assert.equal(facts['Device cookie'], `present · pending · ${st.response.code}`);
  assert.equal(facts.Session, 'not signed in');
  assert.ok(facts['Cookies sent'].startsWith(`${diag.response.cookies.count} — `));
  assert.ok(!/=/.test(facts['Cookies sent']), 'names only, never values');

  // An administrator approves it by the code read out to them.
  const devices = await owner.client.get('/api/admin/devices?status=pending');
  const d = devices.body.devices.find((x) => x.code === st.response.code);
  assert.ok(d, 'the console lists it by its code');
  const ap = await owner.client.post(`/api/admin/devices/${d.id}/approve`, { code: st.response.code });
  assert.equal(ap.status, 200, ap.text);
  await page.fireTimers(15000); // the 15-second poll
  await settle(page);
  assert.equal(calls(page, 'GET', '/api/device/status').at(-1).response.status, 'approved');
  assert.ok(page.visible('pane-approved'));
  assert.equal(page.text('title'), 'You’re approved');
  assert.equal(page.$('continue').getAttribute('href'), '/');
  noFailures(page);
  const next = await openLive(c, page.$('continue').getAttribute('href'));
  assert.equal(next.served.file, 'login.html', 'past the waiting room: the sign-in page');
  next.dispose();
});

test('pending: a device blocked while it waits sees the blocked pane (the gate refuses it outright) and stops polling', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  setSetting(env, 'device_gating', '1');
  const c = client(env, { ip: OWNER_IP });
  const page = await openLive(c, '/');
  await settle(page);
  const code = page.text('device-code');
  const devices = await owner.client.get('/api/admin/devices?status=pending');
  const d = devices.body.devices.find((x) => x.code === code);
  assert.equal((await owner.client.post(`/api/admin/devices/${d.id}/block`, {})).status, 200);
  await page.fireTimers(15000);
  await settle(page);
  const last = calls(page, 'GET', '/api/device/status').at(-1);
  assert.equal(last.status, 403, 'the gate refuses a blocked device (CONTRACTS §7.8 step 1)');
  assert.equal(last.response, null, 'with nothing in it');
  assert.ok(page.visible('pane-blocked'));
  assert.ok(!page.visible('check-error'));
  assert.equal(page.text('device-code'), code);
  assert.deepEqual(page.pendingTimers(15000), [], 'polling stopped');
  page.dispose();
});

// ------------------------------------------------------------ login shell ----

test('fingerprint gate: the login shell reports the browser first, then signs in', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const u = await makeUser(env, owner.client, { role: 'employee' });
  setSetting(env, 'access_mode', 'fingerprint_gate');
  const c = client(env); // a stranger: no device, off the allowlist
  const page = await openLive(c, '/');
  assert.equal(page.served.file, 'login.html');
  assert.deepEqual(Object.keys(page.served.assets).sort(), ['/css/app.css', '/favicon.svg', '/js/common.js', '/js/fp.js', '/js/login.js', '/js/webauthn.js']);
  await settle(page);
  page.fill('identifier', u.user.email);
  page.fill('password', PASSWORD);
  await page.submit('form-password');
  await settle(page);
  const fp = calls(page, 'POST', '/api/fp');
  assert.ok(fp.length >= 1, 'the fingerprint was reported');
  assert.equal(fp[0].status, 200, JSON.stringify(fp[0].response));
  const logins = calls(page, 'POST', '/api/auth/login');
  assert.equal(logins.at(-1).status, 200, JSON.stringify(logins.at(-1).response));
  assert.equal(logins.at(-1).response.enroll_prompt, true, 'no second factor yet');
  assert.ok(page.visible('pane-enroll'), 'signed in, with the prompt');
  assert.equal(calls(page, 'GET', '/api/auth/whoami').at(-1).response.authenticated, true);
  const home = await openLive(c, page.$('enroll-skip').getAttribute('href'));
  assert.equal(home.served.file, 'dashboard.html', 'the fingerprint cookie under the threshold now admits this browser');
  home.dispose();
  const risk = q(env, 'SELECT risk FROM fingerprints ORDER BY last_seen DESC LIMIT 1')[0].risk;
  assert.ok(risk < 70, `this browser scores under the threshold (${risk})`);
});

test('fingerprint gate: a signed-in browser whose fingerprint cookie lapsed is not sent round in a loop — the report lands before the page leaves (FE-1)', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const u = await makeUser(env, owner.client, { role: 'employee' });
  setSetting(env, 'session_absolute_hours', '48'); // allowed: 1..72
  setSetting(env, 'session_idle_minutes', '1440'); // allowed: 5..1440
  setSetting(env, 'access_mode', 'fingerprint_gate');
  // A second, unapproved browser of the same person signs in normally.
  const c = client(env);
  const fp = await c.post('/api/fp', { signals: { v: 1, ua: c.ua, languages: ['en-US'], tz: 'America/New_York', screen: { w: 1440, h: 900, cd: 24, dpr: 2 } } });
  assert.equal(fp.status, 200, fp.text);
  const login = await c.post('/api/auth/login', { identifier: u.user.email, password: PASSWORD });
  assert.equal(login.status, 200, login.text);
  assert.equal((await navigate(c, '/')).file, 'dashboard.html');
  advance(env, 12 * HOUR);
  assert.equal((await c.get('/api/me')).status, 200);
  advance(env, 13 * HOUR); // the fingerprint cookie (24 h) lapsed; the session (48 h, 24 h idle) did not

  // The report is held back a while, as the browser probes hold it back
  // (WebRTC alone may take 800 ms), then really sent to the worker.
  const base = liveFetch(c);
  const handler = async (url, init = {}) => {
    if (String(init.method || 'GET').toUpperCase() === 'POST' && new URL(url, env.ORIGIN).pathname === '/api/fp') await new Promise((r) => setTimeout(r, 300));
    return base(url, init);
  };
  handler.client = c;
  const page = await openLive(c, '/', { live: handler });
  assert.equal(page.served.file, 'login.html', 'the login shell serves the sign-in page to the signed-in browser');
  // Watch (in real time) for the moment the page asks to leave; what a
  // browser gets for that address THEN is what decides whether it loops.
  let nav = null;
  let reportDone = null;
  let landed = null;
  for (const t0 = Date.now(); !nav && Date.now() - t0 < 3000; ) {
    await page.drain(2);
    nav = lastNav(page);
    if (!nav) {
      await new Promise((r) => setTimeout(r, 5));
      continue;
    }
    const report = calls(page, 'POST', '/api/fp');
    reportDone = report.length > 0 && report.every((r) => r.done);
    landed = await navigate(c, nav.url);
  }
  assert.deepEqual(nav, { type: 'replace', url: '/' });
  assert.equal(reportDone, true, 'left before the fingerprint report landed');
  assert.equal(landed.file, 'dashboard.html', 'the address it went to shows the sign-in page again: a reload loop');
  await settle(page);
  assert.equal(calls(page, 'POST', '/api/fp')[0].status, 200);
  noFailures(page);
  page.dispose();
});

await run();
