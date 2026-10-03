// Fresh deploy and bootstrap (CONTRACTS §8.4 POST /api/setup; B §5, trap 3;
// SPEC §6.6), driven through worker.fetch.

import { test, assert, run } from '../helpers/t.js';
import {
  freshEnv, client, bootstrap, rawRequest, pageText, q, count, auditRows, advance, MINUTE, OWNER, OWNER_IP, HOSTILE, SESSION_COOKIE, DEVICE_COOKIE,
} from '../helpers/flows.js';
import { iso } from '../../src/util.js';

const GOOD = { email: OWNER.email, full_name: OWNER.full_name, password: OWNER.password };

test('fresh deploy: everything outside /healthz and the setup shell is an empty 403', async () => {
  const env = freshEnv();
  const c = client(env);
  const h = await c.get('/healthz');
  assert.equal(h.status, 200);
  assert.equal(h.text, 'ok');
  for (const [method, path] of [
    ['GET', '/login'], ['GET', '/admin'], ['GET', '/account'], ['GET', '/dashboard'], ['GET', '/invite'], ['GET', '/pending'],
    ['GET', '/request-access'], ['GET', '/api/me'], ['GET', '/api/auth/whoami'], ['GET', '/api/diag'], ['GET', '/api/device/status'],
    ['GET', '/js/login.js'], ['GET', '/js/admin.js'], ['POST', '/api/auth/login'], ['POST', '/api/fp'], ['POST', '/api/access-request'],
  ]) {
    const r = await c.request(method, path, method === 'POST' ? {} : undefined);
    assert.equal(r.status, 403, `${method} ${path}`);
    assert.equal(r.text, '', `${method} ${path} must say nothing`);
    assert.equal(r.headers.get('set-cookie'), null, `${method} ${path} sets no cookie`);
  }
  assert.equal(count(env, 'SELECT COUNT(*) FROM users'), 0);
});

test('fresh deploy: the setup shell serves the setup page, its script and the status', async () => {
  const env = freshEnv();
  const c = client(env);
  const setupHtml = await pageText('setup.html');
  for (const p of ['/', '/setup']) {
    const r = await c.get(p);
    assert.equal(r.status, 200, p);
    assert.equal(r.text, setupHtml, `${p} serves setup.html`);
  }
  assert.equal((await c.get('/js/setup.js')).status, 200);
  assert.equal((await c.get('/css/app.css')).status, 200);
  const s = await c.get('/api/setup/status');
  assert.equal(s.status, 200);
  assert.deepEqual(s.body, { needed: true, org_name: 'Acme Inc.' });
});

test('a wrong setup key is refused, audited, and rate-limited per address', async () => {
  const env = freshEnv();
  const c = client(env);
  for (let i = 0; i < 5; i++) {
    const r = await c.post('/api/setup', { ...GOOD, setup_key: `wrong-key-${i}-0123456789abcdef0123456789` });
    assert.equal(r.status, 403);
    assert.equal(r.body.field, 'setup_key');
  }
  // Charged before the key is checked: even the right key now waits.
  const limited = await c.post('/api/setup', { ...GOOD, setup_key: env.SETUP_KEY });
  assert.equal(limited.status, 429);
  assert.equal(count(env, 'SELECT COUNT(*) FROM users'), 0);
  assert.equal(c.jar.has(SESSION_COOKIE), false);
  const denied = auditRows(env, 'setup.complete');
  assert.equal(denied.length, 5);
  assert.ok(denied.every((r) => r.outcome === 'denied' && /wrong setup key/.test(r.detail)));
  assert.ok(!JSON.stringify(denied).includes('wrong-key-'), 'the guessed key is never logged');
  // Another address is not limited by this one.
  const other = await client(env).post('/api/setup', { ...GOOD, setup_key: env.SETUP_KEY });
  assert.equal(other.status, 200);
});

test('hostile setup keys are refused without creating anything', async () => {
  const env = freshEnv();
  for (const v of HOSTILE) {
    const r = await client(env).post('/api/setup', { ...GOOD, setup_key: v });
    assert.equal(r.status, 403, `setup_key ${String(typeof v === 'symbol' ? 'Symbol' : JSON.stringify(v))}`);
  }
  // A body that is not JSON at all.
  const junk = await client(env).post('/api/setup', 'not json', { 'content-type': 'text/plain' });
  assert.equal(junk.status, 403);
  assert.equal(count(env, 'SELECT COUNT(*) FROM users'), 0);
  assert.equal(count(env, "SELECT COUNT(*) FROM meta WHERE key = 'setup_claim'"), 0);
});

test('a missing SETUP_KEY matches nothing, not even an empty key', async () => {
  const env = freshEnv({ vars: { SETUP_KEY: undefined } });
  for (const key of ['', 'undefined', 'test-setup-key-0123456789abcdef0123456789abcdef']) {
    const r = await client(env).post('/api/setup', { ...GOOD, setup_key: key });
    assert.equal(r.status, 403);
  }
  assert.ok(auditRows(env, 'setup.complete').every((r) => /not configured/.test(r.detail)));
  assert.equal(count(env, 'SELECT COUNT(*) FROM users'), 0);
});

test('hostile account fields are validation errors and release the claim', async () => {
  const env = freshEnv();
  for (const field of ['email', 'full_name', 'password']) {
    // 'abc' is a fine name, so it is a hostile value only for the other two.
    for (const v of [null, '', '   ', {}, [], true, 0, ...(field === 'full_name' ? [] : ['abc'])]) {
      const r = await client(env).post('/api/setup', { ...GOOD, setup_key: env.SETUP_KEY, [field]: v });
      assert.equal(r.status, 400, `${field} = ${JSON.stringify(v)}: ${r.text}`);
    }
  }
  assert.equal(count(env, 'SELECT COUNT(*) FROM users'), 0);
  assert.equal(count(env, "SELECT COUNT(*) FROM meta WHERE key = 'setup_claim'"), 0, 'a failed setup leaves no claim behind');
  const ok = await client(env).post('/api/setup', { ...GOOD, setup_key: env.SETUP_KEY });
  assert.equal(ok.status, 200);
});

test('the right key creates a Super Admin, allowlists the caller (tier 1), approves the device, pins enrolment', async () => {
  const env = freshEnv();
  const c = client(env, { ip: OWNER_IP });
  const r = await c.post('/api/setup', { ...GOOD, setup_key: env.SETUP_KEY });
  assert.equal(r.status, 200);
  assert.equal(r.body.ok, true);
  assert.equal(r.body.pinned, 'mfa_enroll');
  assert.equal(r.body.next, '/account?pin=mfa_enroll');
  assert.equal(r.body.user.role.key, 'super_admin');
  assert.equal(r.body.user.status, 'active');
  assert.ok(c.jar.has(SESSION_COOKIE) && c.jar.has(DEVICE_COOKIE));
  const allow = q(env, 'SELECT * FROM allowed_ips');
  assert.equal(allow.length, 1);
  assert.equal(allow[0].cidr, `${OWNER_IP}/32`);
  assert.equal(allow[0].tier, 1);
  assert.equal(allow[0].expires_at, null);
  const devices = q(env, 'SELECT * FROM devices');
  assert.equal(devices.length, 1);
  assert.equal(devices[0].status, 'approved');
  assert.equal(devices[0].approved_by, r.body.user.id);
  const s = q(env, 'SELECT * FROM sessions');
  assert.equal(s.length, 1);
  assert.equal(s[0].pinned, 'mfa_enroll');
  assert.equal(s[0].device_id, devices[0].id);
  assert.equal(count(env, "SELECT COUNT(*) FROM meta WHERE key = 'setup_claim'"), 0);
  for (const a of ['network.allow.add', 'device.approve', 'setup.complete', 'login.success']) {
    assert.equal(auditRows(env, a).length, 1, a);
  }
  assert.ok(!JSON.stringify(auditRows(env)).includes(OWNER.password), 'no password in the audit log');
  assert.ok(!r.text.includes(OWNER.password));
});

test('after setup, /setup and the setup API are gone for everyone', async () => {
  const env = freshEnv();
  const { client: owner } = await bootstrap(env);
  assert.equal((await owner.get('/setup')).status, 404);
  assert.equal((await owner.get('/api/setup/status')).status, 404);
  const again = await owner.post('/api/setup', { ...GOOD, email: 'second@acme.com', setup_key: env.SETUP_KEY });
  assert.equal(again.status, 404);
  const stranger = client(env);
  for (const p of ['/', '/setup', '/api/setup/status']) {
    const r = await stranger.get(p);
    assert.equal(r.status, 403, p);
    assert.equal(r.text, '');
  }
  assert.equal((await stranger.post('/api/setup', { ...GOOD, setup_key: env.SETUP_KEY })).status, 403);
  assert.equal(count(env, 'SELECT COUNT(*) FROM users'), 1);
});

test('two setups at once create exactly one account', async () => {
  const env = freshEnv();
  const a = client(env);
  const b = client(env);
  const [ra, rb] = await Promise.all([
    a.post('/api/setup', { ...GOOD, setup_key: env.SETUP_KEY }),
    b.post('/api/setup', { ...GOOD, email: 'rival@acme.com', setup_key: env.SETUP_KEY }),
  ]);
  const statuses = [ra.status, rb.status].sort();
  assert.deepEqual(statuses, [200, 409]);
  assert.equal(count(env, 'SELECT COUNT(*) FROM users'), 1);
  assert.equal(count(env, 'SELECT COUNT(*) FROM sessions'), 1);
  assert.equal(auditRows(env, 'login.success').length, 1);
});

test('a stale claim (a setup that died halfway) expires after ten minutes', async () => {
  const env = freshEnv();
  await client(env).get('/'); // creates the schema
  q(env, "INSERT INTO meta (key, value) VALUES ('setup_claim', ?)", `${iso(env.__clock() + 10 * MINUTE)}|crashed-isolate`);
  const c = client(env);
  const blocked = await c.post('/api/setup', { ...GOOD, setup_key: env.SETUP_KEY });
  assert.equal(blocked.status, 409);
  assert.equal(blocked.body.code, 'setup_in_progress');
  advance(env, 9 * MINUTE);
  assert.equal((await client(env).post('/api/setup', { ...GOOD, setup_key: env.SETUP_KEY })).status, 409);
  advance(env, MINUTE);
  const ok = await client(env).post('/api/setup', { ...GOOD, setup_key: env.SETUP_KEY });
  assert.equal(ok.status, 200);
  assert.equal(count(env, 'SELECT COUNT(*) FROM users'), 1);
});

test('an unreadable claim does not wall the portal off forever', async () => {
  const env = freshEnv();
  await client(env).get('/');
  q(env, "INSERT INTO meta (key, value) VALUES ('setup_claim', 'garbage')");
  const ok = await client(env).post('/api/setup', { ...GOOD, setup_key: env.SETUP_KEY });
  assert.equal(ok.status, 200);
});

test('setup from a private address skips the allowlist with a notice; the approved device is the way back', async () => {
  const env = freshEnv();
  const c = client(env, { ip: '10.1.2.3' });
  const r = await c.post('/api/setup', { ...GOOD, setup_key: env.SETUP_KEY });
  assert.equal(r.status, 200);
  assert.equal(count(env, 'SELECT COUNT(*) FROM allowed_ips'), 0);
  assert.match(auditRows(env, 'setup.complete')[0].detail, /private or reserved/);
  // Still in: the device was approved in the same request.
  const me = await c.get('/api/me');
  assert.equal(me.status, 200);
  assert.equal(me.body.pinned, 'mfa_enroll');
});

await run();
