// Cross-site writes (CONTRACTS §8.1 step 6; SPEC §3.4): a write must carry
// our exact Origin, or no Origin and Sec-Fetch-Site: same-origin.

import { test, assert, run } from '../helpers/t.js';
import { freshEnv, bootstrap, rawRequest, count, OWNER_IP, OWNER, SESSION_COOKIE, DEVICE_COOKIE } from '../helpers/flows.js';

async function world() {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const cookie = `${SESSION_COOKIE}=${owner.client.jar.get(SESSION_COOKIE)}; ${DEVICE_COOKIE}=${owner.client.jar.get(DEVICE_COOKIE)}`;
  return { env, owner, cookie };
}

const JSON_H = { 'content-type': 'application/json' };

test('a write without Origin, or with the wrong one, is an empty 403 and changes nothing', async () => {
  const { env, cookie } = await world();
  const live = () => count(env, 'SELECT COUNT(*) FROM sessions WHERE revoked_at IS NULL');
  const before = live();
  for (const [what, extra] of [
    ['no Origin', {}],
    ['foreign Origin', { origin: 'https://evil.example' }],
    ['lookalike Origin', { origin: 'https://staff.example.com.evil.example' }],
    ['http downgrade', { origin: 'http://staff.example.com' }],
    ['trailing slash', { origin: 'https://staff.example.com/' }],
    ['null Origin', { origin: 'null' }],
    ['cross-site fetch metadata', { 'sec-fetch-site': 'cross-site' }],
    ['same-site is not same-origin', { 'sec-fetch-site': 'same-site' }],
  ]) {
    for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
      const r = await rawRequest(env, method, '/api/auth/logout', { ip: OWNER_IP, headers: { ...JSON_H, cookie, ...extra }, body: '{}' });
      assert.equal(r.status, 403, `${what} ${method}`);
      assert.equal(r.text, '', `${what} ${method}`);
    }
  }
  assert.equal(live(), before, 'still signed in');
  assert.ok(count(env, "SELECT COUNT(*) FROM visits WHERE reason = 'cross_origin'") >= 1, 'refusals are logged');
});

test('our Origin, or same-origin fetch metadata with no Origin, goes through', async () => {
  const { env, cookie } = await world();
  const ok1 = await rawRequest(env, 'POST', '/api/auth/login', {
    ip: OWNER_IP,
    headers: { ...JSON_H, origin: env.ORIGIN },
    body: JSON.stringify({ identifier: OWNER.email, password: OWNER.password }),
  });
  assert.equal(ok1.status, 200);
  const ok2 = await rawRequest(env, 'POST', '/api/auth/logout', { ip: OWNER_IP, headers: { ...JSON_H, cookie, 'sec-fetch-site': 'same-origin' }, body: '{}' });
  assert.equal(ok2.status, 200);
});

test('reads need no Origin', async () => {
  const { env, cookie } = await world();
  const r = await rawRequest(env, 'GET', '/api/me', { ip: OWNER_IP, headers: { cookie } });
  assert.equal(r.status, 200);
});

test('a form post (not JSON) cannot drive a JSON route even from our origin', async () => {
  const { env } = await world();
  const r = await rawRequest(env, 'POST', '/api/auth/login', {
    ip: OWNER_IP,
    headers: { origin: env.ORIGIN, 'content-type': 'application/x-www-form-urlencoded' },
    body: `identifier=${encodeURIComponent(OWNER.email)}&password=${encodeURIComponent(OWNER.password)}`,
  });
  assert.equal(r.status, 401);
});

await run();
