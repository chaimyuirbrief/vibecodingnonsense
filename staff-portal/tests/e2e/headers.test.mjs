// Response hardening on EVERY response, the empty ones included (CONTRACTS
// §8.2; A §2), and the fail-closed answers around it (CONTRACTS §3, §8.1).

import { test, assert, run } from '../helpers/t.js';
import { freshEnv, client, bootstrap, rawRequest, setSetting, OWNER_IP } from '../helpers/flows.js';
import { CSP, SECURITY_HEADERS } from '../../src/pages.js';

const EXACT_CSP =
  "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; manifest-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

function hardened(r, what) {
  assert.equal(r.headers.get('content-security-policy'), EXACT_CSP, what);
  assert.equal(r.headers.get('x-content-type-options'), 'nosniff', what);
  assert.equal(r.headers.get('x-frame-options'), 'DENY', what);
  assert.equal(r.headers.get('referrer-policy'), 'no-referrer', what);
  assert.equal(r.headers.get('cross-origin-opener-policy'), 'same-origin', what);
  assert.equal(r.headers.get('cross-origin-resource-policy'), 'same-origin', what);
  assert.equal(
    r.headers.get('permissions-policy'),
    'camera=(), microphone=(), geolocation=(), payment=(), usb=(), publickey-credentials-get=(self), publickey-credentials-create=(self)',
    what,
  );
  assert.equal(r.headers.get('strict-transport-security'), 'max-age=63072000; includeSubDomains', what);
  assert.equal(r.headers.get('cache-control'), 'no-store, no-cache, must-revalidate, private', what);
}

test('the CSP is exactly the contract’s, with no unsafe-inline anywhere', () => {
  assert.equal(CSP, EXACT_CSP);
  assert.ok(!Object.values(SECURITY_HEADERS).join(' ').includes('unsafe'));
});

test('every kind of response carries every header', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const stranger = client(env);
  const anon = client(env, { ip: OWNER_IP });
  const cases = [
    ['healthz', await stranger.get('/healthz'), 200],
    ['empty 403 (gate)', await stranger.get('/'), 403],
    ['empty 403 (gate, API write)', await stranger.post('/api/auth/login', {}), 403],
    ['page', await owner.client.get('/'), 200],
    ['redirect', await anon.get('/admin'), 302],
    ['asset', await owner.client.get('/css/app.css'), 200],
    ['empty 404 (page)', await owner.client.get('/nope'), 404],
    ['JSON 404 (api)', await owner.client.get('/api/nope'), 404],
    ['JSON 401', await anon.get('/api/me'), 401],
    ['JSON 405', await owner.client.del('/api/auth/whoami'), 405],
    ['identical 401', await anon.post('/api/auth/login', { identifier: 'x@acme.com', password: 'y' }), 401],
    ['JSON 200', await owner.client.get('/api/me'), 200],
    ['cross-origin 403', await owner.client.post('/api/auth/logout', {}, { origin: 'https://evil.example' }), 403],
  ];
  for (const [what, r, status] of cases) {
    assert.equal(r.status, status, what);
    hardened(r, what);
  }
  setSetting(env, 'deny_style', 'decoy');
  hardened(await stranger.get('/'), 'decoy 404');
});

test('missing secrets: an empty 503 for everything but /healthz', async () => {
  for (const vars of [{ SESSION_SECRET: undefined }, { DATA_KEY: undefined }, { SESSION_SECRET: 'too-short' }, { DATA_KEY: 'test-session-secret-0123456789abcdef0123456789abcdef' }]) {
    const env = freshEnv({ vars });
    const h = await rawRequest(env, 'GET', '/healthz');
    assert.equal(h.status, 200);
    assert.equal(h.text, 'ok');
    hardened(h, 'healthz without secrets');
    for (const [m, p] of [['GET', '/'], ['GET', '/setup'], ['GET', '/api/setup/status'], ['POST', '/api/setup']]) {
      const r = await rawRequest(env, m, p, { headers: { origin: env.ORIGIN, 'content-type': 'application/json' }, body: m === 'POST' ? '{}' : undefined });
      assert.equal(r.status, 503, `${m} ${p} with ${Object.keys(vars)}`);
      assert.equal(r.text, '');
      hardened(r, `503 ${p}`);
    }
    // Nothing was even created: the schema step never ran.
    assert.equal(env.DB.q("SELECT COUNT(*) AS n FROM sqlite_master WHERE type = 'table'")[0].n, 0);
  }
});

test('Set-Cookie never rides on a refusal', async () => {
  const env = freshEnv();
  await bootstrap(env);
  const r = await client(env).get('/invite?token=' + 'A'.repeat(43));
  assert.equal(r.status, 403);
  assert.equal(r.headers.get('set-cookie'), null);
});

await run();
