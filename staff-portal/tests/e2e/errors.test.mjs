// A bug answers one polite sentence; the audit log gets the real exception
// (CONTRACTS §0.4, §4.4; B trap 2). Before the gate has let a request in, a
// failure says nothing at all.

import { test, assert, run } from '../helpers/t.js';
import { freshEnv, client, bootstrap, makeUser, auditRows, PASSWORD, OWNER_IP } from '../helpers/flows.js';

test('an unexpected failure is a 500 with one sentence, and the real error is audited', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const bob = await makeUser(env, owner.client, { email: 'bob@acme.com' });
  env.DB.failOn = /INSERT INTO device_users/;
  const r = await bob.client.post('/api/auth/login', { identifier: 'bob@acme.com', password: PASSWORD });
  env.DB.failOn = null;
  assert.equal(r.status, 500);
  assert.equal(r.text, '{"error":"Something went wrong."}');
  const err = auditRows(env, 'error').at(-1);
  assert.equal(err.severity, 'critical');
  assert.match(err.error, /injected failure for: INSERT INTO device_users/);
  assert.match(err.detail, /POST \/api\/auth\/login/);
  assert.equal(r.headers.get('cache-control'), 'no-store, no-cache, must-revalidate, private');
});

test('a failure before the gate has decided is an empty 403', async () => {
  const env = freshEnv();
  await bootstrap(env);
  env.DB.failOn = /FROM blocked_ips/;
  const r = await client(env, { ip: OWNER_IP }).get('/');
  env.DB.failOn = null;
  assert.equal(r.status, 403);
  assert.equal(r.text, '');
  assert.match(auditRows(env, 'error').at(-1).error, /injected failure/);
});

test('a page missing from the deploy is a 500, not a blank page', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const real = env.ASSETS;
  env.ASSETS = { fetch: async (req) => (new URL(req.url).pathname === '/dashboard.html' ? new Response('nope', { status: 404 }) : real.fetch(req)) };
  const r = await owner.client.get('/');
  assert.equal(r.status, 500);
  assert.match(auditRows(env, 'error').at(-1).error, /dashboard\.html is missing/);
});

await run();
