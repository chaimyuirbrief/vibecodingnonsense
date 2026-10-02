// Access requests from strangers (CONTRACTS §8.4; SPEC §6.8): one reply
// whatever the email, evidence recorded, five an hour per address.

import { test, assert, run } from '../helpers/t.js';
import { freshEnv, client, bootstrap, q, count, auditRows, setSetting, advance, HOUR, OWNER, HOSTILE } from '../helpers/flows.js';

async function world() {
  const env = freshEnv();
  await bootstrap(env);
  setSetting(env, 'access_mode', 'request_access');
  return env;
}

test('the reply is identical whether or not the email belongs to someone', async () => {
  const env = await world();
  const a = await client(env).post('/api/access-request', { email: 'stranger@example.org', full_name: 'Sam Stranger', reason: 'New contractor' });
  const b = await client(env).post('/api/access-request', { email: OWNER.email, full_name: 'Not The Owner', reason: 'hello' });
  assert.equal(a.status, 200);
  assert.equal(a.text, b.text);
  assert.equal(a.text, '{"ok":true}');
  const rows = q(env, 'SELECT * FROM access_requests ORDER BY id');
  assert.equal(rows.length, 2);
  assert.equal(rows[0].country, 'US');
  assert.match(rows[0].ip, /^\d+\.\d+\.\d+\.\d+$/);
  assert.equal(rows[0].status, 'pending');
  assert.equal(auditRows(env, 'request.create').length, 2);
  // A second pending request for the same address is not stored twice.
  await client(env).post('/api/access-request', { email: 'Stranger@Example.org', full_name: 'Sam again' });
  assert.equal(count(env, 'SELECT COUNT(*) FROM access_requests'), 2);
});

test('hostile fields are validation errors and store nothing', async () => {
  const env = await world();
  let n = 0;
  for (const field of ['email', 'full_name']) {
    for (const v of HOSTILE) {
      if (field === 'full_name' && v === 'abc') continue; // a fine name
      if (n++ % 5 === 4) advance(env, HOUR);
      const r = await client(env).post('/api/access-request', { email: 'sam@example.org', full_name: 'Sam', [field]: v });
      assert.equal(r.status, 400, `${field} ${String(typeof v === 'symbol' ? 'Symbol' : JSON.stringify(v))}: ${r.text}`);
    }
  }
  const long = await client(env).post('/api/access-request', { email: 'sam@example.org', full_name: 'Sam', reason: 'x'.repeat(1001) });
  assert.equal(long.status, 400);
  assert.equal(count(env, 'SELECT COUNT(*) FROM access_requests'), 0);
});

test('five requests an hour per address', async () => {
  const env = await world();
  const c = client(env);
  for (let i = 0; i < 5; i++) assert.equal((await c.post('/api/access-request', { email: `p${i}@example.org`, full_name: `P ${i}` })).status, 200);
  assert.equal((await c.post('/api/access-request', { email: 'p9@example.org', full_name: 'P 9' })).status, 429);
  assert.equal(count(env, 'SELECT COUNT(*) FROM access_requests'), 5);
});

await run();
