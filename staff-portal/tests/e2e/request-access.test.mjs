// Access requests from strangers (CONTRACTS §8.4; SPEC §6.8): one reply
// whatever the email, evidence recorded, five an hour per address.

import { test, assert, run } from '../helpers/t.js';
import { freshEnv, client, bootstrap, q, count, auditRows, setSetting, advance, HOUR, DAY, OWNER, HOSTILE } from '../helpers/flows.js';

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


// SPEC §6.4: the per-address brake keys on the network. A home line or a
// server is handed a whole IPv6 /64; per address it would have 2^64 buckets.
test('five requests an hour per IPv6 /64, however many addresses in it are used', async () => {
  const env = await world();
  let accepted = 0;
  for (let a = 1; a <= 40; a++) {
    const c = client(env, { ip: `2a02:ec80:600:ed1a:${a.toString(16)}::1` });
    const r = await c.post('/api/access-request', { email: `spam${a}@example.org`, full_name: 'Spam', reason: 'x'.repeat(1000) });
    if (r.status === 200) accepted++;
    else assert.equal(r.status, 429, r.text);
  }
  assert.equal(accepted, 5);
  assert.equal(count(env, 'SELECT COUNT(*) FROM access_requests'), 5);
  assert.equal(auditRows(env, 'request.create').length, 5);
  // The neighbouring /64 is someone else.
  assert.equal((await client(env, { ip: '2a02:ec80:600:ed1b::1' }).post('/api/access-request', { email: 'next@example.org', full_name: 'Next' })).status, 200);
});

// SPEC §13.4, §16.34: a table strangers write is trimmed by the write that
// grows it — by age, and by count.
test('access requests are trimmed by the write that grows them', async () => {
  const env = await world();
  for (let a = 1; a <= 4; a++) await client(env).post('/api/access-request', { email: `old${a}@example.org`, full_name: 'Old' });
  // One decided long ago, three left pending.
  q(env, "UPDATE access_requests SET status = 'denied', decided_at = created_at WHERE email = 'old1@example.org'");
  advance(env, 89 * DAY);
  await client(env).post('/api/access-request', { email: 'recent@example.org', full_name: 'Recent' });
  assert.equal(count(env, 'SELECT COUNT(*) FROM access_requests'), 5, '89 days: everything kept');
  advance(env, 2 * DAY);
  await client(env).post('/api/access-request', { email: 'new@example.org', full_name: 'New' });
  assert.deepEqual(
    q(env, 'SELECT email FROM access_requests ORDER BY id').map((r) => r.email),
    ['recent@example.org', 'new@example.org'],
    'requests made or decided over 90 days ago are gone, pending or not',
  );

  // And by count, the newest kept, however many networks a flood comes from.
  env.__retention = (k) => (k === 'access_requests' ? 10 : undefined);
  for (let a = 1; a <= 30; a++) await client(env).post('/api/access-request', { email: `flood${a}@example.org`, full_name: 'Flood' });
  const left = q(env, 'SELECT email FROM access_requests ORDER BY id').map((r) => r.email);
  assert.equal(left.length, 10);
  assert.equal(left.at(-1), 'flood30@example.org', 'the request just made is kept');
  env.__retention = () => 1_000_000;
  await client(env).post('/api/access-request', { email: 'more@example.org', full_name: 'More' });
  assert.equal(count(env, 'SELECT COUNT(*) FROM access_requests'), 11, '__retention can lower the cap, never raise it past 2,000');
});

// SPEC §16.34: a refused stranger must not grow auth_attempts either. The
// fingerprint report is the request shell's first call.
test('a stranger hammering a refused route adds no rate-limit rows past the limit', async () => {
  const env = await world();
  const c = client(env);
  const statuses = {};
  for (let i = 0; i < 300; i++) {
    const r = await c.post('/api/fp', { signals: { v: 1, tz: 'America/New_York' } });
    statuses[r.status] = (statuses[r.status] || 0) + 1;
  }
  assert.deepEqual(statuses, { 200: 30, 429: 270 });
  assert.equal(count(env, "SELECT COUNT(*) FROM auth_attempts WHERE kind = 'fp_ip'"), 30);
  for (let i = 0; i < 50; i++) await c.post('/api/access-request', { email: `p${i}@example.org`, full_name: 'P' });
  assert.equal(count(env, "SELECT COUNT(*) FROM auth_attempts WHERE kind = 'request_ip'"), 5);
});

await run();
