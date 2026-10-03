// The password gate (CONTRACTS §8.4 Auth; A §2, §6; B §5, trap 4; SPEC §6.3–6.4).

import { test, assert, run } from '../helpers/t.js';
import {
  freshEnv, client, bootstrap, makeUser, actorRc, roleId, q, count, auditRows, advance, setSetting, MINUTE, OWNER, OWNER_IP, HOSTILE, PASSWORD, SESSION_COOKIE,
} from '../helpers/flows.js';
import { createUser } from '../../src/users.js';

const INVALID = '{"error":"Invalid credentials."}';

async function world() {
  const env = freshEnv();
  const owner = await bootstrap(env);
  return { env, owner };
}

function assertInvalid(r, what) {
  assert.equal(r.status, 401, `${what}: ${r.text}`);
  assert.equal(r.text, INVALID, `${what}: identical bytes`);
  assert.equal(r.headers.get('content-type'), 'application/json; charset=utf-8', what);
  assert.equal(r.headers.get('set-cookie'), null, `${what}: no cookie of any kind`);
}

test('unknown, wrong, suspended, disabled, invited and locked all get the same 401 bytes; the log says which', async () => {
  const { env, owner } = await world();
  const bob = await makeUser(env, owner.client, { email: 'bob@acme.com' });
  const carol = await makeUser(env, owner.client, { email: 'carol@acme.com' });
  const dave = await makeUser(env, owner.client, { email: 'dave@acme.com' });
  const erin = await makeUser(env, owner.client, { email: 'erin@acme.com' });
  await createUser(await actorRc(env, owner.user), { email: 'ivy@acme.com', full_name: 'Ivy Invited', role_id: roleId(env, 'employee') });
  q(env, "UPDATE users SET status = 'suspended' WHERE id = ?", carol.user.id);
  q(env, "UPDATE users SET status = 'disabled' WHERE id = ?", erin.user.id);
  q(env, 'UPDATE users SET failed_logins = 10, locked_until = ? WHERE id = ?', new Date(env.__clock() + 10 * MINUTE).toISOString(), dave.user.id);
  const stranger = client(env, { ip: OWNER_IP });
  const before = count(env, 'SELECT COUNT(*) FROM sessions');
  const cases = [
    ['unknown', 'nobody@acme.com', PASSWORD, /No account called 'nobody@acme\.com'/],
    ['wrong password', 'bob@acme.com', 'not-the-password-0', /Wrong password for 'bob@acme\.com'/],
    ['suspended', 'carol@acme.com', PASSWORD, /account is suspended/],
    ['disabled', 'erin@acme.com', PASSWORD, /account is disabled/],
    ['invited (no password yet)', 'ivy@acme.com', PASSWORD, /Wrong password for 'ivy@acme\.com'/],
    ['locked, unknown device', 'dave@acme.com', PASSWORD, /locked after repeated failures/],
  ];
  for (const [what, identifier, password, detail] of cases) {
    const n = auditRows(env, 'login.fail').length;
    assertInvalid(await stranger.post('/api/auth/login', { identifier, password }), what);
    const rows = auditRows(env, 'login.fail');
    assert.equal(rows.length, n + 1, `${what}: one audit row`);
    assert.match(rows[rows.length - 1].detail, detail, what);
    assert.ok(!rows[rows.length - 1].detail.includes(password), `${what}: the password is not logged`);
  }
  assert.equal(count(env, 'SELECT COUNT(*) FROM sessions'), before, 'no session was created');
  assert.equal(auditRows(env, 'login.success').length, 5, 'only the setup and invitation sign-ins');
  void bob;
});

// SPEC §16.25–16.26: the password is checked BEFORE the account's state. A
// suspended or disabled account with a WRONG password is a wrong password —
// in the log too — and costs the same derivation as any other account, so
// neither the reply, the clock nor the log says "this one is suspended".
test('suspended and disabled accounts with a wrong password: a wrong password, at full cost', async () => {
  const { env, owner } = await world();
  const real = crypto.subtle.deriveBits.bind(crypto.subtle);
  async function attempt(identifier) {
    let derivations = 0;
    crypto.subtle.deriveBits = (...a) => {
      derivations++;
      return real(...a);
    };
    try {
      assertInvalid(await client(env, { ip: OWNER_IP }).post('/api/auth/login', { identifier, password: 'definitely-wrong-000' }), identifier);
    } finally {
      crypto.subtle.deriveBits = real;
    }
    return { derivations, detail: auditRows(env, 'login.fail').at(-1).detail };
  }
  await makeUser(env, owner.client, { email: 'active@acme.com' });
  const baseline = await attempt('active@acme.com');
  assert.ok(baseline.derivations >= 1);
  for (const [status, email] of [['suspended', 'sam@acme.com'], ['disabled', 'dina@acme.com']]) {
    const u = await makeUser(env, owner.client, { email });
    q(env, 'UPDATE users SET status = ? WHERE id = ?', status, u.user.id);
    const r = await attempt(email);
    assert.match(r.detail, /^Wrong password for/, `${status}: ${r.detail}`);
    assert.doesNotMatch(r.detail, /correct password|suspended|disabled/);
    assert.equal(r.derivations, baseline.derivations, `${status}: the same password work as an active account`);
  }
});

test('hostile identifiers and passwords get the same 401 and no session', async () => {
  const { env } = await world();
  const c = client(env, { ip: OWNER_IP });
  let i = 0;
  for (const v of HOSTILE) {
    // login_id allows ten a quarter-hour; hostile identifiers share one bucket.
    if (++i % 8 === 0) advance(env, 16 * MINUTE);
    assertInvalid(await c.post('/api/auth/login', { identifier: v, password: PASSWORD }), `identifier ${String(typeof v === 'symbol' ? 'Symbol' : JSON.stringify(v))}`);
    assertInvalid(await c.post('/api/auth/login', { identifier: OWNER.email, password: v }), `password ${String(typeof v === 'symbol' ? 'Symbol' : JSON.stringify(v))}`);
  }
  assertInvalid(await c.post('/api/auth/login', 'identifier=x&password=y', { 'content-type': 'application/x-www-form-urlencoded' }), 'form body');
  assertInvalid(await c.post('/api/auth/login', { identifier: 'x'.repeat(5000), password: 'y'.repeat(5000) }), 'oversized');
  assert.equal(c.jar.has(SESSION_COOKIE), false);
});

test('the per-IP bucket is never cleared, not even by a successful sign-in (B trap 4)', async () => {
  const { env, owner } = await world();
  const amy = await makeUser(env, owner.client, { email: 'amy@acme.com' });
  const ip = amy.client.ip; // not allowlisted: the 20-per-10-minutes bucket
  for (let i = 0; i < 19; i++) assertInvalid(await amy.client.post('/api/auth/login', { identifier: `ghost${i}@acme.com`, password: PASSWORD }), `spray ${i}`);
  const ok = await amy.client.post('/api/auth/login', { identifier: 'amy@acme.com', password: PASSWORD });
  assert.equal(ok.status, 200, 'the 20th attempt is still allowed, and succeeds');
  assert.equal(count(env, "SELECT COUNT(*) FROM auth_attempts WHERE kind = 'login_ip' AND subject = ?", ip), 20, 'success did not clear the per-IP bucket');
  const after = await amy.client.post('/api/auth/login', { identifier: 'amy@acme.com', password: PASSWORD });
  assert.equal(after.status, 429, 'the brake is still on after a success');
  assert.ok(Number(after.headers.get('retry-after')) > 0);
  advance(env, 10 * MINUTE + 1000);
  assert.equal((await amy.client.post('/api/auth/login', { identifier: 'amy@acme.com', password: PASSWORD })).status, 200);
});

test('an allowlisted address gets the higher per-IP ceiling', async () => {
  const { env } = await world();
  const c = client(env, { ip: OWNER_IP });
  for (let i = 0; i < 25; i++) {
    if (i && i % 9 === 0) advance(env, 16 * MINUTE); // keep clear of login_id; the IP window is longer than this loop's spread
    assertInvalid(await c.post('/api/auth/login', { identifier: `ghost${i}@acme.com`, password: PASSWORD }), `attempt ${i}`);
  }
});

// SPEC §6.4: login_ip is the only brake on spraying one guess across many
// accounts. Keyed per address, one IPv6 /64 — one home line, one server —
// would be 2^64 buckets and no brake at all.
test('one IPv6 /64 is one per-address bucket: rotating addresses inside it does not dodge the spray brake', async () => {
  const { env } = await world();
  setSetting(env, 'access_mode', 'public');
  const fails = auditRows(env, 'login.fail').length;
  const statuses = {};
  for (let i = 0; i < 50; i++) {
    const c = client(env, { ip: `2a01:4f8:c17:1a2b:${(i + 1).toString(16)}::1` });
    const r = await c.post('/api/auth/login', { identifier: `ghost${i}@acme.com`, password: PASSWORD });
    statuses[r.status] = (statuses[r.status] || 0) + 1;
  }
  assert.deepEqual(statuses, { 401: 20, 429: 30 });
  assert.equal(auditRows(env, 'login.fail').length - fails, 20, 'only the guesses let through reach the log');
  assert.equal(count(env, "SELECT COUNT(*) FROM auth_attempts WHERE kind = 'login_ip' AND subject = '2a01:4f8:c17:1a2b::/64'"), 20, 'refused attempts add no rows');
  // The neighbouring /64 is another line with its own bucket.
  assertInvalid(await client(env, { ip: '2a01:4f8:c17:1a2c::1' }).post('/api/auth/login', { identifier: 'ghost@acme.com', password: PASSWORD }), 'next /64');
});

test('the per-identifier bucket refuses the 11th try in 15 minutes, from any address', async () => {
  const { env, owner } = await world();
  await makeUser(env, owner.client, { email: 'bob@acme.com' });
  for (let i = 0; i < 10; i++) {
    assertInvalid(await client(env, { ip: OWNER_IP }).post('/api/auth/login', { identifier: 'Bob@Acme.com ', password: `wrong-${i}-password` }), `try ${i}`);
  }
  const r = await client(env, { ip: OWNER_IP }).post('/api/auth/login', { identifier: 'bob@acme.com', password: PASSWORD });
  assert.equal(r.status, 429, 'normalised identifiers share a bucket');
  assert.equal(count(env, "SELECT COUNT(*) FROM auth_attempts WHERE kind = 'login_id' AND subject = 'bob@acme.com'"), 10, 'the refused 11th is not recorded');
});

// SPEC §6.4: login_id's subject is the normalised identifier — the name the
// lookup matches. A username is matched on its first 32 characters, so every
// longer spelling of a 32-character username is the same account and must be
// the same bucket.
test('every spelling the lookup treats as one account is one login_id bucket', async () => {
  const { env, owner } = await world();
  const U = 'abcdefghijklmnopqrstuvwxyz012345';
  assert.equal(U.length, 32);
  const rc = await actorRc(env, owner.user);
  await createUser(rc, { email: 'long@acme.com', full_name: 'Long Name', role_id: roleId(env, 'employee'), username: U });
  const atk = client(env, { ip: OWNER_IP });
  const statuses = [];
  for (let i = 0; i < 15; i++) {
    const r = await atk.post('/api/auth/login', { identifier: ` ${U}${String.fromCharCode(97 + i)}`.toUpperCase(), password: `wrong-password-${i}` });
    statuses.push(r.status);
  }
  assert.deepEqual(statuses, [...Array(10).fill(401), ...Array(5).fill(429)]);
  assert.deepEqual(q(env, "SELECT DISTINCT subject FROM auth_attempts WHERE kind = 'login_id'").map((r) => r.subject), [U]);
});

// D6: "a stranger can lock an account against strangers, never against a
// device that has signed in to it before" — and that holds for the
// per-identifier bucket too, not only the account lock, for as long as the
// stranger keeps going.
test('a stranger spending the login_id bucket cannot keep the owner out of their own laptop', async () => {
  const { env, owner } = await world();
  setSetting(env, 'access_mode', 'public');
  const attacker = client(env, { ip: '185.15.56.77' });
  const elsewhere = client(env, { ip: '91.198.174.77' }); // the owner's password, on a device the account has never used
  for (let round = 0; round < 4; round++) {
    for (let i = 0; i < 11; i++) await attacker.post('/api/auth/login', { identifier: OWNER.email, password: `junk-${round}-${i}-xxxxx` });
    advance(env, 7 * MINUTE);
    const r = await owner.client.post('/api/auth/login', { identifier: OWNER.email, password: OWNER.password });
    assert.equal(r.status, 200, `round ${round}: ${r.text}`);
    assert.equal((await elsewhere.post('/api/auth/login', { identifier: OWNER.email, password: OWNER.password })).status, 429, `round ${round}: the account's bucket still holds for an unknown device`);
    advance(env, 8 * MINUTE);
  }
  // The laptop's own bucket is still a limit: ten wrong guesses from it, then 429.
  const fresh = await world();
  for (let i = 0; i < 10; i++) assertInvalid(await fresh.owner.client.post('/api/auth/login', { identifier: OWNER.email, password: `wrong-${i}-password` }), `own guess ${i}`);
  assert.equal((await fresh.owner.client.post('/api/auth/login', { identifier: OWNER.email, password: OWNER.password })).status, 429);
});

test('an office insider cannot keep the owner out of their own laptop either', async () => {
  const { env, owner } = await world();
  const insider = client(env, { ip: OWNER_IP });
  for (let i = 0; i < 11; i++) await insider.post('/api/auth/login', { identifier: OWNER.email, password: `junk-${i}-xxxxxxxx` });
  const r = await owner.client.post('/api/auth/login', { identifier: OWNER.email, password: OWNER.password });
  assert.equal(r.status, 200, r.text);
});

test('ten failures lock the account against strangers, never against a device that signed in to it before', async () => {
  const { env, owner } = await world();
  const dave = await makeUser(env, owner.client, { email: 'dave@acme.com' });
  const stranger = client(env, { ip: OWNER_IP });
  for (let i = 0; i < 10; i++) {
    assertInvalid(await stranger.post('/api/auth/login', { identifier: 'dave@acme.com', password: `wrong-${i}-password` }), `failure ${i}`);
    advance(env, MINUTE);
  }
  const row = q(env, 'SELECT failed_logins, locked_until FROM users WHERE id = ?', dave.user.id)[0];
  assert.equal(row.failed_logins, 10);
  assert.ok(row.locked_until > new Date(env.__clock()).toISOString());
  assert.match(auditRows(env, 'login.fail').at(-1).detail, /now locked/);
  advance(env, 6 * MINUTE); // the oldest failures leave the login_id window; the lock (15 min) holds
  assertInvalid(await stranger.post('/api/auth/login', { identifier: 'dave@acme.com', password: PASSWORD }), 'stranger with the right password');
  assert.match(auditRows(env, 'login.fail').at(-1).detail, /locked/);
  // Dave's own laptop, on its own (non-allowlisted) network, walks past the lock.
  const ok = await dave.client.post('/api/auth/login', { identifier: 'dave@acme.com', password: PASSWORD });
  assert.equal(ok.status, 200, ok.text);
  const cleared = q(env, 'SELECT failed_logins, locked_until FROM users WHERE id = ?', dave.user.id)[0];
  assert.deepEqual(cleared, { failed_logins: 0, locked_until: null });
});

test('a lock that is present but unreadable is a lock', async () => {
  const { env, owner } = await world();
  const dave = await makeUser(env, owner.client, { email: 'dave@acme.com' });
  q(env, "UPDATE users SET locked_until = 'not a date' WHERE id = ?", dave.user.id);
  assertInvalid(await client(env, { ip: OWNER_IP }).post('/api/auth/login', { identifier: 'dave@acme.com', password: PASSWORD }), 'unreadable lock');
  assert.equal((await dave.client.post('/api/auth/login', { identifier: 'dave@acme.com', password: PASSWORD })).status, 200);
});

test('lockdown: a stranger device is refused at the gate; a Super Admin still reaches the factor step', async () => {
  const { env, owner } = await world();
  await makeUser(env, owner.client, { email: 'bob@acme.com', ip: OWNER_IP });
  setSetting(env, 'access_mode', 'lockdown');
  const c = client(env, { ip: OWNER_IP });
  // A stranger device on the office network: lockdown needs an approved device too.
  assert.equal((await c.post('/api/auth/login', { identifier: 'bob@acme.com', password: PASSWORD })).status, 403);
  assert.equal((await c.post('/api/auth/login', { identifier: 'bob@acme.com', password: PASSWORD })).text, '');
  const ownerTry = await owner.client.post('/api/auth/login', { identifier: OWNER.email, password: OWNER.password });
  assert.equal(ownerTry.status, 200);
  assert.equal(ownerTry.body.mfa_required, true);
});

test('lockdown: a non-super on an approved device and allowlisted address gets 403 after the password', async () => {
  const { env, owner } = await world();
  const bob = await makeUser(env, owner.client, { email: 'bob@acme.com', ip: OWNER_IP });
  setSetting(env, 'access_mode', 'lockdown');
  const wrong = await bob.client.post('/api/auth/login', { identifier: 'bob@acme.com', password: 'wrong-password-00' });
  assertInvalid(wrong, 'wrong password in lockdown');
  const r = await bob.client.post('/api/auth/login', { identifier: 'bob@acme.com', password: PASSWORD });
  assert.equal(r.status, 403);
  assert.equal(r.body.code, 'lockdown');
  assert.equal(auditRows(env, 'login.denied').length, 1);
  // And the session bob already held stopped working (sessions.loadSession).
  assert.equal((await bob.client.get('/api/me')).status, 401);
});

await run();
