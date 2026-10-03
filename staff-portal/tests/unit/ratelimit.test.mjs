import { test, assert, run } from '../helpers/t.js';
import { makeEnvWithSchema } from '../helpers/env.js';
import { iso, HOUR, MINUTE, SECOND, DAY } from '../../src/util.js';
import { LIMITS, charge, peek, clear } from '../../src/ratelimit.js';

const HOSTILE = [null, undefined, NaN, Infinity, '', '   ', 'abc', {}, [], true, 0, Symbol('x')];
const show = (v) => (typeof v === 'symbol' ? 'Symbol' : JSON.stringify(v) ?? String(v));
const IP = '81.2.69.142';

function count(env, where = '1=1', ...args) {
  return env.DB.q(`SELECT COUNT(*) AS n FROM auth_attempts WHERE ${where}`, ...args)[0].n;
}

test('LIMITS are exactly §7.1', () => {
  assert.deepEqual(JSON.parse(JSON.stringify(LIMITS)), {
    login_ip: { max: 20, windowSec: 600 },
    login_id: { max: 10, windowSec: 900 },
    mfa_user: { max: 5, windowSec: 900 },
    otp_send: { max: 5, windowSec: 900 },
    setup_ip: { max: 5, windowSec: 3600 },
    curpw_user: { max: 10, windowSec: 900 },
    request_ip: { max: 5, windowSec: 3600 },
    fp_ip: { max: 30, windowSec: 600 },
    invite_ip: { max: 20, windowSec: 3600 },
    device_code_user: { max: 10, windowSec: 3600 },
  });
  assert.ok(Object.isFrozen(LIMITS));
  assert.ok(Object.isFrozen(LIMITS.login_ip));
});

test('charge: allowed while count ≤ max, refused on the next one', async () => {
  const env = await makeEnvWithSchema();
  for (let i = 1; i <= 20; i++) {
    const r = await charge(env, 'login_ip', IP, env.__clock());
    assert.equal(r.count, i);
    assert.equal(r.allowed, true, `attempt ${i}`);
    env.__advance(SECOND);
  }
  const r = await charge(env, 'login_ip', IP, env.__clock());
  assert.equal(r.count, 21);
  assert.equal(r.allowed, false);
  // A bucket that is already full refuses without writing (SPEC §16.34): a
  // stranger hammering a refused route cannot grow the table.
  assert.equal(count(env), 20);
  assert.equal((await charge(env, 'login_ip', IP, env.__clock())).count, 21);
  assert.equal(count(env), 20);
  // Other subjects and kinds are separate buckets.
  assert.equal((await charge(env, 'login_ip', '91.198.174.10', env.__clock())).count, 1);
  assert.equal((await charge(env, 'login_id', IP, env.__clock())).count, 1);
});

test('the window slides: attempts older than windowSec stop counting (boundary excluded)', async () => {
  const env = await makeEnvWithSchema();
  const t0 = env.__clock();
  for (let i = 0; i < 5; i++) await charge(env, 'mfa_user', '42', t0 + i * MINUTE);
  assert.equal((await charge(env, 'mfa_user', '42', t0 + 5 * MINUTE)).allowed, false);
  // Exactly 900 s after the first attempt, the first is out of the window.
  let r = await charge(env, 'mfa_user', '42', t0 + 900 * SECOND);
  assert.equal(r.count, 5, 'attempts at +1..+4 min plus this one (the refused one was never recorded)');
  assert.equal(r.allowed, true);
  r = await charge(env, 'mfa_user', '42', t0 + 30 * MINUTE);
  assert.equal(r.count, 1);
  assert.equal(r.allowed, true);
  assert.equal(await peek(env, 'mfa_user', '42', t0 + 30 * MINUTE), 1);
});

test('retryAfterSec is the time until the oldest in-window attempt ages out, at least 1', async () => {
  const env = await makeEnvWithSchema();
  const t0 = env.__clock();
  for (let i = 0; i < 20; i++) await charge(env, 'login_ip', IP, t0 + i * 10 * SECOND);
  let r = await charge(env, 'login_ip', IP, t0 + 300 * SECOND);
  assert.equal(r.allowed, false);
  assert.equal(r.retryAfterSec, 300, '600 s window, oldest at t0');
  r = await charge(env, 'login_ip', IP, t0 + 599 * SECOND + 500);
  assert.equal(r.retryAfterSec, 1, 'rounded up');
  const fresh = await makeEnvWithSchema();
  r = await charge(fresh, 'setup_ip', IP, fresh.__clock());
  assert.equal(r.retryAfterSec, 3600);
  assert.ok(r.retryAfterSec >= 1);
});

test('charge prunes rows older than a day, of every kind, in the same batch as the insert', async () => {
  const env = await makeEnvWithSchema();
  const now = env.__clock();
  env.DB.q('INSERT INTO auth_attempts (kind, subject, at) VALUES (?, ?, ?)', 'login_id', 'old@acme.com', iso(now - DAY - SECOND));
  env.DB.q('INSERT INTO auth_attempts (kind, subject, at) VALUES (?, ?, ?)', 'fp_ip', '1.1.1.1', iso(now - 2 * DAY));
  env.DB.q('INSERT INTO auth_attempts (kind, subject, at) VALUES (?, ?, ?)', 'otp_send', '9', iso(now - 23 * HOUR));
  const batches = [];
  const orig = env.DB.batch.bind(env.DB);
  env.DB.batch = (stmts) => {
    batches.push(stmts.map((s) => s.sql));
    return orig(stmts);
  };
  await charge(env, 'login_ip', IP, now);
  assert.equal(batches.length, 1, 'one batch');
  assert.ok(batches[0].some((s) => /^INSERT INTO auth_attempts/.test(s)));
  assert.ok(batches[0].some((s) => /^DELETE FROM auth_attempts WHERE at < \?/.test(s)));
  assert.equal(count(env, "subject = 'old@acme.com'"), 0);
  assert.equal(count(env, "subject = '1.1.1.1'"), 0);
  assert.equal(count(env, "subject = '9'"), 1, '23 hours old is kept');
  assert.equal(count(env), 2);
});

test('an unknown kind throws (a programming error) and writes nothing', async () => {
  const env = await makeEnvWithSchema();
  for (const k of ['login', 'LOGIN_IP', 'toString', '__proto__', 'constructor', ...HOSTILE]) {
    await assert.rejects(charge(env, k, IP, env.__clock()), /unknown kind/, show(k));
    await assert.rejects(peek(env, k, IP, env.__clock()), /unknown kind/, show(k));
    await assert.rejects(clear(env, k, IP), /unknown kind/, show(k));
  }
  assert.equal(count(env), 0);
});

test('subjects are capped at 200 characters; hostile subjects share one bucket and never throw', async () => {
  const env = await makeEnvWithSchema();
  const a = 'x'.repeat(200) + 'A'.repeat(300);
  const b = 'x'.repeat(200) + 'B';
  await charge(env, 'login_id', a, env.__clock());
  const r = await charge(env, 'login_id', b, env.__clock());
  assert.equal(r.count, 2, 'same first 200 characters → same bucket');
  assert.equal(env.DB.q('SELECT MAX(LENGTH(subject)) AS n FROM auth_attempts')[0].n, 200);
  await charge(env, 'mfa_user', 42, env.__clock());
  assert.equal((await charge(env, 'mfa_user', '42', env.__clock())).count, 2, 'a numeric id and its string are one bucket');
  const fresh = await makeEnvWithSchema();
  let n = 0;
  for (const v of HOSTILE) {
    if (typeof v === 'string' || (typeof v === 'number' && Number.isFinite(v))) continue;
    const res = await charge(fresh, 'login_id', v, fresh.__clock());
    assert.equal(res.count, ++n, `hostile subject ${show(v)}`);
  }
});

test('a hostile nowMs falls back to the env clock', async () => {
  const env = await makeEnvWithSchema();
  for (const v of HOSTILE) {
    if (typeof v === 'number' && Number.isFinite(v)) continue;
    await charge(env, 'fp_ip', IP, v);
  }
  const ats = env.DB.q('SELECT DISTINCT at FROM auth_attempts').map((r) => r.at);
  assert.deepEqual(ats, [iso(env.__clock())]);
  assert.equal(await peek(env, 'fp_ip', IP, NaN), HOSTILE.length - 1);
});

test('the max override: a valid one applies, an unreadable one falls back to the default', async () => {
  const env = await makeEnvWithSchema();
  for (let i = 0; i < 200; i++) await charge(env, 'login_ip', IP, env.__clock(), { max: 200 });
  assert.equal((await charge(env, 'login_ip', IP, env.__clock(), { max: 200 })).allowed, false);
  const fresh = await makeEnvWithSchema();
  for (const max of [0, -5, '', '  ', null, 'abc', true, {}, NaN, Infinity, 1.5]) {
    for (let i = 0; i < 20; i++) await charge(fresh, 'login_ip', `s${show(max)}`, fresh.__clock(), { max });
    const r = await charge(fresh, 'login_ip', `s${show(max)}`, fresh.__clock(), { max });
    assert.equal(r.allowed, false, `override ${show(max)} must not loosen the limit`);
  }
  for (const opts of [null, undefined, 'x', 5]) await charge(fresh, 'login_ip', 'o', fresh.__clock(), opts);
});

test('peek counts without charging; clear empties one bucket; login_ip can never be cleared', async () => {
  const env = await makeEnvWithSchema();
  const now = env.__clock();
  for (let i = 0; i < 3; i++) await charge(env, 'login_id', 'jane@acme.com', now);
  await charge(env, 'login_id', 'bob@acme.com', now);
  await charge(env, 'login_ip', IP, now);
  assert.equal(await peek(env, 'login_id', 'jane@acme.com', now), 3);
  assert.equal(await peek(env, 'login_id', 'jane@acme.com', now), 3, 'peek does not insert');
  await clear(env, 'login_id', 'jane@acme.com');
  assert.equal(await peek(env, 'login_id', 'jane@acme.com', now), 0);
  assert.equal(await peek(env, 'login_id', 'bob@acme.com', now), 1, 'other buckets untouched');
  await assert.rejects(clear(env, 'login_ip', IP), /never cleared/);
  assert.equal(await peek(env, 'login_ip', IP, now), 1, 'B trap 4: the per-IP bucket survives');
});

test('a stranger hammering a full bucket adds no rows past the limit (SPEC §16.34)', async () => {
  const env = await makeEnvWithSchema();
  let allowed = 0;
  for (let i = 0; i < 1000; i++) if ((await charge(env, 'fp_ip', IP, env.__clock())).allowed) allowed++;
  assert.equal(allowed, LIMITS.fp_ip.max);
  assert.equal(count(env), LIMITS.fp_ip.max, 'only the attempts that were let through are rows');
  // Once the window slides, the bucket opens again and is charged as before.
  env.__advance(LIMITS.fp_ip.windowSec * 1000 + SECOND);
  assert.equal((await charge(env, 'fp_ip', IP, env.__clock())).allowed, true);
});

test('concurrent attempts that all peeked under the limit are still refused past it', async () => {
  const env = await makeEnvWithSchema();
  const t = env.__clock();
  for (let i = 0; i < 18; i++) await charge(env, 'login_ip', IP, t);
  const r = await Promise.all(Array.from({ length: 6 }, () => charge(env, 'login_ip', IP, t)));
  assert.equal(r.filter((x) => x.allowed).length, 2, 'exactly the two left under 20');
});

test('per-address kinds key IPv6 on its /64 and IPv4 on the address (SPEC §6.4)', async () => {
  const env = await makeEnvWithSchema();
  const t = env.__clock();
  // One /64 handed to one line: every address in it is one bucket.
  for (let i = 1; i <= 20; i++) assert.equal((await charge(env, 'login_ip', `2a02:1210:5c00:9e00:${i.toString(16)}::1`, t)).allowed, true);
  assert.equal((await charge(env, 'login_ip', '2a02:1210:5c00:9e00:ffff:ffff:ffff:ffff', t)).allowed, false);
  assert.equal((await charge(env, 'login_ip', '2A02:1210:5C00:9E00::abcd', t)).allowed, false, 'any spelling of the same network');
  assert.equal(await peek(env, 'login_ip', '2a02:1210:5c00:9e00::7', t), 20);
  assert.deepEqual(env.DB.q('SELECT DISTINCT subject FROM auth_attempts').map((r) => r.subject), ['2a02:1210:5c00:9e00::/64']);
  // The next /64 is a different line.
  assert.equal((await charge(env, 'login_ip', '2a02:1210:5c00:9e01::1', t)).allowed, true);
  // IPv4 stays per address, including its IPv4-mapped IPv6 spelling.
  for (let i = 0; i < 20; i++) await charge(env, 'request_ip', `91.198.174.${10 + i}`, t);
  assert.equal(await peek(env, 'request_ip', '91.198.174.10', t), 1);
  assert.equal(await peek(env, 'request_ip', '::ffff:91.198.174.10', t), 1);
  // Every *_ip kind, not just login_ip; per-account kinds are untouched.
  for (const kind of ['setup_ip', 'request_ip', 'fp_ip', 'invite_ip']) {
    await charge(env, kind, '2001:4860:4860:1::8888', t);
    assert.equal(await peek(env, kind, '2001:4860:4860:1:dead:beef::1', t), 1, kind);
  }
  await charge(env, 'login_id', '2001:4860:4860:1::8888', t);
  assert.equal(await peek(env, 'login_id', '2001:4860:4860:1::1', t), 0);
  // An address that does not parse shares the one '?' bucket.
  await charge(env, 'setup_ip', 'not-an-ip', t);
  assert.equal(await peek(env, 'setup_ip', null, t), 1);
});

// CONTRACTS §0.2: an unreadable count is over the limit — on the peek that
// decides whether to write at all, and on the count after the write.
test('an unreadable count is treated as over the limit, before and after the insert', async () => {
  for (const at of ['peek', 'batch']) {
    const stmt = {
      bind() {
        return this;
      },
      first: async () => (at === 'peek' ? { n: 'x', oldest: null } : { n: 0, oldest: null }),
    };
    let wrote = false;
    const env = {
      DB: {
        prepare: () => stmt,
        batch: async () => {
          wrote = true;
          return [{}, {}, { results: [{ n: 'x', oldest: null }] }];
        },
      },
    };
    const r = await charge(env, 'login_ip', '185.15.56.1', 1_800_000_000_000);
    assert.equal(r.allowed, false, at);
    assert.equal(r.count, LIMITS.login_ip.max + 1, at);
    assert.equal(wrote, at === 'batch', `${at}: an unreadable peek writes nothing`);
  }
});

test('a database failure throws rather than allowing the attempt', async () => {
  const env = await makeEnvWithSchema();
  env.DB.failOn = /auth_attempts/;
  await assert.rejects(charge(env, 'login_ip', IP, env.__clock()));
  env.DB.failOn = null;
  env.DB.q('DROP TABLE auth_attempts');
  await assert.rejects(charge(env, 'login_ip', IP, env.__clock()));
});

await run();
