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
  // Charged before the check: refused attempts still count.
  assert.equal(count(env), 21);
  assert.equal((await charge(env, 'login_ip', IP, env.__clock())).count, 22);
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
  assert.equal(r.count, 6, 'attempts at +1..+5 min plus this one');
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
    const res = await charge(fresh, 'otp_send', v, fresh.__clock());
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

test('a database failure throws rather than allowing the attempt', async () => {
  const env = await makeEnvWithSchema();
  env.DB.failOn = /auth_attempts/;
  await assert.rejects(charge(env, 'login_ip', IP, env.__clock()));
  env.DB.failOn = null;
  env.DB.q('DROP TABLE auth_attempts');
  await assert.rejects(charge(env, 'login_ip', IP, env.__clock()));
});

await run();
