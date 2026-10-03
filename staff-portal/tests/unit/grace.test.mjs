import { test, assert, run } from '../helpers/t.js';
import { makeEnvWithSchema } from '../helpers/env.js';
import { iso, HOUR, DAY, MINUTE } from '../../src/util.js';
import { GRACE_MS, recordGrace, graceValid, dropGrace } from '../../src/grace.js';

const HOSTILE = [null, undefined, NaN, Infinity, '', '   ', 'abc', {}, [], true, 0, Symbol('x')];
const show = (v) => (typeof v === 'symbol' ? 'Symbol' : JSON.stringify(v) ?? String(v));
const rows = (env) => env.DB.q('SELECT user_id, device_id, tier FROM mfa_grace ORDER BY user_id, device_id');

test('GRACE_MS is A §8’s table: 7 days, 24 hours, 2 hours, never', () => {
  assert.deepEqual({ ...GRACE_MS }, { 1: 7 * DAY, 2: DAY, 3: 2 * HOUR, 4: 0 });
  assert.ok(Object.isFrozen(GRACE_MS));
});

for (const [tier, ms] of [[1, 7 * DAY], [2, DAY], [3, 2 * HOUR]]) {
  test(`tier ${tier}: valid until ${ms / HOUR}h after the proof, then not`, async () => {
    const env = await makeEnvWithSchema();
    const t0 = env.__clock();
    await recordGrace(env, 7, 'dev-1', tier, t0);
    assert.deepEqual(await graceValid(env, 7, 'dev-1', tier, t0), { valid: true, verifiedAt: t0 });
    assert.equal((await graceValid(env, 7, 'dev-1', tier, t0 + ms - 1)).valid, true);
    assert.deepEqual(await graceValid(env, 7, 'dev-1', tier, t0 + ms), { valid: false, verifiedAt: null });
  });
}

test('tier 4 records nothing and is never valid; no tier is never valid', async () => {
  const env = await makeEnvWithSchema();
  const t0 = env.__clock();
  await recordGrace(env, 7, 'dev-1', 4, t0);
  assert.deepEqual(rows(env), []);
  await recordGrace(env, 7, 'dev-1', 1, t0);
  assert.equal((await graceValid(env, 7, 'dev-1', 4, t0 + MINUTE)).valid, false, 'arriving on a tier-4 network costs a factor');
  for (const tier of [null, undefined, 0, 5, '', 'abc', NaN, Infinity, {}, [], true, Symbol('x')]) {
    assert.equal((await graceValid(env, 7, 'dev-1', tier, t0 + MINUTE)).valid, false, `tier ${show(tier)}`);
  }
});

test('a lower-trust network shortens the window; a higher one never lengthens it', async () => {
  const env = await makeEnvWithSchema();
  const t0 = env.__clock();
  await recordGrace(env, 7, 'dev-1', 1, t0);
  assert.equal((await graceValid(env, 7, 'dev-1', 3, t0 + 2 * HOUR - 1)).valid, true);
  assert.equal((await graceValid(env, 7, 'dev-1', 3, t0 + 2 * HOUR)).valid, false, 'tier 3 from a tier-1 proof: 2 hours');
  assert.equal((await graceValid(env, 7, 'dev-1', 2, t0 + 23 * HOUR)).valid, true);
  assert.equal((await graceValid(env, 7, 'dev-1', 2, t0 + DAY)).valid, false);
  assert.equal((await graceValid(env, 7, 'dev-1', 1, t0 + 6 * DAY)).valid, true, 'back on tier 1 the stored window still holds');

  await recordGrace(env, 8, 'dev-1', 3, t0);
  assert.equal((await graceValid(env, 8, 'dev-1', 1, t0 + 2 * HOUR)).valid, false, 'a tier-3 proof never buys tier 1’s week');
});

test('the window is per account AND per device', async () => {
  const env = await makeEnvWithSchema();
  const t0 = env.__clock();
  await recordGrace(env, 7, 'dev-1', 1, t0);
  assert.equal((await graceValid(env, 7, 'dev-2', 1, t0)).valid, false);
  assert.equal((await graceValid(env, 8, 'dev-1', 1, t0)).valid, false);
});

test('the latest proof replaces the row', async () => {
  const env = await makeEnvWithSchema();
  const t0 = env.__clock();
  await recordGrace(env, 7, 'dev-1', 1, t0);
  await recordGrace(env, 7, 'dev-1', 3, t0 + HOUR);
  assert.deepEqual(rows(env), [{ user_id: 7, device_id: 'dev-1', tier: 3 }]);
  assert.equal((await graceValid(env, 7, 'dev-1', 1, t0 + 3 * HOUR + 1)).valid, false);
  assert.equal((await graceValid(env, 7, 'dev-1', 1, t0 + 2 * HOUR)).valid, true);
});

test('stored values that do not read are invalid, never "valid forever" (A §14.3)', async () => {
  const env = await makeEnvWithSchema();
  const t0 = env.__clock();
  const put = (tier, verified, expires) => {
    env.DB.q('DELETE FROM mfa_grace');
    env.DB.q('INSERT INTO mfa_grace (user_id, device_id, tier, verified_at, expires_at) VALUES (7, ?, ?, ?, ?)', 'dev-1', tier, verified, expires);
  };
  const cases = [
    [1, 'yesterday', iso(t0 + DAY)],
    [1, iso(t0 - HOUR), '42'],
    [1, iso(t0 - HOUR), ''],
    [9, iso(t0 - HOUR), iso(t0 + DAY)],
    [0, iso(t0 - HOUR), iso(t0 + DAY)],
    ['one', iso(t0 - HOUR), iso(t0 + DAY)],
    [4, iso(t0 - HOUR), iso(t0 + DAY)],
    [1, iso(t0 + HOUR), iso(t0 + 2 * DAY)], // proof dated in the future: a clock moved
  ];
  for (const [tier, verified, expires] of cases) {
    put(tier, verified, expires);
    assert.equal((await graceValid(env, 7, 'dev-1', 1, t0)).valid, false, JSON.stringify([tier, verified, expires]));
  }
  // A tampered far-future expiry is capped by the stored tier's own window.
  put(3, iso(t0 - HOUR), '2999-01-01T00:00:00.000Z');
  assert.equal((await graceValid(env, 7, 'dev-1', 1, t0)).valid, true);
  assert.equal((await graceValid(env, 7, 'dev-1', 1, t0 + HOUR)).valid, false);
});

test('recordGrace with hostile arguments writes nothing; graceValid answers invalid', async () => {
  const env = await makeEnvWithSchema();
  const t0 = env.__clock();
  for (const v of HOSTILE) {
    await recordGrace(env, v, 'dev-1', 1, t0);
    if (v !== 'abc') await recordGrace(env, 7, v, 1, t0);
    await recordGrace(env, 7, 'dev-1', v, t0);
  }
  await recordGrace(env, 7, 'x'.repeat(129), 1, t0);
  assert.deepEqual(rows(env), []);
  await recordGrace(env, 7, 'dev-1', 1, t0);
  for (const v of HOSTILE) {
    assert.equal((await graceValid(env, v, 'dev-1', 1, t0)).valid, false, show(v));
    assert.equal((await graceValid(env, 7, v, 1, t0)).valid, false, show(v));
  }
});

test('dropGrace by user, by device, or both; hostile keys throw and drop nothing', async () => {
  const env = await makeEnvWithSchema();
  const t0 = env.__clock();
  const seed = async () => {
    env.DB.q('DELETE FROM mfa_grace');
    for (const [u, d] of [[7, 'a'], [7, 'b'], [8, 'a'], [8, 'b']]) await recordGrace(env, u, d, 1, t0);
  };
  await seed();
  await dropGrace(env, { userId: 7 });
  assert.deepEqual(rows(env).map((r) => `${r.user_id}${r.device_id}`), ['8a', '8b']);
  await seed();
  await dropGrace(env, { deviceId: 'a' });
  assert.deepEqual(rows(env).map((r) => `${r.user_id}${r.device_id}`), ['7b', '8b']);
  await seed();
  await dropGrace(env, { userId: '8', deviceId: 'b' });
  assert.deepEqual(rows(env).map((r) => `${r.user_id}${r.device_id}`), ['7a', '7b', '8a']);

  await seed();
  for (const v of HOSTILE.filter((x) => x !== null && x !== undefined)) {
    await assert.rejects(dropGrace(env, { userId: v }), Error, show(v));
    if (v !== 'abc' && v !== '   ') await assert.rejects(dropGrace(env, { deviceId: v }), Error, show(v));
  }
  for (const v of HOSTILE) await assert.rejects(dropGrace(env, v), Error, show(v));
  await assert.rejects(dropGrace(env, { userId: null, deviceId: undefined }), Error);
  assert.equal(rows(env).length, 4, 'a refused drop dropped nothing');
});

await run();
