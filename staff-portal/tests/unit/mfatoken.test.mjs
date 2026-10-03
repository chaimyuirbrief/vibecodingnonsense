import { test, assert, run } from '../helpers/t.js';
import { makeEnv } from '../helpers/env.js';
import { MINUTE } from '../../src/util.js';
import { signToken } from '../../src/crypto.js';
import { issueMfaToken, readMfaToken, MFA_TOKEN_TTL_MS } from '../../src/mfa/token.js';

const HOSTILE = [null, undefined, NaN, Infinity, '', '   ', 'abc', {}, [], true, 0, Symbol('x')];
const show = (v) => (typeof v === 'symbol' ? 'Symbol' : JSON.stringify(v) ?? String(v));

test('round trip: user and destination survive; no destination reads as null', async () => {
  const env = makeEnv();
  const t = env.__clock();
  assert.equal(MFA_TOKEN_TTL_MS, 5 * MINUTE);
  assert.deepEqual(await readMfaToken(env, await issueMfaToken(env, 42, 7, t), t), { userId: 42, destinationId: 7 });
  assert.deepEqual(await readMfaToken(env, await issueMfaToken(env, 42, null, t), t), { userId: 42, destinationId: null });
  assert.deepEqual(await readMfaToken(env, await issueMfaToken(env, 42, undefined, t), t), { userId: 42, destinationId: null });
});

test('the payload is exactly userId.destinationId.expiresAtMs and carries nothing secret', async () => {
  const env = makeEnv();
  const t = env.__clock();
  const tok = await issueMfaToken(env, 42, 7, t);
  const payload = tok.slice(0, tok.lastIndexOf('.'));
  assert.equal(payload, `42.7.${t + 5 * MINUTE}`);
  assert.ok(!tok.includes(env.SESSION_SECRET));
});

test('five minutes: valid one ms before expiry, refused at it', async () => {
  const env = makeEnv();
  const t = env.__clock();
  const tok = await issueMfaToken(env, 42, 7, t);
  assert.ok(await readMfaToken(env, tok, t + 5 * MINUTE - 1));
  assert.equal(await readMfaToken(env, tok, t + 5 * MINUTE), null);
  assert.equal(await readMfaToken(env, tok, t + 60 * MINUTE), null);
  // nowMs omitted or junk → the env clock, not "no expiry".
  env.__setNow(t + 6 * MINUTE);
  for (const v of [undefined, NaN, 'abc', null]) assert.equal(await readMfaToken(env, tok, v), null, show(v));
  env.__setNow(t + MINUTE);
  assert.ok(await readMfaToken(env, tok, undefined));
});

test('a token claiming to expire further out than we ever issue is refused (clock skew allowance only)', async () => {
  const env = makeEnv();
  const t = env.__clock();
  assert.ok(await readMfaToken(env, await signToken(env, 'mfa', `42.0.${t + 6 * MINUTE}`), t), 'one minute of skew');
  assert.equal(await readMfaToken(env, await signToken(env, 'mfa', `42.0.${t + 6 * MINUTE + 1}`), t), null);
  assert.equal(await readMfaToken(env, await signToken(env, 'mfa', `42.0.${t + 365 * 24 * 60 * MINUTE}`), t), null);
});

test('forged, re-purposed or re-keyed tokens are refused', async () => {
  const env = makeEnv();
  const t = env.__clock();
  const tok = await issueMfaToken(env, 42, 7, t);
  const mac = tok.slice(tok.lastIndexOf('.') + 1);
  assert.equal(await readMfaToken(env, `43.7.${t + 5 * MINUTE}.${mac}`, t), null, 'another user');
  assert.equal(await readMfaToken(env, `42.8.${t + 5 * MINUTE}.${mac}`, t), null, 'another destination');
  assert.equal(await readMfaToken(env, `42.7.${t + 10 * MINUTE}.${mac}`, t), null, 'a longer life');
  assert.equal(await readMfaToken(env, await signToken(env, 'device', `42.7.${t + MINUTE}`), t), null, 'device purpose');
  assert.equal(await readMfaToken(env, await signToken(env, 'fp', `42.7.${t + MINUTE}`), t), null, 'fp purpose');
  const other = makeEnv({ vars: { SESSION_SECRET: 'another-session-secret-0123456789abcdef0123456789' } });
  assert.equal(await readMfaToken(other, tok, t), null, 'a rotated secret');
  assert.equal(await readMfaToken(env, tok + 'x', t), null);
  assert.equal(await readMfaToken(env, tok.slice(0, -1), t), null);
});

test('strict payload shape even under a valid MAC: no signs, leading zeros, exponents or missing parts', async () => {
  const env = makeEnv();
  const t = env.__clock();
  const exp = t + MINUTE;
  for (const p of [
    `042.0.${exp}`, `42.07.${exp}`, `+42.0.${exp}`, `-42.0.${exp}`, `42.-1.${exp}`, `0.0.${exp}`, `42.0`, `42.0.0`, `42.0.${exp}.9`,
    ` 42.0.${exp}`, `42 .0.${exp}`, `4e1.0.${exp}`, `42.0.${exp / 1000}e3`, `42.0.${exp}.`, `42..${exp}`, `1.5.0.${exp}`,
    `99999999999999999.0.${exp}`, `42.0x7.${exp}`, `NaN.0.${exp}`, `Infinity.0.${exp}`, '', `42.0.0${exp}`,
  ]) {
    assert.equal(await readMfaToken(env, await signToken(env, 'mfa', p), t), null, p);
  }
});

test('readMfaToken: hostile tokens and clocks → null, never a throw', async () => {
  const env = makeEnv();
  for (const v of HOSTILE) {
    assert.equal(await readMfaToken(env, v, env.__clock()), null, show(v));
    assert.equal(await readMfaToken(env, v, v), null, show(v));
  }
  assert.equal(await readMfaToken(env, 'a'.repeat(5000), env.__clock()), null);
});

test('issueMfaToken refuses ids it could not read back', async () => {
  const env = makeEnv();
  for (const v of HOSTILE) await assert.rejects(issueMfaToken(env, v, 1, env.__clock()), RangeError, `user ${show(v)}`);
  for (const v of HOSTILE.filter((x) => x !== null && x !== undefined)) {
    await assert.rejects(issueMfaToken(env, 42, v, env.__clock()), RangeError, `dest ${show(v)}`);
  }
  for (const v of [-1, 1.5, 2 ** 53]) await assert.rejects(issueMfaToken(env, v, null, env.__clock()), RangeError);
});

await run();
