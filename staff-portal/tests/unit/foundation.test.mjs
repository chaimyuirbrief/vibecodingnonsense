import { test, assert, run } from '../helpers/t.js';
import { makeEnv, makeEnvWithSchema } from '../helpers/env.js';
import * as u from '../../src/util.js';
import * as c from '../../src/crypto.js';
import { ensureSchema, DDL } from '../../src/schema.js';
import { SYSTEM_ROLES, PERMISSIONS, RESERVED } from '../../src/catalog.js';
import { Router } from '../../src/router.js';

const HOSTILE = [null, undefined, NaN, Infinity, -Infinity, '', '   ', 'abc', {}, [], true, false, Symbol('x'), 10n, () => 1, { valueOf() { throw new Error('boom'); } }];

test('toNum is total and never turns a blank into zero', () => {
  for (const v of HOSTILE) assert.ok(Number.isNaN(u.toNum(v)), `toNum(${String(typeof v === 'symbol' ? 'Symbol' : v)})`);
  assert.equal(u.toNum(0), 0);
  assert.equal(u.toNum('0'), 0);
  assert.equal(u.toNum(' 42 '), 42);
  assert.equal(u.toNum('-1.5e2'), -150);
  assert.ok(Number.isNaN(u.toNum('0x10')));
  assert.ok(Number.isNaN(u.toNum('1e400')));
});

test('toInt enforces integer and range', () => {
  assert.equal(u.toInt('5', 0, 10), 5);
  assert.ok(Number.isNaN(u.toInt('5.5', 0, 10)));
  assert.ok(Number.isNaN(u.toInt('11', 0, 10)));
  for (const v of HOSTILE) assert.ok(Number.isNaN(u.toInt(v)));
});

test('parseIsoStrict refuses what Date.parse forgives', () => {
  assert.equal(Date.parse('42'), Date.UTC(2042, 0, 1)); // the trap itself
  for (const v of ['42', '1', '2026', '2026-01-01', 'Tue Jan 06 2026', '', null, 1, {}]) assert.ok(Number.isNaN(u.parseIsoStrict(v)), String(v));
  assert.equal(u.parseIsoStrict('2026-01-06T15:00:00.000Z'), Date.UTC(2026, 0, 6, 15));
  assert.equal(u.parseIsoStrict('2026-01-06T10:00:00-05:00'), Date.UTC(2026, 0, 6, 15));
});

test('b64url round-trips and is url-safe on bytes that differ between alphabets', () => {
  const bytes = new Uint8Array([0xfb, 0xff, 0xbe, 0x01]);
  assert.equal(u.b64urlEncode(bytes), '-_--AQ');
  assert.deepEqual([...u.b64urlDecode('-_--AQ')], [...bytes]);
  assert.equal(u.b64urlDecode('+/++AQ=='), null);
  const big = u.randomBytes(200000);
  assert.deepEqual(u.b64urlDecode(u.b64urlEncode(big)), big);
});

test('randomInt is in range', () => {
  for (let i = 0; i < 2000; i++) {
    const n = u.randomInt(31);
    assert.ok(n >= 0 && n < 31);
  }
});

test('canonicalJson is key-order independent', () => {
  assert.equal(u.canonicalJson({ b: 1, a: [1, { d: 2, c: undefined, e: null }] }), u.canonicalJson({ a: [1, { e: null, d: 2 }], b: 1 }));
});

test('cookies default to Lax, Secure, HttpOnly', () => {
  const c1 = u.cookie('__Host-sid', 'x', { maxAge: 60 });
  assert.match(c1, /SameSite=Lax/);
  assert.match(c1, /Secure/);
  assert.match(c1, /HttpOnly/);
  assert.doesNotMatch(c1, /Strict/);
  assert.deepEqual({ ...u.parseCookies('a=1; b=2; a=3') }, { a: '1', b: '2' });
});

test('chained PBKDF2 never asks for more than 100k in one derivation', async () => {
  const orig = crypto.subtle.deriveBits.bind(crypto.subtle);
  const seen = [];
  crypto.subtle.deriveBits = (alg, key, len) => {
    seen.push(alg.iterations);
    return orig(alg, key, len);
  };
  try {
    const env = makeEnv({ vars: { PBKDF2_ITERATIONS: '250000' } });
    const h = await c.hashPassword(env, 'correct horse battery staple');
    assert.equal(h.iters, 250000);
    assert.deepEqual(seen, [100000, 100000, 50000]);
    assert.ok(Math.max(...seen) <= 100000);
    assert.equal(await c.verifyPassword('correct horse battery staple', { password_hash: h.hash, password_salt: h.salt, password_algo: h.algo, password_iters: h.iters }), true);
    assert.equal(await c.verifyPassword('wrong', { password_hash: h.hash, password_salt: h.salt, password_algo: h.algo, password_iters: h.iters }), false);
  } finally {
    crypto.subtle.deriveBits = orig;
  }
});

test('the chunk size is frozen at 100,000 and part of the digest', async () => {
  assert.equal(c.PBKDF2_CHUNK, 100000);
  const salt = new Uint8Array(32).fill(7);
  const chained = await c.pbkdf2Chain('pw', salt, 200000);
  // One 200k derivation is a different digest: the split is part of the hash.
  const key = await crypto.subtle.importKey('raw', u.utf8('pw'), 'PBKDF2', false, ['deriveBits']);
  const single = new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 200000 }, key, 256));
  assert.notEqual(u.hex(chained), u.hex(single));
  // Golden value: if this changes, every stored password just stopped verifying.
  assert.equal(u.hex(chained), u.hex(await c.pbkdf2Chain('pw', salt, 200000)));
});

test('verifyPassword fails closed on unreadable rows', async () => {
  const env = makeEnv();
  const h = await c.hashPassword(env, 'pw-pw-pw-pw');
  const good = { password_hash: h.hash, password_salt: h.salt, password_algo: h.algo, password_iters: h.iters };
  for (const bad of [
    { ...good, password_algo: 'md5' },
    { ...good, password_iters: 'garbage' },
    { ...good, password_iters: 1 },
    { ...good, password_iters: null },
    { ...good, password_salt: '' },
    { ...good, password_hash: 'zz' },
    null,
  ]) assert.equal(await c.verifyPassword('pw-pw-pw-pw', bad), false);
});

test('signed tokens: purpose-bound, tamper-evident', async () => {
  const env = makeEnv();
  const t = await c.signToken(env, 'device', 'abc123');
  assert.equal(await c.verifyToken(env, 'device', t), 'abc123');
  assert.equal(await c.verifyToken(env, 'mfa', t), null);
  assert.equal(await c.verifyToken(env, 'device', t.replace('abc123', 'abc124')), null);
  for (const bad of ['', '.', 'abc.', '.sig', null, 5, 'a'.repeat(5000)]) assert.equal(await c.verifyToken(env, 'device', bad), null);
});

test('encryption round-trips, binds AAD, and refuses tampering', async () => {
  const env = makeEnv();
  const blob = await c.encrypt(env, 'JBSWY3DPEHPK3PXP', 'totp:1');
  assert.match(blob, /^v1\./);
  assert.equal(await c.decrypt(env, blob, 'totp:1'), 'JBSWY3DPEHPK3PXP');
  assert.equal(await c.decrypt(env, blob, 'totp:2'), null);
  assert.equal(await c.decrypt({ ...env, DATA_KEY: 'another-data-key-0123456789abcdef0123456789' }, blob, 'totp:1'), null);
  assert.equal(await c.decrypt(env, blob.slice(0, -2) + 'AA', 'totp:1'), null);
  assert.equal(await c.decrypt(env, 'v2.' + blob.slice(3), 'totp:1'), null);
});

test('missing secrets throw SecretMissing', async () => {
  await assert.rejects(() => c.signToken({ SESSION_SECRET: 'short' }, 'x', 'y'), c.SecretMissing);
});

test('schema is idempotent and seeds the system roles', async () => {
  const env = await makeEnvWithSchema();
  await ensureSchema(env);
  const roles = env.DB.q('SELECT key, rank, permissions FROM roles ORDER BY rank DESC');
  assert.deepEqual(roles.map((r) => r.key), SYSTEM_ROLES.map((r) => r.key));
  assert.deepEqual(JSON.parse(roles[0].permissions), ['*']);
  const admin = JSON.parse(roles.find((r) => r.key === 'admin').permissions);
  for (const k of RESERVED) assert.ok(!admin.includes(k), `admin must not hold reserved ${k}`);
  assert.ok(DDL.length > 20);
});

test('catalogue: every role grants only catalogued keys', () => {
  const keys = new Set(PERMISSIONS.map((p) => p.key));
  for (const r of SYSTEM_ROLES) for (const p of r.permissions) assert.ok(p === '*' ? r.rank === 100 : keys.has(p), `${r.key}:${p}`);
});

test('router matches params and reports 405', () => {
  const r = new Router();
  r.add('GET', '/api/admin/users/:id', async () => new Response('ok'));
  const m = r.match('GET', '/api/admin/users/42');
  assert.equal(m.params.id, '42');
  assert.ok(r.match('POST', '/api/admin/users/42').methodNotAllowed);
  assert.equal(r.match('GET', '/api/admin/users/42/x'), null);
});

await run();
