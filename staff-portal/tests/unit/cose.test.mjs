// src/webauthn/cose.js — COSE → JWK and THE one validator (CONTRACTS §7.5;
// A §7.4 registration table, §14.5).

import { test, assert, run } from '../helpers/t.js';
import { coseToJwk, validatePublicKey, importVerifyKey, CoseError, SUPPORTED_ALGS } from '../../src/webauthn/cose.js';
import { b64u, fromB64u, emsaPkcs1v15 } from '../helpers/authenticator.js';

const HOSTILE = [null, undefined, NaN, Infinity, '', '   ', 'abc', {}, [], true, 0, Symbol('x')];
const show = (v) => (typeof v === 'symbol' ? 'Symbol' : JSON.stringify(v) ?? String(v));

function refuses(fn, reason, label) {
  assert.throws(fn, (e) => e instanceof CoseError && e.reason === reason, `${label} → expected CoseError ${reason}`);
}
async function refusesAsync(p, reason, label) {
  await assert.rejects(p, (e) => e instanceof CoseError && e.reason === reason, `${label} → expected CoseError ${reason}`);
}

let ecCache;
async function ec() {
  if (!ecCache) {
    const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    ecCache = { kp, jwk: await crypto.subtle.exportKey('jwk', kp.publicKey) };
  }
  return ecCache;
}
let rsaCache;
async function rsa() {
  if (!rsaCache) {
    const kp = await crypto.subtle.generateKey(
      { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: Uint8Array.from([1, 0, 1]), hash: 'SHA-256' },
      true,
      ['sign', 'verify'],
    );
    rsaCache = { kp, jwk: await crypto.subtle.exportKey('jwk', kp.publicKey) };
  }
  return rsaCache;
}

function ecCose(jwk, edits = {}) {
  const m = new Map([[1, 2], [3, -7], [-1, 1], [-2, fromB64u(jwk.x)], [-3, fromB64u(jwk.y)]]);
  for (const [k, v] of Object.entries(edits)) (v === undefined ? m.delete(Number(k)) : m.set(Number(k), v));
  return m;
}
function rsaCose(jwk, edits = {}) {
  const m = new Map([[1, 3], [3, -257], [-1, fromB64u(jwk.n)], [-2, fromB64u(jwk.e)]]);
  for (const [k, v] of Object.entries(edits)) (v === undefined ? m.delete(Number(k)) : m.set(Number(k), v));
  return m;
}

// An odd modulus of exactly `bits` bits (validation never factors it).
function modulus(bits, { odd = true } = {}) {
  const len = Math.ceil(bits / 8);
  const n = new Uint8Array(len).fill(0xa5);
  const top = bits - (len - 1) * 8;
  n[0] = (n[0] & ((1 << top) - 1)) | (1 << (top - 1));
  n[len - 1] = odd ? n[len - 1] | 1 : n[len - 1] & 0xfe;
  return b64u(n);
}

test('SUPPORTED_ALGS is exactly ES256 and RS256', () => {
  assert.deepEqual([...SUPPORTED_ALGS], [-7, -257]);
});

test('coseToJwk: a real P-256 key → the same public JWK, alg -7', async () => {
  const { jwk } = await ec();
  const out = coseToJwk(ecCose(jwk));
  assert.deepEqual(out, { jwk: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, alg: -7 });
});

test('coseToJwk: a real RSA key → the same n and e, alg -257', async () => {
  const { jwk } = await rsa();
  const out = coseToJwk(rsaCose(jwk));
  assert.deepEqual(out, { jwk: { kty: 'RSA', n: jwk.n, e: 'AQAB' }, alg: -257 });
});

test('coseToJwk: the algorithm label must match the key type, both directions', async () => {
  const { jwk: e } = await ec();
  const { jwk: r } = await rsa();
  refuses(() => coseToJwk(ecCose(e, { 3: -257 })), 'alg_mismatch', 'RS256 on an EC2 key');
  refuses(() => coseToJwk(rsaCose(r, { 3: -7 })), 'alg_mismatch', 'ES256 on an RSA key');
  refuses(() => coseToJwk(ecCose(e, { 1: 1 })), 'alg_mismatch', 'ES256 on an OKP key');
  refuses(() => coseToJwk(ecCose(e, { 1: undefined })), 'alg_mismatch', 'ES256 with no kty');
});

test('coseToJwk: only ES256 and RS256 are accepted', async () => {
  const { jwk } = await ec();
  for (const alg of [-8, -35, -36, -37, -258, -65535, 0, 1, '-7', null, undefined, true]) {
    refuses(() => coseToJwk(ecCose(jwk, { 3: alg })), 'alg_unsupported', `alg ${show(alg)}`);
  }
});

test('coseToJwk: P-256 only, coordinates exactly 32 bytes and byte strings', async () => {
  const { jwk } = await ec();
  const x = fromB64u(jwk.x);
  refuses(() => coseToJwk(ecCose(jwk, { '-1': 2 })), 'ec_curve', 'P-384');
  refuses(() => coseToJwk(ecCose(jwk, { '-1': 3 })), 'ec_curve', 'P-521');
  refuses(() => coseToJwk(ecCose(jwk, { '-1': undefined })), 'ec_curve', 'no curve');
  refuses(() => coseToJwk(ecCose(jwk, { '-2': x.slice(1) })), 'ec_coordinate', 'x 31 bytes');
  refuses(() => coseToJwk(ecCose(jwk, { '-3': Uint8Array.from([0, ...fromB64u(jwk.y)]) })), 'ec_coordinate', 'y 33 bytes');
  refuses(() => coseToJwk(ecCose(jwk, { '-2': jwk.x })), 'ec_coordinate', 'x as text');
  refuses(() => coseToJwk(ecCose(jwk, { '-3': true })), 'ec_coordinate', 'compressed-point sign bit');
  refuses(() => coseToJwk(ecCose(jwk, { '-3': undefined })), 'ec_coordinate', 'no y');
});

test('coseToJwk: unexpected labels — above all private-key members — are refused', async () => {
  const { jwk: e } = await ec();
  const { jwk: r } = await rsa();
  refuses(() => coseToJwk(ecCose(e, { '-4': new Uint8Array(32) })), 'cose_label', 'EC2 d');
  refuses(() => coseToJwk(ecCose(e, { 2: new Uint8Array(4) })), 'cose_label', 'kid');
  refuses(() => coseToJwk(rsaCose(r, { '-3': new Uint8Array(256) })), 'cose_label', 'RSA d');
  refuses(() => coseToJwk(rsaCose(r, { '-4': new Uint8Array(128) })), 'cose_label', 'RSA p');
});

test('coseToJwk: RSA n and e must be byte strings', async () => {
  const { jwk } = await rsa();
  refuses(() => coseToJwk(rsaCose(jwk, { '-1': jwk.n })), 'rsa_modulus', 'n as text');
  refuses(() => coseToJwk(rsaCose(jwk, { '-2': 65537 })), 'rsa_exponent', 'e as an integer');
  refuses(() => coseToJwk(rsaCose(jwk, { '-2': undefined })), 'rsa_exponent', 'no e');
});

test('coseToJwk: anything but a Map is refused', () => {
  for (const v of [...HOSTILE, new Map().entries(), Object.fromEntries([[1, 2], [3, -7]])]) {
    refuses(() => coseToJwk(v), 'cose_shape', show(v));
  }
});

test('validatePublicKey RSA: modulus 1024–8192 bits, minimal, odd', () => {
  const ok = (n) => validatePublicKey({ kty: 'RSA', n, e: 'AQAB' }, -257);
  ok(modulus(1024));
  ok(modulus(2048));
  ok(modulus(8192));
  refuses(() => ok(modulus(1023)), 'rsa_modulus', '1023 bits');
  refuses(() => ok(modulus(512)), 'rsa_modulus', '512 bits');
  refuses(() => ok(modulus(8193)), 'rsa_modulus', '8193 bits');
  refuses(() => ok(modulus(2048, { odd: false })), 'rsa_modulus', 'even');
  refuses(() => ok(b64u(Uint8Array.from([0, ...fromB64u(modulus(2048))]))), 'rsa_modulus', 'leading zero byte');
  refuses(() => ok(''), 'rsa_modulus', 'empty');
  refuses(() => ok('*not b64*'), 'rsa_modulus', 'not base64url');
  refuses(() => ok(undefined), 'rsa_modulus', 'missing');
});

test('validatePublicKey RSA: exponent odd, ≥ 3, minimal, at most 8 bytes', () => {
  const n = modulus(2048);
  const ok = (e) => validatePublicKey({ kty: 'RSA', n, e: b64u(Uint8Array.from(e)) }, -257);
  ok([3]);
  ok([1, 0, 1]);
  ok([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
  refuses(() => ok([1]), 'rsa_exponent', 'e = 1');
  refuses(() => ok([0]), 'rsa_exponent', 'e = 0');
  refuses(() => ok([2]), 'rsa_exponent', 'e = 2');
  refuses(() => ok([1, 0, 0]), 'rsa_exponent', 'e = 65536 (even)');
  refuses(() => ok([0, 3]), 'rsa_exponent', 'e = 00 03 (not minimal)');
  refuses(() => ok([1, 0, 0, 0, 0, 0, 0, 0, 1]), 'rsa_exponent', '9 bytes');
  refuses(() => ok([]), 'rsa_exponent', 'empty');
});

test('validatePublicKey EC: P-256, x and y exactly 32 bytes', async () => {
  const { jwk } = await ec();
  const base = { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
  validatePublicKey(base, -7);
  validatePublicKey({ ...base, alg: 'ES256', key_ops: ['verify'], ext: true }, -7);
  refuses(() => validatePublicKey({ ...base, crv: 'P-384' }, -7), 'ec_curve', 'P-384');
  refuses(() => validatePublicKey({ ...base, x: b64u(fromB64u(jwk.x).slice(1)) }, -7), 'ec_coordinate', 'x 31');
  refuses(() => validatePublicKey({ ...base, y: b64u(new Uint8Array(33)) }, -7), 'ec_coordinate', 'y 33');
  refuses(() => validatePublicKey({ ...base, y: undefined }, -7), 'ec_coordinate', 'y missing');
  refuses(() => validatePublicKey({ ...base, x: '+/++' + jwk.x.slice(4) }, -7), 'ec_coordinate', 'standard alphabet');
});

test('validatePublicKey: alg and kty must agree; JWK alg must agree; private members refused', async () => {
  const { jwk: e } = await ec();
  const { jwk: r } = await rsa();
  const ecPub = { kty: 'EC', crv: 'P-256', x: e.x, y: e.y };
  const rsaPub = { kty: 'RSA', n: r.n, e: r.e };
  refuses(() => validatePublicKey(ecPub, -257), 'alg_mismatch', 'EC key as RS256');
  refuses(() => validatePublicKey(rsaPub, -7), 'alg_mismatch', 'RSA key as ES256');
  refuses(() => validatePublicKey({ ...ecPub, alg: 'RS256' }, -7), 'alg_mismatch', 'JWK alg RS256 on ES256');
  refuses(() => validatePublicKey({ ...rsaPub, alg: 'PS256' }, -257), 'alg_mismatch', 'JWK alg PS256');
  for (const m of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k']) {
    refuses(() => validatePublicKey({ ...rsaPub, [m]: 'AQAB' }, -257), 'private_key', `member ${m}`);
  }
  refuses(() => validatePublicKey({ ...ecPub, d: e.x }, -7), 'private_key', 'EC d');
});

test('validatePublicKey: hostile keys and hostile algs throw CoseError, never TypeError', async () => {
  const { jwk } = await ec();
  const good = { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
  for (const v of HOSTILE) {
    assert.throws(() => validatePublicKey(v, -7), (e) => e instanceof CoseError, `jwk ${show(v)}`);
    assert.throws(() => validatePublicKey(good, v), (e) => e instanceof CoseError && e.reason === 'alg_unsupported', `alg ${show(v)}`);
    assert.throws(() => validatePublicKey({ ...good, x: v }, -7), (e) => e instanceof CoseError, `x ${show(v)}`);
    // 'abc' is valid base64url for 0x69b7 = 27063: odd, ≥ 3, a legitimate exponent.
    if (v === 'abc') validatePublicKey({ kty: 'RSA', n: modulus(2048), e: v }, -257);
    else assert.throws(() => validatePublicKey({ kty: 'RSA', n: modulus(2048), e: v }, -257), (e) => e instanceof CoseError, `e ${show(v)}`);
  }
  for (const alg of ['-7', -7.0000001, -8, null]) {
    refuses(() => validatePublicKey(good, alg), 'alg_unsupported', `alg ${show(alg)}`);
  }
});

test('e = 1: WebCrypto itself accepts a PKCS#1 "signature" forged with no private key; importVerifyKey refuses the key', async () => {
  const { jwk } = await rsa();
  const planted = { kty: 'RSA', n: jwk.n, e: 'AQ' };
  const data = new TextEncoder().encode('authData ‖ SHA-256(clientDataJSON)');
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', data));
  const forged = emsaPkcs1v15(digest, fromB64u(jwk.n).length);
  // The danger is real: an unvalidated import verifies the forgery.
  const raw = await crypto.subtle.importKey('jwk', planted, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  assert.equal(await crypto.subtle.verify('RSASSA-PKCS1-v1_5', raw, forged, data), true);
  // …and the real key does not.
  const real = await importVerifyKey({ kty: 'RSA', n: jwk.n, e: jwk.e }, -257);
  assert.equal(await crypto.subtle.verify('RSASSA-PKCS1-v1_5', real, forged, data), false);
  // The one validator stands in the way.
  await refusesAsync(importVerifyKey(planted, -257), 'rsa_exponent', 'planted e = 1');
  refuses(() => coseToJwk(rsaCose({ n: jwk.n, e: 'AQ' })), 'rsa_exponent', 'COSE e = 1');
});

test('importVerifyKey: imports only public members and the key verifies real signatures', async () => {
  const { kp, jwk } = await ec();
  const data = Uint8Array.from([9, 8, 7]);
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, data);
  // Extra JWK members that would make a direct importKey throw are ignored.
  const key = await importVerifyKey({ kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, key_ops: ['sign'], ext: false }, -7);
  assert.equal(key.type, 'public');
  assert.deepEqual(key.usages, ['verify']);
  assert.equal(key.extractable, false);
  assert.ok(await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, sig, data));
  const r = await rsa();
  const rk = await importVerifyKey({ kty: 'RSA', n: r.jwk.n, e: r.jwk.e }, -257);
  const rs = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', r.kp.privateKey, data);
  assert.ok(await crypto.subtle.verify('RSASSA-PKCS1-v1_5', rk, rs, data));
});

test('importVerifyKey: a P-256 point that is not on the curve is refused as key_import', async () => {
  const { jwk } = await ec();
  const y = fromB64u(jwk.y);
  y[31] ^= 1;
  await refusesAsync(importVerifyKey({ kty: 'EC', crv: 'P-256', x: jwk.x, y: b64u(y) }, -7), 'key_import', 'off-curve');
  await refusesAsync(importVerifyKey({ kty: 'EC', crv: 'P-256', x: b64u(new Uint8Array(32)), y: b64u(new Uint8Array(32)) }, -7), 'key_import', '(0,0)');
});

test('importVerifyKey runs the validator first: nothing reaches WebCrypto unvalidated', async () => {
  for (const v of HOSTILE) await assert.rejects(importVerifyKey(v, -7), (e) => e instanceof CoseError, `jwk ${show(v)}`);
  await refusesAsync(importVerifyKey({ kty: 'RSA', n: modulus(2048), e: 'Ag' }, -257), 'rsa_exponent', 'e = 2');
  await refusesAsync(importVerifyKey({ kty: 'RSA', n: modulus(1000), e: 'AQAB' }, -257), 'rsa_modulus', '1000 bits');
});

await run();
