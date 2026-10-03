// COSE public keys → JWK, and THE one public-key validator (CONTRACTS §0.8).
//
// Under attestation 'none' registration verifies no signature at all, so the
// key that arrives is entirely attacker-chosen (A §14.5): modulus, exponent,
// curve, coordinates and the algorithm label. validatePublicKey checks every
// one of those parameters and runs at enrolment AND on the stored copy before
// every assertion, because a database column is not a trust boundary
// (A §7.4). importVerifyKey calls it, so nothing can import a key unvalidated.
//
// The exponent is the one that matters: RSASSA-PKCS1-v1_5 verification is
// s^e mod n, and with e = 1 the "signature" is just the PKCS#1 encoding of the
// digest — anyone holding the public key can write it down. e = 0 never
// verifies, an even e is not an RSA key, and a megabyte-long e is not
// something to agree to exponentiate by.

import { b64urlEncode, b64urlDecode } from '../util.js';

export const ALG_ES256 = -7;
export const ALG_RS256 = -257;
export const SUPPORTED_ALGS = Object.freeze([ALG_ES256, ALG_RS256]);

export class CoseError extends Error {
  constructor(reason, message) {
    super(`cose: ${message}`);
    this.name = 'CoseError';
    this.reason = reason;
  }
}

// COSE labels: RFC 9052 (common), RFC 9053 (EC2), RFC 8230 (RSA).
const L_KTY = 1;
const L_ALG = 3;
const KTY_EC2 = 2;
const KTY_RSA = 3;
const CRV_P256 = 1;
// What an authenticator sends, and nothing else — no kid, no key_ops, and
// above all no private-key members (EC2 -4 = d; RSA -3.. = d, p, q, …).
const EC2_LABELS = new Set([L_KTY, L_ALG, -1, -2, -3]);
const RSA_LABELS = new Set([L_KTY, L_ALG, -1, -2]);

const JWK_PRIVATE = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];
const JWK_ALG = { [ALG_ES256]: 'ES256', [ALG_RS256]: 'RS256' };

const RSA_MIN_BITS = 1024;
const RSA_MAX_BITS = 8192;
const RSA_MAX_EXPONENT_BYTES = 8;

function checkLabels(cose, allowed) {
  for (const k of cose.keys()) {
    if (!allowed.has(k)) throw new CoseError('cose_label', `unexpected COSE key label ${JSON.stringify(k)}`);
  }
}

function bytesOrThrow(v, reason, what) {
  if (!(v instanceof Uint8Array)) throw new CoseError(reason, `${what} is not a byte string`);
  return v;
}

// → { jwk, alg }. Throws CoseError; the result has passed validatePublicKey.
export function coseToJwk(cose) {
  if (!(cose instanceof Map)) throw new CoseError('cose_shape', 'COSE key is not a map');
  const kty = cose.get(L_KTY);
  const alg = cose.get(L_ALG);
  let jwk;
  if (alg === ALG_ES256) {
    // The label must agree with the key type: a key claiming ES256 is
    // imported as EC P-256 or not at all (A §7.4).
    if (kty !== KTY_EC2) throw new CoseError('alg_mismatch', 'ES256 claimed on a non-EC2 key');
    checkLabels(cose, EC2_LABELS);
    if (cose.get(-1) !== CRV_P256) throw new CoseError('ec_curve', 'curve is not P-256');
    const x = bytesOrThrow(cose.get(-2), 'ec_coordinate', 'x');
    const y = bytesOrThrow(cose.get(-3), 'ec_coordinate', 'y');
    jwk = { kty: 'EC', crv: 'P-256', x: b64urlEncode(x), y: b64urlEncode(y) };
  } else if (alg === ALG_RS256) {
    if (kty !== KTY_RSA) throw new CoseError('alg_mismatch', 'RS256 claimed on a non-RSA key');
    checkLabels(cose, RSA_LABELS);
    const n = bytesOrThrow(cose.get(-1), 'rsa_modulus', 'n');
    const e = bytesOrThrow(cose.get(-2), 'rsa_exponent', 'e');
    jwk = { kty: 'RSA', n: b64urlEncode(n), e: b64urlEncode(e) };
  } else {
    throw new CoseError('alg_unsupported', `algorithm ${JSON.stringify(alg)} is not offered`);
  }
  validatePublicKey(jwk, alg);
  return { jwk, alg };
}

function bitLength(bytes) {
  return (bytes.length - 1) * 8 + (32 - Math.clz32(bytes[0]));
}

// Throws CoseError with a machine reason; returns nothing. Applies to keys
// from an authenticator and to keys read back from the database alike.
export function validatePublicKey(jwk, alg) {
  if (!jwk || typeof jwk !== 'object' || Array.isArray(jwk)) throw new CoseError('key_shape', 'key is not an object');
  for (const m of JWK_PRIVATE) {
    if (Object.hasOwn(jwk, m)) throw new CoseError('private_key', 'key carries private material');
  }
  if (alg !== ALG_ES256 && alg !== ALG_RS256) throw new CoseError('alg_unsupported', 'algorithm not supported');
  if (jwk.alg !== undefined && jwk.alg !== JWK_ALG[alg]) throw new CoseError('alg_mismatch', 'JWK alg disagrees');

  if (alg === ALG_ES256) {
    if (jwk.kty !== 'EC') throw new CoseError('alg_mismatch', 'ES256 on a non-EC key');
    if (jwk.crv !== 'P-256') throw new CoseError('ec_curve', 'curve is not P-256');
    const x = b64urlDecode(jwk.x);
    const y = b64urlDecode(jwk.y);
    if (!x || x.length !== 32 || !y || y.length !== 32) {
      throw new CoseError('ec_coordinate', 'P-256 coordinates must be exactly 32 bytes');
    }
    return;
  }

  if (jwk.kty !== 'RSA') throw new CoseError('alg_mismatch', 'RS256 on a non-RSA key');
  const n = b64urlDecode(jwk.n);
  // Minimal encoding (RFC 7518 §6.3.1): a leading zero would let the byte
  // length overstate the modulus size.
  if (!n || n.length === 0 || n[0] === 0) throw new CoseError('rsa_modulus', 'modulus missing or not minimal');
  const bits = bitLength(n);
  if (bits < RSA_MIN_BITS || bits > RSA_MAX_BITS) throw new CoseError('rsa_modulus', `modulus is ${bits} bits`);
  if ((n[n.length - 1] & 1) === 0) throw new CoseError('rsa_modulus', 'modulus is even');
  const e = b64urlDecode(jwk.e);
  if (!e || e.length === 0 || e[0] === 0) throw new CoseError('rsa_exponent', 'exponent missing or not minimal');
  if (e.length > RSA_MAX_EXPONENT_BYTES) throw new CoseError('rsa_exponent', 'exponent wider than 8 bytes');
  if ((e[e.length - 1] & 1) === 0) throw new CoseError('rsa_exponent', 'exponent is even');
  // Odd and minimal, so the only values below 3 are a single byte 0x01.
  if (e.length === 1 && e[0] < 3) throw new CoseError('rsa_exponent', 'exponent below 3');
}

// Validates, then imports only the public members (anything else in a stored
// JWK — key_ops, ext — is not ours to honour).
export async function importVerifyKey(jwk, alg) {
  validatePublicKey(jwk, alg);
  const clean = alg === ALG_ES256 ? { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y } : { kty: 'RSA', n: jwk.n, e: jwk.e };
  const algorithm = alg === ALG_ES256 ? { name: 'ECDSA', namedCurve: 'P-256' } : { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
  try {
    return await crypto.subtle.importKey('jwk', clean, algorithm, false, ['verify']);
  } catch (e) {
    // e.g. a P-256 point that is not on the curve.
    throw new CoseError('key_import', `WebCrypto refused the key: ${e && e.message}`);
  }
}
