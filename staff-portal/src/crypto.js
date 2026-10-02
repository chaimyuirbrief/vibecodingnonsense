// Password hashing, HMAC signing, at-rest encryption. WebCrypto only.
//
// Two secrets, deliberately separate (SPEC §11 "Rotating the server secret"):
//   SESSION_SECRET  signs device cookies, MFA tokens and fingerprint cookies.
//                   Rotating it signs everyone out — annoying, recoverable.
//   DATA_KEY        derives the AES-GCM key for secrets stored at rest (TOTP).
//                   Rotating it without re-encrypting kills every
//                   authenticator app, so it is never the same secret.

import { utf8, hex, fromHex, b64urlEncode, b64urlDecode, randomBytes, toInt, fromUtf8 } from './util.js';

// ---------------------------------------------------------------- secrets

export class SecretMissing extends Error {
  constructor(name) {
    super(`secret ${name} is missing or shorter than 32 characters`);
    this.name = 'SecretMissing';
  }
}

export function requireSecret(env, name) {
  const v = env && env[name];
  if (typeof v !== 'string' || v.length < 32) throw new SecretMissing(name);
  return v;
}

// ---------------------------------------------------------------- digests

export async function sha256(data) {
  const bytes = typeof data === 'string' ? utf8(data) : data;
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

export async function sha256Hex(data) {
  return hex(await sha256(data));
}

// Constant-time equality: hash both sides to fixed-length digests, then
// compare every byte. Never `===` two secrets.
export async function timingSafeEqual(a, b) {
  const da = await sha256(typeof a === 'string' ? utf8(a) : a);
  const db = await sha256(typeof b === 'string' ? utf8(b) : b);
  let diff = 0;
  for (let i = 0; i < da.length; i++) diff |= da[i] ^ db[i];
  return diff === 0;
}

// ---------------------------------------------------------------- HMAC

const hmacKeys = new Map();

async function hmacKey(secret) {
  let k = hmacKeys.get(secret);
  if (!k) {
    k = await crypto.subtle.importKey('raw', utf8(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    if (hmacKeys.size > 16) hmacKeys.clear();
    hmacKeys.set(secret, k);
  }
  return k;
}

export async function hmac(secret, message) {
  const key = await hmacKey(secret);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, typeof message === 'string' ? utf8(message) : message));
}

export async function hmacHex(secret, message) {
  return hex(await hmac(secret, message));
}

// `<payload>.<b64url(HMAC(SESSION_SECRET, purpose + "." + payload))>`
// The purpose prefix stops a token minted for one job being replayed as
// another (a device cookie presented as an MFA token).
export async function signToken(env, purpose, payload) {
  const secret = requireSecret(env, 'SESSION_SECRET');
  const mac = await hmac(secret, `${purpose}.${payload}`);
  return `${payload}.${b64urlEncode(mac)}`;
}

// Returns the payload, or null for anything forged, malformed or empty.
export async function verifyToken(env, purpose, token) {
  if (typeof token !== 'string' || token.length > 2048) return null;
  const i = token.lastIndexOf('.');
  if (i <= 0 || i === token.length - 1) return null;
  const payload = token.slice(0, i);
  const given = b64urlDecode(token.slice(i + 1));
  if (!given || given.length !== 32) return null;
  const secret = requireSecret(env, 'SESSION_SECRET');
  const want = await hmac(secret, `${purpose}.${payload}`);
  return (await timingSafeEqual(given, want)) ? payload : null;
}

// ---------------------------------------------------------------- passwords

// FROZEN — DO NOT CHANGE, EVER.
//
// This is not "the platform limit". Cloudflare Workers refuses a single
// PBKDF2 derivation above 100,000 iterations (and `wrangler dev` does not
// enforce that, so it only fails in production). We reach a real work factor
// by chaining rounds: each round's 256-bit output is the next round's key
// material, so an attacker still performs every iteration in sequence.
//
// The chunk size decides how a total splits into rounds, and the split is
// part of the digest. If the platform ceiling rises and someone raises this
// to match, 600,000 becomes three rounds instead of six and every stored
// password stops verifying at once.
export const PBKDF2_CHUNK = 100_000;

export const PASSWORD_ALGO = 'pbkdf2-sha256-chain';
export const MIN_ITERATIONS = 100_000;
export const MAX_ITERATIONS = 10_000_000;
export const DEFAULT_ITERATIONS = 600_000;

// Work factor for NEW hashes. Existing rows verify with their own stored
// count, so raising this never invalidates anyone. An unreadable or too-low
// configured value falls back to the default — the stronger option.
export function passwordIterations(env) {
  const n = toInt(env && env.PBKDF2_ITERATIONS, MIN_ITERATIONS, MAX_ITERATIONS);
  return Number.isFinite(n) ? n : DEFAULT_ITERATIONS;
}

async function pbkdf2Round(material, salt, iterations) {
  const key = await crypto.subtle.importKey('raw', material, 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, 256);
  return new Uint8Array(bits);
}

export async function pbkdf2Chain(secret, salt, totalIterations) {
  if (!Number.isInteger(totalIterations) || totalIterations < 1 || totalIterations > MAX_ITERATIONS) {
    throw new RangeError('pbkdf2Chain: bad iteration count');
  }
  let material = typeof secret === 'string' ? utf8(secret) : secret;
  let remaining = totalIterations;
  while (remaining > 0) {
    const n = Math.min(PBKDF2_CHUNK, remaining);
    material = await pbkdf2Round(material, salt, n);
    remaining -= n;
  }
  return material;
}

export async function hashPassword(env, password, iterations = passwordIterations(env)) {
  const salt = randomBytes(32);
  const digest = await pbkdf2Chain(String(password), salt, iterations);
  return { hash: hex(digest), salt: hex(salt), algo: PASSWORD_ALGO, iters: iterations };
}

// Verifies against the row's own algorithm, salt and iteration count. Every
// unreadable field fails closed.
export async function verifyPassword(password, row) {
  if (typeof password !== 'string' || !row) return false;
  if (row.password_algo !== PASSWORD_ALGO) return false;
  const iters = toInt(row.password_iters, MIN_ITERATIONS, MAX_ITERATIONS);
  if (!Number.isFinite(iters)) return false;
  const salt = fromHex(row.password_salt);
  const want = fromHex(row.password_hash);
  if (!salt || salt.length < 16 || !want || want.length !== 32) return false;
  const got = await pbkdf2Chain(password, salt, iters);
  return timingSafeEqual(got, want);
}

// Spend the same work as a real verification, so "no such account" and
// "wrong password" take the same time.
const BURN_SALT = new Uint8Array(32);
export async function burnPasswordCost(env, password = '') {
  await pbkdf2Chain(String(password), BURN_SALT, passwordIterations(env));
  return false;
}

// ---------------------------------------------------------------- at rest

const BLOB_V1 = 'v1';
const aesKeys = new Map();

async function dataKey(env) {
  const secret = requireSecret(env, 'DATA_KEY');
  let k = aesKeys.get(secret);
  if (!k) {
    const ikm = await crypto.subtle.importKey('raw', utf8(secret), 'HKDF', false, ['deriveKey']);
    k = await crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: utf8('staff-portal/at-rest'), info: utf8('aes-gcm-256 v1') },
      ikm,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
    if (aesKeys.size > 4) aesKeys.clear();
    aesKeys.set(secret, k);
  }
  return k;
}

// `v1.<b64url iv>.<b64url ciphertext>`. The version prefix means a future
// algorithm is a new prefix, not a guess. `aad` binds the blob to its row
// (e.g. "totp:42") so a ciphertext cannot be moved to another account.
export async function encrypt(env, plaintext, aad = '') {
  const key = await dataKey(env);
  const iv = randomBytes(12);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: utf8(aad) }, key, utf8(plaintext));
  return `${BLOB_V1}.${b64urlEncode(iv)}.${b64urlEncode(new Uint8Array(ct))}`;
}

// The plaintext, or null. Null means "present but unreadable": callers must
// REFUSE, never treat it as "nothing configured" (SPEC §7.3, §14.3).
export async function decrypt(env, blob, aad = '') {
  if (typeof blob !== 'string') return null;
  const parts = blob.split('.');
  if (parts.length !== 3 || parts[0] !== BLOB_V1) return null;
  const iv = b64urlDecode(parts[1]);
  const ct = b64urlDecode(parts[2]);
  if (!iv || iv.length !== 12 || !ct || ct.length < 16) return null;
  try {
    const key = await dataKey(env);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: utf8(aad) }, key, ct);
    return fromUtf8(new Uint8Array(pt));
  } catch {
    return null;
  }
}
