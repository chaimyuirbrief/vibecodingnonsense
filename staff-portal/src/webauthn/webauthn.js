// Passkeys: registration and assertion ceremonies (CONTRACTS §7.5; A §7.4 —
// every row of both tables; B §5).
//
// A demo works with almost none of these checks in place, so each one names
// what it prevents. Every refusal is the same 400 to the client; the real
// reason rides on a non-enumerable `err.reason` for the API layer to audit
// without telling a caller which check it tripped.
//
// Challenges are rows, not tokens (A §7.4): 5 minutes, and DELETEd the moment
// a ceremony presents them, before any other check can fail — so a refused
// attempt has spent its challenge too.

import { audit } from '../audit.js';
import { sha256, hmac, requireSecret } from '../crypto.js';
import { HttpError } from '../errors.js';
import {
  now, iso, str, toInt, hex, b64urlEncode, b64urlDecode, concatBytes, randomToken, parseIsoStrict, safeJsonParse, MINUTE,
} from '../util.js';
import { decodeCbor, decodeCborPrefix, CborError } from './cbor.js';
import { derToRaw, DerError } from './der.js';
import { coseToJwk, importVerifyKey, CoseError, ALG_ES256, SUPPORTED_ALGS } from './cose.js';

export const CHALLENGE_TTL_MS = 5 * MINUTE;
// The browser gives up a minute before the row expires, so a slow ceremony
// fails in the dialog rather than as a mysterious refusal afterwards.
export const CEREMONY_TIMEOUT_MS = 4 * MINUTE;
// Only what we can verify: offering more enrols keys that cannot sign in.
export const PUB_KEY_CRED_PARAMS = Object.freeze(
  SUPPORTED_ALGS.map((alg) => Object.freeze({ type: 'public-key', alg })),
);
export const KNOWN_TRANSPORTS = Object.freeze(['usb', 'nfc', 'ble', 'smart-card', 'hybrid', 'internal']);
// We ask for attestation 'none' and verify no statement whatever its format,
// but a format nobody has defined is a structure we have misread.
const KNOWN_FORMATS = new Set(['none', 'packed', 'tpm', 'android-key', 'android-safetynet', 'fido-u2f', 'apple']);
const ASSERTION_KINDS = new Set(['auth', 'stepup']);

// Outstanding challenges per user and kind (B trap 6: everything that grows
// gets a trim). Two open tabs still work.
const MAX_OPEN_CHALLENGES = 5;
const MAX_CLIENT_DATA = 4096;
const MAX_ATTESTATION = 32 * 1024;
const MAX_AUTH_DATA = 4096;
const MAX_SIGNATURE = 1024; // RSA-8192
const MAX_CREDENTIAL_ID = 1023; // WebAuthn §5.8.3
const MAX_USER_HANDLE = 64;
const LABEL_MAX = 60;

export const FLAG_UP = 0x01;
export const FLAG_UV = 0x04;
export const FLAG_BE = 0x08;
export const FLAG_BS = 0x10;
export const FLAG_AT = 0x40;
export const FLAG_ED = 0x80;

const CHALLENGE_RE = /^[A-Za-z0-9_-]{43}$/;
const utf8Fatal = new TextDecoder('utf-8', { fatal: true });

// ---------------------------------------------------------------- errors

export function passkeyError(reason) {
  const err = new HttpError(400, { error: 'That passkey could not be verified.', code: 'passkey_invalid' });
  Object.defineProperty(err, 'reason', { value: String(reason), enumerable: false });
  return err;
}

function fail(reason) {
  throw passkeyError(reason);
}

function reasonOf(e, prefix) {
  if (e instanceof CoseError) return e.reason;
  if (e instanceof CborError || e instanceof DerError) return `${prefix}_${e.code}`;
  throw e; // not a parse refusal: a bug, let the worker audit it
}

// ---------------------------------------------------------------- config

// Misconfiguration is our fault, not the caller's: a plain Error the worker
// answers with a 500 and audits. ORIGIN must be an exact origin — a trailing
// slash would quietly refuse every passkey.
function config(env) {
  const rpId = env && typeof env.RP_ID === 'string' ? env.RP_ID : '';
  const origin = env && typeof env.ORIGIN === 'string' ? env.ORIGIN : '';
  let ok = false;
  try {
    ok = !!rpId && new URL(origin).origin === origin;
  } catch {
    ok = false;
  }
  if (!ok) throw new Error('webauthn: RP_ID and ORIGIN (an exact origin, e.g. https://staff.example.com) must be set');
  return { rpId, origin, rpName: str(env.ORG_NAME, 100) || rpId };
}

function clock(rc) {
  return typeof rc?.nowMs === 'number' && Number.isFinite(rc.nowMs) ? rc.nowMs : now(rc?.env);
}

function userIdOf(user) {
  const id = toInt(user?.id, 1, Number.MAX_SAFE_INTEGER);
  if (!Number.isFinite(id)) fail('bad_user');
  return id;
}

// b64url(first 16 bytes of HMAC(SESSION_SECRET, 'webauthn-user.' + id)):
// stable per user, reveals nothing about the account.
export async function userHandle(env, userId) {
  const mac = await hmac(requireSecret(env, 'SESSION_SECRET'), `webauthn-user.${userId}`);
  return b64urlEncode(mac.subarray(0, 16));
}

// ---------------------------------------------------------------- challenges

async function issueChallenge(env, userId, kind, t) {
  const challenge = randomToken(32);
  const db = env.DB;
  await db.batch([
    db.prepare('DELETE FROM webauthn_challenges WHERE expires_at <= ?').bind(iso(t)),
    db.prepare(
      `DELETE FROM webauthn_challenges WHERE user_id = ? AND kind = ? AND challenge NOT IN
         (SELECT challenge FROM webauthn_challenges WHERE user_id = ? AND kind = ? ORDER BY expires_at DESC LIMIT ?)`,
    ).bind(userId, kind, userId, kind, MAX_OPEN_CHALLENGES - 1),
    db
      .prepare('INSERT INTO webauthn_challenges (challenge, user_id, kind, expires_at) VALUES (?, ?, ?, ?)')
      .bind(challenge, userId, kind, iso(t + CHALLENGE_TTL_MS)),
  ]);
  return challenge;
}

// DELETE … RETURNING: one statement both claims and spends the row, so two
// concurrent presentations cannot both see it.
async function consumeChallenge(env, challenge, userId, kind, t) {
  if (typeof challenge !== 'string' || !CHALLENGE_RE.test(challenge)) fail('challenge_malformed');
  const row = await env.DB.prepare('DELETE FROM webauthn_challenges WHERE challenge = ? RETURNING user_id, kind, expires_at')
    .bind(challenge)
    .first();
  if (!row) fail('challenge_unknown');
  if (row.kind !== kind) fail('challenge_kind');
  if (toInt(row.user_id, 1) !== userId) fail('challenge_user');
  const exp = parseIsoStrict(row.expires_at);
  if (!Number.isFinite(exp) || t >= exp) fail('challenge_expired');
}

// ---------------------------------------------------------------- parsing

function field(v, maxBytes, reason) {
  if (typeof v !== 'string' || v.length === 0 || v.length > Math.ceil((maxBytes * 4) / 3)) fail(reason);
  const b = b64urlDecode(v);
  if (!b || b.length === 0 || b.length > maxBytes) fail(reason);
  return b;
}

function credentialShape(credential) {
  if (!credential || typeof credential !== 'object' || Array.isArray(credential)) fail('credential_shape');
  const r = credential.response;
  if (!r || typeof r !== 'object' || Array.isArray(r)) fail('credential_shape');
  return r;
}

function parseClientData(v) {
  const raw = field(v, MAX_CLIENT_DATA, 'client_data');
  let cd;
  try {
    cd = JSON.parse(utf8Fatal.decode(raw));
  } catch {
    fail('client_data_json');
  }
  if (!cd || typeof cd !== 'object' || Array.isArray(cd)) fail('client_data_json');
  return { raw, cd };
}

function checkClientData(cd, type, cfg) {
  // 'webauthn.get' replayed as a registration, or the reverse.
  if (cd.type !== type) fail('type_mismatch');
  // Exactly — a lookalike origin must not enrol or sign in.
  if (typeof cd.origin !== 'string' || cd.origin !== cfg.origin) fail('origin_mismatch');
  // frame-ancestors 'none': we are never legitimately inside someone's iframe.
  if ((cd.crossOrigin !== undefined && cd.crossOrigin !== false) || cd.topOrigin !== undefined) fail('cross_origin');
  // We cannot check a token binding, so one that claims to be in use is refused.
  if (cd.tokenBinding && typeof cd.tokenBinding === 'object' && cd.tokenBinding.status === 'present') fail('token_binding');
}

// WebAuthn §6.1: a 37-byte head, attested credential data iff AT, extensions
// iff ED, and NOTHING after that (A §7.4 detail 3). Leftover bytes mean a
// structure we have misread; ED with no extension map behind it means the
// flag and the bytes disagree. Either way the safe reading is none at all.
export function parseAuthData(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length < 37) fail('authdata_short');
  const flags = bytes[32];
  const signCount = ((bytes[33] << 24) >>> 0) + (bytes[34] << 16) + (bytes[35] << 8) + bytes[36];
  if (flags & FLAG_BS && !(flags & FLAG_BE)) fail('flags_backup');
  let o = 37;
  let attested = null;
  if (flags & FLAG_AT) {
    if (bytes.length < o + 18) fail('authdata_truncated');
    const aaguid = bytes.slice(o, o + 16);
    const idLen = (bytes[o + 16] << 8) | bytes[o + 17];
    o += 18;
    if (idLen < 1 || idLen > MAX_CREDENTIAL_ID) fail('credential_id_length');
    if (bytes.length < o + idLen) fail('authdata_truncated');
    const credentialId = bytes.slice(o, o + idLen);
    o += idLen;
    if (o >= bytes.length) fail('authdata_truncated');
    let cose;
    try {
      const r = decodeCborPrefix(bytes.subarray(o));
      cose = r.value;
      o += r.length;
    } catch (e) {
      fail(reasonOf(e, 'cbor'));
    }
    attested = { aaguid, credentialId, cose };
  }
  let extensions = null;
  if (flags & FLAG_ED) {
    if (o >= bytes.length) fail('ed_without_extensions');
    try {
      const r = decodeCborPrefix(bytes.subarray(o));
      extensions = r.value;
      o += r.length;
    } catch (e) {
      fail(reasonOf(e, 'cbor'));
    }
    if (!(extensions instanceof Map)) fail('extensions_shape');
  }
  if (o !== bytes.length) fail('authdata_trailing');
  return { rpIdHash: bytes.subarray(0, 32), flags, signCount, attested, extensions };
}

async function checkRpAndPresence(ad, cfg) {
  const want = await sha256(cfg.rpId);
  let diff = 0;
  for (let i = 0; i < 32; i++) diff |= ad.rpIdHash[i] ^ want[i];
  // A credential scoped to another site.
  if (diff !== 0) fail('rp_id_hash');
  // No human was involved.
  if (!(ad.flags & FLAG_UP)) fail('user_not_present');
}

function cleanTransports(v) {
  if (!Array.isArray(v)) return [];
  const out = [];
  for (const t of v.slice(0, 16)) if (typeof t === 'string' && KNOWN_TRANSPORTS.includes(t) && !out.includes(t)) out.push(t);
  return out;
}

// A sensible guess so a list of three passkeys reads as three devices
// (A §7.5). User agent only — client hints are not universal (A §14.7).
export function labelFromUa(ua) {
  const s = str(ua, 512);
  const browser = /\bEdg(?:e|A|iOS)?\//.test(s) ? 'Edge'
    : /\bOPR\//.test(s) ? 'Opera'
      : /\b(?:Firefox|FxiOS)\//.test(s) ? 'Firefox'
        : /\b(?:Chrome|CriOS)\//.test(s) ? 'Chrome'
          : /\bVersion\/.*\bSafari\//.test(s) ? 'Safari' : '';
  const os = /\biPhone\b/.test(s) ? 'iPhone'
    : /\biPad\b/.test(s) ? 'iPad'
      : /\bAndroid\b/.test(s) ? 'Android'
        : /\bWindows\b/.test(s) ? 'Windows'
          : /\bCrOS\b/.test(s) ? 'ChromeOS'
            : /\b(?:Macintosh|Mac OS X)\b/.test(s) ? 'macOS'
              : /\bLinux\b/.test(s) ? 'Linux' : '';
  if (browser && os) return `${browser} on ${os}`;
  return browser || os || 'Passkey';
}

function cleanLabel(label, ua) {
  const s = str(label, 200).replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, LABEL_MAX);
  return s || labelFromUa(ua);
}

async function descriptors(env, userId) {
  const { results } = await env.DB.prepare('SELECT id, transports FROM user_passkeys WHERE user_id = ? ORDER BY created_at, id LIMIT 100')
    .bind(userId)
    .all();
  const out = [];
  for (const row of results) {
    // An id the browser could not decode would break the whole ceremony.
    const raw = b64urlDecode(row.id);
    if (!raw || raw.length === 0 || raw.length > MAX_CREDENTIAL_ID) continue;
    const d = { type: 'public-key', id: row.id };
    const transports = cleanTransports(safeJsonParse(row.transports, null));
    if (transports.length) d.transports = transports;
    out.push(d);
  }
  return out;
}

// ---------------------------------------------------------------- registration

export async function registrationOptions(rc, user) {
  const env = rc.env;
  const cfg = config(env);
  const uid = userIdOf(user);
  const t = clock(rc);
  // The browser refuses to register the same authenticator twice instead of
  // silently making a duplicate (A §7.4).
  const excludeCredentials = await descriptors(env, uid);
  const challenge = await issueChallenge(env, uid, 'register', t);
  const name = str(user.email, 254) || str(user.username, 64) || `user-${uid}`;
  return {
    challenge,
    rp: { id: cfg.rpId, name: cfg.rpName },
    user: { id: await userHandle(env, uid), name, displayName: str(user.full_name, 120) || name },
    pubKeyCredParams: PUB_KEY_CRED_PARAMS.map((p) => ({ ...p })),
    timeout: CEREMONY_TIMEOUT_MS,
    attestation: 'none',
    authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
    excludeCredentials,
  };
}

// → the inserted user_passkeys row. Under attestation 'none' no signature is
// verified here, so the key is attacker-chosen input until coseToJwk and
// importVerifyKey say otherwise (A §14.5).
export async function verifyRegistration(rc, user, credential, label) {
  const env = rc.env;
  const cfg = config(env);
  const uid = userIdOf(user);
  const t = clock(rc);
  const response = credentialShape(credential);

  const { cd } = parseClientData(response.clientDataJSON);
  await consumeChallenge(env, cd.challenge, uid, 'register', t);

  if (credential.type !== 'public-key') fail('credential_type');
  checkClientData(cd, 'webauthn.create', cfg);

  const attBytes = field(response.attestationObject, MAX_ATTESTATION, 'attestation_object');
  let att;
  try {
    att = decodeCbor(attBytes);
  } catch (e) {
    fail(reasonOf(e, 'cbor'));
  }
  if (!(att instanceof Map) || att.size !== 3) fail('attestation_object');
  const fmt = att.get('fmt');
  const attStmt = att.get('attStmt');
  const authDataBytes = att.get('authData');
  if (typeof fmt !== 'string' || !(attStmt instanceof Map) || !(authDataBytes instanceof Uint8Array)) fail('attestation_object');
  if (!KNOWN_FORMATS.has(fmt)) fail('attestation_format');
  if (fmt === 'none' && attStmt.size !== 0) fail('attestation_statement');

  const ad = parseAuthData(authDataBytes);
  await checkRpAndPresence(ad, cfg);
  // Nothing to store.
  if (!ad.attested) fail('no_attested_data');

  const id = b64urlEncode(ad.attested.credentialId);
  if (credential.id !== id || credential.rawId !== id) fail('credential_id_mismatch');

  let key;
  try {
    key = coseToJwk(ad.attested.cose);
    // Import now: a key that cannot sign in is found at enrolment, not at
    // the worst possible moment.
    await importVerifyKey(key.jwk, key.alg);
  } catch (e) {
    fail(reasonOf(e, 'cose'));
  }

  const row = {
    id,
    user_id: uid,
    public_key: JSON.stringify(key.jwk),
    algorithm: key.alg,
    sign_count: ad.signCount,
    aaguid: hex(ad.attested.aaguid),
    transports: JSON.stringify(cleanTransports(response.transports)),
    label: cleanLabel(label, rc.ua),
    created_at: iso(t),
    last_used_at: null,
  };
  const res = await env.DB.prepare(
    `INSERT INTO user_passkeys (id, user_id, public_key, algorithm, sign_count, aaguid, transports, label, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING`,
  )
    .bind(row.id, row.user_id, row.public_key, row.algorithm, row.sign_count, row.aaguid, row.transports, row.label, row.created_at)
    .run();
  if (res.meta.changes !== 1) throw new HttpError(409, { error: 'That passkey is already registered.', code: 'passkey_duplicate' });
  return row;
}

// ---------------------------------------------------------------- assertion

export async function assertionOptions(rc, user, kind = 'auth') {
  const env = rc.env;
  const cfg = config(env);
  if (!ASSERTION_KINDS.has(kind)) fail('bad_kind');
  const uid = userIdOf(user);
  const t = clock(rc);
  const allowCredentials = await descriptors(env, uid);
  // An empty list would invite ANY discoverable credential on the device.
  if (!allowCredentials.length) throw new HttpError(400, { error: 'No passkey is registered for this account.', code: 'no_passkeys' });
  const challenge = await issueChallenge(env, uid, kind, t);
  return { challenge, rpId: cfg.rpId, timeout: CEREMONY_TIMEOUT_MS, userVerification: 'preferred', allowCredentials };
}

// → { passkeyId, userVerified }.
export async function verifyAssertion(rc, user, credential, kind) {
  const env = rc.env;
  const cfg = config(env);
  if (!ASSERTION_KINDS.has(kind)) fail('bad_kind');
  const uid = userIdOf(user);
  const t = clock(rc);
  const response = credentialShape(credential);

  const { raw: clientDataBytes, cd } = parseClientData(response.clientDataJSON);
  await consumeChallenge(env, cd.challenge, uid, kind, t);

  if (credential.type !== 'public-key') fail('credential_type');
  checkClientData(cd, 'webauthn.get', cfg);

  const id = credential.id;
  if (typeof id !== 'string' || id !== credential.rawId) fail('credential_id_mismatch');
  const idBytes = b64urlDecode(id);
  if (!idBytes || idBytes.length === 0 || idBytes.length > MAX_CREDENTIAL_ID) fail('credential_id_malformed');
  const row = await env.DB.prepare('SELECT * FROM user_passkeys WHERE id = ?').bind(id).first();
  if (!row) fail('credential_unknown');
  // Someone else's passkey must not sign you in.
  if (toInt(row.user_id, 1) !== uid) fail('credential_not_owned');
  // userHandle is not covered by the signature and the credential is already
  // bound to this user above; comparing it adds nothing and would refuse every
  // passkey after a SESSION_SECRET rotation. Its shape is still checked.
  if (response.userHandle !== undefined && response.userHandle !== null) {
    const h = typeof response.userHandle === 'string' ? b64urlDecode(response.userHandle) : null;
    if (!h || h.length > MAX_USER_HANDLE) fail('user_handle_malformed');
  }

  const authDataBytes = field(response.authenticatorData, MAX_AUTH_DATA, 'authenticator_data');
  const ad = parseAuthData(authDataBytes);
  if (ad.attested) fail('unexpected_attested_data');
  await checkRpAndPresence(ad, cfg);

  // Re-validate the stored key on every use: a row edited, restored from an
  // old backup or written by older code must fail closed (A §7.4, §14.5).
  // importVerifyKey runs validatePublicKey before WebCrypto sees anything.
  const alg = toInt(row.algorithm);
  if (!SUPPORTED_ALGS.includes(alg)) fail('stored_algorithm');
  const jwk = safeJsonParse(row.public_key, null);
  let key;
  try {
    key = await importVerifyKey(jwk, alg);
  } catch (e) {
    fail(reasonOf(e, 'cose'));
  }

  const sig = field(response.signature, MAX_SIGNATURE, 'signature');
  let sigForCrypto = sig;
  if (alg === ALG_ES256) {
    try {
      sigForCrypto = derToRaw(sig, 32);
    } catch (e) {
      fail(reasonOf(e, 'der'));
    }
  }
  const signed = concatBytes(authDataBytes, await sha256(clientDataBytes));
  let ok = false;
  try {
    const params = alg === ALG_ES256 ? { name: 'ECDSA', hash: 'SHA-256' } : { name: 'RSASSA-PKCS1-v1_5' };
    ok = await crypto.subtle.verify(params, key, sigForCrypto, signed);
  } catch {
    ok = false;
  }
  if (!ok) fail('signature_invalid');

  // Strictly increasing whenever either side is non-zero; 0 → 0 is an
  // authenticator without a counter. A step back means a cloned authenticator
  // (B §5): refuse, and audit it here because no caller could know (§4.2).
  const stored = toInt(row.sign_count, 0, 0xffffffff);
  if (!Number.isFinite(stored)) fail('stored_counter_unreadable');
  const presented = ad.signCount;
  if ((stored !== 0 || presented !== 0) && presented <= stored) {
    await audit(rc, {
      action: 'mfa.passkey.counter_regressed',
      outcome: 'denied',
      severity: 'critical',
      target: { type: 'user', id: uid },
      detail: `Refused passkey “${str(row.label, LABEL_MAX) || 'unnamed'}”: its signature counter went from ${stored} to ${presented}. The authenticator may have been cloned.`,
      before: { sign_count: stored },
      after: { sign_count: presented, credential: row.id },
    });
    fail('counter_regressed');
  }
  // Conditional on the counter still being below what we verified, so a
  // concurrent assertion cannot move it backwards.
  const upd = await env.DB.prepare(
    `UPDATE user_passkeys SET sign_count = ?, last_used_at = ?
      WHERE id = ? AND user_id = ? AND (sign_count < ? OR (sign_count = 0 AND ? = 0))`,
  )
    .bind(presented, iso(t), row.id, uid, presented, presented)
    .run();
  if (upd.meta.changes !== 1) fail('counter_race');
  return { passkeyId: row.id, userVerified: (ad.flags & FLAG_UV) !== 0 };
}
