// webauthn.js — passkeys in the browser (CONTRACTS §7.5, §10; A §7.4, §7.6).
//
// Exports:
//   supportsPasskeys() → bool
//   createPasskey(options) → credential | { cancelled: true } | { error }
//   getPasskey(options)    → credential | { cancelled: true } | { error }
//   b64urlEncode(bytes)    → url-safe base64, no padding
//   b64urlDecode(string)   → Uint8Array (accepts url-safe or standard, padded or not)
//
// The browser speaks ArrayBuffer; the wire format is base64url, both ways.
// Both conversions are loops: the spread form String.fromCharCode(...bytes)
// throws past a stack-dependent size. The output must be URL-SAFE — a '+' or
// '/' in a credential id breaks the server's lookup — and the tests check it
// with bytes that differ between the alphabets ([0xfb,0xff,0xbe,0x01] →
// '-_--AQ', not '+/++AQ==').
//
// A dismissed system dialog is not an error: NotAllowedError and AbortError
// come back as { cancelled: true } so the login page can return to the
// chooser quietly (A §7.6).
//
// No imports, no module-level state: the login shell may load this file and
// nothing beyond common.js and fp.js (CONTRACTS §7.8).

export function b64urlEncode(input) {
  let bytes;
  if (input instanceof Uint8Array) bytes = input;
  else if (input instanceof ArrayBuffer) bytes = new Uint8Array(input);
  else if (input && ArrayBuffer.isView(input)) bytes = new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  else bytes = new Uint8Array(0);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function b64urlDecode(str) {
  if (typeof str !== 'string') throw new TypeError('base64url: expected a string');
  let s = str.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
  if (/[^A-Za-z0-9+/]/.test(s) || s.length % 4 === 1) throw new TypeError('base64url: not base64');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function toBuffer(str) {
  const u8 = b64urlDecode(str);
  return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength);
}

export function supportsPasskeys() {
  try {
    return (
      typeof window !== 'undefined' &&
      typeof window.PublicKeyCredential === 'function' &&
      !!navigator.credentials &&
      typeof navigator.credentials.get === 'function' &&
      typeof navigator.credentials.create === 'function'
    );
  } catch {
    return false;
  }
}

function failure(err) {
  const name = err && typeof err.name === 'string' ? err.name : '';
  if (name === 'NotAllowedError' || name === 'AbortError') return { cancelled: true };
  if (name === 'InvalidStateError') return { error: 'This passkey is already registered on your account.' };
  const message = err && typeof err.message === 'string' && err.message ? err.message : String(err || 'Unknown error');
  return { error: message.slice(0, 300) };
}

function descriptors(list) {
  return (Array.isArray(list) ? list : []).map((c) => {
    const d = { type: c.type || 'public-key', id: toBuffer(c.id) };
    if (Array.isArray(c.transports) && c.transports.length) d.transports = c.transports.slice();
    return d;
  });
}

function transportsOf(response) {
  try {
    if (typeof response.getTransports === 'function') {
      const t = response.getTransports();
      return Array.isArray(t) ? t.slice(0, 8) : undefined;
    }
  } catch {
    // Older browsers: transports are optional on the wire.
  }
  return undefined;
}

// The id is always re-derived from rawId so it is url-safe whatever the
// browser put in `id`.
function credentialId(cred) {
  return cred.rawId ? b64urlEncode(cred.rawId) : String(cred.id || '');
}

// Registration: server options (§7.5 wire format) → navigator.credentials.create.
export async function createPasskey(options) {
  if (!supportsPasskeys()) return { error: 'This browser can’t create passkeys.' };
  let publicKey;
  try {
    const o = options || {};
    publicKey = {
      challenge: toBuffer(o.challenge),
      rp: { ...o.rp },
      user: { ...o.user, id: toBuffer(o.user.id) },
      pubKeyCredParams: Array.isArray(o.pubKeyCredParams) ? o.pubKeyCredParams : [],
      timeout: o.timeout,
      attestation: o.attestation || 'none',
      authenticatorSelection: o.authenticatorSelection,
      excludeCredentials: descriptors(o.excludeCredentials),
    };
  } catch (err) {
    return { error: `The server sent options this page couldn’t read (${err.message}).` };
  }
  let cred;
  try {
    cred = await navigator.credentials.create({ publicKey });
  } catch (err) {
    return failure(err);
  }
  if (!cred) return { cancelled: true };
  try {
    const r = cred.response;
    const out = {
      id: credentialId(cred),
      rawId: b64urlEncode(cred.rawId),
      type: 'public-key',
      response: {
        clientDataJSON: b64urlEncode(r.clientDataJSON),
        attestationObject: b64urlEncode(r.attestationObject),
      },
    };
    const transports = transportsOf(r);
    if (transports) out.response.transports = transports;
    return out;
  } catch (err) {
    return failure(err);
  }
}

// Assertion: server options → navigator.credentials.get.
export async function getPasskey(options) {
  if (!supportsPasskeys()) return { error: 'This browser can’t use passkeys.' };
  let publicKey;
  try {
    const o = options || {};
    publicKey = {
      challenge: toBuffer(o.challenge),
      timeout: o.timeout,
      userVerification: o.userVerification || 'preferred',
      allowCredentials: descriptors(o.allowCredentials),
    };
    if (o.rpId) publicKey.rpId = o.rpId;
  } catch (err) {
    return { error: `The server sent options this page couldn’t read (${err.message}).` };
  }
  let cred;
  try {
    cred = await navigator.credentials.get({ publicKey });
  } catch (err) {
    return failure(err);
  }
  if (!cred) return { cancelled: true };
  try {
    const r = cred.response;
    const out = {
      id: credentialId(cred),
      rawId: b64urlEncode(cred.rawId),
      type: 'public-key',
      response: {
        clientDataJSON: b64urlEncode(r.clientDataJSON),
        authenticatorData: b64urlEncode(r.authenticatorData),
        signature: b64urlEncode(r.signature),
      },
    };
    if (r.userHandle && r.userHandle.byteLength) out.response.userHandle = b64urlEncode(r.userHandle);
    return out;
  } catch (err) {
    return failure(err);
  }
}
