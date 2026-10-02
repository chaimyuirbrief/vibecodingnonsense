// A software passkey authenticator plus the browser half of the ceremony
// (CONTRACTS §7.5, §12). It takes the server's options JSON and returns the
// wire JSON public/js/webauthn.js would POST, signed with real ES256 / RS256
// keys from WebCrypto.
//
//   const a = new SoftAuthenticator({ alg: -7, origin: env.ORIGIN, rpId: env.RP_ID });
//   const cred = await a.create(await registrationOptions(rc, user));
//   await verifyRegistration(rc, user, cred, 'Laptop');
//   const assertion = await a.get(await assertionOptions(rc, user, 'auth'));
//   await verifyAssertion(rc, user, assertion, 'auth');
//
// new SoftAuthenticator({ alg = -7, origin, rpId, signCount = 0, increment = true })
//   alg        -7 (ES256, P-256) or -257 (RS256, 2048-bit, e = 65537)
//   origin     clientData.origin (default 'https://staff.example.com')
//   rpId       what rpIdHash is computed over (default 'staff.example.com').
//              create()/get() throw SecurityError when the options name another
//              RP ID, as a browser would — unless the rpId knob is given.
//   signCount  the counter reported at registration. get() adds 1 first when
//              `increment` is true; increment: false is an authenticator with
//              no counter (always 0). `a.signCount` may be set directly.
//
// Every created credential is remembered. get() uses the first remembered one
// listed in allowCredentials (or the `credential` knob) and throws
// NotAllowedError if there is none; create() throws InvalidStateError when one
// of its credentials is in excludeCredentials. Both like a browser.
//
// Knobs (second argument) break exactly one thing each. Anything the server
// verifies a signature over is modified BEFORE signing, so the signature stays
// valid and only the targeted check can refuse the response.
//
//   create() and get():
//     type, origin, challenge   clientData fields
//     clientData                object merged into clientData ({ crossOrigin: true })
//     clientDataJSON            raw string replacing the whole clientDataJSON
//     rpId                      rpIdHash computed over this instead
//     flags                     number = the exact flags byte;
//                               object { UP, UV, AT, ED, BE, BS: bool } = toggle bits of the default
//     signCount                 exact counter for this response (state unchanged)
//     extensions                Map/object appended as the extensions CBOR (sets ED)
//     truncate                  drop N bytes from the end of authenticator data
//     extend                    append bytes (Uint8Array | number[]) or N zero bytes (number)
//     id, rawId, credentialType override the wire strings
//     transform(json)           last-chance edit of the returned JSON (return it)
//   create() only:
//     duplicateKey              true: attestationObject holds 'authData' twice, a decoy
//                               (wrong rpIdHash) first and the real one last, so a
//                               last-wins parser accepts it. 'realFirst' swaps them.
//     fmt, attStmt              attestation format / statement (default 'none', {})
//     transports                response.transports (default ['internal', 'hybrid'])
//     credentialIdLength        bytes in the new credential id (default 32)
//     credentialId              the new credential id's exact bytes
//     attestedData              false: no attested credential data at all (AT clear)
//     aaguid                    16 bytes
//     alg                       raw COSE alg label
//     algMismatch               true: claim ES256 on an RSA key / RS256 on an EC key
//     rsaExponent               COSE e built by hand around the real modulus: a number
//                               (1, 0, 2, 3, 65537, …) or raw bytes. Registration verifies
//                               no signature — exactly the attacker's move. With e = 1 the
//                               credential is forgeable and get() forges every signature.
//     rsaModulusBits            a hand-made odd modulus of this many bits (cannot sign)
//     rsaModulusEven            true: clear the real modulus's low bit (cannot sign)
//     ecCoordinateLength        x and y trimmed / zero-padded to this many bytes
//     ecCurve                   COSE crv label (default 1 = P-256)
//     coseEdit(map)             edit the COSE key Map before encoding (1 kty, 3 alg, -1, -2, -3)
//   get() only:
//     credential                id (b64url) of the remembered credential to use
//     badSignature              sign different bytes: well-formed, wrong signature
//     nonMinimalDer             true / 'leading-zero': an unneeded 0x00 on r or s (one whose
//                               high bit is clear, so a lenient reader would accept it);
//                               'long-length': the SEQUENCE length in long form below 128
//     trailingDer               true or bytes: appended after the DER SEQUENCE
//     forge                     true: the PKCS#1 v1.5 encoding of the digest as the
//                               "signature" — no private key involved (valid only if e = 1)
//     signature                 raw bytes to send as the signature
//     userHandle                string | null (default: the handle from registration)
//
// Also exported for tests: encodeCbor, CborPairs (a map that may repeat keys),
// CborRaw (pre-encoded bytes), rawToDer, emsaPkcs1v15, b64u, fromB64u.

const enc = new TextEncoder();

export const FLAGS = Object.freeze({ UP: 0x01, UV: 0x04, BE: 0x08, BS: 0x10, AT: 0x40, ED: 0x80 });
export const TEST_AAGUID = Uint8Array.from([
  0x5f, 0x0e, 0x7c, 0x3a, 0x11, 0x22, 0x4b, 0x6d, 0x9e, 0x01, 0xa2, 0xb3, 0xc4, 0xd5, 0xe6, 0xf7,
]);

export function b64u(bytes) {
  return Buffer.from(bytes).toString('base64url');
}

export function fromB64u(s) {
  return new Uint8Array(Buffer.from(s, 'base64url'));
}

function concat(...parts) {
  const arrs = parts.map((p) => (p instanceof Uint8Array ? p : Uint8Array.from(p)));
  const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
  let o = 0;
  for (const a of arrs) {
    out.set(a, o);
    o += a.length;
  }
  return out;
}

async function sha256(data) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', typeof data === 'string' ? enc.encode(data) : data));
}

function u32(n) {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
}

function domError(name) {
  return new DOMException(`SoftAuthenticator: ${name}`, name);
}

// ---------------------------------------------------------------- CBOR (encoder)

export class CborPairs {
  constructor(pairs) {
    this.pairs = pairs;
  }
}

export class CborRaw {
  constructor(bytes) {
    this.bytes = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
  }
}

export function encodeCbor(value) {
  const out = [];
  const push = (bytes) => {
    for (let i = 0; i < bytes.length; i++) out.push(bytes[i]);
  };
  const head = (major, n) => {
    const m = major << 5;
    if (n < 24) out.push(m | n);
    else if (n < 256) out.push(m | 24, n);
    else if (n < 65536) out.push(m | 25, n >> 8, n & 255);
    else if (n < 2 ** 32) out.push(m | 26, ...u32(n));
    else out.push(m | 27, ...u32(Math.floor(n / 2 ** 32)), ...u32(n >>> 0));
  };
  const item = (v) => {
    if (v instanceof CborRaw) push(v.bytes);
    else if (typeof v === 'number') {
      if (!Number.isSafeInteger(v)) throw new RangeError('encodeCbor: integers only');
      if (v >= 0) head(0, v);
      else head(1, -1 - v);
    } else if (typeof v === 'string') {
      const b = enc.encode(v);
      head(3, b.length);
      push(b);
    } else if (v instanceof Uint8Array) {
      head(2, v.length);
      push(v);
    } else if (Array.isArray(v)) {
      head(4, v.length);
      v.forEach(item);
    } else if (v instanceof CborPairs) {
      head(5, v.pairs.length);
      for (const [k, x] of v.pairs) {
        item(k);
        item(x);
      }
    } else if (v instanceof Map) {
      head(5, v.size);
      for (const [k, x] of v) {
        item(k);
        item(x);
      }
    } else if (v === false) out.push(0xf4);
    else if (v === true) out.push(0xf5);
    else if (v === null) out.push(0xf6);
    else if (typeof v === 'object') item(new Map(Object.entries(v)));
    else throw new TypeError(`encodeCbor: cannot encode ${typeof v}`);
  };
  item(value);
  return Uint8Array.from(out);
}

// ---------------------------------------------------------------- DER / PKCS#1

function derLength(n, longForm) {
  if (n < 128 && !longForm) return [n];
  if (n < 256) return [0x81, n];
  return [0x82, n >> 8, n & 255];
}

function minimalUnsigned(bytes) {
  let i = 0;
  while (i < bytes.length - 1 && bytes[i] === 0) i++;
  let v = bytes.slice(i);
  if (v[0] & 0x80) v = concat([0], v);
  return v;
}

// raw r‖s → DER. opts: { padR, padS } add an unneeded 0x00; longLength puts
// the SEQUENCE length in long form; trailing is appended after the SEQUENCE.
export function rawToDer(raw, { padR = false, padS = false, longLength = false, trailing = null } = {}) {
  const half = raw.length / 2;
  let r = minimalUnsigned(raw.slice(0, half));
  let s = minimalUnsigned(raw.slice(half));
  if (padR) r = concat([0], r);
  if (padS) s = concat([0], s);
  const body = concat([0x02, ...derLength(r.length)], r, [0x02, ...derLength(s.length)], s);
  const der = concat([0x30, ...derLength(body.length, longLength)], body);
  return trailing ? concat(der, trailing) : der;
}

const SHA256_DIGEST_INFO = Uint8Array.from([
  0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
]);

// EMSA-PKCS1-v1_5 (RFC 8017 §9.2): 00 01 FF…FF 00 DigestInfo H. With e = 1
// this IS a valid signature, because s^1 mod n = s.
export function emsaPkcs1v15(digest, k) {
  const t = concat(SHA256_DIGEST_INFO, digest);
  const em = new Uint8Array(k);
  em[1] = 0x01;
  em.fill(0xff, 2, k - t.length - 1);
  em.set(t, k - t.length);
  return em;
}

function unsignedBytes(n) {
  if (n === 0) return Uint8Array.from([0]);
  const out = [];
  let v = BigInt(n);
  while (v > 0n) {
    out.unshift(Number(v & 255n));
    v >>= 8n;
  }
  return Uint8Array.from(out);
}

function handMadeModulus(bits) {
  const len = Math.ceil(bits / 8);
  const n = crypto.getRandomValues(new Uint8Array(len));
  const top = bits - (len - 1) * 8;
  n[0] = (n[0] & ((1 << top) - 1)) | (1 << (top - 1));
  n[len - 1] |= 1;
  return n;
}

function fitTo(bytes, len) {
  if (bytes.length >= len) return bytes.slice(bytes.length - len);
  return concat(new Uint8Array(len - bytes.length), bytes);
}

// ---------------------------------------------------------------- the authenticator

export class SoftAuthenticator {
  constructor({ alg = -7, origin = 'https://staff.example.com', rpId = 'staff.example.com', signCount = 0, increment = true } = {}) {
    if (alg !== -7 && alg !== -257) throw new RangeError('SoftAuthenticator: alg must be -7 or -257');
    this.alg = alg;
    this.origin = origin;
    this.rpId = rpId;
    this.signCount = signCount;
    this.increment = increment;
    this.credentials = new Map(); // b64url id → { id, alg, keyPair, n, forgeable, userHandle }
  }

  get lastCredential() {
    return [...this.credentials.values()].pop() || null;
  }

  async _keyPair() {
    const params =
      this.alg === -7
        ? { name: 'ECDSA', namedCurve: 'P-256' }
        : { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: Uint8Array.from([1, 0, 1]), hash: 'SHA-256' };
    return crypto.subtle.generateKey(params, true, ['sign', 'verify']);
  }

  async _cose(keyPair, k) {
    const jwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
    let cose;
    let n = null;
    if (this.alg === -7) {
      let x = fromB64u(jwk.x);
      let y = fromB64u(jwk.y);
      if (k.ecCoordinateLength !== undefined) {
        x = fitTo(x, k.ecCoordinateLength);
        y = fitTo(y, k.ecCoordinateLength);
      }
      cose = new Map([[1, 2], [3, k.algMismatch ? -257 : -7], [-1, k.ecCurve ?? 1], [-2, x], [-3, y]]);
    } else {
      n = fromB64u(jwk.n);
      let modulus = n;
      if (k.rsaModulusBits !== undefined) modulus = handMadeModulus(k.rsaModulusBits);
      if (k.rsaModulusEven) {
        modulus = modulus.slice();
        modulus[modulus.length - 1] &= 0xfe;
      }
      let e = fromB64u(jwk.e);
      if (k.rsaExponent !== undefined) e = k.rsaExponent instanceof Uint8Array ? k.rsaExponent : unsignedBytes(k.rsaExponent);
      cose = new Map([[1, 3], [3, k.algMismatch ? -7 : -257], [-1, modulus], [-2, e]]);
    }
    if (k.alg !== undefined) cose.set(3, k.alg);
    if (typeof k.coseEdit === 'function') cose = k.coseEdit(cose) || cose;
    return { cose, n };
  }

  _clientData(type, challenge, k) {
    if (k.clientDataJSON !== undefined) return enc.encode(k.clientDataJSON);
    const cd = {
      type: k.type ?? type,
      challenge: k.challenge ?? challenge,
      origin: k.origin ?? this.origin,
      crossOrigin: false,
      ...(k.clientData || {}),
    };
    return enc.encode(JSON.stringify(cd));
  }

  _flags(def, k) {
    if (typeof k.flags === 'number') return k.flags;
    let f = def;
    if (k.extensions !== undefined) f |= FLAGS.ED;
    if (k.flags && typeof k.flags === 'object') {
      for (const [name, on] of Object.entries(k.flags)) {
        if (!(name in FLAGS)) throw new RangeError(`SoftAuthenticator: unknown flag ${name}`);
        f = on ? f | FLAGS[name] : f & ~FLAGS[name];
      }
    }
    return f;
  }

  _reshape(authData, k) {
    let out = authData;
    if (k.extensions !== undefined) out = concat(out, encodeCbor(k.extensions));
    if (k.truncate) out = out.slice(0, out.length - k.truncate);
    if (k.extend !== undefined) out = concat(out, typeof k.extend === 'number' ? new Uint8Array(k.extend) : k.extend);
    return out;
  }

  _finish(json, k) {
    if (k.id !== undefined) json.id = k.id;
    if (k.rawId !== undefined) json.rawId = k.rawId;
    if (k.credentialType !== undefined) json.type = k.credentialType;
    return typeof k.transform === 'function' ? k.transform(json) || json : json;
  }

  async create(options, k = {}) {
    if (k.rpId === undefined && options?.rp?.id !== this.rpId) throw domError('SecurityError');
    for (const ex of options.excludeCredentials || []) if (this.credentials.has(ex.id)) throw domError('InvalidStateError');
    const keyPair = await this._keyPair();
    const credId = k.credentialId ? Uint8Array.from(k.credentialId) : crypto.getRandomValues(new Uint8Array(k.credentialIdLength ?? 32));
    const { cose, n } = await this._cose(keyPair, k);
    const clientDataJSON = this._clientData('webauthn.create', options.challenge, k);
    const rpIdHash = await sha256(k.rpId ?? this.rpId);
    const attested = k.attestedData !== false;
    const flags = this._flags(FLAGS.UP | FLAGS.UV | (attested ? FLAGS.AT : 0), k);
    const count = k.signCount ?? this.signCount;
    const head = (hash) =>
      attested
        ? concat(hash, [flags], u32(count), k.aaguid ?? TEST_AAGUID, [credId.length >> 8, credId.length & 255], credId, encodeCbor(cose))
        : concat(hash, [flags], u32(count));
    const authData = this._reshape(head(rpIdHash), k);
    const fmt = k.fmt ?? 'none';
    const attStmt = k.attStmt ?? new Map();
    let attestationObject;
    if (k.duplicateKey) {
      const decoy = this._reshape(head(await sha256('evil.example')), k);
      const pairs = k.duplicateKey === 'realFirst' ? [authData, decoy] : [decoy, authData];
      attestationObject = encodeCbor(new CborPairs([['fmt', fmt], ['attStmt', attStmt], ['authData', pairs[0]], ['authData', pairs[1]]]));
    } else {
      attestationObject = encodeCbor(new Map([['fmt', fmt], ['attStmt', attStmt], ['authData', authData]]));
    }
    const id = b64u(credId);
    this.credentials.set(id, {
      id,
      alg: this.alg,
      keyPair,
      n,
      forgeable: k.rsaExponent === 1,
      userHandle: options?.user?.id ?? null,
    });
    const json = {
      id,
      rawId: id,
      type: 'public-key',
      response: {
        clientDataJSON: b64u(clientDataJSON),
        attestationObject: b64u(attestationObject),
        transports: k.transports ?? ['internal', 'hybrid'],
      },
    };
    return this._finish(json, k);
  }

  async _sign(cred, data, k) {
    if (k.signature !== undefined) return k.signature instanceof Uint8Array ? k.signature : Uint8Array.from(k.signature);
    if (k.forge || cred.forgeable) {
      if (!cred.n) throw new Error('SoftAuthenticator: forging needs an RSA credential');
      return emsaPkcs1v15(await sha256(data), cred.n.length);
    }
    const signed = k.badSignature ? concat(data.slice(0, -1), [data[data.length - 1] ^ 1]) : data;
    if (cred.alg === -257) {
      return new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', cred.keyPair.privateKey, signed));
    }
    const mode = k.nonMinimalDer === true ? 'leading-zero' : k.nonMinimalDer;
    for (let attempt = 0; attempt < 64; attempt++) {
      const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, cred.keyPair.privateKey, signed));
      const opts = { trailing: k.trailingDer ? (k.trailingDer === true ? [0x00] : k.trailingDer) : null };
      if (mode === 'long-length') opts.longLength = true;
      if (mode === 'leading-zero') {
        // Pad an integer whose high bit is clear: one extra zero then decodes
        // to the same value within the coordinate width, so only the
        // minimality rule can refuse it. ECDSA is randomised; sign again
        // until r or s qualifies.
        if (!(raw[0] & 0x80) && raw[0] !== 0) opts.padR = true;
        else if (!(raw[32] & 0x80) && raw[32] !== 0) opts.padS = true;
        else continue;
      }
      return rawToDer(raw, opts);
    }
    throw new Error('SoftAuthenticator: could not produce the requested DER shape');
  }

  async get(options, k = {}) {
    if (k.rpId === undefined && options?.rpId !== this.rpId) throw domError('SecurityError');
    let cred = null;
    if (k.credential !== undefined) cred = this.credentials.get(k.credential) || null;
    else for (const c of options.allowCredentials || []) if (!cred && this.credentials.has(c.id)) cred = this.credentials.get(c.id);
    if (!cred) throw domError('NotAllowedError');
    let count;
    if (k.signCount !== undefined) count = k.signCount;
    else {
      if (this.increment) this.signCount += 1;
      count = this.signCount;
    }
    const clientDataJSON = this._clientData('webauthn.get', options.challenge, k);
    const rpIdHash = await sha256(k.rpId ?? this.rpId);
    const flags = this._flags(FLAGS.UP | FLAGS.UV, k);
    const authData = this._reshape(concat(rpIdHash, [flags], u32(count)), k);
    const signature = await this._sign(cred, concat(authData, await sha256(clientDataJSON)), k);
    const response = {
      clientDataJSON: b64u(clientDataJSON),
      authenticatorData: b64u(authData),
      signature: b64u(signature),
    };
    const handle = k.userHandle !== undefined ? k.userHandle : cred.userHandle;
    if (handle !== null && handle !== undefined) response.userHandle = handle;
    return this._finish({ id: cred.id, rawId: cred.id, type: 'public-key', response }, k);
  }
}
