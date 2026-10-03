// Strict CBOR decoder (RFC 8949) for the subset WebAuthn uses: unsigned and
// negative integers, byte and text strings, arrays, maps, false/true/null.
//
// Everything else is refused rather than guessed at: indefinite lengths,
// tags, floats, other simple values, integers beyond 2^53, map keys that are
// not integers or text, invalid UTF-8, and — the one that matters — DUPLICATE
// MAP KEYS (A §7.4 detail 2). RFC 8949 §5.6 calls such a map invalid; "last one
// wins" is a parser differential: {"authData":A,"authData":B} reads as B here
// and as A to anything that stops at the first match.
//
// Non-minimal argument encodings are accepted: they decode to one unambiguous
// value, and refusing them would refuse authenticators for no security gain.
//
//   decodeCbor(bytes)        → value; the input must be exactly one item
//   decodeCborPrefix(bytes)  → { value, length } for the COSE key and
//                              extensions embedded in authenticator data
//
// Maps decode to Map (no prototype to pollute), byte strings to fresh
// Uint8Array copies, arrays to arrays.

export class CborError extends Error {
  constructor(code, message) {
    super(`cbor: ${message}`);
    this.name = 'CborError';
    this.code = code;
  }
}

export const MAX_INPUT_BYTES = 64 * 1024;
export const MAX_DEPTH = 16;

const utf8Fatal = new TextDecoder('utf-8', { fatal: true });

function asBytes(input) {
  if (!(input instanceof Uint8Array)) throw new CborError('bad_input', 'input is not a Uint8Array');
  if (input.length > MAX_INPUT_BYTES) throw new CborError('too_long', `input over ${MAX_INPUT_BYTES} bytes`);
  return input;
}

class Reader {
  constructor(bytes) {
    this.b = bytes;
    this.o = 0;
  }

  need(n) {
    if (n > this.b.length - this.o) throw new CborError('truncated', 'unexpected end of input');
  }

  u8() {
    this.need(1);
    return this.b[this.o++];
  }

  // The argument of an initial byte. 24..27 → 1/2/4/8 following bytes;
  // 28..30 are reserved; 31 is indefinite length, which we never accept.
  arg(info) {
    if (info < 24) return info;
    if (info === 24) return this.u8();
    if (info === 25 || info === 26) {
      const n = info === 25 ? 2 : 4;
      this.need(n);
      let v = 0;
      for (let i = 0; i < n; i++) v = v * 256 + this.b[this.o++];
      return v;
    }
    if (info === 27) {
      this.need(8);
      let hi = 0;
      let lo = 0;
      for (let i = 0; i < 4; i++) hi = hi * 256 + this.b[this.o++];
      for (let i = 0; i < 4; i++) lo = lo * 256 + this.b[this.o++];
      // 2^53 - 1 is hi = 0x1fffff, lo = 0xffffffff: anything above would round.
      if (hi > 0x1fffff) throw new CborError('int_range', 'integer beyond 2^53');
      return hi * 2 ** 32 + lo;
    }
    if (info === 31) throw new CborError('indefinite_length', 'indefinite-length item');
    throw new CborError('reserved', `reserved additional info ${info}`);
  }

  bytes(n) {
    this.need(n);
    const out = this.b.slice(this.o, this.o + n);
    this.o += n;
    return out;
  }

  item(depth) {
    if (depth > MAX_DEPTH) throw new CborError('too_deep', `nesting deeper than ${MAX_DEPTH}`);
    const ib = this.u8();
    const major = ib >> 5;
    const info = ib & 0x1f;
    switch (major) {
      case 0:
        return this.arg(info);
      case 1: {
        const v = this.arg(info);
        // -1 - v must stay a safe integer too.
        if (v >= Number.MAX_SAFE_INTEGER) throw new CborError('int_range', 'integer beyond -2^53');
        return -1 - v;
      }
      case 2:
        return this.bytes(this.arg(info));
      case 3: {
        const raw = this.bytes(this.arg(info));
        try {
          return utf8Fatal.decode(raw);
        } catch {
          throw new CborError('bad_utf8', 'text string is not valid UTF-8');
        }
      }
      case 4: {
        const n = this.arg(info);
        // Every element takes at least one byte: refuse an absurd count before
        // looping over it.
        this.need(n);
        const out = [];
        for (let i = 0; i < n; i++) out.push(this.item(depth + 1));
        return out;
      }
      case 5: {
        const n = this.arg(info);
        this.need(n * 2);
        const out = new Map();
        const seen = new Set();
        for (let i = 0; i < n; i++) {
          const k = this.item(depth + 1);
          let id;
          if (typeof k === 'number') id = `i${k}`;
          else if (typeof k === 'string') id = `s${k}`;
          else throw new CborError('bad_key', 'map key is not an integer or text string');
          if (seen.has(id)) throw new CborError('duplicate_key', `duplicate map key ${JSON.stringify(k)}`);
          seen.add(id);
          out.set(k, this.item(depth + 1));
        }
        return out;
      }
      case 6:
        throw new CborError('unsupported', 'tagged items are not used by WebAuthn');
      default: {
        // Major 7: only false, true and null. Floats and other simple values
        // have no place in authenticator output.
        if (info === 20) return false;
        if (info === 21) return true;
        if (info === 22) return null;
        if (info === 31) throw new CborError('indefinite_length', 'unexpected break');
        throw new CborError('unsupported', `simple/float value ${info}`);
      }
    }
  }
}

export function decodeCborPrefix(input) {
  const r = new Reader(asBytes(input));
  const value = r.item(0);
  return { value, length: r.o };
}

export function decodeCbor(input) {
  const bytes = asBytes(input);
  const { value, length } = decodeCborPrefix(bytes);
  if (length !== bytes.length) throw new CborError('trailing_bytes', `${bytes.length - length} trailing byte(s)`);
  return value;
}
