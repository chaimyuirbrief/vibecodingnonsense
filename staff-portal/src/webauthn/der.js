// Strict DER → raw ECDSA signature (A §7.4 detail 1).
//
// WebAuthn hands over ASN.1 `SEQUENCE { INTEGER r, INTEGER s }`; WebCrypto
// wants r ‖ s, each left-padded to the coordinate size. Every rule below
// exists because a lenient reader accepts two encodings of one signature —
// signature malleability — and anything that identifies a signature by its
// bytes (a replay cache, a dedup key, an audit trail) can then be shown both:
//
//   * exact outer length, nothing after the SEQUENCE, nothing after s;
//   * minimal lengths: long form only above 127, two-byte form only above 255,
//     never indefinite;
//   * minimal integers: a leading 0x00 only to keep a high-bit value positive;
//   * no negative integer, no zero, nothing wider than a coordinate.

export class DerError extends Error {
  constructor(code, message) {
    super(`der: ${message}`);
    this.name = 'DerError';
    this.code = code;
  }
}

// → [length, offsetAfterLengthBytes]
function readLength(b, o) {
  if (o >= b.length) throw new DerError('truncated', 'missing length');
  const first = b[o];
  if (first < 0x80) return [first, o + 1];
  if (first === 0x80) throw new DerError('indefinite_length', 'indefinite length');
  if (first === 0x81) {
    if (o + 1 >= b.length) throw new DerError('truncated', 'missing length byte');
    const n = b[o + 1];
    if (n < 0x80) throw new DerError('non_minimal_length', 'long-form length below 128');
    return [n, o + 2];
  }
  if (first === 0x82) {
    if (o + 2 >= b.length) throw new DerError('truncated', 'missing length bytes');
    const n = (b[o + 1] << 8) | b[o + 2];
    if (n < 0x100) throw new DerError('non_minimal_length', 'two-byte length below 256');
    return [n, o + 3];
  }
  // No ECDSA signature needs more than two length bytes.
  throw new DerError('length_too_long', 'length wider than two bytes');
}

// → [magnitude bytes, offsetAfter]
function readInteger(b, o, end, coordinateBytes) {
  if (o >= end || b[o] !== 0x02) throw new DerError('expected_integer', 'expected INTEGER');
  const [len, start] = readLength(b, o + 1);
  if (len === 0) throw new DerError('empty_integer', 'zero-length INTEGER');
  const stop = start + len;
  if (stop > end) throw new DerError('truncated', 'INTEGER runs past the SEQUENCE');
  if (b[start] & 0x80) throw new DerError('negative_integer', 'negative INTEGER');
  let mag = b.subarray(start, stop);
  if (mag[0] === 0x00) {
    if (mag.length === 1) throw new DerError('zero_integer', 'INTEGER is zero');
    if (!(mag[1] & 0x80)) throw new DerError('non_minimal_integer', 'unneeded leading zero');
    mag = mag.subarray(1);
  }
  if (mag.length > coordinateBytes) throw new DerError('integer_too_wide', 'INTEGER wider than a coordinate');
  return [mag, stop];
}

export function derToRaw(der, coordinateBytes = 32) {
  if (!(der instanceof Uint8Array)) throw new DerError('bad_input', 'input is not a Uint8Array');
  if (!Number.isInteger(coordinateBytes) || coordinateBytes < 1 || coordinateBytes > 66) {
    throw new DerError('bad_input', 'bad coordinate size');
  }
  if (der.length < 2 || der[0] !== 0x30) throw new DerError('expected_sequence', 'expected SEQUENCE');
  const [len, body] = readLength(der, 1);
  if (body + len !== der.length) {
    throw new DerError(body + len > der.length ? 'truncated' : 'trailing_bytes', 'SEQUENCE length does not match the input');
  }
  const [r, afterR] = readInteger(der, body, der.length, coordinateBytes);
  const [s, afterS] = readInteger(der, afterR, der.length, coordinateBytes);
  if (afterS !== der.length) throw new DerError('trailing_bytes', 'bytes after s inside the SEQUENCE');
  const out = new Uint8Array(coordinateBytes * 2);
  out.set(r, coordinateBytes - r.length);
  out.set(s, coordinateBytes * 2 - s.length);
  return out;
}
