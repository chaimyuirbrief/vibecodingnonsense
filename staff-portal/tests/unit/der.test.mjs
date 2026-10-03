// src/webauthn/der.js — strict DER ECDSA → raw r‖s (CONTRACTS §7.5; A §7.4 detail 1).

import { test, assert, run } from '../helpers/t.js';
import { derToRaw, DerError } from '../../src/webauthn/der.js';
import { rawToDer } from '../helpers/authenticator.js';

const HOSTILE = [null, undefined, NaN, Infinity, '', '   ', 'abc', {}, [], true, 0, Symbol('x')];
const show = (v) => (typeof v === 'symbol' ? 'Symbol' : JSON.stringify(v) ?? String(v));
const h = (s) => Uint8Array.from(Buffer.from(s.replace(/\s+/g, ''), 'hex'));
const ff = (n) => 'ff'.repeat(n);
const x7 = (n) => '7f'.repeat(n);

function refuses(bytes, code, label, coord = 32) {
  assert.throws(
    () => derToRaw(bytes, coord),
    (e) => e instanceof DerError && e.code === code,
    `${label} → expected DerError ${code}`,
  );
}

async function realSignature(data = new Uint8Array([1, 2, 3])) {
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, data));
  return { kp, raw, data };
}

test('minimal r = 1, s = 1 decodes to left-padded 32-byte coordinates', () => {
  const out = derToRaw(h('30 06 02 01 01 02 01 01'));
  assert.equal(out.length, 64);
  const want = new Uint8Array(64);
  want[31] = 1;
  want[63] = 1;
  assert.deepEqual(out, want);
});

test('a high-bit integer carries exactly one leading zero and decodes to 32 bytes', () => {
  const r = '80' + '11'.repeat(31);
  const s = '7f' + '22'.repeat(31);
  const der = h(`30 45 02 21 00 ${r} 02 20 ${s}`);
  assert.equal(Buffer.from(derToRaw(der)).toString('hex'), r + s);
});

test('real WebCrypto signatures: canonical DER decodes back to the exact r‖s and verifies', async () => {
  const { kp, raw, data } = await realSignature();
  for (let i = 0; i < 40; i++) {
    const sig = i === 0 ? raw : new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, data));
    const back = derToRaw(rawToDer(sig));
    assert.deepEqual(back, sig);
    assert.ok(await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, kp.publicKey, back, data));
  }
});

test('non-minimal lengths: long form below 128, two-byte form below 256, indefinite, over two bytes', () => {
  refuses(h('30 81 06 02 01 01 02 01 01'), 'non_minimal_length', 'SEQUENCE 0x81 06');
  refuses(h('30 82 00 06 02 01 01 02 01 01'), 'non_minimal_length', 'SEQUENCE 0x82 0006');
  refuses(h('30 07 02 81 01 01 02 01 01'), 'non_minimal_length', 'INTEGER 0x81 01');
  refuses(h('30 80 02 01 01 02 01 01 00 00'), 'indefinite_length', 'SEQUENCE 0x80');
  refuses(h('30 83 00 00 06 02 01 01 02 01 01'), 'length_too_long', 'three length bytes');
  // 0x81 is legitimate at 128+: a P-521-sized signature uses it.
  const r = '01' + '33'.repeat(65);
  const ok = h(`30 81 88 02 42 ${r} 02 42 ${r}`);
  assert.equal(derToRaw(ok, 66).length, 132);
});

test('non-minimal integers: an unneeded leading zero, even on a 32-byte value', () => {
  refuses(h('30 07 02 02 00 01 02 01 01'), 'non_minimal_integer', 'r = 00 01');
  refuses(h('30 07 02 01 01 02 02 00 7f'), 'non_minimal_integer', 's = 00 7f');
  // 33 bytes whose stripped form would fit a coordinate: only minimality refuses it.
  refuses(h(`30 45 02 21 00 ${x7(32)} 02 20 ${x7(32)}`), 'non_minimal_integer', 'r = 00 7f…(32)');
  refuses(h(`30 45 02 21 00 00 ${ff(31)} 02 20 ${x7(32)}`), 'non_minimal_integer', 'r = 00 00 ff…');
});

test('negative, zero and empty integers are refused', () => {
  refuses(h('30 06 02 01 80 02 01 01'), 'negative_integer', 'r = 0x80');
  refuses(h('30 06 02 01 01 02 01 ff'), 'negative_integer', 's = 0xff');
  refuses(h(`30 44 02 20 ${ff(32)} 02 20 ${x7(32)}`), 'negative_integer', 'r high bit, no zero');
  refuses(h('30 06 02 01 00 02 01 01'), 'zero_integer', 'r = 0');
  refuses(h('30 05 02 00 02 01 01'), 'empty_integer', 'r empty');
});

test('integers wider than a coordinate are refused (33 magnitude bytes, 34 encoded)', () => {
  refuses(h(`30 46 02 22 00 ${ff(33)} 02 20 ${x7(32)}`), 'integer_too_wide', '00 + 33 high bytes');
  refuses(h(`30 45 02 21 01 ${ff(32)} 02 20 ${x7(32)}`), 'integer_too_wide', '33 bytes, no zero');
  refuses(h(`30 45 02 20 ${x7(32)} 02 21 01 ${ff(32)}`), 'integer_too_wide', 's too wide');
  // The same bytes are fine for a wider curve.
  assert.equal(derToRaw(h(`30 45 02 21 01 ${ff(32)} 02 20 ${x7(32)}`), 48).length, 96);
});

test('trailing bytes after the SEQUENCE and inside it are refused; a short SEQUENCE is truncated', () => {
  refuses(h('30 06 02 01 01 02 01 01 00'), 'trailing_bytes', 'after the SEQUENCE');
  refuses(h('30 09 02 01 01 02 01 01 05 00 00'), 'trailing_bytes', 'NULL after s inside the SEQUENCE');
  refuses(h('30 08 02 01 01 02 01 01'), 'truncated', 'outer length longer than input');
  refuses(h('30 06 02 01 01 02 02 01'), 'truncated', 's runs past the SEQUENCE');
  refuses(h('30 03 02 01 01'), 'expected_integer', 'missing s');
  refuses(h('30 06 02 01 01 03 01 01'), 'expected_integer', 's is a BIT STRING');
  refuses(h('31 06 02 01 01 02 01 01'), 'expected_sequence', 'SET, not SEQUENCE');
  refuses(h('30'), 'expected_sequence', 'one byte');
  refuses(new Uint8Array(0), 'expected_sequence', 'empty');
});

test('one signature, one accepted encoding: every malleable variant of a real one is refused', async () => {
  let raw;
  // Need r and s both with the high bit clear and non-zero first byte so
  // padding either yields a 33-byte, otherwise-in-range integer.
  const { kp, data } = await realSignature();
  for (;;) {
    raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, data));
    if (raw[0] && !(raw[0] & 0x80) && raw[32] && !(raw[32] & 0x80)) break;
  }
  assert.deepEqual(derToRaw(rawToDer(raw)), raw);
  refuses(rawToDer(raw, { padR: true }), 'non_minimal_integer', 'padded r');
  refuses(rawToDer(raw, { padS: true }), 'non_minimal_integer', 'padded s');
  refuses(rawToDer(raw, { longLength: true }), 'non_minimal_length', 'long-form length');
  refuses(rawToDer(raw, { trailing: [0] }), 'trailing_bytes', 'trailing 00');
  refuses(rawToDer(raw, { trailing: rawToDer(raw) }), 'trailing_bytes', 'signature twice');
});

test('hostile inputs and bad coordinate sizes throw DerError, never TypeError', () => {
  for (const v of [...HOSTILE, new ArrayBuffer(8), [0x30, 0x00]]) {
    assert.throws(() => derToRaw(v), (e) => e instanceof DerError && e.code === 'bad_input', show(v));
  }
  const good = h('30 06 02 01 01 02 01 01');
  for (const c of [0, -1, 67, 32.5, NaN, Infinity, '32', null, true, {}]) {
    assert.throws(() => derToRaw(good, c), (e) => e instanceof DerError && e.code === 'bad_input', `coord ${show(c)}`);
  }
  assert.equal(derToRaw(good, undefined).length, 64, 'undefined → default 32');
});

await run();
