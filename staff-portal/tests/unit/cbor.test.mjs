// src/webauthn/cbor.js — strict decoder (CONTRACTS §7.5; A §7.4 detail 2).

import { test, assert, run } from '../helpers/t.js';
import { decodeCbor, decodeCborPrefix, CborError, MAX_DEPTH, MAX_INPUT_BYTES } from '../../src/webauthn/cbor.js';
import { encodeCbor, CborPairs, CborRaw } from '../helpers/authenticator.js';

const HOSTILE = [null, undefined, NaN, Infinity, '', '   ', 'abc', {}, [], true, 0, Symbol('x')];
const show = (v) => (typeof v === 'symbol' ? 'Symbol' : JSON.stringify(v) ?? String(v));
const h = (s) => Uint8Array.from(Buffer.from(s.replace(/\s+/g, ''), 'hex'));

function refuses(bytes, code, label = '') {
  assert.throws(
    () => decodeCbor(bytes),
    (e) => e instanceof CborError && e.code === code,
    `${label || Buffer.from(bytes).toString('hex').slice(0, 40)} → expected CborError ${code}`,
  );
}

test('RFC 8949 Appendix A vectors in the supported subset', () => {
  const cases = [
    ['00', 0], ['01', 1], ['0a', 10], ['17', 23], ['1818', 24], ['1864', 100], ['1903e8', 1000],
    ['1a000f4240', 1000000], ['1b000000e8d4a51000', 1000000000000],
    ['20', -1], ['29', -10], ['3863', -100], ['3903e7', -1000],
    ['60', ''], ['6161', 'a'], ['6449455446', 'IETF'], ['62225c', '"\\'], ['62c3bc', 'ü'], ['63e6b0b4', '水'],
    ['f4', false], ['f5', true], ['f6', null],
    ['80', []], ['83010203', [1, 2, 3]], ['8301820203820405', [1, [2, 3], [4, 5]]],
  ];
  for (const [hex, want] of cases) assert.deepEqual(decodeCbor(h(hex)), want, hex);
  assert.deepEqual(decodeCbor(h('40')), new Uint8Array(0));
  assert.deepEqual(decodeCbor(h('4401020304')), Uint8Array.from([1, 2, 3, 4]));
  const m = decodeCbor(h('a201020304'));
  assert.ok(m instanceof Map);
  assert.deepEqual([...m], [[1, 2], [3, 4]]);
  const m2 = decodeCbor(h('a26161016162820203'));
  assert.deepEqual([...m2], [['a', 1], ['b', [2, 3]]]);
  assert.deepEqual([...decodeCbor(h('a0'))], []);
});

test('largest safe integers decode; anything beyond 2^53 is refused, not rounded', () => {
  assert.equal(decodeCbor(h('1b001fffffffffffff')), Number.MAX_SAFE_INTEGER);
  assert.equal(decodeCbor(h('3b001ffffffffffffe')), -Number.MAX_SAFE_INTEGER);
  refuses(h('1b0020000000000000'), 'int_range');
  refuses(h('1bffffffffffffffff'), 'int_range');
  refuses(h('3b001fffffffffffff'), 'int_range', '-2^53 - 0');
  refuses(h('3bffffffffffffffff'), 'int_range');
});

test('duplicate map keys are refused — integer, text, and the authData parser differential', () => {
  refuses(h('a2 01 02 01 03'), 'duplicate_key', '{1:2, 1:3}');
  refuses(h('a2 6161 01 6161 02'), 'duplicate_key', '{"a":1, "a":2}');
  refuses(h('a2 20 01 20 02'), 'duplicate_key', '{-1:1, -1:2}');
  const A = Uint8Array.from([1, 2, 3]);
  const B = Uint8Array.from([4, 5, 6]);
  const bytes = encodeCbor(new CborPairs([['fmt', 'none'], ['authData', A], ['authData', B]]));
  refuses(bytes, 'duplicate_key', '{"fmt":"none","authData":A,"authData":B}');
  // Nested maps too.
  refuses(encodeCbor(new Map([['x', new CborPairs([[3, 1], [3, 1]])]])), 'duplicate_key', 'nested');
  // Same spelling in different types is not a duplicate: 1, -1 and "1" are three keys.
  const ok = decodeCbor(encodeCbor(new CborPairs([[1, 'a'], [-1, 'b'], ['1', 'c']])));
  assert.deepEqual([...ok], [[1, 'a'], [-1, 'b'], ['1', 'c']]);
});

test('map keys must be integers or text', () => {
  refuses(h('a1 4101 00'), 'bad_key', 'byte-string key');
  refuses(h('a1 80 00'), 'bad_key', 'array key');
  refuses(h('a1 a0 00'), 'bad_key', 'map key');
  refuses(h('a1 f6 00'), 'bad_key', 'null key');
  refuses(h('a1 f5 00'), 'bad_key', 'true key');
});

test('indefinite lengths are refused for every major type, and a bare break', () => {
  refuses(h('5f 4101 ff'), 'indefinite_length', 'bytes');
  refuses(h('7f 6161 ff'), 'indefinite_length', 'text');
  refuses(h('9f 01 ff'), 'indefinite_length', 'array');
  refuses(h('bf 01 02 ff'), 'indefinite_length', 'map');
  refuses(h('ff'), 'indefinite_length', 'break');
  refuses(h('1f'), 'indefinite_length', 'uint with info 31');
});

test('reserved additional info, tags, floats and other simple values are refused', () => {
  for (const b of ['1c', '1d', '1e', '3c', '5c', '7c', '9c', 'bc']) refuses(h(b), 'reserved', b);
  refuses(h('c0 74 323031332d30332d32315432303a30343a30305a'), 'unsupported', 'tag 0');
  refuses(h('d8 18 45 6449455446'), 'unsupported', 'tag 24');
  refuses(h('f9 3c00'), 'unsupported', 'half float');
  refuses(h('fa 47c35000'), 'unsupported', 'single float');
  refuses(h('fb 3ff199999999999a'), 'unsupported', 'double float');
  refuses(h('f7'), 'unsupported', 'undefined');
  refuses(h('f0'), 'unsupported', 'simple(16)');
  refuses(h('f8 ff'), 'unsupported', 'simple(255)');
});

test('trailing bytes: decodeCbor refuses them, decodeCborPrefix reports the exact length', () => {
  refuses(h('00 00'), 'trailing_bytes');
  refuses(h('a1 01 02 ff'), 'trailing_bytes');
  assert.deepEqual(decodeCborPrefix(h('00 00')), { value: 0, length: 1 });
  const cose = encodeCbor(new Map([[1, 2], [3, -7]]));
  const withTail = Uint8Array.from([...cose, 0xa0, 0x99]);
  const p = decodeCborPrefix(withTail);
  assert.equal(p.length, cose.length);
  assert.deepEqual([...p.value], [[1, 2], [3, -7]]);
});

test('truncated input is refused everywhere it can end early', () => {
  for (const b of ['', '18', '19 01', '1a 0102', '1b 01020304050607', '44 0102', '62 61', '82 01', 'a1 01', 'a2 01 02 03']) {
    refuses(h(b), 'truncated', b || '(empty)');
  }
});

test('absurd declared lengths fail fast without allocating or looping', () => {
  const t0 = Date.now();
  refuses(h('9b 001fffffffffffff'), 'truncated', 'array of 2^53-1');
  refuses(h('bb 001fffffffffffff'), 'truncated', 'map of 2^53-1');
  refuses(h('5b 001fffffffffffff'), 'truncated', 'bytes of 2^53-1');
  refuses(h('7a ffffffff'), 'truncated', 'text of 2^32-1');
  refuses(h('9a ffffffff 00'), 'truncated', 'array of 2^32-1 with one element');
  assert.ok(Date.now() - t0 < 200, 'refused quickly');
});

test(`nesting is capped at ${MAX_DEPTH}; deeper input is refused, never a stack overflow`, () => {
  const nested = (n) => Uint8Array.from([...new Array(n).fill(0x81), 0x00]);
  let v = decodeCbor(nested(MAX_DEPTH));
  for (let i = 0; i < MAX_DEPTH; i++) v = v[0];
  assert.equal(v, 0);
  refuses(nested(MAX_DEPTH + 1), 'too_deep');
  refuses(Uint8Array.from([...new Array(60000).fill(0x81), 0x00]), 'too_deep', '60k deep');
  // Maps count as nesting too.
  const maps = Uint8Array.from([...new Array(MAX_DEPTH + 1).fill([0xa1, 0x01]).flat(), 0x00]);
  refuses(maps, 'too_deep', 'nested maps');
});

test(`input over ${MAX_INPUT_BYTES} bytes is refused before parsing`, () => {
  const big = new Uint8Array(MAX_INPUT_BYTES + 1);
  big[0] = 0x5a; // a byte string that would otherwise be read
  refuses(big, 'too_long');
  assert.throws(() => decodeCborPrefix(big), (e) => e instanceof CborError && e.code === 'too_long');
  // Exactly at the cap is fine.
  const body = MAX_INPUT_BYTES - 5;
  const ok = new Uint8Array(MAX_INPUT_BYTES);
  ok.set([0x5a, (body >>> 24) & 255, (body >>> 16) & 255, (body >>> 8) & 255, body & 255]);
  assert.equal(decodeCbor(ok).length, body);
});

test('text must be valid UTF-8', () => {
  refuses(h('62 c328'), 'bad_utf8');
  refuses(h('61 ff'), 'bad_utf8');
  refuses(h('63 eda080'), 'bad_utf8', 'encoded surrogate');
  refuses(h('a1 61ff 00'), 'bad_utf8', 'as a map key');
});

test('hostile non-byte inputs throw CborError, never TypeError', () => {
  for (const v of [...HOSTILE, new ArrayBuffer(1), [0x00], Buffer.from([0]).toString(), new Uint16Array(1)]) {
    for (const fn of [decodeCbor, decodeCborPrefix]) {
      assert.throws(() => fn(v), (e) => e instanceof CborError && e.code === 'bad_input', `${fn.name}(${show(v)})`);
    }
  }
  // A Node Buffer is a Uint8Array and is accepted.
  assert.equal(decodeCbor(Buffer.from([0x05])), 5);
});

test('maps are Maps: "__proto__" is an ordinary key and pollutes nothing', () => {
  const m = decodeCbor(encodeCbor(new Map([['__proto__', 1], ['constructor', 2]])));
  assert.ok(m instanceof Map);
  assert.equal(m.get('__proto__'), 1);
  assert.equal({}.constructor, Object);
  assert.equal(Object.prototype[1], undefined);
});

test('byte strings are copies, not views of the input', () => {
  const input = h('43 010203');
  const out = decodeCbor(input);
  input[1] = 0xff;
  assert.deepEqual([...out], [1, 2, 3]);
  assert.equal(out.byteOffset, 0);
  assert.equal(out.buffer.byteLength, 3);
});

test('non-minimal argument encodings decode to their one value (documented, not ambiguous)', () => {
  assert.equal(decodeCbor(h('18 00')), 0);
  assert.equal(decodeCbor(h('19 0001')), 1);
  assert.deepEqual(decodeCbor(h('78 01 61')), 'a');
});

test('round-trips WebAuthn-shaped structures from an independent encoder', () => {
  const att = new Map([
    ['fmt', 'none'],
    ['attStmt', new Map()],
    ['authData', crypto.getRandomValues(new Uint8Array(300))],
  ]);
  const back = decodeCbor(encodeCbor(att));
  assert.equal(back.get('fmt'), 'none');
  assert.equal(back.get('attStmt').size, 0);
  assert.deepEqual(back.get('authData'), att.get('authData'));
  const ints = [0, 23, 24, 255, 256, 65535, 65536, 2 ** 32 - 1, 2 ** 32, -1, -24, -25, -256, -257, -65537, -(2 ** 32) - 1];
  assert.deepEqual(decodeCbor(encodeCbor(ints)), ints);
  assert.deepEqual(decodeCbor(new CborRaw([0]).bytes), 0);
});

await run();
