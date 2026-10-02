// The QR encoder is checked from the outside: every symbol generated here is
// read back by jsQR (an independent decoder), its function patterns and
// format word are read at the ISO 18004 positions by code in THIS file, and
// the SVG is parsed and painted by a rasteriser in this file — then compared
// cell by cell with the matrix. jsQR alone is not enough: it ignores pad
// codewords, silently retries a transposed symbol and (unless told not to)
// an inverted one (A §13.7).

import { test, assert, run } from '../helpers/t.js';
import { createHash } from 'node:crypto';
import jsQR from 'jsqr';
import { qrMatrix, qrSvg, qrDataUri, _internal } from '../../src/qr.js';

const enc = new TextEncoder();
const HOSTILE = [null, undefined, NaN, Infinity, -Infinity, '', '   ', 'abc', {}, [], true, false, 0, Symbol('x'), 10n, () => 1,
  { valueOf() { throw new Error('boom'); } }];
const label = (v) => (typeof v === 'symbol' ? 'Symbol' : typeof v === 'bigint' ? `${v}n` : typeof v === 'function' ? 'fn' : JSON.stringify(v) ?? String(v));

// Byte-mode capacity, ISO 18004 Table 7, versions 1–10.
const CAPACITY = {
  L: [17, 32, 53, 78, 106, 134, 154, 192, 230, 271],
  M: [14, 26, 42, 62, 84, 106, 122, 152, 180, 213],
  Q: [11, 20, 32, 46, 60, 74, 86, 108, 130, 151],
  H: [7, 14, 24, 34, 44, 58, 64, 84, 98, 119],
};
const ECC_OF_BITS = { 1: 'L', 0: 'M', 3: 'Q', 2: 'H' };
const VERSION_WORDS = { 7: 0x07c94, 8: 0x085bc, 9: 0x09a99, 10: 0x0a4d3 };
const SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
const OTPAUTH = `otpauth://totp/Acme%20Inc.:jane%40acme.com?secret=${SECRET}&issuer=Acme%20Inc.&algorithm=SHA1&digits=6&period=30`;

const bytesOf = (text) => (typeof text === 'string' ? enc.encode(text) : Uint8Array.from(text));
const expectedVersion = (len, ecc) => CAPACITY[ecc].findIndex((c) => len <= c) + 1;
const rows = (m) => m.map((r) => r.map((c) => (c ? '1' : '0')).join(''));
const sha = (m) => createHash('sha256').update(rows(m).join('\n')).digest('hex');

// ---------------------------------------------------------------- reading

// The 15 format bits, bit 0 first, at the ISO 18004 Figure 25 positions.
function formatPositions(n) {
  const one = [];
  for (let i = 0; i <= 5; i++) one.push([8, i]);
  one.push([8, 7], [8, 8], [7, 8]);
  for (let i = 9; i < 15; i++) one.push([14 - i, 8]);
  const two = [];
  for (let i = 0; i < 8; i++) two.push([n - 1 - i, 8]);
  for (let i = 8; i < 15; i++) two.push([8, n - 15 + i]);
  return [one, two];
}

function readWord(m, positions) {
  let v = 0;
  positions.forEach(([x, y], i) => {
    if (m[y][x]) v |= 1 << i;
  });
  return v;
}

function bchRemainder(word, bits, gen) {
  const genDeg = Math.floor(Math.log2(gen));
  for (let i = bits - 1; i >= genDeg; i--) if ((word >>> i) & 1) word ^= gen << (i - genDeg);
  return word;
}

// Asserts the fixed structure of a symbol in its upright orientation and
// returns { version, ecc, mask } read from it.
function structure(m, wantEcc) {
  const n = m.length;
  assert.ok(n >= 21 && (n - 17) % 4 === 0, `size ${n}`);
  for (const r of m) assert.equal(r.length, n);
  const version = (n - 17) / 4;
  const finderAt = (ox, oy) => {
    for (let dy = 0; dy < 7; dy++) {
      for (let dx = 0; dx < 7; dx++) if (m[oy + dy][ox + dx] !== (Math.max(Math.abs(dx - 3), Math.abs(dy - 3)) !== 2)) return false;
    }
    return true;
  };
  assert.ok(finderAt(0, 0), 'top-left finder');
  assert.ok(finderAt(n - 7, 0), 'top-right finder');
  assert.ok(finderAt(0, n - 7), 'bottom-left finder');
  assert.ok(!finderAt(n - 7, n - 7), 'no finder bottom-right');
  for (let i = 0; i < 8; i++) {
    // Separators.
    assert.equal(m[7][i] || m[i][7] || m[7][n - 1 - i] || m[i][n - 8] || m[n - 8][i] || m[n - 1 - i][7], false, 'separator');
  }
  for (let i = 8; i < n - 8; i++) {
    assert.equal(m[6][i], i % 2 === 0, `horizontal timing ${i}`);
    assert.equal(m[i][6], i % 2 === 0, `vertical timing ${i}`);
  }
  assert.equal(m[n - 8][8], true, 'dark module');
  const [p1, p2] = formatPositions(n);
  const f1 = readWord(m, p1);
  const f2 = readWord(m, p2);
  assert.equal(f1, f2, 'both format copies agree');
  assert.equal(bchRemainder(f1 ^ 0x5412, 15, 0x537), 0, 'format word is a BCH codeword');
  const data = (f1 ^ 0x5412) >>> 10;
  const ecc = ECC_OF_BITS[data >>> 3];
  if (wantEcc) assert.equal(ecc, wantEcc, 'ECC level in the format word');
  if (version >= 7) {
    let bl = 0;
    let tr = 0;
    for (let i = 0; i < 18; i++) {
      if (m[n - 11 + (i % 3)][Math.floor(i / 3)]) bl |= 1 << i;
      if (m[Math.floor(i / 3)][n - 11 + (i % 3)]) tr |= 1 << i;
    }
    assert.equal(bl, VERSION_WORDS[version], 'version info, bottom left');
    assert.equal(tr, VERSION_WORDS[version], 'version info, top right');
  }
  return { version, ecc, mask: data & 7 };
}

// ---------------------------------------------------------------- pixels

function withQuietZone(m, q) {
  const full = m.length + 2 * q;
  return Array.from({ length: full }, (_, y) => Array.from({ length: full }, (_, x) => {
    const mx = x - q;
    const my = y - q;
    return mx >= 0 && my >= 0 && mx < m.length && my < m.length && m[my][mx];
  }));
}

function rgba(cells, k = 4) {
  const w = cells.length * k;
  const px = new Uint8ClampedArray(w * w * 4).fill(255);
  for (let y = 0; y < cells.length; y++) {
    for (let x = 0; x < cells.length; x++) {
      if (!cells[y][x]) continue;
      for (let dy = 0; dy < k; dy++) {
        for (let dx = 0; dx < k; dx++) {
          const o = ((y * k + dy) * w + x * k + dx) * 4;
          px[o] = px[o + 1] = px[o + 2] = 0;
        }
      }
    }
  }
  return { px, w };
}

// dontInvert: a colour-swapped symbol must FAIL, not be rescued.
function jsqr(cells) {
  const { px, w } = rgba(cells);
  return jsQR(px, w, w, { inversionAttempts: 'dontInvert' });
}

function decodeCells(cells) {
  const r = jsqr(cells);
  return r ? Uint8Array.from(r.binaryData) : null;
}

// ---------------------------------------------------------------- SVG

function parseSvg(svg) {
  const re = /<(\/?)([a-zA-Z]+)((?:\s+[a-zA-Z:-]+="[^"<>]*")*)\s*(\/?)>/g;
  const tags = [];
  let pos = 0;
  let mt;
  while ((mt = re.exec(svg))) {
    assert.equal(mt.index, pos, `unexpected content in the SVG at ${pos}`);
    pos = re.lastIndex;
    const attrs = {};
    for (const a of mt[3].matchAll(/([a-zA-Z:-]+)="([^"]*)"/g)) {
      assert.ok(!(a[1] in attrs), `duplicate attribute ${a[1]}`);
      attrs[a[1]] = a[2];
    }
    tags.push({ close: mt[1] === '/', name: mt[2], attrs, selfClose: mt[4] === '/' });
  }
  assert.equal(pos, svg.length, 'trailing content after the SVG');
  assert.equal(tags[0].name, 'svg');
  assert.ok(!tags[0].close && !tags[0].selfClose);
  const last = tags[tags.length - 1];
  assert.ok(last.close && last.name === 'svg', 'closing </svg>');
  const children = tags.slice(1, -1);
  for (const c of children) assert.ok(c.selfClose && !c.close, `flat children only (${c.name})`);
  return { root: tags[0].attrs, children };
}

const int = (s) => {
  assert.match(String(s), /^-?\d+$/, `integer coordinate: ${s}`);
  return Number(s);
};

// Axis-aligned rectangles from M/m/H/h/V/v/Z/z subpaths; anything else fails.
function pathRects(d) {
  const tokens = [];
  const re = /\s*(?:([MmHhVvZz])|(-?\d+))\s*,?/gy;
  let mt;
  while (re.lastIndex < d.length && (mt = re.exec(d))) tokens.push(mt[1] ?? Number(mt[2]));
  assert.equal(re.lastIndex, d.length, `unparsed path data at ${re.lastIndex}`);
  const rects = [];
  let i = 0;
  let cx = 0;
  let cy = 0;
  let verts = null;
  const num = () => {
    assert.equal(typeof tokens[i], 'number', 'path number');
    return tokens[i++];
  };
  while (i < tokens.length) {
    const c = tokens[i++];
    if (c === 'M' || c === 'm') {
      assert.equal(verts, null, 'subpath left open');
      const x = num();
      const y = num();
      cx = c === 'M' ? x : cx + x;
      cy = c === 'M' ? y : cy + y;
      verts = [[cx, cy]];
    } else if ('HhVv'.includes(c)) {
      assert.ok(verts, 'drawing without a moveto');
      const v = num();
      if (c === 'H') cx = v;
      else if (c === 'h') cx += v;
      else if (c === 'V') cy = v;
      else cy += v;
      verts.push([cx, cy]);
    } else {
      assert.ok(c === 'Z' || c === 'z', `path command ${c}`);
      const xs = verts.map((p) => p[0]);
      const ys = verts.map((p) => p[1]);
      const box = [Math.min(...xs), Math.min(...ys), Math.max(...xs), Math.max(...ys)];
      const distinct = new Set(verts.map((p) => p.join()));
      assert.equal(distinct.size, 4, 'each subpath is a rectangle');
      for (const [x, y] of verts) assert.ok((x === box[0] || x === box[2]) && (y === box[1] || y === box[3]), 'rectangle corner');
      rects.push(box);
      [cx, cy] = verts[0];
      verts = null;
    }
  }
  assert.equal(verts, null, 'path ends with an open subpath');
  return rects;
}

function colour(fill) {
  if (/^(#fff|#ffffff|white)$/i.test(fill)) return false;
  if (/^(#000|#000000|black)$/i.test(fill)) return true;
  assert.fail(`unexpected fill ${fill}`);
}

// Paints the SVG one viewBox unit per cell. Returns { full, scale, cells }.
function svgCells(svg) {
  const { root, children } = parseSvg(svg);
  assert.equal(root.xmlns, 'http://www.w3.org/2000/svg');
  assert.equal(root['shape-rendering'], 'crispEdges');
  const vb = root.viewBox.split(' ').map(int);
  assert.equal(vb.length, 4);
  assert.deepEqual(vb.slice(0, 2), [0, 0], 'viewBox origin');
  assert.equal(vb[2], vb[3], 'square viewBox');
  const full = vb[2];
  const width = int(root.width);
  assert.equal(int(root.height), width);
  assert.equal(width % full, 0, 'whole pixels per module');
  // The plate comes first and covers the whole viewBox, quiet zone included.
  assert.ok(children.length >= 2);
  assert.equal(children[0].name, 'rect', 'white plate first');
  assert.equal(colour(children[0].attrs.fill), false, 'plate is white');
  assert.deepEqual(['x', 'y', 'width', 'height'].map((k) => int(children[0].attrs[k] ?? '0')), [0, 0, full, full], 'plate covers the viewBox');
  const cells = Array.from({ length: full }, () => new Array(full).fill(null));
  const paint = ([x0, y0, x1, y1], dark) => {
    assert.ok(x0 >= 0 && y0 >= 0 && x1 <= full && y1 <= full && x0 < x1 && y0 < y1, 'shape inside the viewBox');
    for (let y = y0; y < y1; y++) for (let x = x0; x < x1; x++) cells[y][x] = dark;
  };
  for (const c of children) {
    assert.ok(!('style' in c.attrs) && !('href' in c.attrs) && !('xlink:href' in c.attrs) && !('transform' in c.attrs), 'plain shapes only');
    const dark = colour(c.attrs.fill);
    if (c.name === 'rect') {
      const [x, y, w, h] = ['x', 'y', 'width', 'height'].map((k) => int(c.attrs[k] ?? '0'));
      paint([x, y, x + w, y + h], dark);
    } else {
      assert.equal(c.name, 'path');
      for (const r of pathRects(c.attrs.d)) paint(r, dark);
    }
  }
  for (const r of cells) for (const c of r) assert.notEqual(c, null, 'every cell painted');
  return { full, scale: width / full, cells };
}

// ---------------------------------------------------------------- the check

// Encode, verify structure, decode the matrix, render the SVG, compare it
// with the matrix cell by cell, decode the SVG. Returns the matrix.
function check(text, opts = {}) {
  const ecc = opts.ecc ?? 'M';
  const want = bytesOf(text);
  const m = qrMatrix(text, opts);
  const s = structure(m, ecc);
  assert.equal(s.version, expectedVersion(want.length, ecc), `version for ${want.length} bytes at ${ecc}`);
  assert.deepEqual(decodeCells(withQuietZone(m, 4)), want, `matrix decodes (${want.length} bytes, ${ecc})`);
  const svg = qrSvg(text, opts);
  const { full, cells } = svgCells(svg);
  const margin = opts.margin ?? 4;
  assert.equal(full, m.length + 2 * margin, 'viewBox = symbol + 2 × margin');
  assert.deepEqual(cells, withQuietZone(m, margin), 'SVG paints exactly the matrix, offset by the margin');
  if (margin >= 4) assert.deepEqual(decodeCells(cells), want, `SVG decodes (${want.length} bytes, ${ecc})`);
  return m;
}

function asciiPayload(len, seed = 0) {
  let s = '';
  for (let i = 0; i < len; i++) s += String.fromCharCode(32 + ((i * 7 + len + seed) % 95));
  return s;
}

// ---------------------------------------------------------------- round trips

for (const ecc of ['M', 'L', 'Q', 'H']) {
  test(`every length 1..capacity for versions 1–4, then every 7th to version 10 (${ecc}) decodes`, () => {
    const caps = CAPACITY[ecc];
    const lengths = [];
    for (let len = 1; len <= caps[3]; len++) lengths.push(len);
    for (let len = caps[3] + 1; len < caps[9]; len += 7) lengths.push(len);
    lengths.push(caps[9]);
    const seen = new Set();
    for (const len of lengths) {
      const m = check(asciiPayload(len), { ecc });
      seen.add((m.length - 17) / 4);
    }
    assert.deepEqual([...seen].sort((a, b) => a - b), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 'every version exercised');
  });
}

test('multibyte UTF-8 decodes byte for byte', () => {
  const samples = ['é', 'Grüße, Zoë', '日本語のテキスト', 'שלום עולם', '🔐🔑', 'a\u0000b', 'tab\there\nnewline', '\ud800 lone surrogate',
    'é'.repeat(7), 'é'.repeat(8), 'é'.repeat(106), '日'.repeat(71), '🔐'.repeat(53), 'Ω'.repeat(31) + 'x'];
  for (const s of samples) check(s);
  for (let n = 1; n <= 70; n += 3) check('日本'.repeat(n).slice(0, n));
});

test('every byte value 0–255 round-trips (Uint8Array input)', () => {
  const all = Uint8Array.from({ length: 256 }, (_, i) => i);
  check(all, { ecc: 'L' });
  check(all.slice(0, 213));
  check(all.slice(213));
  check(Uint8Array.from(all).reverse().slice(0, 200));
  check(new Uint8Array(0));
  check(Buffer.from([0xff, 0xfe, 0x00, 0xec, 0x11]));
  // The input array is not modified.
  const copy = Uint8Array.from(all);
  qrMatrix(all, { ecc: 'L' });
  assert.deepEqual(all, copy);
});

test('a real otpauth:// URI with a 32-character base32 secret decodes exactly', () => {
  const m = check(OTPAUTH);
  assert.equal(jsqr(withQuietZone(m, 4)).data, OTPAUTH);
  assert.equal(jsqr(svgCells(qrSvg(OTPAUTH)).cells).data, OTPAUTH);
  assert.equal(SECRET.length, 32);
});

test('empty, blank and short strings encode', () => {
  for (const s of ['', ' ', '   ', 'abc', '0', 'A']) check(s);
});

// ---------------------------------------------------------------- version selection

test('version selection: exactly at each capacity, and one byte over', () => {
  for (const ecc of ['L', 'M', 'Q', 'H']) {
    for (let v = 1; v <= 10; v++) {
      const cap = CAPACITY[ecc][v - 1];
      assert.equal(qrMatrix('x'.repeat(cap), { ecc }).length, 17 + 4 * v, `${ecc} ${cap} bytes → v${v}`);
      assert.equal(_internal.pickVersion(cap, ecc), v);
      if (v < 10) assert.equal(qrMatrix(new Uint8Array(cap + 1), { ecc }).length, 17 + 4 * (v + 1), `${ecc} ${cap + 1} bytes → v${v + 1}`);
      // Capacity = the data codewords the tables give, less mode + count.
      assert.equal(Math.floor((_internal.dataCodewordCount(v, ecc) * 8 - 4 - (v < 10 ? 8 : 16)) / 8), cap);
    }
  }
  // Bytes, not characters, decide: 'é' is two bytes.
  assert.equal(qrMatrix('é'.repeat(7)).length, 21);
  assert.equal(qrMatrix('é'.repeat(8)).length, 25);
  assert.equal(qrMatrix('é'.repeat(106)).length, 57);
});

test('too long throws RangeError, without echoing the payload', () => {
  const cases = [['x'.repeat(214), {}], [new Uint8Array(214), {}], ['é'.repeat(107), {}], ['x'.repeat(272), { ecc: 'L' }],
    ['x'.repeat(152), { ecc: 'Q' }], ['x'.repeat(120), { ecc: 'H' }], [SECRET.repeat(7), {}], ['x'.repeat(5_000_000), {}]];
  for (const [text, opts] of cases) {
    let err;
    try {
      qrMatrix(text, opts);
    } catch (e) {
      err = e;
    }
    assert.ok(err instanceof RangeError, `RangeError for ${text.length}`);
    assert.ok(!err.message.includes('xxxx') && !err.message.includes(SECRET), 'message carries no payload');
    assert.throws(() => qrSvg(text, opts), RangeError);
    assert.throws(() => qrDataUri(text, opts), RangeError);
  }
});

// ---------------------------------------------------------------- fixed vectors

// Golden hashes of the whole matrix (rows of '0'/'1' joined by '\n'),
// computed once and checked bit for bit against Nayuki's qrcodegen. A change
// here means the encoder's output changed: re-verify against jsQR and an
// independent encoder before updating them.
test('golden SHA-256 of three fixed symbols', () => {
  // 1-M, mask 4, mostly pad codewords.
  assert.equal(sha(qrMatrix('A')), '177b3a1897a152aee17ab1ee4b667913c6bb873e6ba357debfc5ba243dabff0e');
  // 8-M, mask 6, version information, four blocks of two lengths.
  assert.equal(sha(qrMatrix(OTPAUTH)), 'f6b3b83791124f063e9c682fa2d0abde37636fc796aa6bdea7fa86243fb8a4f5');
  // 10-L, mask 4, 16-bit count, every byte value.
  assert.equal(sha(qrMatrix(Uint8Array.from({ length: 256 }, (_, i) => i), { ecc: 'L' })), '6012b4a89494f96930af62daab7812b446badfcc06eb65eb2c46ec98f49cc6af');
});

test('data codewords: mode, count, terminator, then pads 0xEC 0x11 alternating', () => {
  const dc = _internal.dataCodewords;
  assert.deepEqual(dc([0x41], 1, 'M'), [0x40, 0x14, 0x10, 0xec, 0x11, 0xec, 0x11, 0xec, 0x11, 0xec, 0x11, 0xec, 0x11, 0xec, 0x11, 0xec]);
  assert.deepEqual(dc([], 1, 'H'), [0x40, 0x00, 0xec, 0x11, 0xec, 0x11, 0xec, 0x11, 0xec]);
  const a = (n) => new Array(n).fill(0x41);
  // 12 bytes at 1-M: 4 + 8 + 96 + 4 = 112 bits → two pads.
  assert.deepEqual(dc(a(12), 1, 'M').slice(-3), [0x10, 0xec, 0x11]);
  // 13 bytes: 120 bits → one pad.
  assert.deepEqual(dc(a(13), 1, 'M').slice(-2), [0x10, 0xec]);
  // 14 bytes: the terminator fills the last nibble; no pad at all.
  const full = dc(a(14), 1, 'M');
  assert.equal(full.length, 16);
  assert.equal(full[15], 0x10);
  // Version 9 counts in 8 bits, version 10 in 16.
  assert.deepEqual(dc(a(150), 9, 'M').slice(0, 3), [0x49, 0x64, 0x14]);
  assert.deepEqual(dc(a(200), 10, 'M').slice(0, 3), [0x40, 0x0c, 0x84]);
  for (const [v, e] of [[1, 'M'], [5, 'Q'], [10, 'L']]) assert.equal(dc([1, 2, 3], v, e).length, _internal.dataCodewordCount(v, e));
});

test('Reed–Solomon: published vectors, and every block size is a codeword', () => {
  // ISO 18004 / thonky.com "HELLO WORLD" 1-M and 1-Q.
  assert.deepEqual(_internal.rsEcc([32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17], 10),
    [196, 35, 39, 119, 235, 215, 231, 226, 93, 23]);
  assert.deepEqual(_internal.rsEcc([32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236], 13),
    [168, 72, 22, 82, 217, 54, 156, 0, 46, 15, 180, 122, 16]);
  // An independent GF(256): data ‖ ecc must vanish at α^0 … α^(n−1).
  const gmul = (a, b) => {
    let p = 0;
    while (b) {
      if (b & 1) p ^= a;
      a <<= 1;
      if (a & 0x100) a ^= 0x11d;
      b >>= 1;
    }
    return p;
  };
  let seed = 12345;
  const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) >> 16 & 0xff;
  for (const n of [7, 10, 13, 15, 16, 17, 18, 20, 22, 24, 26, 28, 30]) {
    for (const len of [1, 9, 44, 122]) {
      const data = Array.from({ length: len }, rnd);
      const cw = [...data, ..._internal.rsEcc(data, n)];
      assert.equal(cw.length, len + n);
      for (let i = 0, alpha = 1; i < n; i++, alpha = gmul(alpha, 2)) {
        let s = 0;
        for (const c of cw) s = gmul(s, alpha) ^ c;
        assert.equal(s, 0, `syndrome ${i} for n=${n}`);
      }
    }
  }
});

test('format and version words match the ISO 18004 tables', () => {
  const table = {
    L: ['111011111000100', '111001011110011', '111110110101010', '111100010011101', '110011000101111', '110001100011000', '110110001000001', '110100101110110'],
    M: ['101010000010010', '101000100100101', '101111001111100', '101101101001011', '100010111111001', '100000011001110', '100111110010111', '100101010100000'],
    Q: ['011010101011111', '011000001101000', '011111100110001', '011101000000110', '010010010110100', '010000110000011', '010111011011010', '010101111101101'],
    H: ['001011010001001', '001001110111110', '001110011100111', '001100111010000', '000011101100010', '000001001010101', '000110100001100', '000100000111011'],
  };
  for (const ecc of Object.keys(table)) {
    table[ecc].forEach((bits, mask) => assert.equal(_internal.formatBits(ecc, mask), parseInt(bits, 2), `${ecc}${mask}`));
  }
  for (const [v, w] of Object.entries(VERSION_WORDS)) assert.equal(_internal.versionBits(Number(v)), w, `v${v}`);
});

// ---------------------------------------------------------------- masks

const grid = (...lines) => lines.map((l) => [...l].map((c) => c === '#'));

test('penalty rule 1: runs of five or more score 3 + (run − 5)', () => {
  // Rows all-dark / all-light; columns alternate; 50% dark → rules 2–4 score 0.
  assert.equal(_internal.penalty(grid('######', '......')), 2 * (3 + 1));
  assert.equal(_internal.penalty(grid('#####', '.....')), 2 * 3);
  assert.equal(_internal.penalty(grid('#######', '.......')), 2 * (3 + 2));
  assert.equal(_internal.penalty(grid('####', '....')), 0);
});

test('penalty rule 2: every 2×2 block of one colour scores 3', () => {
  assert.equal(_internal.penalty(grid('##..', '##..')), 6);
  assert.equal(_internal.penalty(grid('###...', '###...')), 12);
  assert.equal(_internal.penalty(grid('#.#.', '.#.#')), 0);
});

test('penalty rule 3: 1:1:3:1:1 with light ≥ 4 on a side scores 40 per side', () => {
  // The complement row keeps the dark share at 50% and holds no pattern.
  assert.equal(_internal.penalty(grid('....#.###.#....', '####.#...#.####')), 80); // light on both sides
  assert.equal(_internal.penalty(grid('##.#.###.#....##', '..#.#...#.####..')), 40); // only one side has four
  assert.equal(_internal.penalty(grid('#.#.###.#.#.', '.#.#...#.#.#')), 0); // neither side
  // At twice the module width (2:2:6:2:2), the light run must be 8.
  // Rule 1 adds 6 + 4 + 6 per row for the runs of 8, 6 and 8.
  assert.equal(_internal.penalty(grid('........##..######..##........', '########..##......##..########')), 80 + 2 * (6 + 4 + 6));
  // The edge of the symbol is the quiet zone: it counts as light.
  assert.equal(_internal.penalty(grid('#.###.#', '.#...#.')), 80);
});

// 20 cells put every case exactly on a band edge (30%, 25%, 35%), where the
// lower band applies: k is the smallest with the share in (45−5k)…(55+5k)%.
test('penalty rule 4: 10 for each 5% band beyond 45–55% dark', () => {
  // 1×20 rows with isolated dark modules: rules 2 and 3 cannot fire on them.
  const row = (dark) => [Array.from({ length: 20 }, (_, i) => i < dark * 3 && i % 3 === 0)];
  const lightRun = (m) => {
    // rule 1 on the row: trailing light run after the last dark module
    const last = m[0].lastIndexOf(true);
    const run = 19 - last;
    return run >= 5 ? 3 + run - 5 : 0;
  };
  for (const [dark, k] of [[6, 3], [5, 4], [7, 2]]) {
    const m = row(dark);
    assert.equal(m[0].filter(Boolean).length, dark);
    assert.equal(_internal.penalty(m), 10 * k + lightRun(m), `${dark}/20 dark`);
  }
  assert.equal(_internal.penalty([[true, false, false, true, false, false, true, false, false, false]]), 10 * 3);
  assert.equal(_internal.penalty([[true, false, true, false, true, false, false, true, false, true, false]]), 0); // 5/11
});

test('the auto mask is the lowest penalty, and the LOWEST mask number wins a tie', () => {
  // Found by search: two masks share the minimum for these payloads.
  for (const [text, tied] of [['tie-55', [2, 7]], ['tie-172', [0, 7]]]) {
    const pens = [0, 1, 2, 3, 4, 5, 6, 7].map((k) => _internal.penalty(qrMatrix(text, { mask: k })));
    const min = Math.min(...pens);
    assert.deepEqual(pens.map((p, k) => (p === min ? k : -1)).filter((k) => k >= 0), tied, `${text} ties`);
    const m = check(text);
    assert.equal(structure(m).mask, tied[0]);
    assert.deepEqual(m, qrMatrix(text, { mask: tied[0] }));
  }
  for (let i = 0; i < 40; i++) {
    const text = asciiPayload(5 + i * 5, i);
    const pens = [0, 1, 2, 3, 4, 5, 6, 7].map((k) => _internal.penalty(qrMatrix(text, { mask: k })));
    assert.equal(structure(qrMatrix(text)).mask, pens.indexOf(Math.min(...pens)), text);
  }
});

test('every forced mask decodes and is written into the format word', () => {
  for (const ecc of ['L', 'M', 'Q', 'H']) {
    for (let k = 0; k < 8; k++) {
      const m = check('mask test ' + ecc + k, { ecc, mask: k });
      assert.equal(structure(m, ecc).mask, k);
    }
  }
});

// ---------------------------------------------------------------- SVG

test('the SVG draws its own white plate over the whole viewBox, then black modules', () => {
  const svg = qrSvg('plate');
  const { root, children } = parseSvg(svg);
  const n = qrMatrix('plate').length;
  assert.equal(root.viewBox, `0 0 ${n + 8} ${n + 8}`);
  assert.equal(children[0].name, 'rect');
  assert.deepEqual([children[0].attrs.x, children[0].attrs.y, children[0].attrs.width, children[0].attrs.height], ['0', '0', String(n + 8), String(n + 8)]);
  assert.equal(colour(children[0].attrs.fill), false);
  assert.equal(children.length, 2);
  assert.equal(children[1].name, 'path');
  assert.equal(colour(children[1].attrs.fill), true);
  assert.equal(root['shape-rendering'], 'crispEdges');
  // Nothing external, nothing scriptable, nothing readable.
  for (const bad of ['href', 'url(', '<script', 'style', '<image', '<text', '<title', '<desc', '<!--', 'on', 'plate']) {
    if (bad === 'on') assert.ok(!/\son[a-z]+=/i.test(svg));
    else assert.ok(!svg.includes(bad), bad);
  }
});

test('quiet zone: present for default and blank margins, absent for an explicit 0', () => {
  const m = qrMatrix('quiet');
  const n = m.length;
  for (const margin of [undefined, null, '', '   ', '\t', NaN, -1, -4, 2.5, '2.5', 'abc', '4abc', 65, 1e9, Infinity, true, false, {}, [], Symbol('m'), 10n]) {
    const svg = qrSvg('quiet', { margin });
    assert.equal(svg, qrSvg('quiet'), `margin ${label(margin)} → default`);
    const { full, cells } = svgCells(svg);
    assert.equal(full, n + 8);
    for (let i = 0; i < full; i++) {
      for (let j = 0; j < 4; j++) {
        assert.equal(cells[j][i] || cells[full - 1 - j][i] || cells[i][j] || cells[i][full - 1 - j], false, 'quiet zone is light');
      }
    }
    assert.equal(cells[4][4], true, 'symbol starts at the margin');
  }
  for (const margin of [0, '0', ' 0 ']) {
    const { full, cells } = svgCells(qrSvg('quiet', { margin }));
    assert.equal(full, n, `margin ${label(margin)} honoured`);
    assert.deepEqual(cells, m);
    assert.equal(cells[0][0], true, 'finder corner at the edge');
  }
  for (const [margin, q] of [[1, 1], ['2', 2], [10, 10], [64, 64]]) {
    const { full, cells } = svgCells(qrSvg('quiet', { margin }));
    assert.equal(full, n + 2 * q);
    assert.deepEqual(cells, withQuietZone(m, q));
  }
  check('quiet', { margin: 0 });
  check('quiet', { margin: 6 });
});

test('scale sets the pixel size only; junk scale falls back to 4', () => {
  const n = qrMatrix('scale').length + 8;
  const base = svgCells(qrSvg('scale'));
  assert.equal(base.scale, 4);
  for (const [scale, px] of [[1, 1], [8, 8], ['10', 10], [64, 64]]) {
    const s = svgCells(qrSvg('scale', { scale }));
    assert.equal(s.scale, px);
    assert.deepEqual(s.cells, base.cells);
    assert.match(qrSvg('scale', { scale }), new RegExp(`width="${n * px}" height="${n * px}"`));
  }
  for (const scale of [...HOSTILE, -1, 0.5, 65, '']) assert.equal(qrSvg('scale', { scale }), qrSvg('scale'), label(scale));
});

test('qrDataUri is the same SVG, base64, with no secret readable in it', () => {
  const uri = qrDataUri(OTPAUTH, { margin: 4 });
  assert.ok(uri.startsWith('data:image/svg+xml;base64,'));
  const svg = Buffer.from(uri.slice('data:image/svg+xml;base64,'.length), 'base64').toString('utf8');
  assert.equal(svg, qrSvg(OTPAUTH));
  for (const text of [svg, uri]) {
    assert.ok(!text.includes(SECRET) && !text.includes('otpauth') && !text.includes('JBSWY'), 'no payload text in the output');
  }
  assert.deepEqual(decodeCells(svgCells(svg).cells), enc.encode(OTPAUTH));
});

// ---------------------------------------------------------------- hostile input

test('hostile text: a TypeError, never a symbol of "null" or "[object Object]"', () => {
  for (const v of [null, undefined, NaN, Infinity, {}, [], true, false, 0, Symbol('x'), 10n, () => 1, new String('x'), [65, 66],
    new ArrayBuffer(4), new Uint16Array(2), { length: 3 }]) {
    assert.throws(() => qrMatrix(v), TypeError, label(v));
    assert.throws(() => qrSvg(v), TypeError, label(v));
    assert.throws(() => qrDataUri(v), TypeError, label(v));
  }
});

test('hostile options fall back to defaults and never throw', () => {
  const dflt = qrSvg('opts');
  check('opts');
  for (const opts of [null, undefined, 'abc', '', Symbol('o'), 0, 1, true, [], () => 1, 10n, NaN]) {
    assert.equal(qrSvg('opts', opts), dflt, `opts ${label(opts)}`);
    assert.deepEqual(qrMatrix('opts', opts), qrMatrix('opts'));
  }
  for (const v of HOSTILE) {
    assert.deepEqual(qrMatrix('opts', { ecc: v }), qrMatrix('opts'), `ecc ${label(v)}`);
    if (v !== 0) assert.deepEqual(qrMatrix('opts', { mask: v }), qrMatrix('opts'), `mask ${label(v)}`);
    if (v !== 0) assert.equal(qrSvg('opts', { margin: v }), dflt, `margin ${label(v)}`);
    assert.equal(qrSvg('opts', { scale: v }), dflt, `scale ${label(v)}`);
  }
  for (const ecc of ['X', 'MM', 'medium', 'constructor', '__proto__', 'toString', 'hasOwnProperty']) {
    assert.deepEqual(qrMatrix('opts', { ecc }), qrMatrix('opts'), ecc);
  }
  for (const mask of [8, -1, 1.5, '9', '']) assert.deepEqual(qrMatrix('opts', { mask }), qrMatrix('opts'), label(mask));
  // Case and whitespace are forgiven for a real level; a forced mask may be a numeric string.
  assert.deepEqual(qrMatrix('opts', { ecc: ' q ' }), qrMatrix('opts', { ecc: 'Q' }));
  assert.equal(structure(qrMatrix('opts', { ecc: 'h' }), 'H').ecc, 'H');
  assert.equal(structure(qrMatrix('opts', { mask: '3' })).mask, 3);
  assert.equal(structure(qrMatrix('opts', { mask: 0 })).mask, 0);
  check('opts', { ecc: 'H', mask: 5, margin: 2, scale: 3 });
});

test('a fresh matrix every call: mutating one changes nothing', () => {
  const a = qrMatrix('fresh');
  a[0][0] = false;
  a.length = 0;
  const b = qrMatrix('fresh');
  assert.equal(b[0][0], true);
  check('fresh');
});

await run();
