// QR encoder → SVG (CONTRACTS §7.3, A §7.3). Byte mode, versions 1–10, ECC
// L/M/Q/H (M by default), ISO/IEC 18004.
//
// Ours because the otpauth:// URI it carries IS the TOTP secret: handing it
// to a QR service hands out a working credential, and no CDN library gets
// past the CSP anyway (A §2, §7.3). Every symbol the tests generate is
// decoded by an independent reader (jsQR) — a symbol that merely looks right
// is the failure this file exists to avoid (A §13.7).
//
// Matrices are rows: m[y][x], true = dark.

import { toInt, utf8 } from './util.js';

// ---------------------------------------------------------------- tables

// ISO 18004 Table 9, versions 1–10: EC codewords per block, number of blocks.
const EC_PER_BLOCK = {
  L: [7, 10, 15, 20, 26, 18, 20, 24, 30, 18],
  M: [10, 16, 26, 18, 24, 16, 18, 22, 22, 26],
  Q: [13, 22, 18, 26, 18, 24, 18, 22, 20, 24],
  H: [17, 28, 22, 16, 22, 28, 26, 26, 24, 28],
};
const NUM_BLOCKS = {
  L: [1, 1, 1, 1, 1, 2, 2, 2, 2, 4],
  M: [1, 1, 1, 2, 2, 4, 4, 4, 5, 5],
  Q: [1, 1, 2, 2, 4, 4, 6, 6, 8, 8],
  H: [1, 1, 2, 4, 4, 4, 5, 6, 8, 8],
};
const TOTAL_CODEWORDS = [26, 44, 70, 100, 134, 172, 196, 242, 292, 346];
const ALIGNMENT = [[], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34], [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50]];
// Format-information ECC indicator (Table 12) — note M is 00, not 01.
const ECC_BITS = { L: 1, M: 0, Q: 3, H: 2 };
const MAX_VERSION = 10;
const DEFAULT_MARGIN = 4; // the quiet zone the standard requires
const MAX_MARGIN = 64;
const DEFAULT_SCALE = 4;
const MAX_SCALE = 64;

function dataCodewordCount(version, ecc) {
  const i = version - 1;
  return TOTAL_CODEWORDS[i] - EC_PER_BLOCK[ecc][i] * NUM_BLOCKS[ecc][i];
}

// ---------------------------------------------------------------- GF(256)

// Primitive polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11d), α = 2.
const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
for (let i = 0, x = 1; i < 255; i++) {
  EXP[i] = x;
  LOG[x] = i;
  x <<= 1;
  if (x & 0x100) x ^= 0x11d;
}
for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];

function gfMul(a, b) {
  return a && b ? EXP[LOG[a] + LOG[b]] : 0;
}

// ∏ (x − α^i), i = 0..n−1; coefficients highest power first, g[0] = 1.
function rsGenerator(n) {
  let g = [1];
  for (let i = 0; i < n; i++) {
    const next = new Array(g.length + 1).fill(0);
    for (let j = 0; j < g.length; j++) {
      next[j] ^= g[j];
      next[j + 1] ^= gfMul(g[j], EXP[i]);
    }
    g = next;
  }
  return g;
}

const generators = new Map();

// EC codewords: the remainder of data(x)·x^n divided by the generator.
function rsEcc(data, n) {
  let gen = generators.get(n);
  if (!gen) generators.set(n, (gen = rsGenerator(n)));
  const rem = new Array(n).fill(0);
  for (const b of data) {
    const factor = b ^ rem.shift();
    rem.push(0);
    for (let i = 0; i < n; i++) rem[i] ^= gfMul(gen[i + 1], factor);
  }
  return rem;
}

// ---------------------------------------------------------------- data

function countBits(version) {
  return version < 10 ? 8 : 16; // byte-mode character count, Table 3
}

function pickVersion(len, ecc) {
  for (let v = 1; v <= MAX_VERSION; v++) {
    if (4 + countBits(v) + 8 * len <= dataCodewordCount(v, ecc) * 8) return v;
  }
  return 0;
}

// Mode, count, bytes, terminator, zero-fill to a byte, then the pad
// codewords 0xEC, 0x11 alternating (ISO 18004 §7.4.10). A decoder stops at
// the count and never reads the pads, so only the tests' fixed vectors and
// golden hashes can notice them going wrong (A §13.7).
function dataCodewords(bytes, version, ecc) {
  const capBits = dataCodewordCount(version, ecc) * 8;
  const bits = [];
  const push = (val, len) => {
    for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1);
  };
  push(0b0100, 4);
  push(bytes.length, countBits(version));
  for (const b of bytes) push(b, 8);
  push(0, Math.min(4, capBits - bits.length));
  push(0, (8 - (bits.length % 8)) % 8);
  const out = [];
  for (let i = 0; i < bits.length; i += 8) {
    let b = 0;
    for (let j = 0; j < 8; j++) b = (b << 1) | bits[i + j];
    out.push(b);
  }
  for (let pad = 0xec; out.length < capBits / 8; pad = pad === 0xec ? 0x11 : 0xec) out.push(pad);
  return out;
}

// Split into blocks (short blocks first), append each block's EC codewords,
// then interleave column-wise: data across blocks, then EC across blocks.
function finalCodewords(data, version, ecc) {
  const i = version - 1;
  const numBlocks = NUM_BLOCKS[ecc][i];
  const ecLen = EC_PER_BLOCK[ecc][i];
  const total = TOTAL_CODEWORDS[i];
  const shortLen = Math.floor(total / numBlocks);
  const numShort = numBlocks - (total % numBlocks);
  const blocks = [];
  for (let b = 0, k = 0; b < numBlocks; b++) {
    const len = shortLen - ecLen + (b < numShort ? 0 : 1);
    const d = data.slice(k, k + len);
    k += len;
    blocks.push({ d, e: rsEcc(d, ecLen) });
  }
  const out = [];
  for (let c = 0; c <= shortLen - ecLen; c++) for (const b of blocks) if (c < b.d.length) out.push(b.d[c]);
  for (let c = 0; c < ecLen; c++) for (const b of blocks) out.push(b.e[c]);
  return out;
}

// ---------------------------------------------------------------- BCH

// 15-bit format word: 2 ECC bits + 3 mask bits, BCH(15,5) over 0x537,
// XORed with 0x5412 so it is never all zero.
function formatBits(ecc, mask) {
  const data = (ECC_BITS[ecc] << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  return ((data << 10) | (rem & 0x3ff)) ^ 0x5412;
}

// 18-bit version word for v7+: 6 version bits, BCH(18,6) over 0x1f25.
function versionBits(version) {
  let rem = version;
  for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
  return (version << 12) | (rem & 0xfff);
}

// ---------------------------------------------------------------- matrix

function bit(x, i) {
  return ((x >>> i) & 1) !== 0;
}

const MASKS = [
  (x, y) => (x + y) % 2 === 0,
  (x, y) => y % 2 === 0,
  (x, y) => x % 3 === 0,
  (x, y) => (x + y) % 3 === 0,
  (x, y) => (Math.floor(y / 2) + Math.floor(x / 3)) % 2 === 0,
  (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
  (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0,
  (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0,
];

class Grid {
  constructor(version, ecc) {
    this.version = version;
    this.ecc = ecc;
    this.size = 17 + 4 * version;
    this.m = Array.from({ length: this.size }, () => new Array(this.size).fill(false));
    this.fn = Array.from({ length: this.size }, () => new Array(this.size).fill(false));
    this.drawFunctionPatterns();
  }

  set(x, y, dark) {
    this.m[y][x] = dark;
    this.fn[y][x] = true;
  }

  drawFunctionPatterns() {
    const n = this.size;
    for (let i = 0; i < n; i++) {
      this.set(6, i, i % 2 === 0);
      this.set(i, 6, i % 2 === 0);
    }
    // Finders with their light separators; they overwrite the timing ends.
    for (const [cx, cy] of [[3, 3], [n - 4, 3], [3, n - 4]]) {
      for (let dy = -4; dy <= 4; dy++) {
        for (let dx = -4; dx <= 4; dx++) {
          const x = cx + dx;
          const y = cy + dy;
          if (x < 0 || y < 0 || x >= n || y >= n) continue;
          const d = Math.max(Math.abs(dx), Math.abs(dy));
          this.set(x, y, d !== 2 && d !== 4);
        }
      }
    }
    const pos = ALIGNMENT[this.version - 1];
    const last = pos.length - 1;
    for (let i = 0; i <= last; i++) {
      for (let j = 0; j <= last; j++) {
        if ((i === 0 && j === 0) || (i === 0 && j === last) || (i === last && j === 0)) continue; // under a finder
        for (let dy = -2; dy <= 2; dy++) {
          for (let dx = -2; dx <= 2; dx++) this.set(pos[i] + dx, pos[j] + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
        }
      }
    }
    this.drawFormat(0); // reserves the area; redrawn once the mask is chosen
    if (this.version >= 7) {
      const vb = versionBits(this.version);
      for (let i = 0; i < 18; i++) {
        const a = n - 11 + (i % 3);
        const b = Math.floor(i / 3);
        this.set(a, b, bit(vb, i)); // top right
        this.set(b, a, bit(vb, i)); // bottom left
      }
    }
  }

  drawFormat(mask) {
    const n = this.size;
    const f = formatBits(this.ecc, mask);
    // Around the top-left finder.
    for (let i = 0; i <= 5; i++) this.set(8, i, bit(f, i));
    this.set(8, 7, bit(f, 6));
    this.set(8, 8, bit(f, 7));
    this.set(7, 8, bit(f, 8));
    for (let i = 9; i < 15; i++) this.set(14 - i, 8, bit(f, i));
    // Split between the other two finders.
    for (let i = 0; i < 8; i++) this.set(n - 1 - i, 8, bit(f, i));
    for (let i = 8; i < 15; i++) this.set(8, n - 15 + i, bit(f, i));
    this.set(8, n - 8, true); // the dark module
  }

  // Two-column zigzag from the bottom right, skipping the vertical timing
  // column. Remainder bits are left light.
  drawCodewords(cw) {
    const n = this.size;
    let i = 0;
    for (let right = n - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      const upward = ((right + 1) & 2) === 0;
      for (let vert = 0; vert < n; vert++) {
        const y = upward ? n - 1 - vert : vert;
        for (let j = 0; j < 2; j++) {
          const x = right - j;
          if (this.fn[y][x] || i >= cw.length * 8) continue;
          this.m[y][x] = bit(cw[i >>> 3], 7 - (i & 7));
          i++;
        }
      }
    }
    if (i !== cw.length * 8) throw new Error('qr: codewords do not fit the symbol');
  }

  applyMask(mask) {
    const f = MASKS[mask];
    for (let y = 0; y < this.size; y++) {
      for (let x = 0; x < this.size; x++) if (!this.fn[y][x] && f(x, y)) this.m[y][x] = !this.m[y][x];
    }
  }
}

// ---------------------------------------------------------------- penalty

// ISO 18004 §7.8.3 leaves rules 3 and 4 open to reading; this follows the
// reading of Nayuki's qrcodegen, so the mask choice matches a widely used
// reference rather than a private interpretation.
const N1 = 3;
const N2 = 3;
const N3 = 40;
const N4 = 10;

function linePenalty(get, n) {
  let s = 0;
  // Rule 1: a run of five or more same-colour modules scores N1 + (run − 5).
  let run = 0;
  let prev = null;
  for (let i = 0; i < n; i++) {
    const c = get(i);
    if (c === prev) run++;
    else {
      if (run >= 5) s += N1 + run - 5;
      prev = c;
      run = 1;
    }
  }
  if (run >= 5) s += N1 + run - 5;
  // Rule 3: dark:light:dark:light:dark at 1:1:3:1:1 (any module width k),
  // with light ≥ 4k on one side and ≥ k on the other; each qualifying side
  // scores. Outside the symbol is the quiet zone, so it counts as light.
  const runs = []; // alternating light, dark, light, …; starts and ends light
  let color = false;
  let len = n;
  for (let i = 0; i < n; i++) {
    const c = get(i);
    if (c === color) len++;
    else {
      runs.push(len);
      color = c;
      len = 1;
    }
  }
  if (color) {
    runs.push(len);
    len = 0;
  }
  runs.push(len + n);
  for (let i = 1; i + 5 < runs.length; i += 2) {
    const k = runs[i];
    if (runs[i + 1] !== k || runs[i + 2] !== 3 * k || runs[i + 3] !== k || runs[i + 4] !== k) continue;
    const before = runs[i - 1];
    const after = runs[i + 5];
    if (before >= 4 * k && after >= k) s += N3;
    if (after >= 4 * k && before >= k) s += N3;
  }
  return s;
}

// Works on any rectangular boolean[][] (rows).
function penalty(m) {
  const h = m.length;
  const w = h ? m[0].length : 0;
  let s = 0;
  for (let y = 0; y < h; y++) s += linePenalty((i) => m[y][i], w);
  for (let x = 0; x < w; x++) s += linePenalty((i) => m[i][x], h);
  // Rule 2: every 2×2 block of one colour (overlapping blocks all count).
  for (let y = 0; y + 1 < h; y++) {
    for (let x = 0; x + 1 < w; x++) {
      const c = m[y][x];
      if (c === m[y][x + 1] && c === m[y + 1][x] && c === m[y + 1][x + 1]) s += N2;
    }
  }
  // Rule 4: N4·k for the smallest k with the dark share inside
  // (45 − 5k)% … (55 + 5k)%.
  let dark = 0;
  for (const row of m) for (const c of row) if (c) dark++;
  const total = w * h;
  if (total) s += N4 * Math.max(0, Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1);
  return s;
}

// ---------------------------------------------------------------- options

// Blank and junk fall back to the default, never to zero (A §14.11): toInt
// reads '' and '   ' as NaN, not 0, and an explicit 0 stays legal.
function intOpt(v, min, max, dflt) {
  const n = toInt(v, min, max);
  return Number.isNaN(n) ? dflt : n;
}

function eccOpt(v) {
  if (typeof v !== 'string') return 'M';
  const k = v.trim().toUpperCase();
  return Object.hasOwn(ECC_BITS, k) ? k : 'M';
}

function optsOf(opts) {
  return opts && typeof opts === 'object' ? opts : {};
}

function payload(text) {
  if (typeof text === 'string') {
    // Every UTF-16 unit is at least one UTF-8 byte: refuse a huge string
    // before encoding it.
    if (text.length > dataCodewordCount(MAX_VERSION, 'L')) throw new RangeError('qr: text too long');
    return utf8(text);
  }
  if (text instanceof Uint8Array) return text;
  throw new TypeError('qr: text must be a string or a Uint8Array');
}

// ---------------------------------------------------------------- exports

// opts.mask (0–7) forces a mask; otherwise the lowest penalty wins and the
// LOWEST mask number wins a tie.
export function qrMatrix(text, opts) {
  const o = optsOf(opts);
  const ecc = eccOpt(o.ecc);
  const bytes = payload(text);
  const version = pickVersion(bytes.length, ecc);
  if (!version) throw new RangeError(`qr: ${bytes.length} bytes do not fit a version ${MAX_VERSION}-${ecc} symbol`);
  const sym = new Grid(version, ecc);
  sym.drawCodewords(finalCodewords(dataCodewords(bytes, version, ecc), version, ecc));
  let mask = toInt(o.mask, 0, 7);
  if (Number.isNaN(mask)) {
    let best = Infinity;
    for (let k = 0; k < 8; k++) {
      sym.applyMask(k);
      sym.drawFormat(k);
      const p = penalty(sym.m);
      if (p < best) {
        best = p;
        mask = k;
      }
      sym.applyMask(k); // XOR undoes it
    }
  }
  sym.applyMask(mask);
  sym.drawFormat(mask);
  return sym.m;
}

// The QR always sits on its OWN white plate covering the whole viewBox: a
// dark-on-dark symbol in dark mode does not scan (A §7.3). The plate
// includes the quiet zone (margin, in modules).
export function qrSvg(text, opts) {
  const o = optsOf(opts);
  const m = qrMatrix(text, o);
  const margin = intOpt(o.margin, 0, MAX_MARGIN, DEFAULT_MARGIN);
  const scale = intOpt(o.scale, 1, MAX_SCALE, DEFAULT_SCALE);
  const n = m.length;
  const full = n + 2 * margin;
  let d = '';
  for (let y = 0; y < n; y++) {
    for (let x = 0; x < n; ) {
      if (!m[y][x]) {
        x++;
        continue;
      }
      let run = 1;
      while (x + run < n && m[y][x + run]) run++;
      d += `M${x + margin} ${y + margin}h${run}v1h-${run}z`;
      x += run;
    }
  }
  return (
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${full} ${full}" width="${full * scale}" height="${full * scale}" shape-rendering="crispEdges">` +
    `<rect x="0" y="0" width="${full}" height="${full}" fill="#ffffff"/>` +
    `<path fill="#000000" d="${d}"/>` +
    `</svg>`
  );
}

// For an <img src>: the SVG is pure ASCII, so btoa is safe.
export function qrDataUri(text, opts) {
  return 'data:image/svg+xml;base64,' + btoa(qrSvg(text, opts));
}

// Internals, exported for the tests' fixed vectors only.
export const _internal = Object.freeze({ dataCodewords, rsEcc, formatBits, versionBits, penalty, dataCodewordCount, pickVersion });
