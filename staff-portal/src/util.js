// Small, total helpers shared by every module.
//
// Contract: nothing in this file throws on bad input unless its name says so
// (requireX). Values that arrive from a request are hostile until a function
// here has shaped them — see SPEC §14.1, §14.11, §14.12.

export const SECOND = 1000;
export const MINUTE = 60 * SECOND;
export const HOUR = 60 * MINUTE;
export const DAY = 24 * HOUR;

// ---------------------------------------------------------------- time

// The one clock. Tests inject `env.__clock` (a function — wrangler vars are
// strings, so production config can never set it).
export function now(env) {
  const c = env && env.__clock;
  if (typeof c === 'function') {
    const v = c();
    if (typeof v === 'number' && Number.isFinite(v)) return v;
  }
  return Date.now();
}

export function iso(ms) {
  return new Date(ms).toISOString();
}

export function nowIso(env) {
  return iso(now(env));
}

// Date.parse('42') is 2042-01-01. Require the shape first (SPEC §14.2).
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,3})?)?(?:Z|[+-]\d{2}:\d{2})$/;

export function parseIsoStrict(v) {
  if (typeof v !== 'string' || !ISO_RE.test(v)) return NaN;
  const ms = Date.parse(v);
  return Number.isFinite(ms) ? ms : NaN;
}

// ---------------------------------------------------------------- coercion

const NUM_RE = /^[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?$/;

// Total numeric coercion. null, undefined, '', whitespace, booleans, objects,
// arrays, symbols and bigints are all NaN — never 0. A blank must not be able
// to become a meaningful zero (SPEC §14.11), and Number(Symbol()) throws
// (§14.12), so this never calls Number() on anything but a vetted string.
export function toNum(v) {
  if (typeof v === 'number') return Number.isFinite(v) ? v : NaN;
  if (typeof v === 'string') {
    const s = v.trim();
    if (!NUM_RE.test(s)) return NaN;
    const n = Number(s);
    return Number.isFinite(n) ? n : NaN;
  }
  return NaN;
}

// Integer in [min, max], else NaN.
export function toInt(v, min = -Infinity, max = Infinity) {
  const n = toNum(v);
  if (!Number.isInteger(n) || n < min || n > max) return NaN;
  return n;
}

// Trimmed string or '' — never throws, never returns a non-string.
export function str(v, max = 1000) {
  if (typeof v !== 'string') return '';
  return v.trim().slice(0, max);
}

// Trimmed string with length in [min, max], else null (not truncated).
export function strStrict(v, min = 1, max = 1000) {
  if (typeof v !== 'string') return null;
  const s = v.trim();
  if (s.length < min || s.length > max) return null;
  return s;
}

export function bool01(v) {
  return v === true || v === 1 || v === '1' || v === 'true';
}

export function clamp(n, lo, hi) {
  return Math.min(hi, Math.max(lo, n));
}

export function safeJsonParse(s, fallback) {
  if (typeof s !== 'string') return fallback;
  try {
    return JSON.parse(s);
  } catch {
    return fallback;
  }
}

// Sorted keys, no whitespace. Used for hashing (audit chain, fingerprints),
// so it must be deterministic: undefined members are dropped, non-finite
// numbers become null, and anything exotic is stringified.
export function canonicalJson(v) {
  if (v === null || v === undefined) return 'null';
  const t = typeof v;
  if (t === 'number') return Number.isFinite(v) ? JSON.stringify(v) : 'null';
  if (t === 'boolean') return v ? 'true' : 'false';
  if (t === 'string') return JSON.stringify(v);
  if (t === 'bigint') return JSON.stringify(v.toString());
  if (Array.isArray(v)) return '[' + v.map((x) => (x === undefined ? 'null' : canonicalJson(x))).join(',') + ']';
  if (t === 'object') {
    const keys = Object.keys(v).filter((k) => v[k] !== undefined).sort();
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalJson(v[k])).join(',') + '}';
  }
  return JSON.stringify(String(v));
}

// ---------------------------------------------------------------- strings

const EMAIL_RE = /^[^\s@<>()[\]\\,;:"]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;

export function normEmail(v) {
  const s = str(v, 254).toLowerCase();
  return EMAIL_RE.test(s) ? s : null;
}

const USERNAME_RE = /^[a-z0-9][a-z0-9._-]{1,31}$/;

export function normUsername(v) {
  const s = str(v, 32).toLowerCase();
  return USERNAME_RE.test(s) ? s : null;
}

// Only for the few server-built HTML strings (decoy 404). Pages never take
// HTML strings — they build DOM nodes.
export function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

// ---------------------------------------------------------------- bytes

const enc = new TextEncoder();
const dec = new TextDecoder();

export function utf8(s) {
  return enc.encode(String(s));
}

export function fromUtf8(bytes) {
  return dec.decode(bytes);
}

export function hex(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let out = '';
  for (let i = 0; i < b.length; i++) out += b[i].toString(16).padStart(2, '0');
  return out;
}

export function fromHex(s) {
  if (typeof s !== 'string' || s.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(s)) return null;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// Loop rather than String.fromCharCode(...bytes): the spread form throws past
// ~120k elements (SPEC §7.4).
export function b64urlEncode(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = '';
  for (let i = 0; i < b.length; i++) bin += String.fromCharCode(b[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function b64urlDecode(s) {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) return null;
  try {
    const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4);
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

export function concatBytes(...parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

// getRandomValues refuses more than 65,536 bytes per call.
export function randomBytes(n) {
  const b = new Uint8Array(n);
  for (let o = 0; o < n; o += 65536) crypto.getRandomValues(b.subarray(o, Math.min(n, o + 65536)));
  return b;
}

// 256-bit url-safe token by default.
export function randomToken(nBytes = 32) {
  return b64urlEncode(randomBytes(nBytes));
}

// Uniform integer in [0, n) by rejection sampling — never `% n` (SPEC §7.3).
export function randomInt(n) {
  if (!Number.isInteger(n) || n <= 0 || n > 2 ** 32) throw new RangeError('randomInt: bad bound');
  const limit = Math.floor(2 ** 32 / n) * n;
  const buf = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(buf);
    if (buf[0] < limit) return buf[0] % n;
  }
}

// ---------------------------------------------------------------- http

export function json(status, body, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...headers },
  });
}

export function empty(status) {
  return new Response(null, { status });
}

export function redirect(location, status = 302) {
  return new Response(null, { status, headers: { location } });
}

// Append Set-Cookie headers (a plain object cannot hold two of them).
export function withCookies(response, cookies) {
  const list = (cookies || []).filter(Boolean);
  if (!list.length) return response;
  const headers = new Headers(response.headers);
  for (const c of list) headers.append('set-cookie', c);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

// JSON body or null. Requires an application/json content type — which is
// also a CSRF brake, since a cross-site form cannot send one without a
// preflight — and caps the size before parsing.
export async function readJson(request, maxBytes = 64 * 1024) {
  try {
    const ct = request.headers.get('content-type') || '';
    if (!/^application\/json\b/i.test(ct)) return null;
    const declared = toInt(request.headers.get('content-length'), 0);
    if (Number.isFinite(declared) && declared > maxBytes) return null;
    const buf = await request.arrayBuffer();
    if (buf.byteLength > maxBytes) return null;
    const v = JSON.parse(dec.decode(buf));
    return v && typeof v === 'object' && !Array.isArray(v) ? v : null;
  } catch {
    return null;
  }
}

export function parseCookies(header) {
  const out = Object.create(null);
  if (typeof header !== 'string' || !header) return out;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i <= 0) continue;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    if (k && !(k in out)) out[k] = v;
  }
  return out;
}

// SameSite=Lax, not Strict: Strict drops the cookie on every navigation that
// began off-site (a link in an email, a QR code) and the device then reads as
// brand new every time (SPEC §14.6).
export function cookie(name, value, { maxAge, httpOnly = true, secure = true, sameSite = 'Lax', path = '/' } = {}) {
  let c = `${name}=${value}; Path=${path}; SameSite=${sameSite}`;
  if (secure) c += '; Secure';
  if (httpOnly) c += '; HttpOnly';
  if (maxAge !== undefined) c += `; Max-Age=${Math.max(0, Math.floor(maxAge))}`;
  return c;
}

export function clearCookie(name) {
  return cookie(name, '', { maxAge: 0 });
}

// Cloudflare overwrites CF-Connecting-IP at the edge, so a client cannot
// choose it. Anything that does not parse as an address is treated as absent.
export function clientIpRaw(request) {
  const v = request.headers.get('cf-connecting-ip');
  return typeof v === 'string' ? v.trim() : '';
}
