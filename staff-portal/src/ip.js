// IPv4/IPv6 addresses and CIDR ranges (CONTRACTS §7.2, A §4).
//
// Both sides of every comparison are bytes, never strings (A §4 "Matching").
// The caller's address and an admin's typed range both arrive from a request,
// so nothing exported here throws: unreadable input is null / false, and the
// two refusal predicates (isPrivateOrReserved, isWholeFamily) answer true for
// it — "present but unreadable" is a reason to refuse (CONTRACTS §0.2).

import { strStrict, toInt } from './util.js';

// "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255/128" is 49 characters.
const MAX_LEN = 64;
// '01' is octal to some parsers and decimal to others; refuse it rather than
// guess which network the admin meant. Same for a prefix of '024'.
const V4_OCTET = /^(?:0|[1-9]\d{0,2})$/;
const V6_GROUP = /^[0-9A-Fa-f]{1,4}$/;
// No zone id ('fe80::1%eth0'), brackets, whitespace or anything else.
const V6_CHARS = /^[0-9A-Fa-f:.]+$/;
const PREFIX = /^(?:0|[1-9]\d{0,2})$/;

// ---------------------------------------------------------------- parsing

function parseV4(s) {
  const parts = s.split('.');
  if (parts.length !== 4) return null;
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    if (!V4_OCTET.test(parts[i])) return null;
    const n = parseInt(parts[i], 10);
    if (n > 255) return null;
    out[i] = n;
  }
  return out;
}

// One side of a '::' → 16-bit words, or null. Only the last part of the
// whole address may be an embedded dotted quad.
function v6Words(side, mayEndWithV4) {
  if (side === '') return [];
  const parts = side.split(':');
  const words = [];
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i];
    if (p.includes('.')) {
      if (!mayEndWithV4 || i !== parts.length - 1) return null;
      const b = parseV4(p);
      if (!b) return null;
      words.push((b[0] << 8) | b[1], (b[2] << 8) | b[3]);
    } else {
      if (!V6_GROUP.test(p)) return null;
      words.push(parseInt(p, 16));
    }
  }
  return words;
}

function parseV6(s) {
  if (!V6_CHARS.test(s)) return null;
  const dbl = s.indexOf('::');
  if (dbl !== -1 && s.indexOf('::', dbl + 1) !== -1) return null; // ':::' and '1::2::3'
  let head;
  let tail;
  if (dbl === -1) {
    head = v6Words(s, true);
    tail = [];
    if (!head || head.length !== 8) return null;
  } else {
    head = v6Words(s.slice(0, dbl), false);
    tail = v6Words(s.slice(dbl + 2), true);
    // '::' stands for at least one zero group (RFC 4291 §2.2).
    if (!head || !tail || head.length + tail.length > 7) return null;
  }
  const words = [...head, ...new Array(8 - head.length - tail.length).fill(0), ...tail];
  const out = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    out[2 * i] = words[i] >> 8;
    out[2 * i + 1] = words[i] & 0xff;
  }
  return out;
}

// Trimmed text in, { v, bytes } out; IPv4-mapped IPv6 is NOT folded here.
function parseAddrText(t) {
  if (t.includes(':')) {
    const bytes = parseV6(t);
    return bytes ? { v: 6, bytes } : null;
  }
  const bytes = parseV4(t);
  return bytes ? { v: 4, bytes } : null;
}

function isMapped(b) {
  for (let i = 0; i < 10; i++) if (b[i] !== 0) return false;
  return b[10] === 0xff && b[11] === 0xff;
}

// ::ffff:a.b.c.d is the IPv4 caller a.b.c.d (a dual-stack socket reports it
// that way). Folding it means one address has one identity: a v4 allowlist
// entry matches it, and a v4 block cannot be dodged by spelling it as v6.
function foldIp(a) {
  return a.v === 6 && isMapped(a.bytes) ? { v: 4, bytes: a.bytes.slice(12) } : a;
}

function hostBitsZero(bytes, prefix) {
  for (let i = 0; i < bytes.length; i++) {
    const keep = Math.max(0, Math.min(8, prefix - i * 8));
    if (bytes[i] & (0xff >> keep)) return false;
  }
  return true;
}

// Host bits set → null: '81.2.69.7/24' is a typo or a misunderstanding, and
// silently widening it to the whole /24 is not ours to decide.
function canonCidr(v, bytes, prefix) {
  if (!hostBitsZero(bytes, prefix)) return null;
  if (v === 6 && prefix >= 96 && isMapped(bytes)) return { v: 4, bytes: bytes.slice(12), prefix: prefix - 96 };
  return { v, bytes: bytes.slice(), prefix };
}

function validBytes(v, bytes) {
  return (v === 4 || v === 6) && bytes instanceof Uint8Array && bytes.length === (v === 4 ? 4 : 16);
}

// String or an object shaped like parseIp's result. Anything else → null.
function asIp(x) {
  if (typeof x === 'string') return parseIp(x);
  if (!x || typeof x !== 'object') return null;
  const { v, bytes } = x;
  if (!validBytes(v, bytes)) return null;
  return foldIp({ v, bytes: bytes.slice() });
}

function asCidr(x) {
  if (typeof x === 'string') return parseCidr(x);
  if (!x || typeof x !== 'object') return null;
  const { v, bytes, prefix } = x;
  if (!validBytes(v, bytes) || !Number.isInteger(prefix) || prefix < 0 || prefix > bytes.length * 8) return null;
  return canonCidr(v, bytes, prefix);
}

// ---------------------------------------------------------------- text

function formatV6(b) {
  const words = [];
  for (let i = 0; i < 16; i += 2) words.push((b[i] << 8) | b[i + 1]);
  // RFC 5952 §4.2: compress the longest run of two or more zero groups, the
  // first one on a tie; a lone zero group is written out.
  let bestAt = -1;
  let bestLen = 1;
  for (let i = 0; i < 8; ) {
    if (words[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && words[j] === 0) j++;
    if (j - i > bestLen) {
      bestAt = i;
      bestLen = j - i;
    }
    i = j;
  }
  const hexes = words.map((w) => w.toString(16));
  if (bestAt === -1) return hexes.join(':');
  return hexes.slice(0, bestAt).join(':') + '::' + hexes.slice(bestAt + bestLen).join(':');
}

function formatAddr(a) {
  return a.v === 4 ? Array.from(a.bytes).join('.') : formatV6(a.bytes);
}

// ---------------------------------------------------------------- exports

export function parseIp(s) {
  try {
    const t = strStrict(s, 1, MAX_LEN);
    if (t === null) return null;
    const a = parseAddrText(t);
    return a ? foldIp(a) : null;
  } catch {
    return null;
  }
}

export function normalizeIp(s) {
  const a = parseIp(s);
  return a ? formatAddr(a) : null;
}

// The network a per-address rate limit is keyed on (SPEC §6.4): an IPv4
// address is itself, an IPv6 address is its /64. One home line or one server
// is handed a whole /64, so keying on the full address would give it 2^64
// buckets and no brake at all. → '81.2.69.142' | '2a02:1210:5c00:9e00::/64'
// | null (unreadable).
export function rateLimitNetwork(s) {
  const a = parseIp(s);
  if (!a) return null;
  if (a.v === 4) return formatAddr(a);
  const net = new Uint8Array(16);
  net.set(a.bytes.subarray(0, 8));
  return `${formatV6(net)}/64`;
}

// A bare address is its own full-length range.
export function parseCidr(s) {
  try {
    const t = strStrict(s, 1, MAX_LEN);
    if (t === null) return null;
    const slash = t.indexOf('/');
    const a = parseAddrText(slash === -1 ? t : t.slice(0, slash));
    if (!a) return null;
    const bits = a.bytes.length * 8;
    let prefix = bits;
    if (slash !== -1) {
      const p = t.slice(slash + 1);
      if (!PREFIX.test(p)) return null; // also refuses '/', '+24', ' 24', a second '/'
      prefix = parseInt(p, 10);
      if (prefix > bits) return null;
    }
    return canonCidr(a.v, a.bytes, prefix);
  } catch {
    return null;
  }
}

export function normalizeCidr(s) {
  const c = parseCidr(s);
  return c ? `${formatAddr(c)}/${c.prefix}` : null;
}

function samePrefix(a, b, bits) {
  const full = bits >> 3;
  for (let i = 0; i < full; i++) if (a[i] !== b[i]) return false;
  const rem = bits & 7;
  if (!rem) return true;
  const mask = (0xff << (8 - rem)) & 0xff;
  return (a[full] & mask) === (b[full] & mask);
}

// An IPv4 address never matches an IPv6 range (mapped addresses are folded
// to v4 first, so ::ffff:a.b.c.d is matched as a.b.c.d).
export function cidrContains(cidr, ip) {
  try {
    const c = asCidr(cidr);
    const a = asIp(ip);
    if (!c || !a || c.v !== a.v) return false;
    return samePrefix(c.bytes, a.bytes, c.prefix);
  } catch {
    return false;
  }
}

// Ranges no caller can arrive from (A §4). An entry is refused if it
// OVERLAPS one, not only if it sits inside one: 10.0.0.0/7 contains 10/8.
// The IPv4-mapped block is held unfolded, so it only meets a v6 range wide
// enough to contain all of it; a mapped range of /96 or longer is folded to
// v4 by parseCidr and classified by the v4 address it embeds.
// Beyond the list in the brief: 64:ff9b:1::/48 (RFC 8215 local-use NAT64),
// fec0::/10 (deprecated site-local) and 3fff::/20 (RFC 9637 documentation).
function rawCidr(s) {
  const [addr, p] = s.split('/');
  const a = parseAddrText(addr);
  if (!a) throw new Error(`ip: bad reserved range ${s}`);
  return { v: a.v, bytes: a.bytes, prefix: parseInt(p, 10) };
}

const RESERVED = [
  '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
  '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16',
  '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4',
  '::/128', '::1/128', '::ffff:0:0/96', '64:ff9b::/96', '64:ff9b:1::/48', '100::/64',
  '2001::/23', '2001:db8::/32', '3fff::/20', 'fc00::/7', 'fe80::/10', 'fec0::/10', 'ff00::/8',
].map(rawCidr);

export function isPrivateOrReserved(cidr) {
  try {
    const c = asCidr(cidr);
    if (!c) return true;
    return RESERVED.some((r) => r.v === c.v && samePrefix(r.bytes, c.bytes, Math.min(r.prefix, c.prefix)));
  } catch {
    return true;
  }
}

// 0.0.0.0/0 or ::/0 is not an allowlist entry, it is the gate turned off;
// that has its own audited, time-boxed switch (A §4).
export function isWholeFamily(cidr) {
  try {
    const c = asCidr(cidr);
    return c ? c.prefix === 0 : true;
  } catch {
    return true;
  }
}

// A stored tier that is not 1–4 ranks above every real tier: on a tie it
// wins, so a corrupt row can never buy a longer grace window. The caller
// still coerces entry.tier itself.
function tierRank(t) {
  const n = toInt(t, 1, 4);
  return Number.isNaN(n) ? 5 : n;
}

// Most specific wins — a /32 carve-out beats the /16 around it. On an exact
// tie the stricter (higher-numbered) tier wins (A §4). Entries whose cidr
// does not parse grant nothing and are skipped.
export function bestMatch(entries, ip) {
  try {
    if (!Array.isArray(entries)) return null;
    const a = asIp(ip);
    if (!a) return null;
    let best = null;
    let bestPrefix = -1;
    let bestRank = -1;
    for (const e of entries) {
      if (!e || typeof e !== 'object') continue;
      const c = asCidr(e.cidr);
      if (!c || c.v !== a.v || !samePrefix(c.bytes, a.bytes, c.prefix)) continue;
      const rank = tierRank(e.tier);
      if (c.prefix > bestPrefix || (c.prefix === bestPrefix && rank > bestRank)) {
        best = e;
        bestPrefix = c.prefix;
        bestRank = rank;
      }
    }
    return best;
  } catch {
    return null;
  }
}
