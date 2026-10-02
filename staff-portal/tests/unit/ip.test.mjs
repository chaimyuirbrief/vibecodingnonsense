import { test, assert, run } from '../helpers/t.js';
import {
  parseIp,
  normalizeIp,
  parseCidr,
  normalizeCidr,
  cidrContains,
  isPrivateOrReserved,
  isWholeFamily,
  bestMatch,
} from '../../src/ip.js';

const throwing = new Proxy({}, { get() { throw new Error('boom'); }, has() { throw new Error('boom'); }, ownKeys() { throw new Error('boom'); } });
const HOSTILE = [null, undefined, NaN, Infinity, -Infinity, '', '   ', 'abc', {}, [], true, false, 0, 1, Symbol('x'), 10n, () => 1,
  { valueOf() { throw new Error('boom'); }, toString() { return '81.2.69.1'; } }, throwing, new String('81.2.69.1')];
const label = (v) => (typeof v === 'symbol' ? 'Symbol' : typeof v === 'bigint' ? `${v}n` : (() => { try { return JSON.stringify(v) ?? String(v); } catch { return typeof v; } })());

const bytes = (p) => (p ? Array.from(p.bytes) : null);
// ::ffff:a.b.c.d as raw 16 bytes (parseIp would fold it to v4).
const mapped16 = (a, b, c, d) => new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a, b, c, d]);

// ---------------------------------------------------------------- IPv4

test('parseIp accepts strict dotted quads', () => {
  assert.deepEqual(parseIp('81.2.69.1'), { v: 4, bytes: new Uint8Array([81, 2, 69, 1]) });
  assert.deepEqual(bytes(parseIp('0.0.0.0')), [0, 0, 0, 0]);
  assert.deepEqual(bytes(parseIp('255.255.255.255')), [255, 255, 255, 255]);
  assert.deepEqual(bytes(parseIp('91.198.174.192')), [91, 198, 174, 192]);
  assert.deepEqual(bytes(parseIp(' 185.15.56.1 ')), [185, 15, 56, 1]); // surrounding whitespace only
});

test('parseIp refuses leading zeros, out-of-range octets and wrong part counts', () => {
  for (const s of ['01.2.3.4', '1.2.3.04', '00.1.2.3', '1.2.3.00', '010.0.0.1', '256.1.1.1', '1.2.3.256', '1.2.3.999', '1.2.3.1000',
    '1.2.3', '1.2.3.4.5', '1.2.3.', '.1.2.3', '1..2.3', '1.2.3.-1', '+1.2.3.4', '1.2.3.+4', '1.2.3.4a', '0x1.2.3.4', '0x51020045',
    '1e1.2.3.4', '1.2.3.4e0', '１.2.3.4', '1.2. 3.4', '1.2.3.4/32', '1.2.3.4:80', '1,2,3,4', '1.2.3.4\n5', '16909060', '1.2.3.4 x']) {
    assert.equal(parseIp(s), null, s);
    assert.equal(normalizeIp(s), null, s);
  }
});

// ---------------------------------------------------------------- IPv6

test('parseIp accepts full, compressed and embedded-IPv4 IPv6', () => {
  const full = parseIp('2001:0db8:0000:0000:0000:ff00:0042:8329');
  assert.equal(full.v, 6);
  assert.deepEqual(bytes(full), [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0xff, 0x00, 0x00, 0x42, 0x83, 0x29]);
  assert.deepEqual(bytes(parseIp('2001:db8::ff00:42:8329')), bytes(full));
  assert.deepEqual(bytes(parseIp('::')), new Array(16).fill(0));
  assert.deepEqual(bytes(parseIp('::1')), [...new Array(15).fill(0), 1]);
  assert.deepEqual(bytes(parseIp('1::')), [0, 1, ...new Array(14).fill(0)]);
  assert.deepEqual(bytes(parseIp('FE80::ABCD')), bytes(parseIp('fe80::abcd')));
  // '::' may stand for a single zero group when parsing (RFC 4291 §2.2).
  assert.deepEqual(bytes(parseIp('1:2:3:4:5:6:7::')), bytes(parseIp('1:2:3:4:5:6:7:0')));
  assert.deepEqual(bytes(parseIp('::2:3:4:5:6:7:8')), bytes(parseIp('0:2:3:4:5:6:7:8')));
  assert.deepEqual(bytes(parseIp('1:2:3:4:5:6:1.2.3.4')), bytes(parseIp('1:2:3:4:5:6:102:304')));
  const nat64 = parseIp('64:ff9b::81.2.69.1');
  assert.equal(nat64.v, 6);
  assert.deepEqual(bytes(nat64).slice(12), [81, 2, 69, 1]);
});

test('parseIp refuses zone ids and malformed IPv6', () => {
  for (const s of ['fe80::1%eth0', 'fe80::1%1', '::1%', '[::1]', '[::1]:443', ':::', '1:::2', '1::2::3', '::1::', '1:2:3:4:5:6:7:8:9',
    '1:2:3:4:5:6:7', '1:2:3:4:5:6:7:8::', '::1:2:3:4:5:6:7:8', '12345::', 'g::1', ':1::', '1::2:', ':1:2:3:4:5:6:7:8', '1:2:3:4:5:6:7:8:',
    '::1.2.3.4.5', '::01.2.3.4', '::1.2.3.256', '1.2.3.4::', '::1.2.3.4:1', '1:2:3:4:5:6:7:1.2.3.4', '::ffff:1.2.3', ':', '::-1',
    '::ffff:256.1.1.1', ':: 1', '1 ::', '::/0', '2001:db8::1/128', 'fe80::1 %eth0', '0x1::', '::+1']) {
    assert.equal(parseIp(s), null, s);
    assert.equal(normalizeIp(s), null, s);
  }
});

test('IPv4-mapped IPv6 is folded to IPv4, in either spelling', () => {
  assert.deepEqual(parseIp('::ffff:81.2.69.1'), { v: 4, bytes: new Uint8Array([81, 2, 69, 1]) });
  assert.deepEqual(parseIp('::FFFF:5102:4501'), { v: 4, bytes: new Uint8Array([81, 2, 69, 1]) });
  assert.deepEqual(parseIp('0:0:0:0:0:ffff:81.2.69.1'), { v: 4, bytes: new Uint8Array([81, 2, 69, 1]) });
  assert.equal(normalizeIp('::ffff:81.2.69.1'), '81.2.69.1');
  assert.equal(normalizeIp('::ffff:5102:4501'), '81.2.69.1');
  // Not mapped: IPv4-compatible (::a.b.c.d), NAT64 and ::fffe: stay v6.
  assert.equal(parseIp('::81.2.69.1').v, 6);
  assert.equal(parseIp('::fffe:81.2.69.1').v, 6);
  assert.equal(parseIp('1::ffff:81.2.69.1').v, 6);
});

test('normalizeIp writes RFC 5952 canonical text', () => {
  const cases = [
    ['2001:0db8:0000:0000:0000:0000:0000:0001', '2001:db8::1'],
    ['2001:db8:0:0:1:0:0:1', '2001:db8::1:0:0:1'], // equal runs: the first is compressed
    ['2001:0:0:1:0:0:0:1', '2001:0:0:1::1'], // the longest run wins
    ['2001:db8:0:1:1:1:1:1', '2001:db8:0:1:1:1:1:1'], // a lone zero group is written out
    ['2001:DB8::ABCD:EF', '2001:db8::abcd:ef'],
    ['0:0:0:0:0:0:0:0', '::'],
    ['0:0:0:0:0:0:0:1', '::1'],
    ['1:0:0:0:0:0:0:0', '1::'],
    ['0001:0002:0003:0004:0005:0006:0007:0008', '1:2:3:4:5:6:7:8'],
    ['1:2:3:4:5:6:7::', '1:2:3:4:5:6:7:0'],
    ['64:ff9b::81.2.69.1', '64:ff9b::5102:4501'],
    ['fe80:0:0:0:0:0:0:0', 'fe80::'],
    ['1:0:0:2:0:0:0:3', '1:0:0:2::3'],
    ['81.2.69.1', '81.2.69.1'],
  ];
  for (const [input, want] of cases) assert.equal(normalizeIp(input), want, input);
  // Idempotent.
  for (const [, want] of cases) assert.equal(normalizeIp(want), want, want);
});

// ---------------------------------------------------------------- CIDR

test('parseCidr: bare address is the full prefix; prefix range per family', () => {
  assert.deepEqual(parseCidr('81.2.69.0/24'), { v: 4, bytes: new Uint8Array([81, 2, 69, 0]), prefix: 24 });
  assert.equal(parseCidr('81.2.69.7').prefix, 32);
  assert.equal(parseCidr('2a00:1450::1').prefix, 128);
  assert.equal(parseCidr('0.0.0.0/0').prefix, 0);
  assert.equal(parseCidr('::/0').prefix, 0);
  assert.equal(parseCidr('81.2.69.7/32').prefix, 32);
  assert.equal(parseCidr('2a00:1450::1/128').prefix, 128);
  assert.equal(parseCidr('81.2.69.0/33'), null);
  assert.equal(parseCidr('2a00:1450::/129'), null);
  assert.equal(parseCidr('81.2.69.128/25').prefix, 25);
});

test('parseCidr refuses host bits and malformed prefixes', () => {
  for (const s of ['81.2.69.1/24', '81.2.69.128/24', '81.2.69.0/23', '0.0.0.1/0', '2a00:1450::1/64', '2a00:1450:8000::/32', '::1/0',
    '81.2.69.0/', '/24', '81.2.69.0/024', '81.2.69.0/+24', '81.2.69.0/-1', '81.2.69.0/24/24', '81.2.69.0/ 24', '81.2.69.0 /24',
    '81.2.69.0/24 x', '81.2.69.0/2.4', '81.2.69.0/0x18', '81.2.69.0/1e1', '81.2.69.0/１', '01.2.69.0/24', 'fe80::%1/64', '81.2.69.0\\24']) {
    assert.equal(parseCidr(s), null, s);
    assert.equal(normalizeCidr(s), null, s);
  }
});

test('mapped IPv6 ranges of /96 or longer fold to IPv4', () => {
  assert.deepEqual(parseCidr('::ffff:81.2.69.0/120'), { v: 4, bytes: new Uint8Array([81, 2, 69, 0]), prefix: 24 });
  assert.equal(normalizeCidr('::ffff:81.2.69.0/120'), '81.2.69.0/24');
  assert.equal(normalizeCidr('::ffff:81.2.69.1'), '81.2.69.1/32');
  assert.equal(normalizeCidr('::ffff:0:0/96'), '0.0.0.0/0');
  assert.equal(parseCidr('::ffff:81.2.69.1/120'), null); // host bits, whichever spelling
  assert.equal(parseCidr('::/80').v, 6);
});

test('normalizeCidr is canonical and always carries the prefix', () => {
  assert.equal(normalizeCidr('81.2.69.7'), '81.2.69.7/32');
  assert.equal(normalizeCidr(' 81.2.69.0/24 '), '81.2.69.0/24');
  assert.equal(normalizeCidr('2A00:1450:0000:0000::/32'), '2a00:1450::/32');
  assert.equal(normalizeCidr('2a00:1450:4001:0820:0000:0000:0000:200e'), '2a00:1450:4001:820::200e/128');
  assert.equal(normalizeCidr('::/0'), '::/0');
});

test('cidrContains compares bytes at the prefix boundary', () => {
  assert.equal(cidrContains('81.2.69.0/24', '81.2.69.0'), true);
  assert.equal(cidrContains('81.2.69.0/24', '81.2.69.255'), true);
  assert.equal(cidrContains('81.2.69.0/24', '81.2.70.0'), false);
  assert.equal(cidrContains('81.2.69.0/24', '81.2.68.255'), false);
  assert.equal(cidrContains('81.2.69.128/25', '81.2.69.128'), true);
  assert.equal(cidrContains('81.2.69.128/25', '81.2.69.127'), false);
  assert.equal(cidrContains('81.2.69.0/31', '81.2.69.1'), true);
  assert.equal(cidrContains('81.2.69.0/31', '81.2.69.2'), false);
  assert.equal(cidrContains('81.2.69.7', '81.2.69.7'), true);
  assert.equal(cidrContains('81.2.69.7', '81.2.69.6'), false);
  assert.equal(cidrContains('80.0.0.0/4', '95.255.255.255'), true);
  assert.equal(cidrContains('80.0.0.0/4', '96.0.0.0'), false);
  assert.equal(cidrContains('0.0.0.0/0', '185.15.56.1'), true);
  assert.equal(cidrContains('2a00:1450:4001::/48', '2a00:1450:4001:820::200e'), true);
  assert.equal(cidrContains('2a00:1450:4001::/48', '2a00:1450:4002::1'), false);
  assert.equal(cidrContains('2a00:1450:4001:800::/53', '2a00:1450:4001:7ff::1'), false);
  assert.equal(cidrContains('2a00:1450:4001:800::/53', '2a00:1450:4001:fff::1'), true);
  // Families never cross; a mapped address is the v4 caller.
  assert.equal(cidrContains('::/0', '81.2.69.1'), false);
  assert.equal(cidrContains('0.0.0.0/0', '2a00:1450::1'), false);
  assert.equal(cidrContains('81.2.69.0/24', '::ffff:81.2.69.7'), true);
  assert.equal(cidrContains('::ffff:81.2.69.0/120', '81.2.69.7'), true);
  assert.equal(cidrContains('81.2.69.0/24', '::81.2.69.7'), false);
  // Parsed objects on either side.
  assert.equal(cidrContains(parseCidr('91.198.174.0/24'), parseIp('91.198.174.192')), true);
  assert.equal(cidrContains({ v: 4, bytes: new Uint8Array([91, 198, 174, 0]), prefix: 24 }, '91.198.174.1'), true);
  assert.equal(cidrContains({ v: 6, bytes: mapped16(91, 198, 174, 0), prefix: 120 }, '91.198.174.1'), true);
});

test('cidrContains refuses malformed parsed objects', () => {
  const ip = '81.2.69.1';
  for (const c of [
    { v: 4, bytes: [81, 2, 69, 0], prefix: 24 },
    { v: 4, bytes: new Uint8Array([81, 2, 69, 0]), prefix: 33 },
    { v: 4, bytes: new Uint8Array([81, 2, 69, 0]), prefix: '24' },
    { v: 4, bytes: new Uint8Array([81, 2, 69, 0]), prefix: 24.5 },
    { v: 4, bytes: new Uint8Array([81, 2, 69, 0]), prefix: -1 },
    { v: 4, bytes: new Uint8Array([81, 2, 69, 1]), prefix: 24 },
    { v: '4', bytes: new Uint8Array([81, 2, 69, 0]), prefix: 24 },
    { v: 6, bytes: new Uint8Array([81, 2, 69, 0]), prefix: 24 },
    { v: 4, bytes: new Uint8Array(16), prefix: 0 },
    { v: 4, prefix: 24 },
  ]) assert.equal(cidrContains(c, ip), false, label(c));
  assert.equal(cidrContains('81.2.69.0/24', { v: 4, bytes: [81, 2, 69, 1] }), false);
  assert.equal(cidrContains('81.2.69.0/24', { v: 6, bytes: new Uint8Array(4) }), false);
});

// ---------------------------------------------------------------- refusal predicates

test('isPrivateOrReserved refuses every listed range and anything overlapping one', () => {
  const reserved = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24',
    '192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4',
    '::/128', '::1/128', '::ffff:0:0/96', '64:ff9b::/96', '64:ff9b:1::/48', '100::/64', '2001::/23', '2001:db8::/32', '3fff::/20',
    'fc00::/7', 'fe80::/10', 'fec0::/10', 'ff00::/8'];
  for (const r of reserved) assert.equal(isPrivateOrReserved(r), true, r);
  // Inside a range: the last address and a sub-range.
  for (const r of ['10.255.255.255', '10.1.2.0/24', '100.127.255.255', '127.0.0.1', '169.254.169.254', '172.31.255.255', '192.168.1.1/32',
    '198.19.255.255', '203.0.113.7', '255.255.255.255', '0.0.0.0', '239.1.2.3', '::', '::1', '2001:db8:1::/48', 'fd12:3456::1',
    'febf::1', 'ff02::1', '2001:1ff::/32', '64:ff9b::81.2.69.1', '100::ffff', '3fff:fff::1']) assert.equal(isPrivateOrReserved(r), true, r);
  // OVERLAPPING without being inside: a wider range that contains one.
  for (const r of ['10.0.0.0/7', '8.0.0.0/5', '0.0.0.0/1', '128.0.0.0/2', '192.0.0.0/16', '198.0.0.0/8', '100.0.0.0/8', '172.0.0.0/8',
    '192.168.0.0/15', '0.0.0.0/0', '::/0', '::/64', '::/96', '::ff00:0:0/88', '2001::/16', '2000::/3', 'fc00::/6', 'fe80::/9', 'f000::/4']) {
    assert.equal(isPrivateOrReserved(r), true, r);
  }
});

test('isPrivateOrReserved passes public ranges, including the neighbours of reserved ones', () => {
  for (const r of ['81.2.69.0/24', '91.198.174.0/24', '185.15.56.0/24', '1.1.1.1', '8.8.8.8', '9.255.255.255', '11.0.0.0/8',
    '100.63.255.255', '100.128.0.0/10', '126.255.255.255', '128.0.0.0/16', '169.253.255.255', '169.255.0.0/16', '172.15.255.255',
    '172.32.0.0/11', '192.0.1.0/24', '192.0.3.0/24', '192.88.98.0/24', '192.167.255.255', '192.169.0.0/16', '198.17.255.255',
    '198.20.0.0/14', '198.51.99.0/24', '198.51.101.0/24', '203.0.112.0/24', '203.0.114.0/24', '223.255.255.255', '64.0.0.0/3',
    '2a00:1450:4001::/48', '2606:4700::1111', '2001:200::/23', '2001:db7::/32', '2001:db9::/32', '3fff:1000::/20', '2002::/16',
    'fbff:ffff::/32', 'fe00::/16', 'fe00::/9', 'ff::/16', '64:ff9a::/32', '::ffff:81.2.69.0/120', '::ffff:91.198.174.192']) {
    assert.equal(isPrivateOrReserved(r), false, r);
  }
});

test('a mapped range is classified by the IPv4 it embeds', () => {
  assert.equal(isPrivateOrReserved('::ffff:10.0.0.0/104'), true);
  assert.equal(isPrivateOrReserved('::ffff:192.168.1.1'), true);
  assert.equal(isPrivateOrReserved('::ffff:203.0.113.0/120'), true);
  assert.equal(isPrivateOrReserved('::ffff:81.2.69.0/120'), false);
  assert.equal(isPrivateOrReserved(parseCidr('::ffff:81.2.69.0/120')), false);
  assert.equal(isPrivateOrReserved({ v: 6, bytes: mapped16(81, 2, 69, 0), prefix: 120 }), false);
  assert.equal(isPrivateOrReserved({ v: 6, bytes: mapped16(10, 0, 0, 0), prefix: 104 }), true);
});

test('isWholeFamily is prefix 0 in either family, however it is spelled', () => {
  for (const r of ['0.0.0.0/0', '::/0', '::ffff:0:0/96', '0:0:0:0:0:0:0:0/0']) assert.equal(isWholeFamily(r), true, r);
  for (const r of ['0.0.0.0/1', '128.0.0.0/1', '::/1', '81.2.69.0/24', '2a00:1450::/32', '81.2.69.1', '::ffff:0:0/97']) {
    assert.equal(isWholeFamily(r), false, r);
  }
  assert.equal(isWholeFamily({ v: 4, bytes: new Uint8Array(4), prefix: 0 }), true);
});

// ---------------------------------------------------------------- bestMatch

test('bestMatch: most specific wins, whatever the order', () => {
  const wide = { id: 1, cidr: '81.2.0.0/16', tier: 1 };
  const mid = { id: 2, cidr: '81.2.69.0/24', tier: 2 };
  const narrow = { id: 3, cidr: '81.2.69.7/32', tier: 3 };
  for (const list of [[wide, mid, narrow], [narrow, mid, wide], [mid, narrow, wide]]) {
    assert.equal(bestMatch(list, '81.2.69.7'), narrow);
    assert.equal(bestMatch(list, '81.2.69.8'), mid);
    assert.equal(bestMatch(list, '81.2.70.1'), wide);
    assert.equal(bestMatch(list, '81.3.0.1'), null);
  }
  // A stricter wide entry does not beat a more specific lenient one: specificity first.
  const strictWide = { id: 4, cidr: '81.2.0.0/16', tier: 4 };
  const lenientNarrow = { id: 5, cidr: '81.2.69.0/24', tier: 1 };
  assert.equal(bestMatch([strictWide, lenientNarrow], '81.2.69.1'), lenientNarrow);
  assert.equal(bestMatch([lenientNarrow, strictWide], '81.2.69.1'), lenientNarrow);
});

test('bestMatch: an exact tie goes to the stricter (higher-numbered) tier', () => {
  const t1 = { id: 1, cidr: '91.198.174.0/24', tier: 1 };
  const t3 = { id: 3, cidr: '91.198.174.0/24', tier: 3 };
  const t2 = { id: 2, cidr: '::ffff:91.198.174.0/120', tier: 2 }; // the same range, spelled as v6
  assert.equal(bestMatch([t1, t3], '91.198.174.10'), t3);
  assert.equal(bestMatch([t3, t1], '91.198.174.10'), t3);
  assert.equal(bestMatch([t1, t2], '91.198.174.10'), t2);
  assert.equal(bestMatch([t2, t1, t3], '91.198.174.10'), t3);
  // A tier that is not 1–4 ranks as stricter than any real tier.
  for (const bad of ['x', null, undefined, 0, 9, 2.5, {}, NaN]) {
    const corrupt = { id: 9, cidr: '91.198.174.0/24', tier: bad };
    const t4 = { id: 4, cidr: '91.198.174.0/24', tier: 4 };
    assert.equal(bestMatch([t4, corrupt], '91.198.174.10'), corrupt, label(bad));
    assert.equal(bestMatch([corrupt, t4], '91.198.174.10'), corrupt, label(bad));
  }
  // Numeric strings read as the tier they spell.
  assert.equal(bestMatch([{ cidr: '91.198.174.0/24', tier: '3' }, t1], '91.198.174.10').tier, '3');
});

test('bestMatch: families, mapped callers, IPv6 and unreadable entries', () => {
  const v6 = { cidr: '2a00:1450:4001::/48', tier: 2 };
  const v6narrow = { cidr: '2a00:1450:4001:820::/64', tier: 1 };
  const v4 = { cidr: '185.15.56.0/24', tier: 2 };
  const list = [null, 'x', 42, {}, { cidr: 'abc', tier: 1 }, { cidr: Symbol('x'), tier: 1 }, { cidr: '185.15.56.1/24', tier: 1 },
    { tier: 1 }, v6, v6narrow, v4];
  assert.equal(bestMatch(list, '2a00:1450:4001:820::200e'), v6narrow);
  assert.equal(bestMatch(list, '2a00:1450:4001:821::1'), v6);
  assert.equal(bestMatch(list, '185.15.56.9'), v4);
  assert.equal(bestMatch(list, '::ffff:185.15.56.9'), v4);
  assert.equal(bestMatch(list, parseIp('185.15.56.9')), v4);
  assert.equal(bestMatch(list, '185.15.57.1'), null);
  assert.equal(bestMatch([], '185.15.56.9'), null);
  assert.equal(bestMatch([{ cidr: '::/0', tier: 1 }], '185.15.56.9'), null); // v6 never matches a v4 caller
});

// ---------------------------------------------------------------- hostile input

test('nothing throws on hostile input; refusal predicates fail closed', () => {
  const good = [{ cidr: '81.2.69.0/24', tier: 1 }];
  for (const v of HOSTILE) {
    const l = label(v);
    assert.equal(parseIp(v), null, l);
    assert.equal(normalizeIp(v), null, l);
    assert.equal(parseCidr(v), null, l);
    assert.equal(normalizeCidr(v), null, l);
    assert.equal(cidrContains(v, '81.2.69.1'), false, l);
    assert.equal(cidrContains('81.2.69.0/24', v), false, l);
    assert.equal(cidrContains(v, v), false, l);
    assert.equal(isPrivateOrReserved(v), true, l);
    assert.equal(isWholeFamily(v), true, l);
    assert.equal(bestMatch(v, '81.2.69.1'), null, l);
    assert.equal(bestMatch(good, v), null, l);
    assert.equal(bestMatch([v], '81.2.69.1'), null, l);
    assert.equal(bestMatch([{ cidr: v, tier: 1 }], '81.2.69.1'), null, l);
  }
  // An array whose iteration throws, and an entry whose getter throws.
  const evilArr = new Proxy([], { get(t, k) { if (k === Symbol.iterator) throw new Error('boom'); return Reflect.get(t, k); } });
  assert.equal(bestMatch(evilArr, '81.2.69.1'), null);
  assert.equal(bestMatch([throwing], '81.2.69.1'), null);
  assert.equal(bestMatch([{ get cidr() { throw new Error('boom'); }, tier: 1 }], '81.2.69.1'), null);
  // Absurdly long input is refused before parsing.
  assert.equal(parseIp('1'.repeat(100000)), null);
  assert.equal(parseCidr('81.2.69.0/' + '0'.repeat(100000)), null);
  assert.equal(parseIp('::' + ':1'.repeat(40)), null);
});

test('returned bytes are copies: mutating them changes nothing', () => {
  const c = parseCidr('81.2.69.0/24');
  const e = { cidr: c, tier: 1 };
  assert.equal(bestMatch([e], '81.2.69.5'), e);
  const ip = parseIp('81.2.69.5');
  assert.equal(cidrContains(c, ip), true);
  ip.bytes[0] = 10;
  assert.equal(cidrContains(c, '81.2.69.5'), true);
  assert.equal(normalizeIp('81.2.69.5'), '81.2.69.5');
});

await run();
