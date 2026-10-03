import { test, assert, run } from '../helpers/t.js';
import { makeEnvWithSchema } from '../helpers/env.js';
import { CHROME_UA, FIREFOX_UA, SAFARI_IOS_UA } from '../helpers/http.js';
import { iso, DAY, HOUR, MINUTE } from '../../src/util.js';
import { signToken } from '../../src/crypto.js';
import * as F from '../../src/fingerprint.js';

const HOSTILE = [null, undefined, NaN, Infinity, '', '   ', 'abc', {}, [], true, 0, Symbol('x')];
const show = (v) => {
  try {
    return typeof v === 'symbol' ? 'Symbol' : JSON.stringify(v) ?? String(v);
  } catch {
    return '(unprintable)';
  }
};
const CHROME_CH = '"Google Chrome";v="129", "Not=A?Brand";v="8", "Chromium";v="129"';
const CF = { country: 'US', asn: 7922, asOrganization: 'Comcast Cable', colo: 'EWR', city: 'Newark', timezone: 'America/New_York', tlsVersion: 'TLSv1.3', tlsCipher: 'AEAD-AES128-GCM-SHA256', httpProtocol: 'HTTP/2' };

function request(headers = {}) {
  return new Request('https://staff.example.com/login', {
    headers: { 'cf-connecting-ip': '81.2.69.10', 'user-agent': CHROME_UA, 'accept-language': 'en-US,en;q=0.9', 'sec-ch-ua': CHROME_CH, 'sec-ch-ua-mobile': '?0', 'sec-ch-ua-platform': '"macOS"', ...headers },
  });
}

const edgeWith = (headers = {}, cf = {}) => F.edgeSignals(request(headers), { ...CF, ...cf });

function cleanClient(o = {}) {
  return {
    v: 1,
    ua: CHROME_UA,
    platform: 'MacIntel',
    vendor: 'Google Inc.',
    uaData: { brands: [{ brand: 'Chromium', version: '129' }], mobile: false, platform: 'macOS' },
    language: 'en-US',
    languages: ['en-US', 'en'],
    tz: 'America/New_York',
    tzOffset: 300,
    intl: { locale: 'en-US', calendar: 'gregory', numberingSystem: 'latn', hourCycle: 'h12' },
    screen: { w: 1512, h: 982, aw: 1512, ah: 945, cd: 30, dpr: 2 },
    window: { iw: 1400, ih: 800, ow: 1512, oh: 900 },
    hw: { cores: 10, memory: 8, touch: 0 },
    media: { dark: true, reducedMotion: false, contrast: 'no-preference', pointerCoarse: false, hover: true, gamut: 'p3', forcedColors: false },
    canvas: 'c'.repeat(64),
    webgl: { vendor: 'Apple', renderer: 'Apple M2', hash: 'd'.repeat(64) },
    audio: 'e'.repeat(64),
    fonts: ['Arial', 'Helvetica', 'Menlo'],
    storage: { cookies: true, local: true, session: true, idb: true, quotaMb: 100000 },
    net: { type: '4g', downlink: 10, rtt: 50, saveData: false },
    perms: { notifications: 'prompt', geolocation: 'prompt', camera: 'prompt', microphone: 'prompt' },
    webrtc: { candidates: 1, mdns: true, ipv6: false },
    math: 'f'.repeat(64),
    features: { serviceWorker: true, webgpu: true },
    automation: [],
    blocked: [],
    elapsedMs: 120,
    ...o,
  };
}

const keys = (r) => r.flags.map((f) => f.key).sort();
const cookieValue = (sc) => sc.split(';')[0].split('=').slice(1).join('=');

// ---------------------------------------------------------------- edge

test('edgeSignals reads cf and headers; header NAMES only, never values', () => {
  const e = edgeWith({ cookie: '__Host-sid=secret-session-value', 'sec-ch-ua-model': '"Pixel 8"' }, { botManagement: { score: 88, ja3Hash: 'abc123', ja4: 't13d' } });
  assert.equal(e.ip, '81.2.69.10');
  assert.equal(e.country, 'US');
  assert.equal(e.asn, 7922);
  assert.equal(e.as_org, 'Comcast Cable');
  assert.equal(e.timezone, 'America/New_York');
  assert.equal(e.tls_version, 'TLSv1.3');
  assert.equal(e.http_protocol, 'HTTP/2');
  assert.equal(e.bot_score, 88);
  assert.equal(e.ja3, 'abc123');
  assert.equal(e.ua, CHROME_UA);
  assert.equal(e.sec_ch_ua_platform, '"macOS"');
  assert.equal(e.sec_ch_ua_model, '"Pixel 8"');
  assert.ok(e.header_names.includes('cookie'));
  assert.deepEqual(e.header_names, [...e.header_names].sort());
  assert.ok(!JSON.stringify(e).includes('secret-session-value'));
});

test('edgeSignals never throws: hostile cf, throwing getters, no request', () => {
  const evil = { get country() { throw new Error('boom'); }, asn: 'AS13335', botManagement: { get score() { throw new Error('x'); } } };
  for (const cf of [...HOSTILE, evil, { country: 'usa' }, { country: 'T1' }]) {
    const e = F.edgeSignals(request(), cf);
    assert.equal(typeof e, 'object', show(cf));
    assert.ok(e.country === null || /^[A-Z][A-Z0-9]$/.test(e.country));
  }
  assert.equal(F.edgeSignals(request(), { country: 't1' }).country, 'T1');
  assert.equal(F.edgeSignals(request(), evil).country, null);
  assert.equal(F.edgeSignals(request(), evil).asn, null);
  for (const r of HOSTILE) assert.equal(typeof F.edgeSignals(r, CF), 'object', show(r));
  const trap = new Proxy({}, { get() { throw new Error('every read throws'); } });
  const fromTrap = F.edgeSignals(request(), trap);
  assert.deepEqual([fromTrap.country, fromTrap.asn, fromTrap.as_org, fromTrap.tls_version, fromTrap.ja3], [null, null, null, null, null]);
  assert.equal(F.edgeSignals(request(), { botManagement: trap }).ja3, null);
  const badHeaders = { headers: { get() { throw new Error('x'); }, keys() { throw new Error('y'); } } };
  assert.equal(F.edgeSignals(badHeaders, CF).ua, '');
});

// ---------------------------------------------------------------- client

test('sanitizeClientSignals keeps the §10.1 shape, drops unknown keys, caps strings and arrays', () => {
  const s = F.sanitizeClientSignals({
    ...cleanClient(),
    evil: 'drop me',
    ua: 'x'.repeat(1000),
    fonts: Array.from({ length: 200 }, (_, i) => `Font${i}`),
    languages: ['en', 5, null, { a: 1 }, 'fr'],
    screen: { w: 1, h: 2, extra: 3, cd: '24' },
    hw: { cores: Infinity, memory: NaN, touch: -1 },
    features: { serviceWorker: true, webgpu: 'yes', __proto__x: true, ['__proto__']: true, constructor: true },
    automation: ['webdriver', '<script>', 'x'.repeat(65)],
    uaData: { brands: [{ brand: 'Chromium', version: '129', x: 1 }, 'junk'], mobile: 'no', platform: 'macOS' },
    webgl: null,
    net: 'fast',
  });
  assert.ok(!('evil' in s));
  assert.equal(s.ua.length, 256);
  assert.equal(s.fonts.length, 64);
  assert.deepEqual(s.languages, ['en', 'fr']);
  assert.deepEqual(s.screen, { w: 1, h: 2 });
  assert.deepEqual(s.hw, {});
  assert.deepEqual(Object.keys(s.features).sort(), ['constructor', 'serviceWorker']);
  assert.equal(Object.getPrototypeOf(s.features), Object.prototype);
  assert.deepEqual(s.automation, ['webdriver']);
  assert.deepEqual(s.uaData, { brands: [{ brand: 'Chromium', version: '129' }], platform: 'macOS' });
  assert.equal(s.webgl, null);
  assert.ok(!('net' in s));
  assert.deepEqual(F.sanitizeClientSignals(s), s, 'idempotent');
});

test('sanitizeClientSignals refuses non-objects and bodies over 16 KiB', () => {
  for (const v of HOSTILE) {
    const out = F.sanitizeClientSignals(v);
    if (v && typeof v === 'object' && !Array.isArray(v)) assert.deepEqual(out, {}, show(v));
    else assert.equal(out, null, show(v));
  }
  assert.equal(F.sanitizeClientSignals({ fonts: Array.from({ length: 100 }, () => 'x'.repeat(200)) }), null);
  const cyclic = { v: 1 };
  cyclic.self = cyclic;
  assert.equal(F.sanitizeClientSignals(cyclic), null);
  assert.equal(F.sanitizeClientSignals({ v: 10n }), null);
  const throwing = { get ua() { throw new Error('getter'); } };
  assert.equal(F.sanitizeClientSignals(throwing), null);
});

// ---------------------------------------------------------------- risk

test('a clean Chrome on a home network scores 0', () => {
  const r = F.scoreRisk(edgeWith(), cleanClient());
  assert.deepEqual(r, { score: 0, flags: [] });
});

test('every edge flag fires alone, once, with a plain-English reason', () => {
  const cases = [
    ['no_ua', edgeWith({ 'user-agent': '' })],
    ['no_accept_language', edgeWith({ 'accept-language': '' })],
    ['old_http', edgeWith({}, { httpProtocol: 'HTTP/1.1' })],
    ['old_tls', edgeWith({}, { tlsVersion: 'TLSv1.1' })],
    ['bot_score', edgeWith({}, { botManagement: { score: 12 } })],
    ['datacenter', edgeWith({}, { asn: 16509, asOrganization: 'AMAZON-02' })],
    ['tor', edgeWith({}, { country: 'T1' })],
    ['ch_mismatch', edgeWith({ 'user-agent': FIREFOX_UA, 'sec-ch-ua-platform': '"Windows"' })],
  ];
  for (const [key, edge] of cases) {
    const r = F.scoreRisk(edge, null);
    assert.deepEqual(keys(r), [key], key);
    assert.ok(r.flags[0].weight > 0 && r.flags[0].reason.length > 15, key);
    assert.equal(r.score, r.flags[0].weight);
  }
  assert.match(F.scoreRisk(edgeWith({}, { asn: 16509, asOrganization: 'AMAZON-02' }), null).flags[0].reason, /AS16509 AMAZON-02/);
  assert.match(F.scoreRisk(edgeWith({}, { botManagement: { score: 12 } }), null).flags[0].reason, /12/);
  assert.deepEqual(keys(F.scoreRisk(edgeWith({}, { botManagement: { score: 30 } }), null)), [], 'exactly 30 is not below 30');
  assert.deepEqual(keys(F.scoreRisk(edgeWith({}, { tlsVersion: 'TLSv1.2' }), null)), []);
});

test('automation user agents are flagged and named', () => {
  const uas = ['Mozilla/5.0 HeadlessChrome/129.0.0.0', 'Mozilla/5.0 PhantomJS/2.1.1', 'curl/8.4.0', 'Wget/1.21', 'python-requests/2.31', 'Go-http-client/2.0', 'node-fetch/1.0', 'axios/1.6.0', 'Java/17.0.2', 'libwww-perl/6.72', 'Scrapy/2.11 (+https://scrapy.org)', 'okhttp/4.12.0'];
  for (const ua of uas) {
    const r = F.scoreRisk(edgeWith({ 'user-agent': ua, 'sec-ch-ua': '', 'sec-ch-ua-platform': '' }), null);
    assert.ok(keys(r).includes('automation_ua'), ua);
    assert.ok(F.automationTells(edgeWith({ 'user-agent': ua }), null).length > 0, ua);
  }
  assert.match(F.scoreRisk(edgeWith({ 'user-agent': 'curl/8.4.0' }), null).flags.find((f) => f.key === 'automation_ua').reason, /curl/);
  assert.deepEqual(F.automationTells(edgeWith(), cleanClient()), []);
});

test('curl with no Accept-Language scores over the default threshold of 70', () => {
  const r = F.scoreRisk(edgeWith({ 'user-agent': 'curl/8.4.0', 'accept-language': '', 'sec-ch-ua': '', 'sec-ch-ua-platform': '' }), null);
  assert.ok(r.score >= 70, String(r.score));
});

test('client hints: Brave-style brands pass; a Firefox UA with hints, hints without Chromium and a platform clash do not', () => {
  assert.deepEqual(keys(F.scoreRisk(edgeWith({ 'sec-ch-ua': '"Brave";v="129", "Chromium";v="129", "Not=A?Brand";v="8"' }), null)), []);
  assert.deepEqual(keys(F.scoreRisk(edgeWith({ 'user-agent': FIREFOX_UA, 'sec-ch-ua-platform': '' }), null)), ['ch_mismatch']);
  assert.deepEqual(keys(F.scoreRisk(edgeWith({ 'sec-ch-ua': '"Google Chrome";v="129"' }), null)), ['ch_mismatch']);
  assert.deepEqual(keys(F.scoreRisk(edgeWith({ 'sec-ch-ua-platform': '"Windows"' }), null)), ['ch_mismatch']);
  assert.deepEqual(keys(F.scoreRisk(edgeWith({ 'user-agent': FIREFOX_UA, 'sec-ch-ua': '', 'sec-ch-ua-platform': '' }), null)), [], 'Firefox without hints is normal');
});

test('every client flag fires alone with a reason', () => {
  const e = edgeWith();
  const cases = [
    ['client_automation', { automation: ['webdriver'] }],
    ['client_automation', { automation: ['cdc', 'selenium'] }],
    ['no_plugins', { automation: ['no-plugins'] }],
    ['zero_outer', { window: { iw: 800, ih: 600, ow: 0, oh: 0 } }],
    ['software_gl', { webgl: { vendor: 'Google Inc.', renderer: 'ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero)))', hash: 'x' } }],
    ['software_gl', { webgl: { vendor: 'Mesa', renderer: 'llvmpipe (LLVM 15.0.7, 256 bits)', hash: 'x' } }],
    ['zero_screen', { screen: { w: 0, h: 0, aw: 0, ah: 0, cd: 24, dpr: 1 } }],
    ['no_languages', { languages: [] }],
    ['blocked_probes', { blocked: ['canvas', 'webgl', 'audio', 'fonts', 'webrtc'] }],
    ['tz_mismatch', { tz: 'Asia/Tokyo' }],
    ['tz_mismatch', { tz: 'Mars/Olympus_Mons' }],
  ];
  for (const [key, patch] of cases) {
    const r = F.scoreRisk(e, cleanClient(patch));
    assert.deepEqual(keys(r), [key], JSON.stringify(patch));
    assert.ok(r.flags[0].reason.length > 15);
  }
  assert.match(F.scoreRisk(e, cleanClient({ automation: ['webdriver'] })).flags[0].reason, /navigator\.webdriver/);
  assert.deepEqual(keys(F.scoreRisk(e, cleanClient({ blocked: ['a', 'b', 'c', 'd'] }))), [], 'four blocked probes are not five');
  const phone = edgeWith({ 'user-agent': SAFARI_IOS_UA, 'sec-ch-ua': '', 'sec-ch-ua-platform': '' });
  assert.deepEqual(keys(F.scoreRisk(phone, cleanClient({ ua: SAFARI_IOS_UA, hw: { cores: 6, memory: 4, touch: 0 } }))), ['touch_mismatch']);
  assert.deepEqual(keys(F.scoreRisk(phone, cleanClient({ ua: SAFARI_IOS_UA, hw: { cores: 6, memory: 4, touch: 5 } }))), []);
});

test('time zones: same offsets in either season do not flag; different in both do', () => {
  const e = (tz) => edgeWith({}, { timezone: tz });
  assert.deepEqual(keys(F.scoreRisk(e('America/New_York'), cleanClient({ tz: 'America/Detroit' }))), []);
  assert.deepEqual(keys(F.scoreRisk(e('America/Denver'), cleanClient({ tz: 'America/Phoenix' }))), [], 'differs only in summer');
  assert.deepEqual(keys(F.scoreRisk(e('Europe/London'), cleanClient({ tz: 'America/New_York' }))), ['tz_mismatch']);
  assert.deepEqual(keys(F.scoreRisk(e(null), cleanClient({ tz: 'Asia/Tokyo' }))), [], 'no edge zone, no comparison');
  assert.deepEqual(keys(F.scoreRisk(e('Not/AZone'), cleanClient({ tz: 'Asia/Tokyo' }))), []);
});

test('score is the sum, capped at 100', () => {
  const edge = edgeWith({ 'user-agent': 'Mozilla/5.0 HeadlessChrome/129.0.0.0', 'accept-language': '' }, { country: 'T1', asn: 14061, tlsVersion: 'TLSv1', botManagement: { score: 2 } });
  const r = F.scoreRisk(edge, cleanClient({ automation: ['webdriver'], languages: [] }));
  assert.equal(r.score, 100);
  assert.ok(r.flags.reduce((s, f) => s + f.weight, 0) > 100);
  assert.equal(new Set(r.flags.map((f) => f.key)).size, r.flags.length, 'each flag once');
});

test('scoreRisk and automationTells never throw on hostile edge or client', () => {
  for (const e of HOSTILE) {
    for (const c of HOSTILE) {
      const r = F.scoreRisk(e, c);
      assert.ok(Number.isInteger(r.score) && r.score >= 0 && r.score <= 100);
      assert.ok(Array.isArray(F.automationTells(e, c)));
    }
  }
  const weird = { ua: { toString: () => 'curl/1' }, asn: '16509', country: ['T1'], bot_score: '5', tls_version: 7 };
  const r = F.scoreRisk(weird, { automation: 'webdriver', window: [], screen: 'big' });
  assert.ok(keys(r).includes('no_ua'), 'a non-string UA reads as no UA');
  assert.ok(keys(r).includes('datacenter'), "an ASN as a numeric string is still read");
  assert.ok(!keys(r).includes('tor'));
});

test('isDatacenterAsn: a curated list of at least 30 hosting networks; hostile → false', () => {
  const listed = [16509, 14618, 15169, 396982, 19527, 8075, 14061, 63949, 20473, 16276, 24940, 12876, 51167, 31898, 45102, 132203, 45090, 60781, 28753, 9009];
  for (const asn of listed) assert.equal(F.isDatacenterAsn(asn), true, String(asn));
  assert.equal(F.isDatacenterAsn('16509'), true);
  let n = 0;
  for (let a = 1; a < 400000; a++) if (F.isDatacenterAsn(a)) n++;
  assert.ok(n >= 30, `${n} ASNs`);
  for (const asn of [7922, 3320, 2856, ...HOSTILE]) assert.equal(F.isDatacenterAsn(asn), false, show(asn));
});

// ---------------------------------------------------------------- hashes

test('fingerprintHash is this exact configuration; visitorId survives a browser update', async () => {
  const e = edgeWith();
  const c = cleanClient();
  const h = await F.fingerprintHash(e, c);
  const v = await F.visitorId(e, c);
  assert.match(h, /^[0-9a-f]{64}$/);
  assert.match(v, /^[0-9a-f]{64}$/);
  assert.equal(await F.fingerprintHash(e, c), h);
  const ua2 = CHROME_UA.replace('Chrome/129', 'Chrome/130');
  const e2 = edgeWith({ 'user-agent': ua2 });
  const c2 = cleanClient({ ua: ua2 });
  assert.notEqual(await F.fingerprintHash(e2, c2), h, 'a new browser version is a new configuration');
  assert.equal(await F.visitorId(e2, c2), v, '…but the same visitor');
  assert.notEqual(await F.visitorId(e, cleanClient({ screen: { w: 1920, h: 1080, cd: 24, dpr: 1 } })), v);
  assert.equal(await F.fingerprintHash(e, cleanClient({ elapsedMs: 999, net: { type: '3g', rtt: 300 }, window: { iw: 1 }, blocked: ['x'] })), h, 'per-request noise is ignored');
  assert.equal(await F.fingerprintHash(edgeWith({}, { country: 'GB', colo: 'LHR' }), c), h, 'network location is not configuration');
  for (const x of HOSTILE) {
    assert.match(await F.fingerprintHash(x, x), /^[0-9a-f]{64}$/);
    assert.match(await F.visitorId(x, x), /^[0-9a-f]{64}$/);
  }
});

// ---------------------------------------------------------------- cookie

test('fp cookie: signed, 24 hours, carries risk, visitor and the automation bit; forged and expired read as none', async () => {
  const env = await makeEnvWithSchema();
  const t = env.__clock();
  const hash = 'a'.repeat(64);
  const sc = await F.fpCookie(env, hash, 35, t, { visitorId: 'b'.repeat(64), automation: true });
  assert.match(sc, /^__Host-fp=/);
  assert.match(sc, /Max-Age=86400/);
  assert.match(sc, /SameSite=Lax/);
  const v = cookieValue(sc);
  const rc = (val, at = t) => ({ env, nowMs: at, cookies: { [F.FP_COOKIE]: val } });
  assert.deepEqual(await F.readFpCookie(rc(v)), { hash, risk: 35, visitor_id: 'b'.repeat(64), automation: true });
  assert.equal(await F.readFpCookie(rc(v, t + DAY)), null, 'expired');
  assert.ok(await F.readFpCookie(rc(v, t + DAY - 1)));
  const payload = v.slice(0, v.lastIndexOf('.'));
  const forged = [
    payload,
    v.replace('.35.', '.5.'),
    v.replace(`${hash}`, 'c'.repeat(64)),
    await signToken(env, 'device', payload),
    await signToken(env, 'fp', `${hash}.-.5.0.${t + 365 * DAY}`), // signed, but claims a year
    await signToken(env, 'fp', `${hash}.-.500.0.${t + HOUR}`),
    await signToken(env, 'fp', `${hash}.-.5.2.${t + HOUR}`),
  ];
  for (const f of [...forged, ...HOSTILE]) assert.equal(await F.readFpCookie(rc(f)), null, show(f));
  assert.equal(await F.readFpCookie(null), null);
  const worst = cookieValue(await F.fpCookie(env, hash, 'abc', t));
  assert.equal((await F.readFpCookie(rc(worst))).risk, 100, 'an unreadable score is stored as the worst');
  for (const h of HOSTILE) await assert.rejects(F.fpCookie(env, h, 0, t), Error, show(h));
});

// ---------------------------------------------------------------- storage

test('recordFingerprint upserts by hash, counts hits, returns a cookie that reads back', async () => {
  const env = await makeEnvWithSchema();
  const rc = { env, nowMs: env.__clock(), ip: '81.2.69.10', edge: edgeWith(), user: { id: 5 } };
  const a = await F.recordFingerprint(rc, { client: cleanClient() });
  env.__advance(MINUTE);
  const b = await F.recordFingerprint({ ...rc, nowMs: env.__clock(), user: null }, { client: cleanClient({ elapsedMs: 7 }) });
  assert.equal(a.hash, b.hash);
  assert.equal(a.risk, 0);
  const rows = env.DB.q('SELECT * FROM fingerprints');
  assert.equal(rows.length, 1);
  assert.equal(rows[0].hits, 2);
  assert.equal(rows[0].last_user_id, 5, 'a later anonymous visit keeps the last known person');
  assert.equal(rows[0].last_seen, iso(env.__clock()));
  assert.equal(rows[0].visitor_id, a.visitor_id);
  const read = await F.readFpCookie({ env, nowMs: env.__clock(), cookies: { [F.FP_COOKIE]: cookieValue(b.setCookie) } });
  assert.deepEqual(read, { hash: b.hash, risk: 0, visitor_id: b.visitor_id, automation: false });
  const bot = await F.recordFingerprint(rc, { client: cleanClient({ automation: ['webdriver'] }) });
  assert.deepEqual(bot.automation, ['webdriver']);
  assert.equal((await F.readFpCookie({ env, nowMs: env.__clock(), cookies: { [F.FP_COOKIE]: cookieValue(bot.setCookie) } })).automation, true);
  for (const v of HOSTILE) await assert.doesNotReject(F.recordFingerprint(rc, v ? { client: v } : v), show(v));
});

test('B trap 6: 5,000 distinct client signal sets cannot grow the fingerprints table past its cap', async () => {
  const env = await makeEnvWithSchema();
  env.__retention = (k) => (k === 'fingerprints' ? 300 : undefined);
  const edge = edgeWith();
  let last;
  for (let i = 0; i < 5000; i++) {
    if (i % 50 === 0) env.__advance(1000);
    last = await F.recordFingerprint({ env, nowMs: env.__clock(), ip: '91.198.174.7', edge }, { client: cleanClient({ ua: `${CHROME_UA} r${i}`, canvas: `c${i}` }) });
  }
  assert.equal(env.DB.q('SELECT COUNT(*) AS n FROM fingerprints')[0].n, 300);
  assert.equal(env.DB.q('SELECT COUNT(*) AS n FROM fingerprints WHERE hash = ?', last.hash)[0].n, 1, 'the newest row survives');
});

test('fingerprints at the real cap (20,000) and the 90-day age trim; __retention cannot raise the cap', async () => {
  const env = await makeEnvWithSchema();
  env.__retention = () => 10_000_000;
  const t = env.__clock();
  env.DB.sqlite.exec('BEGIN');
  const ins = env.DB.sqlite.prepare('INSERT INTO fingerprints (hash, first_seen, last_seen) VALUES (?, ?, ?)');
  for (let i = 0; i < 20000; i++) ins.run(`seed${i}`, iso(t - HOUR), iso(t - HOUR + i));
  ins.run('ancient', iso(t - 91 * DAY), iso(t - 91 * DAY));
  env.DB.sqlite.exec('COMMIT');
  for (let i = 0; i < 25; i++) await F.recordFingerprint({ env, nowMs: t, edge: edgeWith() }, { client: cleanClient({ canvas: `n${i}` }) });
  assert.equal(env.DB.q('SELECT COUNT(*) AS n FROM fingerprints')[0].n, 20000);
  assert.equal(env.DB.q("SELECT COUNT(*) AS n FROM fingerprints WHERE hash = 'ancient'")[0].n, 0);
  assert.equal(env.DB.q("SELECT COUNT(*) AS n FROM fingerprints WHERE hash IN ('seed0', 'seed1', 'seed24')")[0].n, 0, 'the least recently seen go first');
  assert.equal(env.DB.q("SELECT COUNT(*) AS n FROM fingerprints WHERE hash = 'seed19999'")[0].n, 1);
});

test('the 90-day age trim works on its own, well under the count cap', async () => {
  const env = await makeEnvWithSchema();
  const t = env.__clock();
  env.DB.q("INSERT INTO fingerprints (hash, first_seen, last_seen) VALUES ('stale', ?, ?)", iso(t - 91 * DAY), iso(t - 91 * DAY));
  env.DB.q("INSERT INTO fingerprints (hash, first_seen, last_seen) VALUES ('recent', ?, ?)", iso(t - 89 * DAY), iso(t - 89 * DAY));
  await F.recordFingerprint({ env, nowMs: t, edge: edgeWith() }, { client: cleanClient() });
  assert.deepEqual(env.DB.q("SELECT hash FROM fingerprints WHERE hash IN ('stale', 'recent')").map((r) => r.hash), ['recent']);
});

// ---------------------------------------------------------------- visits

function visitRc(env, o = {}) {
  return { env, nowMs: env.__clock(), ip: '81.2.69.10', method: 'get', path: '/login', ua: CHROME_UA, edge: edgeWith(), fp: { hash: 'a'.repeat(64), risk: 12, visitor_id: 'b'.repeat(64) }, device: { id: 'dev-1', row: null }, user: { id: 3 }, ...o };
}

test('recordVisit writes one row with the decision and reason', async () => {
  const env = await makeEnvWithSchema();
  await F.recordVisit(visitRc(env, { gate: { allowed: 'none', reason: 'country', risk: { score: 40 } } }), { decision: 'none', reason: 'country' });
  const v = env.DB.q('SELECT * FROM visits');
  assert.equal(v.length, 1);
  assert.equal(v[0].decision, 'none');
  assert.equal(v[0].reason, 'country');
  assert.equal(v[0].method, 'GET');
  assert.equal(v[0].country, 'US');
  assert.equal(v[0].asn, 7922);
  assert.equal(v[0].fp_hash, 'a'.repeat(64));
  assert.equal(v[0].device_id, 'dev-1');
  assert.equal(v[0].user_id, 3);
  assert.equal(v[0].risk, 40);
});

test('recordVisit is bounded by count and by age', async () => {
  const env = await makeEnvWithSchema();
  env.__retention = (k) => (k === 'visits' ? 50 : undefined);
  const t = env.__clock();
  env.DB.q("INSERT INTO visits (at, path) VALUES (?, '/old')", iso(t - 31 * DAY));
  for (let i = 0; i < 120; i++) await F.recordVisit(visitRc(env, { path: `/p${i}` }), { decision: 'none', reason: 'x' });
  assert.equal(env.DB.q('SELECT COUNT(*) AS n FROM visits')[0].n, 50);
  assert.equal(env.DB.q("SELECT COUNT(*) AS n FROM visits WHERE path = '/old'")[0].n, 0);
  assert.equal(env.DB.q("SELECT COUNT(*) AS n FROM visits WHERE path = '/p119'")[0].n, 1);
});

test('recordVisit never throws — hostile context, broken table — and audits the failure at most once per ten minutes', async () => {
  const env = await makeEnvWithSchema();
  for (const v of HOSTILE) {
    assert.equal(await F.recordVisit(v, v), undefined, show(v));
    assert.equal(await F.recordVisit(visitRc(env, { path: v, method: v, ip: v, edge: v, fp: v, device: v, user: v, gate: v }), v), undefined, show(v));
  }
  const before = env.DB.q('SELECT COUNT(*) AS n FROM audit_log')[0].n;
  env.DB.failOn = /INSERT INTO visits/;
  for (let i = 0; i < 20; i++) assert.equal(await F.recordVisit(visitRc(env), { decision: 'none' }), undefined);
  env.DB.failOn = null;
  const audits = env.DB.q('SELECT * FROM audit_log WHERE seq > ?', before);
  assert.equal(audits.length, 1);
  assert.equal(audits[0].severity, 'critical');
  assert.match(audits[0].error, /injected failure/);
});

await run();
