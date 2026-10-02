// Edge and browser signals, risk, fingerprints and the visit log
// (CONTRACTS §7.8, §10.1, B §6, D14).
//
// A fingerprint informs; the device cookie identifies. Every browser signal
// is attacker-controlled — a careful attacker presents a clean browser and
// scores zero — so the edge signals (network, TLS, bot score), which are much
// harder to fake, carry the heavier weights. Risk raises the cost of lazy
// automation and explains anomalies; it is not authentication.
//
// Risk weights (score = min(100, sum); each flag fires once, with a reason):
//   edge    automation tool / headless UA 60 · Tor 50 · bot score < 30 40 ·
//           datacenter network 35 · no user agent 30 · client hints that
//           contradict the UA 30 · TLS older than 1.2 25 · no Accept-Language
//           15 · HTTP/1.x from a modern browser 15
//   client  automation tells (webdriver, cdc, selenium, phantom) 50 · zero
//           outer window 20 · software WebGL renderer 20 · 0×0 screen 20 ·
//           time zone inconsistent with the address 15 · empty
//           navigator.languages 15 · desktop Chrome with no plugins 10 ·
//           ≥ 5 probes blocked 10 · touch-less phone 10
//
// The fingerprints table is keyed by a hash of CLIENT-CHOSEN input, so it is
// trimmed by last_seen and by count on every write, never by id (B trap 6).

import { iso, now, toInt, str, canonicalJson, cookie, clientIpRaw, utf8, MINUTE, DAY } from './util.js';
import { sha256Hex, signToken, verifyToken } from './crypto.js';
import { normalizeIp } from './ip.js';
import { parseUa } from './devices.js';
import { auditError } from './audit.js';

export const FP_COOKIE = '__Host-fp';
export const FP_TTL_MS = DAY;
export const CLIENT_MAX_BYTES = 16 * 1024;
const FP_CAP = 20000;
const FP_MAX_AGE_MS = 90 * DAY;
const VISIT_CAP = 50000;
const VISIT_MAX_AGE_MS = 30 * DAY;
const MAX_STR = 256;
const MAX_ARR = 64;
const HEX64 = /^[0-9a-f]{64}$/;
const COUNTRY_RE = /^[A-Z][A-Z0-9]$/;

function finite(n) {
  return typeof n === 'number' && Number.isFinite(n);
}

function nowOf(rc) {
  return finite(rc?.nowMs) ? rc.nowMs : now(rc?.env);
}

// Tests may LOWER a retention cap with env.__retention (a function, so a
// wrangler string var can never set it); nothing can raise one.
function capOf(env, key, def) {
  const f = env && env.__retention;
  if (typeof f !== 'function') return def;
  const n = toInt(f(key), 1, def);
  return Number.isFinite(n) ? n : def;
}

function safe(fn, fallback = null) {
  try {
    const v = fn();
    return v === undefined ? fallback : v;
  } catch {
    return fallback;
  }
}

// ---------------------------------------------------------------- edge

const HEADER_NAME = /^[a-z0-9-]{1,64}$/;

// Free on every request. Never throws: `request.cf` is whatever the platform
// (or a test) put there, and a getter that throws reads as absent.
export function edgeSignals(request, cf) {
  const c = cf && typeof cf === 'object' ? cf : {};
  const headers = safe(() => (request && request.headers && typeof request.headers.get === 'function' ? request.headers : null));
  const h = (name, max = MAX_STR) => safe(() => (headers ? str(headers.get(name), max) : ''), '');
  const bm = safe(() => (c.botManagement && typeof c.botManagement === 'object' ? c.botManagement : {}), {});
  const country = safe(() => (typeof c.country === 'string' ? c.country.trim().toUpperCase() : ''), '');
  const asn = safe(() => toInt(c.asn, 1, 4294967295), NaN);
  const bot = safe(() => toInt(bm.score, 0, 100), NaN);
  const text = (o, k, max) => safe(() => str(o[k], max), '') || null;
  return {
    ip: safe(() => (headers ? normalizeIp(clientIpRaw(request)) : null)),
    country: COUNTRY_RE.test(country) ? country : null,
    asn: Number.isFinite(asn) ? asn : null,
    as_org: text(c, 'asOrganization', 128),
    colo: text(c, 'colo', 16),
    city: text(c, 'city', 64),
    timezone: text(c, 'timezone', 64),
    tls_version: text(c, 'tlsVersion', 16),
    tls_cipher: text(c, 'tlsCipher', 64),
    http_protocol: text(c, 'httpProtocol', 16),
    bot_score: Number.isFinite(bot) ? bot : null,
    ja3: text(bm, 'ja3Hash', 64),
    ja4: text(bm, 'ja4', 64),
    ua: h('user-agent', 512),
    accept_language: h('accept-language'),
    sec_ch_ua: h('sec-ch-ua'),
    sec_ch_ua_mobile: h('sec-ch-ua-mobile', 8),
    sec_ch_ua_platform: h('sec-ch-ua-platform', 64),
    sec_ch_ua_model: h('sec-ch-ua-model', 64),
    sec_fetch_site: h('sec-fetch-site', 32),
    sec_fetch_mode: h('sec-fetch-mode', 32),
    sec_fetch_dest: h('sec-fetch-dest', 32),
    header_names: safe(() => (headers ? [...headers.keys()].filter((k) => HEADER_NAME.test(k)).sort().slice(0, MAX_ARR) : []), []),
  };
}

function edgeOf(rc) {
  if (rc?.edge && typeof rc.edge === 'object') return rc.edge;
  return rc?.request ? edgeSignals(rc.request, rc.cf) : {};
}

// ---------------------------------------------------------------- client

// Combinators: each returns the cleaned value or undefined (= drop the key).
const S = (v) => (typeof v === 'string' ? v.slice(0, MAX_STR) : undefined);
const N = (lo, hi) => (v) => (typeof v === 'number' && Number.isFinite(v) && v >= lo && v <= hi ? v : undefined);
const B = (v) => (typeof v === 'boolean' ? v : undefined);
const nullable = (f) => (v) => (v === null ? null : f(v));
const TOKEN = (v) => (typeof v === 'string' && /^[A-Za-z0-9_.:-]{1,64}$/.test(v) ? v : undefined);
const FEATURE_KEY = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;

function isPlain(v) {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

const list = (item) => (v) => {
  if (!Array.isArray(v)) return undefined;
  const out = [];
  for (const x of v) {
    if (out.length >= MAX_ARR) break;
    const y = item(x);
    if (y !== undefined) out.push(y);
  }
  return out;
};

const obj = (shape) => (v) => {
  if (!isPlain(v)) return undefined;
  const out = {};
  for (const k of Object.keys(shape)) {
    if (!Object.hasOwn(v, k)) continue;
    const y = shape[k](v[k]);
    if (y !== undefined) out[k] = y;
  }
  return out;
};

const boolMap = (v) => {
  if (!isPlain(v)) return undefined;
  const out = {};
  let n = 0;
  for (const k of Object.keys(v)) {
    if (n >= MAX_ARR) break;
    if (FEATURE_KEY.test(k) && typeof v[k] === 'boolean') {
      out[k] = v[k];
      n++;
    }
  }
  return out;
};

const DIM = N(0, 100000);
const STR_FIELDS = (keys) => Object.fromEntries(keys.map((k) => [k, S]));

// Exactly CONTRACTS §10.1; anything else is dropped.
const CLIENT_SHAPE = obj({
  v: N(0, 1000),
  ua: S,
  platform: S,
  vendor: S,
  uaData: nullable(obj({ brands: list(obj({ brand: S, version: S })), mobile: B, platform: S })),
  language: S,
  languages: list(S),
  tz: S,
  tzOffset: N(-1440, 1440),
  intl: obj(STR_FIELDS(['locale', 'calendar', 'numberingSystem', 'hourCycle'])),
  screen: obj({ w: DIM, h: DIM, aw: DIM, ah: DIM, cd: N(0, 128), dpr: N(0, 100) }),
  window: obj({ iw: DIM, ih: DIM, ow: DIM, oh: DIM }),
  hw: obj({ cores: N(0, 4096), memory: N(0, 4096), touch: N(0, 1000) }),
  media: obj({ dark: B, reducedMotion: B, contrast: S, pointerCoarse: B, hover: B, gamut: S, forcedColors: B }),
  canvas: nullable(S),
  webgl: nullable(obj(STR_FIELDS(['vendor', 'renderer', 'hash']))),
  audio: nullable(S),
  fonts: list(S),
  storage: obj({ cookies: B, local: B, session: B, idb: B, quotaMb: nullable(N(0, 1e9)) }),
  net: nullable(obj({ type: S, downlink: N(0, 1e6), rtt: N(0, 1e6), saveData: B })),
  perms: nullable(obj(STR_FIELDS(['notifications', 'geolocation', 'camera', 'microphone']))),
  webrtc: nullable(obj({ candidates: N(0, 1000), mdns: B, ipv6: B })),
  math: S,
  features: boolMap,
  automation: list(TOKEN),
  blocked: list(TOKEN),
  elapsedMs: N(0, 600000),
});

// → the §10.1 object with types checked, strings ≤ 256, arrays ≤ 64 and
// unknown keys dropped; null for anything that is not a plain object or
// serialises to more than 16 KiB. Idempotent.
export function sanitizeClientSignals(input) {
  try {
    if (!isPlain(input)) return null;
    const json = JSON.stringify(input);
    if (typeof json !== 'string' || utf8(json).length > CLIENT_MAX_BYTES) return null;
    return CLIENT_SHAPE(input) ?? null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------- networks

// Curated hosting and cloud ASNs. A visitor from one is not a person at home
// or in an office; a VPN or a script is the likely story. Not every hosting
// ASN on earth — the ones scrapers and residential-looking VPNs most use.
const DATACENTER_ASNS = new Map([
  [16509, 'Amazon AWS'], [14618, 'Amazon AWS'], [8987, 'Amazon AWS'],
  [15169, 'Google'], [396982, 'Google Cloud'], [19527, 'Google'],
  [8075, 'Microsoft Azure'], [8068, 'Microsoft'],
  [14061, 'DigitalOcean'], [63949, 'Akamai Linode'], [20473, 'Vultr'],
  [16276, 'OVHcloud'], [24940, 'Hetzner'], [213230, 'Hetzner'],
  [12876, 'Scaleway'], [51167, 'Contabo'], [31898, 'Oracle Cloud'],
  [45102, 'Alibaba Cloud'], [37963, 'Alibaba Cloud'],
  [132203, 'Tencent Cloud'], [45090, 'Tencent Cloud'],
  [60781, 'Leaseweb'], [28753, 'Leaseweb'], [16265, 'Leaseweb'],
  [9009, 'M247'], [36351, 'IBM Cloud'], [19994, 'Rackspace'],
  [26496, 'GoDaddy'], [47583, 'Hostinger'], [36352, 'ColoCrossing'],
  [8100, 'QuadraNet'], [40676, 'Psychz Networks'], [53667, 'FranTech'],
  [60068, 'Datacamp (CDN77)'], [136907, 'Huawei Cloud'], [8560, 'IONOS'],
  [197540, 'netcup'], [202053, 'UpCloud'], [54290, 'Hostwinds'],
  [36007, 'Kamatera'], [21859, 'Zenlayer'], [199524, 'G-Core Labs'],
  [46606, 'Unified Layer'], [26347, 'DreamHost'],
]);

export function isDatacenterAsn(asn) {
  const n = toInt(asn, 1, 4294967295);
  return Number.isFinite(n) && DATACENTER_ASNS.has(n);
}

// ---------------------------------------------------------------- tells

const HEADLESS_UA = [/HeadlessChrome/i, /PhantomJS/i];
const TOOL_UA = [
  [/\bcurl\//i, 'curl'],
  [/\bWget\//i, 'Wget'],
  [/python-requests/i, 'python-requests'],
  [/Python-urllib/i, 'Python urllib'],
  [/aiohttp/i, 'aiohttp'],
  [/\bhttpx\//i, 'httpx'],
  [/Go-http-client/i, 'Go-http-client'],
  [/node-fetch/i, 'node-fetch'],
  [/\baxios\//i, 'axios'],
  [/(?:^|[\s(;])Java\/\d/, 'Java'],
  [/libwww-perl/i, 'libwww-perl'],
  [/Scrapy/i, 'Scrapy'],
  [/okhttp/i, 'okhttp'],
  [/Apache-HttpClient/i, 'Apache HttpClient'],
  [/PostmanRuntime/i, 'Postman'],
];

// The tells strong enough to refuse on when block_automation is on. Weak
// ones (no plugins, software WebGL — a VDI desktop has those) only add risk.
const CLIENT_STRONG = {
  webdriver: 'navigator.webdriver is set',
  'headless-ua': 'the browser calls itself headless',
  cdc: 'ChromeDriver markers are on the page',
  selenium: 'Selenium markers are on the page',
  phantom: 'PhantomJS markers are on the page',
};

function toolOf(ua) {
  for (const [re, name] of TOOL_UA) if (re.test(ua)) return name;
  return null;
}

function edgeText(e, k, max = 512) {
  return typeof e[k] === 'string' ? e[k].slice(0, max) : '';
}

function edgeObj(edge) {
  return edge && typeof edge === 'object' ? edge : {};
}

// Named tells: 'headless-ua' and 'automation-ua' from the edge, plus the
// strong ones the browser reported.
export function automationTells(edge, client) {
  try {
    const e = edgeObj(edge);
    const ua = edgeText(e, 'ua');
    const out = new Set();
    if (HEADLESS_UA.some((re) => re.test(ua))) out.add('headless-ua');
    if (toolOf(ua)) out.add('automation-ua');
    const c = client ? sanitizeClientSignals(client) : null;
    for (const t of c?.automation || []) if (Object.hasOwn(CLIENT_STRONG, t)) out.add(t);
    return [...out];
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------- time zones

const REF_INSTANTS = [Date.UTC(2026, 0, 15, 12), Date.UTC(2026, 6, 15, 12)];
const offsetCache = new Map();

// [January offset, July offset] in minutes, or null for a zone Intl refuses.
function zoneOffsets(tz) {
  if (typeof tz !== 'string' || !tz || tz.length > 64) return null;
  if (offsetCache.has(tz)) return offsetCache.get(tz);
  let out = null;
  try {
    const f = new Intl.DateTimeFormat('en-US', { timeZone: tz, timeZoneName: 'longOffset' });
    out = REF_INSTANTS.map((ms) => {
      const name = f.formatToParts(ms).find((p) => p.type === 'timeZoneName')?.value || '';
      const m = /^GMT(?:([+-])(\d{2}):(\d{2}))?$/.exec(name);
      if (!m) throw new Error('unreadable offset');
      return m[1] ? (m[1] === '-' ? -1 : 1) * (toInt(m[2]) * 60 + toInt(m[3])) : 0;
    });
  } catch {
    out = null;
  }
  if (offsetCache.size > 512) offsetCache.clear();
  offsetCache.set(tz, out);
  return out;
}

// Inconsistent only when the two zones disagree in BOTH seasons, so two
// zones that merely follow different daylight-saving rules never flag.
function tzFlag(clientTz, edgeTz) {
  if (typeof clientTz !== 'string' || !clientTz || typeof edgeTz !== 'string' || !edgeTz || clientTz === edgeTz) return null;
  const e = zoneOffsets(edgeTz);
  if (!e) return null;
  const c = zoneOffsets(clientTz);
  if (!c) return 'The browser reported a time zone that does not exist.';
  return c[0] !== e[0] && c[1] !== e[1] ? `The browser’s time zone (${clientTz}) disagrees with the network’s (${edgeTz}).` : null;
}

// ---------------------------------------------------------------- risk

function brandsOf(header) {
  const out = [];
  const re = /"([^"]{1,64})"\s*;\s*v\s*=\s*"[^"]*"/g;
  let m;
  while ((m = re.exec(header)) && out.length < 16) out.push(m[1]);
  return out;
}

const CHROMIUM = new Set(['Chrome', 'Edge', 'Opera', 'Samsung Internet']);

function hintContradiction(e, parsed) {
  const ch = edgeText(e, 'sec_ch_ua');
  const plat = edgeText(e, 'sec_ch_ua_platform').replace(/"/g, '').trim();
  if (ch && (parsed.browser === 'Firefox' || parsed.browser === 'Safari')) {
    return `The browser sent Chromium client hints but its user agent says ${parsed.browser}.`;
  }
  if (ch && CHROMIUM.has(parsed.browser)) {
    const brands = brandsOf(ch);
    if (brands.length && !brands.includes('Chromium')) return 'The client hints do not name Chromium, but the user agent claims a Chromium browser.';
  }
  if (plat && parsed.os) {
    const hinted = parseUa('', { platform: plat }).os;
    const same = hinted === parsed.os || (hinted === 'macOS' && parsed.os === 'iPadOS');
    if (hinted && !same) return `The client hints say ${hinted} but the user agent says ${parsed.os}.`;
  }
  return null;
}

// → { score: 0–100, flags: [{ key, weight, reason }] }. Every flag explains
// itself in a sentence an administrator can act on (B §6).
export function scoreRisk(edge, client) {
  const flags = [];
  const add = (key, weight, reason) => {
    if (!flags.some((f) => f.key === key)) flags.push({ key, weight, reason });
  };
  try {
    const e = edgeObj(edge);
    const ua = edgeText(e, 'ua');
    const parsed = parseUa(ua, null);

    if (!ua) add('no_ua', 30, 'The browser sent no user agent.');
    if (HEADLESS_UA.some((re) => re.test(ua))) add('automation_ua', 60, 'The user agent is a headless browser, which is driven by a script.');
    const tool = toolOf(ua);
    if (tool) add('automation_ua', 60, `The user agent is ${tool}, an automation tool rather than a browser.`);
    if (!edgeText(e, 'accept_language')) add('no_accept_language', 15, 'No Accept-Language header — every real browser sends one.');
    const proto = edgeText(e, 'http_protocol');
    if (/^HTTP\/1(?:\.\d)?$/i.test(proto) && parsed.browser && !tool) {
      add('old_http', 15, `The user agent claims ${parsed.browser}, but it connected over ${proto}, which modern browsers rarely use.`);
    }
    const tls = edgeText(e, 'tls_version');
    if (/^(?:SSLv\d|TLSv1(?:\.[01])?)$/i.test(tls)) add('old_tls', 25, `It connected with ${tls}, which no current browser uses.`);
    const bot = toInt(e.bot_score, 0, 100);
    if (Number.isFinite(bot) && bot < 30) add('bot_score', 40, `Cloudflare’s bot score is ${bot}; below 30 suggests automation.`);
    if (isDatacenterAsn(e.asn)) {
      const org = edgeText(e, 'as_org', 128) || DATACENTER_ASNS.get(toInt(e.asn));
      add('datacenter', 35, `The address belongs to a hosting provider (AS${toInt(e.asn)} ${org}), not a home or office network.`);
    }
    if (e.country === 'T1') add('tor', 50, 'The connection came through the Tor network.');
    const hint = hintContradiction(e, parsed);
    if (hint) add('ch_mismatch', 30, hint);

    const c = client ? sanitizeClientSignals(client) : null;
    if (c) {
      const tells = c.automation || [];
      const strong = tells.filter((t) => Object.hasOwn(CLIENT_STRONG, t));
      if (strong.length) add('client_automation', 50, `The browser shows signs of automation: ${strong.map((t) => CLIENT_STRONG[t]).join('; ')}.`);
      if (tells.includes('no-plugins')) add('no_plugins', 10, 'Desktop Chrome reported no plugins, which is typical of headless Chrome.');
      if ((c.window && c.window.ow === 0 && c.window.oh === 0) || tells.includes('zero-outer')) {
        add('zero_outer', 20, 'The browser window has no outer size, which happens when nothing is drawn on a screen.');
      }
      const renderer = c.webgl?.renderer || '';
      const sw = /SwiftShader|llvmpipe|softpipe|Software Rasterizer/i.exec(renderer)?.[0] || (tells.includes('swiftshader') ? 'SwiftShader' : tells.includes('llvmpipe') ? 'llvmpipe' : null);
      if (sw) add('software_gl', 20, `WebGL is rendered in software (${sw}), as in headless browsers and some virtual machines.`);
      if (c.screen && c.screen.w === 0 && c.screen.h === 0) add('zero_screen', 20, 'The browser reported a 0×0 screen.');
      if (Array.isArray(c.languages) && c.languages.length === 0) add('no_languages', 15, 'The browser lists no languages, which is common in headless browsers.');
      if ((c.blocked || []).length >= 5) add('blocked_probes', 10, `${c.blocked.length} browser checks were blocked or timed out.`);
      const tz = tzFlag(c.tz, e.timezone);
      if (tz) add('tz_mismatch', 15, tz);
      const p = parseUa(c.ua || ua, { touch: c.hw?.touch });
      if ((p.os === 'iOS' || p.os === 'Android') && c.hw && c.hw.touch === 0) {
        add('touch_mismatch', 10, `The user agent says ${p.os}, but the device reports no touch support.`);
      }
    }
  } catch {
    add('unreadable', 30, 'The request’s signals could not be read.');
  }
  return { score: Math.min(100, flags.reduce((s, f) => s + f.weight, 0)), flags };
}

// ---------------------------------------------------------------- hashes

function pick(o, keys) {
  const out = {};
  for (const k of keys) if (o[k] !== undefined) out[k] = o[k];
  return out;
}

// This exact configuration. Network location (address, country, colo) and
// per-request noise (header order, fetch metadata, timings, connection
// speed, window size, storage quota) are left out so one browser does not
// mint a new row with every request. ASYNC (WebCrypto).
export async function fingerprintHash(edge, client) {
  const e = edgeObj(edge);
  const c = client ? sanitizeClientSignals(client) : null;
  let cPart = null;
  if (c) {
    cPart = { ...c, storage: c.storage ? { ...c.storage, quotaMb: undefined } : undefined };
    for (const k of ['elapsedMs', 'blocked', 'net', 'window']) delete cPart[k];
  }
  const ePart = pick(e, ['ua', 'accept_language', 'sec_ch_ua', 'sec_ch_ua_mobile', 'sec_ch_ua_platform', 'tls_version', 'tls_cipher', 'http_protocol', 'ja3', 'ja4']);
  return sha256Hex('fp1\n' + canonicalJson({ e: ePart, c: cPart }));
}

// The stable subset: browser FAMILY (no version), OS, languages, zone,
// locale, screen, hardware, GPU, fonts — so a browser update is not a new
// stranger (B §6). ASYNC.
export async function visitorId(edge, client) {
  const e = edgeObj(edge);
  const c = client ? sanitizeClientSignals(client) : null;
  const p = parseUa(c?.ua || edgeText(e, 'ua'), { platform: c?.uaData?.platform || edgeText(e, 'sec_ch_ua_platform'), touch: c?.hw?.touch });
  const stable = {
    browser: p.browser,
    os: p.os,
    accept_language: edgeText(e, 'accept_language') || null,
    platform: c?.platform ?? null,
    languages: c?.languages ?? null,
    tz: c?.tz ?? null,
    intl: c?.intl ?? null,
    screen: c?.screen ? pick(c.screen, ['w', 'h', 'cd', 'dpr']) : null,
    hw: c?.hw ?? null,
    gpu: c?.webgl ? pick(c.webgl, ['vendor', 'renderer']) : null,
    fonts: c?.fonts ?? null,
  };
  return sha256Hex('visitor1\n' + canonicalJson(stable));
}

// ---------------------------------------------------------------- cookie

const FP_PAYLOAD = /^([0-9a-f]{64})\.([0-9a-f]{64}|-)\.(\d{1,3})\.([01])\.(\d{1,15})$/;

// Signed, so a client cannot claim a lower score than it was given (SPEC
// §9.3). `extra` = { visitorId, automation } — the automation bit lets the
// gate refuse a webdriver browser without a database read.
export async function fpCookie(env, hash, risk, nowMs, extra = {}) {
  if (typeof hash !== 'string' || !HEX64.test(hash)) throw new Error('fingerprint: fpCookie needs a fingerprint hash');
  const r = toInt(risk, 0, 100);
  const t = finite(nowMs) ? nowMs : now(env);
  const vid = typeof extra?.visitorId === 'string' && HEX64.test(extra.visitorId) ? extra.visitorId : '-';
  // An unreadable score is stored as the worst one.
  const payload = `${hash}.${vid}.${Number.isFinite(r) ? r : 100}.${extra?.automation === true ? 1 : 0}.${t + FP_TTL_MS}`;
  return cookie(FP_COOKIE, await signToken(env, 'fp', payload), { maxAge: FP_TTL_MS / 1000 });
}

// → { hash, risk, visitor_id, automation } | null — forged, malformed or
// expired all read as "no fingerprint".
export async function readFpCookie(rc) {
  try {
    const raw = rc?.cookies?.[FP_COOKIE];
    if (typeof raw !== 'string' || !raw) return null;
    const payload = await verifyToken(rc.env, 'fp', raw);
    const m = payload === null ? null : FP_PAYLOAD.exec(payload);
    if (!m) return null;
    const t = nowOf(rc);
    const exp = toInt(m[5], 0);
    const risk = toInt(m[3], 0, 100);
    if (!Number.isFinite(risk) || !(exp > t) || exp > t + FP_TTL_MS + MINUTE) return null;
    return { hash: m[1], risk, visitor_id: m[2] === '-' ? null : m[2], automation: m[4] === '1' };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------- storage

// POST /api/fp. → { hash, visitor_id, risk (number), flags, automation
// (tells), setCookie } — append setCookie to the response.
export async function recordFingerprint(rc, opts = {}) {
  const env = rc.env;
  const db = env.DB;
  const t = nowOf(rc);
  const client = sanitizeClientSignals(opts && typeof opts === 'object' ? opts.client : null);
  const edge = edgeOf(rc);
  const risk = scoreRisk(edge, client);
  const tells = automationTells(edge, client);
  const hash = await fingerprintHash(edge, client);
  const vid = await visitorId(edge, client);
  const cap = capOf(env, 'fingerprints', FP_CAP);
  const uid = toInt(rc.user?.id, 1);
  await db.batch([
    db
      .prepare(
        `INSERT INTO fingerprints (hash, visitor_id, first_seen, last_seen, hits, risk, flags, edge, client, last_ip, last_user_id)
         VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(hash) DO UPDATE SET last_seen = excluded.last_seen, hits = hits + 1, risk = excluded.risk,
           flags = excluded.flags, edge = excluded.edge, last_ip = excluded.last_ip,
           last_user_id = COALESCE(excluded.last_user_id, last_user_id)`,
      )
      .bind(
        hash,
        vid,
        iso(t),
        iso(t),
        risk.score,
        JSON.stringify(risk.flags),
        JSON.stringify(edge),
        client ? JSON.stringify(client) : null,
        typeof rc.ip === 'string' ? rc.ip.slice(0, 64) : null,
        Number.isFinite(uid) ? uid : null,
      ),
    // B trap 6: by timestamp and by count, and the row just written stays.
    db.prepare('DELETE FROM fingerprints WHERE last_seen < ?').bind(iso(t - FP_MAX_AGE_MS)),
    db
      .prepare('DELETE FROM fingerprints WHERE hash IN (SELECT hash FROM fingerprints WHERE hash != ? ORDER BY last_seen DESC, hash LIMIT -1 OFFSET ?)')
      .bind(hash, cap - 1),
  ]);
  return {
    hash,
    visitor_id: vid,
    risk: risk.score,
    flags: risk.flags,
    automation: tells,
    setCookie: await fpCookie(env, hash, risk.score, t, { visitorId: vid, automation: tells.length > 0 }),
  };
}

const VISIT_AUDIT_EVERY_MS = 10 * MINUTE;
let lastVisitAuditMs = -Infinity;

function hexOrNull(v) {
  return typeof v === 'string' && HEX64.test(v) ? v : null;
}

// Every refusal, every navigation, every API write (CONTRACTS §8.1 step 4),
// run through waitUntil. NEVER throws. Trimmed by age and by count in the
// same batch; ids are server-assigned and increasing, so the count trim is
// one indexed lookup however hard someone hammers the gate.
export async function recordVisit(rc, opts) {
  if (!rc || typeof rc !== 'object' || !rc.env || !rc.env.DB) return;
  let t = 0;
  try {
    t = nowOf(rc);
    const env = rc.env;
    const db = env.DB;
    const o = opts && typeof opts === 'object' ? opts : {};
    const e = edgeObj(rc.edge);
    const country = typeof e.country === 'string' && COUNTRY_RE.test(e.country) ? e.country : null;
    const asn = toInt(e.asn, 1, 4294967295);
    const uid = toInt(rc.user?.id, 1);
    const risk = toInt(rc.gate?.risk?.score ?? rc.fp?.risk, 0, 100);
    const deviceId = typeof rc.device?.id === 'string' && rc.device.id.length <= 128 ? rc.device.id : null;
    const cap = capOf(env, 'visits', VISIT_CAP);
    await db.batch([
      db
        .prepare(
          `INSERT INTO visits (at, ip, country, asn, method, path, decision, reason, fp_hash, visitor_id, device_id, user_id, risk, ua)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          iso(t),
          typeof rc.ip === 'string' ? rc.ip.slice(0, 64) : null,
          country,
          Number.isFinite(asn) ? asn : null,
          str(rc.method, 10).toUpperCase() || null,
          str(rc.path, 512) || null,
          str(o.decision ?? rc.gate?.allowed, 16) || null,
          str(o.reason ?? rc.gate?.reason, 64) || null,
          hexOrNull(rc.fp?.hash),
          hexOrNull(rc.fp?.visitor_id),
          deviceId,
          Number.isFinite(uid) ? uid : null,
          Number.isFinite(risk) ? risk : null,
          str(rc.ua ?? e.ua, 512) || null,
        ),
      db.prepare('DELETE FROM visits WHERE at < ?').bind(iso(t - VISIT_MAX_AGE_MS)),
      db.prepare('DELETE FROM visits WHERE id <= (SELECT MAX(id) FROM visits) - ?').bind(cap),
    ]);
  } catch (err) {
    // The real error is recorded (B trap 2), but at most once per isolate
    // per ten minutes: the audit log is never trimmed, and a broken visits
    // table must not turn every refused request into a permanent row.
    try {
      console.error('recordVisit failed:', err && err.message);
      if (t - lastVisitAuditMs >= VISIT_AUDIT_EVERY_MS) {
        lastVisitAuditMs = t;
        await auditError(rc, 'error', err, { detail: 'Could not record a visit.' });
      }
    } catch {
      /* never throws */
    }
  }
}
