// Device identity and inventory (CONTRACTS §7.8, A §5, B §6).
//
// A device is a random id in a signed cookie, recorded server-side. It is
// inventory and an approval handle, never a fingerprint (D14): the HMAC is
// verified before the database is touched, so a forged or mangled cookie costs
// nothing and can never name someone else's device.
//
// Statuses: 'pending' · 'approved' · 'blocked'. Anything else stored reads as
// 'blocked' (CONTRACTS §0.2), the same rule users.knownDeviceFor applies.

import { cookie, iso, now, toInt, str, strStrict, parseIsoStrict, randomToken, DAY, HOUR } from './util.js';
import { signToken, verifyToken, sha256 } from './crypto.js';
import { ValidationError, GuardError, notFound } from './errors.js';

export const DEVICE_COOKIE = '__Host-dev';
export const DEVICE_STATUSES = Object.freeze(['pending', 'approved', 'blocked']);
export const CODE_ALPHABET = '23456789ABCDEFGHJKMNPQRSTUVWXYZ'; // no 0 1 I O L

const COOKIE_MAX_AGE_SEC = 400 * 24 * 3600; // the browser ceiling for a cookie
const ID_RE = /^[A-Za-z0-9_-]{16,128}$/; // what we mint and sign
const ANY_ID_RE = /^[\x21-\x7e]{1,128}$/; // what a lookup will consider
const PENDING_CAP = 2000;
const PENDING_STALE_MS = 30 * DAY;
const CODE_WINDOW_MS = 7 * DAY;
const TOUCH_MS = HOUR;
const LABEL_MAX = 100;

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

function actorId(rc) {
  const n = toInt(rc?.user?.id, 1);
  return Number.isFinite(n) ? n : null;
}

function asDeviceId(v) {
  return typeof v === 'string' && ANY_ID_RE.test(v) ? v : null;
}

// 'none' | 'pending' | 'approved' | 'blocked'. An unrecognised status is
// 'blocked': a corrupt row must never read as trusted or as "nothing here".
export function deviceState(row) {
  if (!row || typeof row !== 'object') return 'none';
  return row.status === 'approved' || row.status === 'pending' ? row.status : 'blocked';
}

// ---------------------------------------------------------------- user agent

// Two characters at least: Chrome's reduced Android UA puts a placeholder
// 'K' where the model was.
const MODEL_RE = /^[A-Za-z0-9][A-Za-z0-9 _.+-]{1,39}$/;
const GENERIC_MODELS = new Set(['mobile', 'tablet', 'desktop', 'android', 'unknown', 'wv', 'linux']);

const BROWSERS = [
  // Chromium derivatives first: their user agents also say Chrome/.
  ['Edge', /\b(?:Edg|Edge|EdgA|EdgiOS)\/(\d+)/],
  ['Opera', /\b(?:OPR|OPiOS|OPT)\/(\d+)|\bOpera\b/],
  ['Samsung Internet', /\bSamsungBrowser\/(\d+)/],
  ['Firefox', /\b(?:Firefox|FxiOS)\/(\d+)/],
  ['Chrome', /\b(?:Chrome|CriOS|HeadlessChrome)\/(\d+)/],
  ['Safari', /\bVersion\/(\d+)[\d.]*(?: Mobile\/\w+)? Safari\//],
];

// A Map, not an object literal: a hint of "constructor" must not find
// Object.prototype.constructor.
const HINT_PLATFORMS = new Map([
  ['windows', 'Windows'],
  ['macos', 'macOS'],
  ['mac os x', 'macOS'],
  ['android', 'Android'],
  ['chrome os', 'ChromeOS'],
  ['chromeos', 'ChromeOS'],
  ['chromium os', 'ChromeOS'],
  ['linux', 'Linux'],
  ['ios', 'iOS'],
]);

// Header form '"macOS"' and the JS form 'macOS' both arrive here.
function unquote(v) {
  if (typeof v !== 'string') return '';
  const s = v.trim().slice(0, 64);
  return s.length >= 2 && s.startsWith('"') && s.endsWith('"') ? s.slice(1, -1).trim() : s;
}

function cleanModel(v) {
  const s = unquote(v);
  return MODEL_RE.test(s) && !GENERIC_MODELS.has(s.toLowerCase()) ? s : null;
}

function hintMobile(v) {
  return v === true || v === '?1';
}

// The user agent decides; client hints only refine (A §14.7). Hints are
// Chromium-only, so branching on them files every Firefox and Safari visitor
// wrongly, and a missing Sec-CH-UA-Model must never surface as the model
// "Mobile". `hints`: { platform, mobile, model, touch } in header or JS form.
export function parseUa(ua, hints) {
  const u = str(ua, 512);
  const h = hints && typeof hints === 'object' ? hints : {};
  let browser = null;
  let version = null;
  for (const [name, re] of BROWSERS) {
    const m = re.exec(u);
    if (m) {
      browser = name;
      const v = toInt(m[1], 0, 9999);
      version = Number.isFinite(v) ? v : null;
      break;
    }
  }
  const touch = toInt(h.touch, 0, 1000);
  let os = null;
  if (/\biPad\b/.test(u)) os = 'iPadOS';
  else if (/\b(?:iPhone|iPod)\b/.test(u)) os = 'iOS';
  else if (/\bAndroid\b/.test(u)) os = 'Android';
  else if (/\bCrOS\b/.test(u)) os = 'ChromeOS';
  else if (/\bWindows\b|\bWin64\b|\bWin32\b/.test(u)) os = 'Windows';
  // iPadOS asks for desktop sites with a Mac user agent; only touch tells.
  else if (/\bMacintosh\b|\bMac OS X\b/.test(u)) os = touch > 1 ? 'iPadOS' : 'macOS';
  else if (/\bLinux\b|\bX11\b/.test(u)) os = 'Linux';
  if (!os) os = HINT_PLATFORMS.get(unquote(h.platform).toLowerCase()) || null;

  let model = null;
  if (os === 'Android') {
    const m = /\bAndroid [\d.]+; ([^;)]+?)(?: Build\/[^;)]*)?[;)]/.exec(u);
    model = m ? cleanModel(m[1]) : null;
  }
  if (!model && (os === 'Android' || os === null)) model = cleanModel(h.model);

  const mobile = os === 'iOS' || (os === 'Android' && /\bMobile\b/.test(u)) || (os === null && hintMobile(h.mobile));
  return { browser, version, os, model, mobile };
}

export function deviceLabelFromUa(ua, hints) {
  try {
    const p = parseUa(ua, hints);
    if (!p.browser && !p.os) return 'Unknown device';
    const base = p.os ? `${p.browser || 'Browser'} on ${p.os}` : p.browser;
    return p.model ? `${base} (${p.model})` : base;
  } catch {
    return 'Unknown device';
  }
}

function hintsOf(rc) {
  const e = rc?.edge && typeof rc.edge === 'object' ? rc.edge : {};
  return { platform: e.sec_ch_ua_platform, mobile: e.sec_ch_ua_mobile, model: e.sec_ch_ua_model };
}

function uaOf(rc) {
  if (typeof rc?.ua === 'string') return rc.ua;
  if (typeof rc?.edge?.ua === 'string') return rc.edge.ua;
  return '';
}

function ipOf(rc) {
  return typeof rc?.ip === 'string' && rc.ip.length <= 64 ? rc.ip : null;
}

// ---------------------------------------------------------------- cookie

// → { id, row } — row null when the signed id has no row (e.g. a pruned
// pending device; ensureDevice recreates it) — or { id: null, row: null }.
export async function readDevice(rc) {
  const none = { id: null, row: null };
  try {
    const raw = rc?.cookies?.[DEVICE_COOKIE];
    if (typeof raw !== 'string' || !raw) return none;
    // Verified BEFORE any query (A §5, B §6).
    const id = await verifyToken(rc.env, 'device', raw);
    if (id === null || !ID_RE.test(id)) return none;
    const row = await rc.env.DB.prepare('SELECT * FROM devices WHERE id = ?').bind(id).first();
    return { id, row: row || null };
  } catch {
    return none;
  }
}

async function deviceCookie(env, id) {
  return cookie(DEVICE_COOKIE, await signToken(env, 'device', id), { maxAge: COOKIE_MAX_AGE_SEC });
}

function insertPending(db, id, rc, t) {
  const ua = uaOf(rc);
  const p = parseUa(ua, hintsOf(rc));
  return db
    .prepare(
      `INSERT INTO devices (id, status, label, ua, platform, first_ip, last_ip, visitor_id, first_seen, last_seen)
       VALUES (?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING`,
    )
    .bind(id, deviceLabelFromUa(ua, hintsOf(rc)), str(ua, 512) || null, p.os, ipOf(rc), ipOf(rc), visitorOf(rc), iso(t), iso(t));
}

function visitorOf(rc) {
  const v = rc?.fp?.visitor_id;
  return typeof v === 'string' && /^[0-9a-f]{64}$/.test(v) ? v : null;
}

// Pending rows are created by anyone who reaches the pending page, so the
// write that creates one also prunes (A §11, CONTRACTS §11): stale pending
// rows, then everything past the cap — rows nobody ever signed in on go
// first, and the row just written is never the one dropped.
function prunePending(db, env, keepId, t) {
  const cap = capOf(env, 'devices_pending', PENDING_CAP);
  return [
    db.prepare("DELETE FROM devices WHERE status = 'pending' AND last_seen < ? AND id != ?").bind(iso(t - PENDING_STALE_MS), keepId),
    db
      .prepare(
        `DELETE FROM devices WHERE id IN (
           SELECT id FROM devices WHERE status = 'pending'
           ORDER BY (id = ?) DESC, (id IN (SELECT device_id FROM device_users)) DESC, last_seen DESC, id
           LIMIT -1 OFFSET ?)`,
      )
      .bind(keepId, cap),
    db.prepare('DELETE FROM device_users WHERE device_id NOT IN (SELECT id FROM devices)'),
  ];
}

// → { id, row, setCookie|null }. The caller appends setCookie to the
// response; rc.device is updated so later code in the same request (an
// invitation accepting, completeSignIn) sees the device just minted.
export async function ensureDevice(rc) {
  const env = rc.env;
  const db = env.DB;
  const t = nowOf(rc);
  let cur = rc.device && typeof rc.device.id === 'string' && rc.device.row ? rc.device : await readDevice(rc);
  if (cur.id && cur.row) {
    // Keep a device sitting on the pending page findable by its code.
    const seen = parseIsoStrict(cur.row.last_seen);
    if (!(t - seen < TOUCH_MS)) {
      await db.prepare('UPDATE devices SET last_seen = ?, last_ip = COALESCE(?, last_ip) WHERE id = ?').bind(iso(t), ipOf(rc), cur.id).run();
      cur = { id: cur.id, row: { ...cur.row, last_seen: iso(t), last_ip: ipOf(rc) ?? cur.row.last_ip } };
    }
    rc.device = cur;
    return { id: cur.id, row: cur.row, setCookie: null };
  }
  // A signed id whose row was pruned keeps its id (and its cookie).
  const id = cur.id || randomToken(16);
  await db.batch([insertPending(db, id, rc, t), ...prunePending(db, env, id, t)]);
  const row = await db.prepare('SELECT * FROM devices WHERE id = ?').bind(id).first();
  rc.device = { id, row };
  return { id, row, setCookie: cur.id ? null : await deviceCookie(env, id) };
}

// completeSignIn's first step: the device (minted if needed), the ledger of
// who signed in on it, and its last-seen details. A label an administrator
// typed is kept; only an automatic label follows the user agent.
export async function trackDevice(rc, userId) {
  const uid = toInt(userId, 1);
  if (!Number.isFinite(uid)) throw new Error('devices: trackDevice needs a user id');
  const d = await ensureDevice(rc);
  const t = nowOf(rc);
  const db = rc.env.DB;
  const ua = uaOf(rc);
  const hints = hintsOf(rc);
  const autoLabel = d.row && (d.row.label === null || d.row.label === deviceLabelFromUa(d.row.ua, null));
  await db.batch([
    db
      .prepare(
        `INSERT INTO device_users (device_id, user_id, first_seen, last_seen, sign_ins) VALUES (?, ?, ?, ?, 1)
         ON CONFLICT(device_id, user_id) DO UPDATE SET last_seen = excluded.last_seen, sign_ins = sign_ins + 1`,
      )
      .bind(d.id, uid, iso(t), iso(t)),
    db
      .prepare(
        `UPDATE devices SET last_seen = ?, last_ip = COALESCE(?, last_ip), visitor_id = COALESCE(?, visitor_id),
           ua = COALESCE(?, ua), platform = COALESCE(?, platform), label = CASE WHEN ? THEN ? ELSE label END
         WHERE id = ?`,
      )
      .bind(iso(t), ipOf(rc), visitorOf(rc), str(ua, 512) || null, parseUa(ua, hints).os, autoLabel ? 1 : 0, deviceLabelFromUa(ua, hints), d.id),
  ]);
  return { id: d.id, setCookie: d.setCookie };
}

// ---------------------------------------------------------------- codes

// 'K7F3-9QX2': eight characters drawn from SHA-256(id) by rejection sampling
// (no modulo bias) over an alphabet with no 0/O, 1/I/L. ASYNC — WebCrypto
// digests are. Not a secret: it names a device to an administrator, and the
// approve-by-code endpoints are step-up gated and rate-limited.
export async function deviceCode(id) {
  if (!asDeviceId(id)) return null;
  const n = CODE_ALPHABET.length;
  const limit = 256 - (256 % n);
  let out = '';
  let bytes = await sha256(id);
  for (;;) {
    for (const b of bytes) {
      if (b < limit) out += CODE_ALPHABET[b % n];
      if (out.length === 8) return `${out.slice(0, 4)}-${out.slice(4)}`;
    }
    bytes = await sha256(bytes);
  }
}

// Uppercase, spaces and hyphens removed, exactly eight alphabet characters —
// shape-gated so '' or 'abc' can never match anything (A §14.4).
export function normalizeDeviceCode(v) {
  if (typeof v !== 'string' || v.length > 32) return null;
  const s = v.toUpperCase().replace(/[\s-]/g, '');
  if (s.length !== 8) return null;
  for (const c of s) if (!CODE_ALPHABET.includes(c)) return null;
  return `${s.slice(0, 4)}-${s.slice(4)}`;
}

// Pending devices seen in the last 7 days, bounded by the pending cap. An
// ambiguous code (two devices) matches nothing.
export async function findDeviceByCode(env, code) {
  const want = normalizeDeviceCode(code);
  if (!want) return null;
  const t = now(env);
  const { results } = await env.DB.prepare(
    "SELECT * FROM devices WHERE status = 'pending' AND last_seen >= ? ORDER BY last_seen DESC LIMIT ?",
  )
    .bind(iso(t - CODE_WINDOW_MS), PENDING_CAP)
    .all();
  const hits = [];
  for (const row of results || []) if ((await deviceCode(row.id)) === want) hits.push(row);
  return hits.length === 1 ? hits[0] : null;
}

// ---------------------------------------------------------------- admin

async function loadDevice(env, deviceId) {
  const id = asDeviceId(deviceId);
  const row = id ? await env.DB.prepare('SELECT * FROM devices WHERE id = ?').bind(id).first() : null;
  if (!row) throw notFound('No such device.');
  return row;
}

function gatingMayBeOn(rc) {
  return rc?.policy?.device_gating !== false;
}

// Withdrawing trust from the device you are using locks you out of it at
// once (blocked) or on the next request (pending, with gating on) — B trap 8.
function assertNotOwnDevice(rc, deviceId, next) {
  if (rc?.device?.id !== deviceId) return;
  if (next === 'blocked') throw new GuardError('self_lockout', 'You can’t block the device you’re using.', 409);
  if (next === 'pending' && gatingMayBeOn(rc)) {
    throw new GuardError('self_lockout', 'Device approval is on, so this would lock you out of the device you’re using. Do it from another approved device.', 409);
  }
}

// Grace windows and sessions on the device go with the trust (A §8).
function dropTrust(db, deviceId, t, reason) {
  return [
    db.prepare('DELETE FROM mfa_grace WHERE device_id = ?').bind(deviceId),
    db.prepare('UPDATE sessions SET revoked_at = ?, revoke_reason = ? WHERE device_id = ? AND revoked_at IS NULL').bind(iso(t), reason, deviceId),
  ];
}

function validLabel(label) {
  const s = strStrict(label, 1, LABEL_MAX);
  if (s === null) throw new ValidationError(`A device name must be 1 to ${LABEL_MAX} characters.`, 'label');
  return s;
}

// → { prior, row }. 'approved' records who and when; 'blocked' refuses the
// device at the gate's first step in every mode; leaving 'approved' for
// 'pending' or anything for 'blocked' drops grace windows and sessions there.
export async function setDeviceStatus(rc, deviceId, status, opts = {}) {
  if (typeof status !== 'string' || !DEVICE_STATUSES.includes(status)) {
    throw new ValidationError('Device status must be pending, approved or blocked.', 'status');
  }
  const label = opts && opts.label !== undefined ? validLabel(opts.label) : null;
  const env = rc.env;
  const db = env.DB;
  const t = nowOf(rc);
  const prior = await loadDevice(env, deviceId);
  assertNotOwnDevice(rc, prior.id, status);
  const by = actorId(rc);
  const stmts = [];
  if (status === 'approved') {
    stmts.push(
      db
        .prepare("UPDATE devices SET status = 'approved', approved_by = ?, approved_at = ?, blocked_by = NULL, blocked_at = NULL, label = COALESCE(?, label) WHERE id = ?")
        .bind(by, iso(t), label, prior.id),
    );
  } else if (status === 'blocked') {
    stmts.push(
      db.prepare("UPDATE devices SET status = 'blocked', blocked_by = ?, blocked_at = ?, label = COALESCE(?, label) WHERE id = ?").bind(by, iso(t), label, prior.id),
      ...dropTrust(db, prior.id, t, 'device_blocked'),
    );
  } else {
    stmts.push(
      db
        .prepare("UPDATE devices SET status = 'pending', approved_by = NULL, approved_at = NULL, blocked_by = NULL, blocked_at = NULL, label = COALESCE(?, label) WHERE id = ?")
        .bind(label, prior.id),
    );
    if (deviceState(prior) !== 'pending') stmts.push(...dropTrust(db, prior.id, t, 'device_revoked'));
  }
  await db.batch(stmts);
  const row = await db.prepare('SELECT * FROM devices WHERE id = ?').bind(prior.id).first();
  return { prior, row };
}

export async function renameDevice(rc, deviceId, label) {
  const name = validLabel(label);
  const prior = await loadDevice(rc.env, deviceId);
  await rc.env.DB.prepare('UPDATE devices SET label = ? WHERE id = ?').bind(name, prior.id).run();
  const row = await rc.env.DB.prepare('SELECT * FROM devices WHERE id = ?').bind(prior.id).first();
  return { prior, row };
}

// Back to 'pending' with grace and sessions dropped. A blocked device (or an
// unreadable status) stays as it is: revoking must never loosen anything.
export async function revokeDevice(rc, deviceId) {
  const env = rc.env;
  const db = env.DB;
  const t = nowOf(rc);
  const prior = await loadDevice(env, deviceId);
  if (deviceState(prior) === 'approved') assertNotOwnDevice(rc, prior.id, 'pending');
  await db.batch([
    db
      .prepare(
        `UPDATE devices SET status = 'pending', approved_by = NULL, approved_at = NULL
         WHERE id = ? AND status IN ('approved', 'pending')`,
      )
      .bind(prior.id),
    ...dropTrust(db, prior.id, t, 'device_revoked'),
  ]);
}

// Newest first, each with the people who signed in on it and its code.
export async function listDevices(env, opts = {}) {
  const o = opts && typeof opts === 'object' ? opts : {};
  let status = null;
  if (o.status !== undefined && o.status !== null && o.status !== '') {
    if (typeof o.status !== 'string' || !DEVICE_STATUSES.includes(o.status)) {
      throw new ValidationError('Device status must be pending, approved or blocked.', 'status');
    }
    status = o.status;
  }
  let userId = null;
  if (o.userId !== undefined && o.userId !== null) {
    userId = toInt(o.userId, 1);
    if (!Number.isFinite(userId)) throw new ValidationError('Unknown person.', 'userId');
  }
  const lim = toInt(o.limit, 1, 500);
  const limit = Number.isFinite(lim) ? lim : 100;
  const db = env.DB;
  const { results } = await db
    .prepare(
      `SELECT * FROM devices d
       WHERE (? IS NULL OR d.status = ?)
         AND (? IS NULL OR EXISTS (SELECT 1 FROM device_users du WHERE du.device_id = d.id AND du.user_id = ?))
       ORDER BY d.last_seen DESC, d.id LIMIT ?`,
    )
    .bind(status, status, userId, userId, limit)
    .all();
  const rows = results || [];
  const byDevice = new Map(rows.map((r) => [r.id, []]));
  // D1 allows 100 bound parameters per statement, so the ledger lookup goes
  // in chunks (a single IN list of 500 ids is a 500 in production).
  const people = [];
  for (let i = 0; i < rows.length; i += 90) {
    const chunk = rows.slice(i, i + 90);
    const { results: part } = await db
      .prepare(
        `SELECT du.device_id, du.user_id, du.first_seen, du.last_seen, du.sign_ins, u.email, u.full_name
         FROM device_users du LEFT JOIN users u ON u.id = du.user_id
         WHERE du.device_id IN (${chunk.map(() => '?').join(',')}) ORDER BY du.last_seen DESC`,
      )
      .bind(...chunk.map((r) => r.id))
      .all();
    people.push(...(part || []));
  }
  for (const p of people) {
    byDevice.get(p.device_id)?.push({
      user_id: p.user_id,
      email: p.email ?? null,
      full_name: p.full_name ?? null,
      sign_ins: p.sign_ins,
      first_seen: p.first_seen,
      last_seen: p.last_seen,
    });
  }
  return Promise.all(rows.map(async (r) => ({ ...r, code: await deviceCode(r.id), users: byDevice.get(r.id) || [] })));
}
