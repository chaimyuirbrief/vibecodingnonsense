// The hash-chained audit log (CONTRACTS §4.2, B §7, A §9).
//
//   hash = SHA-256(prev_hash + "\n" + canonicalJson(every column but id and hash))
//
// Editing or deleting any row breaks every hash after it, and verifyChain
// names the first row where it stops matching. Rows are never updated: a
// revert is a new row whose reverts_id points at the original, and
// "reverted" is derived.
//
// audit() and auditError() NEVER throw (B trap 2: the logger must not break
// the operation it reports on). undo_payload never leaves the server except
// through getAuditEntry, which only the revert endpoint calls.

import { sha256Hex } from './crypto.js';
import { now, iso, toInt, str, canonicalJson, safeJsonParse, randomInt } from './util.js';
import { isUndoKind } from './undo.js';

export const GENESIS_HASH = '0'.repeat(64);

export const SCRUB_RE = /pass|secret|token|hash|salt|code|cookie|session/i;

// Hashed, in this order of meaning (canonicalJson sorts the keys anyway).
export const CHAIN_FIELDS = Object.freeze([
  'seq', 'at', 'actor_id', 'actor_label', 'action', 'target_type', 'target_id', 'outcome', 'severity', 'detail',
  'before_state', 'after_state', 'error', 'ip', 'device_id', 'session_ref', 'undo_kind', 'undo_payload', 'reverts_id',
  'prev_hash',
]);

const OUTCOMES = ['success', 'failure', 'denied'];
const SEVERITIES = ['info', 'notice', 'warning', 'critical'];
const DEFAULT_SEVERITY = { success: 'info', denied: 'notice', failure: 'warning' };

const DETAIL_MAX = 1000;
const ERROR_MAX = 2000;
const STATE_MAX_BYTES = 16 * 1024;
const UNDO_MAX_BYTES = 512 * 1024;
const SCRUB_MAX_DEPTH = 12;
const MAX_ATTEMPTS = 8;
const VERIFY_PAGE = 500;

const enc = new TextEncoder();

// What goes into a TEXT column must come back byte-identical, or the chain
// would "break" on an honest row: a lone surrogate cannot survive UTF-8, and
// NUL is not safe in every driver.
function cleanText(s) {
  const w = typeof s.toWellFormed === 'function' ? s.toWellFormed() : s;
  return w.replace(/\u0000/g, '�');
}

function textOrNull(v, max) {
  if (typeof v !== 'string') return null;
  const s = cleanText(v).slice(0, max);
  return s === '' ? null : s;
}

function idOrNull(v) {
  const n = toInt(v, 1, Number.MAX_SAFE_INTEGER);
  return Number.isFinite(n) ? n : null;
}

// ---------------------------------------------------------------- shaping

// Drops every key that looks like a credential, at any depth, and anything a
// JSON column cannot hold. Cycles and absurd depth become markers.
export function scrub(v, depth = 0, seen = new WeakSet()) {
  if (v === null || v === undefined) return v === null ? null : undefined;
  const t = typeof v;
  if (t === 'string') return cleanText(v);
  if (t === 'number') return Number.isFinite(v) ? v : null;
  if (t === 'boolean') return v;
  if (t === 'bigint') return v.toString();
  if (t !== 'object') return null; // functions, symbols
  if (seen.has(v)) return '[cycle]';
  if (depth >= SCRUB_MAX_DEPTH) return '[too deep]';
  seen.add(v);
  try {
    if (Array.isArray(v)) return v.map((x) => {
      const s = scrub(x, depth + 1, seen);
      return s === undefined ? null : s;
    });
    if (v instanceof Date) return Number.isFinite(v.getTime()) ? v.toISOString() : null;
    const out = {};
    for (const k of Object.keys(v)) {
      if (SCRUB_RE.test(k) || k === '__proto__') continue;
      const s = scrub(v[k], depth + 1, seen);
      if (s !== undefined) out[cleanText(k)] = s;
    }
    return out;
  } finally {
    seen.delete(v);
  }
}

function stateColumn(v) {
  if (v === undefined || v === null) return null;
  let s;
  try {
    s = canonicalJson(scrub(v));
  } catch {
    return canonicalJson({ _unserialisable: true });
  }
  const bytes = enc.encode(s).length;
  return bytes <= STATE_MAX_BYTES ? s : canonicalJson({ _truncated: true, bytes });
}

// `${name}: ${message}` and the first three stack frames — the REAL error,
// not the polite sentence the caller was shown (B trap 2).
export function formatError(err) {
  if (err === undefined || err === null) return null;
  try {
    if (typeof err === 'string') return textOrNull(err, ERROR_MAX);
    if (typeof err === 'object' && typeof err.message === 'string') {
      const name = typeof err.name === 'string' && err.name ? err.name : 'Error';
      const frames = typeof err.stack === 'string' ? err.stack.split('\n').filter((l) => /^\s+at\s/.test(l)).slice(0, 3) : [];
      return textOrNull([`${name}: ${err.message}`, ...frames.map((l) => l.trim())].join('\n'), ERROR_MAX);
    }
    return textOrNull(`Non-error thrown: ${canonicalJson(scrub(err))}`, ERROR_MAX);
  } catch {
    return 'Unformattable error';
  }
}

function targetIdText(id) {
  if (typeof id === 'number') return Number.isFinite(id) ? String(id) : null;
  if (typeof id === 'bigint') return id.toString();
  return textOrNull(id, 200);
}

function undoColumns(undo) {
  if (!undo) return { undo_kind: null, undo_payload: null };
  // Only a kind with a reverter may be recorded (A §14.9); undoFor enforces
  // that at the call site, this catches anything built by hand.
  if (!isUndoKind(undo.kind)) {
    console.error('audit: dropping undo with unknown kind', String(undo.kind));
    return { undo_kind: null, undo_payload: null };
  }
  const payload = canonicalJson(undo.payload ?? null);
  if (enc.encode(payload).length > UNDO_MAX_BYTES) {
    console.error('audit: undo payload too large to store; entry will not be revertible', undo.kind);
    return { undo_kind: null, undo_payload: null };
  }
  return { undo_kind: undo.kind, undo_payload: cleanText(payload) };
}

// Everything but seq, prev_hash and hash, already in the exact form SQLite
// will hand back — the hash is computed over these values.
function buildRow(rc, entry, nowMs) {
  const user = rc.user || null;
  const outcome = entry.outcome === undefined ? 'success' : OUTCOMES.includes(entry.outcome) ? entry.outcome : 'failure';
  const severity = SEVERITIES.includes(entry.severity) ? entry.severity : DEFAULT_SEVERITY[outcome];
  const target = entry.target && typeof entry.target === 'object' ? entry.target : null;
  const sessionId = typeof rc.session?.id === 'string' ? rc.session.id : null;
  return {
    at: iso(nowMs),
    actor_id: idOrNull(entry.actorId !== undefined ? entry.actorId : user?.id),
    actor_label: textOrNull(entry.actorLabel !== undefined ? entry.actorLabel : user?.email, 254),
    action: textOrNull(entry.action, 100) || 'unknown',
    target_type: target ? textOrNull(target.type, 50) : null,
    target_id: target ? targetIdText(target.id) : null,
    outcome,
    severity,
    detail: textOrNull(entry.detail, DETAIL_MAX),
    before_state: stateColumn(entry.before),
    after_state: stateColumn(entry.after),
    error: formatError(entry.error),
    ip: textOrNull(rc.ip, 64),
    device_id: textOrNull(rc.device?.id, 128),
    // A short prefix of the stored session hash: enough to correlate, useless
    // as a credential (A §11).
    session_ref: sessionId ? textOrNull(sessionId.slice(0, 12), 12) : null,
    ...undoColumns(entry.undo),
    reverts_id: idOrNull(entry.revertsId),
  };
}

export async function hashRow(row) {
  const content = {};
  for (const k of CHAIN_FIELDS) content[k] = row[k] === undefined ? null : row[k];
  return sha256Hex(`${row.prev_hash}\n${canonicalJson(content)}`);
}

// ---------------------------------------------------------------- writing

const INSERT_SQL = `INSERT INTO audit_log (${CHAIN_FIELDS.join(', ')}, hash)
  SELECT ${CHAIN_FIELDS.map(() => '?').join(', ')}, ?
  WHERE (SELECT COALESCE(MAX(seq), 0) FROM audit_log) = ?`;

async function readHead(db) {
  const head = await db.prepare('SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1').first();
  return head ? { seq: head.seq, hash: head.hash } : { seq: 0, hash: GENESIS_HASH };
}

// Writes from one request (or one test env) queue behind each other, so they
// never race themselves. Writes from different requests or isolates race on
// the conditional insert below and retry.
const queues = new WeakMap();

function serialised(key, fn) {
  const prev = queues.get(key) || Promise.resolve();
  const run = prev.then(fn);
  queues.set(key, run.then(() => undefined, () => undefined));
  return run;
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function append(db, base) {
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    const head = await readHead(db);
    const row = { ...base, seq: head.seq + 1, prev_hash: head.hash };
    row.hash = await hashRow(row);
    let res = null;
    try {
      res = await db.prepare(INSERT_SQL).bind(...CHAIN_FIELDS.map((k) => row[k]), row.hash, head.seq).run();
    } catch (e) {
      if (!/UNIQUE/i.test(String(e && e.message))) throw e;
    }
    if (res && res.meta && res.meta.changes === 1) return { id: res.meta.last_row_id, seq: row.seq };
    // Lost the race to another writer: back off a little, re-read the head.
    if (attempt < MAX_ATTEMPTS) await sleep(randomInt(2 ** attempt));
  }
  throw new Error(`audit: gave up after ${MAX_ATTEMPTS} contended attempts`);
}

// → { id, seq } | null. Never throws.
export async function audit(rc, entry) {
  try {
    const env = rc && rc.env;
    if (!env || !env.DB || !entry || typeof entry !== 'object') throw new Error('audit: needs rc.env and an entry');
    const nowMs = typeof rc.nowMs === 'number' && Number.isFinite(rc.nowMs) ? rc.nowMs : now(env);
    const base = buildRow(rc, entry, nowMs);
    return await serialised(rc.ctx && typeof rc.ctx === 'object' ? rc.ctx : env.DB, () => append(env.DB, base));
  } catch (e) {
    let action = '?';
    try {
      action = String(entry && entry.action);
    } catch {
      /* unprintable */
    }
    console.error('audit: could not write audit row', action, e && e.message);
    return null;
  }
}

// The catch-block companion: critical, with the real exception (B trap 2).
export function auditError(rc, action, err, opts = {}) {
  try {
    const o = opts && typeof opts === 'object' ? opts : {};
    const label = typeof action === 'string' && action ? action : 'error';
    return audit(rc, {
      ...o,
      action: label,
      outcome: 'failure',
      severity: 'critical',
      error: err ?? 'unknown error',
      detail: typeof o.detail === 'string' && o.detail ? o.detail : `Unexpected failure during ${label}.`,
    });
  } catch {
    return Promise.resolve(null);
  }
}

// ---------------------------------------------------------------- verifying

// → { ok, checked, head_seq, broken_at: null | { seq, id, reason } }.
// Walks EVERY row in seq order, 500 at a time. Nothing bounds the walk by a
// stored value: a seq tampered to text would make MAX(seq) unreadable, and a
// bound read from it would verify nothing and report the chain intact. The
// first page has no lower bound, so a seq moved below 1 is visited too (text
// sorts after every integer, so it is reached at the end).
export async function verifyChain(env) {
  const db = env.DB;
  const maxSeq = toInt(await db.prepare('SELECT MAX(seq) AS s FROM audit_log').first('s'), 0);
  let expectSeq = 1;
  let prevHash = GENESIS_HASH;
  let checked = 0;
  let after = null;
  for (;;) {
    const page =
      after === null
        ? db.prepare('SELECT * FROM audit_log ORDER BY seq LIMIT ?').bind(VERIFY_PAGE)
        : db.prepare('SELECT * FROM audit_log WHERE seq > ? ORDER BY seq LIMIT ?').bind(after, VERIFY_PAGE);
    const { results } = await page.all();
    for (const row of results) {
      const broken = (reason) => ({
        ok: false,
        checked,
        head_seq: Number.isFinite(maxSeq) ? maxSeq : null,
        broken_at: { seq: row.seq, id: row.id, reason },
      });
      if (row.seq !== expectSeq) return broken('seq_gap');
      if (row.prev_hash !== prevHash) return broken('prev_mismatch');
      if ((await hashRow(row)) !== row.hash) return broken('hash_mismatch');
      prevHash = row.hash;
      expectSeq++;
      checked++;
      after = row.seq;
    }
    if (results.length < VERIFY_PAGE) break;
  }
  return { ok: true, checked, head_seq: checked, broken_at: null };
}

// ---------------------------------------------------------------- reading

const LIST_COLUMNS = `a.id, a.seq, a.at, a.actor_id, a.actor_label, a.action, a.target_type, a.target_id,
  a.outcome, a.severity, a.detail, a.before_state, a.after_state, a.error, a.ip, a.device_id, a.undo_kind,
  a.reverts_id, (a.undo_payload IS NOT NULL) AS has_undo,
  (SELECT r.id FROM audit_log r WHERE r.reverts_id = a.id AND r.action = 'audit.revert' AND r.outcome = 'success'
     ORDER BY r.seq DESC LIMIT 1) AS reverted_by`;

function likeEscape(s) {
  return s.replace(/[\\%_]/g, (c) => '\\' + c);
}

function blank(v) {
  return v === undefined || v === null || (typeof v === 'string' && v.trim() === '');
}

// Filters arrive from a query string. Blank means "not filtering"; a value
// that cannot be valid matches nothing rather than being silently dropped.
export async function listAudit(env, filters = {}, { canRevert = false, revertibleKinds = new Set() } = {}) {
  const f = filters && typeof filters === 'object' ? filters : {};
  const where = [];
  const args = [];
  const none = { entries: [], next_before_seq: null };

  if (!blank(f.action)) {
    if (typeof f.action !== 'string') return none;
    where.push(`a.action LIKE ? ESCAPE '\\'`);
    args.push(likeEscape(str(f.action, 100)) + '%');
  }
  if (!blank(f.actor)) {
    const id = idOrNull(f.actor);
    if (id === null) return none;
    where.push('a.actor_id = ?');
    args.push(id);
  }
  if (!blank(f.target_type)) {
    if (typeof f.target_type !== 'string') return none;
    where.push('a.target_type = ?');
    args.push(str(f.target_type, 50));
  }
  if (!blank(f.target_id)) {
    const tid = typeof f.target_id === 'string' ? str(f.target_id, 200) : typeof f.target_id === 'number' ? targetIdText(f.target_id) : null;
    if (tid === null) return none;
    where.push('a.target_id = ?');
    args.push(tid);
  }
  if (!blank(f.outcome)) {
    if (!OUTCOMES.includes(f.outcome)) return none;
    where.push('a.outcome = ?');
    args.push(f.outcome);
  }
  if (!blank(f.severity)) {
    if (!SEVERITIES.includes(f.severity)) return none;
    where.push('a.severity = ?');
    args.push(f.severity);
  }
  if (!blank(f.q)) {
    if (typeof f.q !== 'string') return none;
    where.push(`a.detail LIKE ? ESCAPE '\\'`);
    args.push('%' + likeEscape(str(f.q, 200)) + '%');
  }
  if (!blank(f.before_seq)) {
    const b = idOrNull(f.before_seq);
    if (b === null) return none;
    where.push('a.seq < ?');
    args.push(b);
  }
  const lim = toInt(f.limit, 1);
  const limit = Number.isFinite(lim) ? Math.min(lim, 200) : 50;

  const sql = `SELECT ${LIST_COLUMNS} FROM audit_log a ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
    ORDER BY a.seq DESC LIMIT ?`;
  const { results } = await env.DB.prepare(sql).bind(...args, limit + 1).all();
  const more = results.length > limit;
  const kinds = revertibleKinds instanceof Set ? revertibleKinds : new Set(Array.isArray(revertibleKinds) ? revertibleKinds : []);
  const entries = results.slice(0, limit).map((r) => ({
    id: r.id,
    seq: r.seq,
    at: r.at,
    actor_id: r.actor_id,
    actor_label: r.actor_label,
    action: r.action,
    target_type: r.target_type,
    target_id: r.target_id,
    outcome: r.outcome,
    severity: r.severity,
    detail: r.detail,
    before: safeJsonParse(r.before_state, null),
    after: safeJsonParse(r.after_state, null),
    error: r.error,
    ip: r.ip,
    device_id: r.device_id,
    undo_kind: r.undo_kind,
    reverts_id: r.reverts_id,
    reverted_by: r.reverted_by ?? null,
    // Offered from the reverter catalogue, never from "undo_kind is set" (A §14.9).
    revertible:
      canRevert === true &&
      !!r.has_undo &&
      typeof r.undo_kind === 'string' &&
      kinds.has(r.undo_kind) &&
      r.outcome === 'success' &&
      r.action !== 'audit.revert' &&
      (r.reverted_by === null || r.reverted_by === undefined),
  }));
  return { entries, next_before_seq: more && entries.length ? entries[entries.length - 1].seq : null };
}

// The full row, undo_payload parsed — for the revert endpoint only.
// undo_unreadable: a payload is stored but will not parse; the revert must refuse.
export async function getAuditEntry(env, id) {
  const n = idOrNull(id);
  if (n === null) return null;
  const r = await env.DB.prepare(
    `SELECT a.*, (SELECT x.id FROM audit_log x WHERE x.reverts_id = a.id AND x.action = 'audit.revert'
       AND x.outcome = 'success' ORDER BY x.seq DESC LIMIT 1) AS reverted_by
     FROM audit_log a WHERE a.id = ?`,
  )
    .bind(n)
    .first();
  if (!r) return null;
  const payload = safeJsonParse(r.undo_payload, undefined);
  return {
    ...r,
    before: safeJsonParse(r.before_state, null),
    after: safeJsonParse(r.after_state, null),
    undo_payload: payload === undefined ? null : payload,
    undo_unreadable: r.undo_payload !== null && payload === undefined,
    reverted_by: r.reverted_by ?? null,
  };
}

// Own activity (GET /api/me/activity): what they did and what was done to
// them. No undo data, no states, no hashes.
export async function listAuditForUser(env, userId, limit = 50) {
  const id = idOrNull(userId);
  if (id === null) return [];
  const lim = toInt(limit, 1, 200);
  const { results } = await env.DB.prepare(
    `SELECT id, at, action, outcome, detail, ip FROM audit_log
     WHERE actor_id = ? OR (target_type = 'user' AND target_id = ?)
     ORDER BY seq DESC LIMIT ?`,
  )
    .bind(id, String(id), Number.isFinite(lim) ? lim : 50)
    .all();
  return results;
}
