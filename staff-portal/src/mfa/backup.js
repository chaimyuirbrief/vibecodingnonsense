// Backup codes (CONTRACTS §7.6; A §7.3, §14.4; SPEC §7.5).
//
// Ten single-use codes, shown once, stored only as salted PBKDF2 hashes. All
// codes in a set share ONE salt, so a guess costs one derivation compared
// against every unused hash — ten salts would be ten 100k-iteration
// derivations per guess on an endpoint a stranger can reach.

import { audit } from '../audit.js';
import { pbkdf2Chain, timingSafeEqual, MIN_ITERATIONS, MAX_ITERATIONS } from '../crypto.js';
import { now, iso, toInt, hex, fromHex, randomBytes, randomInt } from '../util.js';

export const BACKUP_ALPHABET = '23456789ABCDEFGHJKMNPQRSTUVWXYZ'; // no 0 1 I O L
export const BACKUP_ITERS = 100_000; // exactly one PBKDF2 chunk
export const BACKUP_COUNT = 10;
const CODE_LEN = 10;
const SALT_BYTES = 16;
const INPUT_MAX = 64;
// Normally one set; a few tolerated (a restore beside a partial set). Beyond
// that the extra sets are not tried rather than paid for.
const MAX_SALTS_PER_ATTEMPT = 4;
const SHAPE_RE = new RegExp(`^[${BACKUP_ALPHABET}]{${CODE_LEN}}$`);

function userIdOf(v) {
  const n = toInt(v, 1, Number.MAX_SAFE_INTEGER);
  return Number.isFinite(n) ? n : null;
}

// Rejection sampling via util.randomInt — never `% n`, or the first letters
// of the alphabet become measurably likelier (A §7.3).
export function generateBackupCodes(n = BACKUP_COUNT) {
  const count = toInt(n, 1, 100);
  if (!Number.isFinite(count)) throw new RangeError('generateBackupCodes: bad count');
  const out = new Set();
  while (out.size < count) {
    let s = '';
    for (let i = 0; i < CODE_LEN; i++) s += BACKUP_ALPHABET[randomInt(BACKUP_ALPHABET.length)];
    out.add(`${s.slice(0, 5)}-${s.slice(5)}`);
  }
  return [...out];
}

// Case, spaces and hyphens are forgiven: a code read off paper arrives
// lowercase, spaced or run together. Then SHAPE-GATE: '', '   ', '-----',
// null and [] would all otherwise normalise to '' and match any row holding
// hash('') — an absent code opening an account (A §14.4). Nothing that fails
// here reaches the KDF, so junk on an open endpoint costs us nothing.
export function normalizeBackupCode(input) {
  if (typeof input !== 'string' || input.length > INPUT_MAX) return null;
  const s = input.toUpperCase().replace(/[\s-]/g, '');
  return SHAPE_RE.test(s) ? s : null;
}

// Replaces the unused set (used rows stay as history) in one batch.
export async function storeBackupCodes(env, userId, codes, nowMs) {
  const uid = userIdOf(userId);
  if (uid === null) throw new RangeError('storeBackupCodes: bad user id');
  if (!Array.isArray(codes) || codes.length < 1 || codes.length > 100) throw new RangeError('storeBackupCodes: bad code list');
  const norm = codes.map(normalizeBackupCode);
  if (norm.some((c) => c === null)) throw new RangeError('storeBackupCodes: malformed code');
  const t = iso(Number.isFinite(nowMs) ? nowMs : now(env));
  const salt = randomBytes(SALT_BYTES);
  const saltHex = hex(salt);
  const hashes = [];
  for (const c of norm) hashes.push(hex(await pbkdf2Chain(c, salt, BACKUP_ITERS)));
  const db = env.DB;
  await db.batch([
    db.prepare('DELETE FROM backup_codes WHERE user_id = ? AND used_at IS NULL').bind(uid),
    ...hashes.map((h) =>
      db
        .prepare('INSERT INTO backup_codes (user_id, code_hash, salt, iters, created_at) VALUES (?, ?, ?, ?, ?)')
        .bind(uid, h, saltHex, BACKUP_ITERS, t),
    ),
  ]);
}

// One KDF per distinct (salt, iters) among the unused rows — normally one.
// Every row is compared (no early exit), and spending is a conditional UPDATE
// so two simultaneous submissions of one code cannot both succeed.
export async function consumeBackupCode(rc, userId, input) {
  const code = normalizeBackupCode(input);
  if (code === null) return false;
  const uid = userIdOf(userId);
  if (uid === null) return false;
  const env = rc.env;
  const t = Number.isFinite(rc.nowMs) ? rc.nowMs : now(env);
  const { results } = await env.DB.prepare(
    'SELECT id, code_hash, salt, iters FROM backup_codes WHERE user_id = ? AND used_at IS NULL ORDER BY id',
  )
    .bind(uid)
    .all();
  const groups = new Map();
  for (const r of results) {
    // A row whose salt, iteration count or hash is unreadable can never match.
    const salt = fromHex(r.salt);
    const iters = toInt(r.iters, MIN_ITERATIONS, MAX_ITERATIONS);
    const want = fromHex(r.code_hash);
    if (!salt || salt.length < SALT_BYTES || !Number.isFinite(iters) || !want || want.length !== 32) continue;
    const key = `${r.salt}:${iters}`;
    if (!groups.has(key)) {
      if (groups.size >= MAX_SALTS_PER_ATTEMPT) continue;
      groups.set(key, { salt, iters, rows: [] });
    }
    groups.get(key).rows.push({ id: r.id, want });
  }
  let hit = null;
  for (const g of groups.values()) {
    const got = await pbkdf2Chain(code, g.salt, g.iters);
    for (const row of g.rows) {
      if ((await timingSafeEqual(got, row.want)) && hit === null) hit = row.id;
    }
  }
  if (hit === null) return false;
  const upd = await env.DB.prepare('UPDATE backup_codes SET used_at = ? WHERE id = ? AND user_id = ? AND used_at IS NULL')
    .bind(iso(t), hit, uid)
    .run();
  if (upd.meta.changes !== 1) return false;
  const remaining = await countUnusedBackupCodes(env, uid);
  // Audited here: no caller could know the count fell (CONTRACTS §4.2).
  await audit(rc, {
    action: 'mfa.backup.used',
    severity: 'notice',
    target: { type: 'user', id: uid },
    detail: `Used a backup code; ${remaining} left.`,
    after: { remaining },
  });
  return true;
}

export async function countUnusedBackupCodes(env, userId) {
  const uid = userIdOf(userId);
  if (uid === null) return 0;
  const n = await env.DB.prepare('SELECT COUNT(*) AS n FROM backup_codes WHERE user_id = ? AND used_at IS NULL').bind(uid).first('n');
  const c = toInt(n, 0);
  return Number.isFinite(c) ? c : 0;
}
