// What an account can prove with, and the guards on taking it away
// (CONTRACTS §7.6, §4.2.1 'mfa.reset'; A §7.1, §7.5; SPEC §7.1, §7.8).
//
// Two things never count as a factor: an authenticator that was never
// confirmed, and backup codes on their own — they are what an interrupted
// reset leaves behind, not something the person chose, and they run out
// (A §7.1). An authenticator whose row will not decrypt, or whose replay
// floor is unreadable, refuses every code, so it does not count either.

import { GuardError, notFound } from '../errors.js';
import { toInt } from '../util.js';
import { usableKinds } from '../notify.js';
import { loadConfirmedTotp } from './totp.js';

const MAX_ID = Number.MAX_SAFE_INTEGER;
// Bounds on a snapshot we are asked to write back: far above anything real,
// low enough that a corrupt payload cannot become a huge batch.
const SNAPSHOT_MAX_ROWS = { passkeys: 100, backup: 500, grace: 2000 };

function userIdOf(v) {
  const n = toInt(v, 1, MAX_ID);
  return Number.isFinite(n) ? n : null;
}

// An unreadable count is zero: it never makes something look present.
function countOf(v) {
  const n = toInt(v, 0);
  return Number.isFinite(n) ? n : 0;
}

async function factorState(env, uid) {
  const db = env.DB;
  const kinds = new Set(usableKinds(env));
  const [totp, passkeys, backup, dests] = await Promise.all([
    loadConfirmedTotp(env, uid),
    db.prepare('SELECT COUNT(*) AS n FROM user_passkeys WHERE user_id = ?').bind(uid).first('n'),
    db.prepare('SELECT COUNT(*) AS n FROM backup_codes WHERE user_id = ? AND used_at IS NULL').bind(uid).first('n'),
    db.prepare('SELECT id, kind FROM code_destinations WHERE user_id = ? ORDER BY is_primary DESC, id').bind(uid).all(),
  ]);
  return {
    totp: !!totp && totp.problem === null,
    totpUnreadable: !!totp && totp.problem !== null,
    passkeys: countOf(passkeys),
    backup: countOf(backup),
    usable: dests.results.filter((d) => typeof d.kind === 'string' && kinds.has(d.kind)),
  };
}

const NONE = Object.freeze({ totp: false, totpUnreadable: false, passkeys: 0, backup: 0, destinations: 0 });

export async function userFactors(env, userId) {
  const uid = userIdOf(userId);
  if (uid === null) return { ...NONE };
  const f = await factorState(env, uid);
  return { totp: f.totp, totpUnreadable: f.totpUnreadable, passkeys: f.passkeys, backup: f.backup, destinations: f.usable.length };
}

// Strongest first (D8). 'email'/'sms' appear only for a destination whose
// provider is configured — no provider, no method, no outbound call.
export async function availableMethods(env, userId) {
  const uid = userIdOf(userId);
  if (uid === null) return [];
  const f = await factorState(env, uid);
  const out = [];
  if (f.passkeys > 0) out.push('passkey');
  if (f.totp) out.push('totp');
  if (f.backup > 0) out.push('backup');
  if (f.usable.some((d) => d.kind === 'email')) out.push('email');
  if (f.usable.some((d) => d.kind === 'sms')) out.push('sms');
  return out;
}

export async function hasStrongFactor(env, userId) {
  const uid = userIdOf(userId);
  if (uid === null) return false;
  const f = await factorState(env, uid);
  return f.passkeys > 0 || f.totp;
}

// THE one guard (A §7.5, §14.8), for the self-service page, the admin page
// and the reverters: after the drop, at least one of a usable authenticator,
// a passkey or a usable code destination must remain. Backup codes alone do
// not count. Anything unrecognised as `dropping` answers no.
export async function canDropFactor(env, userId, dropping) {
  const uid = userIdOf(userId);
  if (uid === null) return false;
  let keep;
  if (dropping === 'totp') keep = (f) => f.passkeys > 0 || f.usable.length > 0;
  else if (dropping === 'passkey') keep = (f) => f.totp || f.passkeys > 1 || f.usable.length > 0;
  else if (dropping && typeof dropping === 'object' && !Array.isArray(dropping)) {
    const did = toInt(dropping.destinationId, 1, MAX_ID);
    if (!Number.isFinite(did)) return false;
    keep = (f) => f.totp || f.passkeys > 0 || f.usable.some((d) => d.id !== did);
  } else return false;
  return keep(await factorState(env, uid));
}

// ---------------------------------------------------------------- admin reset

// "I've lost my phone": clears the authenticator, every passkey, every backup
// code and the grace windows (so no already-verified browser coasts through)
// in ONE batch, and returns exactly what it cleared as the 'mfa.reset' undo
// payload — the TOTP still encrypted, so the app on their phone works again
// after a revert (A §7.5). The caller audits.
//
// Refuses unless a usable code destination remains: clearing the last factor
// is a lockout (or a password-only account), not a reset. The guard is
// evaluated INSIDE the batch and every DELETE is conditional on it, so a
// destination removed concurrently cannot slip between check and write.
export async function resetFactors(rc, userId) {
  const env = rc.env;
  const db = env.DB;
  const uid = userIdOf(userId);
  if (uid === null) throw notFound('No such account.');
  if (!(await db.prepare('SELECT 1 AS ok FROM users WHERE id = ?').bind(uid).first())) throw notFound('No such account.');
  const kinds = usableKinds(env);
  if (!kinds.length) throw nothingLeft();
  const guard = `EXISTS (SELECT 1 FROM code_destinations WHERE user_id = ? AND kind IN (${kinds.map(() => '?').join(', ')}))`;
  const g = [uid, ...kinds];
  const res = await db.batch([
    db.prepare(`SELECT ${guard} AS ok`).bind(...g),
    db.prepare('SELECT * FROM user_totp WHERE user_id = ?').bind(uid),
    db.prepare('SELECT * FROM user_passkeys WHERE user_id = ? ORDER BY created_at, id').bind(uid),
    db.prepare('SELECT * FROM backup_codes WHERE user_id = ? ORDER BY id').bind(uid),
    db.prepare('SELECT * FROM mfa_grace WHERE user_id = ? ORDER BY device_id').bind(uid),
    db.prepare(`DELETE FROM user_totp WHERE user_id = ? AND ${guard}`).bind(uid, ...g),
    db.prepare(`DELETE FROM user_passkeys WHERE user_id = ? AND ${guard}`).bind(uid, ...g),
    db.prepare(`DELETE FROM backup_codes WHERE user_id = ? AND ${guard}`).bind(uid, ...g),
    db.prepare(`DELETE FROM mfa_grace WHERE user_id = ? AND ${guard}`).bind(uid, ...g),
  ]);
  if (res[0].results?.[0]?.ok !== 1) throw nothingLeft();
  const prior = {
    userId: uid,
    totp: res[1].results[0] ?? null,
    passkeys: res[2].results,
    backup: res[3].results,
    grace: res[4].results,
  };
  const cleared = {
    totp: prior.totp !== null,
    passkeys: prior.passkeys.length,
    backup: prior.backup.filter((b) => b.used_at === null).length,
    grace: prior.grace.length,
  };
  return { cleared, prior };
}

function nothingLeft() {
  return new GuardError('nothing_left', 'They would have no way to sign in. Add a phone number or email for codes first.', 409);
}

// ---------------------------------------------------------------- restore

function enrolledSince() {
  return new GuardError('enrolled_since', 'They have set up a sign-in method since this reset, so it can’t be undone without replacing it.', 409);
}

function unreadableSnapshot() {
  return new GuardError('snapshot_unreadable', 'That reset can’t be undone: its saved copy is unreadable.', 409);
}

function scalar(v) {
  return v === null || typeof v === 'string' || (typeof v === 'number' && Number.isFinite(v));
}

// Column values exactly as stored, refusing anything SQLite did not hand us
// (objects, booleans, non-finite numbers) and any `required` column that is
// null. Rows must belong to the snapshot's user.
function columns(row, uid, names, required) {
  if (!row || typeof row !== 'object' || Array.isArray(row)) throw unreadableSnapshot();
  if (row.user_id !== undefined && row.user_id !== uid) throw unreadableSnapshot();
  return names.map((k) => {
    const v = row[k] === undefined ? null : row[k];
    if (!scalar(v) || (v === null && required.includes(k))) throw unreadableSnapshot();
    return v;
  });
}

function rowsOf(list, max) {
  if (!Array.isArray(list) || list.length > max) throw unreadableSnapshot();
  return list;
}

const TOTP_COLS = ['secret_enc', 'confirmed_at', 'last_counter', 'created_at'];
const PASSKEY_COLS = ['id', 'public_key', 'algorithm', 'sign_count', 'aaguid', 'transports', 'label', 'created_at', 'last_used_at'];
const BACKUP_COLS = ['id', 'code_hash', 'salt', 'iters', 'created_at', 'used_at'];
const GRACE_COLS = ['device_id', 'tier', 'verified_at', 'expires_at'];

// The reverter's half of 'mfa.reset': writes the snapshot back exactly.
// Refused if they have ANY authenticator row (even a half-finished setup), a
// passkey or an unused backup code now — enrolling something since means a
// revert would silently replace it (A §7.5). The TOTP insert is a plain
// INSERT on its primary key, so one created after the check fails the whole
// batch rather than being overwritten.
export async function restoreFactors(rc, prior) {
  const env = rc.env;
  const db = env.DB;
  if (!prior || typeof prior !== 'object' || Array.isArray(prior)) throw unreadableSnapshot();
  const uid = userIdOf(prior.userId);
  if (uid === null) throw unreadableSnapshot();
  if (prior.totp !== null && (typeof prior.totp !== 'object' || Array.isArray(prior.totp))) throw unreadableSnapshot();
  const totp = prior.totp ? columns(prior.totp, uid, TOTP_COLS, ['secret_enc', 'created_at']) : null;
  const passkeys = rowsOf(prior.passkeys, SNAPSHOT_MAX_ROWS.passkeys).map((r) =>
    columns(r, uid, PASSKEY_COLS, ['id', 'public_key', 'algorithm', 'sign_count', 'created_at']),
  );
  const backup = rowsOf(prior.backup, SNAPSHOT_MAX_ROWS.backup).map((r) =>
    columns(r, uid, BACKUP_COLS, ['code_hash', 'salt', 'iters', 'created_at']),
  );
  const grace = rowsOf(prior.grace, SNAPSHOT_MAX_ROWS.grace).map((r) =>
    columns(r, uid, GRACE_COLS, ['device_id', 'tier', 'verified_at', 'expires_at']),
  );

  const [t, p, b] = await db.batch([
    db.prepare('SELECT COUNT(*) AS n FROM user_totp WHERE user_id = ?').bind(uid),
    db.prepare('SELECT COUNT(*) AS n FROM user_passkeys WHERE user_id = ?').bind(uid),
    db.prepare('SELECT COUNT(*) AS n FROM backup_codes WHERE user_id = ? AND used_at IS NULL').bind(uid),
  ]);
  // Unreadable counts refuse too: we cannot show nothing was enrolled.
  const counts = [t, p, b].map((r) => toInt(r.results?.[0]?.n, 0));
  if (counts.some((n) => n !== 0)) throw enrolledSince();

  const stmts = [];
  if (totp) {
    stmts.push(
      db.prepare('INSERT INTO user_totp (user_id, secret_enc, confirmed_at, last_counter, created_at) VALUES (?, ?, ?, ?, ?)').bind(uid, ...totp),
    );
  }
  for (const r of passkeys) {
    stmts.push(
      db
        .prepare(
          `INSERT INTO user_passkeys (user_id, ${PASSKEY_COLS.join(', ')}) VALUES (?, ${PASSKEY_COLS.map(() => '?').join(', ')})`,
        )
        .bind(uid, ...r),
    );
  }
  for (const r of backup) {
    stmts.push(
      db.prepare(`INSERT INTO backup_codes (user_id, ${BACKUP_COLS.join(', ')}) VALUES (?, ${BACKUP_COLS.map(() => '?').join(', ')})`).bind(uid, ...r),
    );
  }
  // A window earned since the reset is newer evidence: it wins.
  for (const r of grace) {
    stmts.push(
      db
        .prepare(
          `INSERT INTO mfa_grace (user_id, ${GRACE_COLS.join(', ')}) VALUES (?, ${GRACE_COLS.map(() => '?').join(', ')})
           ON CONFLICT(user_id, device_id) DO NOTHING`,
        )
        .bind(uid, ...r),
    );
  }
  if (!stmts.length) return;
  try {
    await db.batch(stmts);
  } catch (e) {
    // A key that exists now and did not at the check: enrolled in between.
    if (/UNIQUE|constraint/i.test(String(e?.message))) throw enrolledSince();
    throw e;
  }
}
