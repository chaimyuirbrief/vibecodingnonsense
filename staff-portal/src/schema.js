// Schema: created idempotently on demand, once per isolate, before the first
// query (SPEC §11). No migration tool and no build step.
//
// Rules for changing it:
//   * New tables / indexes: add to DDL with IF NOT EXISTS.
//   * New columns on an existing table: APPEND a line to MIGRATIONS. Never edit
//     or reorder a line that has shipped — it has already run in production
//     and editing it silently diverges environments. Never make one
//     destructive; drops and rewrites are manual, backed-up operations.
//   * Bump SCHEMA_VERSION.
//
// All times are ISO-8601 UTC strings (util.iso). Never store local time.

import { SYSTEM_ROLES } from './catalog.js';
import { nowIso } from './util.js';

export const SCHEMA_VERSION = 1;

export const DDL = [
  // ---------------------------------------------------------------- meta
  `CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
  )`,
  // Every policy knob. Read through policy.js only: each read has a default
  // and every unrecognised value reads as the RESTRICTIVE option.
  `CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT,
    updated_by INTEGER
  )`,

  // ---------------------------------------------------------------- identity
  `CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    rank INTEGER NOT NULL,
    permissions TEXT NOT NULL DEFAULT '[]',
    is_system INTEGER NOT NULL DEFAULT 0,
    description TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    username TEXT UNIQUE,
    full_name TEXT NOT NULL DEFAULT '',
    employee_no TEXT UNIQUE,
    job_title TEXT,
    department TEXT,
    manager_id INTEGER,
    phone TEXT,
    password_hash TEXT,
    password_salt TEXT,
    password_algo TEXT,
    password_iters INTEGER,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'invited',
    role_id INTEGER NOT NULL,
    perm_grants TEXT NOT NULL DEFAULT '[]',
    perm_denies TEXT NOT NULL DEFAULT '[]',
    mfa_policy TEXT NOT NULL DEFAULT 'inherit',
    failed_logins INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    last_login_at TEXT,
    last_seen_at TEXT,
    created_by INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    disabled_at TEXT
  )`,
  `CREATE INDEX IF NOT EXISTS users_role ON users(role_id)`,
  `CREATE INDEX IF NOT EXISTS users_manager ON users(manager_id)`,
  `CREATE INDEX IF NOT EXISTS users_status ON users(status)`,
  // Additional, optionally time-boxed role grants ("admin for a week").
  `CREATE TABLE IF NOT EXISTS user_roles (
    user_id INTEGER NOT NULL,
    role_id INTEGER NOT NULL,
    granted_by INTEGER,
    expires_at TEXT,
    created_at TEXT NOT NULL,
    PRIMARY KEY (user_id, role_id)
  )`,
  `CREATE TABLE IF NOT EXISTS invitations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT NOT NULL UNIQUE,
    user_id INTEGER NOT NULL,
    email TEXT NOT NULL,
    role_id INTEGER NOT NULL,
    created_by INTEGER,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    revoked_at TEXT
  )`,
  `CREATE INDEX IF NOT EXISTS invitations_user ON invitations(user_id)`,
  `CREATE TABLE IF NOT EXISTS access_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    full_name TEXT,
    reason TEXT,
    ip TEXT,
    country TEXT,
    visitor_id TEXT,
    risk INTEGER,
    status TEXT NOT NULL DEFAULT 'pending',
    decided_by INTEGER,
    decided_at TEXT,
    invitation_id INTEGER,
    created_at TEXT NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS access_requests_status ON access_requests(status, created_at)`,

  // ---------------------------------------------------------------- sessions
  // id is the SHA-256 of the cookie token: a database leak is not a session leak.
  `CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    device_id TEXT,
    created_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    idle_expires_at TEXT NOT NULL,
    absolute_expires_at TEXT NOT NULL,
    ip TEXT,
    ua TEXT,
    aal INTEGER NOT NULL DEFAULT 1,
    mfa_at TEXT,
    mfa_method TEXT,
    pinned TEXT,
    revoked_at TEXT,
    revoke_reason TEXT
  )`,
  `CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id)`,
  `CREATE INDEX IF NOT EXISTS sessions_abs ON sessions(absolute_expires_at)`,

  // ---------------------------------------------------------------- devices
  `CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'pending',
    label TEXT,
    ua TEXT,
    platform TEXT,
    first_ip TEXT,
    last_ip TEXT,
    visitor_id TEXT,
    approved_by INTEGER,
    approved_at TEXT,
    blocked_by INTEGER,
    blocked_at TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS devices_status ON devices(status, last_seen)`,
  `CREATE TABLE IF NOT EXISTS device_users (
    device_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    sign_ins INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (device_id, user_id)
  )`,
  `CREATE INDEX IF NOT EXISTS device_users_user ON device_users(user_id)`,

  // ---------------------------------------------------------------- network
  // tier: 1 core admin (7d grace) · 2 trusted (24h) · 3 shared (2h) · 4 temporary (none, must expire)
  `CREATE TABLE IF NOT EXISTS allowed_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cidr TEXT NOT NULL,
    tier INTEGER NOT NULL DEFAULT 3,
    label TEXT,
    owner TEXT,
    user_id INTEGER,
    expires_at TEXT,
    created_by INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS blocked_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cidr TEXT NOT NULL,
    reason TEXT,
    expires_at TEXT,
    created_by INTEGER,
    created_at TEXT NOT NULL
  )`,
  // Per account AND per device: a browser that never completed a factor
  // check gets no grace however trusted the network is.
  `CREATE TABLE IF NOT EXISTS mfa_grace (
    user_id INTEGER NOT NULL,
    device_id TEXT NOT NULL,
    tier INTEGER NOT NULL,
    verified_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    PRIMARY KEY (user_id, device_id)
  )`,

  // ---------------------------------------------------------------- second factors
  `CREATE TABLE IF NOT EXISTS user_totp (
    user_id INTEGER PRIMARY KEY,
    secret_enc TEXT NOT NULL,
    confirmed_at TEXT,
    last_counter INTEGER,
    created_at TEXT NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS user_passkeys (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    public_key TEXT NOT NULL,
    algorithm INTEGER NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    aaguid TEXT,
    transports TEXT,
    label TEXT,
    created_at TEXT NOT NULL,
    last_used_at TEXT
  )`,
  `CREATE INDEX IF NOT EXISTS user_passkeys_user ON user_passkeys(user_id)`,
  `CREATE TABLE IF NOT EXISTS backup_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    code_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    iters INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    used_at TEXT
  )`,
  `CREATE INDEX IF NOT EXISTS backup_codes_user ON backup_codes(user_id)`,
  `CREATE TABLE IF NOT EXISTS webauthn_challenges (
    challenge TEXT PRIMARY KEY,
    user_id INTEGER,
    kind TEXT NOT NULL,
    expires_at TEXT NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS webauthn_challenges_exp ON webauthn_challenges(expires_at)`,
  // Where a texted / emailed code may go. Adding one is handing out a second
  // factor, not editing a contact detail.
  `CREATE TABLE IF NOT EXISTS code_destinations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    address TEXT NOT NULL,
    label TEXT,
    is_primary INTEGER NOT NULL DEFAULT 0,
    created_by INTEGER,
    created_at TEXT NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS code_destinations_user ON code_destinations(user_id)`,
  `CREATE TABLE IF NOT EXISTS otp_challenges (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    destination_id INTEGER NOT NULL,
    code_hash TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    created_at TEXT NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS otp_challenges_user ON otp_challenges(user_id, created_at)`,

  // ---------------------------------------------------------------- rate limits
  // One row per attempt; count rows in a window. Pruned by the write that
  // creates the pressure, so no scheduled job is needed.
  `CREATE TABLE IF NOT EXISTS auth_attempts (
    kind TEXT NOT NULL,
    subject TEXT NOT NULL,
    at TEXT NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS auth_attempts_ksa ON auth_attempts(kind, subject, at)`,
  `CREATE INDEX IF NOT EXISTS auth_attempts_at ON auth_attempts(at)`,

  // ---------------------------------------------------------------- visibility
  // Keyed by a hash of client-chosen input: trimmed by TIMESTAMP and COUNT,
  // never by id (SPEC trap B6).
  `CREATE TABLE IF NOT EXISTS fingerprints (
    hash TEXT PRIMARY KEY,
    visitor_id TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    hits INTEGER NOT NULL DEFAULT 1,
    risk INTEGER,
    flags TEXT,
    edge TEXT,
    client TEXT,
    last_ip TEXT,
    last_user_id INTEGER
  )`,
  `CREATE INDEX IF NOT EXISTS fingerprints_last_seen ON fingerprints(last_seen)`,
  `CREATE INDEX IF NOT EXISTS fingerprints_visitor ON fingerprints(visitor_id)`,
  `CREATE TABLE IF NOT EXISTS visits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL,
    ip TEXT,
    country TEXT,
    asn INTEGER,
    method TEXT,
    path TEXT,
    decision TEXT,
    reason TEXT,
    fp_hash TEXT,
    visitor_id TEXT,
    device_id TEXT,
    user_id INTEGER,
    risk INTEGER,
    ua TEXT
  )`,
  `CREATE INDEX IF NOT EXISTS visits_at ON visits(at)`,
  `CREATE INDEX IF NOT EXISTS visits_ip ON visits(ip, at)`,

  // ---------------------------------------------------------------- audit
  // Hash-chained: hash = SHA-256(prev_hash + "\n" + canonical row content).
  // Rows are never updated or deleted. A revert is a NEW row whose
  // reverts_id points at the original; "reverted" is derived, not stored.
  // undo_payload is for the server only — never returned by any API.
  `CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    seq INTEGER NOT NULL UNIQUE,
    at TEXT NOT NULL,
    actor_id INTEGER,
    actor_label TEXT,
    action TEXT NOT NULL,
    target_type TEXT,
    target_id TEXT,
    outcome TEXT NOT NULL,
    severity TEXT NOT NULL,
    detail TEXT,
    before_state TEXT,
    after_state TEXT,
    error TEXT,
    ip TEXT,
    device_id TEXT,
    session_ref TEXT,
    undo_kind TEXT,
    undo_payload TEXT,
    reverts_id INTEGER,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS audit_at ON audit_log(at)`,
  `CREATE INDEX IF NOT EXISTS audit_actor ON audit_log(actor_id, seq)`,
  `CREATE INDEX IF NOT EXISTS audit_target ON audit_log(target_type, target_id, seq)`,
  `CREATE INDEX IF NOT EXISTS audit_action ON audit_log(action, seq)`,
  `CREATE INDEX IF NOT EXISTS audit_reverts ON audit_log(reverts_id)`,

  // ---------------------------------------------------------------- streaks
  // last_at: the most recent sign-in (the window runs from here).
  // last_day: the portal-local date (YYYY-MM-DD) of the last sign-in that
  // COUNTED — two sign-ins on one local day count once.
  `CREATE TABLE IF NOT EXISTS streaks (
    user_id INTEGER PRIMARY KEY,
    current INTEGER NOT NULL DEFAULT 0,
    longest INTEGER NOT NULL DEFAULT 0,
    total_days INTEGER NOT NULL DEFAULT 0,
    started_day TEXT,
    last_day TEXT,
    last_at TEXT,
    updated_at TEXT NOT NULL
  )`,
  // One row per counted local day: the history strip, and the evidence an
  // admin needs when someone asks why their streak reset.
  `CREATE TABLE IF NOT EXISTS streak_days (
    user_id INTEGER NOT NULL,
    day TEXT NOT NULL,
    first_at TEXT NOT NULL,
    PRIMARY KEY (user_id, day)
  )`,
];

// Forward-only, allowed to fail (already applied). APPEND ONLY.
export const MIGRATIONS = [
  // (none yet — version 1 is the baseline)
];

const ensured = new WeakMap();

// Idempotent; runs once per isolate per database. A failure is not cached, so
// the next request retries rather than serving from a half-made schema.
export function ensureSchema(env) {
  const db = env.DB;
  let p = ensured.get(db);
  if (!p) {
    p = migrate(env).catch((e) => {
      ensured.delete(db);
      throw e;
    });
    ensured.set(db, p);
  }
  return p;
}

async function migrate(env) {
  const db = env.DB;
  await db.batch(DDL.map((sql) => db.prepare(sql)));
  for (const sql of MIGRATIONS) {
    try {
      await db.prepare(sql).run();
    } catch {
      /* already applied */
    }
  }
  // System roles: code is the source of truth, so a release that changes a
  // system role's grants takes effect on the next cold start. Custom roles
  // (is_system = 0) are never touched here.
  const t = nowIso(env);
  await db.batch(
    SYSTEM_ROLES.map((r) =>
      db
        .prepare(
          `INSERT INTO roles (key, name, rank, permissions, is_system, description, created_at, updated_at)
           VALUES (?, ?, ?, ?, 1, ?, ?, ?)
           ON CONFLICT(key) DO UPDATE SET name = excluded.name, rank = excluded.rank,
             permissions = excluded.permissions, is_system = 1, description = excluded.description`,
        )
        .bind(r.key, r.name, r.rank, JSON.stringify(r.permissions), r.description, t, t),
    ),
  );
  await db
    .prepare(`INSERT INTO meta (key, value) VALUES ('schema_version', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`)
    .bind(String(SCHEMA_VERSION))
    .run();
}

// Tests only: forget that a database has been migrated.
export function _resetSchemaCache(env) {
  ensured.delete(env.DB);
}
