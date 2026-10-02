// A D1 stand-in backed by real SQLite (node:sqlite), so tests run the
// worker's own schema and its real SQL (SPEC §13.1). A mock would accept
// every query; this one rejects the same ones production would.
//
// Surface mirrored from D1:
//   db.prepare(sql).bind(...args).first(col?) / .all() / .run() / .raw()
//   db.batch([stmt, ...])   — atomic, like D1
//   db.exec(sql)
// Parameters are normalised the way the D1 binding does it: undefined/null →
// NULL, booleans → 0/1. Anything else unbindable throws, as D1 does.

import { DatabaseSync } from 'node:sqlite';

function normaliseParam(v) {
  if (v === undefined || v === null) return null;
  if (typeof v === 'boolean') return v ? 1 : 0;
  if (typeof v === 'number' || typeof v === 'string' || typeof v === 'bigint') return v;
  if (v instanceof Uint8Array) return v;
  if (v instanceof ArrayBuffer) return new Uint8Array(v);
  throw new TypeError(`D1_TYPE_ERROR: Type '${typeof v}' not supported for value '${String(v)}'`);
}

// D1 enforces limits node:sqlite does not, and each one has taken a
// production portal down while every local test passed:
//   * at most 100 bound parameters per statement ("too many SQL variables");
//   * LIKE/GLOB patterns of at most 50 bytes ("LIKE or GLOB pattern too
//     complex") — SQLITE_LIMIT_LIKE_PATTERN_LENGTH, literal or bound.
// Real D1 only complains when it evaluates the pattern (so a long GLOB behind
// an OR can lie dormant until some row reaches it); this stand-in refuses the
// statement outright, which is stricter and finds the bug on the first run.
export const D1_MAX_PARAMS = 100;
export const D1_MAX_PATTERN_BYTES = 50;
const enc = new TextEncoder();

function patternPlaceholders(sql) {
  // Indexes (0-based, in bind order) of '?' placeholders that are the right
  // operand of LIKE or GLOB. String literals and comments are skipped.
  const out = [];
  let n = 0;
  let prev = '';
  for (let i = 0; i < sql.length; i++) {
    const c = sql[i];
    if (c === "'") {
      let j = i + 1;
      while (j < sql.length && !(sql[j] === "'" && sql[j + 1] !== "'")) j += sql[j] === "'" ? 2 : 1;
      const literal = sql.slice(i + 1, j).replace(/''/g, "'");
      if (/^(LIKE|GLOB)$/i.test(prev) && enc.encode(literal).length > D1_MAX_PATTERN_BYTES) {
        throw new Error(`D1_ERROR: LIKE or GLOB pattern too complex: SQLITE_ERROR (literal of ${enc.encode(literal).length} bytes)`);
      }
      prev = 'LITERAL';
      i = j;
      continue;
    }
    if (c === '-' && sql[i + 1] === '-') {
      while (i < sql.length && sql[i] !== '\n') i++;
      continue;
    }
    if (c === '?') {
      if (/^(LIKE|GLOB)$/i.test(prev)) out.push(n);
      n++;
      prev = '?';
      continue;
    }
    if (/[A-Za-z_]/.test(c)) {
      let j = i;
      while (j < sql.length && /[A-Za-z0-9_]/.test(sql[j])) j++;
      prev = sql.slice(i, j);
      i = j - 1;
      continue;
    }
    if (!/\s/.test(c)) prev = c;
  }
  return out;
}

function checkD1Limits(sql, params) {
  if (params.length > D1_MAX_PARAMS) throw new Error(`D1_ERROR: too many SQL variables (${params.length} > ${D1_MAX_PARAMS}): SQLITE_ERROR`);
  for (const i of patternPlaceholders(sql)) {
    const v = params[i];
    if (typeof v === 'string' && enc.encode(v).length > D1_MAX_PATTERN_BYTES) {
      throw new Error(`D1_ERROR: LIKE or GLOB pattern too complex: SQLITE_ERROR (bound pattern of ${enc.encode(v).length} bytes)`);
    }
  }
}

function plainRow(row) {
  if (!row) return row;
  const out = {};
  for (const k of Object.keys(row)) {
    const v = row[k];
    out[k] = typeof v === 'bigint' ? Number(v) : v;
  }
  return out;
}

class Statement {
  constructor(db, sql, params = []) {
    this.db = db;
    this.sql = sql;
    this.params = params;
  }

  bind(...args) {
    return new Statement(this.db, this.sql, args.map(normaliseParam));
  }

  _stmt() {
    this.db._maybeFail(this.sql);
    checkD1Limits(this.sql, this.params);
    return this.db.sqlite.prepare(this.sql);
  }

  async first(col) {
    const row = plainRow(this._stmt().get(...this.params));
    if (row === undefined) return null;
    if (col !== undefined) {
      if (!(col in row)) throw new Error(`D1_COLUMN_NOTFOUND: Column not found (${col})`);
      return row[col];
    }
    return row;
  }

  async all() {
    const rows = this._stmt().all(...this.params).map(plainRow);
    return { success: true, results: rows, meta: { rows_read: rows.length, changes: 0 } };
  }

  async raw() {
    const rows = this._stmt().all(...this.params).map(plainRow);
    return rows.map((r) => Object.values(r));
  }

  async run() {
    const info = this._stmt().run(...this.params);
    return {
      success: true,
      results: [],
      meta: { changes: Number(info.changes), last_row_id: Number(info.lastInsertRowid) },
    };
  }

  _runSync() {
    const st = this._stmt();
    if (/^\s*(select|with|pragma)\b/i.test(this.sql) || /\breturning\b/i.test(this.sql)) {
      const rows = st.all(...this.params).map(plainRow);
      return { success: true, results: rows, meta: { changes: 0 } };
    }
    const info = st.run(...this.params);
    return { success: true, results: [], meta: { changes: Number(info.changes), last_row_id: Number(info.lastInsertRowid) } };
  }
}

export class FakeD1 {
  constructor() {
    this.sqlite = new DatabaseSync(':memory:');
    this.sqlite.exec('PRAGMA foreign_keys = OFF;');
    this.failOn = null; // RegExp: make matching statements throw (fault injection)
  }

  _maybeFail(sql) {
    if (this.failOn && this.failOn.test(sql)) throw new Error(`injected failure for: ${sql.slice(0, 60)}`);
  }

  prepare(sql) {
    return new Statement(this, sql);
  }

  async batch(statements) {
    this.sqlite.exec('BEGIN');
    try {
      const out = statements.map((s) => s._runSync());
      this.sqlite.exec('COMMIT');
      return out;
    } catch (e) {
      this.sqlite.exec('ROLLBACK');
      throw e;
    }
  }

  async exec(sql) {
    this._maybeFail(sql);
    this.sqlite.exec(sql);
    return { count: 1, duration: 0 };
  }

  // Test convenience (not part of D1): synchronous query.
  q(sql, ...params) {
    return this.sqlite.prepare(sql).all(...params.map(normaliseParam)).map(plainRow);
  }
}
