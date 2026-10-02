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
