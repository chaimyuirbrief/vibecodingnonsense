// What the real D1 refuses and node:sqlite allows (SPEC §14.6 "local is more
// permissive"; found by the wrangler dev smoke run). D1's SQLite caps a
// LIKE/GLOB pattern at 50 BYTES and answers anything longer with
// "LIKE or GLOB pattern too complex"; node:sqlite allows 50,000. Measured
// under workerd: a 50-byte pattern runs, 51 bytes fails, bound or literal.
//
// node:sqlite has no limits API, but SQLite lets an application override the
// built-in glob() and like() functions. The override below enforces D1's cap
// and hands the actual matching to a second in-memory database, whose
// built-ins are untouched, so matching semantics are SQLite's own.

import { DatabaseSync } from 'node:sqlite';
import { test, assert, run } from '../helpers/t.js';
import {
  freshEnv, client, bootstrap, signOut, signIn, q, count, auditRows, advance, MINUTE, OWNER, OWNER_IP,
} from '../helpers/flows.js';
import { iso } from '../../src/util.js';

const D1_PATTERN_MAX_BYTES = 50;
const GOOD = { email: OWNER.email, full_name: OWNER.full_name, password: OWNER.password };

function withD1PatternLimit(env) {
  const aux = new DatabaseSync(':memory:');
  const glob = aux.prepare('SELECT ? GLOB ? AS x');
  const like = aux.prepare('SELECT ? LIKE ? AS x');
  const likeEsc = aux.prepare('SELECT ? LIKE ? ESCAPE ? AS x');
  const guard = (pattern) => {
    if (pattern !== null && Buffer.byteLength(String(pattern), 'utf8') > D1_PATTERN_MAX_BYTES) {
      throw new Error('D1_ERROR: LIKE or GLOB pattern too complex: SQLITE_ERROR');
    }
  };
  // SQL `X GLOB P` is glob(P, X); `X LIKE P [ESCAPE E]` is like(P, X[, E]).
  env.DB.sqlite.function('glob', (p, x) => (guard(p), glob.get(x, p).x));
  env.DB.sqlite.function('like', (p, x) => (guard(p), like.get(x, p).x));
  env.DB.sqlite.function('like', (p, x, e) => (guard(p), likeEsc.get(x, p, e).x));
  return env;
}

function d1Env() {
  return withD1PatternLimit(freshEnv());
}

test('the emulation matches what workerd measured: 50 bytes run, 51 fail, counted in bytes', async () => {
  const env = d1Env();
  const db = env.DB;
  assert.equal(await db.prepare("SELECT 'a' GLOB ? AS x").bind('a' + '*'.repeat(49)).first('x'), 1);
  await assert.rejects(db.prepare("SELECT 'a' GLOB ? AS x").bind('a' + '*'.repeat(50)).first('x'), /pattern too complex/);
  await assert.rejects(db.prepare(`SELECT 'a' GLOB '${'[0-9]'.repeat(11)}' AS x`).first('x'), /pattern too complex/, 'literals count too');
  await assert.rejects(db.prepare("SELECT 'a' LIKE ? AS x").bind('ש'.repeat(26)).first('x'), /pattern too complex/, '52 bytes, 26 letters');
  // Matching itself is untouched.
  assert.equal(await db.prepare("SELECT 'ACME000001' GLOB 'ACME[0-9]*' AS x").first('x'), 1);
  assert.equal(await db.prepare("SELECT 'ACMEX' GLOB 'ACME[0-9]*' AS x").first('x'), 0);
  assert.equal(await db.prepare("SELECT 'A_b' LIKE ? ESCAPE '\\' AS x").bind('a\\_B').first('x'), 1);
  assert.equal(await db.prepare("SELECT 'axb' LIKE ? ESCAPE '\\' AS x").bind('a\\_b').first('x'), 0);
  assert.equal(await db.prepare('SELECT NULL GLOB ? AS x').bind('*').first('x'), null);
});

test('a claim left by a setup that died halfway answers 409, then expires — never a 500 (D1)', async () => {
  const env = d1Env();
  await client(env).get('/'); // creates the schema
  q(env, "INSERT INTO meta (key, value) VALUES ('setup_claim', ?)", `${iso(env.__clock() + 10 * MINUTE)}|crashed-isolate`);
  const blocked = await client(env).post('/api/setup', { ...GOOD, setup_key: env.SETUP_KEY });
  assert.equal(blocked.status, 409, blocked.text);
  assert.equal(blocked.body.code, 'setup_in_progress');
  advance(env, 9 * MINUTE);
  assert.equal((await client(env).post('/api/setup', { ...GOOD, setup_key: env.SETUP_KEY })).status, 409);
  advance(env, MINUTE);
  const ok = await client(env).post('/api/setup', { ...GOOD, setup_key: env.SETUP_KEY });
  assert.equal(ok.status, 200, ok.text);
  assert.equal(count(env, 'SELECT COUNT(*) FROM users'), 1);
  assert.equal(count(env, "SELECT COUNT(*) FROM meta WHERE key = 'setup_claim'"), 0, 'released after success');
  assert.equal(auditRows(env, 'error').length, 0, 'nothing failed unexpectedly');
});

test('an unreadable claim is retakeable under D1 (no shape check in SQL)', async () => {
  for (const bad of [null, '', 'garbage', '|', 'x|y', '2026-01-06T15:10:00Z|short-iso', `${'9'.repeat(24)}|digits`, '2026-01-06T15:10:00.000Z']) {
    const env = d1Env();
    await client(env).get('/');
    q(env, "INSERT INTO meta (key, value) VALUES ('setup_claim', ?)", bad);
    const r = await client(env).post('/api/setup', { ...GOOD, setup_key: env.SETUP_KEY });
    assert.equal(r.status, 200, `claim ${JSON.stringify(bad)}: ${r.text}`);
    assert.equal(auditRows(env, 'error').length, 0, `claim ${JSON.stringify(bad)}`);
  }
});

test('a well-formed claim that has not expired holds setup, whatever follows the bar', async () => {
  const env = d1Env();
  await client(env).get('/');
  q(env, "INSERT INTO meta (key, value) VALUES ('setup_claim', ?)", `${iso(env.__clock() + MINUTE)}|`);
  const r = await client(env).post('/api/setup', { ...GOOD, setup_key: env.SETUP_KEY });
  assert.equal(r.status, 409, r.text);
  assert.equal(count(env, 'SELECT COUNT(*) FROM users'), 0);
});

test('setups racing on D1: one 200, the rest 409 — never a 500', async () => {
  const env = d1Env();
  const rs = await Promise.all(
    Array.from({ length: 4 }, (_, i) => client(env).post('/api/setup', { ...GOOD, email: `racer${i}@acme.com`, setup_key: env.SETUP_KEY })),
  );
  assert.deepEqual(rs.map((r) => r.status).sort(), [200, 409, 409, 409], rs.map((r) => r.text).join('\n'));
  assert.equal(count(env, 'SELECT COUNT(*) FROM users'), 1);
  assert.equal(auditRows(env, 'error').length, 0);
});

test('the whole first-run story runs under D1’s pattern limit', async () => {
  const env = d1Env();
  const owner = await bootstrap(env, { ip: OWNER_IP });
  const c = owner.client;
  assert.equal((await c.get('/')).status, 200);
  for (const p of ['/api/me', '/api/me/streak', '/api/admin/overview', '/api/admin/users', '/api/admin/audit', '/api/admin/devices', '/api/admin/network']) {
    const r = await c.get(p);
    assert.equal(r.status, 200, `${p}: ${r.text}`);
  }
  await signOut(c);
  await signIn(env, c, OWNER.email, OWNER.password);
  assert.equal((await c.get('/api/me')).status, 200);
  assert.equal(auditRows(env, 'error').length, 0, JSON.stringify(auditRows(env, 'error').map((a) => a.error)));
});

await run();
