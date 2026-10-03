// Production D1 refuses what node:sqlite allows: more than 100 bound
// parameters, and LIKE/GLOB patterns over 50 bytes. Each of these was found by
// running the real worker under `wrangler dev`; every one had passed the whole
// node suite. The stand-in in tests/helpers/d1.js now enforces both limits, so
// these tests pin the stand-in itself and the four places that broke.

import { test, assert, run } from '../helpers/t.js';
import { makeEnvWithSchema } from '../helpers/env.js';
import { FakeD1, D1_MAX_PARAMS, D1_MAX_PATTERN_BYTES } from '../helpers/d1.js';
import { iso, HOUR, DAY, isoShapeSql } from '../../src/util.js';
import { isIpBlocked } from '../../src/network.js';
import { listUsers } from '../../src/users.js';
import { listAudit, audit } from '../../src/audit.js';
import { listDevices } from '../../src/devices.js';

const tooComplex = /LIKE or GLOB pattern too complex/;

test('the stand-in refuses what D1 refuses', async () => {
  const db = new FakeD1();
  db.sqlite.exec('CREATE TABLE t (a TEXT)');
  const many = Array.from({ length: D1_MAX_PARAMS + 1 }, (_, i) => i);
  await assert.rejects(db.prepare(`SELECT * FROM t WHERE a IN (${many.map(() => '?').join(',')})`).bind(...many).all(), /too many SQL variables/);
  const ok = many.slice(0, D1_MAX_PARAMS);
  await db.prepare(`SELECT * FROM t WHERE a IN (${ok.map(() => '?').join(',')})`).bind(...ok).all();

  const long = 'x'.repeat(D1_MAX_PATTERN_BYTES + 1);
  await assert.rejects(db.prepare(`SELECT * FROM t WHERE a GLOB '${long}'`).all(), tooComplex);
  await assert.rejects(db.prepare(`SELECT * FROM t WHERE a NOT LIKE '${long}'`).all(), tooComplex);
  await assert.rejects(db.prepare(`SELECT * FROM t WHERE a LIKE ? ESCAPE '\\'`).bind(long).all(), tooComplex);
  // Bytes, not characters: 26 Hebrew letters are 52 bytes.
  await assert.rejects(db.prepare('SELECT * FROM t WHERE a LIKE ?').bind('א'.repeat(26)).all(), tooComplex);
  // Exactly 50 bytes is allowed; a long string that is not a pattern is fine.
  await db.prepare(`SELECT * FROM t WHERE a GLOB '${'x'.repeat(D1_MAX_PATTERN_BYTES)}'`).all();
  await db.prepare('SELECT * FROM t WHERE a = ?').bind(long).all();
  await db.prepare(`SELECT * FROM t WHERE a = '${long}'`).all();
});

test('isoShapeSql: both halves fit the limit and the check is exact', async () => {
  const env = await makeEnvWithSchema();
  for (const [v, want] of [
    [iso(Date.UTC(2026, 0, 6, 15)), 1],
    ['2026-01-06T15:00:00Z', 0],
    ['garbage', 0],
    ['1', 0],
    ['2026-01-06T15:00:00.000Z ', 0],
    ['2026-01-06 15:00:00.000Z', 0],
  ]) {
    const r = await env.DB.prepare(`SELECT ${isoShapeSql('?')} AS ok`.replace(/\?/g, "'" + v.replace(/'/g, "''") + "'")).first();
    assert.equal(r.ok, want, v);
  }
});

test('an EXPIRED or unreadable IP block no longer takes the gate down', async () => {
  const env = await makeEnvWithSchema();
  const now = env.__clock();
  const add = (cidr, expires) =>
    env.DB.q('INSERT INTO blocked_ips (cidr, reason, expires_at, created_at) VALUES (?, ?, ?, ?)', cidr, 'test', expires, iso(now));
  add('91.198.174.0/24', iso(now - HOUR)); // expired: in production this row made every request a 500
  add('185.15.56.0/24', iso(now + HOUR)); // live
  add('81.2.69.0/24', '1'); // unreadable: sorts below now, must still block (fail closed)
  assert.equal(await isIpBlocked(env, '91.198.174.10', now), false, 'expired block lifted');
  assert.equal(await isIpBlocked(env, '185.15.56.10', now), true, 'live block holds');
  assert.equal(await isIpBlocked(env, '81.2.69.10', now), true, 'unreadable expiry keeps blocking');
  assert.equal(await isIpBlocked(env, '185.15.56.10', now + DAY), false, 'live block expires');
});

test('people and audit searches accept long and non-Latin queries', async () => {
  const env = await makeEnvWithSchema();
  const t = iso(env.__clock());
  env.DB.q("INSERT INTO users (email, full_name, role_id, status, created_at, updated_at) VALUES ('miriam@acme.com', 'מרים כהן', 1, 'active', ?, ?)", t, t);
  for (const q of ['m'.repeat(100), 'א'.repeat(60), '%_\\', 'מרים', 'MIRIAM@']) {
    const r = await listUsers(env, { q });
    assert.ok(Array.isArray(r.users), q);
  }
  assert.equal((await listUsers(env, { q: 'MIRIAM@' })).users.length, 1, 'case-insensitive substring');
  assert.equal((await listUsers(env, { q: 'מרים' })).users.length, 1, 'Hebrew name');
  assert.equal((await listUsers(env, { q: '%' })).users.length, 0, '% is a literal, not a wildcard');

  await audit({ env, nowMs: env.__clock() }, { action: 'user.edit', detail: 'Edited miriam@acme.com: full_name' });
  await audit({ env, nowMs: env.__clock() }, { action: 'login.success', detail: 'Signed in with an authenticator app' });
  for (const q of ['x'.repeat(200), 'א'.repeat(80)]) assert.deepEqual((await listAudit(env, { q })).entries, [], q);
  assert.equal((await listAudit(env, { action: 'login' })).entries.length, 1, 'action is a prefix match');
  assert.equal((await listAudit(env, { action: 'user.edit' })).entries.length, 1);
  assert.equal((await listAudit(env, { action: '%' })).entries.length, 0, '% is a literal');
  assert.equal((await listAudit(env, { action: 'x'.repeat(100) })).entries.length, 0);
  assert.equal((await listAudit(env, { q: 'AUTHENTICATOR' })).entries.length, 1, 'case-insensitive detail search');
});

test('the device inventory lists more than 100 devices', async () => {
  const env = await makeEnvWithSchema();
  const t = iso(env.__clock());
  env.DB.q("INSERT INTO users (email, full_name, role_id, status, created_at, updated_at) VALUES ('a@acme.com', 'A', 1, 'active', ?, ?)", t, t);
  for (let i = 0; i < 150; i++) {
    env.DB.q("INSERT INTO devices (id, status, first_seen, last_seen) VALUES (?, 'pending', ?, ?)", `dev${i}`, t, iso(env.__clock() - i * 1000));
    env.DB.q('INSERT INTO device_users (device_id, user_id, first_seen, last_seen, sign_ins) VALUES (?, 1, ?, ?, 1)', `dev${i}`, t, t);
  }
  const rows = await listDevices(env, { limit: 500 });
  assert.equal(rows.length, 150);
  assert.ok(rows.every((r) => r.users.length === 1), 'every device kept its ledger');
});

await run();
