import { test, assert, run } from '../helpers/t.js';
import { makeEnvWithSchema } from '../helpers/env.js';
import { iso, HOUR, DAY } from '../../src/util.js';
import { ValidationError, HttpError } from '../../src/errors.js';
import * as N from '../../src/network.js';

const HOSTILE = [null, undefined, NaN, Infinity, '', '   ', 'abc', {}, [], true, 0, Symbol('x')];
const show = (v) => (typeof v === 'symbol' ? 'Symbol' : JSON.stringify(v) ?? String(v));

function rcFor(env, o = {}) {
  return { env, nowMs: env.__clock(), ip: '81.2.69.10', user: { id: 1 }, setCookies: [], ...o };
}

const count = (env, table) => env.DB.q(`SELECT COUNT(*) AS n FROM ${table}`)[0].n;

const invalid = (field, re) => (e) => {
  assert.ok(e instanceof ValidationError, `expected ValidationError, got ${e && e.stack}`);
  if (field) assert.equal(e.body.field, field);
  if (re) assert.match(e.body.error, re);
  return true;
};

// Bypasses validation, for overlapping or corrupt rows.
function rawAllow(env, cidr, tier, expiresAt = null) {
  const t = iso(env.__clock());
  env.DB.q('INSERT INTO allowed_ips (cidr, tier, expires_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?)', cidr, tier, expiresAt, t, t);
  return env.DB.q('SELECT MAX(id) AS id FROM allowed_ips')[0].id;
}

// ---------------------------------------------------------------- validation

test('addAllowed refuses private and reserved ranges with an explanation, and writes nothing', async () => {
  const env = await makeEnvWithSchema();
  for (const cidr of ['10.0.0.0/8', '192.168.1.0/24', '172.16.0.0/12', '127.0.0.1', '100.64.0.0/10', '169.254.0.0/16', '203.0.113.0/24', '198.51.100.7', '::1', 'fc00::/7', 'fe80::/10', '2001:db8::/32', '10.0.0.0/7']) {
    await assert.rejects(N.addAllowed(rcFor(env), { cidr, tier: 1 }), invalid('cidr', /private or reserved.*could never match/), cidr);
  }
  assert.equal(count(env, 'allowed_ips'), 0);
});

test('addAllowed refuses the whole address family and points at the time-boxed switch', async () => {
  const env = await makeEnvWithSchema();
  for (const cidr of ['0.0.0.0/0', '::/0']) {
    await assert.rejects(N.addAllowed(rcFor(env), { cidr, tier: 1 }), invalid('cidr', /entire internet.*Open to the internet/), cidr);
  }
  await assert.rejects(N.addBlocked(rcFor(env), { cidr: '0.0.0.0/0' }), invalid('cidr', /lockdown/));
  assert.equal(count(env, 'allowed_ips') + count(env, 'blocked_ips'), 0);
});

test('a range with host bits set is refused with the range it sits in', async () => {
  const env = await makeEnvWithSchema();
  await assert.rejects(N.addAllowed(rcFor(env), { cidr: '81.2.69.7/24', tier: 2 }), invalid('cidr', /81\.2\.69\.0\/24/));
  await assert.rejects(N.addAllowed(rcFor(env), { cidr: '81.2.69.300', tier: 2 }), invalid('cidr', /not an IPv4 or IPv6/));
});

test('hostile cidr, tier, label, owner, user and expiry values are ValidationErrors and write nothing', async () => {
  const env = await makeEnvWithSchema();
  const ok = { cidr: '81.2.69.0/24', tier: 2 };
  for (const v of HOSTILE) {
    await assert.rejects(N.addAllowed(rcFor(env), { ...ok, cidr: v }), invalid('cidr'), `cidr ${show(v)}`);
    await assert.rejects(N.addAllowed(rcFor(env), { ...ok, tier: v }), invalid('tier'), `tier ${show(v)}`);
    if (v !== null && v !== undefined) {
      await assert.rejects(N.addAllowed(rcFor(env), { ...ok, expires_in_hours: v }), invalid('expires_in_hours'), `hours ${show(v)}`);
      await assert.rejects(N.addAllowed(rcFor(env), { ...ok, expires_at: v }), invalid('expires_at'), `expires_at ${show(v)}`);
      await assert.rejects(N.addAllowed(rcFor(env), { ...ok, user_id: v }), invalid('user_id'), `user_id ${show(v)}`);
    }
    if (typeof v !== 'string' && v !== null && v !== undefined) {
      await assert.rejects(N.addAllowed(rcFor(env), { ...ok, label: v }), invalid('label'), `label ${show(v)}`);
      await assert.rejects(N.addAllowed(rcFor(env), { ...ok, owner: v }), invalid('owner'), `owner ${show(v)}`);
    }
    if (v === undefined || (v && typeof v === 'object' && !Array.isArray(v))) continue;
    await assert.rejects(N.addAllowed(rcFor(env), v), invalid(), `input ${show(v)}`);
  }
  for (const tier of [0, 5, 1.5, '-1', '01x']) await assert.rejects(N.addAllowed(rcFor(env), { ...ok, tier }), invalid('tier'), show(tier));
  await assert.rejects(N.addAllowed(rcFor(env), { ...ok, label: 'x'.repeat(101) }), invalid('label'));
  await assert.rejects(N.addAllowed(rcFor(env), { ...ok, owner: 'x'.repeat(101) }), invalid('owner'));
  assert.equal(count(env, 'allowed_ips'), 0);
});

test('expiry: strict ISO in the future, or 1–8760 hours, never both; "42" is not 2042 (A §14.2)', async () => {
  const env = await makeEnvWithSchema();
  const t = env.__clock();
  const ok = { cidr: '81.2.69.0/24', tier: 2 };
  for (const expires_at of ['42', '2042', iso(t - 1000), iso(t), '2026-13-01T00:00:00Z', 'Tue Jan 06 2027']) {
    await assert.rejects(N.addAllowed(rcFor(env), { ...ok, expires_at }), invalid('expires_at'), expires_at);
  }
  for (const h of [0, -1, 8761, 1.5, '', ' ', '1e2x']) {
    await assert.rejects(N.addAllowed(rcFor(env), { ...ok, expires_in_hours: h }), invalid('expires_in_hours'), show(h));
  }
  await assert.rejects(N.addAllowed(rcFor(env), { ...ok, expires_at: iso(t + DAY), expires_in_hours: 2 }), invalid('expires_at', /not both/));
  const a = await N.addAllowed(rcFor(env), { ...ok, expires_in_hours: '3' });
  assert.equal(a.expires_at, iso(t + 3 * HOUR));
  const b = await N.addAllowed(rcFor(env), { cidr: '91.198.174.0/24', tier: 1, expires_at: '2026-03-01T09:00:00+01:00' });
  assert.equal(b.expires_at, '2026-03-01T08:00:00.000Z');
  const c = await N.addAllowed(rcFor(env), { cidr: '185.15.56.0/24', tier: 3, expires_at: null, label: '', owner: '  ' });
  assert.equal(c.expires_at, null, 'null means no expiry');
  assert.equal(c.label, null);
  assert.equal(c.owner, null);
});

test('addAllowed stores canonical text, the actor and the person; duplicates of a live entry are refused', async () => {
  const env = await makeEnvWithSchema();
  const t = iso(env.__clock());
  const role = env.DB.q("SELECT id FROM roles WHERE key = 'employee'")[0].id;
  env.DB.q("INSERT INTO users (email, role_id, created_at, updated_at) VALUES ('p@acme.com', ?, ?, ?)", role, t, t);
  const uid = env.DB.q('SELECT id FROM users')[0].id;
  const r = await N.addAllowed(rcFor(env, { user: { id: 42 } }), { cidr: ' 2A00:1450:4001:0::/48 ', tier: '2', label: ' Office ', owner: 'IT', user_id: uid });
  assert.equal(r.cidr, '2a00:1450:4001::/48');
  assert.equal(r.tier, 2);
  assert.equal(r.label, 'Office');
  assert.equal(r.user_id, uid);
  assert.equal(r.created_by, 42);
  const mapped = await N.addAllowed(rcFor(env), { cidr: '::ffff:81.2.69.0/120', tier: 3 });
  assert.equal(mapped.cidr, '81.2.69.0/24', 'IPv4-mapped is stored as IPv4');
  await assert.rejects(N.addAllowed(rcFor(env), { cidr: '81.2.69.0/24', tier: 1 }), invalid('cidr', /already on the allowlist/));
  await assert.rejects(N.addAllowed(rcFor(env), { cidr: '81.2.69.0/24', tier: 1, user_id: 999 }), invalid('user_id'));
});

test('tier 4 without an expiry gets 24 hours and then grants nothing', async () => {
  const env = await makeEnvWithSchema();
  const t0 = env.__clock();
  const r = await N.addAllowed(rcFor(env), { cidr: '81.2.69.0/24', tier: 4 });
  assert.equal(r.expires_at, iso(t0 + DAY));
  const short = await N.addAllowed(rcFor(env), { cidr: '91.198.174.0/24', tier: 4, expires_in_hours: 2 });
  assert.equal(short.expires_at, iso(t0 + 2 * HOUR));
  assert.equal((await N.tierForIp(env, '81.2.69.10', t0 + DAY - 1))?.tier, 4);
  assert.equal(await N.tierForIp(env, '81.2.69.10', t0 + DAY), null);
  assert.equal((await N.listAllowed(env, t0 + DAY)).find((x) => x.id === r.id).active, false, 'expired rows are kept, inactive');
});

// ---------------------------------------------------------------- matching

test('tierForIp: most specific wins; on an exact tie the stricter tier wins', async () => {
  const env = await makeEnvWithSchema();
  const t = env.__clock();
  rawAllow(env, '81.2.0.0/16', 1);
  const carve = rawAllow(env, '81.2.69.0/24', 3);
  assert.equal((await N.tierForIp(env, '81.2.69.10', t)).tier, 3);
  assert.equal((await N.tierForIp(env, '81.2.69.10', t)).entry.id, carve);
  assert.equal((await N.tierForIp(env, '81.2.70.10', t)).tier, 1);
  rawAllow(env, '91.198.174.0/24', 1);
  rawAllow(env, '91.198.174.0/24', 2);
  assert.equal((await N.tierForIp(env, '91.198.174.9', t)).tier, 2, 'tie → stricter');
  rawAllow(env, '2a00:1450::/32', 2);
  assert.equal((await N.tierForIp(env, '2a00:1450:4001::1', t)).tier, 2);
  assert.equal((await N.tierForIp(env, '::ffff:81.2.69.10', t)).tier, 3, 'mapped v6 matches the v4 entry');
  assert.equal(await N.tierForIp(env, '185.15.56.1', t), null);
});

test('expired and unreadable-expiry entries grant nothing; an unreadable tier reads as 4', async () => {
  const env = await makeEnvWithSchema();
  const t = env.__clock();
  rawAllow(env, '81.2.69.0/24', 1, iso(t - 1));
  rawAllow(env, '91.198.174.0/24', 1, 'zzzz-not-a-date');
  rawAllow(env, '91.198.175.0/24', 1, '9999');
  rawAllow(env, '185.15.56.0/24', 'x');
  rawAllow(env, '185.15.57.0/24', 9);
  assert.equal(await N.tierForIp(env, '81.2.69.10', t), null);
  assert.equal(await N.tierForIp(env, '91.198.174.10', t), null);
  assert.equal(await N.tierForIp(env, '91.198.175.10', t), null);
  assert.equal((await N.tierForIp(env, '185.15.56.10', t)).tier, 4);
  assert.equal((await N.tierForIp(env, '185.15.57.10', t)).tier, 4);
  assert.equal(await N.liveCount(env, t), 2);
});

test('tierForIp, isIpBlocked, coveringEntries never throw on hostile addresses; blocked is the answer for none', async () => {
  const env = await makeEnvWithSchema();
  const t = env.__clock();
  rawAllow(env, '81.2.69.0/24', 1);
  for (const v of HOSTILE) {
    assert.equal(await N.tierForIp(env, v, t), null, show(v));
    assert.equal(await N.isIpBlocked(env, v, t), true, show(v));
    assert.deepEqual(await N.coveringEntries(env, v, t), [], show(v));
  }
});

test('isIpBlocked: live blocks only; an unreadable expiry keeps blocking', async () => {
  const env = await makeEnvWithSchema();
  const t = env.__clock();
  const rc = rcFor(env);
  await N.addBlocked(rc, { cidr: '91.198.174.0/24', reason: 'scanner', expires_in_hours: 1 });
  assert.equal(await N.isIpBlocked(env, '91.198.174.20', t), true);
  assert.equal(await N.isIpBlocked(env, '91.198.174.20', t + HOUR), false);
  assert.equal(await N.isIpBlocked(env, '81.2.69.10', t), false);
  env.DB.q("INSERT INTO blocked_ips (cidr, expires_at, created_at) VALUES ('185.15.56.0/24', 'garbage', ?)", iso(t));
  env.DB.q("INSERT INTO blocked_ips (cidr, expires_at, created_at) VALUES ('185.15.57.0/24', '0', ?)", iso(t));
  assert.equal(await N.isIpBlocked(env, '185.15.56.1', t), true);
  assert.equal(await N.isIpBlocked(env, '185.15.57.1', t), true);
  for (const cidr of ['10.0.0.0/8', '::/0', ...HOSTILE]) await assert.rejects(N.addBlocked(rc, { cidr }), invalid('cidr'), show(cidr));
  await assert.rejects(N.addBlocked(rc, { cidr: '81.2.69.0/24', reason: 'x'.repeat(201) }), invalid('reason'));
  const { row } = await N.removeBlocked(rc, env.DB.q("SELECT id FROM blocked_ips WHERE cidr = '91.198.174.0/24'")[0].id);
  assert.equal(row.reason, 'scanner');
  for (const v of HOSTILE) await assert.rejects(N.removeBlocked(rc, v), (e) => e instanceof HttpError && e.status === 404, show(v));
});

test('coveringEntries and liveCount: live only, with excludeId — what the anti-lockout guards ask', async () => {
  const env = await makeEnvWithSchema();
  const t = env.__clock();
  const wide = rawAllow(env, '81.2.0.0/16', 2);
  const narrow = rawAllow(env, '81.2.69.0/24', 1);
  rawAllow(env, '81.2.69.0/25', 1, iso(t - 1));
  rawAllow(env, '91.198.174.0/24', 1);
  assert.deepEqual((await N.coveringEntries(env, '81.2.69.10', t)).map((r) => r.id), [wide, narrow]);
  assert.deepEqual((await N.coveringEntries(env, '81.2.69.10', t, { excludeId: narrow })).map((r) => r.id), [wide]);
  assert.deepEqual((await N.coveringEntries(env, '81.2.69.10', t, { excludeId: String(wide) })).map((r) => r.id), [narrow]);
  assert.equal(await N.liveCount(env, t), 3);
  assert.equal(await N.liveCount(env, t, { excludeId: wide }), 2);
  for (const v of HOSTILE) assert.equal(await N.liveCount(env, t, { excludeId: v }), 3, show(v));
});

test('listAllowed / listBlocked: every row with active and covers_ip', async () => {
  const env = await makeEnvWithSchema();
  const t = env.__clock();
  rawAllow(env, '81.2.69.0/24', 1);
  rawAllow(env, '91.198.174.0/24', 2, iso(t - 1));
  const rows = await N.listAllowed(env, t, '81.2.69.10');
  assert.deepEqual(rows.map((r) => [r.cidr, r.active, r.covers_ip]), [['81.2.69.0/24', true, true], ['91.198.174.0/24', false, false]]);
  assert.ok(!('covers_ip' in (await N.listAllowed(env, t))[0]));
  await N.addBlocked(rcFor(env), { cidr: '185.15.56.0/24' });
  assert.deepEqual((await N.listBlocked(env, t, '185.15.56.3')).map((r) => [r.active, r.covers_ip]), [[true, true]]);
});

// ---------------------------------------------------------------- editing

test('editAllowed: prior and row; the range is not editable; nothing to change is refused', async () => {
  const env = await makeEnvWithSchema();
  const t = env.__clock();
  const a = await N.addAllowed(rcFor(env), { cidr: '81.2.69.0/24', tier: 1, label: 'HQ' });
  env.__advance(1000);
  const { prior, row } = await N.editAllowed(rcFor(env), a.id, { tier: 2, label: 'Head office', expires_in_hours: 5 });
  assert.equal(prior.tier, 1);
  assert.equal(prior.label, 'HQ');
  assert.equal(row.tier, 2);
  assert.equal(row.label, 'Head office');
  assert.equal(row.expires_at, iso(t + 1000 + 5 * HOUR));
  assert.equal(row.updated_at, iso(t + 1000));
  const back = await N.editAllowed(rcFor(env), a.id, { expires_at: null });
  assert.equal(back.row.expires_at, null);
  await assert.rejects(N.editAllowed(rcFor(env), a.id, { cidr: '81.2.70.0/24' }), invalid('cidr'));
  await assert.rejects(N.editAllowed(rcFor(env), a.id, {}), invalid(undefined, /Nothing to change/));
  await assert.rejects(N.editAllowed(rcFor(env), a.id, { colour: 'red' }), invalid(undefined, /Nothing to change/));
  for (const v of HOSTILE) {
    await assert.rejects(N.editAllowed(rcFor(env), v, { tier: 2 }), (e) => e instanceof HttpError && e.status === 404, show(v));
    if (v !== undefined) await assert.rejects(N.editAllowed(rcFor(env), a.id, { tier: v }), invalid('tier'), show(v));
  }
  assert.equal(env.DB.q('SELECT tier FROM allowed_ips')[0].tier, 2);
});

test('editAllowed to tier 4 gets 24 hours; an expired entry is not revived by a tier change', async () => {
  const env = await makeEnvWithSchema();
  const t = env.__clock();
  const a = await N.addAllowed(rcFor(env), { cidr: '81.2.69.0/24', tier: 1 });
  const r = await N.editAllowed(rcFor(env), a.id, { tier: 4 });
  assert.equal(r.row.expires_at, iso(t + DAY));
  const old = rawAllow(env, '91.198.174.0/24', 1, iso(t - HOUR));
  const r2 = await N.editAllowed(rcFor(env), old, { tier: 4 });
  assert.equal(r2.row.expires_at, iso(t - HOUR));
  assert.equal(await N.tierForIp(env, '91.198.174.1', t), null);
});

test('removeAllowed returns the row it removed; unknown ids are 404', async () => {
  const env = await makeEnvWithSchema();
  const a = await N.addAllowed(rcFor(env), { cidr: '81.2.69.0/24', tier: 1 });
  const { row } = await N.removeAllowed(rcFor(env), a.id);
  assert.equal(row.cidr, '81.2.69.0/24');
  assert.equal(count(env, 'allowed_ips'), 0);
  await assert.rejects(N.removeAllowed(rcFor(env), a.id), (e) => e instanceof HttpError && e.status === 404);
});

await run();
