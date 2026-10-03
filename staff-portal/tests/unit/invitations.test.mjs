import { test, assert, run } from '../helpers/t.js';
import { makeEnvWithSchema } from '../helpers/env.js';
import { iso, HOUR, DAY } from '../../src/util.js';
import { sha256Hex, verifyPassword } from '../../src/crypto.js';
import { effectivePermissions } from '../../src/rbac.js';
import { GuardError, ValidationError, HttpError } from '../../src/errors.js';
import * as I from '../../src/invitations.js';
import { createUser, setStatus } from '../../src/users.js';

const HOSTILE = [null, undefined, NaN, Infinity, '', '   ', 'abc', {}, [], true, 0, Symbol('x')];
const show = (v) => (typeof v === 'symbol' ? 'Symbol' : JSON.stringify(v) ?? String(v));
const PW = 'correct horse battery';

function roleRow(env, key) {
  return env.DB.q('SELECT * FROM roles WHERE key = ?', key)[0];
}

let seq = 0;
function addUser(env, roleKey, o = {}) {
  const n = ++seq;
  const t = iso(env.__clock());
  const email = o.email ?? `i${n}@acme.com`;
  const status = o.status ?? 'active';
  env.DB.q(
    `INSERT INTO users (email, full_name, status, role_id, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
    email,
    `I ${n}`,
    status,
    roleRow(env, roleKey).id,
    status === 'invited' ? null : 'placeholder',
    t,
    t,
  );
  return env.DB.q('SELECT * FROM users WHERE email = ?', email)[0];
}

const user = (env, id) => env.DB.q('SELECT * FROM users WHERE id = ?', id)[0];
const invRow = (env, id) => env.DB.q('SELECT * FROM invitations WHERE id = ?', id)[0];
const count = (env, sql, ...a) => env.DB.q(sql, ...a)[0].n;

async function rcAs(env, u, extra = {}) {
  const nowMs = env.__clock();
  return { env, nowMs, user: u, authz: u ? await effectivePermissions(env, u, nowMs) : null, ip: '81.2.69.10', cf: { country: 'US' }, setCookies: [], ...extra };
}

// A stranger's request: no session, maybe a device.
function anon(env, extra = {}) {
  return { env, nowMs: env.__clock(), ip: '91.198.174.20', cf: { country: 'GB' }, device: { id: null, row: null }, setCookies: [], ...extra };
}

function addDevice(env, id, status) {
  const t = iso(env.__clock());
  env.DB.q('INSERT INTO devices (id, status, first_seen, last_seen) VALUES (?, ?, ?, ?)', id, status, t, t);
}

async function invited(env, { roleKey = 'employee', by } = {}) {
  const admin = by ?? addUser(env, 'admin');
  const rc = await rcAs(env, admin);
  const u = await createUser(rc, { email: `new${++seq}@acme.com`, full_name: 'New Person', role_id: roleRow(env, roleKey).id });
  const inv = await I.createInvitation(rc, u.id);
  return { admin, rc, u, inv };
}

const http = (status, re) => (e) => {
  assert.ok(e instanceof HttpError, `expected HttpError(${status}), got ${e && e.stack}`);
  assert.equal(e.status, status, e.message);
  if (re) assert.match(e.body.error, re);
  return true;
};
const invalid = (field) => (e) => {
  assert.ok(e instanceof ValidationError, `expected ValidationError, got ${e && e.stack}`);
  if (field) assert.equal(e.body.field, field);
  return true;
};

// ---------------------------------------------------------------- invitations

test('createInvitation: the token lives only in the link; the database keeps its SHA-256; seven days', async () => {
  const env = await makeEnvWithSchema();
  const { admin, u, inv } = await invited(env);
  assert.deepEqual(Object.keys(inv).sort(), ['expires_at', 'id', 'token', 'url']);
  assert.match(inv.token, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(inv.url, `https://staff.example.com/invite?token=${inv.token}`);
  assert.equal(inv.expires_at, iso(env.__clock() + 7 * DAY));
  const row = invRow(env, inv.id);
  assert.equal(row.token_hash, await sha256Hex(inv.token));
  assert.ok(!Object.values(row).some((v) => typeof v === 'string' && v.includes(inv.token)), 'token never stored');
  assert.equal(row.email, u.email);
  assert.equal(row.role_id, u.role_id);
  assert.equal(row.created_by, admin.id);
  assert.equal(row.used_at, null);

  const env2 = await makeEnvWithSchema({ vars: { ORIGIN: 'not a url' } });
  assert.match((await invited(env2)).inv.url, /^\/invite\?token=[A-Za-z0-9_-]{43}$/);
});

test('createInvitation: a new link revokes the earlier ones; only an invited account; rank-guarded', async () => {
  const env = await makeEnvWithSchema();
  const { rc, u, inv } = await invited(env, { roleKey: 'auditor' });
  const again = await I.reissueInvitation(rc, u.id);
  assert.ok(invRow(env, inv.id).revoked_at, 'the first link is revoked');
  assert.equal(await I.lookupInvitation(env, inv.token, env.__clock()), null);
  assert.ok(await I.lookupInvitation(env, again.token, env.__clock()));

  const mgr = addUser(env, 'manager');
  await assert.rejects(I.reissueInvitation(await rcAs(env, mgr), u.id), (e) => e instanceof GuardError && e.code === 'rank');
  assert.equal(invRow(env, again.id).revoked_at, null, 'a refused reissue revokes nothing');
  await assert.rejects(I.createInvitation(rc, addUser(env, 'employee').id), http(409));
  for (const v of HOSTILE) await assert.rejects(I.createInvitation(rc, v), http(404), show(v));
});

test('lookupInvitation: expired, revoked, used, wrong, malformed (never queried), or the account moved on', async () => {
  const env = await makeEnvWithSchema();
  const { rc, u, inv } = await invited(env);
  const t = env.__clock();
  const found = await I.lookupInvitation(env, inv.token, t);
  assert.equal(found.user.id, u.id);
  assert.equal(found.invitation.id, inv.id);
  assert.ok(!('token_hash' in found.invitation));
  assert.equal(await I.lookupInvitation(env, inv.token, t + 7 * DAY), null, 'expired at the instant');
  assert.ok(await I.lookupInvitation(env, inv.token, t + 7 * DAY - 1));

  const flipped = inv.token[0] === 'A' ? 'B' + inv.token.slice(1) : 'A' + inv.token.slice(1);
  assert.equal(await I.lookupInvitation(env, flipped, t), null);
  env.DB.failOn = /invitations/;
  for (const v of [...HOSTILE, inv.token + 'A', inv.token.slice(1), ` ${inv.token.slice(1)}`, inv.token.replace(/.$/, '='), 'x'.repeat(5000)]) {
    assert.equal(await I.lookupInvitation(env, v, t), null, show(v));
  }
  env.DB.failOn = null;
  for (const v of [NaN, undefined, 'abc', null]) assert.ok(await I.lookupInvitation(env, inv.token, v), `clock ${show(v)} → now`);

  env.DB.q("UPDATE invitations SET expires_at = 'garbage' WHERE id = ?", inv.id);
  assert.equal(await I.lookupInvitation(env, inv.token, t), null, 'an unreadable expiry has expired');
  env.DB.q('UPDATE invitations SET expires_at = ? WHERE id = ?', iso(t + DAY), inv.id);
  await setStatus(rc, u.id, 'disabled');
  assert.equal(await I.lookupInvitation(env, inv.token, t), null, 'disabling revoked it');
  env.DB.q('UPDATE invitations SET revoked_at = NULL WHERE id = ?', inv.id);
  assert.equal(await I.lookupInvitation(env, inv.token, t), null, 'and the account is no longer invited');
});

test('acceptInvitation: sets their password, activates, spends the link, approves the device it was accepted on', async () => {
  const env = await makeEnvWithSchema();
  const { admin, u, inv } = await invited(env);
  addDevice(env, 'dev-new', 'pending');
  const out = await I.acceptInvitation(anon(env, { device: { id: 'dev-new', row: {} } }), inv.token, { password: PW, full_name: '  Jane Q. Doe ' });
  assert.equal(out.id, u.id);
  assert.equal(out.status, 'active');
  assert.equal(out.full_name, 'Jane Q. Doe');
  assert.equal(out.must_change_password, 0);
  assert.equal(await verifyPassword(PW, out), true);
  assert.ok(invRow(env, inv.id).used_at);
  const dev = env.DB.q("SELECT * FROM devices WHERE id = 'dev-new'")[0];
  assert.equal(dev.status, 'approved');
  assert.equal(dev.approved_by, admin.id, 'the invitation is the administrator’s approval');

  const second = await invited(env);
  const out2 = await I.acceptInvitation(anon(env), second.inv.token, { password: PW });
  assert.equal(out2.full_name, 'New Person', 'name optional');
  assert.equal(out2.status, 'active');
});

test('acceptInvitation: a link works once; a double submit activates once', async () => {
  const env = await makeEnvWithSchema();
  const { u, inv } = await invited(env);
  await I.acceptInvitation(anon(env), inv.token, { password: PW });
  await assert.rejects(I.acceptInvitation(anon(env), inv.token, { password: 'another long passphrase' }), http(404));
  assert.equal(await verifyPassword(PW, user(env, u.id)), true, 'the second attempt changed nothing');

  const b = await invited(env);
  addDevice(env, 'dev-a', 'pending');
  addDevice(env, 'dev-b', 'pending');
  const results = await Promise.allSettled([
    I.acceptInvitation(anon(env, { device: { id: 'dev-a' } }), b.inv.token, { password: 'first long passphrase' }),
    I.acceptInvitation(anon(env, { device: { id: 'dev-b' } }), b.inv.token, { password: 'second long passphrase' }),
  ]);
  const won = results.findIndex((r) => r.status === 'fulfilled');
  assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1);
  http(404)(results[1 - won].reason);
  const pw = won === 0 ? 'first long passphrase' : 'second long passphrase';
  assert.equal(await verifyPassword(pw, user(env, b.u.id)), true);
  const statuses = env.DB.q("SELECT id, status FROM devices WHERE id IN ('dev-a', 'dev-b') ORDER BY id").map((d) => d.status);
  assert.deepEqual(statuses, won === 0 ? ['approved', 'pending'] : ['pending', 'approved'], 'only the winner’s device');
});

test('acceptInvitation: a weak password or bad name changes nothing and leaves the link usable', async () => {
  const env = await makeEnvWithSchema();
  const { u, inv } = await invited(env);
  addDevice(env, 'dev-x', 'pending');
  const rc = anon(env, { device: { id: 'dev-x' } });
  await assert.rejects(I.acceptInvitation(rc, inv.token, { password: 'short' }), invalid('password'));
  await assert.rejects(I.acceptInvitation(rc, inv.token, { password: u.email }), invalid('password'));
  await assert.rejects(I.acceptInvitation(rc, inv.token, { password: PW, full_name: 'x'.repeat(201) }), invalid('full_name'));
  for (const v of [0, true, {}, [], Symbol('x'), NaN]) {
    await assert.rejects(I.acceptInvitation(rc, inv.token, { password: PW, full_name: v }), invalid('full_name'), show(v));
  }
  for (const v of HOSTILE) {
    if (v !== 'abc') await assert.rejects(I.acceptInvitation(rc, inv.token, { password: v }), invalid('password'), show(v));
    await assert.rejects(I.acceptInvitation(rc, inv.token, v), invalid('password'), `body ${show(v)}`);
  }
  assert.equal(user(env, u.id).status, 'invited');
  assert.equal(user(env, u.id).password_hash, null);
  assert.equal(invRow(env, inv.id).used_at, null);
  assert.equal(env.DB.q("SELECT status FROM devices WHERE id = 'dev-x'")[0].status, 'pending');
  assert.equal((await I.acceptInvitation(rc, inv.token, { password: PW, full_name: '   ' })).status, 'active');
});

test('acceptInvitation: hostile and stale tokens are the same 404, and touch nothing', async () => {
  const env = await makeEnvWithSchema();
  const { u, inv } = await invited(env);
  for (const v of [...HOSTILE, inv.token.slice(1), 'A'.repeat(43)]) {
    await assert.rejects(I.acceptInvitation(anon(env), v, { password: PW }), http(404, /no longer valid/), show(v));
  }
  env.__advance(8 * DAY);
  await assert.rejects(I.acceptInvitation(anon(env), inv.token, { password: PW }), http(404, /no longer valid/));
  assert.equal(user(env, u.id).status, 'invited');
});

test('acceptInvitation: revoked after lookup → refused; disabled after the claim → link spent, nobody activated', async () => {
  const env = await makeEnvWithSchema();
  const { u, inv } = await invited(env);
  const origPrepare = env.DB.prepare.bind(env.DB);
  const before = (re, fn) => {
    let done = false;
    env.DB.prepare = (sql) => {
      if (!done && re.test(sql)) {
        done = true;
        fn();
      }
      return origPrepare(sql);
    };
  };
  before(/^UPDATE invitations SET used_at/, () => env.DB.q('UPDATE invitations SET revoked_at = ? WHERE id = ?', iso(env.__clock()), inv.id));
  await assert.rejects(I.acceptInvitation(anon(env), inv.token, { password: PW }), http(404));
  assert.equal(user(env, u.id).status, 'invited');
  assert.equal(invRow(env, inv.id).used_at, null);

  const b = await invited(env);
  addDevice(env, 'dev-z', 'pending');
  before(/^\s*UPDATE users SET password_hash/, () => env.DB.q("UPDATE users SET status = 'disabled' WHERE id = ?", b.u.id));
  await assert.rejects(I.acceptInvitation(anon(env, { device: { id: 'dev-z' } }), b.inv.token, { password: PW }), http(404));
  env.DB.prepare = origPrepare;
  assert.equal(user(env, b.u.id).status, 'disabled');
  assert.equal(user(env, b.u.id).password_hash, null);
  assert.ok(invRow(env, b.inv.id).used_at, 'the link stays spent');
  assert.equal(env.DB.q("SELECT status FROM devices WHERE id = 'dev-z'")[0].status, 'pending');
});

test('acceptInvitation: a blocked device stays blocked; an approved one keeps its approver; a write failure gives the link back', async () => {
  const env = await makeEnvWithSchema();
  const a = await invited(env);
  addDevice(env, 'dev-blocked', 'blocked');
  await I.acceptInvitation(anon(env, { device: { id: 'dev-blocked' } }), a.inv.token, { password: PW });
  assert.equal(env.DB.q("SELECT status FROM devices WHERE id = 'dev-blocked'")[0].status, 'blocked');

  const b = await invited(env);
  addDevice(env, 'dev-approved', 'approved');
  env.DB.q("UPDATE devices SET approved_by = 999 WHERE id = 'dev-approved'");
  await I.acceptInvitation(anon(env, { device: { id: 'dev-approved' } }), b.inv.token, { password: PW });
  assert.equal(env.DB.q("SELECT approved_by FROM devices WHERE id = 'dev-approved'")[0].approved_by, 999);

  const c = await invited(env);
  env.DB.failOn = /^\s*UPDATE users SET password_hash/;
  await assert.rejects(I.acceptInvitation(anon(env), c.inv.token, { password: PW }), /injected failure/);
  env.DB.failOn = null;
  assert.equal(invRow(env, c.inv.id).used_at, null, 'retryable');
  assert.equal((await I.acceptInvitation(anon(env), c.inv.token, { password: PW })).status, 'active');
});

test('revokeInvitation, listInvitations (never token material)', async () => {
  const env = await makeEnvWithSchema();
  const { rc, inv } = await invited(env);
  const other = await invited(env, { by: rc.user });
  const used = await invited(env, { by: rc.user });
  await I.acceptInvitation(anon(env), used.inv.token, { password: PW });

  const { row } = await I.revokeInvitation(rc, inv.id);
  assert.ok(row.revoked_at);
  assert.ok(!('token_hash' in row));
  await assert.rejects(I.revokeInvitation(rc, inv.id), http(409));
  await assert.rejects(I.revokeInvitation(rc, used.inv.id), http(409));
  await assert.rejects(I.revokeInvitation(await rcAs(env, addUser(env, 'guest')), other.inv.id), (e) => e instanceof GuardError && e.code === 'rank');
  for (const v of HOSTILE) await assert.rejects(I.revokeInvitation(rc, v), http(404), show(v));

  const all = await I.listInvitations(env, {});
  assert.equal(all.length, 3);
  assert.deepEqual(all.map((r) => r.state).sort(), ['pending', 'revoked', 'used']);
  const text = JSON.stringify(all);
  assert.ok(!text.includes('token_hash'));
  for (const t of [inv.token, other.inv.token, await sha256Hex(other.inv.token)]) assert.ok(!text.includes(t));
  const pending = await I.listInvitations(env, { pending: true });
  assert.deepEqual(pending.map((r) => r.id), [other.inv.id]);
  env.__advance(8 * DAY);
  assert.deepEqual(await I.listInvitations(env, { pending: true }), []);
  for (const v of HOSTILE) assert.equal((await I.listInvitations(env, v)).length, 3, show(v));
});

// ---------------------------------------------------------------- access requests

test('createAccessRequest: the same reply whether or not the email is known; one pending request per address', async () => {
  const env = await makeEnvWithSchema();
  addUser(env, 'employee', { email: 'known@acme.com' });
  const rc = anon(env, { fp: { hash: 'ab'.repeat(32), risk: 10 }, gate: { risk: { score: 42 } } });
  const known = await I.createAccessRequest(rc, { email: 'Known@Acme.com', full_name: 'K', reason: 'I work here' });
  const unknown = await I.createAccessRequest(rc, { email: 'stranger@example.org', full_name: 'S', reason: 'Please' });
  assert.deepEqual(known, { ok: true });
  assert.equal(JSON.stringify(known), JSON.stringify(unknown));
  const again = await I.createAccessRequest(rc, { email: 'stranger@example.org', full_name: 'S again', reason: 'Still me' });
  assert.deepEqual(again, { ok: true });
  assert.equal(count(env, "SELECT COUNT(*) AS n FROM access_requests WHERE email = 'stranger@example.org'"), 1, 'not duplicated');
  const r = env.DB.q("SELECT * FROM access_requests WHERE email = 'stranger@example.org'")[0];
  assert.equal(r.full_name, 'S');
  assert.equal(r.reason, 'Please');
  assert.equal(r.ip, '91.198.174.20');
  assert.equal(r.country, 'GB');
  assert.equal(r.visitor_id, 'ab'.repeat(32));
  assert.equal(r.risk, 42);
  assert.equal(r.status, 'pending');

  // Once decided, the same address may ask again.
  env.DB.q("UPDATE access_requests SET status = 'denied' WHERE id = ?", r.id);
  await I.createAccessRequest(rc, { email: 'stranger@example.org', full_name: 'S', reason: 'Please?' });
  assert.equal(count(env, "SELECT COUNT(*) AS n FROM access_requests WHERE email = 'stranger@example.org'"), 2);
});

test('createAccessRequest: validation, hostile input, odd context, and five per address per hour', async () => {
  const env = await makeEnvWithSchema();
  const rc = anon(env, { cf: { country: '<script>' }, fp: { hash: 'not-hex' }, gate: { risk: { score: 'high' } } });
  const ok = { email: 'a@example.org', full_name: 'A' };
  for (const v of HOSTILE) {
    env.DB.q('DELETE FROM auth_attempts');
    await assert.rejects(I.createAccessRequest(rc, { ...ok, email: v }), invalid('email'), `email ${show(v)}`);
    if (v !== 'abc') await assert.rejects(I.createAccessRequest(rc, { ...ok, full_name: v }), invalid('full_name'), `name ${show(v)}`);
    await assert.rejects(I.createAccessRequest(rc, v), invalid('email'), `body ${show(v)}`);
    if (v !== null && v !== undefined && typeof v !== 'string') {
      await assert.rejects(I.createAccessRequest(rc, { ...ok, reason: v }), invalid('reason'), `reason ${show(v)}`);
    }
  }
  await assert.rejects(I.createAccessRequest(rc, { ...ok, reason: 'x'.repeat(1001) }), invalid('reason'));
  assert.equal(count(env, 'SELECT COUNT(*) AS n FROM access_requests'), 0);
  env.DB.q('DELETE FROM auth_attempts');
  await I.createAccessRequest(rc, ok);
  const r = env.DB.q('SELECT * FROM access_requests')[0];
  assert.equal(r.country, null);
  assert.equal(r.visitor_id, null);
  assert.equal(r.risk, null);
  assert.equal(r.reason, null);

  env.DB.q('DELETE FROM auth_attempts');
  for (let i = 0; i < 5; i++) await I.createAccessRequest(rc, { email: `r${i}@example.org`, full_name: 'R' });
  await assert.rejects(I.createAccessRequest(rc, { email: 'r9@example.org', full_name: 'R' }), http(429));
  await assert.rejects(I.createAccessRequest(rc, { email: 'bad' }), http(429), 'charged before validation');
  assert.equal(count(env, "SELECT COUNT(*) AS n FROM access_requests WHERE email = 'r9@example.org'"), 0);
  await I.createAccessRequest(anon(env, { ip: '185.15.56.1' }), { email: 'r9@example.org', full_name: 'R' });
});

test('approveAccessRequest: invited account + invitation; the request remembers it; minting; decided once', async () => {
  const env = await makeEnvWithSchema();
  await I.createAccessRequest(anon(env), { email: 'Newbie@Example.org', full_name: 'New Bie', reason: 'Hi' });
  await I.createAccessRequest(anon(env), { email: 'second@example.org', full_name: 'Second' });
  const [r1, r2] = (await I.listAccessRequests(env, { status: 'pending' })).sort((a, b) => a.id - b.id);
  const admin = addUser(env, 'admin');
  const rc = await rcAs(env, admin);

  await assert.rejects(I.approveAccessRequest(rc, r1.id, { role_id: roleRow(env, 'admin').id }), (e) => e instanceof GuardError && e.code === 'minting');
  assert.equal(env.DB.q('SELECT status FROM access_requests WHERE id = ?', r1.id)[0].status, 'pending');
  assert.equal(count(env, "SELECT COUNT(*) AS n FROM users WHERE email = 'newbie@example.org'"), 0);

  const { user: u, invitation } = await I.approveAccessRequest(rc, r1.id, { role_id: roleRow(env, 'employee').id });
  assert.equal(u.email, 'newbie@example.org');
  assert.equal(u.full_name, 'New Bie');
  assert.equal(u.status, 'invited');
  assert.match(invitation.url, /\/invite\?token=/);
  const after = env.DB.q('SELECT * FROM access_requests WHERE id = ?', r1.id)[0];
  assert.equal(after.status, 'approved');
  assert.equal(after.invitation_id, invitation.id);
  assert.equal(after.decided_by, admin.id);
  assert.ok((await I.lookupInvitation(env, invitation.token, env.__clock())).user.id === u.id);
  await assert.rejects(I.approveAccessRequest(rc, r1.id, { role_id: roleRow(env, 'employee').id }), http(409));

  await I.denyAccessRequest(rc, r2.id);
  assert.equal(env.DB.q('SELECT status FROM access_requests WHERE id = ?', r2.id)[0].status, 'denied');
  await assert.rejects(I.denyAccessRequest(rc, r2.id), http(409));
  await assert.rejects(I.approveAccessRequest(rc, r2.id, { role_id: roleRow(env, 'employee').id }), http(409));

  // A known address surfaces createUser's sentence to the reviewer.
  await I.createAccessRequest(anon(env), { email: admin.email, full_name: 'Me Again' });
  const r3 = (await I.listAccessRequests(env, { status: 'pending' }))[0];
  await assert.rejects(I.approveAccessRequest(rc, r3.id, { role_id: roleRow(env, 'employee').id }), http(409, /already has that email/));

  for (const v of HOSTILE) {
    await assert.rejects(I.approveAccessRequest(rc, v, { role_id: 1 }), http(404), show(v));
    await assert.rejects(I.denyAccessRequest(rc, v), http(404), show(v));
    await assert.rejects(I.approveAccessRequest(rc, r3.id, v), invalid('role_id'), `opts ${show(v)}`);
    assert.ok(Array.isArray(await I.listAccessRequests(env, v)));
  }
  assert.equal((await I.listAccessRequests(env, {})).length, 3);
  assert.equal((await I.listAccessRequests(env, { status: 'approved' })).length, 1);
});

await run();
