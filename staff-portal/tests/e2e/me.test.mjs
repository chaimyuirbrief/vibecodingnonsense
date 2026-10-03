// Self-service (CONTRACTS §8.4 Me; A §7.3–7.5; SPEC §7.8–7.9): every route
// acts on the caller's own account; anything that weakens it needs a fresh
// step-up; the last factor never goes.

import { test, assert, run } from '../helpers/t.js';
import {
  freshEnv, client, bootstrap, makeUser, stepUp, signIn, nextTotp, q, count, auditRows, advance, MINUTE, OWNER_IP, PASSWORD, HOSTILE,
} from '../helpers/flows.js';
import { SoftAuthenticator } from '../helpers/authenticator.js';

async function world(opts = {}) {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const amy = await makeUser(env, owner.client, { email: 'amy@acme.com', ...opts });
  return { env, owner, amy };
}

const show = (v) => String(typeof v === 'symbol' ? 'Symbol' : JSON.stringify(v));

test('GET /api/me: who, what they may do, their factors — and nothing secret', async () => {
  const { amy } = await world();
  const r = await amy.client.get('/api/me');
  assert.equal(r.status, 200);
  const b = r.body;
  assert.equal(b.user.email, 'amy@acme.com');
  assert.equal(b.user.role.key, 'employee');
  assert.deepEqual(b.permissions, []);
  assert.equal(b.pinned, null);
  assert.equal(b.enroll_prompt, true);
  assert.equal(b.step_up_fresh, false);
  assert.deepEqual(b.factors, { totp: false, totpUnreadable: false, passkeys: 0, backup: 0, destinations: 0 });
  assert.deepEqual(b.passkeys, []);
  assert.equal(b.org_name, 'Acme Inc.');
  assert.equal(b.timezone, 'America/New_York');
  assert.equal(typeof b.privacy_notice, 'string');
  for (const k of ['password', 'failed_logins', 'locked_until', 'secret', 'token']) assert.ok(!r.text.includes(k), k);
});

test('an owner sees their permissions sorted, with where each came from', async () => {
  const { owner } = await world();
  const b = (await owner.client.get('/api/me')).body;
  assert.ok(b.permissions.includes('gate.open'));
  assert.deepEqual(b.permissions, [...b.permissions].sort());
  assert.equal(b.sources['audit.revert'], 'account');
  assert.equal(b.is_super, true);
  assert.equal(b.rank, 100);
  assert.equal(b.step_up_fresh, true, 'enrolling just proved a factor');
});

test('PATCH /api/me changes only your name, audited with an undo', async () => {
  const { env, amy } = await world();
  const r = await amy.client.patch('/api/me', { full_name: 'Amy Example', job_title: 'Boss', email: 'x@y.com' });
  assert.equal(r.status, 200, r.text);
  const u = q(env, 'SELECT full_name, job_title, email FROM users WHERE id = ?', amy.user.id)[0];
  assert.deepEqual(u, { full_name: 'Amy Example', job_title: null, email: 'amy@acme.com' });
  const a = auditRows(env, 'user.edit').at(-1);
  assert.equal(a.undo_kind, 'user.profile');
  for (const v of HOSTILE) {
    if (v === 'abc') continue;
    assert.equal((await amy.client.patch('/api/me', { full_name: v })).status, 400, show(v));
  }
  assert.equal(q(env, 'SELECT full_name FROM users WHERE id = ?', amy.user.id)[0].full_name, 'Amy Example');
});

test('sessions: list by reference only, end one, end the others', async () => {
  const { env, amy } = await world();
  const laptop2 = client(env, { ip: OWNER_IP });
  const phone = client(env, { ip: OWNER_IP });
  for (const c of [laptop2, phone]) assert.equal((await c.post('/api/auth/login', { identifier: 'amy@acme.com', password: PASSWORD })).status, 200);
  const list = await amy.client.get('/api/me/sessions');
  assert.equal(list.body.sessions.length, 3);
  assert.ok(list.body.sessions.every((s) => /^[0-9a-f]{12}$/.test(s.id_ref) && Object.keys(s).sort().join() === 'aal,created_at,current,id_ref,ip,last_seen_at,ua'));
  assert.equal(list.body.sessions.filter((s) => s.current).length, 1);
  const other = list.body.sessions.find((s) => !s.current);
  const del = await amy.client.del(`/api/me/sessions/${other.id_ref}`);
  assert.equal(del.status, 200);
  const alive = [await laptop2.get('/api/me'), await phone.get('/api/me')].filter((r) => r.status === 200).length;
  assert.equal(alive, 1);
  for (const v of ['nope', '0'.repeat(12), 'zzzzzzzzzzzz', '%00', other.id_ref]) assert.equal((await amy.client.del(`/api/me/sessions/${v}`)).status, 404, v);
  const rest = await amy.client.post('/api/me/sessions/revoke-others', {});
  assert.deepEqual(rest.body, { ok: true, revoked: 1 });
  assert.equal((await laptop2.get('/api/me')).status, 401);
  assert.equal((await phone.get('/api/me')).status, 401);
  assert.equal((await amy.client.get('/api/me')).status, 200, 'this one stays');
});

test('another person’s session reference is refused', async () => {
  const { env, owner, amy } = await world();
  const ownerRef = q(env, 'SELECT substr(id, 1, 12) AS r FROM sessions WHERE user_id = ?', owner.user.id)[0].r;
  assert.equal((await amy.client.del(`/api/me/sessions/${ownerRef}`)).status, 404);
  assert.equal((await owner.client.get('/api/me')).status, 200);
});

test('devices: list mine, forget one (sessions, grace and ledger go; the device row stays)', async () => {
  const { env, amy } = await world({ ip: OWNER_IP, totp: true });
  const laptop2 = client(env, { ip: OWNER_IP });
  assert.equal((await signIn(env, laptop2, 'amy@acme.com', PASSWORD, { totpSecret: amy.totpSecret })).status, 200);
  const devs = (await amy.client.get('/api/me/devices')).body.devices;
  assert.equal(devs.length, 2);
  assert.equal(devs.filter((d) => d.current).length, 1);
  const other = devs.find((d) => !d.current);
  assert.equal(count(env, 'SELECT COUNT(*) FROM mfa_grace WHERE device_id = ?', other.id), 1);
  const r = await amy.client.del(`/api/me/devices/${encodeURIComponent(other.id)}`);
  assert.deepEqual(r.body, { ok: true, signed_out: false });
  assert.equal((await laptop2.get('/api/me')).status, 401);
  assert.equal(count(env, 'SELECT COUNT(*) FROM mfa_grace WHERE device_id = ?', other.id), 0);
  assert.equal(count(env, 'SELECT COUNT(*) FROM device_users WHERE device_id = ? AND user_id = ?', other.id, amy.user.id), 0);
  assert.equal(count(env, 'SELECT COUNT(*) FROM devices WHERE id = ?', other.id), 1);
  for (const v of ['nope', other.id, 'x'.repeat(200)]) assert.equal((await amy.client.del(`/api/me/devices/${v}`)).status, 404, v.slice(0, 8));
  const ownerDev = q(env, 'SELECT device_id FROM sessions WHERE user_id = 1')[0].device_id;
  assert.equal((await amy.client.del(`/api/me/devices/${ownerDev}`)).status, 404, 'not on my account');
  // Forgetting the device in hand signs this browser out.
  const mine = devs.find((d) => d.current);
  const self = await amy.client.del(`/api/me/devices/${encodeURIComponent(mine.id)}`);
  assert.deepEqual(self.body, { ok: true, signed_out: true });
  assert.equal((await amy.client.get('/api/me')).status, 401);
});

test('activity and fingerprint are your own, without undo data', async () => {
  const { amy } = await world();
  await amy.client.post('/api/fp', { signals: { v: 1, tz: 'Europe/Paris', languages: ['en-US'] } });
  const act = await amy.client.get('/api/me/activity');
  assert.ok(act.body.entries.some((e) => e.action === 'login.success'));
  assert.ok(act.body.entries.every((e) => Object.keys(e).sort().join() === 'action,at,detail,id,ip,outcome'));
  const fp = await amy.client.get('/api/me/fingerprint');
  assert.equal(fp.status, 200);
  assert.equal(fp.body.threshold, 70);
  assert.equal(fp.body.fingerprint.tz, 'Europe/Paris');
  assert.ok(fp.body.risk.flags.some((f) => f.key === 'tz_mismatch' && typeof f.reason === 'string'));
  assert.equal(fp.body.risk.score, fp.body.risk.flags.reduce((n, f) => n + f.weight, 0));
});

test('step-up: wrong codes are audited and refused, a right one is fresh for step_up_minutes', async () => {
  const { env, amy } = await world({ totp: true });
  advance(env, 16 * MINUTE);
  assert.equal((await amy.client.get('/api/me')).body.step_up_fresh, false);
  const info = await amy.client.get('/api/me/step-up');
  assert.deepEqual(info.body, { methods: ['totp', 'backup'], destinations: [] });
  for (const v of [...HOSTILE.slice(0, 4), '000000']) {
    assert.equal((await amy.client.post('/api/me/step-up/code', { code: v })).status, 400, show(v));
  }
  assert.equal(auditRows(env, 'stepup.fail').length, 5);
  assert.equal((await amy.client.post('/api/me/step-up/code', { code: await nextTotp(env, amy.totpSecret) })).status, 429, 'the sixth factor attempt in 15 minutes');
  advance(env, 16 * MINUTE);
  await stepUp(env, amy.client);
  assert.equal((await amy.client.get('/api/me')).body.step_up_fresh, true);
  assert.equal(count(env, "SELECT COUNT(*) FROM auth_attempts WHERE kind = 'mfa_user' AND subject = ?", String(amy.user.id)), 0, 'a success clears the factor bucket');
  advance(env, 16 * MINUTE);
  assert.equal((await amy.client.get('/api/me')).body.step_up_fresh, false);
});

test('removing the authenticator: step-up first, and never the last factor', async () => {
  const { env, amy } = await world({ totp: true });
  advance(env, 16 * MINUTE);
  const r1 = await amy.client.del('/api/me/mfa/totp');
  assert.equal(r1.status, 403);
  assert.equal(r1.body.step_up_required, true);
  await stepUp(env, amy.client);
  const r2 = await amy.client.del('/api/me/mfa/totp');
  assert.equal(r2.status, 409);
  assert.equal(r2.body.code, 'last_factor');
  assert.equal(count(env, 'SELECT COUNT(*) FROM user_totp WHERE user_id = ?', amy.user.id), 1);
  const auth = new SoftAuthenticator({ origin: env.ORIGIN, rpId: env.RP_ID });
  const o = await amy.client.post('/api/me/mfa/passkey/options', {});
  const reg = await amy.client.post('/api/me/mfa/passkey/register', { credential: await auth.create(o.body), label: 'Key' });
  assert.equal(reg.body.backup_codes, null, 'she already has unused backup codes');
  assert.equal((await amy.client.del('/api/me/mfa/totp')).status, 200);
  assert.equal((await amy.client.del('/api/me/mfa/totp')).status, 404);
  assert.equal(auditRows(env, 'mfa.totp.remove').length, 1);
});

test('new backup codes need a step-up and replace the old ones', async () => {
  const { env, amy } = await world({ totp: true });
  const old = amy.client.backupCodes;
  advance(env, 16 * MINUTE);
  assert.equal((await amy.client.post('/api/me/mfa/backup/regenerate', {})).status, 403);
  await stepUp(env, amy.client);
  const r = await amy.client.post('/api/me/mfa/backup/regenerate', {});
  assert.equal(r.status, 200);
  assert.equal(r.body.backup_codes.length, 10);
  assert.notDeepEqual(r.body.backup_codes, old);
  const p = await amy.client.post('/api/auth/login', { identifier: 'amy@acme.com', password: PASSWORD });
  assert.equal((await amy.client.post('/api/auth/mfa/code', { token: p.body.token, code: old[0] })).status, 401);
  assert.equal((await amy.client.post('/api/auth/mfa/code', { token: p.body.token, code: r.body.backup_codes[0] })).status, 200);
});

test('a non-JSON or junk body on any self-service write is refused cleanly', async () => {
  const { amy } = await world({ totp: true });
  for (const [m, p] of [
    ['PATCH', '/api/me'], ['POST', '/api/me/password'], ['POST', '/api/me/step-up/code'], ['POST', '/api/me/step-up/send'],
    ['POST', '/api/me/step-up/otp'], ['POST', '/api/me/mfa/totp/confirm'], ['POST', '/api/me/mfa/passkey/register'],
  ]) {
    for (const body of ['not json', '[]', '"string"', '{"__proto__": {"admin": true}}']) {
      const r = await amy.client.request(m, p, body);
      assert.ok(r.status >= 400 && r.status < 500, `${m} ${p} ${body}: ${r.status} ${r.text}`);
    }
  }
  assert.equal((await amy.client.get('/api/me')).status, 200);
});

await run();
