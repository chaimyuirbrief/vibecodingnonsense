import { test, assert, run } from '../helpers/t.js';
import { makeEnvWithSchema } from '../helpers/env.js';
import { CHROME_UA, FIREFOX_UA, SAFARI_IOS_UA } from '../helpers/http.js';
import { iso, HOUR, DAY } from '../../src/util.js';
import { signToken, verifyToken } from '../../src/crypto.js';
import { GuardError, ValidationError, HttpError } from '../../src/errors.js';
import * as D from '../../src/devices.js';
import { resolvePolicy } from '../../src/policy.js';
import { edgeSignals } from '../../src/fingerprint.js';

const HOSTILE = [null, undefined, NaN, Infinity, '', '   ', 'abc', {}, [], true, 0, Symbol('x')];
const show = (v) => (typeof v === 'symbol' ? 'Symbol' : JSON.stringify(v) ?? String(v));

const SAFARI_MAC_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15';
const EDGE_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0';
const OPERA_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 OPR/114.0.0.0';
const CHROME_ANDROID_K = 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36';
const CHROME_PIXEL = 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36';
const SAMSUNG_UA = 'Mozilla/5.0 (Linux; Android 14; SAMSUNG SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/121.0.0.0 Mobile Safari/537.36';
const CHROME_IOS = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/129.0.6668.69 Mobile/15E148 Safari/604.1';
const FIREFOX_IOS = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/131.0 Mobile/15E148 Safari/605.1.15';
const IPAD_UA = 'Mozilla/5.0 (iPad; CPU OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1';
const CROS_UA = 'Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36';
const FIREFOX_LINUX = 'Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0';
const FIREFOX_ANDROID = 'Mozilla/5.0 (Android 14; Mobile; rv:131.0) Gecko/131.0 Firefox/131.0';

let seq = 0;
function addUser(env) {
  const n = ++seq;
  const t = iso(env.__clock());
  const role = env.DB.q("SELECT id FROM roles WHERE key = 'employee'")[0].id;
  env.DB.q('INSERT INTO users (email, full_name, status, role_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)', `d${n}@acme.com`, `D ${n}`, 'active', role, t, t);
  return env.DB.q('SELECT * FROM users WHERE email = ?', `d${n}@acme.com`)[0];
}

function rcFor(env, o = {}) {
  return { env, nowMs: env.__clock(), ip: '81.2.69.10', ua: CHROME_UA, cookies: {}, setCookies: [], policy: { device_gating: false }, ...o };
}

function addDevice(env, id, status = 'pending', { lastSeen } = {}) {
  const t = iso(lastSeen ?? env.__clock());
  env.DB.q('INSERT INTO devices (id, status, label, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)', id, status, 'Seeded', t, t);
}

function addSession(env, id, userId, deviceId) {
  const t = env.__clock();
  env.DB.q(
    'INSERT INTO sessions (id, user_id, device_id, created_at, last_seen_at, idle_expires_at, absolute_expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
    id, userId, deviceId, iso(t), iso(t), iso(t + HOUR), iso(t + 8 * HOUR),
  );
}

function addGrace(env, userId, deviceId) {
  const t = env.__clock();
  env.DB.q('INSERT INTO mfa_grace (user_id, device_id, tier, verified_at, expires_at) VALUES (?, ?, 1, ?, ?)', userId, deviceId, iso(t), iso(t + DAY));
}

const count = (env, sql, ...a) => env.DB.q(sql, ...a)[0].n;
const cookieValue = (setCookie) => setCookie.split(';')[0].split('=').slice(1).join('=');

function spyQueries(env) {
  const orig = env.DB.prepare;
  const log = [];
  env.DB.prepare = function (sql) {
    log.push(sql);
    return orig.call(this, sql);
  };
  return { log, restore: () => (env.DB.prepare = orig) };
}

const status = (code) => (e) => {
  assert.ok(e instanceof HttpError, `expected HttpError(${code}), got ${e && e.stack}`);
  assert.equal(e.status, code, e.message);
  return true;
};

// ---------------------------------------------------------------- cookie

test('ensureDevice mints a signed id, a pending row with label and addresses, and a Lax __Host- cookie', async () => {
  const env = await makeEnvWithSchema();
  const rc = rcFor(env);
  const r = await D.ensureDevice(rc);
  assert.match(r.id, /^[A-Za-z0-9_-]{22}$/);
  assert.equal(r.row.status, 'pending');
  assert.equal(r.row.label, 'Chrome on macOS');
  assert.equal(r.row.platform, 'macOS');
  assert.equal(r.row.first_ip, '81.2.69.10');
  assert.equal(r.row.last_ip, '81.2.69.10');
  assert.match(r.setCookie, /^__Host-dev=/);
  assert.match(r.setCookie, /SameSite=Lax/);
  assert.match(r.setCookie, /; Secure/);
  assert.match(r.setCookie, /HttpOnly/);
  assert.equal(await verifyToken(env, 'device', cookieValue(r.setCookie)), r.id);
  assert.deepEqual(rc.device, { id: r.id, row: r.row });
  // The same browser again: same id, nothing new to set.
  const rc2 = rcFor(env, { cookies: { [D.DEVICE_COOKIE]: cookieValue(r.setCookie) } });
  const again = await D.ensureDevice(rc2);
  assert.equal(again.id, r.id);
  assert.equal(again.setCookie, null);
  assert.equal(count(env, 'SELECT COUNT(*) AS n FROM devices'), 1);
});

test('readDevice: forged, tampered, cross-purpose and hostile cookies are refused BEFORE any query', async () => {
  const env = await makeEnvWithSchema();
  const real = await D.ensureDevice(rcFor(env));
  const good = cookieValue(real.setCookie);
  const [payload, mac] = [good.slice(0, good.lastIndexOf('.')), good.slice(good.lastIndexOf('.') + 1)];
  const forged = [
    payload, // unsigned id
    `${payload}.${'A'.repeat(43)}`,
    `${payload.slice(0, -1)}${payload.endsWith('A') ? 'B' : 'A'}.${mac}`, // id changed, mac kept
    await signToken(env, 'fp', payload), // right key, wrong purpose
    await signToken(env, 'pass', payload),
    `${good}x`,
    'x'.repeat(5000),
  ];
  const spy = spyQueries(env);
  try {
    for (const v of [...forged, ...HOSTILE]) {
      const r = await D.readDevice(rcFor(env, { cookies: { [D.DEVICE_COOKIE]: v } }));
      assert.deepEqual(r, { id: null, row: null }, show(v));
    }
    assert.deepEqual(await D.readDevice(rcFor(env, { cookies: null })), { id: null, row: null });
    assert.deepEqual(await D.readDevice(null), { id: null, row: null });
    assert.equal(spy.log.length, 0, 'no query for a cookie that does not verify');
    const ok = await D.readDevice(rcFor(env, { cookies: { [D.DEVICE_COOKIE]: good } }));
    assert.equal(ok.id, real.id);
    assert.equal(ok.row.status, 'pending');
  } finally {
    spy.restore();
  }
});

test('a forged device cookie never mints a row under the forged id', async () => {
  const env = await makeEnvWithSchema();
  const rc = rcFor(env, { cookies: { [D.DEVICE_COOKIE]: 'attacker-chosen-id-1234567' } });
  const r = await D.ensureDevice(rc);
  assert.notEqual(r.id, 'attacker-chosen-id-1234567');
  assert.ok(r.setCookie);
  assert.equal(count(env, "SELECT COUNT(*) AS n FROM devices WHERE id = 'attacker-chosen-id-1234567'"), 0);
});

test('a signed id whose row was pruned is recreated under the same id with no new cookie', async () => {
  const env = await makeEnvWithSchema();
  const first = await D.ensureDevice(rcFor(env));
  env.DB.q('DELETE FROM devices');
  const rc = rcFor(env, { cookies: { [D.DEVICE_COOKIE]: cookieValue(first.setCookie) } });
  const r = await D.ensureDevice(rc);
  assert.equal(r.id, first.id);
  assert.equal(r.setCookie, null);
  assert.equal(r.row.status, 'pending');
});

test('ensureDevice keeps a waiting device findable: last_seen is touched at most hourly', async () => {
  const env = await makeEnvWithSchema();
  const first = await D.ensureDevice(rcFor(env));
  const c = { [D.DEVICE_COOKIE]: cookieValue(first.setCookie) };
  env.__advance(10 * 60 * 1000);
  await D.ensureDevice(rcFor(env, { cookies: c }));
  assert.equal(env.DB.q('SELECT last_seen FROM devices')[0].last_seen, first.row.last_seen);
  env.__advance(2 * HOUR);
  await D.ensureDevice(rcFor(env, { cookies: c, ip: '91.198.174.5' }));
  const row = env.DB.q('SELECT last_seen, last_ip FROM devices')[0];
  assert.equal(row.last_seen, iso(env.__clock()));
  assert.equal(row.last_ip, '91.198.174.5');
});

// ---------------------------------------------------------------- retention

test('pending cap: a scanner minting devices cannot grow the pending list past the cap; signed-in devices outlive strangers', async () => {
  const env = await makeEnvWithSchema();
  env.__retention = (k) => (k === 'devices_pending' ? 30 : undefined);
  const u = addUser(env);
  addDevice(env, 'approved-old', 'approved', { lastSeen: env.__clock() - 400 * DAY });
  addDevice(env, 'blocked-old', 'blocked', { lastSeen: env.__clock() - 400 * DAY });
  addDevice(env, 'ledger-device', 'pending', { lastSeen: env.__clock() - 5 * DAY });
  env.DB.q('INSERT INTO device_users (device_id, user_id, first_seen, last_seen, sign_ins) VALUES (?, ?, ?, ?, 1)', 'ledger-device', u.id, iso(0), iso(0));
  let last;
  for (let i = 0; i < 80; i++) {
    env.__advance(1000);
    last = await D.ensureDevice(rcFor(env));
    assert.ok(count(env, "SELECT COUNT(*) AS n FROM devices WHERE status = 'pending'") <= 30);
  }
  assert.equal(count(env, "SELECT COUNT(*) AS n FROM devices WHERE status = 'pending'"), 30);
  assert.equal(count(env, 'SELECT COUNT(*) AS n FROM devices WHERE id = ?', last.id), 1, 'the row just minted is kept');
  assert.equal(count(env, "SELECT COUNT(*) AS n FROM devices WHERE id = 'ledger-device'"), 1, 'a device someone signed in on outlives strangers');
  assert.equal(count(env, "SELECT COUNT(*) AS n FROM devices WHERE id IN ('approved-old', 'blocked-old')"), 2, 'only pending rows are pruned');
});

test('pending cap at the real constant: 2,000 seeded, one more minted, still 2,000; __retention cannot raise it', async () => {
  const env = await makeEnvWithSchema();
  env.__retention = () => 1_000_000;
  const t = iso(env.__clock() - HOUR);
  env.DB.sqlite.exec('BEGIN');
  const ins = env.DB.sqlite.prepare("INSERT INTO devices (id, status, first_seen, last_seen) VALUES (?, 'pending', ?, ?)");
  for (let i = 0; i < 2000; i++) ins.run(`seed-${String(i).padStart(5, '0')}-xxxxxxxx`, t, t);
  env.DB.sqlite.exec('COMMIT');
  const r = await D.ensureDevice(rcFor(env));
  assert.equal(count(env, "SELECT COUNT(*) AS n FROM devices WHERE status = 'pending'"), 2000);
  assert.equal(count(env, 'SELECT COUNT(*) AS n FROM devices WHERE id = ?', r.id), 1);
});

test('pending devices unseen for 30 days are pruned on the next mint, with their ledger rows', async () => {
  const env = await makeEnvWithSchema();
  const u = addUser(env);
  addDevice(env, 'stale-pending', 'pending', { lastSeen: env.__clock() - 31 * DAY });
  addDevice(env, 'fresh-pending', 'pending', { lastSeen: env.__clock() - 29 * DAY });
  addDevice(env, 'stale-approved', 'approved', { lastSeen: env.__clock() - 90 * DAY });
  env.DB.q('INSERT INTO device_users (device_id, user_id, first_seen, last_seen, sign_ins) VALUES (?, ?, ?, ?, 1)', 'stale-pending', u.id, iso(0), iso(0));
  await D.ensureDevice(rcFor(env));
  const ids = env.DB.q('SELECT id FROM devices ORDER BY id').map((r) => r.id);
  assert.ok(!ids.includes('stale-pending'));
  assert.ok(ids.includes('fresh-pending'));
  assert.ok(ids.includes('stale-approved'));
  assert.equal(count(env, "SELECT COUNT(*) AS n FROM device_users WHERE device_id = 'stale-pending'"), 0);
});

// ---------------------------------------------------------------- codes

test('deviceCode: XXXX-XXXX from an unambiguous alphabet, deterministic, distinct per id; hostile → null', async () => {
  const seen = new Set();
  for (let i = 0; i < 300; i++) {
    const c = await D.deviceCode(`device-${i}`);
    assert.match(c, /^[23456789ABCDEFGHJKMNPQRSTUVWXYZ]{4}-[23456789ABCDEFGHJKMNPQRSTUVWXYZ]{4}$/);
    assert.equal(await D.deviceCode(`device-${i}`), c);
    seen.add(c);
  }
  assert.equal(seen.size, 300);
  for (const v of HOSTILE.filter((x) => x !== 'abc')) assert.equal(await D.deviceCode(v), null, show(v));
  assert.match(await D.deviceCode('abc'), /^\w{4}-\w{4}$/);
});

test('findDeviceByCode: tolerant of case, spaces and hyphens; pending and seen in the last 7 days only; hostile → null', async () => {
  const env = await makeEnvWithSchema();
  addDevice(env, 'waiting-device-1');
  addDevice(env, 'approved-device-1', 'approved');
  addDevice(env, 'old-pending-device', 'pending', { lastSeen: env.__clock() - 8 * DAY });
  const code = await D.deviceCode('waiting-device-1');
  for (const typed of [code, code.toLowerCase(), code.replace('-', ''), ` ${code.slice(0, 4)} ${code.slice(5)} `]) {
    assert.equal((await D.findDeviceByCode(env, typed))?.id, 'waiting-device-1', typed);
  }
  assert.equal(await D.findDeviceByCode(env, await D.deviceCode('approved-device-1')), null);
  assert.equal(await D.findDeviceByCode(env, await D.deviceCode('old-pending-device')), null);
  assert.equal(await D.findDeviceByCode(env, 'AAAA-AAAA'), null);
  assert.equal(await D.findDeviceByCode(env, '0000-1111'), null, 'ambiguous characters never match');
  const spy = spyQueries(env);
  try {
    for (const v of HOSTILE) assert.equal(await D.findDeviceByCode(env, v), null, show(v));
    assert.equal(spy.log.length, 0, 'a code with the wrong shape never reaches a query');
  } finally {
    spy.restore();
  }
});

// ---------------------------------------------------------------- status

test('setDeviceStatus approved records who and when; blocked revokes that device’s sessions and grace only', async () => {
  const env = await makeEnvWithSchema();
  const admin = addUser(env);
  const u = addUser(env);
  addDevice(env, 'target-device');
  addDevice(env, 'other-device');
  addSession(env, 's1', u.id, 'target-device');
  addSession(env, 's2', u.id, 'other-device');
  addGrace(env, u.id, 'target-device');
  addGrace(env, u.id, 'other-device');
  const rc = rcFor(env, { user: admin, device: { id: 'admin-device', row: null } });

  const a = await D.setDeviceStatus(rc, 'target-device', 'approved', { label: 'Front desk' });
  assert.equal(a.prior.status, 'pending');
  assert.equal(a.row.status, 'approved');
  assert.equal(a.row.approved_by, admin.id);
  assert.equal(a.row.approved_at, iso(env.__clock()));
  assert.equal(a.row.label, 'Front desk');
  assert.equal(count(env, 'SELECT COUNT(*) AS n FROM sessions WHERE revoked_at IS NULL'), 2, 'approving revokes nothing');

  const b = await D.setDeviceStatus(rc, 'target-device', 'blocked');
  assert.equal(b.prior.status, 'approved');
  assert.equal(b.row.status, 'blocked');
  assert.equal(b.row.blocked_by, admin.id);
  assert.equal(env.DB.q("SELECT revoke_reason FROM sessions WHERE id = 's1'")[0].revoke_reason, 'device_blocked');
  assert.equal(env.DB.q("SELECT revoked_at FROM sessions WHERE id = 's2'")[0].revoked_at, null);
  assert.deepEqual(env.DB.q('SELECT device_id FROM mfa_grace').map((r) => r.device_id), ['other-device']);
});

test('setDeviceStatus approved → pending withdraws trust too; pending → pending revokes nothing', async () => {
  const env = await makeEnvWithSchema();
  const u = addUser(env);
  addDevice(env, 'dev-a', 'approved');
  addDevice(env, 'dev-b', 'pending');
  addSession(env, 'sa', u.id, 'dev-a');
  addSession(env, 'sb', u.id, 'dev-b');
  addGrace(env, u.id, 'dev-a');
  addGrace(env, u.id, 'dev-b');
  const rc = rcFor(env, { user: u, device: { id: 'elsewhere', row: null } });
  await D.setDeviceStatus(rc, 'dev-a', 'pending');
  await D.setDeviceStatus(rc, 'dev-b', 'pending');
  assert.notEqual(env.DB.q("SELECT revoked_at FROM sessions WHERE id = 'sa'")[0].revoked_at, null);
  assert.equal(env.DB.q("SELECT revoked_at FROM sessions WHERE id = 'sb'")[0].revoked_at, null);
  assert.deepEqual(env.DB.q('SELECT device_id FROM mfa_grace').map((r) => r.device_id), ['dev-b']);
  const row = env.DB.q("SELECT * FROM devices WHERE id = 'dev-a'")[0];
  assert.equal(row.approved_by, null);
  assert.equal(row.approved_at, null);
});

test('setDeviceStatus refuses hostile statuses, labels and ids without writing anything', async () => {
  const env = await makeEnvWithSchema();
  addDevice(env, 'dev-x');
  const rc = rcFor(env);
  const before = JSON.stringify(env.DB.q('SELECT * FROM devices'));
  for (const v of [...HOSTILE, 'APPROVED', 'trusted', 'deleted']) {
    await assert.rejects(D.setDeviceStatus(rc, 'dev-x', v), (e) => e instanceof ValidationError, show(v));
  }
  for (const v of [...HOSTILE.filter((x) => x !== undefined && x !== 'abc'), 'x'.repeat(101)]) {
    await assert.rejects(D.setDeviceStatus(rc, 'dev-x', 'approved', { label: v }), (e) => e instanceof ValidationError, show(v));
  }
  for (const v of HOSTILE) await assert.rejects(D.setDeviceStatus(rc, v, 'approved'), status(404), show(v));
  assert.equal(JSON.stringify(env.DB.q('SELECT * FROM devices')), before);
});

// A request context as buildContext makes it, for asking the gate about the
// caller's own device.
async function gateRc(env, { ip = '91.198.174.20', mode = 'allowlist', gating = false, device } = {}) {
  const request = new Request('https://staff.example.com/', { headers: { 'cf-connecting-ip': ip, 'user-agent': CHROME_UA, 'accept-language': 'en-US' } });
  const cf = { country: 'US', asn: 7922, asOrganization: 'Comcast Cable', tlsVersion: 'TLSv1.3', httpProtocol: 'HTTP/2' };
  const policy = { ...(await resolvePolicy(env)), access_mode: mode, device_gating: gating };
  return rcFor(env, { request, ip, cf, edge: edgeSignals(request, cf), fp: null, policy, device });
}

// GATE-1: the gate needs the caller's device approval in lockdown (allowlisted
// AND approved), in invite_only, in the allowlist mode off the allowlist and
// in request_access off it, and with device gating on — not only the last.
test('self-lockout: you cannot block the device you are using, nor un-approve it wherever the gate needs that approval', async () => {
  const env = await makeEnvWithSchema();
  const me = addUser(env);
  addDevice(env, 'my-device', 'approved');
  env.DB.q('INSERT INTO allowed_ips (cidr, tier, created_at, updated_at) VALUES (?, 1, ?, ?)', '81.2.69.0/24', iso(env.__clock()), iso(env.__clock()));
  const mine = { id: 'my-device', row: { id: 'my-device', status: 'approved' } };
  const guard = (e) => e instanceof GuardError && e.code === 'self_lockout' && e.status === 409;
  const as = async (o) => ({ ...(await gateRc(env, { device: mine, ...o })), user: me });

  await assert.rejects(D.setDeviceStatus(await as({ mode: 'public' }), 'my-device', 'blocked'), guard, 'blocking is refused in every mode');
  const needed = [
    ['lockdown on the allowlist', { mode: 'lockdown', ip: '81.2.69.10' }],
    ['invite_only on the allowlist', { mode: 'invite_only', ip: '81.2.69.10' }],
    ['allowlist off the allowlist', { mode: 'allowlist' }],
    ['request_access off the allowlist', { mode: 'request_access' }],
    ['device gating on, allowlisted', { mode: 'allowlist', ip: '81.2.69.10', gating: true }],
    ['device gating on, public', { mode: 'public', gating: true }],
  ];
  for (const [what, o] of needed) {
    await assert.rejects(D.setDeviceStatus(await as(o), 'my-device', 'pending'), guard, `${what}: un-approve`);
    await assert.rejects(D.revokeDevice(await as(o), 'my-device'), guard, `${what}: revoke`);
  }
  await assert.rejects(D.revokeDevice(rcFor(env, { device: mine, policy: undefined, user: me }), 'my-device'), guard, 'an unreadable policy is the restrictive one');
  assert.equal(env.DB.q("SELECT status FROM devices WHERE id = 'my-device'")[0].status, 'approved', 'nothing was written');

  // Where the approval is not what lets you in, un-approving your own device
  // is only a sign-out.
  await D.revokeDevice(await as({ mode: 'allowlist', ip: '81.2.69.10' }), 'my-device');
  assert.equal(env.DB.q("SELECT status FROM devices WHERE id = 'my-device'")[0].status, 'pending');
  env.DB.q("UPDATE devices SET status = 'approved' WHERE id = 'my-device'");
  await D.setDeviceStatus(await as({ mode: 'public' }), 'my-device', 'pending');
  assert.equal(env.DB.q("SELECT status FROM devices WHERE id = 'my-device'")[0].status, 'pending');
});

// AUTHZ-1 / FO-4: withdrawing trust from a device signs out — and, wherever
// approval matters, keeps out — everyone on it, so it is an action on each of
// them (SPEC §5.5): every active account that signed in there must rank below
// the caller.
test('withdrawing trust from a device is refused when someone at or above the caller signs in on it', async () => {
  const env = await makeEnvWithSchema();
  const t = iso(env.__clock());
  const roleOf = (k) => env.DB.q('SELECT id FROM roles WHERE key = ?', k)[0].id;
  const person = (email, role) => {
    env.DB.q('INSERT INTO users (email, full_name, status, role_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)', email, email, 'active', roleOf(role), t, t);
    return env.DB.q('SELECT * FROM users WHERE email = ?', email)[0];
  };
  const owner = person('owner@acme.com', 'super_admin');
  const admin = person('admin@acme.com', 'admin');
  const emp = person('emp@acme.com', 'employee');
  const ledger = (deviceId, u) => env.DB.q('INSERT INTO device_users (device_id, user_id, first_seen, last_seen, sign_ins) VALUES (?, ?, ?, ?, 1)', deviceId, u.id, t, t);
  for (const id of ['owner-laptop', 'emp-phone', 'shared-kiosk', 'admin-phone']) addDevice(env, id, 'approved');
  ledger('owner-laptop', owner);
  ledger('emp-phone', emp);
  ledger('shared-kiosk', emp);
  ledger('shared-kiosk', owner);
  ledger('admin-phone', admin);
  addSession(env, 's-owner', owner.id, 'owner-laptop');
  const rank = (e) => e instanceof GuardError && e.code === 'rank' && e.status === 403;
  const rc = rcFor(env, { user: admin, device: { id: 'admin-laptop', row: null } });

  await assert.rejects(D.setDeviceStatus(rc, 'owner-laptop', 'blocked'), rank, 'block');
  await assert.rejects(D.setDeviceStatus(rc, 'owner-laptop', 'pending'), rank, 'un-approve');
  await assert.rejects(D.revokeDevice(rc, 'owner-laptop'), rank, 'revoke');
  await assert.rejects(D.revokeDevice(rc, 'shared-kiosk'), rank, 'a device shared with someone above you');
  assert.equal(env.DB.q("SELECT revoked_at FROM sessions WHERE id = 's-owner'")[0].revoked_at, null, 'the owner is still signed in');
  assert.equal(count(env, "SELECT COUNT(*) AS n FROM devices WHERE status = 'approved'"), 4, 'nothing was written');

  // Below you, or your own: as before. Extending trust is no action on anyone.
  await D.setDeviceStatus(rc, 'emp-phone', 'blocked');
  await D.revokeDevice(rc, 'admin-phone');
  await D.setDeviceStatus(rc, 'emp-phone', 'pending');
  await D.setDeviceStatus(rc, 'emp-phone', 'approved');
  // A Super Admin acts on a peer; an account that is not active is no one to protect.
  await D.setDeviceStatus(rcFor(env, { user: person('sue@acme.com', 'super_admin') }), 'owner-laptop', 'pending');
  env.DB.q("UPDATE users SET status = 'disabled' WHERE id = ?", owner.id);
  await D.revokeDevice(rc, 'shared-kiosk');
});

test('revokeDevice: back to pending, grace dropped, sessions revoked; a blocked device stays blocked', async () => {
  const env = await makeEnvWithSchema();
  const u = addUser(env);
  addDevice(env, 'dev-ok', 'approved');
  addDevice(env, 'dev-bad', 'blocked');
  addDevice(env, 'dev-weird', 'quarantined');
  addSession(env, 's-ok', u.id, 'dev-ok');
  addGrace(env, u.id, 'dev-ok');
  const rc = rcFor(env, { user: u });
  assert.equal(await D.revokeDevice(rc, 'dev-ok'), undefined);
  assert.equal(env.DB.q("SELECT status FROM devices WHERE id = 'dev-ok'")[0].status, 'pending');
  assert.equal(count(env, 'SELECT COUNT(*) AS n FROM mfa_grace'), 0);
  assert.equal(env.DB.q("SELECT revoke_reason FROM sessions WHERE id = 's-ok'")[0].revoke_reason, 'device_revoked');
  await D.revokeDevice(rc, 'dev-bad');
  await D.revokeDevice(rc, 'dev-weird');
  assert.equal(env.DB.q("SELECT status FROM devices WHERE id = 'dev-bad'")[0].status, 'blocked');
  assert.equal(env.DB.q("SELECT status FROM devices WHERE id = 'dev-weird'")[0].status, 'quarantined', 'an unreadable status is never loosened');
  for (const v of HOSTILE) await assert.rejects(D.revokeDevice(rc, v), status(404), show(v));
});

test('deviceState: an unrecognised stored status reads as blocked', () => {
  assert.equal(D.deviceState(null), 'none');
  assert.equal(D.deviceState({ status: 'approved' }), 'approved');
  assert.equal(D.deviceState({ status: 'pending' }), 'pending');
  for (const s of ['blocked', 'APPROVED', '', null, 'trusted', 1]) assert.equal(D.deviceState({ status: s }), 'blocked', show(s));
});

test('renameDevice validates the label and returns prior and row', async () => {
  const env = await makeEnvWithSchema();
  addDevice(env, 'dev-r');
  const r = await D.renameDevice(rcFor(env), 'dev-r', '  Reception iPad  ');
  assert.equal(r.prior.label, 'Seeded');
  assert.equal(r.row.label, 'Reception iPad');
  for (const v of [...HOSTILE.filter((x) => x !== 'abc'), 'x'.repeat(101)]) await assert.rejects(D.renameDevice(rcFor(env), 'dev-r', v), (e) => e instanceof ValidationError, show(v));
  assert.equal(env.DB.q("SELECT label FROM devices WHERE id = 'dev-r'")[0].label, 'Reception iPad');
});

// ---------------------------------------------------------------- tracking

test('trackDevice: ledger counts sign-ins; last_seen, address and visitor id refresh; a typed label survives', async () => {
  const env = await makeEnvWithSchema();
  const u = addUser(env);
  const rc = rcFor(env, { fp: { hash: 'a'.repeat(64), risk: 0, visitor_id: 'b'.repeat(64) } });
  const first = await D.trackDevice(rc, u.id);
  assert.ok(first.setCookie);
  const cookies = { [D.DEVICE_COOKIE]: cookieValue(first.setCookie) };
  env.__advance(HOUR);
  const second = await D.trackDevice(rcFor(env, { cookies, ip: '185.15.56.20', ua: FIREFOX_UA }), u.id);
  assert.equal(second.id, first.id);
  assert.equal(second.setCookie, null);
  const du = env.DB.q('SELECT * FROM device_users')[0];
  assert.equal(du.sign_ins, 2);
  assert.equal(du.last_seen, iso(env.__clock()));
  let d = env.DB.q('SELECT * FROM devices')[0];
  assert.equal(d.last_ip, '185.15.56.20');
  assert.equal(d.first_ip, '81.2.69.10');
  assert.equal(d.visitor_id, 'b'.repeat(64), 'kept when the new request has no fingerprint');
  assert.equal(d.label, 'Firefox on Windows', 'an automatic label follows the browser');
  env.DB.q("UPDATE devices SET label = 'Reception PC'");
  await D.trackDevice(rcFor(env, { cookies, ua: CHROME_UA }), u.id);
  d = env.DB.q('SELECT * FROM devices')[0];
  assert.equal(d.label, 'Reception PC', 'a label an administrator typed is never overwritten');
  for (const v of HOSTILE) await assert.rejects(D.trackDevice(rcFor(env, { cookies }), v), Error, show(v));
  assert.equal(env.DB.q('SELECT sign_ins FROM device_users')[0].sign_ins, 3);
});

test('listDevices: newest first, with code and the people who signed in; filters validated', async () => {
  const env = await makeEnvWithSchema();
  const u = addUser(env);
  addDevice(env, 'dev-1', 'pending', { lastSeen: env.__clock() - HOUR });
  addDevice(env, 'dev-2', 'approved');
  env.DB.q('INSERT INTO device_users (device_id, user_id, first_seen, last_seen, sign_ins) VALUES (?, ?, ?, ?, 3)', 'dev-1', u.id, iso(0), iso(0));
  const all = await D.listDevices(env, {});
  assert.deepEqual(all.map((d) => d.id), ['dev-2', 'dev-1']);
  assert.equal(all[1].code, await D.deviceCode('dev-1'));
  assert.deepEqual(all[1].users.map((x) => [x.user_id, x.email, x.sign_ins]), [[u.id, u.email, 3]]);
  assert.deepEqual(all[0].users, []);
  assert.deepEqual((await D.listDevices(env, { status: 'approved' })).map((d) => d.id), ['dev-2']);
  assert.deepEqual((await D.listDevices(env, { userId: u.id })).map((d) => d.id), ['dev-1']);
  assert.equal((await D.listDevices(env, { limit: 1 })).length, 1);
  for (const v of [NaN, Infinity, '   ', 'abc', {}, [], true, Symbol('x')]) {
    await assert.rejects(D.listDevices(env, { status: v }), (e) => e instanceof ValidationError, show(v));
    assert.equal((await D.listDevices(env, { limit: v })).length, 2, show(v));
  }
  for (const v of HOSTILE) await assert.doesNotReject(D.listDevices(env, v));
});

// ---------------------------------------------------------------- labels

test('deviceLabelFromUa parses the user agent first (A §14.7)', () => {
  const cases = [
    [CHROME_UA, 'Chrome on macOS'],
    [FIREFOX_UA, 'Firefox on Windows'],
    [SAFARI_IOS_UA, 'Safari on iOS'],
    [SAFARI_MAC_UA, 'Safari on macOS'],
    [EDGE_UA, 'Edge on Windows'],
    [OPERA_UA, 'Opera on Windows'],
    [CHROME_ANDROID_K, 'Chrome on Android'],
    [CHROME_PIXEL, 'Chrome on Android (Pixel 8)'],
    [SAMSUNG_UA, 'Samsung Internet on Android (SAMSUNG SM-S918B)'],
    [CHROME_IOS, 'Chrome on iOS'],
    [FIREFOX_IOS, 'Firefox on iOS'],
    [IPAD_UA, 'Safari on iPadOS'],
    [CROS_UA, 'Chrome on ChromeOS'],
    [FIREFOX_LINUX, 'Firefox on Linux'],
    [FIREFOX_ANDROID, 'Firefox on Android'],
    ['', 'Unknown device'],
    ['SomethingElse/1.0', 'Unknown device'],
  ];
  for (const [ua, want] of cases) assert.equal(D.deviceLabelFromUa(ua, null), want, ua);
});

test('client hints only refine: Sec-CH-UA-Mobile ?1 with no model never shows "Mobile"; hints never override the UA', () => {
  assert.equal(D.deviceLabelFromUa(CHROME_ANDROID_K, { mobile: '?1', platform: '"Android"' }), 'Chrome on Android');
  assert.equal(D.deviceLabelFromUa(CHROME_ANDROID_K, { mobile: '?1', model: '""' }), 'Chrome on Android');
  assert.equal(D.deviceLabelFromUa(CHROME_ANDROID_K, { mobile: '?1', model: '"Mobile"' }), 'Chrome on Android');
  assert.equal(D.deviceLabelFromUa(CHROME_ANDROID_K, { mobile: '?1', model: '"Pixel 8"' }), 'Chrome on Android (Pixel 8)');
  assert.equal(D.deviceLabelFromUa(CHROME_UA, { mobile: '?1', platform: '"Windows"' }), 'Chrome on macOS', 'the UA wins over a contradicting hint');
  assert.equal(D.deviceLabelFromUa(FIREFOX_UA, {}), 'Firefox on Windows', 'no hints at all: a non-Chromium browser still gets a label');
  assert.equal(D.deviceLabelFromUa('Mozilla/5.0 Chrome/129.0', { platform: '"macOS"' }), 'Chrome on macOS', 'hint fills an OS the UA left out');
  assert.equal(D.deviceLabelFromUa(SAFARI_MAC_UA, { touch: 5 }), 'Safari on iPadOS', 'iPad asking for the desktop site');
  for (const h of [{ mobile: '?1' }, { mobile: true }, { model: 'Mobile' }, { model: '"mobile"' }]) {
    const label = D.deviceLabelFromUa('', h);
    assert.ok(!/mobile/i.test(label), `${JSON.stringify(h)} → ${label}`);
  }
});

test('deviceLabelFromUa and parseUa never throw on hostile input and never return a non-string', () => {
  for (const ua of HOSTILE) {
    for (const hints of HOSTILE) {
      const label = D.deviceLabelFromUa(ua, hints);
      assert.equal(typeof label, 'string');
      assert.ok(!/mobile/i.test(label), label);
    }
  }
  for (const platform of ['constructor', '"__proto__"', '"toString"', 'hasOwnProperty', 'valueOf']) {
    assert.equal(D.deviceLabelFromUa('', { platform }), 'Unknown device', platform);
    assert.equal(D.parseUa('', { platform }).os, null, platform);
  }
  const hostileHints = { platform: { toString: () => 'macOS' }, mobile: Symbol('x'), model: ['Pixel'], touch: 'lots' };
  assert.equal(D.deviceLabelFromUa(CHROME_UA, hostileHints), 'Chrome on macOS');
});

await run();
