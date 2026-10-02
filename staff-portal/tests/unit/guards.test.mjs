// Self-lockout guards, called directly (CONTRACTS §8.5; A §4–5; B trap 8).
// The API suites drive them over HTTP; here every branch and every hostile
// caller shape, so a guard that cannot tell where you are refuses.

import { test, assert, run } from '../helpers/t.js';
import { makeEnvWithSchema } from '../helpers/env.js';
import { HttpError, GuardError, ValidationError } from '../../src/errors.js';
import { createOwner } from '../../src/users.js';
import { effectivePermissions } from '../../src/rbac.js';
import { resolvePolicy } from '../../src/policy.js';
import { addAllowed } from '../../src/network.js';
import { iso, HOUR } from '../../src/util.js';
import {
  assertCanRemoveAllowed, assertCanEditAllowed, assertCanBlock, checkSettings, approveCallerDevice, lockout,
} from '../../src/guards.js';

const HOSTILE = [null, undefined, NaN, Infinity, '', '   ', 'abc', {}, [], true, 0, Symbol('x')];
const HOME = '81.2.69.142';
const EDGE = { country: 'US', asn: 7922, ua: 'Mozilla/5.0 (Macintosh) Chrome/129.0.0.0 Safari/537.36', accept_language: 'en', http_protocol: 'HTTP/2', tls_version: 'TLSv1.3' };

async function world() {
  const env = await makeEnvWithSchema();
  const owner = await createOwner(env, { email: 'owner@acme.com', full_name: 'Olive Owner', password: 'owner-password-0123' }, env.__clock());
  return { env, owner };
}

async function rcFor(env, user, extra = {}) {
  const nowMs = env.__clock();
  return {
    env,
    nowMs,
    user,
    authz: await effectivePermissions(env, user, nowMs),
    policy: await resolvePolicy(env),
    ip: HOME,
    edge: EDGE,
    fp: null,
    cookies: {},
    device: { id: null, row: null },
    setCookies: [],
    ...extra,
  };
}

async function entry(env, rc, cidr, extra = {}) {
  return addAllowed(rc, { cidr, tier: 2, ...extra });
}

async function refusedWith(code, fn) {
  try {
    await fn();
  } catch (e) {
    assert.ok(e instanceof GuardError, `expected a GuardError, got ${e && e.name}: ${e && e.message}`);
    assert.equal(e.code, code);
    assert.equal(e.status, code === 'self_lockout' ? 409 : e.status);
    return e;
  }
  assert.fail(`expected ${code}`);
}

test('lockout() is a 409 self_lockout GuardError', () => {
  const e = lockout('x');
  assert.ok(e instanceof GuardError && e instanceof HttpError);
  assert.equal(e.status, 409);
  assert.deepEqual(e.body, { error: 'x', code: 'self_lockout' });
});

test('remove: the last live entry is refused; an expired one counts for nothing and goes freely', async () => {
  const { env, owner } = await world();
  const rc = await rcFor(env, owner);
  const only = await entry(env, rc, `${HOME}/32`);
  await refusedWith('self_lockout', () => assertCanRemoveAllowed(rc, only));
  const lapsed = await entry(env, rc, '185.15.56.0/24', { expires_in_hours: 1 });
  env.__advance(2 * HOUR);
  const later = await rcFor(env, owner);
  const e = await refusedWith('self_lockout', () => assertCanRemoveAllowed(later, only));
  assert.match(e.message, /last live/);
  await assertCanRemoveAllowed(later, lapsed); // expired: nobody's access changes
  // An unreadable expiry is not live either.
  env.DB.q("UPDATE allowed_ips SET expires_at = '42' WHERE id = ?", lapsed.id);
  await refusedWith('self_lockout', () => assertCanRemoveAllowed(later, only));
});

test('remove: your only cover is refused until another live entry covers you; others go freely', async () => {
  const { env, owner } = await world();
  const rc = await rcFor(env, owner);
  const mine = await entry(env, rc, `${HOME}/32`);
  const theirs = await entry(env, rc, '185.15.56.0/24');
  const e = await refusedWith('self_lockout', () => assertCanRemoveAllowed(rc, mine));
  assert.match(e.message, /add your new address first/);
  await assertCanRemoveAllowed(rc, theirs);
  await entry(env, rc, '81.2.69.0/24');
  await assertCanRemoveAllowed(rc, mine);
  // IPv6 callers are covered by IPv6 ranges only.
  const v6 = await rcFor(env, owner, { ip: '2a00:1450:4001:80b::200e' });
  const six = await entry(env, rc, '2a00:1450::/32');
  await refusedWith('self_lockout', () => assertCanRemoveAllowed(v6, six));
  await assertCanRemoveAllowed(v6, mine);
});

test('remove/edit/block: a caller whose address cannot be read is refused (fail closed)', async () => {
  const { env, owner } = await world();
  const rc0 = await rcFor(env, owner);
  const mine = await entry(env, rc0, `${HOME}/32`);
  await entry(env, rc0, '185.15.56.0/24');
  for (const ip of [...HOSTILE, '10.0.0.1x', '999.1.1.1', '81.2.69.142/32']) {
    const rc = await rcFor(env, owner, { ip });
    await refusedWith('self_lockout', () => assertCanRemoveAllowed(rc, mine));
    await refusedWith('self_lockout', () => assertCanEditAllowed(rc, mine, { expires_in_hours: 2 }));
    await refusedWith('self_lockout', () => assertCanBlock(rc, '185.15.56.0/24'));
  }
});

test('edit: only an expiry that would end your only cover is refused', async () => {
  const { env, owner } = await world();
  const rc = await rcFor(env, owner);
  const mine = await entry(env, rc, `${HOME}/32`);
  await entry(env, rc, '185.15.56.0/24');
  await assertCanEditAllowed(rc, mine, { label: 'Desk' });
  await assertCanEditAllowed(rc, mine, { tier: 1 });
  await assertCanEditAllowed(rc, mine, { expires_at: null });
  await assertCanEditAllowed(rc, mine, null);
  await refusedWith('self_lockout', () => assertCanEditAllowed(rc, mine, { expires_in_hours: 8760 }));
  await refusedWith('self_lockout', () => assertCanEditAllowed(rc, mine, { expires_at: iso(env.__clock() + HOUR) }));
  await refusedWith('self_lockout', () => assertCanEditAllowed(rc, mine, { tier: 4 }), 'tier 4 brings its own expiry');
  await refusedWith('self_lockout', () => assertCanEditAllowed(rc, mine, { tier: '4' }));
  // Hostile values are validation errors, not a pass.
  for (const v of ['', '   ', 'abc', {}, [], true, 0, -1]) {
    await assert.rejects(() => assertCanEditAllowed(rc, mine, { expires_in_hours: v }), ValidationError, `hours ${JSON.stringify(v)}`);
    await assert.rejects(() => assertCanEditAllowed(rc, mine, { tier: v }), ValidationError, `tier ${JSON.stringify(v)}`);
  }
  // Extending an expiry is never a lockout; shortening one is.
  env.DB.q('UPDATE allowed_ips SET expires_at = ? WHERE id = ?', iso(env.__clock() + 10 * HOUR), mine.id);
  const timed = { ...mine, expires_at: iso(env.__clock() + 10 * HOUR) };
  await assertCanEditAllowed(rc, timed, { expires_in_hours: 20 });
  await refusedWith('self_lockout', () => assertCanEditAllowed(rc, timed, { expires_in_hours: 5 }));
  // With another cover, anything goes.
  await entry(env, rc, '81.2.69.0/24');
  await assertCanEditAllowed(rc, mine, { expires_in_hours: 1 });
});

test('block: a range containing the caller is refused, v4 and v6; others pass', async () => {
  const { env, owner } = await world();
  const rc = await rcFor(env, owner);
  for (const cidr of [HOME, `${HOME}/32`, '81.2.69.0/24', '81.0.0.0/8', '::ffff:81.2.69.142']) {
    assert.throws(() => assertCanBlock(rc, cidr), (e) => e instanceof GuardError && e.code === 'self_lockout', cidr);
  }
  for (const cidr of ['185.15.56.0/24', '2a00::/16', '81.2.70.0/24', ...HOSTILE]) assertCanBlock(rc, cidr);
  const v6 = await rcFor(env, owner, { ip: '2a00:1450:4001:80b::200e' });
  assert.throws(() => assertCanBlock(v6, '2a00::/16'), GuardError);
  assertCanBlock(v6, '81.2.69.0/24');
});

test('settings: each blocking case away from the allowlist, and the allowlist bypass', async () => {
  const { env, owner } = await world();
  const rc = await rcFor(env, owner, { device: { id: 'dev-1', row: { id: 'dev-1', status: 'approved' } } });
  const cases = [
    [{ country_allow: '["GB"]' }, rc],
    [{ country_deny: '["US"]' }, rc],
    [{ country_deny: '["*"]' }, rc],
    [{ country_allow: '["US"]' }, await rcFor(env, owner, { edge: { ...EDGE, country: null }, device: rc.device })],
    [{ block_tor: '1' }, await rcFor(env, owner, { edge: { ...EDGE, country: 'T1' }, device: rc.device })],
    [{ block_datacenter: '1' }, await rcFor(env, owner, { edge: { ...EDGE, asn: 16509 }, device: rc.device })],
    [{ block_automation: '1' }, await rcFor(env, owner, { edge: { ...EDGE, ua: 'curl/8.0' }, device: rc.device })],
    [{ block_automation: '1' }, await rcFor(env, owner, { fp: { automation: true, risk: 0 }, device: rc.device })],
    [{ risk_threshold: '40' }, await rcFor(env, owner, { gate: { risk: { score: 40 } }, device: rc.device })],
    [{ risk_threshold: '1' }, await rcFor(env, owner, { gate: { risk: { score: 35 } }, device: rc.device })],
    [{ access_mode: 'lockdown' }, rc],
  ];
  for (const [raws, r] of cases) await refusedWith('self_lockout', () => checkSettings(r, raws));
  // Fine away from the allowlist.
  for (const raws of [{ country_allow: '["US","GB"]' }, { country_deny: '["KP"]' }, { block_tor: '1' }, { block_datacenter: '1' }, { risk_threshold: '41' }]) {
    const g = await checkSettings(await rcFor(env, owner, { gate: { risk: { score: 40 } }, device: rc.device }), raws);
    assert.equal(g.approve, false, JSON.stringify(raws));
  }
  // Allowlisted: the edge-rule guards stand aside (B trap 8); lockdown needs a Super Admin there.
  await entry(env, rc, `${HOME}/32`);
  for (const [raws, r] of cases) await checkSettings(r, raws);
  const admin = { ...owner, id: owner.id };
  const notSuper = await rcFor(env, admin, { device: rc.device });
  notSuper.authz = { ...notSuper.authz, isSuper: false };
  await refusedWith('self_lockout', () => checkSettings(notSuper, { access_mode: 'lockdown' }));
});

test('settings: gating on and restrictive modes ask for approval; unknown and gate keys are refused', async () => {
  const { env, owner } = await world();
  await entry(env, await rcFor(env, owner), `${HOME}/32`);
  const pending = { id: 'dev-2', row: { id: 'dev-2', status: 'pending' } };
  const rc = await rcFor(env, owner, { device: pending });
  assert.equal((await checkSettings(rc, { device_gating: '1' })).approve, true);
  assert.match((await checkSettings(rc, { device_gating: '1' })).notices[0], /approved/);
  assert.equal((await checkSettings(rc, { access_mode: 'invite_only' })).approve, true);
  assert.equal((await checkSettings(rc, { access_mode: 'lockdown' })).approve, true);
  assert.equal((await checkSettings(rc, { access_mode: 'request_access' })).approve, false);
  assert.equal((await checkSettings(rc, { device_gating: '0' })).approve, false);
  const approved = await rcFor(env, owner, { device: { id: 'd', row: { status: 'approved' } } });
  assert.equal((await checkSettings(approved, { device_gating: '1' })).approve, false);
  const blocked = await rcFor(env, owner, { device: { id: 'b', row: { status: 'blocked' } } });
  await refusedWith('self_lockout', () => checkSettings(blocked, { device_gating: '1' }));
  for (const raws of [{ gate_open: '1' }, { nope: '1' }, { __proto__: '1', toString: 'x' }, { constructor: '1' }]) {
    await assert.rejects(() => checkSettings(rc, raws), ValidationError, JSON.stringify(raws));
  }
  // A settings-only change needs no address at all; an access change does.
  const nowhere = await rcFor(env, owner, { ip: null, edge: undefined, device: undefined });
  assert.deepEqual(await checkSettings(nowhere, { timezone: 'UTC', streak_window_hours: '30' }), { approve: false, warnings: [], notices: [] });
  await refusedWith('self_lockout', () => checkSettings(nowhere, { device_gating: '1' }));
  // null = back to the default.
  assert.equal((await checkSettings(rc, { access_mode: null })).approve, false);
});

test('settings: the gate simulation refuses what the rules list does not name', async () => {
  const { env, owner } = await world();
  // In through the open gate only: not allowlisted, device pending, no fingerprint.
  env.DB.q("INSERT INTO settings (key, value, updated_at) VALUES ('gate_open', '1', ?)", iso(env.__clock()));
  const rc = await rcFor(env, owner, { device: { id: 'p', row: { status: 'pending' } } });
  const e = await refusedWith('self_lockout', () => checkSettings(rc, { access_mode: 'fingerprint_gate' }));
  assert.match(e.message, /fingerprint required/);
  await checkSettings(rc, { access_mode: 'request_access' });
  // A blocked address is refused whatever the settings say.
  env.DB.q("INSERT INTO blocked_ips (cidr, created_at) VALUES ('81.2.69.0/24', ?)", iso(env.__clock()));
  await refusedWith('self_lockout', () => checkSettings(rc, { access_mode: 'request_access' }));
});

test('settings: hostile caller shapes never throw anything but a guard or validation error', async () => {
  const { env, owner } = await world();
  for (const v of HOSTILE) {
    const rc = await rcFor(env, owner, { edge: v, fp: v, gate: v, device: v, cookies: v, policy: v });
    for (const raws of [{ risk_threshold: '50' }, { block_tor: '1' }, { country_allow: '["US"]' }, { access_mode: 'allowlist' }]) {
      try {
        await checkSettings(rc, raws);
      } catch (e) {
        assert.ok(e instanceof HttpError, `${String(typeof v === 'symbol' ? 'Symbol' : JSON.stringify(v))} ${JSON.stringify(raws)}: ${e && e.stack}`);
      }
    }
  }
});

test('warnings count other people, not the caller', async () => {
  const { env, owner } = await world();
  await entry(env, await rcFor(env, owner), `${HOME}/32`);
  const rc = await rcFor(env, owner, { device: { id: 'd', row: { status: 'approved' } } });
  assert.deepEqual((await checkSettings(rc, { device_gating: '1' })).warnings, [], 'the caller alone: no warning');
  assert.deepEqual((await checkSettings(rc, { mfa_policy: 'required' })).warnings.length, 1, 'the owner has no factor here');
  const t = iso(env.__clock());
  env.DB.q(`INSERT INTO users (email, full_name, status, role_id, created_at, updated_at) VALUES ('a@acme.com', 'A', 'active', 5, ?, ?)`, t, t);
  env.DB.q(`INSERT INTO users (email, full_name, status, role_id, created_at, updated_at) VALUES ('b@acme.com', 'B', 'disabled', 5, ?, ?)`, t, t);
  const w = (await checkSettings(rc, { device_gating: '1' })).warnings;
  assert.equal(w.length, 1);
  assert.match(w[0], /^1 active person has no approved device/);
  assert.match((await checkSettings(rc, { mfa_policy: 'required' })).warnings[0], /^2 active people have no second factor/);
});

test('approveCallerDevice mints and approves, leaves an approved one alone, refuses a blocked one', async () => {
  const { env, owner } = await world();
  const rc = await rcFor(env, owner, { device: { id: null, row: null }, request: new Request('https://staff.example.com/', { headers: { 'user-agent': EDGE.ua } }) });
  const r = await approveCallerDevice(rc);
  assert.equal(r.prior.status, 'pending');
  assert.equal(r.row.status, 'approved');
  assert.equal(rc.setCookies.length, 1, 'a minted device gets its cookie');
  assert.equal(rc.device.row.status, 'approved');
  assert.equal(await approveCallerDevice(rc), null);
  env.DB.q("UPDATE devices SET status = 'blocked' WHERE id = ?", rc.device.id);
  const again = await rcFor(env, owner, { device: { id: rc.device.id, row: { id: rc.device.id, status: 'blocked', last_seen: iso(env.__clock()) } } });
  await refusedWith('self_lockout', () => approveCallerDevice(again));
  assert.equal(env.DB.q('SELECT status FROM devices WHERE id = ?', rc.device.id)[0].status, 'blocked');
});

await run();
