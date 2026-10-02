// Settings and the gate switch over HTTP (CONTRACTS §5, §8.4, §8.5; A §4,
// §14.1, §14.11; B trap 8). Table-driven over every key: its permission,
// hostile values (400, nothing stored), legal edges including an explicit 0,
// every blocking self-lockout case, auto-approve notices and warnings.

import { test, assert, run } from '../helpers/t.js';
import {
  freshEnv, bootstrap, makeUser, stepUp, roleId, signIn, client, q, auditRows, advance, setSetting,
  OWNER, OWNER_IP, HOUR, MINUTE, CHROME_UA,
} from '../helpers/flows.js';
import { Client } from '../helpers/http.js';
import worker from '../../worker.js';
import { SETTINGS } from '../../src/policy.js';

const HEADLESS_UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/129.0.0.0 Safari/537.36';

// CONTRACTS §5, the perm column — the registry must agree with it.
const PERM = {
  access_mode: 'security.manage', deny_style: 'security.manage', country_allow: 'security.manage', country_deny: 'security.manage',
  block_tor: 'security.manage', block_datacenter: 'security.manage', block_automation: 'security.manage', risk_threshold: 'security.manage',
  mfa_policy: 'security.manage', mfa_grace: 'security.manage', device_gating: 'settings.manage', step_up_minutes: 'settings.manage',
  session_idle_minutes: 'settings.manage', session_absolute_hours: 'settings.manage', timezone: 'settings.manage', privacy_notice: 'settings.manage',
  privacy_notice_text: 'settings.manage', streak_enabled: 'settings.manage', streak_window_hours: 'settings.manage',
  streak_reentry_grace_hours: 'settings.manage', streak_max_leeway_days: 'settings.manage', streak_weekly_days: 'settings.manage',
  streak_hebrew_holidays: 'settings.manage', streak_region: 'settings.manage', streak_extra_dates: 'settings.manage', streak_leaderboard: 'settings.manage',
};

// Legal values (edges first), each followed by the stored raw it must produce.
const LEGAL = {
  access_mode: [['request_access', 'request_access'], ['allowlist', 'allowlist']],
  deny_style: [['decoy', 'decoy'], ['empty', 'empty']],
  country_allow: [[['us', 'GB'], '["GB","US"]'], [[], '[]']],
  country_deny: [[['KP'], '["KP"]'], [[], '[]']],
  block_tor: [[false, '0'], [true, '1']],
  block_datacenter: [[true, '1'], [0, '0']],
  block_automation: [['0', '0'], [1, '1']],
  risk_threshold: [[1, '1'], [100, '100'], ['70', '70']],
  mfa_policy: [['required', 'required'], ['prompt', 'prompt']],
  mfa_grace: [[false, '0'], [true, '1']],
  device_gating: [[true, '1'], [false, '0']],
  step_up_minutes: [[120, '120'], [1, '1'], [15, '15']],
  session_idle_minutes: [[1440, '1440'], [5, '5'], [120, '120']],
  session_absolute_hours: [[72, '72'], [1, '1'], [8, '8']],
  timezone: [['Europe/London', 'Europe/London'], ['America/New_York', 'America/New_York']],
  privacy_notice: [[false, '0'], [true, '1']],
  privacy_notice_text: [['abc', 'abc'], ['x'.repeat(500), 'x'.repeat(500)]],
  streak_enabled: [[false, '0'], [true, '1']],
  streak_window_hours: [[24, '24'], [72, '72'], [30, '30']],
  streak_reentry_grace_hours: [[0, '0'], [24, '24'], [12, '12']],
  streak_max_leeway_days: [[0, '0'], ['0', '0'], [7, '7'], [4, '4']],
  streak_weekly_days: [[[0, 6, 6], '[0,6]'], [[], '[]'], [[6], '[6]']],
  streak_hebrew_holidays: [[false, '0'], [true, '1']],
  streak_region: [['israel', 'israel'], ['diaspora', 'diaspora']],
  streak_extra_dates: [[[{ date: '2026-03-01', label: 'Closed' }], '[{"date":"2026-03-01","label":"Closed"}]'], [[], '[]']],
  streak_leaderboard: [['managers', 'managers'], ['off', 'off'], ['all', 'all']],
};

// A §14.1: blanks, null, booleans, objects are errors, never defaults. A
// flag's own value is a boolean (that is what the console sends), and a
// list's own value is an array, so those stay legal for those types.
function hostileFor(key) {
  const s = SETTINGS[key];
  const base = [null, '', '   ', true, {}, [], 'abc'];
  if (s.type === 'flag') return [...base.filter((v) => v !== true), 'true', 'yes', 2, -1];
  if (s.type === 'int') return [...base, false, '2x', 1.5, s.min - 1, s.max + 1, '0x10'];
  if (s.type === 'json-list') return [...base.filter((v) => !Array.isArray(v)), '[]', [{}], [null], ['abc']];
  if (s.type === 'string') return [...base.filter((v) => v !== 'abc'), 'x'.repeat(501)];
  if (s.type === 'timezone') return [...base, 'Mars/Olympus_Mons'];
  return [...base, s.options[0].toUpperCase()];
}

function raw(env, key) {
  const row = q(env, 'SELECT value FROM settings WHERE key = ?', key)[0];
  return row ? row.value : null;
}

function show(v) {
  return typeof v === 'string' ? JSON.stringify(v) : Array.isArray(v) ? `[${v.length}]` : String(v && typeof v === 'object' ? '{…}' : v);
}

async function put(env, c, changes) {
  await stepUp(env, c);
  return c.put('/api/admin/settings', { changes });
}

async function world() {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const admin = await makeUser(env, owner.client, { role: 'admin', totp: true });
  // A second Super Admin on a non-allowlisted address (their approved device
  // lets them in): the edge-rule guards only bite away from the allowlist.
  const away = await makeUser(env, owner.client, { role: 'admin', totp: true });
  await stepUp(env, owner.client);
  const p = await owner.client.post(`/api/admin/users/${away.user.id}/role`, { role_id: roleId(env, 'super_admin'), perm_grants: [], perm_denies: [] });
  assert.equal(p.status, 200, p.text);
  return { env, owner, admin, away };
}

test('the registry carries the §5 permission for every key, and GET says who may edit what', async () => {
  const { owner, admin } = await world();
  assert.deepEqual(Object.keys(SETTINGS).filter((k) => k !== 'gate_open').sort(), Object.keys(PERM).sort());
  for (const [k, perm] of Object.entries(PERM)) assert.equal(SETTINGS[k].perm, perm, k);
  const mine = (await admin.client.get('/api/admin/settings')).body.settings;
  for (const s of mine) {
    assert.equal(s.can_edit, s.key !== 'gate_open' && s.perm === 'settings.manage', `${s.key} can_edit for an administrator`);
    assert.ok('value' in s && 'default' in s && 'raw' in s && 'description' in s, s.key);
  }
  const all = (await owner.client.get('/api/admin/settings')).body.settings;
  assert.ok(all.every((s) => s.can_edit === (s.key !== 'gate_open')));
  assert.equal(all.find((s) => s.key === 'gate_open').value.open, false);
});

test('each key needs its own permission: an administrator is refused every security.manage key', async () => {
  const { env, admin } = await world();
  for (const [key, perm] of Object.entries(PERM)) {
    const before = raw(env, key);
    const [value, stored] = LEGAL[key][0];
    const r = await put(env, admin.client, { [key]: value });
    if (perm === 'security.manage') {
      assert.equal(r.status, 403, `${key}: ${r.text}`);
      assert.equal(raw(env, key), before, `${key} unchanged`);
    } else {
      assert.equal(r.status, 200, `${key}: ${r.text}`);
      assert.equal(raw(env, key), stored, key);
      const back = await put(env, admin.client, { [key]: LEGAL[key][LEGAL[key].length - 1][0] });
      assert.equal(back.status, 200, `${key} back: ${back.text}`);
    }
  }
});

test('hostile values are 400 for every key, and nothing is stored or audited', async () => {
  const { env, owner } = await world();
  const okBefore = auditRows(env, 'setting.change').length;
  for (const key of Object.keys(PERM)) {
    const before = raw(env, key);
    await stepUp(env, owner.client);
    for (const v of hostileFor(key)) {
      const r = await owner.client.put('/api/admin/settings', { changes: { [key]: v } });
      assert.equal(r.status, 400, `${key} = ${show(v)}: ${r.status} ${r.text}`);
      assert.equal(raw(env, key), before, `${key} = ${show(v)} changed the stored value`);
    }
    // "missing": the key with no value, which JSON drops.
    const missing = await owner.client.put('/api/admin/settings', { changes: { [key]: undefined } });
    assert.equal(missing.status, 400, `${key} missing`);
  }
  for (const b of [{}, { changes: null }, { changes: [] }, { changes: 'x' }, { changes: { nope: 1 } }, { changes: { gate_open: '1' } }]) {
    const r = await owner.client.put('/api/admin/settings', b);
    assert.equal(r.status, 400, `${JSON.stringify(b)}: ${r.text}`);
  }
  // All or nothing: one bad value refuses the good one beside it.
  const mixed = await owner.client.put('/api/admin/settings', { changes: { timezone: 'Europe/Paris', step_up_minutes: '' } });
  assert.equal(mixed.status, 400);
  assert.equal(raw(env, 'timezone'), null);
  assert.equal(raw(env, 'gate_open'), null, 'the gate cannot be opened through settings');
  assert.equal(auditRows(env, 'setting.change').length, okBefore, 'no setting.change row for a refusal');
});

test('legal edges are stored exactly — an explicit 0 stays 0 where the range allows it', async () => {
  const { env, owner } = await world();
  for (const [key, values] of Object.entries(LEGAL)) {
    for (const [value, stored] of values) {
      const r = await put(env, owner.client, { [key]: value });
      assert.equal(r.status, 200, `${key} = ${show(value)}: ${r.text}`);
      assert.equal(raw(env, key), stored, `${key} = ${show(value)}`);
    }
  }
  const zero = await put(env, owner.client, { streak_reentry_grace_hours: 0 });
  assert.equal(zero.status, 200);
  assert.equal(raw(env, 'streak_reentry_grace_hours'), '0');
  const policy = (await owner.client.get('/api/admin/settings')).body.settings.find((s) => s.key === 'streak_reentry_grace_hours');
  assert.equal(policy.value, 0, 'read back as 0, not the default 12');
  // An unchanged value is not a write: no row, no undo.
  const n = auditRows(env, 'setting.change').length;
  const same = await put(env, owner.client, { streak_reentry_grace_hours: '0' });
  assert.equal(same.status, 200);
  assert.deepEqual(same.body.applied, []);
  assert.equal(auditRows(env, 'setting.change').length, n);
  const last = auditRows(env, 'setting.change').pop();
  assert.equal(last.undo_kind, 'setting');
  assert.deepEqual(JSON.parse(last.undo_payload), { key: 'streak_reentry_grace_hours', prior: '12' });
});

test('every blocking self-lockout case refuses with 409 self_lockout from a non-allowlisted address', async () => {
  const { env, owner, away } = await world();
  const c = away.client;
  const expect409 = async (changes, why) => {
    const before = q(env, 'SELECT key, value FROM settings ORDER BY key');
    const r = await put(env, c, changes);
    assert.equal(r.status, 409, `${why}: ${r.status} ${r.text}`);
    assert.equal(r.body.code, 'self_lockout', why);
    assert.ok(r.body.error.length > 20, 'a sentence that says what to do instead');
    assert.deepEqual(q(env, 'SELECT key, value FROM settings ORDER BY key'), before, `${why}: nothing stored`);
    const denied = auditRows(env, 'setting.change').pop();
    assert.equal(denied.outcome, 'denied', `${why}: recorded as denied`);
  };
  await expect409({ country_allow: ['GB'] }, 'country_allow without your country');
  await expect409({ country_deny: ['US'] }, 'country_deny with your country');
  await expect409({ country_allow: ['US'], country_deny: ['US'] }, 'the two lists together');
  await expect409({ access_mode: 'lockdown' }, 'lockdown away from the allowlist');

  // Datacenter address: block_datacenter, and a threshold at its risk (35).
  c.cf = { ...c.cf, asn: 14061, asOrganization: 'DigitalOcean' };
  await expect409({ block_datacenter: true }, 'block_datacenter from a datacenter');
  await expect409({ risk_threshold: 35 }, 'threshold equal to your risk');
  await expect409({ risk_threshold: 20 }, 'threshold below your risk');
  assert.equal((await put(env, c, { risk_threshold: 36 })).status, 200, 'just above your risk is fine');
  c.cf = { ...c.cf, asn: 7922, asOrganization: 'Comcast Cable' };
  assert.equal((await put(env, owner.client, { risk_threshold: 70 })).status, 200);

  // Tor: the owner (allowlisted) turns the block off; through Tor, turning it on locks you out.
  assert.equal((await put(env, owner.client, { block_tor: false })).status, 200);
  c.cf = { ...c.cf, country: 'T1' };
  await expect409({ block_tor: true }, 'block_tor through Tor');
  c.cf = { ...c.cf, country: 'US' };

  // Automation tells in the user agent.
  assert.equal((await put(env, owner.client, { block_automation: false })).status, 200);
  c.ua = HEADLESS_UA;
  await expect409({ block_automation: true }, 'block_automation while headless');
  c.ua = CHROME_UA;

  // The same changes from the allowlisted owner: the allowlist bypasses the edge rules (B trap 8).
  for (const changes of [{ country_deny: ['US'] }, { country_deny: [] }, { block_tor: true }, { block_automation: true }, { access_mode: 'lockdown' }, { access_mode: 'allowlist' }]) {
    const r = await put(env, owner.client, changes);
    assert.equal(r.status, 200, `${JSON.stringify(changes)} from the allowlist: ${r.text}`);
  }
});

test('the gate itself is the last word: a change that would leave you refused is refused', async () => {
  const { env, owner, away } = await world();
  // Away from the allowlist on a brand-new device, in only because the gate is open.
  await stepUp(env, owner.client);
  assert.equal((await owner.client.post('/api/admin/gate/open', { hours: 2 })).status, 200);
  const fresh = new Client(worker, env, { ip: '185.15.56.77' });
  const s = await signIn(env, fresh, away.user.email, away.password, { totpSecret: away.totpSecret });
  assert.equal(s.status, 200, s.text);
  await stepUp(env, fresh, away.totpSecret);
  const r2 = await fresh.put('/api/admin/settings', { changes: { access_mode: 'fingerprint_gate' } });
  assert.equal(r2.status, 409, r2.text);
  assert.equal(r2.body.code, 'self_lockout');
  assert.match(r2.body.error, /fingerprint/);
  assert.equal(q(env, "SELECT value FROM settings WHERE key = 'access_mode'").length, 0);
});

test('turning device gating on, or a restrictive mode, approves the caller’s device and says so', async () => {
  const { env, owner } = await world();
  // A fresh browser on the owner's allowlisted address: in by the network, device still pending.
  const fresh = new Client(worker, env, { ip: OWNER_IP });
  assert.equal((await signIn(env, fresh, OWNER.email, OWNER.password, { totpSecret: owner.totpSecret })).status, 200);
  const devId = q(env, 'SELECT device_id FROM sessions ORDER BY created_at DESC LIMIT 1')[0].device_id;
  assert.equal(q(env, 'SELECT status FROM devices WHERE id = ?', devId)[0].status, 'pending');
  await stepUp(env, fresh, owner.totpSecret);
  const r = await fresh.put('/api/admin/settings', { changes: { device_gating: true } });
  assert.equal(r.status, 200, r.text);
  assert.ok(r.body.notices.some((n) => /approved/.test(n)), JSON.stringify(r.body));
  assert.equal(q(env, 'SELECT status FROM devices WHERE id = ?', devId)[0].status, 'approved');
  const appr = auditRows(env, 'device.approve').pop();
  assert.equal(appr.target_id, devId);
  assert.equal(appr.undo_kind, 'device.status');
  assert.equal((await fresh.get('/api/me')).status, 200, 'still in, gating and all');
  assert.equal((await put(env, owner.client, { device_gating: false })).status, 200);
  // Already approved: no second approval, no notice.
  const again = await put(env, owner.client, { device_gating: true });
  assert.deepEqual(again.body.notices, []);
  assert.equal((await put(env, owner.client, { device_gating: false })).status, 200);

  const fresh2 = new Client(worker, env, { ip: OWNER_IP });
  await signIn(env, fresh2, OWNER.email, OWNER.password, { totpSecret: owner.totpSecret });
  await stepUp(env, fresh2, owner.totpSecret);
  const m = await fresh2.put('/api/admin/settings', { changes: { access_mode: 'invite_only' } });
  assert.equal(m.status, 200, m.text);
  assert.ok(m.body.notices.length === 1);
  assert.equal((await fresh2.get('/api/me')).status, 200, 'invite_only admits the newly approved device');
  assert.equal((await put(env, owner.client, { access_mode: 'allowlist' })).status, 200);
});

test('warnings: gating or a restrictive mode while people have no approved device; required MFA while people have no factor', async () => {
  const { env, owner } = await world();
  const plain = await makeUser(env, owner.client, { role: 'employee' }); // no factor
  // Someone active whose device was revoked: no approved device, address not allowlisted.
  q(env, "UPDATE devices SET status = 'pending' WHERE id IN (SELECT device_id FROM device_users WHERE user_id = ?)", plain.user.id);
  const g = await put(env, owner.client, { device_gating: true });
  assert.equal(g.status, 200);
  assert.equal(g.body.warnings.length, 1, JSON.stringify(g.body));
  assert.match(g.body.warnings[0], /^1 active person has no approved device/);
  assert.equal(raw(env, 'device_gating'), '1', 'a warning still saves');
  await put(env, owner.client, { device_gating: false });
  const mode = await put(env, owner.client, { access_mode: 'request_access' });
  assert.deepEqual(mode.body.warnings, []);
  const back = await put(env, owner.client, { access_mode: 'allowlist' });
  assert.match(back.body.warnings[0], /neither an approved device nor an allowlisted address/);
  const mfa = await put(env, owner.client, { mfa_policy: 'required' });
  assert.match(mfa.body.warnings[0], /no second factor/);
  const lock = await put(env, owner.client, { access_mode: 'lockdown' });
  assert.match(lock.body.warnings.join(' '), /signed out and refused until lockdown ends/);
  await put(env, owner.client, { access_mode: 'allowlist' });
  // Nobody affected, no warning.
  q(env, "UPDATE devices SET status = 'approved' WHERE id IN (SELECT device_id FROM device_users WHERE user_id = ?)", plain.user.id);
  await put(env, owner.client, { mfa_policy: 'prompt' });
  q(env, "UPDATE users SET status = 'suspended' WHERE id = ?", plain.user.id);
  assert.deepEqual((await put(env, owner.client, { device_gating: true })).body.warnings, []);
  assert.deepEqual((await put(env, owner.client, { mfa_policy: 'required' })).body.warnings, []);
});

// ---------------------------------------------------------------- the gate

test('opening the gate: hostile hours are 400 before any coercion, and nothing opens', async () => {
  const { env, owner, admin } = await world();
  await stepUp(env, owner.client);
  for (const b of [{ hours: '' }, { hours: null }, {}, { hours: true }, { hours: false }, { hours: 0 }, { hours: 169 }, { hours: '2x' }, { hours: 1.5 },
    { hours: '   ' }, { hours: [] }, { hours: {} }, { hours: -1 }, { forever: 'yes' }, { forever: 1 }, { forever: false }, { hours: 2, forever: true }]) {
    const r = await owner.client.post('/api/admin/gate/open', b);
    assert.equal(r.status, 400, `${JSON.stringify(b)}: ${r.text}`);
    assert.equal(raw(env, 'gate_open'), null, `${JSON.stringify(b)} touched the setting`);
  }
  assert.equal(auditRows(env, 'gate.open').length, 0);
  await stepUp(env, admin.client);
  const notYours = await admin.client.post('/api/admin/gate/open', { hours: 2 });
  assert.equal(notYours.status, 403, 'gate.open is reserved');
  assert.equal((await admin.client.get('/api/admin/gate')).status, 403);
});

test('{ hours: 2 } opens the gate and it closes itself two hours later; forever and close work', async () => {
  const { env, owner } = await world();
  const stranger = client(env);
  assert.equal((await stranger.get('/login')).status, 403, 'a stranger sees nothing while it is closed');
  await stepUp(env, owner.client);
  const r = await owner.client.post('/api/admin/gate/open', { hours: 2 });
  assert.equal(r.status, 200, r.text);
  assert.equal(r.body.open, true);
  assert.equal(r.body.forever, false);
  assert.equal(Date.parse(r.body.until), env.__clock() + 2 * HOUR);
  assert.equal((await stranger.get('/login')).status, 200, 'open to the internet');
  const row = auditRows(env, 'gate.open').pop();
  assert.equal(row.undo_kind, null, 'opening the gate is never revertible');
  advance(env, 2 * HOUR - MINUTE);
  assert.equal((await owner.client.get('/api/admin/gate')).body.open, true);
  advance(env, 2 * MINUTE);
  assert.equal((await owner.client.get('/api/admin/gate')).body.open, false, 'closed by itself');
  assert.equal((await stranger.get('/login')).status, 403);

  await stepUp(env, owner.client);
  const f = await owner.client.post('/api/admin/gate/open', { forever: true });
  assert.equal(f.status, 200);
  assert.equal(f.body.forever, true);
  assert.equal(raw(env, 'gate_open'), '1');
  advance(env, 100 * MINUTE); // well past any timed opening (sessions idle out at 120)
  await stepUp(env, owner.client);
  assert.equal((await owner.client.get('/api/admin/gate')).body.open, true);
  const c = await owner.client.post('/api/admin/gate/close', {});
  assert.equal(c.status, 200);
  assert.equal(c.body.open, false);
  assert.equal(raw(env, 'gate_open'), '0');
  assert.equal(auditRows(env, 'gate.close').length, 1);
  const list = (await owner.client.get('/api/admin/audit?action=gate.')).body.entries;
  assert.ok(list.length >= 3 && list.every((e) => e.revertible === false));
});

test('a stored gate value that is not "0", "1" or a future ISO instant reads as closed', async () => {
  const { env, owner } = await world();
  for (const v of ['42', 'true', 'open', '2099', '', ' 1', '2026-01-06']) {
    setSetting(env, 'gate_open', v);
    const g = await owner.client.get('/api/admin/gate');
    assert.equal(g.body.open, false, `'${v}'`);
  }
});

await run();
