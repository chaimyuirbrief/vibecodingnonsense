// The allowlist and blocklist over HTTP (CONTRACTS §7.8, §8.4, §8.5; A §4;
// B trap 8): what may be entered, what may be removed, and the guards that
// stop an administrator locking themselves out — the same guards a revert
// runs (A §9).

import { test, assert, run } from '../helpers/t.js';
import { freshEnv, bootstrap, makeUser, stepUp, signIn, client, q, count, auditRows, advance, OWNER, OWNER_IP, HOUR, HOSTILE } from '../helpers/flows.js';

async function world() {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const admin = await makeUser(env, owner.client, { role: 'admin', totp: true });
  return { env, owner, admin };
}

function allowRows(env) {
  return q(env, 'SELECT * FROM allowed_ips ORDER BY id');
}

async function as(env, c) {
  await stepUp(env, c);
  return c;
}

test('GET /api/admin/network says where you are and what covers you', async () => {
  const { owner, admin } = await world();
  const r = await owner.client.get('/api/admin/network');
  assert.equal(r.status, 200);
  assert.equal(r.body.you.ip, OWNER_IP);
  assert.equal(r.body.you.tier, 1);
  assert.equal(r.body.you.covered_by.cidr, `${OWNER_IP}/32`);
  assert.equal(r.body.allow.length, 1);
  assert.equal(r.body.allow[0].active, true);
  assert.equal(r.body.allow[0].covers_ip, true);
  const a = (await admin.client.get('/api/admin/network')).body;
  assert.equal(a.you.covered_by, null, 'the administrator gets in by an approved device');
  assert.equal(a.allow[0].covers_ip, false);
});

test('private, reserved and whole-family ranges are refused on the allowlist and the blocklist', async () => {
  const { env, owner } = await world();
  const c = await as(env, owner.client);
  for (const cidr of ['10.0.0.0/8', '192.168.1.0/24', '172.16.0.1', '127.0.0.1', '100.64.0.0/10', '169.254.1.1', '203.0.113.0/24', '198.51.100.7',
    '0.0.0.0/0', '::/0', '::1', 'fe80::/10', 'fc00::/7', '2001:db8::/32', '224.0.0.0/4', '81.2.69.7/24', '1.2.3.4/33', '01.2.3.4']) {
    const r = await c.post('/api/admin/network/allow', { cidr, tier: 2 });
    assert.equal(r.status, 400, `allow ${cidr}: ${r.text}`);
    assert.equal(r.body.field, 'cidr');
    const b = await c.post('/api/admin/network/block', { cidr });
    assert.equal(b.status, 400, `block ${cidr}: ${b.text}`);
  }
  const whole = await c.post('/api/admin/network/allow', { cidr: '0.0.0.0/0', tier: 1 });
  assert.match(whole.body.error, /Open to the internet/);
  for (const v of HOSTILE) {
    assert.equal((await c.post('/api/admin/network/allow', { cidr: v, tier: 2 })).status, 400, `cidr ${String(typeof v === 'symbol' ? 'Symbol' : JSON.stringify(v))}`);
    if (v !== 0) assert.equal((await c.post('/api/admin/network/allow', { cidr: '91.198.174.0/24', tier: v })).status, 400, `tier ${String(typeof v === 'symbol' ? 'Symbol' : JSON.stringify(v))}`);
    assert.equal((await c.post('/api/admin/network/block', { cidr: v })).status, 400);
  }
  // JSON turns NaN and Infinity into null, which means "no expiry"; every
  // other non-integer is refused — a blank never means "never" (A §14.1).
  for (const v of ['', '   ', 'abc', {}, [], true, false, 0, -1, 8761, 1.5, '2x']) {
    const r = await c.post('/api/admin/network/allow', { cidr: '91.198.174.0/24', tier: 2, expires_in_hours: v });
    assert.equal(r.status, 400, `expires_in_hours ${JSON.stringify(v)}: ${r.text}`);
    const at = await c.post('/api/admin/network/allow', { cidr: '91.198.174.0/24', tier: 2, expires_at: v === 0 ? '42' : v });
    assert.equal(at.status, 400, `expires_at ${JSON.stringify(v)}: ${at.text}`);
  }
  assert.equal((await c.post('/api/admin/network/allow', { cidr: '91.198.174.0/24', tier: 0 })).status, 400, 'tier 0');
  assert.equal(allowRows(env).length, 1, 'nothing was added');
  assert.equal(count(env, 'SELECT COUNT(*) FROM blocked_ips'), 0);
  assert.equal(auditRows(env, 'network.allow.add').length, 1, 'only setup’s');
});

test('the last live allowlist entry cannot be removed — an expired entry is not cover', async () => {
  const { env, owner, admin } = await world();
  const c = await as(env, owner.client);
  const setupEntry = allowRows(env)[0];
  const r = await c.del(`/api/admin/network/allow/${setupEntry.id}`);
  assert.equal(r.status, 409, r.text);
  assert.equal(r.body.code, 'self_lockout');
  assert.match(r.body.error, /last live allowlist entry/);
  // A second entry that has since expired grants nothing and counts for nothing.
  const tmp = await c.post('/api/admin/network/allow', { cidr: '91.198.174.0/24', tier: 3, expires_in_hours: 1 });
  assert.equal(tmp.status, 200, tmp.text);
  advance(env, HOUR + 60 * 1000);
  await stepUp(env, c);
  const again = await c.del(`/api/admin/network/allow/${setupEntry.id}`);
  assert.equal(again.status, 409);
  assert.match(again.body.error, /last live allowlist entry/);
  // Even someone it does not cover cannot empty the allowlist.
  await stepUp(env, admin.client);
  const other = await admin.client.del(`/api/admin/network/allow/${setupEntry.id}`);
  assert.equal(other.status, 409);
  assert.equal(allowRows(env).length, 2);
  // Removing the expired one is fine: it changes nobody's access.
  assert.equal((await c.del(`/api/admin/network/allow/${tmp.body.entry.id}`)).status, 200);
  const denied = auditRows(env, 'network.allow.remove').filter((a) => a.outcome === 'denied');
  assert.equal(denied.length, 3, 'each refusal is in the audit log as denied');
});

test('removing, editing or expiring your only cover is refused until another live entry covers you', async () => {
  const { env, owner } = await world();
  const c = await as(env, owner.client);
  const setupEntry = allowRows(env)[0];
  const elsewhere = await c.post('/api/admin/network/allow', { cidr: '185.15.56.0/24', tier: 2, label: 'Branch' });
  assert.equal(elsewhere.status, 200);
  const del = await c.del(`/api/admin/network/allow/${setupEntry.id}`);
  assert.equal(del.status, 409, 'not the last entry, but your only cover');
  assert.match(del.body.error, /add your new address first/);
  // Editing it without touching the expiry is fine; giving it one is not.
  assert.equal((await c.patch(`/api/admin/network/allow/${setupEntry.id}`, { label: 'Owner desk' })).status, 200);
  for (const patch of [{ expires_in_hours: 5 }, { expires_at: new Date(env.__clock() + HOUR).toISOString() }, { tier: 4 }]) {
    const r = await c.patch(`/api/admin/network/allow/${setupEntry.id}`, patch);
    assert.equal(r.status, 409, `${JSON.stringify(patch)}: ${r.text}`);
    assert.equal(r.body.code, 'self_lockout');
  }
  assert.equal(allowRows(env)[0].expires_at, null);
  assert.equal(allowRows(env)[0].label, 'Owner desk');
  // Add the new cover first; then the old one may go.
  const office = await c.post('/api/admin/network/allow', { cidr: '81.2.69.0/24', tier: 2, label: 'Office' });
  assert.equal(office.status, 200);
  assert.equal((await c.patch(`/api/admin/network/allow/${setupEntry.id}`, { expires_in_hours: 5 })).status, 200);
  assert.equal((await c.del(`/api/admin/network/allow/${setupEntry.id}`)).status, 200);
  assert.equal((await c.get('/api/me')).status, 200, 'still in');
  const net = (await c.get('/api/admin/network')).body;
  assert.equal(net.you.covered_by.cidr, '81.2.69.0/24');
  // An entry that never covered you edits and goes freely.
  assert.equal((await c.patch(`/api/admin/network/allow/${elsewhere.body.entry.id}`, { expires_in_hours: 1 })).status, 200);
  assert.equal((await c.del(`/api/admin/network/allow/${elsewhere.body.entry.id}`)).status, 200);
});

test('tier 4 entries get 24 hours by themselves and stop admitting anyone when they lapse', async () => {
  const { env, owner } = await world();
  const c = await as(env, owner.client);
  const t0 = env.__clock();
  const r = await c.post('/api/admin/network/allow', { cidr: '185.15.56.0/24', tier: 4, label: 'Contractor' });
  assert.equal(r.status, 200, r.text);
  assert.equal(Date.parse(r.body.entry.expires_at), t0 + 24 * HOUR);
  const visitor = client(env, { ip: '185.15.56.9' });
  assert.equal((await visitor.get('/login')).status, 200, 'allowlisted for now');
  advance(env, 24 * HOUR + 1000);
  assert.equal((await visitor.get('/login')).status, 403, 'lapsed: grants nothing');
  const relog = await c.get('/api/admin/network');
  assert.equal(relog.status, 401, 'the owner’s own session idled out meanwhile');
  const fresh = client(env, { ip: OWNER_IP });
  assert.equal((await signIn(env, fresh, OWNER.email, OWNER.password, { totpSecret: owner.totpSecret })).status, 200);
  const net = (await fresh.get('/api/admin/network')).body;
  const row = net.allow.find((a) => a.cidr === '185.15.56.0/24');
  assert.equal(row.active, false, 'kept, shown as expired');
  // Removing an explicit expiry on tier 4 is not "never": it gets 24 hours again.
  await stepUp(env, fresh, owner.totpSecret);
  const e = await fresh.patch(`/api/admin/network/allow/${row.id}`, { expires_at: null });
  assert.equal(e.status, 200, e.text);
  assert.ok(Date.parse(e.body.entry.expires_at) > env.__clock());
});

test('a block containing your own address is refused; any other range blocks at once', async () => {
  const { env, owner, admin } = await world();
  const c = await as(env, owner.client);
  for (const cidr of [OWNER_IP, '81.2.69.0/24', '81.2.0.0/16', '81.0.0.0/8']) {
    const r = await c.post('/api/admin/network/block', { cidr, reason: 'oops' });
    assert.equal(r.status, 409, `${cidr}: ${r.text}`);
    assert.equal(r.body.code, 'self_lockout');
  }
  assert.equal(count(env, 'SELECT COUNT(*) FROM blocked_ips'), 0);
  const adminIp = admin.client.ip;
  await stepUp(env, admin.client);
  const self = await admin.client.post('/api/admin/network/block', { cidr: adminIp });
  assert.equal(self.status, 409, 'the guard is about the caller, allowlisted or not');
  const victim = client(env, { ip: '185.15.56.20' });
  const b = await c.post('/api/admin/network/block', { cidr: '185.15.56.0/24', label: 'Credential stuffing', expires_in_hours: 2 });
  assert.equal(b.status, 200, b.text);
  assert.equal(b.body.entry.reason, 'Credential stuffing', 'the console’s label is the reason');
  const r = await victim.get('/login');
  assert.equal(r.status, 403);
  assert.equal(r.text, '');
  const list = (await c.get('/api/admin/network')).body.block;
  assert.equal(list.length, 1);
  assert.equal(list[0].covers_ip, false);
  assert.equal((await c.del(`/api/admin/network/block/${b.body.entry.id}`)).status, 200);
  assert.equal((await victim.get('/login')).status, 403, 'still not allowlisted, but no longer blocked');
  assert.equal(q(env, "SELECT reason FROM visits WHERE ip = '185.15.56.20' ORDER BY id DESC LIMIT 1")[0].reason, 'not_allowlisted');
});

test('unknown or hostile ids are 404; the routes need network.manage and a step-up', async () => {
  const { env, owner, admin } = await world();
  const c = await as(env, owner.client);
  for (const id of ['abc', '0', '-1', '1.5', '99999', '%00', '1e3']) {
    assert.equal((await c.del(`/api/admin/network/allow/${id}`)).status, 404, `allow ${id}`);
    assert.equal((await c.patch(`/api/admin/network/allow/${id}`, { label: 'x' })).status, 404, `patch ${id}`);
    assert.equal((await c.del(`/api/admin/network/block/${id}`)).status, 404, `block ${id}`);
  }
  const auditor = await makeUser(env, owner.client, { role: 'auditor', totp: true });
  await stepUp(env, auditor.client);
  assert.equal((await auditor.client.get('/api/admin/network')).status, 200);
  assert.equal((await auditor.client.post('/api/admin/network/allow', { cidr: '91.198.174.0/24', tier: 2 })).status, 403);
  const stale = admin.client;
  advance(env, 20 * 60 * 1000);
  const r = await stale.post('/api/admin/network/allow', { cidr: '91.198.174.0/24', tier: 2 });
  assert.equal(r.status, 403);
  assert.equal(r.body.step_up_required, true);
  assert.equal(allowRows(env).length, 1);
});

test('reverting an allowlist add that would strip your own cover is refused by the same guard as DELETE', async () => {
  const { env, owner } = await world();
  const c = await as(env, owner.client);
  const setupEntry = allowRows(env)[0];
  const office = await c.post('/api/admin/network/allow', { cidr: '81.2.69.0/24', tier: 2, label: 'Office' });
  assert.equal(office.status, 200);
  assert.equal((await c.del(`/api/admin/network/allow/${setupEntry.id}`)).status, 200);
  // The office range is now the owner's only cover (and the only live entry).
  const add = auditRows(env, 'network.allow.add').find((a) => a.target_id === String(office.body.entry.id));
  const viaDelete = await c.del(`/api/admin/network/allow/${office.body.entry.id}`);
  assert.equal(viaDelete.status, 409);
  await stepUp(env, c);
  const viaRevert = await c.post(`/api/admin/audit/${add.id}/revert`, {});
  assert.equal(viaRevert.status, 409, viaRevert.text);
  assert.equal(viaRevert.body.code, 'self_lockout');
  assert.equal(viaRevert.body.error, viaDelete.body.error, 'one guard, one sentence');
  // With a second cover, a third live entry, the revert goes through.
  await c.post('/api/admin/network/allow', { cidr: `${OWNER_IP}/32`, tier: 1 });
  await stepUp(env, c);
  const ok = await c.post(`/api/admin/audit/${add.id}/revert`, {});
  assert.equal(ok.status, 200, ok.text);
  assert.equal(count(env, 'SELECT COUNT(*) FROM allowed_ips WHERE id = ?', office.body.entry.id), 0);
});

await run();
