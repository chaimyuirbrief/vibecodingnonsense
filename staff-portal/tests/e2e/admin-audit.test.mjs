// The audit log as the console reads it (CONTRACTS §4.2, §8.4; B §7; D10):
// no undo data and no credential ever leaves through the API, the chain
// verifies, and a tampered row is named exactly.

import { test, assert, run } from '../helpers/t.js';
import { freshEnv, bootstrap, makeUser, stepUp, q, count, auditRows, fakeProvider, sessionToken, deviceCookie } from '../helpers/flows.js';

async function world() {
  const mail = fakeProvider();
  const env = freshEnv({ vars: { RESEND_API_KEY: 're_test_key', MAIL_FROM: 'portal@acme.com', __fetch: mail.fetch } });
  const owner = await bootstrap(env);
  const emp = await makeUser(env, owner.client, { role: 'employee', totp: true });
  const auditor = await makeUser(env, owner.client, { role: 'auditor' });
  return { env, owner, emp, auditor };
}

// A busy log: an invitation (token in a URL), a factor reset (an encrypted
// TOTP secret and backup-code hashes in its undo payload), a destination
// (an address), settings, network, a revert.
async function busyLog(env, owner, emp) {
  const c = owner.client;
  await stepUp(env, c);
  const inv = await c.post('/api/admin/users', { email: 'secretive@acme.com', full_name: 'Sec Retive' });
  await c.post(`/api/admin/users/${emp.user.id}/destinations`, { kind: 'email', address: 'private.inbox@example.org' });
  const secrets = {
    totpEnc: q(env, 'SELECT secret_enc FROM user_totp WHERE user_id = ?', emp.user.id)[0].secret_enc,
    backupHashes: q(env, 'SELECT code_hash, salt FROM backup_codes WHERE user_id = ?', emp.user.id),
    inviteToken: new URL(inv.body.invitation.url).searchParams.get('token'),
  };
  assert.equal((await c.post(`/api/admin/users/${emp.user.id}/reset-mfa`, {})).status, 200);
  await c.put('/api/admin/settings', { changes: { session_idle_minutes: 60 } });
  await c.post('/api/admin/network/allow', { cidr: '185.15.56.0/24', tier: 2 });
  const last = auditRows(env, 'network.allow.add').pop();
  await c.post(`/api/admin/audit/${last.id}/revert`, {});
  return secrets;
}

function assertClean(text, env, owner, emp, secrets, where) {
  assert.ok(!text.includes('undo_payload'), `${where}: undo_payload`);
  assert.ok(!text.includes(secrets.totpEnc), `${where}: encrypted TOTP secret`);
  assert.ok(!text.includes(owner.totpSecret) && !text.includes(emp.totpSecret), `${where}: TOTP secret`);
  for (const b of secrets.backupHashes) assert.ok(!text.includes(b.code_hash) && !text.includes(b.salt), `${where}: backup-code hash`);
  assert.ok(!text.includes(secrets.inviteToken), `${where}: invitation token`);
  assert.ok(!text.includes('private.inbox@example.org'), `${where}: destination address`);
  for (const c of [owner.client, emp.client]) {
    const tok = sessionToken(c);
    if (tok) assert.ok(!text.includes(tok), `${where}: session token`);
    const dev = deviceCookie(c);
    if (dev) assert.ok(!text.includes(dev), `${where}: device cookie`);
  }
  for (const { id } of q(env, 'SELECT id FROM sessions')) assert.ok(!text.includes(id), `${where}: stored session id`);
  for (const { password_hash } of q(env, 'SELECT password_hash FROM users WHERE password_hash IS NOT NULL')) {
    assert.ok(!text.includes(password_hash), `${where}: password hash`);
  }
}

test('the audit list never carries undo data, secrets, hashes or session tokens', async () => {
  const { env, owner, emp, auditor } = await world();
  const secrets = await busyLog(env, owner, emp);
  // The payloads ARE stored — server-side.
  const reset = auditRows(env, 'mfa.reset').pop();
  assert.ok(reset.undo_payload.includes(secrets.totpEnc));
  const all = await owner.client.get('/api/admin/audit?limit=200');
  assert.equal(all.status, 200);
  assert.ok(all.body.entries.length >= 20);
  assertClean(all.text, env, owner, emp, secrets, 'owner audit list');
  const aud = await auditor.client.get('/api/admin/audit?limit=200');
  assertClean(aud.text, env, owner, emp, secrets, 'auditor audit list');
  assert.ok(aud.body.entries.every((e) => e.revertible === false), 'nothing is offered to someone who cannot revert');
  assert.ok(all.body.entries.some((e) => e.revertible === true));
  const ov = await auditor.client.get('/api/admin/overview');
  assertClean(ov.text, env, owner, emp, secrets, 'overview');
  const act = await emp.client.get('/api/me/activity');
  assertClean(act.text, env, owner, emp, secrets, 'own activity');
  const filtered = await owner.client.get('/api/admin/audit?action=mfa.');
  assertClean(filtered.text, env, owner, emp, secrets, 'filtered list');
  assert.ok(filtered.body.entries.every((e) => e.action.startsWith('mfa.')));
});

test('verify reports the chain intact, and a tampered row exactly', async () => {
  const { env, owner, emp, auditor } = await world();
  await busyLog(env, owner, emp);
  const n = count(env, 'SELECT COUNT(*) FROM audit_log');
  const v = await auditor.client.post('/api/admin/audit/verify', {});
  assert.equal(v.status, 200);
  assert.deepEqual(v.body, { ok: true, checked: n, head_seq: n, broken_at: null });
  assert.equal(auditRows(env, 'audit.verify').pop().outcome, 'success');

  const target = q(env, "SELECT id, seq FROM audit_log WHERE action = 'mfa.reset'")[0];
  env.DB.q("UPDATE audit_log SET detail = 'Nothing to see here' WHERE id = ?", target.id);
  const broken = await auditor.client.post('/api/admin/audit/verify', {});
  assert.equal(broken.body.ok, false);
  assert.deepEqual(broken.body.broken_at, { seq: target.seq, id: target.id, reason: 'hash_mismatch' });
  assert.equal(broken.body.checked, target.seq - 1);
  const rec = auditRows(env, 'audit.verify').pop();
  assert.equal(rec.outcome, 'failure');
  assert.equal(rec.severity, 'critical');
  assert.match(rec.detail, new RegExp(`#${target.seq}`));
});

test('a deleted row is a gap at its sequence number; an edited link is a prev mismatch', async () => {
  const { env, owner, emp, auditor } = await world();
  await busyLog(env, owner, emp);
  const mid = q(env, 'SELECT seq FROM audit_log ORDER BY seq LIMIT 1 OFFSET 6')[0].seq;
  env.DB.q('DELETE FROM audit_log WHERE seq = ?', mid);
  const r = (await auditor.client.post('/api/admin/audit/verify', {})).body;
  assert.equal(r.ok, false);
  assert.equal(r.broken_at.seq, mid + 1);
  assert.equal(r.broken_at.reason, 'seq_gap');

  const env2 = (await world());
  await busyLog(env2.env, env2.owner, env2.emp);
  const row = q(env2.env, 'SELECT id, seq FROM audit_log ORDER BY seq LIMIT 1 OFFSET 3')[0];
  env2.env.DB.q("UPDATE audit_log SET prev_hash = ? WHERE id = ?", 'f'.repeat(64), row.id);
  const r2 = (await env2.auditor.client.post('/api/admin/audit/verify', {})).body;
  assert.deepEqual(r2.broken_at, { seq: row.seq, id: row.id, reason: 'prev_mismatch' });
});

test('filters: blank means unfiltered, a value that cannot be valid matches nothing, paging by sequence', async () => {
  const { env, owner, emp } = await world();
  await busyLog(env, owner, emp);
  const c = owner.client;
  const total = count(env, 'SELECT COUNT(*) FROM audit_log');
  const blank = await c.get('/api/admin/audit?action=&actor=&outcome=&severity=&q=&limit=500');
  assert.equal(blank.body.entries.length, Math.min(total, 200), 'blank filters filter nothing (limit capped at 200)');
  for (const qs of ['actor=abc', 'actor=-1', 'outcome=maybe', 'severity=loud', 'before_seq=xyz', 'target_id=%00%01']) {
    const r = await c.get(`/api/admin/audit?${qs}`);
    assert.equal(r.status, 200, qs);
    if (qs !== 'target_id=%00%01') assert.deepEqual(r.body.entries, [], `${qs} matches nothing rather than everything`);
  }
  const mine = await c.get(`/api/admin/audit?actor=${owner.user.id}&outcome=success`);
  assert.ok(mine.body.entries.length > 0 && mine.body.entries.every((e) => e.actor_id === owner.user.id && e.outcome === 'success'));
  const page1 = await c.get('/api/admin/audit?limit=5');
  assert.equal(page1.body.entries.length, 5);
  const page2 = await c.get(`/api/admin/audit?limit=5&before_seq=${page1.body.next_before_seq}`);
  assert.ok(page2.body.entries[0].seq < page1.body.entries[4].seq);
  const like = await c.get('/api/admin/audit?q=%25');
  assert.deepEqual(like.body.entries.filter((e) => !String(e.detail).includes('%')), [], '% is a literal, not a wildcard');
  const reverted = (await c.get('/api/admin/audit?action=network.allow.add')).body.entries.find((e) => e.reverted_by !== null);
  assert.ok(reverted, 'the reverted entry says by whom');
  assert.equal(reverted.revertible, false);
});

await run();
