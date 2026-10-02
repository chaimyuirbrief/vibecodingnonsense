// Authenticator codes and backup codes at sign-in (CONTRACTS §8.4 Auth;
// A §7.2–7.3; SPEC §7.2, §7.4–7.5).

import { test, assert, run } from '../helpers/t.js';
import {
  freshEnv, bootstrap, makeUser, nextTotp, totpNow, q, count, auditRows, advance, MINUTE, HOSTILE, PASSWORD, SESSION_COOKIE,
} from '../helpers/flows.js';
import { TOTP_STEP_MS } from '../../src/mfa/totp.js';

async function world() {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const amy = await makeUser(env, owner.client, { email: 'amy@acme.com', totp: true });
  return { env, owner, amy };
}

async function password(c) {
  const r = await c.post('/api/auth/login', { identifier: 'amy@acme.com', password: PASSWORD });
  assert.equal(r.status, 200, r.text);
  assert.equal(r.body.mfa_required, true);
  return r;
}

const sessionsOf = (env, uid) => count(env, 'SELECT COUNT(*) FROM sessions WHERE user_id = ?', uid);

test('password then authenticator: offered methods, then an AAL2 session', async () => {
  const { env, amy } = await world();
  const r = await password(amy.client);
  assert.deepEqual(r.body.methods, ['totp', 'backup']);
  assert.deepEqual(r.body.destinations, []);
  assert.equal(r.body.sent, null);
  assert.equal(typeof r.body.token, 'string');
  assert.equal(r.headers.get('set-cookie'), null, 'no session before the factor');
  const before = sessionsOf(env, amy.user.id);
  const ok = await amy.client.post('/api/auth/mfa/code', { token: r.body.token, code: await nextTotp(env, amy.totpSecret) });
  assert.equal(ok.status, 200, ok.text);
  assert.equal(ok.body.ok, true);
  assert.equal(ok.body.enroll_prompt, false);
  assert.equal(sessionsOf(env, amy.user.id), before + 1);
  const s = q(env, 'SELECT aal, mfa_method FROM sessions WHERE user_id = ? ORDER BY created_at DESC, rowid DESC LIMIT 1', amy.user.id)[0];
  assert.deepEqual(s, { aal: 2, mfa_method: 'totp' });
  assert.match(auditRows(env, 'login.success').at(-1).detail, /authenticator app/);
});

test('a code already spent is refused (the replay floor), a newer one works', async () => {
  const { env, amy } = await world();
  const t1 = await password(amy.client);
  const code = await nextTotp(env, amy.totpSecret);
  assert.equal((await amy.client.post('/api/auth/mfa/code', { token: t1.body.token, code })).status, 200);
  const t2 = await password(amy.client);
  const replay = await amy.client.post('/api/auth/mfa/code', { token: t2.body.token, code });
  assert.equal(replay.status, 401);
  assert.equal(replay.body.code, 'mfa_invalid');
  // The previous step's code is below the floor as well.
  const older = await amy.client.post('/api/auth/mfa/code', { token: t2.body.token, code: await totpNow(amy.totpSecret, env, -1) });
  assert.equal(older.status, 401);
  assert.equal(auditRows(env, 'mfa.fail').length, 2);
  const fresh = await amy.client.post('/api/auth/mfa/code', { token: t2.body.token, code: await nextTotp(env, amy.totpSecret) });
  assert.equal(fresh.status, 200);
});

test('a backup code works in the same box, any case and spacing, exactly once', async () => {
  const { env, amy } = await world();
  const backup = amy.client.backupCodes[0];
  assert.match(backup, /^[A-Z2-9]{5}-[A-Z2-9]{5}$/);
  const typed = ` ${backup.toLowerCase().replace('-', ' ')} `;
  const t1 = await password(amy.client);
  const ok = await amy.client.post('/api/auth/mfa/code', { token: t1.body.token, code: typed });
  assert.equal(ok.status, 200, ok.text);
  assert.match(auditRows(env, 'login.success').at(-1).detail, /backup code/);
  assert.equal(auditRows(env, 'mfa.backup.used').length, 1);
  assert.equal(count(env, 'SELECT COUNT(*) FROM backup_codes WHERE user_id = ? AND used_at IS NULL', amy.user.id), 9);
  const t2 = await password(amy.client);
  assert.equal((await amy.client.post('/api/auth/mfa/code', { token: t2.body.token, code: backup })).status, 401);
});

test('a suspension landing between the password and the factor fails the factor step', async () => {
  const { env, amy } = await world();
  const t = await password(amy.client);
  q(env, "UPDATE users SET status = 'suspended' WHERE id = ?", amy.user.id);
  const sessions = sessionsOf(env, amy.user.id);
  const r = await amy.client.post('/api/auth/mfa/code', { token: t.body.token, code: await nextTotp(env, amy.totpSecret) });
  assert.equal(r.status, 401);
  assert.equal(r.text, '{"error":"Invalid credentials."}');
  assert.equal(sessionsOf(env, amy.user.id), sessions, 'no session');
  assert.match(auditRows(env, 'mfa.fail').at(-1).detail, /suspended/);
  // The code it carried was not spent either.
  assert.equal(count(env, 'SELECT COUNT(*) FROM user_totp WHERE user_id = ? AND last_counter = ?', amy.user.id, Math.floor(env.__clock() / TOTP_STEP_MS)), 0);
});

test('the half-finished sign-in expires after five minutes and cannot be forged', async () => {
  const { env, amy, owner } = await world();
  const t = await password(amy.client);
  advance(env, 5 * MINUTE + 1000);
  const late = await amy.client.post('/api/auth/mfa/code', { token: t.body.token, code: await totpNow(amy.totpSecret, env) });
  assert.equal(late.status, 401);
  assert.equal(late.body.code, 'mfa_expired');
  // Amy's token re-signed for the owner's id is not a token.
  const [, dest, exp, mac] = t.body.token.split('.');
  const forged = `${owner.user.id}.${dest}.${exp}.${mac}`;
  assert.equal((await amy.client.post('/api/auth/mfa/code', { token: forged, code: '123456' })).status, 401);
  for (const v of HOSTILE) {
    const r = await amy.client.post('/api/auth/mfa/code', { token: v, code: '123456' });
    assert.equal(r.status, 401, String(typeof v === 'symbol' ? 'Symbol' : JSON.stringify(v)));
    assert.equal(r.body.code, 'mfa_expired');
  }
  for (const path of ['/api/auth/mfa/send', '/api/auth/mfa/otp', '/api/auth/mfa/passkey/options', '/api/auth/mfa/passkey/verify']) {
    assert.equal((await amy.client.post(path, { token: 'nope', code: '123456', destination_id: 1 })).status, 401, path);
  }
  assert.equal(auditRows(env, 'login.success').length, 2, 'setup and the invitation only');
});

test('hostile codes never sign anyone in; the factor bucket is charged first', async () => {
  const { env, amy } = await world();
  const sessions = sessionsOf(env, amy.user.id);
  let t = await password(amy.client);
  let n = 0;
  for (const v of [...HOSTILE, '000000', '12345', '1234567', 'ABCDE-FGHJK', '-----', ' '.repeat(70)]) {
    if (n++ % 4 === 0 && n > 1) {
      advance(env, 16 * MINUTE);
      t = await password(amy.client);
    }
    const r = await amy.client.post('/api/auth/mfa/code', { token: t.body.token, code: v });
    assert.equal(r.status, 401, `code ${String(typeof v === 'symbol' ? 'Symbol' : JSON.stringify(v))}: ${r.text}`);
  }
  assert.equal(sessionsOf(env, amy.user.id), sessions);
  assert.equal(amy.client.jar.has(SESSION_COOKIE), true, 'the session from the invitation, not a new one');
});

test('five wrong factor attempts and the sixth is refused, even with the right code', async () => {
  const { env, amy } = await world();
  const t = await password(amy.client);
  for (let i = 0; i < 5; i++) assert.equal((await amy.client.post('/api/auth/mfa/code', { token: t.body.token, code: '000000' })).status, 401);
  const r = await amy.client.post('/api/auth/mfa/code', { token: t.body.token, code: await nextTotp(env, amy.totpSecret) });
  assert.equal(r.status, 429);
});

test('an authenticator that will not decrypt is refused, never read as "no factor"', async () => {
  const { env, amy } = await world();
  q(env, "UPDATE user_totp SET secret_enc = 'v1.AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' WHERE user_id = ?", amy.user.id);
  q(env, 'DELETE FROM backup_codes WHERE user_id = ?', amy.user.id);
  const r = await amy.client.post('/api/auth/login', { identifier: 'amy@acme.com', password: PASSWORD });
  assert.equal(r.status, 200);
  assert.equal(r.body.mfa_required, true, 'not a password-only sign-in');
  assert.deepEqual(r.body.methods, []);
  const code = await amy.client.post('/api/auth/mfa/code', { token: r.body.token, code: await nextTotp(env, amy.totpSecret) });
  assert.equal(code.status, 401);
  assert.equal(auditRows(env, 'mfa.decrypt_failed').length, 1);
});

await run();
