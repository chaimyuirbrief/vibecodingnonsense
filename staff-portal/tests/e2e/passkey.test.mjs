// Passkeys end to end with a software authenticator (CONTRACTS §7.5, §8.4;
// A §7.4, §7.6).

import { test, assert, run } from '../helpers/t.js';
import { freshEnv, bootstrap, makeUser, enrollTotp, q, count, auditRows, stepUp, PASSWORD, HOSTILE } from '../helpers/flows.js';
import { SoftAuthenticator } from '../helpers/authenticator.js';

async function world(alg = -7) {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const amy = await makeUser(env, owner.client, { email: 'amy@acme.com' });
  const auth = new SoftAuthenticator({ alg, origin: env.ORIGIN, rpId: env.RP_ID });
  return { env, owner, amy, auth };
}

async function enrolPasskey(c, auth, label = 'Laptop') {
  const opts = await c.post('/api/me/mfa/passkey/options', {});
  assert.equal(opts.status, 200, opts.text);
  const cred = await auth.create(opts.body);
  const r = await c.post('/api/me/mfa/passkey/register', { credential: cred, label });
  assert.equal(r.status, 200, r.text);
  return r;
}

async function passwordStep(c, email = 'amy@acme.com') {
  const r = await c.post('/api/auth/login', { identifier: email, password: PASSWORD });
  assert.equal(r.status, 200, r.text);
  assert.equal(r.body.mfa_required, true);
  return r.body.token;
}

for (const alg of [-7, -257]) {
  test(`enrol and sign in with a passkey (alg ${alg})`, async () => {
    const { env, amy, auth } = await world(alg);
    const reg = await enrolPasskey(amy.client, auth);
    assert.equal(reg.body.passkey.label, 'Laptop');
    assert.equal(reg.body.backup_codes.length, 10, 'first strong factor issues backup codes');
    assert.equal(reg.body.pinned, null);
    assert.equal(auditRows(env, 'mfa.passkey.add').length, 1);

    const token = await passwordStep(amy.client);
    const opts = await amy.client.post('/api/auth/mfa/passkey/options', { token });
    assert.equal(opts.status, 200);
    assert.equal(opts.body.allowCredentials.length, 1);
    const assertion = await auth.get(opts.body);
    const ok = await amy.client.post('/api/auth/mfa/passkey/verify', { token, credential: assertion });
    assert.equal(ok.status, 200, ok.text);
    assert.equal(ok.body.enroll_prompt, false);
    assert.match(auditRows(env, 'login.success').at(-1).detail, /a passkey/);
    const s = q(env, 'SELECT aal, mfa_method FROM sessions WHERE user_id = ? ORDER BY rowid DESC LIMIT 1', amy.user.id)[0];
    assert.deepEqual(s, { aal: 2, mfa_method: 'passkey' });

    // The challenge was spent: the same assertion cannot be replayed.
    const replay = await amy.client.post('/api/auth/mfa/passkey/verify', { token, credential: assertion });
    assert.equal(replay.status, 400);
    assert.match(auditRows(env, 'mfa.fail').at(-1).detail, /challenge_unknown/);
  });
}

test('a passkey refused at sign-in is audited with its reason and signs nobody in', async () => {
  const { env, amy, auth } = await world();
  await enrolPasskey(amy.client, auth);
  const before = count(env, 'SELECT COUNT(*) FROM sessions WHERE user_id = ?', amy.user.id);
  const token = await passwordStep(amy.client);
  const opts = await amy.client.post('/api/auth/mfa/passkey/options', { token });
  const bad = await auth.get(opts.body, { badSignature: true });
  const r = await amy.client.post('/api/auth/mfa/passkey/verify', { token, credential: bad });
  assert.equal(r.status, 400);
  assert.match(auditRows(env, 'mfa.fail').at(-1).detail, /signature_invalid/);
  for (const v of HOSTILE) {
    const o = await amy.client.post('/api/auth/mfa/passkey/options', { token });
    assert.equal(o.status, 200);
    const h = await amy.client.post('/api/auth/mfa/passkey/verify', { token, credential: v });
    assert.ok(h.status === 400 || h.status === 429, `credential ${String(typeof v === 'symbol' ? 'Symbol' : JSON.stringify(v))}: ${h.status}`);
  }
  assert.equal(count(env, 'SELECT COUNT(*) FROM sessions WHERE user_id = ?', amy.user.id), before);
});

test('someone else’s passkey does not sign you in', async () => {
  const { env, owner, amy, auth } = await world();
  await enrolPasskey(amy.client, auth);
  const bob = await makeUser(env, owner.client, { email: 'bob@acme.com' });
  const bobAuth = new SoftAuthenticator({ origin: env.ORIGIN, rpId: env.RP_ID });
  await enrolPasskey(bob.client, bobAuth);
  const token = await passwordStep(amy.client);
  const opts = await amy.client.post('/api/auth/mfa/passkey/options', { token });
  // Bob's authenticator answering Amy's challenge with Bob's credential.
  const forged = await bobAuth.get(opts.body, { credential: bobAuth.lastCredential.id });
  const r = await amy.client.post('/api/auth/mfa/passkey/verify', { token, credential: forged });
  assert.equal(r.status, 400);
  assert.equal(auditRows(env, 'login.success').filter((x) => x.target_id === String(amy.user.id) && /passkey/.test(x.detail)).length, 0);
});

test('passkey step-up, then rename and remove (step-up gated, never the last factor)', async () => {
  const { env, amy, auth } = await world();
  const reg = await enrolPasskey(amy.client, auth);
  const id = reg.body.passkey.id;
  const rename = await amy.client.patch(`/api/me/mfa/passkey/${encodeURIComponent(id)}`, { label: 'Work laptop' });
  assert.equal(rename.status, 200);
  assert.equal(q(env, 'SELECT label FROM user_passkeys WHERE id = ?', id)[0].label, 'Work laptop');
  for (const v of [null, '', '   ', {}, [], true, 0, 'x'.repeat(61)]) {
    assert.equal((await amy.client.patch(`/api/me/mfa/passkey/${encodeURIComponent(id)}`, { label: v })).status, 400);
  }
  assert.equal((await amy.client.patch('/api/me/mfa/passkey/not-mine', { label: 'x' })).status, 404);

  const del1 = await amy.client.del(`/api/me/mfa/passkey/${encodeURIComponent(id)}`);
  assert.equal(del1.status, 403);
  assert.equal(del1.body.step_up_required, true);
  const o = await amy.client.post('/api/me/step-up/passkey/options', {});
  const v = await amy.client.post('/api/me/step-up/passkey/verify', { credential: await auth.get(o.body) });
  assert.equal(v.status, 200, v.text);
  assert.equal((await amy.client.get('/api/me')).body.step_up_fresh, true);
  const last = await amy.client.del(`/api/me/mfa/passkey/${encodeURIComponent(id)}`);
  assert.equal(last.status, 409);
  assert.equal(last.body.code, 'last_factor');
  assert.equal(count(env, 'SELECT COUNT(*) FROM user_passkeys WHERE user_id = ?', amy.user.id), 1);
  // With an authenticator app as well, the passkey may go.
  await enrollTotp(env, amy.client);
  await stepUp(env, amy.client);
  assert.equal((await amy.client.del(`/api/me/mfa/passkey/${encodeURIComponent(id)}`)).status, 200);
  assert.equal(count(env, 'SELECT COUNT(*) FROM user_passkeys WHERE user_id = ?', amy.user.id), 0);
  assert.equal(auditRows(env, 'mfa.passkey.remove').length, 1);
});

await run();
