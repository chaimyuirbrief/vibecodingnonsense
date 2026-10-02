// Texted and emailed codes (CONTRACTS §7.6, §8.4; A §7.1–7.2, §13.2; SPEC
// §7.1, §7.6). The provider is env.__fetch; "no provider" means the TWILIO_*
// and RESEND_* settings are simply absent, so a regression cannot pass by
// texting a stub (A §13.2).

import { test, assert, run } from '../helpers/t.js';
import {
  freshEnv, bootstrap, makeUser, enrollTotp, actorRc, fakeProvider, lastCodeSent, q, count, auditRows, advance, TWILIO, MINUTE, PASSWORD, HOSTILE,
} from '../helpers/flows.js';
import { addDestination, removeDestination } from '../../src/mfa/otp.js';

const PHONE = '+15555550123';

async function world({ sms = true, email = false } = {}) {
  const provider = fakeProvider();
  const vars = { __fetch: provider.fetch, ...(sms ? TWILIO : {}), ...(email ? { RESEND_API_KEY: 're_test_key', MAIL_FROM: 'Portal <portal@acme.com>' } : {}) };
  const env = freshEnv({ vars });
  const owner = await bootstrap(env);
  const amy = await makeUser(env, owner.client, { email: 'amy@acme.com' });
  const rc = await actorRc(env, owner.user);
  const smsDest = await addDestination(rc, amy.user.id, { kind: 'sms', address: PHONE, label: 'Mobile' });
  return { env, owner, amy, provider, rc, smsDest };
}

const login = (c) => c.post('/api/auth/login', { identifier: 'amy@acme.com', password: PASSWORD });

test('a code as the only method is sent automatically and signs in', async () => {
  const { env, amy, provider } = await world();
  const r = await login(amy.client);
  assert.equal(r.status, 200, r.text);
  assert.equal(r.body.mfa_required, true);
  assert.deepEqual(r.body.methods, ['sms']);
  assert.deepEqual(r.body.sent, { kind: 'sms', hint: '•••• 0123' });
  assert.equal(r.body.destinations.length, 1);
  assert.equal(provider.calls.length, 1);
  assert.match(provider.calls[0].url, /api\.twilio\.com/);
  assert.equal(new URLSearchParams(provider.calls[0].body).get('To'), PHONE);
  assert.ok(!r.text.includes(PHONE), 'the full number never leaves the server');
  const code = lastCodeSent(provider);
  const wrong = await amy.client.post('/api/auth/mfa/otp', { token: r.body.token, code: code === '000000' ? '111111' : '000000' });
  assert.equal(wrong.status, 401);
  const ok = await amy.client.post('/api/auth/mfa/otp', { token: r.body.token, code });
  assert.equal(ok.status, 200, ok.text);
  assert.match(auditRows(env, 'login.success').at(-1).detail, /texted code/);
  assert.ok(!JSON.stringify(auditRows(env)).includes(code), 'the code is never logged');
  // Single use.
  const r2 = await login(amy.client);
  assert.equal((await amy.client.post('/api/auth/mfa/otp', { token: r2.body.token, code })).status, 401);
});

test('a code goes out unasked only when it is the ONLY method', async () => {
  const { env, amy, provider } = await world();
  await enrollTotp(env, amy.client);
  const r = await login(amy.client);
  assert.deepEqual(r.body.methods, ['totp', 'backup', 'sms']);
  assert.equal(r.body.sent, null);
  assert.equal(provider.calls.length, 0, 'nobody with an authenticator is texted');
  // Choosing the destination sends one, under a new token bound to it.
  const send = await amy.client.post('/api/auth/mfa/send', { token: r.body.token, destination_id: r.body.destinations[0].id });
  assert.equal(send.status, 200, send.text);
  assert.notEqual(send.body.token, r.body.token);
  assert.deepEqual(send.body.sent, { kind: 'sms', hint: '•••• 0123' });
  assert.equal(provider.calls.length, 1);
  // The old token is bound to no destination: the code does not work with it.
  assert.equal((await amy.client.post('/api/auth/mfa/otp', { token: r.body.token, code: lastCodeSent(provider) })).status, 401);
  assert.equal((await amy.client.post('/api/auth/mfa/otp', { token: send.body.token, code: lastCodeSent(provider) })).status, 200);
});

test('removing the destination stops a code already sent there being a way in', async () => {
  const { env, amy, provider, rc, smsDest } = await world();
  await enrollTotp(env, amy.client); // so the destination is not the last factor
  const r = await login(amy.client);
  const send = await amy.client.post('/api/auth/mfa/send', { token: r.body.token, destination_id: smsDest.id });
  assert.equal(send.status, 200);
  await removeDestination(rc, amy.user.id, smsDest.id);
  const late = await amy.client.post('/api/auth/mfa/otp', { token: send.body.token, code: lastCodeSent(provider) });
  assert.equal(late.status, 401);
});

test('someone else’s destination id is refused and sends nothing', async () => {
  const { env, owner, amy, provider, rc } = await world();
  await enrollTotp(env, amy.client);
  const bob = await makeUser(env, owner.client, { email: 'bob@acme.com' });
  const bobDest = await addDestination(rc, bob.user.id, { kind: 'sms', address: '+15555550999' });
  const r = await login(amy.client);
  const send = await amy.client.post('/api/auth/mfa/send', { token: r.body.token, destination_id: bobDest.id });
  assert.equal(send.status, 404);
  for (const v of HOSTILE) {
    const h = await amy.client.post('/api/auth/mfa/send', { token: r.body.token, destination_id: v });
    assert.ok([400, 404, 429].includes(h.status), `destination_id ${String(typeof v === 'symbol' ? 'Symbol' : JSON.stringify(v))}: ${h.status}`);
  }
  assert.equal(provider.calls.length, 0);
});

test('with NO provider configured nothing is ever fetched and no code method is offered', async () => {
  const { env, amy, provider, smsDest } = await world({ sms: false });
  // Only an unusable destination: the account is password-only for now.
  const plain = await login(amy.client);
  assert.equal(plain.status, 200);
  assert.equal(plain.body.ok, true, 'signed in with the password');
  assert.equal(plain.body.mfa_required, undefined);
  await enrollTotp(env, amy.client);
  const r = await login(amy.client);
  assert.deepEqual(r.body.methods, ['totp', 'backup']);
  assert.ok(!r.body.methods.includes('sms'));
  assert.deepEqual(r.body.destinations, []);
  assert.equal(r.body.sent, null);
  const send = await amy.client.post('/api/auth/mfa/send', { token: r.body.token, destination_id: smsDest.id });
  assert.equal(send.status, 409);
  const step = await amy.client.get('/api/me/step-up');
  assert.deepEqual(step.body.destinations, []);
  assert.equal((await amy.client.post('/api/me/step-up/send', { destination_id: smsDest.id })).status, 409);
  assert.equal(provider.calls.length, 0, 'no outbound fetch, ever');
  assert.equal(auditRows(env, 'mfa.code_sent').length, 0);
});

test('emailed codes work the same way', async () => {
  const { env, amy, provider, rc, smsDest } = await world({ sms: false, email: true });
  await removeDestination(rc, amy.user.id, smsDest.id).catch(() => {});
  q(env, 'DELETE FROM code_destinations WHERE user_id = ?', amy.user.id);
  await addDestination(rc, amy.user.id, { kind: 'email', address: 'amy.personal@example.org' });
  const r = await login(amy.client);
  assert.deepEqual(r.body.methods, ['email']);
  assert.equal(r.body.sent.kind, 'email');
  assert.equal(provider.calls.length, 1);
  assert.match(provider.calls[0].url, /resend/);
  const body = JSON.parse(provider.calls[0].body);
  const code = /\b(\d{6})\b/.exec(body.text)[1];
  const ok = await amy.client.post('/api/auth/mfa/otp', { token: r.body.token, code });
  assert.equal(ok.status, 200);
  assert.match(auditRows(env, 'login.success').at(-1).detail, /emailed code/);
});

test('sending is limited per person, and a provider failure is a polite 503', async () => {
  const { env, amy, provider } = await world();
  await enrollTotp(env, amy.client);
  const r = await login(amy.client);
  const id = r.body.destinations[0].id;
  for (let i = 0; i < 5; i++) assert.equal((await amy.client.post('/api/auth/mfa/send', { token: r.body.token, destination_id: id })).status, 200);
  assert.equal((await amy.client.post('/api/auth/mfa/send', { token: r.body.token, destination_id: id })).status, 429);
  assert.equal(provider.calls.length, 5);
  advance(env, 16 * MINUTE);
  env.__fetch = fakeProvider(500).fetch;
  const r2 = await login(amy.client);
  const fail = await amy.client.post('/api/auth/mfa/send', { token: r2.body.token, destination_id: id });
  assert.equal(fail.status, 503);
  assert.equal(count(env, 'SELECT COUNT(*) FROM otp_challenges WHERE used_at IS NULL AND expires_at > ?', new Date(env.__clock()).toISOString()), 0, 'the failed send left no live code');
});

test('step-up with a texted code', async () => {
  const { env, amy, provider, smsDest } = await world();
  const signedIn = await login(amy.client);
  await amy.client.post('/api/auth/mfa/otp', { token: signedIn.body.token, code: lastCodeSent(provider) });
  const info = await amy.client.get('/api/me/step-up');
  assert.deepEqual(info.body.methods, ['sms']);
  const sent = await amy.client.post('/api/me/step-up/send', { destination_id: smsDest.id });
  assert.equal(sent.status, 200);
  const bad = await amy.client.post('/api/me/step-up/otp', { destination_id: smsDest.id, code: '12345' });
  assert.equal(bad.status, 400);
  const ok = await amy.client.post('/api/me/step-up/otp', { destination_id: smsDest.id, code: lastCodeSent(provider) });
  assert.equal(ok.status, 200, ok.text);
  assert.equal((await amy.client.get('/api/me')).body.step_up_fresh, true);
});

await run();
