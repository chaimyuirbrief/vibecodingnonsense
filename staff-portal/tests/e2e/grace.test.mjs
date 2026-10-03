// Second-factor grace windows at sign-in (CONTRACTS §7.8, §7.9; A §8; SPEC §8.9).

import { test, assert, run } from '../helpers/t.js';
import {
  freshEnv, client, bootstrap, makeUser, signIn, nextTotp, q, count, auditRows, advance, advanceDays, setSetting, actorRc, DAY, HOUR, OWNER_IP, PASSWORD,
} from '../helpers/flows.js';
import { addAllowed } from '../../src/network.js';

async function world() {
  const env = freshEnv();
  const owner = await bootstrap(env);
  // Amy on the tier-1 office address, with an authenticator.
  const amy = await makeUser(env, owner.client, { email: 'amy@acme.com', ip: OWNER_IP, totp: true });
  return { env, owner, amy };
}

const login = (c) => c.post('/api/auth/login', { identifier: 'amy@acme.com', password: PASSWORD });

async function provedSignIn(env, amy) {
  const r = await signIn(env, amy.client, 'amy@acme.com', PASSWORD, { totpSecret: amy.totpSecret });
  assert.equal(r.status, 200, r.text);
  assert.equal(r.body.ok, true);
  return r;
}

test('a factor proved on a tier-1 address lasts seven days on that device', async () => {
  const { env, amy } = await world();
  await provedSignIn(env, amy);
  const g = q(env, 'SELECT * FROM mfa_grace WHERE user_id = ?', amy.user.id);
  assert.equal(g.length, 1);
  assert.equal(g[0].tier, 1);
  assert.equal(g[0].device_id, q(env, 'SELECT device_id FROM sessions WHERE user_id = ? ORDER BY rowid DESC LIMIT 1', amy.user.id)[0].device_id);
  const verifiedAt = g[0].verified_at;

  advanceDays(env, 6);
  const r = await login(amy.client);
  assert.equal(r.status, 200);
  assert.equal(r.body.ok, true, 'no factor asked');
  assert.equal(r.body.mfa_required, undefined);
  assert.match(auditRows(env, 'login.success').at(-1).detail, /grace window/);
  const s = q(env, 'SELECT aal, mfa_at, mfa_method FROM sessions WHERE user_id = ? ORDER BY rowid DESC LIMIT 1', amy.user.id)[0];
  assert.deepEqual(s, { aal: 2, mfa_at: verifiedAt, mfa_method: 'grace' });
  assert.equal(q(env, 'SELECT verified_at FROM mfa_grace WHERE user_id = ?', amy.user.id)[0].verified_at, verifiedAt, 'riding a window does not extend it');

  advance(env, DAY);
  const late = await login(amy.client);
  assert.equal(late.body.mfa_required, true, 'seven days after the proof, a factor again');
});

test('a new device on the same network gets no grace', async () => {
  const { env, amy } = await world();
  await provedSignIn(env, amy);
  const laptop2 = client(env, { ip: OWNER_IP });
  const r = await laptop2.post('/api/auth/login', { identifier: 'amy@acme.com', password: PASSWORD });
  assert.equal(r.body.mfa_required, true);
});

test('the same device from an address that is not allowlisted gets no grace', async () => {
  const { env, amy } = await world();
  await provedSignIn(env, amy);
  amy.client.ip = '91.198.174.200'; // her approved device, on the café wifi
  const r = await login(amy.client);
  assert.equal(r.status, 200);
  assert.equal(r.body.mfa_required, true);
  // …and proving a factor there records no window (no tier, no grace).
  const before = q(env, 'SELECT verified_at FROM mfa_grace WHERE user_id = ?', amy.user.id)[0].verified_at;
  const ok = await amy.client.post('/api/auth/mfa/code', { token: r.body.token, code: await nextTotp(env, amy.totpSecret) });
  assert.equal(ok.status, 200);
  assert.equal(q(env, 'SELECT verified_at FROM mfa_grace WHERE user_id = ?', amy.user.id)[0].verified_at, before);
});

test('a lower-trust network shortens the window; mfa_grace off turns it off', async () => {
  const { env, owner, amy } = await world();
  await provedSignIn(env, amy);
  await addAllowed(await actorRc(env, owner.user), { cidr: '185.15.56.0/24', tier: 2 });
  amy.client.ip = '185.15.56.20';
  advance(env, 23 * HOUR);
  assert.equal((await login(amy.client)).body.ok, true, 'inside a tier-2 day');
  advance(env, 2 * HOUR);
  assert.equal((await login(amy.client)).body.mfa_required, true, 'past a tier-2 day, though tier 1 would still allow it');
  amy.client.ip = OWNER_IP;
  assert.equal((await login(amy.client)).body.ok, true);
  setSetting(env, 'mfa_grace', '0');
  assert.equal((await login(amy.client)).body.mfa_required, true);
  setSetting(env, 'mfa_grace', 'maybe'); // unrecognised reads as off
  assert.equal((await login(amy.client)).body.mfa_required, true);
});

test('a factor proved while mfa_grace is off records no window', async () => {
  const { env, amy } = await world();
  setSetting(env, 'mfa_grace', '0');
  await provedSignIn(env, amy);
  assert.equal(count(env, 'SELECT COUNT(*) FROM mfa_grace WHERE user_id = ?', amy.user.id), 0);
});

await run();
