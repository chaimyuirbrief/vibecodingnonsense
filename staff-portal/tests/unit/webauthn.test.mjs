// src/webauthn/webauthn.js — both ceremonies, every row of both A §7.4
// tables, the three parsing details, challenges as rows, the counter rule
// and its audit row (CONTRACTS §7.5, §4.2; A §7.4, §14.5; B §5).

import { readFileSync } from 'node:fs';
import { createHmac } from 'node:crypto';
import path from 'node:path';
import { test, assert, run } from '../helpers/t.js';
import { makeEnvWithSchema, ROOT } from '../helpers/env.js';
import { HttpError } from '../../src/errors.js';
import { iso, MINUTE, b64urlEncode, concatBytes, hex } from '../../src/util.js';
import { sha256 } from '../../src/crypto.js';
import { decodeCbor } from '../../src/webauthn/cbor.js';
import {
  registrationOptions, verifyRegistration, assertionOptions, verifyAssertion, userHandle, passkeyError, labelFromUa,
  parseAuthData, CHALLENGE_TTL_MS, CEREMONY_TIMEOUT_MS,
} from '../../src/webauthn/webauthn.js';
import { SoftAuthenticator, TEST_AAGUID, b64u, fromB64u, encodeCbor } from '../helpers/authenticator.js';

const HOSTILE = [null, undefined, NaN, Infinity, '', '   ', 'abc', {}, [], true, 0, Symbol('x')];
const show = (v) => (typeof v === 'symbol' ? 'Symbol' : JSON.stringify(v) ?? String(v));

const UA = {
  mac: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  iphone: 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1',
  edge: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
  android: 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36',
  firefox: 'Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0',
  ipadFirefox: 'Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/132.0 Mobile/15E148 Safari/605.1.15',
};

const JANE = { id: 7, email: 'jane@acme.com', full_name: 'Jane Doe' };
const OMAR = { id: 8, email: 'omar@acme.com', full_name: 'Omar Haddad' };
const POLITE = { error: 'That passkey could not be verified.', code: 'passkey_invalid' };

// rc without nowMs: webauthn.js falls back to util.now(env), i.e. the
// injected clock, so env.__advance moves it.
async function setup({ alg = -7, ...authOpts } = {}) {
  const env = await makeEnvWithSchema();
  const rc = { env, ua: UA.mac, ip: '81.2.69.142' };
  const a = new SoftAuthenticator({ alg, origin: env.ORIGIN, rpId: env.RP_ID, ...authOpts });
  return { env, rc, a };
}

function authFor(env, opts = {}) {
  return new SoftAuthenticator({ origin: env.ORIGIN, rpId: env.RP_ID, ...opts });
}

async function enrol(rc, a, user = JANE, knobs = {}, label = 'Laptop') {
  const opts = await registrationOptions(rc, user);
  return verifyRegistration(rc, user, await a.create(opts, knobs), label);
}

async function signIn(rc, a, user = JANE, knobs = {}, kind = 'auth') {
  const opts = await assertionOptions(rc, user, kind);
  return verifyAssertion(rc, user, await a.get(opts, knobs), kind);
}

// The client sees one polite sentence; the real reason is non-enumerable.
async function refused(promise, reason, label = String(reason)) {
  let err = null;
  try {
    await promise;
  } catch (e) {
    err = e;
  }
  assert.ok(err, `${label}: expected a refusal, but it was accepted`);
  assert.ok(err instanceof HttpError, `${label}: ${err && err.stack}`);
  assert.equal(err.status, 400, label);
  assert.deepEqual(err.body, POLITE, label);
  if (reason instanceof RegExp) assert.match(err.reason, reason, label);
  else assert.equal(err.reason, reason, label);
  assert.ok(!Object.keys(err).includes('reason'), `${label}: reason must not be enumerable`);
  assert.ok(!JSON.stringify(err).includes(err.reason), `${label}: reason leaked into JSON`);
  return err;
}

const passkeys = (env) => env.DB.q('SELECT * FROM user_passkeys ORDER BY created_at, id');
const challenges = (env) => env.DB.q('SELECT * FROM webauthn_challenges ORDER BY expires_at');
const audits = (env) => env.DB.q('SELECT * FROM audit_log ORDER BY seq');
const randomChallenge = () => b64u(crypto.getRandomValues(new Uint8Array(32)));

// ------------------------------------------------------------ options

test('registration options: pubKeyCredParams exactly [-7, -257], attestation none, the §7.5 shape', async () => {
  const { env, rc } = await setup();
  const t = env.__clock();
  const o = await registrationOptions(rc, JANE);
  assert.deepEqual(o.pubKeyCredParams, [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }]);
  assert.deepEqual(Object.keys(o).sort(), [
    'attestation', 'authenticatorSelection', 'challenge', 'excludeCredentials', 'pubKeyCredParams', 'rp', 'timeout', 'user',
  ]);
  assert.equal(o.attestation, 'none');
  assert.deepEqual(o.rp, { id: 'staff.example.com', name: 'Acme Inc.' });
  assert.deepEqual(o.authenticatorSelection, { residentKey: 'preferred', userVerification: 'preferred' });
  assert.deepEqual(o.excludeCredentials, []);
  assert.equal(o.user.name, 'jane@acme.com');
  assert.equal(o.user.displayName, 'Jane Doe');
  assert.equal(o.timeout, CEREMONY_TIMEOUT_MS);
  assert.ok(o.timeout < CHALLENGE_TTL_MS, 'the browser gives up before the row expires');
  assert.equal(CHALLENGE_TTL_MS, 5 * MINUTE);
  // Challenge: 32 random bytes, url-safe, stored as a row.
  assert.match(o.challenge, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(fromB64u(o.challenge).length, 32);
  assert.deepEqual(challenges(env), [{ challenge: o.challenge, user_id: 7, kind: 'register', expires_at: iso(t + 5 * MINUTE) }]);
  const o2 = await registrationOptions(rc, JANE);
  assert.notEqual(o2.challenge, o.challenge);
  // Nothing else written.
  assert.equal(passkeys(env).length, 0);
  assert.equal(audits(env).length, 0);
});

test('user handle = b64url(first 16 bytes of HMAC(SESSION_SECRET, "webauthn-user." + id))', async () => {
  const { env, rc } = await setup();
  const want = createHmac('sha256', env.SESSION_SECRET).update('webauthn-user.7').digest().subarray(0, 16).toString('base64url');
  assert.equal(await userHandle(env, 7), want);
  const o = await registrationOptions(rc, JANE);
  assert.equal(o.user.id, want);
  assert.equal(fromB64u(o.user.id).length, 16);
  assert.notEqual((await registrationOptions(rc, OMAR)).user.id, want, 'per user');
  assert.ok(!o.user.id.includes(env.SESSION_SECRET.slice(0, 8)));
});

test('registration options fall back sensibly when the user has no name fields', async () => {
  const { rc } = await setup();
  const o = await registrationOptions(rc, { id: 9 });
  assert.equal(o.user.name, 'user-9');
  assert.equal(o.user.displayName, 'user-9');
  const o2 = await registrationOptions(rc, { id: 9, username: 'sam', full_name: '   ' });
  assert.equal(o2.user.name, 'sam');
  assert.equal(o2.user.displayName, 'sam');
});

test('excludeCredentials lists this user’s existing ids (with known transports) and no one else’s', async () => {
  const { env, rc, a } = await setup();
  const b = authFor(env, { alg: -257 });
  const c = authFor(env);
  const r1 = await enrol(rc, a, JANE, { transports: ['usb', 'nfc', 'bogus', 'usb'] });
  env.__advance(1000);
  const r2 = await enrol(rc, b, JANE, { transports: [] });
  const r3 = await enrol(rc, c, OMAR);
  const o = await registrationOptions(rc, JANE);
  assert.deepEqual(o.excludeCredentials, [
    { type: 'public-key', id: r1.id, transports: ['usb', 'nfc'] },
    { type: 'public-key', id: r2.id },
  ]);
  assert.ok(!JSON.stringify(o).includes(r3.id));
  // A browser then refuses to register the same authenticator twice.
  await assert.rejects(a.create(o), (e) => e.name === 'InvalidStateError');
  // A tampered id the browser could not decode is left out rather than breaking the ceremony.
  env.DB.q('UPDATE user_passkeys SET id = ?, transports = ? WHERE id = ?', '+/+/==', 'not json', r2.id);
  const o2 = await registrationOptions(rc, JANE);
  assert.deepEqual(o2.excludeCredentials.map((d) => d.id), [r1.id]);
});

test('assertion options: rpId, preferred UV, this user’s credentials only; kind stored on the row', async () => {
  const { env, rc, a } = await setup();
  const r1 = await enrol(rc, a, JANE, { transports: ['internal'] });
  const r2 = await enrol(rc, authFor(env), OMAR);
  for (const kind of ['auth', 'stepup']) {
    env.DB.q('DELETE FROM webauthn_challenges');
    const o = await assertionOptions(rc, JANE, kind);
    assert.deepEqual(Object.keys(o).sort(), ['allowCredentials', 'challenge', 'rpId', 'timeout', 'userVerification']);
    assert.equal(o.rpId, 'staff.example.com');
    assert.equal(o.userVerification, 'preferred');
    assert.equal(o.timeout, CEREMONY_TIMEOUT_MS);
    assert.deepEqual(o.allowCredentials, [{ type: 'public-key', id: r1.id, transports: ['internal'] }]);
    assert.ok(!JSON.stringify(o).includes(r2.id));
    assert.deepEqual(challenges(env).map((c) => [c.challenge, c.user_id, c.kind]), [[o.challenge, 7, kind]]);
  }
  const d = await assertionOptions(rc, JANE);
  assert.equal(challenges(env).find((c) => c.challenge === d.challenge).kind, 'auth', 'kind defaults to auth');
});

test('assertion options with no passkey: 400 no_passkeys and no challenge row (an empty allow-list invites any credential)', async () => {
  const { env, rc } = await setup();
  await assert.rejects(assertionOptions(rc, JANE, 'auth'), (e) => e instanceof HttpError && e.status === 400 && e.body.code === 'no_passkeys');
  assert.equal(challenges(env).length, 0);
});

// ------------------------------------------------------------ positive

for (const alg of [-7, -257]) {
  test(`${alg === -7 ? 'ES256' : 'RS256'}: enrol, then sign in repeatedly; the row is exactly what was verified`, async () => {
    const { env, rc, a } = await setup({ alg });
    const t0 = env.__clock();
    const opts = await registrationOptions(rc, JANE);
    const cred = await a.create(opts);
    const row = await verifyRegistration(rc, JANE, cred, 'Work laptop');
    const stored = passkeys(env);
    assert.equal(stored.length, 1);
    assert.deepEqual(stored[0], row, 'returns the row as inserted');
    const pub = await crypto.subtle.exportKey('jwk', a.lastCredential.keyPair.publicKey);
    const jwk = JSON.parse(row.public_key);
    assert.deepEqual(jwk, alg === -7 ? { kty: 'EC', crv: 'P-256', x: pub.x, y: pub.y } : { kty: 'RSA', n: pub.n, e: pub.e });
    assert.ok(!('d' in jwk), 'no private material stored');
    assert.equal(row.id, cred.id);
    assert.equal(row.user_id, 7);
    assert.equal(row.algorithm, alg);
    assert.equal(row.sign_count, 0);
    assert.equal(row.aaguid, hex(TEST_AAGUID));
    assert.equal(row.transports, '["internal","hybrid"]');
    assert.equal(row.label, 'Work laptop');
    assert.equal(row.created_at, iso(t0));
    assert.equal(row.last_used_at, null);
    assert.equal(challenges(env).length, 0, 'the registration challenge is spent');

    for (let i = 1; i <= 3; i++) {
      env.__advance(MINUTE);
      const res = await signIn(rc, a);
      assert.deepEqual(res, { passkeyId: row.id, userVerified: true });
      const now = passkeys(env)[0];
      assert.equal(now.sign_count, i);
      assert.equal(now.last_used_at, iso(env.__clock()));
    }
    // Step-up uses its own challenge kind.
    assert.deepEqual(await signIn(rc, a, JANE, {}, 'stepup'), { passkeyId: row.id, userVerified: true });
    assert.equal(challenges(env).length, 0);
    // Domain code audits nothing on success — the API handler does.
    assert.equal(audits(env).length, 0);
  });
}

test('UV is reported, not required (options say preferred); extensions behind ED are accepted', async () => {
  const { rc, a } = await setup();
  await enrol(rc, a, JANE, { extensions: { credProtect: 1 } });
  assert.equal((await signIn(rc, a, JANE, { flags: { UV: false } })).userVerified, false);
  assert.equal((await signIn(rc, a, JANE, { extensions: new Map([['credProtect', 2]]) })).userVerified, true);
  assert.equal((await signIn(rc, a, JANE, { flags: { BE: true, BS: true } })).userVerified, true);
});

test('labels: trimmed, control characters removed, ≤ 60; blank or hostile → a guess from the user agent', async () => {
  const { env, rc } = await setup();
  const cases = [
    ['  My key  ', 'My key'],
    ['x'.repeat(100), 'x'.repeat(60)],
    ['a\u0000b\nc\td\u007f', 'abcd'],
    ['\n\t ', 'Chrome on macOS'],
  ];
  for (const v of HOSTILE) if (typeof v !== 'string' || !v.trim() || v === 'abc') cases.push([v, v === 'abc' ? 'abc' : 'Chrome on macOS']);
  for (const [label, want] of cases) {
    const opts = await registrationOptions(rc, JANE);
    const row = await verifyRegistration(rc, JANE, await authFor(env).create(opts), label);
    assert.equal(row.label, want, `label ${show(label)}`);
  }
  const ios = await enrol({ ...rc, ua: UA.iphone }, authFor(env), JANE, {}, '');
  assert.equal(ios.label, 'Safari on iPhone');
});

test('labelFromUa: browser and OS from the user agent; never throws', () => {
  assert.equal(labelFromUa(UA.mac), 'Chrome on macOS');
  assert.equal(labelFromUa(UA.iphone), 'Safari on iPhone');
  assert.equal(labelFromUa(UA.edge), 'Edge on Windows');
  assert.equal(labelFromUa(UA.android), 'Chrome on Android');
  assert.equal(labelFromUa(UA.firefox), 'Firefox on Linux');
  assert.equal(labelFromUa(UA.ipadFirefox), 'Firefox on iPad');
  assert.equal(labelFromUa('curl/8.4.0'), 'Passkey');
  for (const v of HOSTILE) assert.equal(typeof labelFromUa(v), 'string', show(v));
  assert.equal(labelFromUa(null), 'Passkey');
});

test('transports: only known values, de-duplicated; anything else stores []', async () => {
  const { env, rc } = await setup();
  const r = await enrol(rc, authFor(env), JANE, { transports: ['usb', 'usb', 'bogus', 7, null, 'internal', 'cable'] });
  assert.equal(r.transports, '["usb","internal"]');
  for (const v of HOSTILE) {
    const row = await enrol(rc, authFor(env), JANE, { transform: (j) => ({ ...j, response: { ...j.response, transports: v } }) });
    assert.equal(row.transports, '[]', show(v));
  }
  const all = await enrol(rc, authFor(env), JANE, { transports: ['usb', 'nfc', 'ble', 'smart-card', 'hybrid', 'internal'] });
  assert.equal(all.transports, '["usb","nfc","ble","smart-card","hybrid","internal"]');
});

// ------------------------------------------------------------ base64url

test('base64url alphabet: credential id [0xfb,0xff,0xbe,0x01] is stored, excluded and looked up as "-_--AQ"', async () => {
  assert.equal(b64urlEncode(Uint8Array.from([0xfb, 0xff, 0xbe, 0x01])), '-_--AQ');
  const { env, rc, a } = await setup();
  const row = await enrol(rc, a, JANE, { credentialId: [0xfb, 0xff, 0xbe, 0x01] });
  assert.equal(row.id, '-_--AQ');
  assert.deepEqual((await registrationOptions(rc, JANE)).excludeCredentials.map((d) => d.id), ['-_--AQ']);
  const o = await assertionOptions(rc, JANE);
  assert.deepEqual(o.allowCredentials.map((d) => d.id), ['-_--AQ']);
  assert.equal((await verifyAssertion(rc, JANE, await a.get(o), 'auth')).passkeyId, '-_--AQ');
  // The standard alphabet is a different string and is not looked up at all.
  await refused(signIn(rc, a, JANE, { id: '+/++AQ==', rawId: '+/++AQ==' }), 'credential_id_malformed');
  await refused(signIn(rc, a, JANE, { id: '+/++AQ', rawId: '+/++AQ' }), 'credential_id_malformed');
  assert.equal(passkeys(env)[0].sign_count, 1, 'only the genuine assertion counted');
});

// ------------------------------------------------------------ A §7.4 registration table

const RANDOM_CHALLENGE = Symbol('random challenge');

// [row of the table, knobs, reason]
const REGISTRATION_ES256 = [
  ['clientData.type === webauthn.create (an assertion replayed as a registration)', { type: 'webauthn.get' }, 'type_mismatch'],
  ['clientData.type: anything else', { type: 'webauthn.create ' }, 'type_mismatch'],
  ['challenge equals the one issued', { challenge: RANDOM_CHALLENGE }, 'challenge_unknown'],
  ['challenge: not even the right shape', { challenge: 'abc' }, 'challenge_malformed'],
  ['origin exactly: lookalike suffix', { origin: 'https://staff.example.com.evil.example' }, 'origin_mismatch'],
  ['origin exactly: lookalike prefix', { origin: 'https://evilstaff.example.com' }, 'origin_mismatch'],
  ['origin exactly: sibling subdomain', { origin: 'https://evil.example.com' }, 'origin_mismatch'],
  ['origin exactly: http', { origin: 'http://staff.example.com' }, 'origin_mismatch'],
  ['origin exactly: explicit port', { origin: 'https://staff.example.com:8443' }, 'origin_mismatch'],
  ['origin exactly: trailing slash', { origin: 'https://staff.example.com/' }, 'origin_mismatch'],
  ['origin exactly: case', { origin: 'https://STAFF.example.com' }, 'origin_mismatch'],
  ['origin exactly: "null"', { origin: 'null' }, 'origin_mismatch'],
  ['origin exactly: not a string', { origin: 42 }, 'origin_mismatch'],
  ['origin: a cross-origin iframe', { clientData: { crossOrigin: true } }, 'cross_origin'],
  ['origin: a top origin is reported', { clientData: { topOrigin: 'https://evil.example' } }, 'cross_origin'],
  ['token binding we cannot check', { clientData: { tokenBinding: { status: 'present', id: 'AAAA' } } }, 'token_binding'],
  ['rpIdHash equals SHA-256(RP ID): parent domain', { rpId: 'example.com' }, 'rp_id_hash'],
  ['rpIdHash: another site', { rpId: 'evil.example' }, 'rp_id_hash'],
  ['User Present flag set', { flags: { UP: false } }, 'user_not_present'],
  ['attested credential data present', { attestedData: false }, 'no_attested_data'],
  ['attested data well-formed: AT set with nothing behind it', { attestedData: false, flags: { AT: true } }, 'authdata_truncated'],
  ['attested data well-formed: credential id length 0', { credentialIdLength: 0 }, 'credential_id_length'],
  ['attested data well-formed: credential id over 1023 bytes', { credentialIdLength: 1024 }, 'credential_id_length'],
  ['attested data well-formed: COSE key cut short', { truncate: 3 }, 'cbor_truncated'],
  ['attested data matches the credential id sent', { id: randomChallenge() }, 'credential_id_mismatch'],
  ['attested data matches the rawId sent', { rawId: randomChallenge() }, 'credential_id_mismatch'],
  ['credential.type is public-key', { credentialType: 'password' }, 'credential_type'],
  ['COSE → JWK, algorithm matches key type (RS256 claimed on an EC key)', { algMismatch: true }, 'alg_mismatch'],
  ['algorithm offered: EdDSA', { alg: -8 }, 'alg_unsupported'],
  ['algorithm offered: ES384', { alg: -35 }, 'alg_unsupported'],
  ['curve is P-256', { ecCurve: 2 }, 'ec_curve'],
  ['P-256 coordinates exactly 32 bytes: 31', { ecCoordinateLength: 31 }, 'ec_coordinate'],
  ['P-256 coordinates exactly 32 bytes: 33', { ecCoordinateLength: 33 }, 'ec_coordinate'],
  ['COSE key carries no private member', { coseEdit: (m) => m.set(-4, new Uint8Array(32)) }, 'cose_label'],
  ['import at enrolment: a point not on the curve', { coseEdit: (m) => { const y = m.get(-3).slice(); y[31] ^= 1; m.set(-3, y); } }, 'key_import'],
  ['attestation: unknown format', { fmt: 'bogus' }, 'attestation_format'],
  ['attestation: "none" with a statement', { attStmt: new Map([['sig', new Uint8Array(8)]]) }, 'attestation_statement'],
  ['attestationObject: duplicate authData, decoy first (A §7.4 detail 2)', { duplicateKey: true }, 'cbor_duplicate_key'],
  ['attestationObject: duplicate authData, real first', { duplicateKey: 'realFirst' }, 'cbor_duplicate_key'],
  ['authData accounts for every byte: one left over (detail 3)', { extend: 1 }, 'authdata_trailing'],
  ['authData: ED set with no extensions behind it', { flags: { ED: true } }, 'ed_without_extensions'],
  ['authData: extensions present without ED', { extensions: { credProtect: 1 }, flags: 0x45 }, 'authdata_trailing'],
  ['authData: extensions that are not a map', { extensions: 5 }, 'extensions_shape'],
  ['authData: backup state without backup eligibility', { flags: { BS: true } }, 'flags_backup'],
];

const REGISTRATION_RS256 = [
  ['COSE → JWK, algorithm matches key type (ES256 claimed on an RSA key)', { algMismatch: true }, 'alg_mismatch'],
  ['RSA modulus ≥ 1024 bits', { rsaModulusBits: 1023 }, 'rsa_modulus'],
  ['RSA modulus ≥ 1024 bits: 512', { rsaModulusBits: 512 }, 'rsa_modulus'],
  ['RSA modulus ≤ 8192 bits', { rsaModulusBits: 8200 }, 'rsa_modulus'],
  ['RSA modulus ODD', { rsaModulusEven: true }, 'rsa_modulus'],
  ['RSA exponent ≥ 3: e = 1 (the big one)', { rsaExponent: 1 }, 'rsa_exponent'],
  ['RSA exponent: e = 0', { rsaExponent: 0 }, 'rsa_exponent'],
  ['RSA exponent odd: e = 2', { rsaExponent: 2 }, 'rsa_exponent'],
  ['RSA exponent odd: e = 65536', { rsaExponent: 65536 }, 'rsa_exponent'],
  ['RSA exponent width-capped: 9 bytes', { rsaExponent: Uint8Array.from([1, 0, 0, 0, 0, 0, 0, 0, 1]) }, 'rsa_exponent'],
  ['RSA exponent minimal: 00 01 00 01', { rsaExponent: Uint8Array.from([0, 1, 0, 1]) }, 'rsa_exponent'],
  ['RSA key carries no private member', { coseEdit: (m) => m.set(-3, new Uint8Array(256)) }, 'cose_label'],
];

for (const [alg, table] of [[-7, REGISTRATION_ES256], [-257, REGISTRATION_RS256]]) {
  test(`A §7.4 registration table (${alg === -7 ? 'ES256' : 'RS256'}): each row refused, nothing stored, challenge spent`, async () => {
    const { env, rc } = await setup({ alg });
    for (const [row, knobs, reason] of table) {
      const k = { ...knobs };
      if (k.challenge === RANDOM_CHALLENGE) k.challenge = randomChallenge();
      const opts = await registrationOptions(rc, JANE);
      const cred = await authFor(env, { alg }).create(opts, k);
      await refused(verifyRegistration(rc, JANE, cred, 'x'), reason, row);
      assert.equal(passkeys(env).length, 0, `${row}: nothing stored`);
      const left = challenges(env).map((c) => c.challenge);
      if (knobs.challenge === undefined) assert.ok(!left.includes(opts.challenge), `${row}: challenge spent despite the refusal`);
      else assert.ok(left.includes(opts.challenge), `${row}: the issued challenge was never presented`);
      env.DB.q('DELETE FROM webauthn_challenges');
    }
    assert.equal(audits(env).length, 0);
  });
}

test('RSA boundaries that ARE acceptable: 1024-bit odd modulus, e = 3, e = 65537 built by hand, 8-byte e', async () => {
  const { env, rc } = await setup({ alg: -257 });
  for (const knobs of [{ rsaModulusBits: 1024 }, { rsaModulusBits: 8192 }, { rsaExponent: 3 }, { rsaExponent: 65537 }, { rsaExponent: Uint8Array.from([1, 0, 0, 0, 0, 0, 0, 1]) }]) {
    await enrol(rc, authFor(env, { alg: -257 }), JANE, knobs);
  }
  assert.equal(passkeys(env).length, 5);
});

test('other attestation formats are accepted but never trusted (we asked for none)', async () => {
  const { env, rc, a } = await setup();
  const row = await enrol(rc, a, JANE, { fmt: 'packed', attStmt: new Map([['alg', -7], ['sig', new Uint8Array(70)]]) });
  assert.equal(passkeys(env).length, 1);
  assert.equal(row.aaguid, hex(TEST_AAGUID));
});

test('attestationObject must hold exactly fmt, attStmt and authData', async () => {
  const { env, rc, a } = await setup();
  const reencode = (extra) => (json) => {
    const m = decodeCbor(fromB64u(json.response.attestationObject));
    extra(m);
    json.response.attestationObject = b64u(encodeCbor(m));
    return json;
  };
  const cases = [
    ['an extra member', (m) => m.set('epAtt', true)],
    ['no attStmt', (m) => m.delete('attStmt')],
    ['fmt not a string', (m) => m.set('fmt', 1)],
    ['authData not bytes', (m) => m.set('authData', 'text')],
    ['attStmt not a map', (m) => m.set('attStmt', [])],
  ];
  for (const [label, edit] of cases) {
    const opts = await registrationOptions(rc, JANE);
    await refused(verifyRegistration(rc, JANE, await a.create(opts, { transform: reencode(edit) }), 'x'), 'attestation_object', label);
    a.credentials.clear();
  }
  const opts = await registrationOptions(rc, JANE);
  const notMap = await a.create(opts, { transform: (j) => ({ ...j, response: { ...j.response, attestationObject: b64u(encodeCbor([1, 2])) } }) });
  await refused(verifyRegistration(rc, JANE, notMap, 'x'), 'attestation_object', 'an array');
  assert.equal(passkeys(env).length, 0);
});

test('RSA e = 1 is refused at enrolment — the credential it carries is forgeable with no private key', async () => {
  const { env, rc, a } = await setup({ alg: -257 });
  const opts = await registrationOptions(rc, JANE);
  const cred = await a.create(opts, { rsaExponent: 1 });
  // What the attacker submitted really is a working "key" for anyone:
  const ad = parseAuthData(decodeCbor(fromB64u(cred.response.attestationObject)).get('authData'));
  const cose = ad.attested.cose;
  assert.deepEqual([...cose.get(-2)], [1]);
  const jwk = { kty: 'RSA', n: b64u(cose.get(-1)), e: b64u(cose.get(-2)) };
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const o2 = { challenge: randomChallenge(), rpId: env.RP_ID, allowCredentials: [{ type: 'public-key', id: cred.id }] };
  const forged = await a.get(o2);
  const signed = concatBytes(fromB64u(forged.response.authenticatorData), await sha256(fromB64u(forged.response.clientDataJSON)));
  assert.equal(await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, fromB64u(forged.response.signature), signed), true);
  // …which is why enrolment refuses it.
  await refused(verifyRegistration(rc, JANE, cred, 'x'), 'rsa_exponent');
  assert.equal(passkeys(env).length, 0);
});

test('the registration challenge is single use: replay after success, and retry after a refusal', async () => {
  const { env, rc, a } = await setup();
  const opts = await registrationOptions(rc, JANE);
  const cred = await a.create(opts);
  await verifyRegistration(rc, JANE, cred, 'x');
  await refused(verifyRegistration(rc, JANE, cred, 'x'), 'challenge_unknown', 'replayed after success');
  const opts2 = await registrationOptions(rc, JANE);
  const b = authFor(env);
  await refused(verifyRegistration(rc, JANE, await b.create(opts2, { origin: 'https://evil.example' }), 'x'), 'origin_mismatch');
  b.credentials.clear();
  await refused(verifyRegistration(rc, JANE, await b.create(opts2), 'x'), 'challenge_unknown', 'genuine retry of a refused ceremony');
  assert.equal(passkeys(env).length, 1);
});

test('a duplicate credential id is 409 and changes nothing — same user or another', async () => {
  const { env, rc, a } = await setup();
  const id = Array.from({ length: 32 }, (_, i) => i);
  const row = await enrol(rc, a, JANE, { credentialId: id });
  for (const user of [JANE, OMAR]) {
    const opts = await registrationOptions(rc, user);
    const cred = await authFor(env).create(opts, { credentialId: id });
    await assert.rejects(
      verifyRegistration(rc, user, cred, 'Dup'),
      (e) => e instanceof HttpError && e.status === 409 && e.body.code === 'passkey_duplicate',
    );
  }
  assert.deepEqual(passkeys(env), [row]);
});

// ------------------------------------------------------------ A §7.4 assertion table

const ASSERTION_COMMON = [
  ['clientData.type === webauthn.get (a registration replayed as a sign-in)', { type: 'webauthn.create' }, 'type_mismatch'],
  ['challenge equals the one issued', { challenge: RANDOM_CHALLENGE }, 'challenge_unknown'],
  ['origin exactly: lookalike', { origin: 'https://staff.example.com.evil.example' }, 'origin_mismatch'],
  ['origin exactly: http', { origin: 'http://staff.example.com' }, 'origin_mismatch'],
  ['origin exactly: trailing slash', { origin: 'https://staff.example.com/' }, 'origin_mismatch'],
  ['origin: cross-origin iframe', { clientData: { crossOrigin: true } }, 'cross_origin'],
  ['origin: crossOrigin not a boolean', { clientData: { crossOrigin: 'false' } }, 'cross_origin'],
  ['rpIdHash equals SHA-256(RP ID)', { rpId: 'evil.example' }, 'rp_id_hash'],
  ['User Present flag set', { flags: { UP: false } }, 'user_not_present'],
  ['signature verifies over authData ‖ SHA-256(clientDataJSON)', { badSignature: true }, 'signature_invalid'],
  ['signature present', { signature: [] }, 'signature'],
  ['credential.type is public-key', { credentialType: 'public-key ' }, 'credential_type'],
  ['id and rawId agree', { rawId: randomChallenge() }, 'credential_id_mismatch'],
  ['credential id is registered', { id: 'AAAA', rawId: 'AAAA' }, 'credential_unknown'],
  ['authData accounts for every byte: one left over', { extend: 1 }, 'authdata_trailing'],
  ['authData accounts for every byte: eight left over', { extend: [1, 2, 3, 4, 5, 6, 7, 8] }, 'authdata_trailing'],
  ['authData: shorter than the 37-byte head', { truncate: 1 }, 'authdata_short'],
  ['authData: ED set with no extensions behind it', { flags: { ED: true } }, 'ed_without_extensions'],
  ['authData: extensions without ED', { extensions: { credProtect: 2 }, flags: 0x05 }, 'authdata_trailing'],
  ['authData: extensions, then a stray byte', { extensions: { credProtect: 2 }, extend: 1 }, 'authdata_trailing'],
  ['authData: AT set in an assertion', { flags: { AT: true } }, 'authdata_truncated'],
  ['authData: backup state without eligibility', { flags: { BS: true } }, 'flags_backup'],
  ['userHandle, when sent, is well-formed', { userHandle: '+/+/' }, 'user_handle_malformed'],
  ['userHandle at most 64 bytes', { userHandle: b64u(new Uint8Array(65)) }, 'user_handle_malformed'],
];

const ASSERTION_ES256 = [
  ['strict DER: unneeded leading zero (A §7.4 detail 1)', { nonMinimalDer: 'leading-zero' }, 'der_non_minimal_integer'],
  ['strict DER: long-form length below 128', { nonMinimalDer: 'long-length' }, 'der_non_minimal_length'],
  ['strict DER: trailing bytes', { trailingDer: true }, 'der_trailing_bytes'],
  ['strict DER: a raw r‖s is not DER', { signature: new Uint8Array(64).fill(1) }, 'der_expected_sequence'],
];

for (const [alg, table] of [[-7, [...ASSERTION_COMMON, ...ASSERTION_ES256]], [-257, ASSERTION_COMMON]]) {
  test(`A §7.4 assertion table (${alg === -7 ? 'ES256' : 'RS256'}): each row refused, counter untouched, challenge spent`, async () => {
    const { env, rc, a } = await setup({ alg });
    const row = await enrol(rc, a);
    for (const [label, knobs, reason] of table) {
      const k = { ...knobs };
      if (k.challenge === RANDOM_CHALLENGE) k.challenge = randomChallenge();
      const opts = await assertionOptions(rc, JANE);
      await refused(verifyAssertion(rc, JANE, await a.get(opts, k), 'auth'), reason, label);
      const now = passkeys(env)[0];
      assert.equal(now.sign_count, 0, `${label}: counter untouched`);
      assert.equal(now.last_used_at, null, `${label}: not marked used`);
      const left = challenges(env).map((c) => c.challenge);
      if (knobs.challenge === undefined) assert.ok(!left.includes(opts.challenge), `${label}: challenge spent`);
      env.DB.q('DELETE FROM webauthn_challenges');
    }
    // The genuine article still works afterwards, and nothing was audited.
    assert.equal((await signIn(rc, a)).passkeyId, row.id);
    assert.equal(audits(env).length, 0);
  });
}

test('the signature binds clientData: a valid signature transplanted onto another ceremony is refused', async () => {
  const { env, rc, a } = await setup();
  await enrol(rc, a);
  const o1 = await assertionOptions(rc, JANE);
  const o2 = await assertionOptions(rc, JANE);
  const r1 = await a.get(o1);
  const r2 = await a.get(o2);
  const franken = { ...r1, response: { ...r1.response, signature: r2.response.signature } };
  await refused(verifyAssertion(rc, JANE, franken, 'auth'), 'signature_invalid');
  // And authData: the counter bytes are signed too.
  const ad = fromB64u(r2.response.authenticatorData);
  ad[36] += 1;
  const bumped = { ...r2, response: { ...r2.response, authenticatorData: b64u(ad) } };
  await refused(verifyAssertion(rc, JANE, bumped, 'auth'), 'signature_invalid');
  assert.equal(passkeys(env)[0].sign_count, 0);
});

test('credential registered to THIS user: someone else’s passkey does not sign you in', async () => {
  const { env, rc, a } = await setup();
  const b = authFor(env);
  await enrol(rc, a, JANE);
  const omars = await enrol(rc, b, OMAR);
  const opts = await assertionOptions(rc, JANE);
  // Omar's authenticator answers Jane's challenge with Omar's (valid) credential.
  const resp = await b.get(opts, { credential: omars.id });
  await refused(verifyAssertion(rc, JANE, resp, 'auth'), 'credential_not_owned');
  const after = passkeys(env).find((p) => p.id === omars.id);
  assert.equal(after.sign_count, 0);
  assert.equal(after.last_used_at, null);
  // A deleted credential is unknown.
  env.DB.q('DELETE FROM user_passkeys WHERE user_id = 7');
  env.DB.q('INSERT INTO user_passkeys (id, user_id, public_key, algorithm, created_at) VALUES (?, 7, ?, -7, ?)', 'AAAA', '{}', iso(0));
  await refused(signIn(rc, a, JANE, { credential: a.lastCredential.id }), 'credential_unknown');
});

test('challenges: wrong kind, wrong user, expired — all refused and all spent', async () => {
  const { env, rc, a } = await setup();
  await enrol(rc, a, JANE);
  await enrol(rc, authFor(env), OMAR);
  // An 'auth' challenge cannot complete a step-up, nor the reverse.
  let o = await assertionOptions(rc, JANE, 'auth');
  await refused(verifyAssertion(rc, JANE, await a.get(o), 'stepup'), 'challenge_kind');
  o = await assertionOptions(rc, JANE, 'stepup');
  await refused(verifyAssertion(rc, JANE, await a.get(o), 'auth'), 'challenge_kind');
  // A registration challenge cannot complete a sign-in.
  const unpresented = [];
  const reg = await registrationOptions(rc, JANE);
  o = await assertionOptions(rc, JANE);
  unpresented.push(o.challenge);
  await refused(verifyAssertion(rc, JANE, await a.get(o, { challenge: reg.challenge }), 'auth'), 'challenge_kind');
  // Omar's challenge cannot complete Jane's ceremony.
  const omarOpts = await assertionOptions(rc, OMAR);
  o = await assertionOptions(rc, JANE);
  unpresented.push(o.challenge);
  await refused(verifyAssertion(rc, JANE, await a.get(o, { challenge: omarOpts.challenge }), 'auth'), 'challenge_user');
  const omarReg = await registrationOptions(rc, OMAR);
  await refused(verifyRegistration(rc, JANE, await authFor(env).create(omarReg), 'x'), 'challenge_user');
  // Every challenge presented above was spent, whoever it belonged to;
  // only the ones never presented remain.
  assert.deepEqual(challenges(env).map((c) => c.challenge).sort(), unpresented.sort());
  assert.equal(passkeys(env).find((p) => p.user_id === 7).sign_count, 0);
});

test('challenge expiry: 5 minutes, boundary refused, 1 ms before accepted; rc.nowMs is honoured', async () => {
  const { env, rc, a } = await setup();
  await enrol(rc, a);
  let o = await assertionOptions(rc, JANE);
  env.__advance(CHALLENGE_TTL_MS);
  await refused(verifyAssertion(rc, JANE, await a.get(o), 'auth'), 'challenge_expired');
  assert.equal(challenges(env).length, 0, 'the expired row was spent too');
  o = await assertionOptions(rc, JANE);
  env.__advance(CHALLENGE_TTL_MS - 1);
  assert.ok(await verifyAssertion(rc, JANE, await a.get(o), 'auth'));
  // A request's own clock (rc.nowMs) wins over the env clock.
  const t = env.__clock();
  o = await assertionOptions({ ...rc, nowMs: t }, JANE);
  await refused(verifyAssertion({ ...rc, nowMs: t + 6 * MINUTE }, JANE, await a.get(o), 'auth'), 'challenge_expired');
  // An unreadable stored expiry fails closed.
  o = await assertionOptions(rc, JANE);
  env.DB.q('UPDATE webauthn_challenges SET expires_at = ? WHERE challenge = ?', '2099', o.challenge);
  await refused(verifyAssertion(rc, JANE, await a.get(o), 'auth'), 'challenge_expired');
});

test('issuing a challenge prunes expired rows (anyone’s) and caps open ones per user and kind', async () => {
  const { env, rc } = await setup();
  const t = env.__clock();
  env.DB.q('INSERT INTO webauthn_challenges VALUES (?, 99, ?, ?)', 'old-1', 'auth', iso(t - 1));
  env.DB.q('INSERT INTO webauthn_challenges VALUES (?, 99, ?, ?)', 'old-2', 'register', iso(t));
  env.DB.q('INSERT INTO webauthn_challenges VALUES (?, 99, ?, ?)', 'live', 'auth', iso(t + 1));
  await registrationOptions(rc, JANE);
  assert.deepEqual(challenges(env).map((c) => c.challenge).filter((c) => c.length < 10), ['live']);
  const issued = [];
  for (let i = 0; i < 7; i++) {
    env.__advance(1000);
    issued.push((await registrationOptions(rc, JANE)).challenge);
  }
  const mine = challenges(env).filter((c) => c.user_id === 7 && c.kind === 'register').map((c) => c.challenge);
  assert.deepEqual(mine, issued.slice(-5), 'the newest five stay open');
  // An evicted challenge is simply unknown; the newest still works.
  const a = authFor(env);
  await refused(verifyRegistration(rc, JANE, await a.create({ ...(await registrationOptions(rc, JANE)), challenge: issued[0] }), 'x'), 'challenge_unknown');
  a.credentials.clear();
  await verifyRegistration(rc, JANE, await a.create({ ...(await registrationOptions(rc, JANE)), challenge: issued[6] }), 'x');
});

test('the assertion challenge is single use, even after a failed verification', async () => {
  const { env, rc, a } = await setup();
  await enrol(rc, a);
  // Refused for a bad signature, then the genuine response to the same challenge.
  let o = await assertionOptions(rc, JANE);
  await refused(verifyAssertion(rc, JANE, await a.get(o, { badSignature: true }), 'auth'), 'signature_invalid');
  await refused(verifyAssertion(rc, JANE, await a.get(o), 'auth'), 'challenge_unknown', 'retry after a bad signature');
  // Refused for the origin, then genuine.
  o = await assertionOptions(rc, JANE);
  await refused(verifyAssertion(rc, JANE, await a.get(o, { origin: 'https://evil.example' }), 'auth'), 'origin_mismatch');
  await refused(verifyAssertion(rc, JANE, await a.get(o), 'auth'), 'challenge_unknown', 'retry after a bad origin');
  // A successful assertion cannot be replayed.
  o = await assertionOptions(rc, JANE);
  const good = await a.get(o);
  const usedAt = env.__clock();
  await verifyAssertion(rc, JANE, good, 'auth');
  env.__advance(MINUTE);
  await refused(verifyAssertion(rc, JANE, good, 'auth'), 'challenge_unknown', 'replay');
  const row = passkeys(env)[0];
  assert.equal(row.sign_count, a.signCount, 'the accepted assertion’s counter');
  assert.equal(row.last_used_at, iso(usedAt), 'only the accepted assertion marked it used');
});

// ------------------------------------------------------------ stored key

test('a planted e = 1 key in the database is refused at assertion — and the forgery it admits is real', async () => {
  const { env, rc, a } = await setup({ alg: -257 });
  const row = await enrol(rc, a);
  const planted = { ...JSON.parse(row.public_key), e: 'AQ' };
  env.DB.q('UPDATE user_passkeys SET public_key = ? WHERE id = ?', JSON.stringify(planted), row.id);
  const opts = await assertionOptions(rc, JANE);
  const forged = await a.get(opts, { forge: true });
  // No private key was involved, yet WebCrypto verifies it under the planted key.
  const r = forged.response;
  const signed = concatBytes(fromB64u(r.authenticatorData), await sha256(fromB64u(r.clientDataJSON)));
  const key = await crypto.subtle.importKey('jwk', planted, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  assert.equal(await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, fromB64u(r.signature), signed), true);
  // The stored copy is re-validated on every use.
  await refused(verifyAssertion(rc, JANE, forged, 'auth'), 'rsa_exponent');
  const after = passkeys(env)[0];
  assert.equal(after.sign_count, 0);
  assert.equal(after.last_used_at, null);
  // And with the real exponent restored, the same forgery is just a bad signature.
  env.DB.q('UPDATE user_passkeys SET public_key = ? WHERE id = ?', row.public_key, row.id);
  await refused(signIn(rc, a, JANE, { forge: true }), 'signature_invalid');
});

test('a stored key that is unreadable, tampered or mislabelled fails closed', async () => {
  const { env, rc, a } = await setup();
  const row = await enrol(rc, a);
  const jwk = JSON.parse(row.public_key);
  const cases = [
    ['public_key not JSON', { public_key: 'not json' }, 'key_shape'],
    ['public_key JSON null', { public_key: 'null' }, 'key_shape'],
    ['public_key an array', { public_key: '[]' }, 'key_shape'],
    ['x cut to 31 bytes', { public_key: JSON.stringify({ ...jwk, x: b64u(fromB64u(jwk.x).slice(1)) }) }, 'ec_coordinate'],
    ['curve relabelled', { public_key: JSON.stringify({ ...jwk, crv: 'P-384' }) }, 'ec_curve'],
    ['private member added', { public_key: JSON.stringify({ ...jwk, d: jwk.x }) }, 'private_key'],
    ['algorithm relabelled RS256', { algorithm: -257 }, 'alg_mismatch'],
    ['algorithm unsupported', { algorithm: -8 }, 'stored_algorithm'],
    ['algorithm unreadable', { algorithm: 'ES256' }, 'stored_algorithm'],
    ['counter negative', { sign_count: -1 }, 'stored_counter_unreadable'],
    ['counter beyond 32 bits', { sign_count: 2 ** 32 }, 'stored_counter_unreadable'],
    ['counter text', { sign_count: 'abc' }, 'stored_counter_unreadable'],
    ['owner unreadable', { user_id: 'seven' }, 'credential_not_owned'],
  ];
  for (const [label, patch, reason] of cases) {
    const [[col, val]] = Object.entries(patch);
    const resp = await a.get(await assertionOptions(rc, JANE));
    env.DB.q(`UPDATE user_passkeys SET ${col} = ? WHERE id = ?`, val, row.id);
    await refused(verifyAssertion(rc, JANE, resp, 'auth'), reason, label);
    env.DB.q(`UPDATE user_passkeys SET ${col} = ? WHERE id = ?`, row[col], row.id);
    assert.equal(passkeys(env)[0].last_used_at, null, `${label}: not marked used`);
  }
  assert.ok(await signIn(rc, a), 'restored row works again');
});

// ------------------------------------------------------------ counter

test('counter regression is refused AND audited as mfa.passkey.counter_regressed (exactly one row)', async () => {
  const { env, rc, a } = await setup({ signCount: 5 });
  const row = await enrol(rc, a);
  assert.equal(row.sign_count, 5);
  await refused(signIn(rc, a, JANE, { signCount: 3 }), 'counter_regressed');
  const log = audits(env);
  assert.equal(log.length, 1);
  assert.equal(log[0].action, 'mfa.passkey.counter_regressed');
  assert.equal(log[0].outcome, 'denied');
  assert.equal(log[0].severity, 'critical');
  assert.equal(log[0].target_type, 'user');
  assert.equal(log[0].target_id, '7');
  assert.equal(log[0].ip, '81.2.69.142');
  assert.match(log[0].detail, /from 5 to 3/);
  assert.match(log[0].detail, /Laptop/);
  assert.deepEqual(JSON.parse(log[0].before_state), { sign_count: 5 });
  assert.deepEqual(JSON.parse(log[0].after_state), { credential: row.id, sign_count: 3 });
  assert.ok(!/BEGIN|"d"|private/i.test(JSON.stringify(log[0])), 'no key material in the audit row');
  const after = passkeys(env)[0];
  assert.equal(after.sign_count, 5);
  assert.equal(after.last_used_at, null);
});

test('counter rule: equal non-zero refused, non-zero → 0 refused, 0 → n accepted, then strictly increasing', async () => {
  const { env, rc, a } = await setup({ signCount: 5 });
  await enrol(rc, a);
  await refused(signIn(rc, a, JANE, { signCount: 5 }), 'counter_regressed', 'equal');
  await refused(signIn(rc, a, JANE, { signCount: 0 }), 'counter_regressed', 'back to zero');
  assert.equal(audits(env).length, 2);
  assert.ok(await signIn(rc, a, JANE, { signCount: 6 }));
  assert.equal(passkeys(env)[0].sign_count, 6);

  const z = await setup();
  await enrol(z.rc, z.a);
  assert.ok(await signIn(z.rc, z.a, JANE, { signCount: 7 }), '0 → 7');
  assert.equal(passkeys(z.env)[0].sign_count, 7);
  await refused(signIn(z.rc, z.a, JANE, { signCount: 7 }), 'counter_regressed', '7 → 7');
  assert.ok(await signIn(z.rc, z.a, JANE, { signCount: 2 ** 32 - 1 }), 'the 32-bit maximum');
  assert.equal(passkeys(z.env)[0].sign_count, 2 ** 32 - 1);
});

test('counters 0 / 0 are allowed every time: an authenticator without a counter', async () => {
  const { env, rc, a } = await setup({ increment: false });
  await enrol(rc, a);
  for (let i = 0; i < 3; i++) {
    env.__advance(MINUTE);
    assert.ok(await signIn(rc, a));
    const row = passkeys(env)[0];
    assert.equal(row.sign_count, 0);
    assert.equal(row.last_used_at, iso(env.__clock()));
  }
  assert.equal(audits(env).length, 0);
});

test('a counter regression with a bad signature is a bad signature: no audit row from an unsigned claim', async () => {
  const { env, rc, a } = await setup({ signCount: 5 });
  await enrol(rc, a);
  await refused(signIn(rc, a, JANE, { signCount: 1, badSignature: true }), 'signature_invalid');
  assert.equal(audits(env).length, 0);
});

test('the counter UPDATE is conditional: concurrent assertions never move it backwards', async () => {
  const { env, rc, a } = await setup({ signCount: 5, increment: false });
  await enrol(rc, a);
  const o1 = await assertionOptions(rc, JANE);
  const o2 = await assertionOptions(rc, JANE);
  const hi = await a.get(o1, { signCount: 7 });
  const lo = await a.get(o2, { signCount: 6 });
  const [r1, r2] = await Promise.allSettled([verifyAssertion(rc, JANE, hi, 'auth'), verifyAssertion(rc, JANE, lo, 'auth')]);
  assert.equal(r1.status, 'fulfilled');
  if (r2.status === 'rejected') assert.match(r2.reason.reason, /^counter_(race|regressed)$/);
  assert.equal(passkeys(env)[0].sign_count, 7);
});

// ------------------------------------------------------------ hostile input

test('hostile credentials, labels, users and kinds: refused as passkey_invalid, nothing written', async () => {
  const { env, rc, a } = await setup();
  for (const v of HOSTILE) {
    await refused(verifyRegistration(rc, JANE, v, v), 'credential_shape', `registration credential ${show(v)}`);
    await refused(verifyAssertion(rc, JANE, v, 'auth'), 'credential_shape', `assertion credential ${show(v)}`);
    // {} is a well-shaped response with nothing in it.
    await refused(verifyRegistration(rc, JANE, { id: 'AAAA', rawId: 'AAAA', type: 'public-key', response: v }, 'x'), /^(credential_shape|client_data)$/);
    await refused(registrationOptions(rc, v), 'bad_user', `user ${show(v)}`);
    await refused(registrationOptions(rc, { id: v }), 'bad_user', `user.id ${show(v)}`);
    await refused(verifyAssertion(rc, { id: v }, {}, 'auth'), 'bad_user');
    await refused(verifyAssertion(rc, JANE, {}, v), 'bad_kind', `kind ${show(v)}`);
    if (v !== undefined) await refused(assertionOptions(rc, JANE, v), 'bad_kind', `options kind ${show(v)}`);
  }
  assert.equal(challenges(env).length, 0, 'no challenge issued for a refused user or kind');

  for (const v of HOSTILE) {
    for (const f of ['clientDataJSON', 'attestationObject']) {
      const opts = await registrationOptions(rc, JANE);
      const cred = await a.create(opts);
      a.credentials.clear();
      cred.response[f] = v;
      await refused(verifyRegistration(rc, JANE, cred, 'x'), /^(client_data|client_data_json|attestation_object|cbor_\w+)$/, `${f} ${show(v)}`);
    }
    for (const f of ['id', 'rawId', 'type']) {
      const opts = await registrationOptions(rc, JANE);
      const cred = await a.create(opts);
      a.credentials.clear();
      cred[f] = v;
      await refused(verifyRegistration(rc, JANE, cred, 'x'), /^(credential_id_mismatch|credential_type)$/, `${f} ${show(v)}`);
    }
  }
  assert.equal(passkeys(env).length, 0);
  assert.equal(audits(env).length, 0);

  await enrol(rc, a);
  for (const v of HOSTILE) {
    for (const f of ['clientDataJSON', 'authenticatorData', 'signature', 'userHandle']) {
      const opts = await assertionOptions(rc, JANE);
      const resp = await a.get(opts);
      resp.response[f] = v;
      const p = verifyAssertion(rc, JANE, resp, 'auth');
      // An absent or blank userHandle is no userHandle; 'abc' decodes to two bytes.
      if (f === 'userHandle' && (v === null || v === undefined || v === '' || v === 'abc')) await p;
      else await refused(p, /^(client_data|client_data_json|authenticator_data|authdata_\w+|signature|der_\w+|user_handle_malformed)$/, `${f} ${show(v)}`);
    }
    for (const f of ['id', 'rawId', 'type']) {
      const opts = await assertionOptions(rc, JANE);
      const resp = await a.get(opts);
      resp[f] = v;
      await refused(verifyAssertion(rc, JANE, resp, 'auth'), /^(credential_id_mismatch|credential_type)$/, `${f} ${show(v)}`);
    }
  }
  assert.equal(audits(env).length, 0);
});

test('oversized fields are refused before decoding', async () => {
  const { rc, a } = await setup();
  await enrol(rc, a);
  const big = (n) => 'A'.repeat(n);
  const cases = [
    ['clientDataJSON', big(6000), 'client_data'],
    ['authenticatorData', big(6000), 'authenticator_data'],
    ['signature', big(1400), 'signature'],
  ];
  for (const [f, v, reason] of cases) {
    const resp = await a.get(await assertionOptions(rc, JANE));
    resp.response[f] = v;
    await refused(verifyAssertion(rc, JANE, resp, 'auth'), reason, f);
  }
  const resp = await a.get(await assertionOptions(rc, JANE));
  resp.id = resp.rawId = big(1400);
  await refused(verifyAssertion(rc, JANE, resp, 'auth'), 'credential_id_malformed');
  const opts = await registrationOptions(rc, JANE);
  const cred = await authFor(rc.env).create(opts);
  cred.response.attestationObject = big(50000);
  await refused(verifyRegistration(rc, JANE, cred, 'x'), 'attestation_object');
});

test('passkeyError: polite body, stable code, reason non-enumerable', () => {
  const e = passkeyError('rsa_exponent');
  assert.ok(e instanceof HttpError);
  assert.equal(e.status, 400);
  assert.deepEqual(e.body, POLITE);
  assert.equal(e.reason, 'rsa_exponent');
  assert.ok(!Object.keys(e).includes('reason'));
  assert.ok(!JSON.stringify(e).includes('rsa_exponent'));
  assert.ok(!JSON.stringify(e.body).includes('rsa'));
});

test('misconfiguration is a server error, not a client refusal, and issues nothing', async () => {
  for (const vars of [{ ORIGIN: 'https://staff.example.com/' }, { ORIGIN: undefined }, { ORIGIN: 'staff.example.com' }, { RP_ID: '' }, { RP_ID: undefined }]) {
    const env = await makeEnvWithSchema({ vars });
    for (const k of Object.keys(vars)) if (vars[k] === undefined) delete env[k];
    const rc = { env };
    await assert.rejects(registrationOptions(rc, JANE), (e) => !(e instanceof HttpError) && /RP_ID and ORIGIN/.test(e.message), JSON.stringify(vars));
    await assert.rejects(verifyAssertion(rc, JANE, {}, 'auth'), (e) => !(e instanceof HttpError), JSON.stringify(vars));
    assert.equal(challenges(env).length, 0);
  }
});

test('static: webauthn sources use the injected clock and total coercion only (A §13.6, §14.12)', () => {
  for (const f of ['cbor.js', 'der.js', 'cose.js', 'webauthn.js']) {
    const src = readFileSync(path.join(ROOT, 'src', 'webauthn', f), 'utf8').replace(/^\s*\/\/.*$/gm, '');
    for (const bad of [/Date\.now\(/, /Date\.parse\(/, /\bparseInt\(/, /\bparseFloat\(/, /[^.\w]Number\((?!\.)/, /innerHTML/]) {
      assert.ok(!bad.test(src), `${f} contains ${bad}`);
    }
  }
  const w = readFileSync(path.join(ROOT, 'src', 'webauthn', 'webauthn.js'), 'utf8');
  assert.match(w, /import \{ audit \} from '\.\.\/audit\.js';/);
});

await run();
