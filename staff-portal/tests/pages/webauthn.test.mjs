// public/js/webauthn.js — base64url both ways, wire shapes, cancellation
// (CONTRACTS §7.5, §10; A §7.4 "client-side mechanics", §7.6).

import { test, assert, run } from '../helpers/t.js';
import { loadPage, importFresh } from '../helpers/dom.js';

const ALPHABET_BYTES = [0xfb, 0xff, 0xbe, 0x01];

const buf = (bytes) => new Uint8Array(bytes).buffer;
const bytesOf = (b) => [...new Uint8Array(b)];

async function env(webauthn) {
  const p = await loadPage('login.html', { import: false, webauthn });
  const w = await importFresh('js/webauthn.js');
  return { p, w };
}

function namedError(name, message = name) {
  const e = new Error(message);
  e.name = name;
  return e;
}

test('base64url: [0xfb,0xff,0xbe,0x01] ⇄ "-_--AQ" (url-safe, unpadded) both directions', async () => {
  const { p, w } = await env();
  assert.equal(w.b64urlEncode(new Uint8Array(ALPHABET_BYTES)), '-_--AQ');
  assert.equal(w.b64urlEncode(buf(ALPHABET_BYTES)), '-_--AQ', 'ArrayBuffer too');
  assert.equal(w.b64urlEncode(new DataView(buf([0, ...ALPHABET_BYTES]), 1)), '-_--AQ', 'any view, honouring offset');
  assert.deepEqual([...w.b64urlDecode('-_--AQ')], ALPHABET_BYTES);
  assert.deepEqual([...w.b64urlDecode('+/++AQ==')], ALPHABET_BYTES, 'standard alphabet accepted on input');
  assert.deepEqual([...w.b64urlDecode('')], []);
  assert.throws(() => w.b64urlDecode('a'), /not base64/);
  assert.throws(() => w.b64urlDecode('ab$c'), /not base64/);
  assert.throws(() => w.b64urlDecode(null), /expected a string/);
  p.dispose();
});

test('base64url: every byte value round-trips and output never has + / =', async () => {
  const { p, w } = await env();
  for (let len = 0; len < 40; len++) {
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) bytes[i] = (i * 97 + len * 31 + 0xfb) & 0xff;
    const s = w.b64urlEncode(bytes);
    assert.ok(!/[+/=]/.test(s), `len ${len}: ${s}`);
    assert.deepEqual([...w.b64urlDecode(s)], [...bytes]);
  }
  const all = new Uint8Array(256).map((_, i) => i);
  assert.deepEqual([...w.b64urlDecode(w.b64urlEncode(all))], [...all]);
  p.dispose();
});

test('base64url: a 300 KB buffer encodes with a loop (no spread into fromCharCode)', async () => {
  const { p, w } = await env();
  const big = new Uint8Array(300000).map((_, i) => (i * 7) & 0xff);
  const s = w.b64urlEncode(big);
  assert.equal(s.length, Math.ceil((big.length * 4) / 3));
  const back = w.b64urlDecode(s);
  assert.equal(back.length, big.length);
  assert.equal(back[299999], big[299999]);
  p.dispose();
});

test('supportsPasskeys follows the browser', async () => {
  const a = await env();
  assert.equal(a.w.supportsPasskeys(), false, 'no PublicKeyCredential');
  a.p.dispose();
  const b = await env({ get: async () => null });
  assert.equal(b.w.supportsPasskeys(), true);
  b.p.dispose();
});

test('getPasskey: options decoded to ArrayBuffers, assertion encoded url-safe (§7.5 wire shape)', async () => {
  let seen = null;
  const { p, w } = await env({
    get: async (o) => {
      seen = o;
      return {
        id: 'not-what-we-send',
        rawId: buf(ALPHABET_BYTES),
        type: 'public-key',
        response: { clientDataJSON: buf([0xfb, 0xff]), authenticatorData: buf([0xbe, 0x01]), signature: buf(ALPHABET_BYTES), userHandle: buf([0xff, 0xfe]) },
      };
    },
  });
  const out = await w.getPasskey({ challenge: '-_--AQ', rpId: 'staff.example.com', timeout: 60000, userVerification: 'preferred', allowCredentials: [{ type: 'public-key', id: '-_--AQ', transports: ['internal'] }] });
  assert.ok(seen.publicKey.challenge instanceof ArrayBuffer);
  assert.deepEqual(bytesOf(seen.publicKey.challenge), ALPHABET_BYTES);
  assert.deepEqual(bytesOf(seen.publicKey.allowCredentials[0].id), ALPHABET_BYTES);
  assert.deepEqual(seen.publicKey.allowCredentials[0].transports, ['internal']);
  assert.equal(seen.publicKey.rpId, 'staff.example.com');
  assert.deepEqual(out, {
    id: '-_--AQ',
    rawId: '-_--AQ',
    type: 'public-key',
    response: { clientDataJSON: '-_8', authenticatorData: 'vgE', signature: '-_--AQ', userHandle: '__4' },
  });
  p.dispose();
});

test('getPasskey: an empty userHandle is omitted', async () => {
  const { p, w } = await env({ get: async () => ({ id: 'x', rawId: buf([1]), type: 'public-key', response: { clientDataJSON: buf([1]), authenticatorData: buf([2]), signature: buf([3]), userHandle: null } }) });
  const out = await w.getPasskey({ challenge: 'AQ', allowCredentials: [] });
  assert.ok(!('userHandle' in out.response));
  p.dispose();
});

test('createPasskey: user id + excludeCredentials decoded; attestation and transports encoded', async () => {
  let seen = null;
  const { p, w } = await env({
    get: async () => null,
    create: async (o) => {
      seen = o;
      return { id: 'x', rawId: buf(ALPHABET_BYTES), type: 'public-key', response: { clientDataJSON: buf([1, 2, 3]), attestationObject: buf(ALPHABET_BYTES), getTransports: () => ['internal', 'hybrid'] } };
    },
  });
  const out = await w.createPasskey({
    challenge: 'AQID',
    rp: { id: 'staff.example.com', name: 'Acme' },
    user: { id: '-_--AQ', name: 'jane@acme.com', displayName: 'Jane' },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
    timeout: 60000,
    attestation: 'none',
    authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
    excludeCredentials: [{ type: 'public-key', id: '-_--AQ' }],
  });
  assert.deepEqual(bytesOf(seen.publicKey.user.id), ALPHABET_BYTES);
  assert.equal(seen.publicKey.user.name, 'jane@acme.com');
  assert.deepEqual(bytesOf(seen.publicKey.challenge), [1, 2, 3]);
  assert.deepEqual(bytesOf(seen.publicKey.excludeCredentials[0].id), ALPHABET_BYTES);
  assert.deepEqual(seen.publicKey.pubKeyCredParams.map((x) => x.alg), [-7, -257]);
  assert.deepEqual(out, { id: '-_--AQ', rawId: '-_--AQ', type: 'public-key', response: { clientDataJSON: 'AQID', attestationObject: '-_--AQ', transports: ['internal', 'hybrid'] } });
  p.dispose();
});

test('NotAllowedError and AbortError are { cancelled: true }; other failures are { error }', async () => {
  for (const [thrown, want] of [
    [namedError('NotAllowedError', 'The operation either timed out or was not allowed.'), { cancelled: true }],
    [namedError('AbortError'), { cancelled: true }],
    [namedError('SecurityError', 'The relying party ID is not a registrable domain suffix.'), { error: 'The relying party ID is not a registrable domain suffix.' }],
    [new TypeError('boom'), { error: 'boom' }],
  ]) {
    const { p, w } = await env({ get: async () => Promise.reject(thrown), create: async () => Promise.reject(thrown) });
    assert.deepEqual(await w.getPasskey({ challenge: 'AQ' }), want, thrown.name);
    assert.deepEqual(await w.createPasskey({ challenge: 'AQ', rp: {}, user: { id: 'AQ' } }), want, `${thrown.name} (create)`);
    p.dispose();
  }
  const n = await env({ get: async () => null });
  assert.deepEqual(await n.w.getPasskey({ challenge: 'AQ' }), { cancelled: true }, 'a null credential is a dismissal');
  n.p.dispose();
});

test('unreadable options and unsupported browsers come back as { error }, never a throw', async () => {
  const { p, w } = await env({ get: async () => null });
  const r = await w.getPasskey({ challenge: '%%%' });
  assert.ok(r.error && /couldn’t read/.test(r.error));
  const r2 = await w.createPasskey({ challenge: 'AQ' });
  assert.ok(r2.error, 'missing user');
  assert.ok((await w.getPasskey(null)).error);
  p.dispose();
  const none = await env();
  assert.match((await none.w.getPasskey({ challenge: 'AQ' })).error, /can’t use passkeys/);
  assert.match((await none.w.createPasskey({ challenge: 'AQ' })).error, /can’t create passkeys/);
  none.p.dispose();
});

test('InvalidStateError on create says the passkey is already registered', async () => {
  const { p, w } = await env({ get: async () => null, create: async () => Promise.reject(namedError('InvalidStateError')) });
  assert.match((await w.createPasskey({ challenge: 'AQ', rp: {}, user: { id: 'AQ' } })).error, /already registered/);
  p.dispose();
});

await run();
