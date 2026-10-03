import jsQR from 'jsqr';
import { test, assert, run } from '../helpers/t.js';
import { makeEnvWithSchema } from '../helpers/env.js';
import { iso, utf8 } from '../../src/util.js';
import { encrypt, decrypt } from '../../src/crypto.js';
import {
  base32Encode, base32Decode, groupSecret, generateTotpSecret, totpCode, verifyTotp, otpauthUri,
  beginTotp, confirmTotp, checkTotp, removeTotp, loadConfirmedTotp, TOTP_STEP_MS,
} from '../../src/mfa/totp.js';
import { BACKUP_ALPHABET } from '../../src/mfa/backup.js';

const HOSTILE = [null, undefined, NaN, Infinity, '', '   ', 'abc', {}, [], true, 0, Symbol('x')];
const show = (v) => (typeof v === 'symbol' || typeof v === 'bigint' ? String(typeof v) : JSON.stringify(v) ?? String(v));
const RFC_SECRET = utf8('12345678901234567890');

async function addUser(env, email = 'jane@acme.com') {
  const t = iso(env.__clock());
  const r = await env.DB.prepare(
    "INSERT INTO users (email, full_name, role_id, status, created_at, updated_at) VALUES (?, 'Jane Doe', 1, 'active', ?, ?)",
  )
    .bind(email, t, t)
    .run();
  return r.meta.last_row_id;
}

const rcOf = (env) => ({ env, nowMs: env.__clock() });
const stepOf = (ms) => Math.floor(ms / TOTP_STEP_MS);
const audits = (env, action) => env.DB.q('SELECT * FROM audit_log WHERE action LIKE ? ORDER BY seq', action ?? '%');
const totpRow = (env, uid) => env.DB.q('SELECT * FROM user_totp WHERE user_id = ?', uid)[0];

// Enrol and confirm, returning the secret bytes.
async function enrol(env, uid) {
  const b = await beginTotp(rcOf(env), uid);
  const secret = base32Decode(b.secret_b32);
  await confirmTotp(rcOf(env), uid, await totpCode(secret, stepOf(env.__clock())));
  return secret;
}

// Render the data-URI SVG back to pixels and read it with an independent decoder.
function decodeQrDataUri(uri) {
  const svg = Buffer.from(uri.replace(/^data:image\/svg\+xml;base64,/, ''), 'base64').toString('utf8');
  const full = Number(/viewBox="0 0 (\d+) \d+"/.exec(svg)[1]);
  const cells = Array.from({ length: full }, () => new Array(full).fill(false));
  for (const m of svg.matchAll(/M(\d+) (\d+)h(\d+)/g)) {
    const [x, y, run] = [Number(m[1]), Number(m[2]), Number(m[3])];
    for (let i = 0; i < run; i++) cells[y][x + i] = true;
  }
  const k = 4;
  const w = full * k;
  const px = new Uint8ClampedArray(w * w * 4).fill(255);
  for (let y = 0; y < full; y++)
    for (let x = 0; x < full; x++)
      if (cells[y][x])
        for (let dy = 0; dy < k; dy++)
          for (let dx = 0; dx < k; dx++) {
            const o = ((y * k + dy) * w + x * k + dx) * 4;
            px[o] = px[o + 1] = px[o + 2] = 0;
          }
  const r = jsQR(px, w, w, { inversionAttempts: 'dontInvert' });
  return r ? r.data : null;
}

// ---------------------------------------------------------------- RFC 6238

test('RFC 6238 Appendix B vectors (SHA-1, truncated to 6 digits)', async () => {
  const vectors = [
    [59, '287082'],
    [1111111109, '081804'],
    [1111111111, '050471'],
    [1234567890, '005924'],
    [2000000000, '279037'],
    [20000000000, '353130'],
  ];
  for (const [t, want] of vectors) {
    assert.equal(await totpCode(RFC_SECRET, Math.floor(t / 30)), want, `T=${t}`);
    assert.equal(await verifyTotp(RFC_SECRET, want, t * 1000, null), Math.floor(t / 30), `verify T=${t}`);
  }
});

test('totpCode refuses a bad counter or secret rather than computing something', async () => {
  for (const c of [-1, 1.5, NaN, Infinity, '1', null, 2 ** 53]) await assert.rejects(totpCode(RFC_SECRET, c), RangeError, show(c));
  await assert.rejects(totpCode(new Uint8Array(0), 1), TypeError);
  await assert.rejects(totpCode('12345678901234567890', 1), TypeError);
});

// ---------------------------------------------------------------- base32

test('base32: RFC 4648 vectors, padding, case, grouping', () => {
  const cases = [['f', 'MY'], ['fo', 'MZXQ'], ['foo', 'MZXW6'], ['foob', 'MZXW6YQ'], ['fooba', 'MZXW6YTB'], ['foobar', 'MZXW6YTBOI']];
  for (const [plain, enc] of cases) {
    assert.equal(base32Encode(utf8(plain)), enc);
    assert.deepEqual(base32Decode(enc), utf8(plain));
    assert.deepEqual(base32Decode(enc.toLowerCase()), utf8(plain));
  }
  assert.deepEqual(base32Decode('MZXW6==='), utf8('foo'));
  const s = generateTotpSecret();
  assert.equal(s.length, 20);
  const b32 = base32Encode(s);
  assert.equal(b32.length, 32);
  assert.deepEqual(base32Decode(b32), s);
  assert.deepEqual(base32Decode(groupSecret(b32)), s, 'the grouped form decodes');
});

test('base32Decode is strict: junk, impossible lengths, trailing bits, empty → null', () => {
  for (const v of [...HOSTILE, 'MZXW6!', 'MZ0W6', 'MZ1W6', 'MZ8W6', 'M', 'MZX', 'MZXW6Y', 'MZ', 'MZXW7', 'A'.repeat(2000), '====']) {
    assert.equal(base32Decode(v), null, show(v));
  }
});

test('groupSecret: groups of four; hostile → empty string', () => {
  assert.equal(groupSecret('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'), 'GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ');
  assert.equal(groupSecret('ABCDEF'), 'ABCD EF');
  for (const v of HOSTILE.filter((x) => typeof x !== 'string')) assert.equal(groupSecret(v), '');
});

// ---------------------------------------------------------------- verifyTotp

test('verifyTotp: ±1 step accepted, ±2 refused; returns the matched counter; spaces forgiven', async () => {
  const t = 1_700_000_000_000;
  const c = stepOf(t);
  for (const d of [-1, 0, 1]) assert.equal(await verifyTotp(RFC_SECRET, await totpCode(RFC_SECRET, c + d), t, null), c + d, `drift ${d}`);
  for (const d of [-2, 2, 3]) assert.equal(await verifyTotp(RFC_SECRET, await totpCode(RFC_SECRET, c + d), t, null), null, `drift ${d}`);
  const code = await totpCode(RFC_SECRET, c);
  assert.equal(await verifyTotp(RFC_SECRET, `${code.slice(0, 3)} ${code.slice(3)}`, t, null), c);
  assert.equal(await verifyTotp(RFC_SECRET, ` ${code} `, t, null), c);
  assert.equal(await verifyTotp(RFC_SECRET, `${code}0`, t, null), null);
  assert.equal(await verifyTotp(RFC_SECRET, code.slice(1), t, null), null);
  assert.equal(await verifyTotp(RFC_SECRET, `${code.slice(0, 5)}a`, t, null), null);
  assert.equal(await verifyTotp(RFC_SECRET, Number(code), t, null), null, 'a number is not a code');
  assert.equal(await verifyTotp(RFC_SECRET, `+${code.slice(1)}`, t, null), null);
});

test('verifyTotp replay floor: null/undefined = none; integer = refuse ≤ floor', async () => {
  const t = 1_700_000_000_000;
  const c = stepOf(t);
  const code = await totpCode(RFC_SECRET, c);
  assert.equal(await verifyTotp(RFC_SECRET, code, t, undefined), c);
  assert.equal(await verifyTotp(RFC_SECRET, code, t, null), c);
  assert.equal(await verifyTotp(RFC_SECRET, code, t, c - 1), c);
  assert.equal(await verifyTotp(RFC_SECRET, code, t, c), null, 'the spent counter');
  assert.equal(await verifyTotp(RFC_SECRET, code, t, c + 1), null);
  assert.equal(await verifyTotp(RFC_SECRET, await totpCode(RFC_SECRET, c + 1), t, c), c + 1, 'the next step still works');
  assert.equal(await verifyTotp(RFC_SECRET, code, t, 0), c, 'an explicit 0 is a real floor, not absence');
});

test('verifyTotp: an UNREADABLE floor refuses every code (A §14.3)', async () => {
  const t = 1_700_000_000_000;
  const code = await totpCode(RFC_SECRET, stepOf(t));
  for (const floor of ['garbage', NaN, {}, Infinity, -Infinity, '5', '', '   ', [], true, false, 1.5, -1, Symbol('f'), 2 ** 53, 10n]) {
    assert.equal(await verifyTotp(RFC_SECRET, code, t, floor), null, show(floor));
  }
});

test('verifyTotp: secrets under 16 bytes are refused at verification (RFC 4226 R6)', async () => {
  const t = 1_700_000_000_000;
  for (const n of [1, 10, 15]) {
    const s = RFC_SECRET.slice(0, n);
    assert.equal(await verifyTotp(s, await totpCode(s, stepOf(t)), t, null), null, `${n} bytes`);
  }
  const s16 = RFC_SECRET.slice(0, 16);
  assert.equal(await verifyTotp(s16, await totpCode(s16, stepOf(t)), t, null), stepOf(t));
});

test('verifyTotp: hostile code, secret and clock → null, never a throw', async () => {
  const t = 1_700_000_000_000;
  const code = await totpCode(RFC_SECRET, stepOf(t));
  for (const v of HOSTILE) {
    assert.equal(await verifyTotp(RFC_SECRET, v, t, null), null, `code ${show(v)}`);
    assert.equal(await verifyTotp(v, code, t, null), null, `secret ${show(v)}`);
    if (v !== 0) assert.equal(await verifyTotp(RFC_SECRET, code, v, null), null, `clock ${show(v)}`);
  }
  assert.equal(await verifyTotp(RFC_SECRET, '1'.repeat(10_000), t, null), null);
});

// ---------------------------------------------------------------- otpauth

test('otpauthUri: issuer and account are encoded; secret and issuer parameters present', () => {
  const u = otpauthUri({ issuer: 'Acme Inc.', account: 'jane@acme.com', secretB32: 'GEZDGNBV' });
  assert.equal(u, 'otpauth://totp/Acme%20Inc.:jane%40acme.com?secret=GEZDGNBV&issuer=Acme%20Inc.');
  const v = otpauthUri({ issuer: 'A:B&C', account: 'x?y', secretB32: 'AA' });
  assert.ok(v.startsWith('otpauth://totp/A%3AB%26C:x%3Fy?'), v);
  assert.ok(v.endsWith('&issuer=A%3AB%26C'));
  for (const h of HOSTILE) assert.doesNotThrow(() => otpauthUri({ issuer: h, account: h, secretB32: 'AA' }), show(h));
});

// ---------------------------------------------------------------- begin / confirm

test('beginTotp: stores the secret encrypted and bound to the user, unconfirmed; returns grouped secret, otpauth and a QR that decodes to it', async () => {
  const env = await makeEnvWithSchema();
  const uid = await addUser(env);
  const other = await addUser(env, 'bob@acme.com');
  const b = await beginTotp(rcOf(env), uid);
  assert.deepEqual(Object.keys(b).sort(), ['otpauth', 'qr', 'secret_b32', 'secret_grouped']);
  assert.equal(base32Decode(b.secret_b32).length, 20);
  assert.match(b.secret_grouped, /^([A-Z2-7]{4} ){7}[A-Z2-7]{4}$/);
  assert.equal(b.secret_grouped.replace(/ /g, ''), b.secret_b32);
  assert.equal(b.otpauth, `otpauth://totp/Acme%20Inc.:jane%40acme.com?secret=${b.secret_b32}&issuer=Acme%20Inc.`);
  assert.match(b.qr, /^data:image\/svg\+xml;base64,/);
  assert.equal(decodeQrDataUri(b.qr), b.otpauth, 'the QR carries exactly the otpauth URI');

  const row = totpRow(env, uid);
  assert.equal(row.confirmed_at, null);
  assert.equal(row.last_counter, null);
  assert.ok(row.secret_enc.startsWith('v1.'));
  assert.ok(!row.secret_enc.includes(b.secret_b32), 'not stored in the clear');
  assert.equal(await decrypt(env, row.secret_enc, `totp:${uid}`), b.secret_b32);
  assert.equal(await decrypt(env, row.secret_enc, `totp:${other}`), null, 'AAD binds the blob to its row');
  // Nothing is a factor yet.
  assert.equal(await loadConfirmedTotp(env, uid), null);
});

test('beginTotp replaces an unconfirmed enrolment; refuses (409) once one is confirmed, leaving it untouched', async () => {
  const env = await makeEnvWithSchema();
  const uid = await addUser(env);
  const a = await beginTotp(rcOf(env), uid);
  const b = await beginTotp(rcOf(env), uid);
  assert.notEqual(a.secret_b32, b.secret_b32);
  assert.equal(env.DB.q('SELECT COUNT(*) AS n FROM user_totp')[0].n, 1);
  assert.equal(await decrypt(env, totpRow(env, uid).secret_enc, `totp:${uid}`), b.secret_b32);
  await confirmTotp(rcOf(env), uid, await totpCode(base32Decode(b.secret_b32), stepOf(env.__clock())));
  const before = totpRow(env, uid);
  await assert.rejects(beginTotp(rcOf(env), uid), (e) => e.status === 409 && e.body.code === 'totp_exists');
  assert.deepEqual(totpRow(env, uid), before);
  await assert.rejects(beginTotp(rcOf(env), 999), (e) => e.status === 404);
  for (const v of HOSTILE) await assert.rejects(beginTotp(rcOf(env), v), (e) => e.status === 404, show(v));
});

test('confirmTotp: a wrong code leaves it unconfirmed; the right one confirms, sets the floor and issues 10 backup codes once', async () => {
  const env = await makeEnvWithSchema();
  const uid = await addUser(env);
  const b = await beginTotp(rcOf(env), uid);
  const secret = base32Decode(b.secret_b32);
  const c = stepOf(env.__clock());
  const good = await totpCode(secret, c);
  const bad = good === '000000' ? '111111' : '000000';
  await assert.rejects(confirmTotp(rcOf(env), uid, bad), (e) => e.status === 400 && e.body.code === 'totp_invalid');
  for (const v of HOSTILE) await assert.rejects(confirmTotp(rcOf(env), uid, v), (e) => e.status === 400, show(v));
  assert.equal(totpRow(env, uid).confirmed_at, null);
  assert.equal(env.DB.q('SELECT COUNT(*) AS n FROM backup_codes')[0].n, 0);

  const r = await confirmTotp(rcOf(env), uid, good);
  assert.equal(r.backup_codes.length, 10);
  const shape = new RegExp(`^[${BACKUP_ALPHABET}]{5}-[${BACKUP_ALPHABET}]{5}$`);
  for (const code of r.backup_codes) assert.match(code, shape);
  const row = totpRow(env, uid);
  assert.equal(row.confirmed_at, iso(env.__clock()));
  assert.equal(row.last_counter, c, 'the confirming code is spent');
  assert.equal(env.DB.q('SELECT COUNT(*) AS n FROM backup_codes WHERE user_id = ? AND used_at IS NULL', uid)[0].n, 10);
  // No pending row any more.
  await assert.rejects(confirmTotp(rcOf(env), uid, good), (e) => e.status === 409 && e.body.code === 'totp_not_pending');
  // The confirming code cannot then sign in (it is below the floor).
  assert.equal(await checkTotp(rcOf(env), uid, good), false);
});

test('confirmTotp does not replace unused backup codes the person already holds', async () => {
  const env = await makeEnvWithSchema();
  const uid = await addUser(env);
  const first = await enrol(env, uid);
  assert.ok(first);
  const hashes = env.DB.q('SELECT code_hash FROM backup_codes WHERE user_id = ? ORDER BY id', uid);
  await removeTotp(rcOf(env), uid);
  const b = await beginTotp(rcOf(env), uid);
  const r = await confirmTotp(rcOf(env), uid, await totpCode(base32Decode(b.secret_b32), stepOf(env.__clock())));
  assert.equal(r.backup_codes, null);
  assert.deepEqual(env.DB.q('SELECT code_hash FROM backup_codes WHERE user_id = ? ORDER BY id', uid), hashes);
});

test('confirmTotp verifies against the CURRENT pending secret: a code from a replaced setup fails', async () => {
  const env = await makeEnvWithSchema();
  const uid = await addUser(env);
  const a = await beginTotp(rcOf(env), uid);
  await beginTotp(rcOf(env), uid);
  const stale = await totpCode(base32Decode(a.secret_b32), stepOf(env.__clock()));
  await assert.rejects(confirmTotp(rcOf(env), uid, stale), (e) => e.status === 400);
  assert.equal(totpRow(env, uid).confirmed_at, null);
});

// ---------------------------------------------------------------- checkTotp

test('checkTotp: unconfirmed rows never sign in', async () => {
  const env = await makeEnvWithSchema();
  const uid = await addUser(env);
  const b = await beginTotp(rcOf(env), uid);
  assert.equal(await checkTotp(rcOf(env), uid, await totpCode(base32Decode(b.secret_b32), stepOf(env.__clock()))), false);
  assert.equal(totpRow(env, uid).last_counter, null);
});

test('checkTotp: accepts once per step, advances the floor, refuses replay, accepts the next step', async () => {
  const env = await makeEnvWithSchema();
  const uid = await addUser(env);
  const secret = await enrol(env, uid);
  env.__advance(TOTP_STEP_MS);
  const c = stepOf(env.__clock());
  const code = await totpCode(secret, c);
  assert.equal(await checkTotp(rcOf(env), uid, code), true);
  assert.equal(totpRow(env, uid).last_counter, c);
  assert.equal(await checkTotp(rcOf(env), uid, code), false, 'replay in the same step');
  env.__advance(10_000);
  assert.equal(await checkTotp(rcOf(env), uid, code), false, 'replay still refused a few seconds later');
  env.__advance(TOTP_STEP_MS);
  assert.equal(await checkTotp(rcOf(env), uid, await totpCode(secret, c + 1)), true);
  assert.equal(totpRow(env, uid).last_counter, c + 1);
  assert.equal(audits(env).length, 0, 'success writes no audit rows here — the sign-in does');
});

test('checkTotp: hostile codes and user ids → false, nothing read or written, no audit', async () => {
  const env = await makeEnvWithSchema();
  const uid = await addUser(env);
  const secret = await enrol(env, uid);
  const before = totpRow(env, uid);
  const code = await totpCode(secret, stepOf(env.__clock()) + 1);
  for (const v of HOSTILE) {
    assert.equal(await checkTotp(rcOf(env), uid, v), false, `code ${show(v)}`);
    assert.equal(await checkTotp(rcOf(env), v, code), false, `uid ${show(v)}`);
  }
  assert.deepEqual(totpRow(env, uid), before);
  assert.equal(audits(env).length, 0);
});

test('checkTotp: a row that will not decrypt is refused and audited critical — never "no authenticator"', async () => {
  const env = await makeEnvWithSchema();
  const uid = await addUser(env);
  const other = await addUser(env, 'bob@acme.com');
  const secret = await enrol(env, uid);
  const code = await totpCode(secret, stepOf(env.__clock()) + 1);
  const good = totpRow(env, uid).secret_enc;
  // (1) corrupt blob, (2) a valid blob moved from another account (AAD), (3) wrong DATA_KEY.
  const moved = await encrypt(env, base32Encode(secret), `totp:${other}`);
  for (const blob of ['v1.garbage.garbage', '', 'not-a-blob', moved]) {
    env.DB.q('UPDATE user_totp SET secret_enc = ? WHERE user_id = ?', blob, uid);
    assert.equal(await checkTotp(rcOf(env), uid, code), false, blob.slice(0, 20));
  }
  env.DB.q('UPDATE user_totp SET secret_enc = ? WHERE user_id = ?', good, uid);
  const rotated = { ...env, DATA_KEY: 'a-completely-different-data-key-0123456789abcdef' };
  assert.equal(await checkTotp({ env: rotated, nowMs: env.__clock() }, uid, code), false);
  const rows = audits(env, 'mfa.%');
  assert.equal(rows.length, 5);
  for (const r of rows) {
    assert.equal(r.action, 'mfa.decrypt_failed');
    assert.equal(r.severity, 'critical');
    assert.equal(r.outcome, 'failure');
    assert.equal(r.target_id, String(uid));
    assert.ok(!JSON.stringify(r).includes(code), 'the submitted code is never logged');
    assert.ok(!JSON.stringify(r).includes(base32Encode(secret)), 'nor the secret');
  }
  // It still reads as a confirmed (unusable) authenticator, not as none.
  assert.equal((await loadConfirmedTotp(rotated, uid)).problem, 'decrypt');
  assert.equal(totpRow(env, uid).last_counter, stepOf(env.__clock()), 'floor untouched');
});

test('checkTotp: a stored secret under 16 bytes is refused even with its own correct code', async () => {
  const env = await makeEnvWithSchema();
  const uid = await addUser(env);
  const short = RFC_SECRET.slice(0, 10);
  const t = iso(env.__clock());
  env.DB.q('INSERT INTO user_totp (user_id, secret_enc, confirmed_at, last_counter, created_at) VALUES (?, ?, ?, NULL, ?)',
    uid, await encrypt(env, base32Encode(short), `totp:${uid}`), t, t);
  assert.equal(await checkTotp(rcOf(env), uid, await totpCode(short, stepOf(env.__clock()))), false);
  assert.equal(totpRow(env, uid).last_counter, null);
  assert.equal(audits(env, 'mfa.decrypt_failed').length, 1);
});

test('checkTotp: an unreadable replay floor refuses the correct code and is audited (A §14.3)', async () => {
  for (const floor of ['garbage', 1.5, -1, '', 1e308 * 10]) {
    const env = await makeEnvWithSchema();
    const uid = await addUser(env);
    const secret = await enrol(env, uid);
    env.DB.q('UPDATE user_totp SET last_counter = ? WHERE user_id = ?', floor, uid);
    const code = await totpCode(secret, stepOf(env.__clock()) + 1);
    assert.equal(await checkTotp(rcOf(env), uid, code), false, show(floor));
    const rows = audits(env, 'mfa.%');
    assert.equal(rows.length, 1, show(floor));
    assert.equal(rows[0].action, 'mfa.replay_floor_unreadable');
    assert.equal(rows[0].severity, 'critical');
    assert.ok(!JSON.stringify(rows[0]).includes(code));
    assert.equal((await loadConfirmedTotp(env, uid)).problem, 'floor');
  }
});

test('checkTotp: two simultaneous uses of one code — exactly one wins', async () => {
  const env = await makeEnvWithSchema();
  const uid = await addUser(env);
  const secret = await enrol(env, uid);
  const code = await totpCode(secret, stepOf(env.__clock()) + 1);
  const results = await Promise.all([checkTotp(rcOf(env), uid, code), checkTotp(rcOf(env), uid, code), checkTotp(rcOf(env), uid, code)]);
  assert.equal(results.filter(Boolean).length, 1, JSON.stringify(results));
});

test('checkTotp: the floor UPDATE is conditional on the floor read (a concurrent winner makes this one lose)', async () => {
  const env = await makeEnvWithSchema();
  const uid = await addUser(env);
  const secret = await enrol(env, uid);
  const c = stepOf(env.__clock()) + 1;
  const code = await totpCode(secret, c);
  // Between our read and our write, another request spends the same counter.
  const prepare = env.DB.prepare.bind(env.DB);
  let raced = false;
  env.DB.prepare = (sql) => {
    if (!raced && /^\s*UPDATE user_totp SET last_counter/.test(sql)) {
      raced = true;
      env.DB.q('UPDATE user_totp SET last_counter = ? WHERE user_id = ?', c, uid);
    }
    return prepare(sql);
  };
  assert.equal(await checkTotp(rcOf(env), uid, code), false);
  assert.ok(raced);
});

test('removeTotp deletes the row; hostile ids are refused', async () => {
  const env = await makeEnvWithSchema();
  const uid = await addUser(env);
  await enrol(env, uid);
  await removeTotp(rcOf(env), uid);
  assert.equal(totpRow(env, uid), undefined);
  for (const v of HOSTILE) await assert.rejects(removeTotp(rcOf(env), v), (e) => e.status === 404);
});

await run();
