import { test, assert, run } from '../helpers/t.js';
import { makeEnvWithSchema } from '../helpers/env.js';
import { iso, hex, fromHex, randomBytes } from '../../src/util.js';
import { pbkdf2Chain } from '../../src/crypto.js';
import {
  BACKUP_ALPHABET, BACKUP_ITERS, generateBackupCodes, normalizeBackupCode, storeBackupCodes, consumeBackupCode,
  countUnusedBackupCodes,
} from '../../src/mfa/backup.js';

const HOSTILE = [null, undefined, NaN, Infinity, '', '   ', 'abc', {}, [], true, 0, Symbol('x')];
const show = (v) => (typeof v === 'symbol' ? 'Symbol' : JSON.stringify(v) ?? String(v));
// Everything that would normalise to '' without the shape gate (A §14.4).
const EMPTYISH = ['', '   ', '-----', '\t\n', ' - - ', '----------', null, undefined, []];

// Counts PBKDF2 derivations: "no KDF ran" is an assertion, not a hope.
let kdfCalls = 0;
const realDeriveBits = crypto.subtle.deriveBits;
crypto.subtle.deriveBits = function (...args) {
  kdfCalls++;
  return realDeriveBits.apply(this, args);
};

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
const rows = (env, uid) => env.DB.q('SELECT * FROM backup_codes WHERE user_id = ? ORDER BY id', uid);
const audits = (env) => env.DB.q('SELECT * FROM audit_log ORDER BY seq');

async function plant(env, uid, code, { salt = randomBytes(16), iters = BACKUP_ITERS } = {}) {
  const h = hex(await pbkdf2Chain(code, salt, iters));
  env.DB.q('INSERT INTO backup_codes (user_id, code_hash, salt, iters, created_at) VALUES (?, ?, ?, ?, ?)', uid, h, hex(salt), iters, iso(env.__clock()));
}

// ---------------------------------------------------------------- generation

test('alphabet is exactly the unambiguous set: no 0 1 I O L', () => {
  assert.equal(BACKUP_ALPHABET, '23456789ABCDEFGHJKMNPQRSTUVWXYZ');
  for (const c of '01IOL') assert.ok(!BACKUP_ALPHABET.includes(c), c);
  assert.equal(BACKUP_ITERS, 100_000);
});

test('generateBackupCodes: 10 distinct ABCDE-FGHJK codes from the alphabet', () => {
  const codes = generateBackupCodes();
  assert.equal(codes.length, 10);
  assert.equal(new Set(codes).size, 10);
  const shape = new RegExp(`^[${BACKUP_ALPHABET}]{5}-[${BACKUP_ALPHABET}]{5}$`);
  for (const c of codes) assert.match(c, shape);
  assert.equal(generateBackupCodes(3).length, 3);
  for (const n of [0, -1, 101, 1.5, 'abc', NaN]) assert.throws(() => generateBackupCodes(n), RangeError, show(n));
});

test('generateBackupCodes: characters are uniform (rejection sampling, not modulo)', () => {
  // A byte % 31 would make the first 8 letters 12.5% likelier; uniform keeps
  // the two groups within a couple of percent at this sample size.
  const counts = new Map([...BACKUP_ALPHABET].map((c) => [c, 0]));
  for (let i = 0; i < 600; i++) for (const code of generateBackupCodes(10)) for (const ch of code.replace('-', '')) counts.set(ch, counts.get(ch) + 1);
  const vals = [...BACKUP_ALPHABET].map((c) => counts.get(c));
  assert.ok(vals.every((v) => v > 0));
  const mean = (a) => a.reduce((x, y) => x + y, 0) / a.length;
  const ratio = mean(vals.slice(0, 8)) / mean(vals.slice(8));
  assert.ok(ratio < 1.06 && ratio > 0.94, `first-8 / rest = ${ratio}`);
});

// ---------------------------------------------------------------- normalise

test('normalizeBackupCode: forgives case, spaces and hyphens', () => {
  for (const v of ['ABCDE-FGHJK', 'abcde-fghjk', 'ABCDEFGHJK', 'abcdefghjk', ' abcde fghjk ', 'ab-cd-ef-gh-jk', 'AbCdE\tFgHjK']) {
    assert.equal(normalizeBackupCode(v), 'ABCDEFGHJK', JSON.stringify(v));
  }
});

test('normalizeBackupCode is SHAPE-GATED: nothing a caller sends normalises to empty (A §14.4)', () => {
  for (const v of [...HOSTILE, ...EMPTYISH, 'ABCDE-FGHJ', 'ABCDE-FGHJKM', 'ABCDE-FGHJ0', 'ABCDE-FGHJ1', 'ABCDE-FGHJI', 'ABCDE-FGHJO', 'ABCDE-FGHJL',
    'ABCDE_FGHJK', 'ABCDE.FGHJK', 'ÀBCDE-FGHJK', 'ABCDE-FGHJK'.padEnd(80, ' '), 12345678, ['ABCDEFGHJK'], { toString: () => 'ABCDEFGHJK' }]) {
    assert.equal(normalizeBackupCode(v), null, show(v));
  }
});

// ---------------------------------------------------------------- store

test('storeBackupCodes: one salt per set, 100k iterations, only hashes stored', async () => {
  const env = await makeEnvWithSchema();
  const uid = await addUser(env);
  const codes = generateBackupCodes();
  await storeBackupCodes(env, uid, codes, env.__clock());
  const r = rows(env, uid);
  assert.equal(r.length, 10);
  assert.equal(new Set(r.map((x) => x.salt)).size, 1, 'one salt for the set');
  assert.equal(fromHex(r[0].salt).length, 16);
  for (let i = 0; i < 10; i++) {
    assert.equal(r[i].iters, 100_000);
    assert.equal(r[i].used_at, null);
    assert.equal(r[i].code_hash, hex(await pbkdf2Chain(normalizeBackupCode(codes[i]), fromHex(r[i].salt), 100_000)));
    for (const c of codes) {
      assert.ok(!JSON.stringify(r[i]).includes(c) && !JSON.stringify(r[i]).includes(c.replace('-', '')), 'no plaintext');
    }
  }
});

test('storeBackupCodes replaces the unused set, keeps used history, and uses a fresh salt', async () => {
  const env = await makeEnvWithSchema();
  const uid = await addUser(env);
  const other = await addUser(env, 'bob@acme.com');
  const first = generateBackupCodes();
  await storeBackupCodes(env, uid, first, env.__clock());
  await storeBackupCodes(env, other, generateBackupCodes(), env.__clock());
  assert.equal(await consumeBackupCode(rcOf(env), uid, first[0]), true);
  const oldSalt = rows(env, uid)[0].salt;
  const second = generateBackupCodes();
  await storeBackupCodes(env, uid, second, env.__clock());
  const r = rows(env, uid);
  assert.equal(r.length, 11, '10 new + the 1 used row');
  assert.equal(r.filter((x) => x.used_at !== null).length, 1);
  assert.notEqual(r.find((x) => x.used_at === null).salt, oldSalt);
  assert.equal(await consumeBackupCode(rcOf(env), uid, first[1]), false, 'the old set is gone');
  assert.equal(await countUnusedBackupCodes(env, other), 10, 'other users untouched');
});

test('storeBackupCodes refuses malformed input before writing anything', async () => {
  const env = await makeEnvWithSchema();
  const uid = await addUser(env);
  await assert.rejects(storeBackupCodes(env, uid, ['ABCDE-FGHJK', ''], env.__clock()), RangeError);
  await assert.rejects(storeBackupCodes(env, uid, [], env.__clock()), RangeError);
  await assert.rejects(storeBackupCodes(env, uid, 'ABCDE-FGHJK', env.__clock()), RangeError);
  for (const v of HOSTILE) await assert.rejects(storeBackupCodes(env, v, ['ABCDE-FGHJK'], env.__clock()), RangeError);
  assert.equal(rows(env, uid).length, 0);
});

// ---------------------------------------------------------------- consume

test('consumeBackupCode: accepts once (lowercase, spaced), marks used, audits mfa.backup.used with the count', async () => {
  const env = await makeEnvWithSchema();
  const uid = await addUser(env);
  const codes = generateBackupCodes();
  await storeBackupCodes(env, uid, codes, env.__clock());
  const typed = codes[3].toLowerCase().replace('-', ' ');
  assert.equal(await consumeBackupCode(rcOf(env), uid, typed), true);
  const used = rows(env, uid).filter((x) => x.used_at !== null);
  assert.equal(used.length, 1);
  assert.equal(used[0].used_at, iso(env.__clock()));
  assert.equal(await countUnusedBackupCodes(env, uid), 9);
  let a = audits(env);
  assert.equal(a.length, 1);
  assert.equal(a[0].action, 'mfa.backup.used');
  assert.equal(a[0].severity, 'notice');
  assert.equal(a[0].outcome, 'success');
  assert.equal(a[0].target_id, String(uid));
  assert.match(a[0].detail, /9 left/);
  assert.ok(!JSON.stringify(a[0]).includes(codes[3]) && !JSON.stringify(a[0]).includes(normalizeBackupCode(codes[3])), 'code never logged');
  // Single use.
  assert.equal(await consumeBackupCode(rcOf(env), uid, codes[3]), false);
  assert.equal(audits(env).length, 1, 'a refused code writes no audit row here');
  // Another works, and the count falls.
  assert.equal(await consumeBackupCode(rcOf(env), uid, codes[7]), true);
  a = audits(env);
  assert.match(a[1].detail, /8 left/);
});

test('consumeBackupCode: a wrong code, another user\'s code → false, nothing changed', async () => {
  const env = await makeEnvWithSchema();
  const uid = await addUser(env);
  const other = await addUser(env, 'bob@acme.com');
  const mine = generateBackupCodes();
  const theirs = generateBackupCodes();
  await storeBackupCodes(env, uid, mine, env.__clock());
  await storeBackupCodes(env, other, theirs, env.__clock());
  const wrong = generateBackupCodes(1)[0];
  assert.equal(await consumeBackupCode(rcOf(env), uid, mine.includes(wrong) ? 'ZZZZZ-ZZZZZ' : wrong), false);
  assert.equal(await consumeBackupCode(rcOf(env), uid, theirs[0]), false);
  assert.equal(await countUnusedBackupCodes(env, uid), 10);
  assert.equal(await countUnusedBackupCodes(env, other), 10);
  assert.equal(audits(env).length, 0);
});

test('a planted hash(\'\') row cannot be opened by an empty, blank or separator-only submission — and no KDF runs', async () => {
  const env = await makeEnvWithSchema();
  const uid = await addUser(env);
  await plant(env, uid, '');
  // Make sure the plant really is hash('') under its own salt.
  const r = rows(env, uid)[0];
  assert.equal(r.code_hash, hex(await pbkdf2Chain('', fromHex(r.salt), BACKUP_ITERS)));
  kdfCalls = 0;
  for (const v of [...EMPTYISH, ...HOSTILE]) assert.equal(await consumeBackupCode(rcOf(env), uid, v), false, show(v));
  assert.equal(kdfCalls, 0, 'shape-gated before any derivation');
  assert.equal(rows(env, uid)[0].used_at, null);
  assert.equal(audits(env).length, 0);
});

test('consumeBackupCode: hostile user ids → false without a KDF', async () => {
  const env = await makeEnvWithSchema();
  const uid = await addUser(env);
  const codes = generateBackupCodes();
  await storeBackupCodes(env, uid, codes, env.__clock());
  kdfCalls = 0;
  for (const v of HOSTILE) assert.equal(await consumeBackupCode(rcOf(env), v, codes[0]), false, show(v));
  assert.equal(kdfCalls, 0);
  assert.equal(await countUnusedBackupCodes(env, uid), 10);
});

test('one KDF per distinct salt, not per row', async () => {
  const env = await makeEnvWithSchema();
  const uid = await addUser(env);
  const codes = generateBackupCodes();
  await storeBackupCodes(env, uid, codes, env.__clock());
  kdfCalls = 0;
  assert.equal(await consumeBackupCode(rcOf(env), uid, 'ZZZZZ-ZZZZY'), false);
  assert.equal(kdfCalls, 1, 'ten rows, one salt, one derivation');
  // A second set under another salt (e.g. a restore beside a partial set).
  const extra = 'MNPQR-STUVW';
  await plant(env, uid, normalizeBackupCode(extra));
  kdfCalls = 0;
  assert.equal(await consumeBackupCode(rcOf(env), uid, extra), true);
  assert.equal(kdfCalls, 2);
});

test('rows with an unreadable salt, iteration count or hash never match', async () => {
  const env = await makeEnvWithSchema();
  const uid = await addUser(env);
  const code = 'ABCDE-FGHJK';
  const n = normalizeBackupCode(code);
  const salt = randomBytes(16);
  const h = hex(await pbkdf2Chain(n, salt, BACKUP_ITERS));
  const t = iso(env.__clock());
  const ins = (hash, s, iters) => env.DB.q('INSERT INTO backup_codes (user_id, code_hash, salt, iters, created_at) VALUES (?, ?, ?, ?, ?)', uid, hash, s, iters, t);
  ins(h, hex(salt), 'abc');
  ins(h, hex(salt), 99_999); // below the floor: we never wrote one
  ins(h, 'zz', BACKUP_ITERS);
  ins(h, hex(salt.slice(0, 8)), BACKUP_ITERS);
  ins(h.slice(2), hex(salt), BACKUP_ITERS);
  ins('', hex(salt), BACKUP_ITERS);
  assert.equal(await consumeBackupCode(rcOf(env), uid, code), false);
  assert.equal(env.DB.q('SELECT COUNT(*) AS n FROM backup_codes WHERE used_at IS NOT NULL')[0].n, 0);
  // The same hash with readable fields does match: the refusals above were about the fields.
  ins(h, hex(salt), BACKUP_ITERS);
  assert.equal(await consumeBackupCode(rcOf(env), uid, code), true);
});

test('two simultaneous submissions of one code — exactly one succeeds, one audit row', async () => {
  const env = await makeEnvWithSchema();
  const uid = await addUser(env);
  const codes = generateBackupCodes();
  await storeBackupCodes(env, uid, codes, env.__clock());
  const r = await Promise.all([consumeBackupCode(rcOf(env), uid, codes[0]), consumeBackupCode(rcOf(env), uid, codes[0])]);
  assert.equal(r.filter(Boolean).length, 1);
  assert.equal(audits(env).length, 1);
});

test('spending is conditional on used_at IS NULL (a concurrent spend makes this one lose)', async () => {
  const env = await makeEnvWithSchema();
  const uid = await addUser(env);
  const codes = generateBackupCodes();
  await storeBackupCodes(env, uid, codes, env.__clock());
  const prepare = env.DB.prepare.bind(env.DB);
  let raced = false;
  env.DB.prepare = (sql) => {
    if (!raced && /^\s*UPDATE backup_codes SET used_at/.test(sql)) {
      raced = true;
      env.DB.q("UPDATE backup_codes SET used_at = '2026-01-01T00:00:00.000Z' WHERE user_id = ?", uid);
    }
    return prepare(sql);
  };
  assert.equal(await consumeBackupCode(rcOf(env), uid, codes[0]), false);
  assert.ok(raced);
  assert.equal(audits(env).length, 0);
});

test('countUnusedBackupCodes: hostile ids → 0', async () => {
  const env = await makeEnvWithSchema();
  for (const v of HOSTILE) assert.equal(await countUnusedBackupCodes(env, v), 0, show(v));
});

await run();
