import { test, assert, run } from '../helpers/t.js';
import { makeEnvWithSchema } from '../helpers/env.js';
import { CHROME_UA } from '../helpers/http.js';
import { iso, parseCookies, HOUR, MINUTE } from '../../src/util.js';
import { signToken } from '../../src/crypto.js';
import { resolvePolicy } from '../../src/policy.js';
import { normalizeIp } from '../../src/ip.js';
import { readDevice, DEVICE_COOKIE } from '../../src/devices.js';
import { tierForIp, isIpBlocked } from '../../src/network.js';
import { edgeSignals, readFpCookie, fpCookie, FP_COOKIE } from '../../src/fingerprint.js';
import * as G from '../../src/gate.js';

const HOSTILE = [null, undefined, NaN, Infinity, '', '   ', 'abc', {}, [], true, 0, Symbol('x')];
const show = (v) => (typeof v === 'symbol' ? 'Symbol' : JSON.stringify(v) ?? String(v));
const CH = '"Google Chrome";v="129", "Not=A?Brand";v="8", "Chromium";v="129"';
const CF = { country: 'US', asn: 7922, asOrganization: 'Comcast Cable', timezone: 'America/New_York', tlsVersion: 'TLSv1.3', httpProtocol: 'HTTP/2' };
const OFFICE_IP = '81.2.69.10'; // allowlisted (tier 2)
const STRANGER_IP = '91.198.174.20';
const APPROVED = 'approvedDevice0000000001';
const PENDING = 'pendingDevice00000000001';
const BLOCKED = 'blockedDevice00000000001';
const WEIRD = 'weirdDevice0000000000001';

const cookieValue = (sc) => sc.split(';')[0].split('=').slice(1).join('=');

async function world({ users = true, settings = {} } = {}) {
  const env = await makeEnvWithSchema();
  const t = iso(env.__clock());
  if (users) {
    const role = env.DB.q("SELECT id FROM roles WHERE key = 'super_admin'")[0].id;
    env.DB.q("INSERT INTO users (email, role_id, status, created_at, updated_at) VALUES ('owner@acme.com', ?, 'active', ?, ?)", role, t, t);
  }
  env.DB.q('INSERT INTO allowed_ips (cidr, tier, created_at, updated_at) VALUES (?, 2, ?, ?)', '81.2.69.0/24', t, t);
  for (const [id, status] of [[APPROVED, 'approved'], [PENDING, 'pending'], [BLOCKED, 'blocked'], [WEIRD, 'quarantined']]) {
    env.DB.q('INSERT INTO devices (id, status, first_seen, last_seen) VALUES (?, ?, ?, ?)', id, status, t, t);
  }
  for (const [k, v] of Object.entries(settings)) env.DB.q('INSERT INTO settings (key, value) VALUES (?, ?)', k, v);
  return env;
}

// What context.buildContext does (CONTRACTS §4.1), from the same modules.
async function ctx(env, { ip = STRANGER_IP, device = null, pass = false, fp = null, cookies = {}, cf = {}, headers = {}, at } = {}) {
  const nowMs = at ?? env.__clock();
  const jar = { ...cookies };
  if (device) jar[DEVICE_COOKIE] = await signToken(env, 'device', device);
  if (pass) jar[G.PASS_COOKIE] = cookieValue(await G.passCookie(env, nowMs));
  if (fp) jar[FP_COOKIE] = cookieValue(await fpCookie(env, 'a'.repeat(64), fp.risk, nowMs, fp));
  const request = new Request('https://staff.example.com/', {
    headers: { 'cf-connecting-ip': ip ?? '', 'user-agent': CHROME_UA, 'accept-language': 'en-US', 'sec-ch-ua': CH, 'sec-ch-ua-platform': '"macOS"', ...headers },
  });
  const rc = { env, request, nowMs, ip: normalizeIp(ip), cf: { ...CF, ...cf }, ua: request.headers.get('user-agent') || '', cookies: parseCookies(Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ')) };
  rc.policy = await resolvePolicy(env);
  rc.edge = edgeSignals(request, rc.cf);
  rc.fp = await readFpCookie(rc);
  rc.device = await readDevice(rc);
  rc.ipTier = await tierForIp(env, rc.ip, nowMs);
  rc.ipBlocked = await isIpBlocked(env, rc.ip, nowMs);
  return rc;
}

const decision = (g) => (g.allowed === 'shell' ? `shell:${g.shell}` : g.allowed);

// ---------------------------------------------------------------- the matrix

// An oracle written from CONTRACTS §7.8 step 4–5 as a table, not as code
// shaped like the implementation.
const MODE_TABLE = {
  public: { trusted: 'all', open: 'all', pass: 'all', stranger: 'all' },
  fingerprint_gate: { trusted: 'all', open: 'shell:login', pass: 'shell:login', stranger: 'shell:login' },
  request_access: { trusted: 'all', open: 'all', pass: 'shell:invite', stranger: 'shell:request' },
  allowlist: { trusted: 'all', open: 'all', pass: 'shell:invite', stranger: 'none' },
};

function expected({ mode, trust, pass, gating, open }) {
  const ipOk = trust === 'ip' || trust === 'both';
  const devOk = trust === 'device' || trust === 'both';
  let r;
  if (mode === 'lockdown') r = ipOk && devOk ? 'all' : 'none';
  // invite_only: the network alone admits nobody — an allowlisted address
  // only reaches the approval queue (CONTRACTS §7.8).
  else if (mode === 'invite_only') r = devOk ? 'all' : open ? 'all' : pass ? 'shell:invite' : ipOk ? 'shell:pending' : 'none';
  else {
    const row = MODE_TABLE[mode];
    r = ipOk || devOk ? row.trusted : open ? row.open : pass ? row.pass : row.stranger;
  }
  if (r !== 'none' && gating && !devOk) r = pass ? 'shell:invite' : 'shell:pending';
  return r;
}

test('evaluateGate: every mode × trust × pass × device gating × gate_open', async () => {
  let n = 0;
  for (const mode of G.MODES) {
    for (const gating of [false, true]) {
      for (const open of [false, true]) {
        const env = await world({ settings: { access_mode: mode, device_gating: gating ? '1' : '0', gate_open: open ? '1' : '0' } });
        for (const trust of ['none', 'ip', 'device', 'both']) {
          for (const pass of [false, true]) {
            const ip = trust === 'ip' || trust === 'both' ? OFFICE_IP : STRANGER_IP;
            const device = trust === 'device' || trust === 'both' ? APPROVED : PENDING;
            const g = await G.evaluateGate(await ctx(env, { ip, device, pass }));
            const want = expected({ mode, trust, pass, gating, open });
            const label = JSON.stringify({ mode, trust, pass, gating, open });
            assert.equal(decision(g), want, `${label} → ${decision(g)} (${g.reason})`);
            assert.equal(g.mode, mode);
            assert.equal(g.trusted, trust !== 'none', label);
            assert.equal(g.ipTier, trust === 'ip' || trust === 'both' ? 2 : null, label);
            assert.equal(typeof g.reason, 'string');
            if (g.allowed !== 'shell') assert.equal(g.shell, null);
            n++;
          }
        }
      }
    }
  }
  assert.equal(n, 6 * 2 * 2 * 4 * 2);
});

test('gate_open never opens lockdown; an expired or unreadable gate_open is closed', async () => {
  const at = (await makeEnvWithSchema()).__clock();
  for (const [raw, open] of [['1', true], [iso(at + HOUR), true], [iso(at - 1), false], ['42', false], ['true', false], ['', false], ['2099', false]]) {
    const env = await world({ settings: { gate_open: raw } });
    const g = await G.evaluateGate(await ctx(env, { at }));
    assert.equal(decision(g), open ? 'all' : 'none', raw);
    if (open) assert.equal(g.reason, 'open');
    const lock = await world({ settings: { access_mode: 'lockdown', gate_open: raw } });
    assert.equal(decision(await G.evaluateGate(await ctx(lock, { at }))), 'none', `lockdown + ${raw}`);
    assert.equal(decision(await G.evaluateGate(await ctx(lock, { at, ip: OFFICE_IP }))), 'none', 'lockdown needs the device too');
  }
});

test('an unknown stored access_mode behaves as lockdown (through policy resolution)', async () => {
  for (const raw of ['open', 'PUBLIC', '', ' allowlist', 'public ']) {
    const env = await world({ settings: { access_mode: raw, gate_open: '1' } });
    assert.equal((await G.evaluateGate(await ctx(env, { device: APPROVED }))).allowed, 'none', raw);
    const g = await G.evaluateGate(await ctx(env, { ip: OFFICE_IP, device: APPROVED }));
    assert.equal(g.mode, 'lockdown', raw);
    assert.equal(g.allowed, 'all');
  }
});

// ---------------------------------------------------------------- step 1

test('step 1: a blocked device, no address, a blocklisted address lose in every mode — allowlisted or not', async () => {
  for (const mode of G.MODES) {
    const env = await world({ settings: { access_mode: mode, gate_open: '1' } });
    const t = iso(env.__clock());
    for (const device of [BLOCKED, WEIRD]) {
      const g = await G.evaluateGate(await ctx(env, { ip: OFFICE_IP, device }));
      assert.deepEqual([g.allowed, g.reason], ['none', 'device_blocked'], `${mode} ${device}`);
    }
    for (const ip of [null, '', 'not-an-ip', '999.1.1.1']) {
      const g = await G.evaluateGate(await ctx(env, { ip, device: APPROVED }));
      assert.deepEqual([g.allowed, g.reason], ['none', 'no_ip'], `${mode} ${ip}`);
    }
    env.DB.q('INSERT INTO blocked_ips (cidr, created_at) VALUES (?, ?)', '81.2.69.10/32', t);
    const g = await G.evaluateGate(await ctx(env, { ip: OFFICE_IP, device: APPROVED, pass: true }));
    assert.deepEqual([g.allowed, g.reason], ['none', 'ip_blocked'], `${mode}: the allowlist does not beat the blocklist`);
  }
});

test('step 1 fails closed when the blocklist answer is missing or not exactly false', async () => {
  const env = await world({ settings: { access_mode: 'public' } });
  for (const v of [true, 'false', 0, null, Promise.resolve(false), {}]) {
    const rc = await ctx(env, { ip: OFFICE_IP });
    rc.ipBlocked = v;
    assert.equal((await G.evaluateGate(rc)).reason, 'ip_blocked', show(v));
  }
  const rc = await ctx(env, { ip: OFFICE_IP });
  delete rc.ipBlocked;
  assert.equal((await G.evaluateGate(rc)).allowed, 'all', 'absent → computed here');
});

// ---------------------------------------------------------------- step 2

const EDGE_RULES = [
  ['country (allow list)', { country_allow: '["US"]' }, { cf: { country: 'GB' } }, 'country'],
  ['country (deny list)', { country_deny: '["GB"]' }, { cf: { country: 'GB' } }, 'country'],
  ['country (unknown with an allow list)', { country_allow: '["US"]' }, { cf: { country: null } }, 'country'],
  ['country (T1 denied as a country)', { block_tor: '0', country_deny: '["T1"]' }, { cf: { country: 'T1' } }, 'country'],
  ['tor', {}, { cf: { country: 'T1' } }, 'tor'],
  ['datacenter', { block_datacenter: '1' }, { cf: { asn: 16509 } }, 'datacenter'],
  ['automation (UA)', {}, { headers: { 'user-agent': 'curl/8.4.0', 'sec-ch-ua': '', 'sec-ch-ua-platform': '' } }, 'automation'],
  ['automation (fp cookie)', {}, { fp: { risk: 10, automation: true } }, 'automation'],
  ['risk (edge)', { block_automation: '0' }, { headers: { 'user-agent': 'curl/8.4.0', 'accept-language': '', 'sec-ch-ua': '', 'sec-ch-ua-platform': '' } }, 'risk'],
  ['risk (fp cookie)', {}, { fp: { risk: 70 } }, 'risk'],
  ['risk (lowered threshold)', { risk_threshold: '35' }, { cf: { asn: 14061 } }, 'risk'],
];

test('step 2: each edge rule refuses a stranger — and an approved device does not bypass it', async () => {
  for (const [name, settings, req, reason] of EDGE_RULES) {
    const env = await world({ settings: { access_mode: 'public', ...settings } });
    const g = await G.evaluateGate(await ctx(env, req));
    assert.deepEqual([g.allowed, g.reason], ['none', reason], name);
    const d = await G.evaluateGate(await ctx(env, { ...req, device: APPROVED }));
    assert.deepEqual([d.allowed, d.reason], ['none', reason], `${name} with an approved device`);
  }
});

test('step 2 is skipped for an allowlisted address (B trap 8) — but a blocked device still loses', async () => {
  for (const [name, settings, req] of EDGE_RULES) {
    const env = await world({ settings: { access_mode: 'allowlist', ...settings } });
    const g = await G.evaluateGate(await ctx(env, { ...req, ip: OFFICE_IP }));
    assert.equal(g.allowed, 'all', `${name} from the office`);
    assert.equal(g.reason, 'allowlisted');
    const b = await G.evaluateGate(await ctx(env, { ...req, ip: OFFICE_IP, device: BLOCKED }));
    assert.equal(b.reason, 'device_blocked', name);
  }
});

test('step 2 country rules read the stored lists fail-closed', async () => {
  const cases = [
    [{ country_allow: '[]' }, 'all'], // stored [] = no restriction
    [{ country_allow: 'not json' }, 'none'], // unrecognised = allow none
    [{ country_deny: '{"x":1}' }, 'none'], // unrecognised = deny all
    [{ country_deny: '["US"]' }, 'none'],
    [{ country_allow: '["GB","US"]' }, 'all'],
  ];
  for (const [settings, want] of cases) {
    const env = await world({ settings: { access_mode: 'public', ...settings } });
    assert.equal((await G.evaluateGate(await ctx(env))).allowed, want, JSON.stringify(settings));
  }
});

test('step 2 reads a malformed policy object fail-closed: odd lists refuse, odd flags block', async () => {
  const env = await world({ settings: { access_mode: 'public' } });
  const cases = [
    [{ country_allow: undefined }, {}, 'country'],
    [{ country_allow: 'US' }, {}, 'country'],
    [{ country_allow: { US: true } }, {}, 'country'],
    [{ country_deny: undefined }, {}, 'country'],
    [{ country_deny: 'GB' }, {}, 'country'],
    [{ block_tor: 'no' }, { cf: { country: 'T1' } }, 'tor'],
    [{ block_tor: undefined }, { cf: { country: 'T1' } }, 'tor'],
    [{ block_datacenter: 0 }, { cf: { asn: 16509 } }, 'datacenter'],
    [{ block_automation: null }, { fp: { risk: 0, automation: true } }, 'automation'],
    [{ risk_threshold: 'high' }, { fp: { risk: 50 } }, 'risk'],
    [{ risk_threshold: 0 }, { fp: { risk: 50 } }, 'risk'],
  ];
  for (const [patch, req, reason] of cases) {
    const rc = await ctx(env, req);
    rc.policy = { ...rc.policy, ...patch };
    const g = await G.evaluateGate(rc);
    assert.deepEqual([g.allowed, g.reason], ['none', reason], JSON.stringify(patch) ?? String(patch));
  }
});

test('step 2 switches: block flags off let the visitor through; the threshold can be raised', async () => {
  const pass = [
    [{ block_tor: '0' }, { cf: { country: 'T1' } }],
    [{}, { cf: { asn: 16509 } }], // block_datacenter defaults off
    [{ block_automation: '0', risk_threshold: '100' }, { fp: { risk: 10, automation: true } }],
    [{ risk_threshold: '90' }, { fp: { risk: 80 } }],
  ];
  for (const [settings, req] of pass) {
    const env = await world({ settings: { access_mode: 'public', ...settings } });
    assert.equal((await G.evaluateGate(await ctx(env, req))).allowed, 'all', JSON.stringify(settings));
  }
});

test('gate risk is max(edge score, fingerprint cookie score) with reasons', async () => {
  const env = await world({ settings: { access_mode: 'public' } });
  const g = await G.evaluateGate(await ctx(env, { fp: { risk: 40 } }));
  assert.equal(g.risk.score, 40);
  assert.ok(g.risk.flags.some((f) => f.key === 'fingerprint' && /40/.test(f.reason)));
  const h = await G.evaluateGate(await ctx(env, { cf: { asn: 16509 }, fp: { risk: 5 } }));
  assert.equal(h.risk.score, 35);
  assert.deepEqual(h.risk.flags.map((f) => f.key), ['datacenter']);
});

// ---------------------------------------------------------------- step 3

test('step 3: with no accounts, the setup shell — in every mode, after the hard blocks and edge rules', async () => {
  for (const mode of G.MODES) {
    const env = await world({ users: false, settings: { access_mode: mode, device_gating: '1' } });
    const g = await G.evaluateGate(await ctx(env));
    assert.equal(decision(g), 'shell:setup', mode);
    assert.equal((await G.evaluateGate(await ctx(env, { device: BLOCKED }))).allowed, 'none');
    assert.equal((await G.evaluateGate(await ctx(env, { cf: { country: 'T1' } }))).reason, 'tor');
  }
  const env = await world({ users: false, settings: { access_mode: 'allowlist' } });
  assert.equal(decision(await G.evaluateGate(await ctx(env))), 'shell:setup');
  const role = env.DB.q("SELECT id FROM roles WHERE key = 'super_admin'")[0].id;
  env.DB.q("INSERT INTO users (email, role_id, created_at, updated_at) VALUES ('a@acme.com', ?, 'x', 'x')", role);
  assert.equal(decision(await G.evaluateGate(await ctx(env))), 'none', 'setup is gone once anyone exists');
  assert.equal(decision(await G.evaluateGate(await ctx(env, { ip: OFFICE_IP }))), 'all');
});

// ---------------------------------------------------------------- step 4 details

test('fingerprint_gate: a valid fingerprint cookie under the threshold → all; forged or expired → the login shell', async () => {
  const env = await world({ settings: { access_mode: 'fingerprint_gate' } });
  const t = env.__clock();
  assert.equal(decision(await G.evaluateGate(await ctx(env, { fp: { risk: 10 } }))), 'all');
  assert.equal((await G.evaluateGate(await ctx(env, { fp: { risk: 10 } }))).reason, 'fingerprint');
  assert.equal(decision(await G.evaluateGate(await ctx(env))), 'shell:login');
  const good = cookieValue(await fpCookie(env, 'a'.repeat(64), 10, t));
  const forged = [
    good.slice(0, good.lastIndexOf('.')),
    good.replace('.10.', '.0.'),
    await signToken(env, 'device', `${'a'.repeat(64)}.-.0.0.${t + HOUR}`),
    await signToken(env, 'pass', `${'a'.repeat(64)}.-.0.0.${t + HOUR}`),
  ];
  for (const f of [...forged, ...HOSTILE.filter((x) => typeof x === 'string')]) {
    assert.equal(decision(await G.evaluateGate(await ctx(env, { cookies: { [FP_COOKIE]: f } }))), 'shell:login', show(f));
  }
  assert.equal(decision(await G.evaluateGate(await ctx(env, { cookies: { [FP_COOKIE]: good }, at: t + 25 * HOUR }))), 'shell:login', 'expired');
});

test('forged or expired device and pass tokens never pass', async () => {
  const env = await world({ settings: { access_mode: 'allowlist' } });
  const t = env.__clock();
  const forgedDevices = [APPROVED, `${APPROVED}.${'A'.repeat(43)}`, await signToken(env, 'fp', APPROVED), await signToken(env, 'pass', APPROVED)];
  for (const v of forgedDevices) {
    const g = await G.evaluateGate(await ctx(env, { cookies: { [DEVICE_COOKIE]: v } }));
    assert.deepEqual([g.allowed, g.trusted], ['none', false], v);
  }
  const goodPass = cookieValue(await G.passCookie(env, t));
  const forgedPasses = [
    goodPass.slice(0, goodPass.lastIndexOf('.')),
    await signToken(env, 'device', `invite.${t + MINUTE}`),
    await signToken(env, 'pass', `invite.${t + 365 * 24 * HOUR}`),
    await signToken(env, 'pass', `invited.${t + MINUTE}`),
    await signToken(env, 'pass', 'invite.42'),
  ];
  for (const v of [...forgedPasses, ...HOSTILE.filter((x) => typeof x === 'string')]) {
    assert.equal(decision(await G.evaluateGate(await ctx(env, { cookies: { [G.PASS_COOKIE]: v } }))), 'none', show(v));
  }
  assert.equal(decision(await G.evaluateGate(await ctx(env, { cookies: { [G.PASS_COOKIE]: goodPass } }))), 'shell:invite');
  assert.equal(decision(await G.evaluateGate(await ctx(env, { cookies: { [G.PASS_COOKIE]: goodPass }, at: t + 15 * MINUTE }))), 'none', 'a pass lasts 15 minutes');
});

test('passCookie / readPass: signed, 15 minutes, Lax __Host-', async () => {
  const env = await makeEnvWithSchema();
  const t = env.__clock();
  const sc = await G.passCookie(env, t);
  assert.match(sc, /^__Host-pass=/);
  assert.match(sc, /Max-Age=900/);
  assert.match(sc, /SameSite=Lax/);
  const rc = (v, at = t) => ({ env, nowMs: at, cookies: { [G.PASS_COOKIE]: v } });
  assert.equal(await G.readPass(rc(cookieValue(sc))), true);
  assert.equal(await G.readPass(rc(cookieValue(sc), t + 15 * MINUTE - 1)), true);
  assert.equal(await G.readPass(rc(cookieValue(sc), t + 15 * MINUTE)), false);
  for (const v of HOSTILE) {
    assert.equal(await G.readPass(rc(v)), false, show(v));
    assert.equal(await G.readPass(v), false, show(v));
  }
});

// ---------------------------------------------------------------- robustness

test('evaluateGate never throws: hostile contexts are refused', async () => {
  for (const v of HOSTILE) {
    const g = await G.evaluateGate(v);
    assert.equal(g.allowed, 'none', show(v));
    assert.equal(g.mode, 'lockdown', 'no policy is the restrictive policy');
  }
  const env = await world({ settings: { access_mode: 'public' } });
  const rc = await ctx(env);
  env.DB.failOn = /FROM users/;
  const broken = await G.evaluateGate(rc);
  assert.deepEqual([broken.allowed, broken.reason], ['none', 'error'], 'a database failure is a refusal');
  env.DB.failOn = null;
  assert.equal((await G.evaluateGate(rc)).allowed, 'all');
  for (const field of ['policy', 'edge', 'fp', 'device', 'ipTier', 'cookies', 'cf', 'request', 'nowMs']) {
    for (const v of HOSTILE) {
      const r = await ctx(env, { ip: OFFICE_IP, device: APPROVED });
      r[field] = v;
      const g = await G.evaluateGate(r);
      assert.ok(['all', 'shell', 'none'].includes(g.allowed), `${field}=${show(v)}`);
    }
  }
});

test('a policy object holding an unknown mode is read as lockdown by the gate itself', async () => {
  const env = await world({ settings: { access_mode: 'public' } });
  for (const mode of ['weird', '', null, undefined, 'PUBLIC', ['public'], 7]) {
    const rc = await ctx(env, { device: APPROVED });
    rc.policy = { ...rc.policy, access_mode: mode };
    const g = await G.evaluateGate(rc);
    assert.deepEqual([g.mode, g.allowed, g.reason], ['lockdown', 'none', 'lockdown'], show(mode));
  }
});

test('a missing policy object is the restrictive policy: lockdown, nobody from outside', async () => {
  const env = await world({ settings: { access_mode: 'public' } });
  const rc = await ctx(env, { ip: OFFICE_IP, device: APPROVED });
  rc.policy = undefined;
  const g = await G.evaluateGate(rc);
  assert.equal(g.mode, 'lockdown');
  assert.equal(g.allowed, 'all', 'allowlisted address + approved device is the one way into lockdown');
  const s = await ctx(env, { device: APPROVED });
  s.policy = null;
  assert.equal((await G.evaluateGate(s)).allowed, 'none');
});

// ---------------------------------------------------------------- shells

test('shellAllows: exactly the CONTRACTS §7.8 table', () => {
  const common = ['/healthz', '/css/app.css', '/js/common.js', '/favicon.svg'];
  const table = {
    setup: ['GET /', 'GET /setup', 'GET /js/setup.js', 'GET /api/setup/status', 'POST /api/setup'],
    request: ['GET /', 'GET /request-access', 'GET /js/request.js', 'GET /js/fp.js', 'POST /api/access-request', 'POST /api/fp'],
    login: [
      'GET /', 'GET /login', 'GET /js/login.js', 'GET /js/fp.js', 'GET /js/webauthn.js', 'POST /api/fp', 'GET /api/auth/whoami',
      'POST /api/auth/login', 'POST /api/auth/mfa/code', 'POST /api/auth/mfa/send', 'POST /api/auth/mfa/otp',
      'POST /api/auth/mfa/passkey/options', 'POST /api/auth/mfa/passkey/verify',
      'GET /invite', 'GET /js/invite.js', 'POST /api/invite/lookup', 'POST /api/invite/accept',
    ],
    invite: ['GET /invite', 'GET /js/invite.js', 'GET /js/fp.js', 'POST /api/invite/lookup', 'POST /api/invite/accept', 'POST /api/fp'],
    pending: ['GET /pending', 'GET /js/pending.js', 'GET /api/device/status', 'GET /api/diag'],
  };
  const everything = new Set(Object.values(table).flat());
  for (const [shell, allowed] of Object.entries(table)) {
    for (const p of common) assert.equal(G.shellAllows(shell, 'GET', p), true, `${shell} ${p}`);
    for (const entry of allowed) {
      const [m, p] = entry.split(' ');
      assert.equal(G.shellAllows(shell, m, p), true, `${shell} ${entry}`);
      assert.equal(G.shellAllows(shell, m.toLowerCase(), p), true);
    }
    for (const entry of everything) {
      if (allowed.includes(entry)) continue;
      const [m, p] = entry.split(' ');
      assert.equal(G.shellAllows(shell, m, p), false, `${shell} must not allow ${entry}`);
    }
    for (const entry of ['GET /api/me', 'POST /api/auth/login', 'GET /admin', 'GET /js/admin.js', 'DELETE /api/fp', 'GET /api/fp', 'POST /setup', 'GET /setup/', 'GET /pending?x=1']) {
      if (allowed.includes(entry)) continue;
      const [m, p] = entry.split(' ');
      assert.equal(G.shellAllows(shell, m, p), false, `${shell} ${entry}`);
    }
  }
  assert.equal(G.shellAllows('setup', 'HEAD', '/setup'), true);
  assert.equal(G.shellAllows('invite', 'GET', '/api/invite/Abc_-123xyz'), false, 'the token never travels in a path');
  assert.equal(G.shellAllows('invite', 'GET', '/api/invite/a/b'), false);
  assert.equal(G.shellAllows('invite', 'POST', '/api/invite/abc'), false);
  assert.equal(G.shellAllows('invite', 'GET', '/api/invite/'), false);
  assert.equal(G.shellAllows('pending', 'GET', '/api/invite/abc'), false);
  for (const v of HOSTILE) {
    assert.equal(G.shellAllows(v, 'GET', '/healthz'), false, show(v));
    assert.equal(G.shellAllows('setup', v, '/setup'), false, show(v));
    assert.equal(G.shellAllows('setup', 'GET', v), false, show(v));
  }
  assert.equal(G.shellAllows('__proto__', 'GET', '/healthz'), false);
  assert.equal(G.shellAllows('toString', 'GET', '/healthz'), false);
});

test('denyResponse: an empty 403 by default; decoy is a stock nginx 404', async () => {
  const empty = G.denyResponse({ deny_style: 'empty' });
  assert.equal(empty.status, 403);
  assert.equal(await empty.text(), '');
  assert.equal(empty.body, null);
  const decoy = G.denyResponse({ deny_style: 'decoy' });
  assert.equal(decoy.status, 404);
  assert.equal(decoy.headers.get('content-type'), 'text/html');
  assert.equal(await decoy.text(), '<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx</center></body></html>');
  for (const v of [...HOSTILE, { deny_style: 'DECOY' }, { deny_style: ['decoy'] }]) {
    const r = G.denyResponse(v);
    assert.equal(r.status, 403, show(v));
    assert.equal(r.body, null);
  }
});

await run();
