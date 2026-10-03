// The access decision for every request (CONTRACTS §7.8, SPEC §3, A §2,
// B §6). Each step fully decides before the next one runs:
//
//   1. hard blocks — blocked device, no usable address, blocklisted address
//   2. edge rules — country, Tor, datacenter, automation, risk — skipped for
//      an allowlisted address (B trap 8: the allowlist is an administrator's
//      explicit statement about a network; the rest are heuristics)
//   3. no accounts yet → the setup shell
//   4. the access mode
//   5. device gating → the pending shell
//
// Every unreadable input resolves to the restrictive reading: no policy is
// the restrictive policy, an unknown mode is lockdown, a blocklist answer
// that is not exactly `false` is "blocked", and any exception is 'none'.

import { cookie, now, toInt, MINUTE } from './util.js';
import { signToken, verifyToken } from './crypto.js';
import { normalizeIp } from './ip.js';
import { restrictivePolicy } from './policy.js';
import { readDevice, deviceState } from './devices.js';
import { tierForIp, isIpBlocked } from './network.js';
import { edgeSignals, scoreRisk, automationTells, isDatacenterAsn, readFpCookie } from './fingerprint.js';

export const MODES = Object.freeze(['public', 'fingerprint_gate', 'request_access', 'allowlist', 'invite_only', 'lockdown']);
export const PASS_COOKIE = '__Host-pass';
export const PASS_TTL_MS = 15 * MINUTE;

// The page each shell shows a navigation outside its list (SPEC §3.3).
export const SHELL_PAGES = Object.freeze({
  setup: '/setup',
  request: '/request-access',
  login: '/login',
  invite: '/invite',
  pending: '/pending',
});

// Assets go through the worker, so a shell names every script its page
// loads; leave one out and the page silently fails to load it.
const COMMON = ['GET /healthz', 'GET /css/app.css', 'GET /js/common.js', 'GET /favicon.svg'];
const SHELLS = Object.freeze({
  setup: new Set([...COMMON, 'GET /', 'GET /setup', 'GET /js/setup.js', 'GET /api/setup/status', 'POST /api/setup']),
  request: new Set([...COMMON, 'GET /', 'GET /request-access', 'GET /js/request.js', 'GET /js/fp.js', 'POST /api/access-request', 'POST /api/fp']),
  // The sign-in POSTs pass the shell so the login API can answer
  // 403 { fingerprint_required } itself; it refuses a stranger with no
  // fingerprint on file, so no MFA token can be had without one.
  login: new Set([
    ...COMMON, 'GET /', 'GET /login', 'GET /js/login.js', 'GET /js/fp.js', 'GET /js/webauthn.js',
    'POST /api/fp', 'GET /api/auth/whoami', 'POST /api/auth/login', 'POST /api/auth/mfa/code',
    'POST /api/auth/mfa/send', 'POST /api/auth/mfa/otp', 'POST /api/auth/mfa/passkey/options', 'POST /api/auth/mfa/passkey/verify',
  ]),
  invite: new Set([...COMMON, 'GET /invite', 'GET /js/invite.js', 'GET /js/fp.js', 'POST /api/invite/lookup', 'POST /api/invite/accept', 'POST /api/fp']),
  pending: new Set([...COMMON, 'GET /pending', 'GET /js/pending.js', 'GET /api/device/status', 'GET /api/diag']),
});
const INVITE_LOOKUP = /^\/api\/invite\/[A-Za-z0-9_-]{1,256}$/;

export const DECOY_404 =
  '<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx</center></body></html>';

function finite(n) {
  return typeof n === 'number' && Number.isFinite(n);
}

function nowOf(rc) {
  return finite(rc?.nowMs) ? rc.nowMs : now(rc?.env);
}

// ---------------------------------------------------------------- shells

export function shellAllows(shell, method, path) {
  if (typeof shell !== 'string' || !Object.hasOwn(SHELLS, shell)) return false;
  if (typeof method !== 'string' || typeof path !== 'string' || path.length > 512) return false;
  const m = method.toUpperCase() === 'HEAD' ? 'GET' : method.toUpperCase();
  if (SHELLS[shell].has(`${m} ${path}`)) return true;
  return shell === 'invite' && m === 'GET' && INVITE_LOOKUP.test(path);
}

// Zero-information either way (D2). The decoy imitates a stock server page
// so the portal does not advertise itself.
export function denyResponse(policy) {
  if (policy && typeof policy === 'object' && policy.deny_style === 'decoy') {
    return new Response(DECOY_404, { status: 404, headers: { 'content-type': 'text/html' } });
  }
  return new Response(null, { status: 403 });
}

// ---------------------------------------------------------------- pass

// Set by /invite when ?token= is valid: a short-lived, signed "holds an
// invitation link" that opens the invite shell (and nothing else).
export async function passCookie(env, nowMs) {
  const t = finite(nowMs) ? nowMs : now(env);
  return cookie(PASS_COOKIE, await signToken(env, 'pass', `invite.${t + PASS_TTL_MS}`), { maxAge: PASS_TTL_MS / 1000 });
}

export async function readPass(rc) {
  try {
    const raw = rc?.cookies?.[PASS_COOKIE];
    if (typeof raw !== 'string' || !raw) return false;
    const payload = await verifyToken(rc.env, 'pass', raw);
    const m = payload === null ? null : /^invite\.(\d{1,15})$/.exec(payload);
    if (!m) return false;
    const exp = toInt(m[1], 0);
    const t = nowOf(rc);
    return exp > t && exp <= t + PASS_TTL_MS + MINUTE;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------- helpers

// Users are never hard-deleted (D17), so once one exists the answer is
// cached for that database.
const usersSeen = new WeakMap();

async function usersExist(env) {
  const db = env.DB;
  if (usersSeen.get(db) === true) return true;
  const row = await db.prepare('SELECT 1 AS one FROM users LIMIT 1').first();
  if (row) usersSeen.set(db, true);
  return !!row;
}

// rc.ipTier is network.tierForIp's { tier, entry }; a bare number is read
// too. Anything else is "not allowlisted".
function tierOf(v) {
  const raw = v && typeof v === 'object' ? v.tier : v;
  const t = typeof raw === 'number' || typeof raw === 'string' ? toInt(raw, 1, 4) : NaN;
  return Number.isFinite(t) ? t : null;
}

function thresholdOf(policy) {
  const n = toInt(policy.risk_threshold, 1, 100);
  return Number.isFinite(n) ? n : 50;
}

// The gate_open switch, re-checked against this request's clock.
function gateIsOpen(policy, t) {
  const g = policy.gate_open;
  if (!g || typeof g !== 'object' || g.open !== true) return false;
  if (g.forever === true) return true;
  return finite(g.until) && g.until > t;
}

// Step 2. country_allow: null = no restriction, a list = only those (an
// unknown country is refused), anything else = nobody. country_deny: a list,
// '*' = everyone, anything else = everyone.
function edgeRefusal(policy, edge, fp, score) {
  const country = typeof edge.country === 'string' ? edge.country : null;
  const allow = policy.country_allow;
  if (allow !== null) {
    const list = Array.isArray(allow) ? allow : [];
    if (!country || !list.includes(country)) return 'country';
  }
  const deny = Array.isArray(policy.country_deny) ? policy.country_deny : ['*'];
  if (deny.includes('*') || (country && deny.includes(country))) return 'country';
  if (policy.block_tor !== false && country === 'T1') return 'tor';
  if (policy.block_datacenter !== false && isDatacenterAsn(edge.asn)) return 'datacenter';
  if (policy.block_automation !== false && (automationTells(edge, null).length > 0 || fp?.automation === true)) return 'automation';
  if (score >= thresholdOf(policy)) return 'risk';
  return null;
}

// ---------------------------------------------------------------- the gate

// → { allowed: 'all'|'shell'|'none', shell, reason, mode, trusted, ipTier,
//     risk: { score, flags } }. Reads rc.ip, rc.policy, rc.edge, rc.fp,
// rc.device, rc.ipTier, rc.ipBlocked, rc.cookies and rc.nowMs; any of the
// derived ones that buildContext has not set is computed here.
export async function evaluateGate(rc) {
  const policy = rc?.policy && typeof rc.policy === 'object' ? rc.policy : restrictivePolicy();
  const mode = MODES.includes(policy.access_mode) ? policy.access_mode : 'lockdown';
  let trusted = false;
  let ipTier = null;
  let risk = { score: 0, flags: [] };
  const out = (allowed, shell, reason) => ({ allowed, shell, reason, mode, trusted, ipTier, risk });
  try {
    const env = rc.env;
    const t = nowOf(rc);
    const edge = rc.edge && typeof rc.edge === 'object' ? rc.edge : rc.request ? edgeSignals(rc.request, rc.cf) : {};
    const fp = rc.fp !== undefined ? rc.fp : await readFpCookie(rc);
    const edgeRisk = scoreRisk(edge, null);
    const fpRisk = toInt(fp?.risk, 0, 100);
    const flags = [...edgeRisk.flags];
    if (Number.isFinite(fpRisk) && fpRisk > edgeRisk.score) {
      flags.push({ key: 'fingerprint', weight: fpRisk, reason: `This browser’s reported fingerprint scored ${fpRisk}.` });
    }
    risk = { score: Math.max(edgeRisk.score, Number.isFinite(fpRisk) ? fpRisk : 0), flags };

    // 1. Hard blocks lose in every mode, allowlisted or not.
    const device = rc.device !== undefined ? rc.device : await readDevice(rc);
    const dstate = deviceState(device?.row);
    if (dstate === 'blocked') return out('none', null, 'device_blocked');
    const ip = normalizeIp(rc.ip);
    if (!ip) return out('none', null, 'no_ip');
    const blocked = rc.ipBlocked !== undefined ? rc.ipBlocked : await isIpBlocked(env, ip, t);
    if (blocked !== false) return out('none', null, 'ip_blocked');

    // 2. Edge rules, unless allowlisted.
    ipTier = tierOf(rc.ipTier !== undefined ? rc.ipTier : await tierForIp(env, ip, t));
    const allowlisted = ipTier !== null;
    if (!allowlisted) {
      const why = edgeRefusal(policy, edge, fp, risk.score);
      if (why) return out('none', null, why);
    }

    // 3. Nothing later can succeed without an account.
    if (!(await usersExist(env))) return out('shell', 'setup', 'setup');

    // 4. The mode. gate_open never applies in lockdown.
    const approved = dstate === 'approved';
    trusted = allowlisted || approved;
    const open = mode !== 'lockdown' && gateIsOpen(policy, t);
    const pass = await readPass(rc);
    const trustedWhy = allowlisted ? 'allowlisted' : 'device';
    let res;
    if (mode === 'lockdown') {
      res = allowlisted && approved ? out('all', null, 'lockdown_trusted') : out('none', null, 'lockdown');
    } else if (mode === 'allowlist') {
      if (trusted) res = out('all', null, trustedWhy);
      else if (open) res = out('all', null, 'open');
      else if (pass) res = out('shell', 'invite', 'invite');
      else res = out('none', null, 'not_allowlisted');
    } else if (mode === 'invite_only') {
      // The network alone admits nobody: you were invited (accepting approves
      // the device) or a device was approved for you. An unknown device on an
      // allowlisted network may queue for approval but never sees sign-in.
      if (approved) res = out('all', null, 'device');
      else if (open) res = out('all', null, 'open');
      else if (pass) res = out('shell', 'invite', 'invite');
      else if (allowlisted) res = out('shell', 'pending', 'not_invited_pending');
      else res = out('none', null, 'not_invited');
    } else if (mode === 'request_access') {
      if (trusted) res = out('all', null, trustedWhy);
      else if (open) res = out('all', null, 'open');
      else if (pass) res = out('shell', 'invite', 'invite');
      else res = out('shell', 'request', 'request_access');
    } else if (mode === 'fingerprint_gate') {
      if (trusted) res = out('all', null, trustedWhy);
      else if (fp && finite(fp.risk) && fp.risk < thresholdOf(policy)) res = out('all', null, 'fingerprint');
      else res = out('shell', 'login', 'fingerprint_required');
    } else {
      res = out('all', null, 'public');
    }
    if (res.allowed === 'none') return res;

    // 5. Device gating covers the API too, so an unapproved device cannot
    // call the endpoint that would approve it (A §2). Accepting an
    // invitation approves the device, so a pass holder gets the invite shell.
    if (policy.device_gating !== false && !approved) {
      return pass ? out('shell', 'invite', 'device_pending_invite') : out('shell', 'pending', 'device_pending');
    }
    return res;
  } catch {
    return out('none', null, 'error');
  }
}
