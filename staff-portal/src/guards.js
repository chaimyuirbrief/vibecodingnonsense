// Self-lockout guards (CONTRACTS §8.5, B trap 8, A §4–5). One module, called
// by the settings and network endpoints AND by the reverters, so undoing an
// "add" can never do what a "remove" may not (SPEC §12).
//
// Three answers to a change: BLOCKING (409 self_lockout, nothing written),
// AUTO-APPROVE (the change goes ahead and approves the caller's device), and
// WARNINGS (saved, with a sentence about other people's next sign-in).
//
// An allowlisted address legitimately bypasses the edge rules (B trap 8), so
// the country/Tor/datacenter/automation/risk guards stand aside for it — the
// gate would let that caller in whatever those settings say.

import { GuardError, ValidationError } from './errors.js';
import { now, iso, toInt, parseIsoStrict, DAY } from './util.js';
import { effectivePermissions, assertCanActOn } from './rbac.js';
import { actorAuthz } from './users.js';
import { SETTINGS, resolvePolicy } from './policy.js';
import { normalizeIp, cidrContains } from './ip.js';
import {
  tierForIp, isIpBlocked, coveringEntries, liveCount, allowLive, entryTier, listAllowed, validateExpiry, validateTier, TIER4_DEFAULT_MS,
} from './network.js';
import { isDatacenterAsn, automationTells, scoreRisk } from './fingerprint.js';
import { evaluateGate } from './gate.js';
import { ensureDevice, setDeviceStatus, deviceState } from './devices.js';
import { usableKinds } from './notify.js';

const RESTRICTIVE_MODES = Object.freeze(['allowlist', 'invite_only', 'lockdown']);
// The settings that decide whether a request reaches the portal at all.
const ACCESS_KEYS = Object.freeze([
  'access_mode', 'country_allow', 'country_deny', 'block_tor', 'block_datacenter', 'block_automation', 'risk_threshold', 'device_gating',
]);

function finite(n) {
  return typeof n === 'number' && Number.isFinite(n);
}

function nowOf(rc) {
  return finite(rc?.nowMs) ? rc.nowMs : now(rc?.env);
}

export function lockout(message) {
  return new GuardError('self_lockout', message, 409);
}

// The caller's address, or a refusal: a guard that cannot tell where you are
// cannot promise you will still get in (CONTRACTS §0.2).
function callerIp(rc) {
  const ip = normalizeIp(rc?.ip);
  if (!ip) throw lockout('Couldn’t tell which address you’re using, so nothing was changed.');
  return ip;
}

// ---------------------------------------------------------------- network

// Removing it must leave the caller's address covered by another LIVE entry
// (A §4: "add your new address first"). An entry that does not cover the
// caller changes nothing for them.
async function assertKeepsCover(rc, row, doing) {
  const ip = callerIp(rc);
  if (!cidrContains(row.cidr, ip)) return;
  const others = await coveringEntries(rc.env, ip, nowOf(rc), { excludeId: row.id });
  if (!others.length) {
    throw lockout(`${row.cidr} is the only live allowlist entry covering your address (${ip}). ${doing} it would lock you out — add your new address first.`);
  }
}

// DELETE …/allow/:id and the reverter of 'network.allow.add'.
export async function assertCanRemoveAllowed(rc, row) {
  const t = nowOf(rc);
  // An expired entry grants nothing, so removing one changes nobody's access;
  // counting it as cover is exactly the bug A §4 warns about.
  if (!allowLive(row, t)) return;
  if ((await liveCount(rc.env, t, { excludeId: row.id })) === 0) {
    throw lockout('That is the last live allowlist entry. An empty allowlist locks everyone out, including you — add another entry first.');
  }
  await assertKeepsCover(rc, row, 'Removing');
}

// The expiry an edit would leave (ms | null), with editAllowed's rules:
// an explicit null clears it, tier 4 always gets one.
function projectedExpiry(row, patch, t) {
  let exp;
  if (patch.expires_at !== undefined || patch.expires_in_hours !== undefined) exp = validateExpiry(patch, t);
  else if (row.expires_at === null || row.expires_at === undefined) exp = null;
  else exp = parseIsoStrict(row.expires_at);
  const tier = patch.tier !== undefined ? validateTier(patch.tier) : entryTier(row);
  if (tier === 4 && exp === null) exp = t + TIER4_DEFAULT_MS;
  return exp;
}

// PATCH …/allow/:id and the reverter of 'network.allow.edit'. Giving the
// caller's only cover an expiry (or an earlier one) is a removal on a timer.
export async function assertCanEditAllowed(rc, row, patch) {
  const t = nowOf(rc);
  if (!allowLive(row, t)) return;
  const p = patch && typeof patch === 'object' ? patch : {};
  const next = projectedExpiry(row, p, t);
  const prior = row.expires_at === null || row.expires_at === undefined ? null : parseIsoStrict(row.expires_at);
  const shortens = next !== null && (prior === null || !(next >= prior));
  if (!shortens) return;
  if ((await liveCount(rc.env, t, { excludeId: row.id })) === 0) {
    throw lockout('That is the last live allowlist entry; letting it expire would lock everyone out, including you. Add another entry first.');
  }
  await assertKeepsCover(rc, row, 'Letting it expire');
}

// How long an address someone signed in from counts as theirs for the
// block guard below.
const SEEN_RECENTLY_MS = 30 * DAY;

// POST …/block and the reverter of 'network.block.remove'.
//
// A block refuses everyone inside it at the gate's first step, sessions and
// approved devices notwithstanding — so it is an action on each of them, not
// only on the caller. Like ending their sessions, it needs every active
// account seen inside the range lately (a live session, or a device it signed
// in on) to rank below the caller; Super Admins are peers (SPEC §5.5, §12:
// "a way to lock yourself — or the owner — out").
export async function assertCanBlock(rc, cidr) {
  const ip = callerIp(rc);
  if (cidrContains(cidr, ip)) {
    throw lockout(`${cidr} contains your own address (${ip}). Blocking it would refuse you at once.`);
  }
  const env = rc.env;
  const t = nowOf(rc);
  const since = iso(t - SEEN_RECENTLY_MS);
  const { results } = await env.DB.prepare(
    `SELECT u.id, u.role_id, u.perm_grants, u.perm_denies, u.status, s.ip AS seen_ip
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.revoked_at IS NULL AND s.idle_expires_at > ? AND u.status = 'active'
     UNION
     SELECT u.id, u.role_id, u.perm_grants, u.perm_denies, u.status, d.last_ip AS seen_ip
       FROM device_users du JOIN users u ON u.id = du.user_id JOIN devices d ON d.id = du.device_id
      WHERE du.last_seen >= ? AND u.status = 'active'`,
  )
    .bind(iso(t), since)
    .all();
  const inside = new Map();
  for (const r of results || []) if (typeof r.seen_ip === 'string' && cidrContains(cidr, r.seen_ip)) inside.set(r.id, r);
  if (!inside.size) return;
  const actor = await actorAuthz(rc);
  for (const u of inside.values()) {
    try {
      assertCanActOn(actor, await effectivePermissions(env, u, t), { allowSelf: true });
    } catch (e) {
      if (!(e instanceof GuardError)) throw e;
      throw new GuardError('rank', `Someone ranked at or above you signs in from inside ${cidr}, so only they or someone above them can block it.`);
    }
  }
}

// ---------------------------------------------------------------- settings

function callerRisk(rc) {
  const s = rc?.gate?.risk?.score;
  if (finite(s)) return s;
  const edge = scoreRisk(rc?.edge && typeof rc.edge === 'object' ? rc.edge : {}, null).score;
  const fp = toInt(rc?.fp?.risk, 0, 100);
  return Math.max(edge, Number.isFinite(fp) ? fp : 0);
}

function countryRefusal(policy, country) {
  const allow = policy.country_allow;
  if (allow !== null) {
    const list = Array.isArray(allow) ? allow : [];
    if (!country || !list.includes(country)) return true;
  }
  const deny = Array.isArray(policy.country_deny) ? policy.country_deny : ['*'];
  return deny.includes('*') || (!!country && deny.includes(country));
}

async function countNoApprovedDevice(env, exceptId) {
  const { results } = await env.DB.prepare(
    `SELECT u.id, (SELECT s.ip FROM sessions s WHERE s.user_id = u.id ORDER BY s.created_at DESC LIMIT 1) AS ip
     FROM users u WHERE u.status = 'active' AND u.id IS NOT ? AND NOT EXISTS (
       SELECT 1 FROM device_users du JOIN devices d ON d.id = du.device_id WHERE du.user_id = u.id AND d.status = 'approved')`,
  )
    .bind(exceptId)
    .all();
  return results || [];
}

async function warningsFor(rc, current, next, has) {
  const env = rc.env;
  const t = nowOf(rc);
  const self = toInt(rc?.user?.id, 1);
  const me = Number.isFinite(self) ? self : null;
  const out = [];
  const people = (n) => (n === 1 ? '1 active person' : `${n} active people`);
  const gatingOn = has('device_gating') && next.device_gating !== false && current.device_gating === false;
  const mode = has('access_mode') && next.access_mode !== current.access_mode ? next.access_mode : null;
  if (gatingOn || mode === 'invite_only') {
    const n = (await countNoApprovedDevice(env, me)).length;
    if (n) out.push(`${people(n)} ${n === 1 ? 'has' : 'have'} no approved device and will wait for approval at their next sign-in.`);
  } else if (mode === 'allowlist') {
    const live = (await listAllowed(env, t)).filter((r) => r.active);
    const n = (await countNoApprovedDevice(env, me)).filter((u) => !live.some((r) => cidrContains(r.cidr, u.ip))).length;
    if (n) out.push(`${people(n)} ${n === 1 ? 'has' : 'have'} neither an approved device nor an allowlisted address, so the portal will refuse them.`);
  }
  if (mode === 'lockdown') {
    const n = toInt(
      await env.DB.prepare(
        `SELECT COUNT(*) AS n FROM users u JOIN roles r ON r.id = u.role_id
         WHERE u.status = 'active' AND r.key != 'super_admin' AND NOT EXISTS (
           SELECT 1 FROM user_roles ur JOIN roles x ON x.id = ur.role_id WHERE ur.user_id = u.id AND x.key = 'super_admin')`,
      ).first('n'),
      0,
    );
    if (n) out.push(`${people(n)} who ${n === 1 ? 'isn’t a Super Admin is' : 'aren’t Super Admins are'} signed out and refused until lockdown ends.`);
  }
  if (has('mfa_policy') && next.mfa_policy === 'required' && current.mfa_policy !== 'required') {
    const kinds = usableKinds(env);
    const n = toInt(
      await env.DB.prepare(
        `SELECT COUNT(*) AS n FROM users u WHERE u.status = 'active'
           AND NOT EXISTS (SELECT 1 FROM user_totp WHERE user_id = u.id AND confirmed_at IS NOT NULL)
           AND NOT EXISTS (SELECT 1 FROM user_passkeys WHERE user_id = u.id)
           ${kinds.length ? `AND NOT EXISTS (SELECT 1 FROM code_destinations WHERE user_id = u.id AND kind IN (${kinds.map(() => '?').join(', ')}))` : ''}`,
      )
        .bind(...kinds)
        .first('n'),
      0,
    );
    if (n) out.push(`${people(n)} ${n === 1 ? 'has' : 'have'} no second factor and will be held on the enrolment page at their next sign-in.`);
  }
  return out;
}

// raws: { key: string (validated, as it will be stored) | null (back to the
// default) }. → { approve, warnings, notices }. Throws 409 self_lockout.
// Called by PUT /api/admin/settings and by the 'setting' reverter.
export async function checkSettings(rc, raws) {
  const env = rc.env;
  const t = nowOf(rc);
  const keys = Object.keys(raws || {});
  for (const k of keys) {
    if (!Object.hasOwn(SETTINGS, k) || k === 'gate_open') throw new ValidationError('Unknown setting.', k);
  }
  const current = rc.policy && typeof rc.policy === 'object' ? rc.policy : await resolvePolicy(env);
  const next = { ...current };
  for (const k of keys) next[k] = SETTINGS[k].parse(raws[k], t);
  const has = (k) => keys.includes(k);
  if (!keys.some((k) => ACCESS_KEYS.includes(k))) return { approve: false, warnings: await warningsFor(rc, current, next, has), notices: [] };

  const ip = callerIp(rc);
  const tier = await tierForIp(env, ip, t);
  const allowlisted = tier !== null;
  const edge = rc.edge && typeof rc.edge === 'object' ? rc.edge : {};
  const country = typeof edge.country === 'string' ? edge.country : null;

  if (!allowlisted) {
    if ((has('country_allow') || has('country_deny')) && countryRefusal(next, country)) {
      throw lockout(`That would refuse visitors from your own country (${country || 'unknown'}), and your address isn’t allowlisted. Allowlist your address first.`);
    }
    if (has('block_tor') && next.block_tor !== false && country === 'T1') {
      throw lockout('You are connected through Tor, so blocking Tor would refuse you. Allowlist your address first.');
    }
    if (has('block_datacenter') && next.block_datacenter !== false && isDatacenterAsn(edge.asn)) {
      throw lockout(`Your address belongs to a hosting provider (AS${edge.asn}), so blocking datacenters would refuse you. Allowlist your address first.`);
    }
    if (has('block_automation') && next.block_automation !== false && (automationTells(edge, null).length > 0 || rc.fp?.automation === true)) {
      throw lockout('Your browser shows signs of automation, so blocking automation would refuse you. Allowlist your address first.');
    }
    if (has('risk_threshold')) {
      const score = callerRisk(rc);
      if (next.risk_threshold <= score) {
        throw lockout(`Your own risk score is ${score}; a threshold of ${next.risk_threshold} would refuse you. Choose a number above ${score}, or allowlist your address first.`);
      }
    }
  }
  if (has('access_mode') && next.access_mode === 'lockdown' && current.access_mode !== 'lockdown' && !(rc.authz?.isSuper === true && allowlisted)) {
    throw lockout('Lockdown admits only a Super Admin on an allowlisted address with an approved device. Switch to it from there.');
  }

  // A §5: turning gating on (or a restrictive mode) approves the device doing
  // the turning rather than refusing the change.
  const gatingOn = has('device_gating') && next.device_gating !== false && current.device_gating === false;
  const restrictive = has('access_mode') && next.access_mode !== current.access_mode && RESTRICTIVE_MODES.includes(next.access_mode);
  const dstate = deviceState(rc.device?.row);
  if (dstate === 'blocked') throw lockout('The device you are using is blocked.');
  const approve = (gatingOn || restrictive) && dstate !== 'approved';

  // The catch-all: the gate itself, asked about this caller under the new
  // settings. Whatever the rules above missed, a change the gate would
  // refuse you under is refused here.
  const sim = await evaluateGate({
    env,
    nowMs: t,
    ip,
    edge,
    fp: rc.fp ?? null,
    cookies: rc.cookies || {},
    policy: next,
    device: approve ? { id: rc.device?.id ?? null, row: { ...(rc.device?.row || {}), status: 'approved' } } : rc.device || { id: null, row: null },
    ipTier: tier ? tier.tier : null,
    ipBlocked: await isIpBlocked(env, ip, t),
  });
  if (sim.allowed !== 'all') {
    throw lockout(`With that change the portal would refuse you (${sim.reason.replace(/_/g, ' ')}). Nothing was changed.`);
  }
  const notices = approve ? ['This device was approved so the change does not lock you out of it.'] : [];
  return { approve, warnings: await warningsFor(rc, current, next, has), notices };
}

// The auto-approve half (A §5, SPEC §8.4): mints the caller a device if it
// has none. → { prior, row } when it approved something, else null.
export async function approveCallerDevice(rc) {
  const d = await ensureDevice(rc);
  if (d.setCookie && Array.isArray(rc.setCookies)) rc.setCookies.push(d.setCookie);
  const state = deviceState(d.row);
  if (state === 'approved') return null;
  if (state === 'blocked') throw lockout('The device you are using is blocked.');
  const res = await setDeviceStatus(rc, d.id, 'approved', {});
  rc.device = { id: d.id, row: res.row };
  return res;
}
