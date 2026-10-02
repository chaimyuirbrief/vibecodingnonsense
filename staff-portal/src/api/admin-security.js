// Settings, the gate switch, the network lists and the visitor log
// (CONTRACTS §8.4 "Admin (security)", §5, §8.5; A §4; B §6, trap 8).
//
// Every write runs the self-lockout guards in guards.js — the same functions
// the reverters call — BEFORE anything is stored, and writes the audit row
// with the undo snapshot itself (CONTRACTS §4.2).

import { json, readJson, iso, toInt, str, safeJsonParse, HOUR } from '../util.js';
import { HttpError, GuardError, ValidationError, forbidden } from '../errors.js';
import { can, requireStepUp } from '../rbac.js';
import { audit, auditError } from '../audit.js';
import { undoFor } from '../undo.js';
import { SETTINGS, SETTING_KEYS, getSettingRaw, writeSetting, gateOpenState } from '../policy.js';
import {
  tierForIp, listAllowed, listBlocked, addAllowed, editAllowed, removeAllowed, addBlocked, removeBlocked, validateCidr,
} from '../network.js';
import { checkSettings, approveCallerDevice, assertCanRemoveAllowed, assertCanEditAllowed, assertCanBlock } from '../guards.js';

const GATE_MAX_HOURS = 168;
const SETTINGS_PERMS = Object.freeze(['settings.manage', 'security.manage']);
const DECISIONS = Object.freeze({ allow: 'all', all: 'all', shell: 'shell', deny: 'none', none: 'none' });
const DECISION_OUT = Object.freeze({ all: 'allow', shell: 'shell', none: 'deny' });

async function body(rc) {
  return (await readJson(rc.request)) || {};
}

function isPlainObject(v) {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

// Guard refusals are recorded as 'denied'; anything unexpected as the real
// error at critical severity, then one polite sentence (B trap 2).
async function writing(rc, action, target, fn) {
  try {
    return await fn();
  } catch (e) {
    if (e instanceof GuardError) {
      await audit(rc, { action, outcome: 'denied', target, detail: `Refused: ${e.message}` });
      throw e;
    }
    if (e instanceof HttpError) throw e;
    await auditError(rc, action, e, { target });
    throw new HttpError(500, { error: 'That couldn’t be saved. The details are in the audit log.' });
  }
}

// ---------------------------------------------------------------- settings

function settingValue(key, raw, nowMs) {
  const v = SETTINGS[key].parse(raw, nowMs);
  if (key !== 'gate_open') return v;
  return { open: v.open, until: v.until === null ? null : iso(v.until), forever: v.forever, raw: v.raw };
}

async function storedRaws(env) {
  const { results } = await env.DB.prepare('SELECT key, value FROM settings').all();
  const out = new Map();
  // A present non-string is unreadable, not absent: '' parses as unrecognised.
  for (const r of results || []) if (Object.hasOwn(SETTINGS, r.key)) out.set(r.key, typeof r.value === 'string' ? r.value : '');
  return out;
}

async function getSettings(rc) {
  const raws = await storedRaws(rc.env);
  const settings = SETTING_KEYS.map((key) => {
    const s = SETTINGS[key];
    const raw = raws.has(key) ? raws.get(key) : null;
    return {
      key,
      label: s.label,
      value: settingValue(key, raw, rc.nowMs),
      raw,
      default: key === 'gate_open' ? settingValue(key, null, rc.nowMs) : s.default,
      perm: s.perm,
      type: s.type,
      options: s.options ?? null,
      min: s.min ?? null,
      max: s.max ?? null,
      description: s.description,
      // The gate switch has its own endpoints (CONTRACTS §5).
      can_edit: key !== 'gate_open' && can(rc.authz, s.perm),
    };
  });
  return json(200, { settings });
}

// { changes: { key: value } } → { ok, applied, warnings, notices }. All or
// nothing: every key is permission-checked and validated, then the guards run
// on the combined result, and only then is anything written.
async function putSettings(rc) {
  if (!SETTINGS_PERMS.some((p) => can(rc.authz, p))) throw forbidden();
  const b = await body(rc);
  const changes = b.changes;
  if (!isPlainObject(changes) || !Object.keys(changes).length) throw new ValidationError('Nothing to change.', 'changes');
  const keys = Object.keys(changes);
  for (const k of keys) {
    if (k === 'gate_open') throw new ValidationError('Opening to the internet is changed only from the gate controls.', k);
    if (!Object.hasOwn(SETTINGS, k)) throw new ValidationError(`Unknown setting “${str(k, 64)}”.`, 'changes');
  }
  for (const k of keys) {
    if (!can(rc.authz, SETTINGS[k].perm)) throw forbidden(`Changing ${SETTINGS[k].label.toLowerCase()} needs the ${SETTINGS[k].perm} permission.`);
  }
  requireStepUp(rc);
  // A §14.1: blanks, null, objects are validation errors here — serialize
  // throws before a single row is written.
  const raws = {};
  for (const k of keys) raws[k] = SETTINGS[k].serialize(changes[k]);
  const priors = {};
  for (const k of keys) priors[k] = await getSettingRaw(rc.env, k);
  const changed = keys.filter((k) => raws[k] !== priors[k]);
  if (!changed.length) return json(200, { ok: true, applied: [], warnings: [], notices: ['Nothing changed.'] });
  const proposed = Object.fromEntries(changed.map((k) => [k, raws[k]]));

  return writing(rc, 'setting.change', { type: 'setting', id: changed.join(',') }, async () => {
    const g = await checkSettings(rc, proposed);
    if (g.approve) {
      const a = await approveCallerDevice(rc);
      if (a) {
        await audit(rc, {
          action: 'device.approve',
          target: { type: 'device', id: a.row.id },
          detail: `Approved the device making a gating change (${a.row.label || 'unnamed'}) so it would not lock itself out`,
          before: { status: a.prior.status },
          after: { status: a.row.status },
          undo: undoFor('device.status', { deviceId: a.row.id, status: a.prior.status }),
        });
      }
    }
    for (const k of changed) {
      const w = await writeSetting(rc, k, changes[k]);
      // `value`, never the key itself, in before/after: the scrubber drops
      // keys like session_idle_minutes (/session/).
      await audit(rc, {
        action: 'setting.change',
        target: { type: 'setting', id: k },
        severity: SETTINGS[k].perm === 'security.manage' ? 'notice' : 'info',
        detail: `Changed ${k} from ${w.prior === null ? 'the default' : str(w.prior, 120)} to ${str(w.raw, 120)}`,
        before: { value: w.prior },
        after: { value: w.raw },
        undo: undoFor('setting', { key: k, prior: w.prior }),
      });
    }
    return json(200, { ok: true, applied: changed, warnings: g.warnings, notices: g.notices });
  });
}

// ---------------------------------------------------------------- the gate

function gateView(rc, raw) {
  const s = gateOpenState(raw, rc.nowMs);
  return {
    open: s.open,
    until: s.until === null ? null : iso(s.until),
    forever: s.forever,
    lockdown: rc.policy?.access_mode === 'lockdown',
  };
}

async function getGate(rc) {
  return json(200, gateView(rc, await getSettingRaw(rc.env, 'gate_open')));
}

// A §14.1: `hours` is refused unless an integer 1–168, and null, '',
// undefined and booleans are rejected BEFORE any numeric coercion; "until I
// close it" is only ever the explicit { forever: true }.
function gateRaw(b, nowMs) {
  const hasHours = Object.hasOwn(b, 'hours');
  const hasForever = Object.hasOwn(b, 'forever');
  if (hasHours && hasForever) throw new ValidationError('Choose a number of hours or “until I close it”, not both.', 'hours');
  if (hasForever) {
    if (b.forever !== true) throw new ValidationError('To leave it open until you close it, send forever: true.', 'forever');
    return '1';
  }
  const h = b.hours;
  if (h === undefined || h === null || h === '' || typeof h === 'boolean' || (typeof h !== 'number' && typeof h !== 'string')) {
    throw new ValidationError(`Say how many hours: a whole number from 1 to ${GATE_MAX_HOURS}.`, 'hours');
  }
  const n = toInt(h, 1, GATE_MAX_HOURS);
  if (!Number.isFinite(n)) throw new ValidationError(`Say how many hours: a whole number from 1 to ${GATE_MAX_HOURS}.`, 'hours');
  return iso(nowMs + n * HOUR);
}

// Opening or closing is audited but never revertible (CONTRACTS §4.2.1): a
// revert could reopen a portal someone just closed.
async function openGate(rc) {
  const b = await body(rc);
  const raw = gateRaw(b, rc.nowMs);
  return writing(rc, 'gate.open', { type: 'setting', id: 'gate_open' }, async () => {
    const w = await writeSetting(rc, 'gate_open', raw, { allowGate: true });
    const view = gateView(rc, w.raw);
    await audit(rc, {
      action: 'gate.open',
      target: { type: 'setting', id: 'gate_open' },
      severity: 'warning',
      detail: view.forever ? 'Opened the portal to the internet until someone closes it' : `Opened the portal to the internet until ${view.until}`,
      before: { value: w.prior },
      after: { value: w.raw },
    });
    const notices = view.lockdown ? ['Lockdown is on, so the open gate has no effect until it ends.'] : [];
    return json(200, { ok: true, ...view, notices });
  });
}

async function closeGate(rc) {
  return writing(rc, 'gate.close', { type: 'setting', id: 'gate_open' }, async () => {
    const w = await writeSetting(rc, 'gate_open', '0', { allowGate: true });
    await audit(rc, {
      action: 'gate.close',
      target: { type: 'setting', id: 'gate_open' },
      severity: 'notice',
      detail: 'Closed the portal to the internet',
      before: { value: w.prior },
      after: { value: w.raw },
    });
    return json(200, { ok: true, ...gateView(rc, w.raw) });
  });
}

// ---------------------------------------------------------------- network

async function getNetwork(rc) {
  const env = rc.env;
  const t = rc.nowMs;
  const [allow, block, tier] = await Promise.all([listAllowed(env, t, rc.ip), listBlocked(env, t, rc.ip), rc.ip ? tierForIp(env, rc.ip, t) : null]);
  const e = tier?.entry;
  return json(200, {
    allow,
    block,
    you: {
      ip: rc.ip ?? null,
      country: rc.edge?.country ?? null,
      asn: rc.edge?.asn ?? null,
      tier: tier ? tier.tier : null,
      covered_by: e ? { id: e.id, cidr: e.cidr, label: e.label ?? null, tier: tier.tier } : null,
    },
  });
}

function allowTarget(id) {
  return { type: 'allowed_ip', id };
}

async function loadAllowRow(rc, id) {
  const n = toInt(id, 1);
  const row = Number.isFinite(n) ? await rc.env.DB.prepare('SELECT * FROM allowed_ips WHERE id = ?').bind(n).first() : null;
  if (!row) throw new HttpError(404, { error: 'No such allowlist entry.', code: 'not_found' });
  return row;
}

async function postAllow(rc) {
  const b = await body(rc);
  return writing(rc, 'network.allow.add', null, async () => {
    const row = await addAllowed(rc, b);
    await audit(rc, {
      action: 'network.allow.add',
      target: allowTarget(row.id),
      detail: `Allowlisted ${row.cidr} (tier ${row.tier}${row.label ? `, “${row.label}”` : ''})`,
      after: row,
      undo: undoFor('network.allow.add', { id: row.id }),
    });
    return json(200, { ok: true, entry: row });
  });
}

async function patchAllow(rc, params) {
  const b = await body(rc);
  const row = await loadAllowRow(rc, params.id);
  return writing(rc, 'network.allow.edit', allowTarget(row.id), async () => {
    await assertCanEditAllowed(rc, row, b);
    const { prior, row: next } = await editAllowed(rc, row.id, b);
    const snap = { tier: prior.tier, label: prior.label, owner: prior.owner, user_id: prior.user_id, expires_at: prior.expires_at };
    await audit(rc, {
      action: 'network.allow.edit',
      target: allowTarget(next.id),
      detail: `Edited allowlist entry ${next.cidr}`,
      before: snap,
      after: { tier: next.tier, label: next.label, owner: next.owner, user_id: next.user_id, expires_at: next.expires_at },
      undo: undoFor('network.allow.edit', { id: next.id, prior: snap }),
    });
    return json(200, { ok: true, entry: next });
  });
}

async function deleteAllow(rc, params) {
  const row = await loadAllowRow(rc, params.id);
  return writing(rc, 'network.allow.remove', allowTarget(row.id), async () => {
    await assertCanRemoveAllowed(rc, row);
    const { row: gone } = await removeAllowed(rc, row.id);
    await audit(rc, {
      action: 'network.allow.remove',
      target: allowTarget(gone.id),
      detail: `Removed ${gone.cidr} from the allowlist`,
      before: gone,
      undo: undoFor('network.allow.remove', { row: gone }),
    });
    return json(200, { ok: true });
  });
}

async function postBlock(rc) {
  const b = await body(rc);
  // The console calls it a label; the table calls it a reason.
  const input = isPlainObject(b) && b.reason === undefined && b.label !== undefined ? { ...b, reason: b.label } : b;
  const cidr = validateCidr(input.cidr, { what: 'blocklist' });
  return writing(rc, 'network.block.add', null, async () => {
    assertCanBlock(rc, cidr);
    const row = await addBlocked(rc, input);
    await audit(rc, {
      action: 'network.block.add',
      target: { type: 'blocked_ip', id: row.id },
      severity: 'notice',
      detail: `Blocked ${row.cidr}${row.reason ? ` (“${row.reason}”)` : ''}`,
      after: row,
      undo: undoFor('network.block.add', { id: row.id }),
    });
    return json(200, { ok: true, entry: row });
  });
}

async function deleteBlock(rc, params) {
  return writing(rc, 'network.block.remove', { type: 'blocked_ip', id: str(params.id, 20) }, async () => {
    const { row } = await removeBlocked(rc, params.id);
    await audit(rc, {
      action: 'network.block.remove',
      target: { type: 'blocked_ip', id: row.id },
      detail: `Unblocked ${row.cidr}`,
      before: row,
      undo: undoFor('network.block.remove', { row }),
    });
    return json(200, { ok: true });
  });
}

// ---------------------------------------------------------------- visitors

function threshold(rc) {
  const n = toInt(rc.policy?.risk_threshold, 1, 100);
  return Number.isFinite(n) ? n : 50;
}

async function getVisitors(rc) {
  const lim = toInt(rc.url.searchParams.get('limit'), 1, 500);
  const { results } = await rc.env.DB.prepare(
    'SELECT hash, visitor_id, first_seen, last_seen, hits, risk, flags, edge, last_ip, last_user_id FROM fingerprints ORDER BY last_seen DESC LIMIT ?',
  )
    .bind(Number.isFinite(lim) ? lim : 200)
    .all();
  const visitors = (results || []).map((r) => {
    const edge = safeJsonParse(r.edge, null) || {};
    const flags = safeJsonParse(r.flags, []);
    const risk = toInt(r.risk, 0, 100);
    return {
      id: r.hash,
      visitor_id: r.visitor_id ?? null,
      first_seen: r.first_seen ?? null,
      last_seen: r.last_seen ?? null,
      hits: r.hits ?? null,
      risk: Number.isFinite(risk) ? risk : null,
      flags: Array.isArray(flags) ? flags.filter((f) => f && typeof f === 'object' && typeof f.reason === 'string') : [],
      ip: r.last_ip ?? null,
      country: typeof edge.country === 'string' ? edge.country : null,
      asn: edge.asn ?? null,
      as_org: typeof edge.as_org === 'string' ? edge.as_org : null,
      ua: typeof edge.ua === 'string' ? edge.ua : null,
      user_id: r.last_user_id ?? null,
    };
  });
  return json(200, { visitors, threshold: threshold(rc) });
}

// ?decision=allow|shell|deny (or the gate's own all|shell|none) &ip= &limit=
async function getVisits(rc) {
  const sp = rc.url.searchParams;
  const d = sp.get('decision');
  const decision = d === null || d === '' ? null : Object.hasOwn(DECISIONS, d) ? DECISIONS[d] : undefined;
  if (decision === undefined) return json(200, { visits: [] });
  const ipq = str(sp.get('ip'), 64) || null;
  const lim = toInt(sp.get('limit'), 1, 500);
  const { results } = await rc.env.DB.prepare(
    `SELECT id, at, ip, country, asn, method, path, decision, reason, visitor_id, device_id, user_id, risk, ua FROM visits
     WHERE (? IS NULL OR decision = ?) AND (? IS NULL OR ip = ?) ORDER BY id DESC LIMIT ?`,
  )
    .bind(decision, decision, ipq, ipq, Number.isFinite(lim) ? lim : 200)
    .all();
  const visits = (results || []).map((v) => ({ ...v, decision: DECISION_OUT[v.decision] ?? v.decision }));
  return json(200, { visits, threshold: threshold(rc) });
}

export function register(router) {
  router.add('GET', '/api/admin/settings', getSettings, { perm: 'settings.view' });
  // Per key (CONTRACTS §5): the handler checks each key's permission and
  // demands the step-up itself (both are danger permissions).
  router.add('PUT', '/api/admin/settings', putSettings, { anyOf: SETTINGS_PERMS });
  router.add('GET', '/api/admin/gate', getGate, { perm: 'gate.open' });
  router.add('POST', '/api/admin/gate/open', openGate, { perm: 'gate.open' });
  router.add('POST', '/api/admin/gate/close', closeGate, { perm: 'gate.open' });
  router.add('GET', '/api/admin/network', getNetwork, { perm: 'network.view' });
  router.add('POST', '/api/admin/network/allow', postAllow, { perm: 'network.manage' });
  router.add('PATCH', '/api/admin/network/allow/:id', patchAllow, { perm: 'network.manage' });
  router.add('DELETE', '/api/admin/network/allow/:id', deleteAllow, { perm: 'network.manage' });
  router.add('POST', '/api/admin/network/block', postBlock, { perm: 'network.manage' });
  router.add('DELETE', '/api/admin/network/block/:id', deleteBlock, { perm: 'network.manage' });
  router.add('GET', '/api/admin/visitors', getVisitors, { perm: 'visitors.view' });
  router.add('GET', '/api/admin/visits', getVisits, { perm: 'visitors.view' });
  return router;
}
