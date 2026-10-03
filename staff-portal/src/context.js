// The request context `rc` (CONTRACTS §4.1), built once per request before
// anything decides. Every derived value comes from the module that owns it;
// nothing here interprets a setting or a cookie itself.

import { now, str, parseCookies, clientIpRaw } from './util.js';
import { normalizeIp } from './ip.js';
import { resolvePolicy } from './policy.js';
import { edgeSignals, readFpCookie } from './fingerprint.js';
import { readDevice } from './devices.js';
import { tierForIp, isIpBlocked } from './network.js';
import { evaluateGate } from './gate.js';

function requestCf(request) {
  try {
    const cf = request.cf;
    return cf && typeof cf === 'object' ? cf : {};
  } catch {
    return {};
  }
}

export async function buildContext(request, env, ctx) {
  const url = new URL(request.url);
  const rc = {
    request,
    env,
    ctx,
    url,
    method: String(request.method || 'GET').toUpperCase(),
    path: url.pathname,
    nowMs: now(env),
    // CF-Connecting-IP is set by the edge; anything that does not parse is
    // "no usable address", which the gate refuses (step 1).
    ip: normalizeIp(clientIpRaw(request)),
    cf: requestCf(request),
    ua: str(request.headers.get('user-agent'), 512),
    cookies: parseCookies(request.headers.get('cookie')),
    setCookies: [],
    session: null,
    user: null,
    authz: null,
  };
  rc.policy = await resolvePolicy(env);
  rc.edge = edgeSignals(request, rc.cf);
  rc.fp = await readFpCookie(rc);
  rc.device = await readDevice(rc);
  if (rc.ip) {
    const [tier, blocked] = await Promise.all([tierForIp(env, rc.ip, rc.nowMs), isIpBlocked(env, rc.ip, rc.nowMs)]);
    // A bare 1..4 (§4.1); the entry itself is kept for the console's "you" panel.
    rc.ipTier = tier ? tier.tier : null;
    rc.ipEntry = tier ? tier.entry : null;
    rc.ipBlocked = blocked;
  } else {
    rc.ipTier = null;
    rc.ipEntry = null;
    rc.ipBlocked = true;
  }
  rc.gate = await evaluateGate(rc);
  return rc;
}
