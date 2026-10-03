// The worker: one pipeline for every request (CONTRACTS §8.1; A §2, §11).
//
//   /healthz → secrets → schema → context + gate → visit log → refuse
//   → same-origin writes → session → shell → pages → assets → API → 404
//
// Each step fully decides before the next one runs. Security headers go on
// every response, the empty ones included; Set-Cookie never goes on a
// refusal. Anything thrown that is not an HttpError is a bug: the real error
// goes to the audit log and the caller gets one polite sentence (B trap 2).

import { Router } from './src/router.js';
import { registerAll } from './src/api/index.js';
import { ensureSchema } from './src/schema.js';
import { buildContext } from './src/context.js';
import { shellAllows, denyResponse } from './src/gate.js';
import { recordVisit } from './src/fingerprint.js';
import { loadSession } from './src/sessions.js';
import { canAll, routeNeedsStepUp, requireStepUp } from './src/rbac.js';
import { auditError } from './src/audit.js';
import { HttpError, forbidden } from './src/errors.js';
import { requireSecret } from './src/crypto.js';
import { json, empty, redirect, now, loggablePath } from './src/util.js';
import { harden, servePage, serveAsset, isNavigation, invitePass } from './src/pages.js';
import { pinTarget } from './src/signin.js';

const router = registerAll(new Router());

// Missing or shared secrets refuse everything but liveness (CONTRACTS §3):
// DATA_KEY equal to SESSION_SECRET would tie the cheap rotation to the one
// that kills every authenticator app (A §11).
function secretsProblem(env) {
  try {
    const s = requireSecret(env, 'SESSION_SECRET');
    const d = requireSecret(env, 'DATA_KEY');
    return s === d ? 'DATA_KEY must differ from SESSION_SECRET' : null;
  } catch (e) {
    return e && e.message ? e.message : 'secrets unreadable';
  }
}

// CSRF: a write must say it came from our own origin. JSON-only bodies are a
// second brake (util.readJson), never the only one.
function sameOrigin(request, env) {
  const origin = request.headers.get('origin');
  if (origin !== null) return typeof env.ORIGIN === 'string' && env.ORIGIN !== '' && origin === env.ORIGIN;
  return request.headers.get('sec-fetch-site') === 'same-origin';
}

function isWrite(rc) {
  return rc.method !== 'GET' && rc.method !== 'HEAD';
}

function refuse(rc, reason, response) {
  rc.visit = { decision: 'none', reason };
  rc.refused = true;
  return response;
}

async function callApi(rc) {
  const m = router.match(rc.method, rc.path);
  if (!m) return json(404, { error: 'Not found.', code: 'not_found' });
  if (m.methodNotAllowed) return json(405, { error: 'That method isn’t allowed here.', code: 'method_not_allowed' });
  const { route, params } = m;
  const { auth, perm } = route.opts;
  if (auth !== 'none' || perm !== undefined) {
    if (!rc.session || !rc.authz) return json(401, { error: 'Sign in first.', code: 'signed_out' });
    // A pinned session reaches only the routes that finish the pinned task
    // (B trap 3: pin, never refuse).
    if (auth === 'session' && rc.session.pinned) {
      return json(403, {
        error: 'Finish setting up your account first.',
        code: 'pinned',
        pinned: rc.session.pinned,
        next: pinTarget(rc.session.pinned),
      });
    }
  }
  if (perm !== undefined && !canAll(rc.authz, perm)) throw forbidden();
  if (isWrite(rc) && routeNeedsStepUp(perm)) requireStepUp(rc);
  const res = await route.handler(rc, params);
  if (!(res instanceof Response)) throw new Error(`route ${route.method} ${route.pattern} returned no Response`);
  return res;
}

async function pipeline(rc) {
  const gate = rc.gate;
  if (gate.allowed === 'none') return refuse(rc, gate.reason, denyResponse(rc.policy));
  if (isWrite(rc) && !sameOrigin(rc.request, rc.env)) return refuse(rc, 'cross_origin', empty(403));
  await loadSession(rc);
  const nav = isNavigation(rc);
  if (nav || (isWrite(rc) && rc.path.startsWith('/api/'))) rc.visit = { decision: gate.allowed, reason: gate.reason };
  if (gate.allowed === 'shell' && !shellAllows(gate.shell, rc.method, rc.path)) {
    // "Any navigation shows /pending" (CONTRACTS §7.8); every other shell
    // refuses what it does not list.
    if (gate.shell === 'pending' && nav) return redirect('/pending');
    return refuse(rc, `outside_shell_${gate.shell}`, denyResponse(rc.policy));
  }
  const page = await servePage(rc);
  if (page) return page;
  const asset = await serveAsset(rc);
  if (asset) return asset;
  if (rc.path.startsWith('/api/')) return callApi(rc);
  return empty(404);
}

function errorResponse(e) {
  const body = e.body && typeof e.body === 'object' ? e.body : { error: e.message };
  const res = json(e.status, body);
  if (e.status === 429 && Number.isInteger(body.retry_after)) res.headers.set('retry-after', String(body.retry_after));
  return res;
}

async function handle(request, env, ctx) {
  const url = new URL(request.url);
  // Liveness before everything (A §11): if this answers and the rest is an
  // empty 403, the gate is working and your address is not on the list.
  if (url.pathname === '/healthz') return harden(new Response('ok', { status: 200, headers: { 'content-type': 'text/plain; charset=utf-8' } }));
  const problem = secretsProblem(env);
  if (problem) {
    console.error(`worker: refusing every request: ${problem}`);
    return harden(empty(503));
  }
  let rc = null;
  let res;
  try {
    await ensureSchema(env);
    rc = await buildContext(request, env, ctx);
    await invitePass(rc);
    res = await pipeline(rc);
  } catch (e) {
    if (e instanceof HttpError) res = errorResponse(e);
    else {
      await auditError(rc || { env, nowMs: now(env) }, 'error', e, {
        detail: `Unexpected failure on ${request.method} ${loggablePath(url.pathname)}.`,
      });
      // Before the gate has let a request in, even a failure says nothing.
      res = rc && rc.gate && rc.gate.allowed !== 'none' ? json(500, { error: 'Something went wrong.' }) : empty(403);
    }
  }
  if (rc && rc.visit) {
    const p = recordVisit(rc, rc.visit);
    if (ctx && typeof ctx.waitUntil === 'function') ctx.waitUntil(p);
    else await p;
  }
  return harden(res, rc && !rc.refused ? rc.setCookies : []);
}

export default {
  async fetch(request, env, ctx) {
    try {
      return await handle(request, env, ctx);
    } catch (e) {
      // Only the hardening itself can land here; still nothing but headers.
      console.error('worker: unhandled', e && e.message);
      return harden(empty(500));
    }
  },
};
