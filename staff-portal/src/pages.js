// Pages, assets and response hardening (CONTRACTS §8.2, §8.3).
//
// Which page a path shows is decided here, on the server, from the session
// and the gate — so a signed-in visitor never sees a flash of the sign-in
// page and a signed-out one never sees a dashboard shell (B §10). HTML files
// are fetched from ASSETS by name; asking for `*.html` directly is a 404, so
// a page cannot be reached around these rules.

import { redirect, empty } from './util.js';
import { can } from './rbac.js';
import { charge, peek, LIMITS } from './ratelimit.js';
import { lookupInvitation } from './invitations.js';
import { evaluateGate, passCookie, PASS_COOKIE } from './gate.js';
import { pinTarget } from './signin.js';

export const CSP =
  "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
  "font-src 'self'; manifest-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

// On EVERY response, the empty ones included (A §2 "Response hardening").
export const SECURITY_HEADERS = Object.freeze({
  'content-security-policy': CSP,
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin',
  'permissions-policy':
    'camera=(), microphone=(), geolocation=(), payment=(), usb=(), publickey-credentials-get=(self), publickey-credentials-create=(self)',
  'strict-transport-security': 'max-age=63072000; includeSubDomains',
  'cache-control': 'no-store, no-cache, must-revalidate, private',
});

// Holding any one of these opens /admin (CONTRACTS §8.3).
export const ADMIN_CONSOLE_PERMS = Object.freeze([
  'users.view', 'team.view', 'directory.view', 'devices.view', 'network.view', 'audit.view', 'settings.view',
  'roles.view', 'visitors.view', 'sessions.view', 'streaks.view_all', 'requests.manage', 'users.invite',
]);

const SHELL_PAGE_FILES = Object.freeze({
  setup: 'setup.html',
  request: 'request.html',
  login: 'login.html',
  invite: 'invite.html',
  pending: 'pending.html',
});

const ASSET_RE = /^\/(?:css\/[A-Za-z0-9][A-Za-z0-9_-]{0,63}\.css|js\/[A-Za-z0-9][A-Za-z0-9_-]{0,63}\.js|favicon\.svg)$/;
const ASSET_TYPES = Object.freeze({ css: 'text/css; charset=utf-8', js: 'text/javascript; charset=utf-8', svg: 'image/svg+xml' });
const INVITE_TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;

export function harden(response, cookies = []) {
  const headers = new Headers(response.headers);
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) headers.set(k, v);
  for (const c of cookies) if (typeof c === 'string' && c) headers.append('set-cookie', c);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

export function isAssetPath(path) {
  return typeof path === 'string' && ASSET_RE.test(path);
}

function safeMethod(rc) {
  return rc.method === 'GET' || rc.method === 'HEAD';
}

// A page load, as opposed to an API call or an asset: what the visit log
// records and what the pending shell answers with its own page.
export function isNavigation(rc) {
  return safeMethod(rc) && !rc.path.startsWith('/api/') && !isAssetPath(rc.path) && rc.path !== '/healthz';
}

// `?next=` keeps its slashes readable (/login?next=/admin); everything else
// is encoded. The login page still runs it through safeNext (A §7.5).
function loginRedirect(rc) {
  const next = encodeURIComponent(`${rc.path}${rc.url.search}`).replace(/%2F/gi, '/');
  return redirect(`/login?next=${next}`);
}

async function pageFile(rc, name) {
  const res = await rc.env.ASSETS.fetch(new Request(new URL(`/${name}`, rc.url.origin)));
  // A missing page is a broken deploy, not the visitor's problem: the worker
  // turns this into a 500 and audits it.
  if (!res || res.status !== 200) throw new Error(`pages: ${name} is missing from the assets (status ${res ? res.status : 'none'})`);
  return new Response(rc.method === 'HEAD' ? null : res.body, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8' } });
}

// → Response, or null when the path is not a page.
export async function servePage(rc) {
  if (!safeMethod(rc)) return null;
  const p = rc.path;
  const shell = rc.gate?.allowed === 'shell' ? rc.gate.shell : null;
  const session = rc.session || null;
  const pin = session && typeof session.pinned === 'string' && session.pinned ? session.pinned : null;
  switch (p) {
    case '/':
      if (shell) return SHELL_PAGE_FILES[shell] ? pageFile(rc, SHELL_PAGE_FILES[shell]) : empty(404);
      if (!session) return pageFile(rc, 'login.html');
      if (pin) return redirect(pinTarget(pin));
      return pageFile(rc, 'dashboard.html');
    case '/login':
      if (session && !shell) return redirect(pinTarget(pin));
      return pageFile(rc, 'login.html');
    case '/account':
      if (!session) return loginRedirect(rc);
      return pageFile(rc, 'account.html');
    case '/admin':
      if (!session) return loginRedirect(rc);
      if (pin) return redirect(pinTarget(pin));
      return ADMIN_CONSOLE_PERMS.some((k) => can(rc.authz, k)) ? pageFile(rc, 'admin.html') : redirect('/');
    case '/setup':
      // Only while no account exists: afterwards the route is gone (B §5).
      return shell === 'setup' ? pageFile(rc, 'setup.html') : empty(404);
    case '/invite':
      return pageFile(rc, 'invite.html');
    case '/request-access':
      return shell === 'request' ? pageFile(rc, 'request.html') : redirect('/');
    case '/pending':
      return shell === 'pending' ? pageFile(rc, 'pending.html') : redirect('/');
    default:
      return null;
  }
}

// Assets go through the gate like everything else (run_worker_first), so a
// refused visitor cannot even fetch the stylesheet.
export async function serveAsset(rc) {
  if (!safeMethod(rc) || !isAssetPath(rc.path)) return null;
  const res = await rc.env.ASSETS.fetch(new Request(new URL(rc.path, rc.url.origin)));
  if (!res || res.status !== 200) return empty(404);
  const ext = rc.path.slice(rc.path.lastIndexOf('.') + 1);
  return new Response(rc.method === 'HEAD' ? null : res.body, { status: 200, headers: { 'content-type': ASSET_TYPES[ext] } });
}

// GET /invite?token=… with a valid token sets the pass cookie (CONTRACTS
// §8.3, SPEC §6.7): the only way a stranger holding a link gets past a mode
// that would otherwise show them nothing. The gate is re-run WITH the pass,
// so hard blocks, edge rules and lockdown still decide exactly as before.
// The bucket is peeked before it is charged so a refused stranger hammering
// this path cannot grow auth_attempts past the limit.
export async function invitePass(rc) {
  if (rc.method !== 'GET' || rc.path !== '/invite') return;
  if (rc.gate?.allowed === 'all' || rc.gate?.shell === 'invite') return;
  const token = rc.url.searchParams.get('token');
  if (typeof token !== 'string' || !INVITE_TOKEN_RE.test(token)) return;
  const subject = rc.ip ?? '?';
  if ((await peek(rc.env, 'invite_ip', subject, rc.nowMs)) >= LIMITS.invite_ip.max) return;
  const lim = await charge(rc.env, 'invite_ip', subject, rc.nowMs);
  if (!lim.allowed || !(await lookupInvitation(rc.env, token, rc.nowMs))) return;
  const setCookie = await passCookie(rc.env, rc.nowMs);
  const value = setCookie.split(';')[0].slice(PASS_COOKIE.length + 1);
  const cookies = { ...rc.cookies, [PASS_COOKIE]: value };
  const gate = await evaluateGate({ ...rc, cookies });
  // Only a verdict the pass itself makes — the invite shell — is taken; in a
  // mode where the pass changes nothing (fingerprint_gate) no pass is set.
  if (gate.allowed !== 'shell' || gate.shell !== 'invite') return;
  rc.cookies = cookies;
  rc.gate = gate;
  rc.setCookies.push(setCookie);
}
