// The live bridge: the REAL page scripts against the REAL worker (A §13.2 +
// §13.4 in one suite). tests/helpers/dom.js builds the page from the real
// HTML and imports the real public/js module; with `live` set, every fetch
// the page makes that no canned route answers goes through a
// tests/helpers/http.js Client into worker.fetch — the Client's cookie jar,
// client IP (cf-connecting-ip), user agent and request.cf come along, and
// Set-Cookie comes back into the jar. Nothing is stubbed between the page
// and the API, so a field the page reads that the API does not send shows up
// as a broken page, not as a passing test.
//
//   import { openLive, settle, lastNav, apiErrors, browserCredentials } from '../helpers/live.js';
//
//   // Navigate as a browser would: GET the path through the worker (gate,
//   // session, pin redirects, invite pass cookie), follow redirects, find out
//   // which public/*.html the server chose, check its stylesheet and module
//   // graph load through the gate, then load THAT page live.
//   const page = await openLive(client, '/login?next=/admin', {
//     webauthn: browserCredentials(new SoftAuthenticator({ origin: env.ORIGIN, rpId: env.RP_ID })),
//   });
//   await settle(page);                // until every request it started has answered
//   page.fill('identifier', 'jane@acme.com'); …
//   await page.submit('form-password');
//   await settle(page);
//   page.served                       // { status, url, path, file: 'login.html', redirects: ['/…'], assets: { '/js/login.js': 200, … } }
//   page.requests('/api/auth/login')  // as in dom.js; live records also carry .live, .status, .response (parsed JSON)
//   apiErrors(page, { ignore })       // every live call that answered ≥ 400 (ignore: ['POST /api/x', /regex/])
//   lastNav(page)                     // { type: 'replace', url: '/' } — the last navigation it asked for
//
//   // Or load a page file directly with the bridge (no navigation):
//   const p = await loadPage('dashboard.html', { live: client });   // dom.js accepts a Client
//   const q = await loadPage('admin.html', { live: liveFetch(client), fetch: { 'GET /api/x': reply(…) } });
//
// Canned routes (opts.fetch) still win over the bridge, so a suite can force
// one failure while everything else is real.
//
// navigate(client, path) → { status, url, path, file, redirects, text, headers }
//   file is the public/*.html whose bytes the worker served, or null (a JSON
//   404, an empty 403 from the gate, …). Redirects (3xx + Location) are
//   followed up to 5 times, same origin only.
//
// pageAssets(client, file) → { '/css/app.css': 200, '/js/login.js': 200, … }
//   what openLive checks: a shell that serves the page but refuses one of its
//   scripts is a blank page in production.
//
// browserCredentials(authenticator) → { get(opts), create(opts) } for dom.js
//   `opts.webauthn`: what navigator.credentials does in a browser. It takes
//   the { publicKey } object public/js/webauthn.js builds (ArrayBuffers),
//   turns it back into the server's base64url JSON for the
//   SoftAuthenticator, and returns a PublicKeyCredential-shaped object
//   (ArrayBuffer rawId, response.clientDataJSON/attestationObject/
//   authenticatorData/signature/userHandle, response.getTransports()) — so
//   webauthn.js's own conversions are what is under test. The authenticator's
//   errors (NotAllowedError, InvalidStateError, SecurityError) pass through.
//   Calls are recorded on .calls ({ kind, options }).

import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { loadPage, PUBLIC_DIR } from './dom.js';

// ------------------------------------------------------------- bridge ----

function headerObject(h) {
  if (!h) return {};
  if (typeof h.forEach === 'function' && !Array.isArray(h)) {
    const out = {};
    h.forEach((v, k) => {
      out[k.toLowerCase()] = v;
    });
    return out;
  }
  if (Array.isArray(h)) return Object.fromEntries(h.map(([k, v]) => [String(k).toLowerCase(), String(v)]));
  return Object.fromEntries(Object.entries(h).map(([k, v]) => [k.toLowerCase(), String(v)]));
}

const NULL_BODY = new Set([101, 103, 204, 205, 304]);

// → (url: URL, init) => Promise<Response>. The handler dom.js calls for every
// fetch no canned route answers. A real browser sends Origin on a
// same-origin POST and Sec-Fetch-Site on everything; the Client adds Origin
// for writes, this adds Sec-Fetch-* so the worker sees a browser fetch.
export function liveFetch(client) {
  if (!client || typeof client.request !== 'function') throw new TypeError('liveFetch needs a tests/helpers/http.js Client');
  const handler = async (url, init = {}) => {
    const method = String(init.method || 'GET').toUpperCase();
    const target = new URL(url, client.env.ORIGIN);
    if (target.origin !== new URL(client.env.ORIGIN).origin) throw new TypeError(`live: cross-origin fetch to ${target.origin} (the CSP's connect-src 'self' would refuse it)`);
    const headers = { 'sec-fetch-site': 'same-origin', 'sec-fetch-mode': 'cors', 'sec-fetch-dest': 'empty', ...headerObject(init.headers) };
    // Client.request treats `undefined` as "no body" and a string as the raw body.
    const body = init.body === undefined || init.body === null ? undefined : String(init.body);
    if (body === undefined && method === 'GET' && !headers.accept) headers.accept = '*/*';
    const r = await client.request(method, target.pathname + target.search, body, headers);
    const out = new Headers();
    r.headers.forEach((v, k) => {
      if (k !== 'set-cookie') out.set(k, v);
    });
    return new Response(NULL_BODY.has(r.status) ? null : r.text, { status: r.status, headers: out });
  };
  handler.client = client;
  return handler;
}

// ------------------------------------------------------------ pages ----

let pageBytes = null;

function servedFile(text) {
  if (!pageBytes) {
    pageBytes = new Map();
    for (const name of readdirSync(PUBLIC_DIR)) {
      if (name.endsWith('.html')) pageBytes.set(readFileSync(path.join(PUBLIC_DIR, name), 'utf8'), name);
    }
  }
  return pageBytes.get(text) ?? null;
}

export async function navigate(client, start, { maxRedirects = 5 } = {}) {
  const origin = new URL(client.env.ORIGIN).origin;
  let url = new URL(start, origin);
  const redirects = [];
  for (let i = 0; ; i++) {
    const r = await client.request('GET', url.pathname + url.search, undefined, {
      accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'sec-fetch-site': i === 0 ? 'none' : 'same-origin',
      'sec-fetch-mode': 'navigate',
      'sec-fetch-dest': 'document',
    });
    const loc = r.headers.get('location');
    if (r.status >= 300 && r.status < 400 && loc) {
      const next = new URL(loc, url);
      if (next.origin !== origin) throw new Error(`live: ${url.pathname} redirected off-site to ${next.href}`);
      if (i >= maxRedirects) throw new Error(`live: too many redirects from ${start}: ${redirects.join(' → ')}`);
      redirects.push(next.pathname + next.search);
      url = next;
      continue;
    }
    const type = r.headers.get('content-type') || '';
    const file = r.status === 200 && type.startsWith('text/html') ? servedFile(r.text) : null;
    return { status: r.status, url: url.href, path: url.pathname + url.search, file, redirects, text: r.text, headers: r.headers };
  }
}

// The stylesheet and the page's module graph (static imports, followed
// through every file), fetched through the worker the way the browser would
// after the HTML: a shell that lets the page in but refuses one of its
// scripts is a blank page in production (CONTRACTS §7.8 shell asset lists).
export async function pageAssets(client, file) {
  const html = readFileSync(path.join(PUBLIC_DIR, file), 'utf8');
  const wanted = [];
  for (const m of html.matchAll(/<(?:link[^>]*href|script[^>]*src)="(\/[^"]+)"/g)) wanted.push(m[1]);
  const seen = new Map();
  while (wanted.length) {
    const p = wanted.shift();
    if (seen.has(p)) continue;
    const r = await client.request('GET', p, undefined, { accept: '*/*', 'sec-fetch-site': 'same-origin', 'sec-fetch-mode': p.endsWith('.js') ? 'cors' : 'no-cors', 'sec-fetch-dest': p.endsWith('.js') ? 'script' : p.endsWith('.css') ? 'style' : 'image' });
    seen.set(p, r.status);
    if (r.status === 200 && p.endsWith('.js')) {
      for (const m of r.text.matchAll(/\bfrom\s+['"](\.\/[^'"]+)['"]/g)) wanted.push(new URL(m[1], `https://x${p}`).pathname);
    }
  }
  return Object.fromEntries(seen);
}

// GET `path` like a browser, then load the page the worker served, live.
// opts.assets: false skips the stylesheet/module-graph check.
export async function openLive(client, start, opts = {}) {
  const served = await navigate(client, start);
  if (!served.file) {
    throw new Error(`live: GET ${start} served no page (status ${served.status}${served.redirects.length ? `, via ${served.redirects.join(' → ')}` : ''}): ${served.text.slice(0, 120)}`);
  }
  if (opts.assets !== false) {
    const assets = await pageAssets(client, served.file);
    const refused = Object.entries(assets).filter(([, status]) => status !== 200);
    if (refused.length) throw new Error(`live: ${served.file} at ${start} cannot load ${refused.map(([p, s]) => `${p} (${s})`).join(', ')}`);
    served.assets = assets;
  }
  const { assets: _skip, ...rest } = opts;
  const page = await loadPage(served.file, { ...rest, url: served.url, live: opts.live || liveFetch(client) });
  page.served = served;
  return page;
}

// Every live call the page made that answered with an error status.
export function apiErrors(page, { ignore = [] } = {}) {
  return page.calls.fetch.filter((c) => c.live && c.status >= 400 && !ignore.some((p) => (p instanceof RegExp ? p.test(`${c.method} ${c.path}`) : `${c.method} ${c.path}`.startsWith(p))));
}

// -------------------------------------------------------- passkeys ----

function bytesOf(v) {
  if (v instanceof ArrayBuffer) return new Uint8Array(v);
  if (ArrayBuffer.isView(v)) return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
  throw new TypeError('live: navigator.credentials expected an ArrayBuffer/BufferSource');
}

function b64u(v) {
  return Buffer.from(bytesOf(v)).toString('base64url');
}

function buf(s) {
  const b = Buffer.from(String(s), 'base64url');
  return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);
}

function descriptorsJson(list) {
  return (list || []).map((d) => ({ type: d.type, id: b64u(d.id), ...(d.transports ? { transports: d.transports } : {}) }));
}

function credentialObject(json) {
  const r = json.response;
  const response = { clientDataJSON: buf(r.clientDataJSON) };
  if (r.attestationObject !== undefined) {
    response.attestationObject = buf(r.attestationObject);
    const transports = Array.isArray(r.transports) ? r.transports.slice() : [];
    response.getTransports = () => transports;
  }
  if (r.authenticatorData !== undefined) response.authenticatorData = buf(r.authenticatorData);
  if (r.signature !== undefined) response.signature = buf(r.signature);
  if (r.authenticatorData !== undefined) response.userHandle = typeof r.userHandle === 'string' ? buf(r.userHandle) : null;
  // A browser's `id` is the base64url of rawId; webauthn.js re-derives it anyway.
  return { id: json.id, rawId: buf(json.rawId), type: json.type, response, authenticatorAttachment: 'platform' };
}

export function browserCredentials(authenticator, { knobs = {} } = {}) {
  const calls = [];
  const host = () => {
    try {
      return new URL(globalThis.location.href).hostname;
    } catch {
      return undefined;
    }
  };
  return {
    calls,
    async create({ publicKey } = {}) {
      const options = {
        challenge: b64u(publicKey.challenge),
        rp: { ...publicKey.rp, id: publicKey.rp?.id ?? host() },
        user: { ...publicKey.user, id: b64u(publicKey.user.id) },
        pubKeyCredParams: publicKey.pubKeyCredParams,
        timeout: publicKey.timeout,
        attestation: publicKey.attestation,
        authenticatorSelection: publicKey.authenticatorSelection,
        excludeCredentials: descriptorsJson(publicKey.excludeCredentials),
      };
      calls.push({ kind: 'create', options });
      return credentialObject(await authenticator.create(options, knobs.create || {}));
    },
    async get({ publicKey } = {}) {
      const options = {
        challenge: b64u(publicKey.challenge),
        rpId: publicKey.rpId ?? host(),
        timeout: publicKey.timeout,
        userVerification: publicKey.userVerification,
        allowCredentials: descriptorsJson(publicKey.allowCredentials),
      };
      calls.push({ kind: 'get', options });
      return credentialObject(await authenticator.get(options, knobs.get || {}));
    },
  };
}

// ------------------------------------------------------------ small kit ----

// The last navigation the page asked for ({ type, url }) or null.
export function lastNav(page) {
  const navs = page.calls.nav.filter((n) => ['assign', 'replace', 'link', 'form'].includes(n.type));
  return navs[navs.length - 1] || null;
}

// Waits until every request the page started has answered and nothing new
// started for a few drain rounds — the worker is async all the way down
// (PBKDF2, WebCrypto), so one dom.js drain() is not enough for a chain of
// awaited calls. Gives up after `timeoutMs` (and says what was in flight).
export async function settle(page, { timeoutMs = 15000, quietRounds = 3 } = {}) {
  // performance.now, not Date.now: a suite may pin Date.now to the env clock.
  const clock = () => performance.now();
  const started = clock();
  let last = -1;
  let quiet = 0;
  while (quiet < quietRounds) {
    await page.drain(4);
    const n = page.calls.fetch.length;
    const busy = page.calls.fetch.some((c) => !c.done);
    quiet = !busy && n === last ? quiet + 1 : 0;
    last = n;
    if (busy) await new Promise((r) => setImmediate(r));
    if (clock() - started > timeoutMs) {
      const open = page.calls.fetch.filter((c) => !c.done).map((c) => `${c.method} ${c.url}`);
      throw new Error(`live: page did not settle in ${timeoutMs} ms${open.length ? `; still waiting on ${open.join(', ')}` : ''}`);
    }
  }
}
