// public/js/fp.js — client fingerprint signals (CONTRACTS §10.1; B §6).
//
// The contract: every probe individually trapped behind ONE overall
// deadline; a probe that throws or times out is named in `blocked`;
// collectSignals and reportFingerprint never throw and never hang.

import { test, assert, run } from '../helpers/t.js';
import { loadPage, importFresh, reply } from '../helpers/dom.js';

async function env(opts = {}) {
  const p = await loadPage('request.html', { import: false, fetch: { 'POST /api/fp': reply(200, { ok: true }) }, ...opts });
  const fp = await importFresh('js/fp.js');
  return { p, fp };
}

// Temporarily replace globals with ones that throw; restore afterwards.
function hostile(doc) {
  const saved = [];
  const boom = () => {
    throw new Error('blocked by the browser');
  };
  const trap = new Proxy({}, { get: boom, has: boom, ownKeys: boom, getOwnPropertyDescriptor: boom });
  const define = (key, desc) => {
    saved.push([key, Object.getOwnPropertyDescriptor(globalThis, key)]);
    Object.defineProperty(globalThis, key, { configurable: true, ...desc });
  };
  for (const key of ['navigator', 'Intl', 'Math']) define(key, { value: trap, writable: true });
  for (const key of ['screen', 'innerWidth', 'innerHeight', 'outerWidth', 'outerHeight', 'devicePixelRatio', 'OfflineAudioContext', 'webkitOfflineAudioContext', 'RTCPeerConnection', 'webkitRTCPeerConnection', 'localStorage', 'sessionStorage', 'indexedDB']) define(key, { get: boom });
  define('matchMedia', { value: boom, writable: true });
  const createElement = doc.createElement;
  doc.createElement = boom;
  return () => {
    doc.createElement = createElement;
    for (const [key, desc] of saved.reverse()) {
      if (desc) Object.defineProperty(globalThis, key, desc);
      else delete globalThis[key];
    }
  };
}

function fakeCanvasFactory({ renderer = 'ANGLE (Apple, ANGLE Metal Renderer: Apple M2, Unspecified Version)' } = {}) {
  return function createCanvas() {
    let font = '';
    const ctx2d = {
      set font(v) {
        font = v;
      },
      get font() {
        return font;
      },
      textBaseline: '',
      fillStyle: '',
      globalCompositeOperation: '',
      fillRect() {},
      fillText() {},
      beginPath() {},
      closePath() {},
      arc() {},
      fill() {},
      measureText: () => ({ width: /"(Arial|Menlo)"/.test(font) ? 101 : 100 }),
    };
    const gl = {
      VENDOR: 7936,
      RENDERER: 7937,
      getExtension: (name) => (name === 'WEBGL_debug_renderer_info' ? { UNMASKED_VENDOR_WEBGL: 37445, UNMASKED_RENDERER_WEBGL: 37446 } : null),
      getParameter: (p) => (p === 37445 ? 'Google Inc. (Apple)' : p === 37446 ? renderer : p === undefined ? null : `param-${p}`),
      getSupportedExtensions: () => ['OES_texture_float', 'WEBGL_debug_renderer_info'],
    };
    return { width: 0, height: 0, getContext: (t) => (t === '2d' ? ctx2d : t === 'webgl' ? gl : null), toDataURL: () => 'data:image/png;base64,iVBORw0KGgo=' };
  };
}

test('in a plain page every signal group is present or named in blocked', async () => {
  const { p, fp } = await env();
  const s = await fp.collectSignals();
  assert.equal(s.v, 1);
  assert.equal(typeof s.ua, 'string');
  assert.ok(Array.isArray(s.languages));
  assert.equal(typeof s.tz, 'string');
  assert.equal(typeof s.tzOffset, 'number');
  assert.ok(s.intl && typeof s.intl.locale === 'string');
  assert.deepEqual(s.window, { iw: 1280, ih: 800, ow: 1280, oh: 900 });
  assert.equal(typeof s.math, 'string');
  assert.match(s.math, /^[0-9a-f]{64}$/);
  assert.ok(s.features && typeof s.features.wasm === 'boolean');
  assert.deepEqual(s.automation, [], 'a normal browser has no tells');
  assert.equal(s.webrtc, null, 'no RTCPeerConnection → null, not blocked');
  assert.equal(s.uaData, null);
  assert.equal(s.net, null);
  assert.equal(s.perms, null);
  // The test DOM has no canvas and no screen: those are blocked, not fatal.
  for (const name of ['canvas', 'webgl', 'fonts', 'audio', 'screen']) assert.ok(s.blocked.includes(name), `${name} blocked`);
  for (const name of fp.PROBE_NAMES) {
    const present = Object.keys(s).length && (name in s || s.blocked.includes(name) || (name === 'navigator' && 'ua' in s) || (name === 'tz' && 'tzOffset' in s));
    assert.ok(present, `${name} neither reported nor blocked`);
  }
  assert.equal(typeof s.elapsedMs, 'number');
  assert.ok(JSON.stringify({ signals: s }).length < 16 * 1024, 'fits the 16 KiB body cap');
  p.dispose();
});

test('every probe throwing: collectSignals still resolves and names them ALL in blocked', async () => {
  const { p, fp } = await env();
  const restore = hostile(p.document);
  let s;
  try {
    s = await fp.collectSignals({ deadlineMs: 500 });
  } finally {
    restore();
  }
  assert.deepEqual([...s.blocked].sort(), [...fp.PROBE_NAMES].sort());
  assert.equal(s.v, 1);
  assert.ok(!('ua' in s) && !('screen' in s) && !('math' in s));
  assert.equal(typeof s.elapsedMs, 'number');
  p.dispose();
});

test('reportFingerprint never throws: hostile globals AND a failing network → { ok: false }', async () => {
  const { p, fp } = await env({ fetch: { 'POST /api/fp': reply(200, null, { networkError: true }) } });
  const restore = hostile(p.document);
  let r;
  try {
    r = await fp.reportFingerprint({ deadlineMs: 200 });
  } finally {
    restore();
  }
  assert.deepEqual(r, { ok: false });
  p.dispose();
});

test('a throwing setTimeout cannot break it either', async () => {
  const { p, fp } = await env();
  const saved = globalThis.setTimeout;
  globalThis.setTimeout = () => {
    throw new Error('no timers');
  };
  let s;
  try {
    s = await fp.collectSignals();
  } finally {
    globalThis.setTimeout = saved;
  }
  assert.equal(s.v, 1);
  assert.ok(s.blocked.length > 0);
  p.dispose();
});

test('a probe that never settles is cut off by the ONE overall deadline and named', async () => {
  const { p, fp } = await env({
    navigator: {
      permissions: { query: () => new Promise(() => {}) },
      storage: { estimate: () => new Promise(() => {}) },
    },
  });
  const t0 = Date.now();
  const s = await fp.collectSignals({ deadlineMs: 60 });
  const took = Date.now() - t0;
  assert.ok(took < 1000, `took ${took} ms`);
  assert.ok(s.blocked.includes('perms'));
  assert.ok(s.blocked.includes('storage'));
  assert.ok(!s.blocked.includes('math'), 'fast probes still report');
  assert.equal(p.pendingTimers().filter((t) => t.delay === 60).length, 0, 'the deadline timer is cleared');
  p.dispose();
});

test('canvas, webgl and fonts hash with SHA-256; a SwiftShader renderer is a tell', async () => {
  const { p, fp } = await env();
  const real = p.document.createElement.bind(p.document);
  const fake = fakeCanvasFactory({ renderer: 'ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero) (0x0000C0DE)), SwiftShader driver)' });
  p.document.createElement = (tag) => (tag === 'canvas' ? fake() : real(tag));
  const s = await fp.collectSignals();
  assert.match(s.canvas, /^[0-9a-f]{64}$/);
  assert.equal(s.webgl.vendor, 'Google Inc. (Apple)');
  assert.match(s.webgl.renderer, /SwiftShader/);
  assert.match(s.webgl.hash, /^[0-9a-f]{64}$/);
  assert.deepEqual(s.fonts, ['Arial', 'Menlo']);
  assert.ok(s.automation.includes('swiftshader'));
  p.dispose();
  const q = await env();
  const realQ = q.p.document.createElement.bind(q.p.document);
  const fakeQ = fakeCanvasFactory({ renderer: 'llvmpipe (LLVM 15.0.7, 256 bits)' });
  q.p.document.createElement = (tag) => (tag === 'canvas' ? fakeQ() : realQ(tag));
  const sq = await q.fp.collectSignals();
  assert.ok(sq.automation.includes('llvmpipe'));
  assert.ok(!sq.automation.includes('swiftshader'));
  q.p.dispose();
});

test('automation tells: webdriver, headless UA, no plugins, zero outer size, $cdc_, selenium', async () => {
  const { p, fp } = await env({
    navigator: {
      webdriver: true,
      userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36',
      plugins: { length: 0 },
    },
    globals: { outerWidth: 0, outerHeight: 0, __selenium_unwrapped: true },
  });
  p.document.$cdc_asdjflasutopfhvcZLmcfl_ = {};
  const s = await fp.collectSignals();
  for (const tell of ['webdriver', 'headless-ua', 'no-plugins', 'zero-outer', 'cdc', 'selenium']) assert.ok(s.automation.includes(tell), `missing ${tell}: ${s.automation}`);
  p.dispose();
});

test('WebRTC: host candidates only, no ICE servers, counts not addresses', async () => {
  const configs = [];
  class FakePC {
    constructor(cfg) {
      configs.push(cfg);
      this.closed = false;
      this.onicecandidate = null;
    }
    createDataChannel() {}
    async createOffer() {
      return { type: 'offer', sdp: '' };
    }
    async setLocalDescription() {
      const fire = (c) => this.onicecandidate && this.onicecandidate({ candidate: c });
      setTimeout(() => {
        fire({ candidate: 'candidate:1 1 udp 2122260223 4b1c7a2e-0000-4f00-a000-123456789abc.local 54321 typ host generation 0' });
        fire({ candidate: 'candidate:2 1 udp 2122260223 192.168.1.20 54322 typ host generation 0' });
        fire({ candidate: 'candidate:3 1 udp 1686052607 81.2.69.1 54323 typ srflx raddr 0.0.0.0 rport 0' });
        fire(null);
      }, 0);
    }
    close() {
      this.closed = true;
    }
  }
  const { p, fp } = await env({ globals: { RTCPeerConnection: FakePC } });
  const s = await fp.collectSignals();
  assert.deepEqual(configs, [{ iceServers: [] }]);
  assert.deepEqual(s.webrtc, { candidates: 2, mdns: true, ipv6: false });
  assert.ok(!JSON.stringify(s).includes('192.168.1.20'), 'no address leaves the browser');
  p.dispose();
});

test('strings are capped at 256 characters and arrays at 64 items', async () => {
  const { p, fp } = await env({ navigator: { userAgent: 'U'.repeat(5000), languages: Array.from({ length: 200 }, (_, i) => `x-${i}`) } });
  const s = await fp.collectSignals();
  assert.equal(s.ua.length, 256);
  assert.equal(s.languages.length, 64);
  p.dispose();
});

test('reportFingerprint posts { signals } to /api/fp and resolves { ok }', async () => {
  const { p, fp } = await env();
  assert.deepEqual(await fp.reportFingerprint(), { ok: true });
  const [call] = p.requests('/api/fp');
  assert.equal(call.method, 'POST');
  assert.deepEqual(Object.keys(call.body), ['signals']);
  assert.equal(call.body.signals.v, 1);
  assert.equal(call.headers['content-type'], 'application/json');
  assert.equal(call.init.credentials, 'same-origin');
  p.dispose();
  for (const r of [reply(500, { error: 'x' }), reply(429, { retry_after: 60 }), reply(403, null)]) {
    const e = await env({ fetch: { 'POST /api/fp': r } });
    assert.deepEqual(await e.fp.reportFingerprint(), { ok: false });
    e.p.dispose();
  }
});

await run();
