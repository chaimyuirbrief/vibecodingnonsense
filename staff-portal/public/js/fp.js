// fp.js — client fingerprint signals (CONTRACTS §10.1, B §6).
//
// Exports:
//   collectSignals({ deadlineMs = 1500 }) → Promise<signals>   never rejects
//   reportFingerprint({ deadlineMs })     → Promise<{ ok }>     never rejects
//   PROBE_NAMES                           the probes, in the order they run
//
// Every probe runs in its own try/catch and is raced against ONE overall
// deadline. A probe that throws or does not finish in time is named in
// `signals.blocked` — a browser that blocks a probe still loads the page
// normally, and the absence is itself a signal (B §6).
//
// What is NOT collected: no network requests besides the one POST to
// /api/fp, no STUN (WebRTC gathers host candidates only and only their count
// and kind leave the browser), nothing written to storage except a probe key
// that is removed immediately.
//
// No imports and no module-level state: every shell that reports a
// fingerprint (login, request, invite) may load this file.

const MAX_STR = 256;
const MAX_ARR = 64;

const FONT_LIST = [
  'Arial', 'Arial Black', 'Arial Narrow', 'Avenir', 'Avenir Next', 'Calibri', 'Cambria', 'Candara',
  'Cantarell', 'Comic Sans MS', 'Consolas', 'Courier New', 'DejaVu Sans', 'DejaVu Sans Mono',
  'Droid Sans', 'Fira Sans', 'Franklin Gothic Medium', 'Futura', 'Garamond', 'Geneva', 'Georgia',
  'Gill Sans', 'Helvetica', 'Helvetica Neue', 'Impact', 'Liberation Sans', 'Lucida Console',
  'Lucida Grande', 'Menlo', 'Monaco', 'Noto Sans', 'Optima', 'Palatino', 'Roboto', 'Segoe UI',
  'SF Pro Text', 'Source Sans Pro', 'Tahoma', 'Times New Roman', 'Trebuchet MS', 'Ubuntu', 'Verdana',
];

function str(v) {
  return typeof v === 'string' ? v.slice(0, MAX_STR) : v === null || v === undefined ? '' : String(v).slice(0, MAX_STR);
}

function num(v) {
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}

function strList(v) {
  return Array.isArray(v) || (v && typeof v.length === 'number') ? Array.from(v).slice(0, MAX_ARR).map(str) : [];
}

async function sha256Hex(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(text)));
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');
}

function canvas2d() {
  const c = document.createElement('canvas');
  c.width = 240;
  c.height = 60;
  const g = c.getContext('2d');
  if (!g) throw new Error('2d context unavailable');
  return { c, g };
}

// Each probe returns a partial signals object. `ctx` carries facts between
// probes (the WebGL renderer feeds the automation tells).
const PROBES = [
  ['navigator', () => {
    const n = navigator;
    return { ua: str(n.userAgent), platform: str(n.platform), vendor: str(n.vendor), language: str(n.language), languages: strList(n.languages) };
  }],
  ['uaData', () => {
    const d = navigator.userAgentData;
    if (!d) return { uaData: null };
    const brands = Array.isArray(d.brands) ? d.brands.slice(0, 16).map((b) => ({ brand: str(b.brand), version: str(b.version) })) : [];
    return { uaData: { brands, mobile: !!d.mobile, platform: str(d.platform) } };
  }],
  ['tz', () => ({ tz: str(Intl.DateTimeFormat().resolvedOptions().timeZone), tzOffset: new Date().getTimezoneOffset() })],
  ['intl', () => {
    const o = new Intl.DateTimeFormat().resolvedOptions();
    const hc = new Intl.DateTimeFormat(undefined, { hour: 'numeric' }).resolvedOptions().hourCycle;
    return { intl: { locale: str(o.locale), calendar: str(o.calendar), numberingSystem: str(o.numberingSystem), hourCycle: str(hc) } };
  }],
  ['screen', () => {
    const s = window.screen;
    return { screen: { w: num(s.width), h: num(s.height), aw: num(s.availWidth), ah: num(s.availHeight), cd: num(s.colorDepth), dpr: num(window.devicePixelRatio) } };
  }],
  ['window', () => ({ window: { iw: num(window.innerWidth), ih: num(window.innerHeight), ow: num(window.outerWidth), oh: num(window.outerHeight) } })],
  ['hw', () => {
    const n = navigator;
    return { hw: { cores: num(n.hardwareConcurrency), memory: num(n.deviceMemory), touch: num(n.maxTouchPoints) ?? 0 } };
  }],
  ['media', () => {
    const mm = (q) => !!window.matchMedia(q).matches;
    const contrast = mm('(prefers-contrast: more)') ? 'more' : mm('(prefers-contrast: less)') ? 'less' : 'no-preference';
    const gamut = mm('(color-gamut: rec2020)') ? 'rec2020' : mm('(color-gamut: p3)') ? 'p3' : mm('(color-gamut: srgb)') ? 'srgb' : '';
    return {
      media: {
        dark: mm('(prefers-color-scheme: dark)'),
        reducedMotion: mm('(prefers-reduced-motion: reduce)'),
        contrast,
        pointerCoarse: mm('(pointer: coarse)'),
        hover: mm('(hover: hover)'),
        gamut,
        forcedColors: mm('(forced-colors: active)'),
      },
    };
  }],
  ['canvas', async () => {
    const { c, g } = canvas2d();
    g.textBaseline = 'top';
    g.font = '16px Arial';
    g.fillStyle = '#f60';
    g.fillRect(100, 1, 62, 20);
    g.fillStyle = '#069';
    g.fillText('Staff portal ✓ 1.0 \u{1F525}', 2, 15);
    g.fillStyle = 'rgba(102, 204, 0, 0.7)';
    g.fillText('Staff portal ✓ 1.0 \u{1F525}', 4, 17);
    g.globalCompositeOperation = 'multiply';
    g.fillStyle = 'rgb(255,0,255)';
    g.beginPath();
    g.arc(50, 50, 50, 0, 6.283185307179586, true);
    g.closePath();
    g.fill();
    return { canvas: await sha256Hex(c.toDataURL()) };
  }],
  ['webgl', async (ctx) => {
    const c = document.createElement('canvas');
    const gl = c.getContext('webgl') || c.getContext('experimental-webgl');
    if (!gl) return { webgl: null };
    const dbg = gl.getExtension('WEBGL_debug_renderer_info');
    const vendor = str(dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR));
    const renderer = str(dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER));
    ctx.renderer = renderer;
    const params = [
      gl.VERSION, gl.SHADING_LANGUAGE_VERSION, gl.MAX_TEXTURE_SIZE, gl.MAX_RENDERBUFFER_SIZE, gl.MAX_VIEWPORT_DIMS,
      gl.ALIASED_LINE_WIDTH_RANGE, gl.ALIASED_POINT_SIZE_RANGE, gl.MAX_VERTEX_ATTRIBS, gl.MAX_VARYING_VECTORS,
      gl.MAX_COMBINED_TEXTURE_IMAGE_UNITS, gl.MAX_FRAGMENT_UNIFORM_VECTORS, gl.MAX_VERTEX_UNIFORM_VECTORS,
    ].map((p) => {
      try {
        const v = gl.getParameter(p);
        return v && typeof v === 'object' && typeof v.length === 'number' ? Array.from(v).join(',') : String(v);
      } catch {
        return '';
      }
    });
    const exts = (gl.getSupportedExtensions() || []).join(',');
    return { webgl: { vendor, renderer, hash: await sha256Hex([vendor, renderer, ...params, exts].join('|')) } };
  }],
  ['audio', async () => {
    const AC = window.OfflineAudioContext || window.webkitOfflineAudioContext;
    if (!AC) throw new Error('no OfflineAudioContext');
    const ac = new AC(1, 5000, 44100);
    const osc = ac.createOscillator();
    osc.type = 'triangle';
    osc.frequency.value = 10000;
    const comp = ac.createDynamicsCompressor();
    comp.threshold.value = -50;
    comp.knee.value = 40;
    comp.ratio.value = 12;
    comp.attack.value = 0;
    comp.release.value = 0.25;
    osc.connect(comp);
    comp.connect(ac.destination);
    osc.start(0);
    const buffer = await ac.startRendering();
    const data = buffer.getChannelData(0);
    let sum = 0;
    for (let i = 4500; i < data.length; i++) sum += data[i] < 0 ? -data[i] : data[i];
    return { audio: await sha256Hex(sum.toString()) };
  }],
  ['fonts', () => {
    const { g } = canvas2d();
    const text = 'mmmmmmmmmmlli1WQ@#';
    const bases = ['monospace', 'sans-serif', 'serif'];
    const base = {};
    for (const b of bases) {
      g.font = `72px ${b}`;
      base[b] = g.measureText(text).width;
    }
    const found = [];
    for (const f of FONT_LIST) {
      for (const b of bases) {
        g.font = `72px "${f}", ${b}`;
        if (g.measureText(text).width !== base[b]) {
          found.push(f);
          break;
        }
      }
    }
    return { fonts: found.slice(0, MAX_ARR) };
  }],
  ['storage', async () => {
    const out = { cookies: !!navigator.cookieEnabled, local: false, session: false, idb: false, quotaMb: null };
    try {
      window.localStorage.setItem('__fp_probe', '1');
      window.localStorage.removeItem('__fp_probe');
      out.local = true;
    } catch {
      out.local = false;
    }
    try {
      window.sessionStorage.setItem('__fp_probe', '1');
      window.sessionStorage.removeItem('__fp_probe');
      out.session = true;
    } catch {
      out.session = false;
    }
    try {
      out.idb = typeof window.indexedDB === 'object' && window.indexedDB !== null;
    } catch {
      out.idb = false;
    }
    if (navigator.storage && typeof navigator.storage.estimate === 'function') {
      const e = await navigator.storage.estimate();
      out.quotaMb = num(e && e.quota) === null ? null : Math.round(e.quota / 1048576);
    }
    return { storage: out };
  }],
  ['net', () => {
    const c = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    if (!c) return { net: null };
    return { net: { type: str(c.effectiveType || c.type), downlink: num(c.downlink), rtt: num(c.rtt), saveData: !!c.saveData } };
  }],
  ['perms', async () => {
    const p = navigator.permissions;
    if (!p || typeof p.query !== 'function') return { perms: null };
    const out = {};
    await Promise.all(
      ['notifications', 'geolocation', 'camera', 'microphone'].map(async (name) => {
        try {
          out[name] = str((await p.query({ name })).state);
        } catch {
          out[name] = 'error';
        }
      }),
    );
    return { perms: out };
  }],
  // Host candidates only: NO iceServers, so nothing leaves the machine and the
  // CSP (connect-src 'self') is not challenged. Only counts are reported.
  ['webrtc', () => new Promise((resolve, reject) => {
    const PC = window.RTCPeerConnection || window.webkitRTCPeerConnection;
    if (typeof PC !== 'function') {
      resolve({ webrtc: null });
      return;
    }
    const pc = new PC({ iceServers: [] });
    const addrs = new Set();
    let settled = false;
    let timer = null;
    const finish = (err) => {
      if (settled) return;
      settled = true;
      if (timer !== null) clearTimeout(timer);
      try {
        pc.close();
      } catch {
        // Already closed.
      }
      if (err) {
        reject(err);
        return;
      }
      const list = [...addrs];
      resolve({ webrtc: { candidates: list.length, mdns: list.some((a) => a.endsWith('.local')), ipv6: list.some((a) => a.includes(':')) } });
    };
    timer = setTimeout(() => finish(null), 800);
    pc.onicecandidate = (e) => {
      if (!e || !e.candidate) {
        finish(null);
        return;
      }
      const parts = String(e.candidate.candidate || '').split(' ');
      if (parts[7] === 'host' && parts[4]) addrs.add(parts[4]);
    };
    pc.createDataChannel('fp');
    pc.createOffer().then((o) => pc.setLocalDescription(o)).catch((err) => finish(err || new Error('offer failed')));
  })],
  ['math', async () => {
    const M = Math;
    const values = [
      M.acos(0.123124234234234242), M.acosh(1e308), M.asin(0.123124234234234242), M.asinh(1), M.atanh(0.5),
      M.atan(2), M.sin(-1e300), M.sinh(1), M.cos(10.000000000123), M.cosh(1), M.tan(-1e300), M.tanh(1),
      M.exp(1), M.expm1(1), M.log1p(10), M.cbrt(100), M.pow(M.PI, -100), M.log(M.E * 7),
    ];
    return { math: await sha256Hex(values.map(String).join(',')) };
  }],
  ['features', () => {
    const w = window;
    const n = navigator;
    return {
      features: {
        serviceWorker: 'serviceWorker' in n,
        webgl2: typeof w.WebGL2RenderingContext === 'function',
        webgpu: 'gpu' in n,
        wasm: typeof w.WebAssembly === 'object',
        sharedArrayBuffer: typeof w.SharedArrayBuffer === 'function',
        bluetooth: 'bluetooth' in n,
        usb: 'usb' in n,
        hid: 'hid' in n,
        serial: 'serial' in n,
        credentials: 'credentials' in n,
        publicKeyCredential: typeof w.PublicKeyCredential === 'function',
        paymentRequest: typeof w.PaymentRequest === 'function',
        notification: typeof w.Notification === 'function',
        speechSynthesis: 'speechSynthesis' in w,
        offscreenCanvas: typeof w.OffscreenCanvas === 'function',
        intlSegmenter: typeof Intl.Segmenter === 'function',
        share: 'share' in n,
        wakeLock: 'wakeLock' in n,
        vibrate: 'vibrate' in n,
        xr: 'xr' in n,
        touchEvents: 'ontouchstart' in w,
        pdfViewer: !!n.pdfViewerEnabled,
      },
    };
  }],
];

// Named automation tells (CONTRACTS §10.1). Runs after the other probes so
// it can use the WebGL renderer.
function automationTells(ctx) {
  const tells = [];
  const n = navigator;
  const ua = str(n.userAgent);
  if (n.webdriver === true) tells.push('webdriver');
  if (/HeadlessChrome/i.test(ua)) tells.push('headless-ua');
  const desktopChrome = /Chrome\//.test(ua) && !/Mobile|Android|Edg\/|OPR\//.test(ua);
  if (desktopChrome && n.plugins && n.plugins.length === 0) tells.push('no-plugins');
  if (window.outerWidth === 0 && window.outerHeight === 0) tells.push('zero-outer');
  const docKeys = Object.getOwnPropertyNames(document);
  if (docKeys.some((k) => /^\$?cdc_|^\$wdc_/.test(k))) tells.push('cdc');
  const winKeys = Object.getOwnPropertyNames(window);
  const all = docKeys.concat(winKeys);
  if (all.some((k) => /^__(webdriver|selenium|driver|fxdriver)_/.test(k) || k === '_Selenium_IDE_Recorder' || k === 'callSelenium' || k === '_selenium')) tells.push('selenium');
  if (all.some((k) => k === '_phantom' || k === 'callPhantom' || k === '__nightmare')) tells.push('phantom');
  if (ctx.renderer && /SwiftShader/i.test(ctx.renderer)) tells.push('swiftshader');
  if (ctx.renderer && /llvmpipe/i.test(ctx.renderer)) tells.push('llvmpipe');
  return tells;
}

export const PROBE_NAMES = PROBES.map(([name]) => name).concat('automation');

function clock() {
  try {
    return typeof performance === 'object' && performance && typeof performance.now === 'function' ? performance.now() : Date.now();
  } catch {
    return 0;
  }
}

export async function collectSignals({ deadlineMs = 1500 } = {}) {
  const started = clock();
  const signals = { v: 1 };
  const blocked = [];
  try {
    const ms = typeof deadlineMs === 'number' && deadlineMs > 0 ? deadlineMs : 1500;
    const TIMEOUT = {};
    let timer = null;
    const deadline = new Promise((resolve) => {
      timer = setTimeout(() => resolve(TIMEOUT), ms);
    });
    const ctx = {};
    const results = await Promise.all(
      PROBES.map(async ([name, run]) => {
        try {
          const value = await Promise.race([Promise.resolve().then(() => run(ctx)), deadline]);
          if (value === TIMEOUT || !value || typeof value !== 'object') return { name, ok: false };
          return { name, ok: true, value };
        } catch {
          return { name, ok: false };
        }
      }),
    );
    clearTimeout(timer);
    for (const r of results) {
      if (r.ok) Object.assign(signals, r.value);
      else blocked.push(r.name);
    }
    try {
      signals.automation = automationTells(ctx).slice(0, MAX_ARR);
    } catch {
      blocked.push('automation');
    }
  } catch {
    // Something outside the probes failed (a timer, Promise itself). Report
    // what we have; the page must never notice.
    if (!blocked.includes('collect')) blocked.push('collect');
  }
  signals.blocked = blocked.slice(0, MAX_ARR);
  // Integer arithmetic only: the probes above may have found Math itself
  // tampered with, and this line must not be the thing that throws.
  const elapsed = clock() - started;
  signals.elapsedMs = typeof elapsed === 'number' && elapsed >= 0 && elapsed < 1e9 ? (elapsed + 0.5) | 0 : 0;
  return signals;
}

// POST /api/fp { signals } → { ok }. Never throws, never blocks the page.
export async function reportFingerprint({ deadlineMs = 1500 } = {}) {
  try {
    const signals = await collectSignals({ deadlineMs });
    const res = await fetch('/api/fp', {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      credentials: 'same-origin',
      cache: 'no-store',
      body: JSON.stringify({ signals }),
    });
    return { ok: !!(res && res.ok) };
  } catch {
    return { ok: false };
  }
}
