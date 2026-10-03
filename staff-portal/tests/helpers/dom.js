// A minimal DOM for testing the real page scripts under plain node (A §13.4).
//
// The pages are ES modules (public/js/<page>.js) that build nodes with
// textContent — never HTML strings — so a small, honest DOM is enough. The
// tree is PARSED FROM THE REAL HTML FILE: ids, classes, the `hidden`
// attribute, label[for], input types and values are what the markup says,
// so a test never asserts against initial state it invented.
//
//   import { loadPage, reply } from '../helpers/dom.js';
//
//   const page = await loadPage('login.html', {
//     url: 'https://staff.example.com/login?next=/admin',
//     fetch: {
//       'GET /api/auth/whoami': [reply(200, { authenticated: false }), reply(200, { authenticated: true })],
//       'POST /api/auth/login': reply(200, { ok: true, pinned: null }),
//       'POST /api/fp': reply(200, { ok: true }),
//     },
//     webauthn: { get: async (opts) => fakeAssertion },   // omit → browser without passkeys
//   });
//   page.fill('identifier', 'jane@acme.com');
//   await page.submit('form-password');          // dispatches submit, then drains
//   page.visible('pane-choose');                 // → true/false (hidden attr/class on it or an ancestor)
//   page.text('otp-sent');                       // normalised textContent
//   page.requests('/api/auth/login');            // fetch calls recorded: { method, path, url, body, headers }
//   page.calls.nav;                              // [{ type: 'assign'|'replace'|'reload'|'link'|'form', url }]
//   page.dispose();                              // restores globals, clears timers (loadPage also does it)
//
// loadPage(htmlFile, scriptFile?, opts?)
//   htmlFile    'login.html' (relative to public/) or an absolute path
//   scriptFile  defaults to the page's <script type="module" src="/js/…">
//   opts.url        page URL (default https://staff.example.com/<page>);
//                   opts.location (a string or { href }) is accepted too
//   opts.fetch      { 'METHOD /path': reply | [reply, …] | (req) => reply }
//                   keys may include the query string ('GET /api/x?y=1'),
//                   which wins over the bare path. Arrays are SEQUENCES: each
//                   call takes the next reply and the last one repeats (whoami
//                   401 then 200 — A §13.4). Unstubbed calls answer 404 and
//                   are listed in page.calls.unmatched.
//                   reply(status, body, { headers, networkError, delayMs })
//   opts.navigator  overrides merged into the navigator stub (userAgent, …)
//   opts.webauthn   { get(opts), create(opts) } → passkeys supported and
//                   navigator.credentials uses them; omit → unsupported
//   opts.localStorage 'throw' → every storage accessor throws (private mode)
//   opts.matchMedia { '(prefers-color-scheme: dark)': true, … }
//   opts.globals    extra globals to install (screen, RTCPeerConnection, …)
//   opts.import     false → build the DOM and globals but import nothing
//   opts.live       a tests/helpers/http.js Client (or a (url, init) =>
//                   Response handler from live.js liveFetch): every fetch no
//                   opts.fetch route answers goes to the REAL worker with
//                   that Client's cookies, IP and cf. Records of those calls
//                   carry live: true, status and response (parsed JSON).
//                   See tests/helpers/live.js (openLive navigates first).
//
// Returns the page object: document, window, location, module (the imported
// namespace), $(id), text(id), visible(id), fill(id, value), check(id, on),
// click(idOrEl), submit(formIdOrEl), key(idOrEl, key), drain(rounds),
// requests(pathPrefix?, method?), setRoute(key, reply), setVisibility(state),
// fireTimers(minDelayMs), calls { fetch, nav, unmatched, clipboard, dialogs,
// timers, scrolls, execCommand }, dispose().
//
// What it deliberately does NOT do: layout, CSS, innerHTML/outerHTML/
// insertAdjacentHTML (they THROW, so a page that uses them fails its test),
// canvas (getContext is absent — fp.js must survive that), real navigation.
//
// Timers: setTimeout/setInterval pass through to node's, but every timer is
// recorded (page.calls.timers) and those of 5 s or more are unref'd so a
// page's polling never keeps the test process alive; fireTimers(ms) runs the
// pending ones with a delay ≥ ms immediately (e.g. a 15 s poll).

import { readFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
export const PUBLIC_DIR = path.resolve(here, '..', '..', 'public');

const realSetTimeout = globalThis.setTimeout;
const realClearTimeout = globalThis.clearTimeout;
const realSetInterval = globalThis.setInterval;
const realClearInterval = globalThis.clearInterval;
const realSetImmediate = globalThis.setImmediate;

export const SVG_NS = 'http://www.w3.org/2000/svg';
export const HTML_NS = 'http://www.w3.org/1999/xhtml';

// ------------------------------------------------------------ parsing ----

const VOID = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'source', 'track', 'wbr']);
const RAW = new Set(['script', 'style', 'textarea', 'title']);
const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', rsquo: '’', lsquo: '‘', ldquo: '“', rdquo: '”', hellip: '…', mdash: '—', ndash: '–', middot: '·', copy: '©', times: '×', rarr: '→', larr: '←', bull: '•' };

export function decodeEntities(s) {
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e) => {
    if (e[0] === '#') {
      const cp = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return Number.isFinite(cp) ? String.fromCodePoint(cp) : m;
    }
    return Object.hasOwn(ENTITIES, e.toLowerCase()) ? ENTITIES[e.toLowerCase()] : m;
  });
}

// A small tokenizer: tags, attributes, text, comments, doctype, raw-text
// elements. Returns a token list; parseHtml builds the tree from it. Also
// used by tests/pages/static.test.mjs to audit the markup.
export function tokenizeHtml(src) {
  const tokens = [];
  let i = 0;
  const n = src.length;
  while (i < n) {
    if (src.startsWith('<!--', i)) {
      const end = src.indexOf('-->', i + 4);
      const stop = end < 0 ? n : end + 3;
      tokens.push({ type: 'comment', text: src.slice(i + 4, end < 0 ? n : end), start: i });
      i = stop;
      continue;
    }
    if (src.startsWith('<!', i) || src.startsWith('<?', i)) {
      const end = src.indexOf('>', i);
      tokens.push({ type: 'doctype', text: src.slice(i, end < 0 ? n : end + 1), start: i });
      i = end < 0 ? n : end + 1;
      continue;
    }
    if (src[i] === '<' && src[i + 1] === '/') {
      const end = src.indexOf('>', i);
      const name = src.slice(i + 2, end < 0 ? n : end).trim().toLowerCase();
      tokens.push({ type: 'end', name, start: i });
      i = end < 0 ? n : end + 1;
      continue;
    }
    if (src[i] === '<' && /[a-zA-Z]/.test(src[i + 1] || '')) {
      let j = i + 1;
      while (j < n && /[^\s/>]/.test(src[j])) j++;
      const rawName = src.slice(i + 1, j);
      const name = rawName.toLowerCase();
      const attrs = [];
      let selfClose = false;
      while (j < n) {
        while (j < n && /\s/.test(src[j])) j++;
        if (src[j] === '>') {
          j++;
          break;
        }
        if (src[j] === '/' && src[j + 1] === '>') {
          selfClose = true;
          j += 2;
          break;
        }
        if (src[j] === '/') {
          j++;
          continue;
        }
        let k = j;
        while (k < n && /[^\s=/>]/.test(src[k])) k++;
        const aname = src.slice(j, k);
        j = k;
        while (j < n && /\s/.test(src[j])) j++;
        let value = '';
        let hasValue = false;
        if (src[j] === '=') {
          hasValue = true;
          j++;
          while (j < n && /\s/.test(src[j])) j++;
          const q = src[j];
          if (q === '"' || q === "'") {
            const end = src.indexOf(q, j + 1);
            value = src.slice(j + 1, end < 0 ? n : end);
            j = end < 0 ? n : end + 1;
          } else {
            let e = j;
            while (e < n && /[^\s>]/.test(src[e])) e++;
            value = src.slice(j, e);
            j = e;
          }
        }
        if (aname) attrs.push({ name: aname, value: decodeEntities(value), hasValue });
      }
      tokens.push({ type: 'start', name, rawName, attrs, selfClose, start: i });
      i = j;
      if (RAW.has(name) && !selfClose) {
        const close = src.toLowerCase().indexOf(`</${name}`, i);
        const stop = close < 0 ? n : close;
        const text = src.slice(i, stop);
        if (text) tokens.push({ type: 'text', text: name === 'script' || name === 'style' ? text : decodeEntities(text), raw: true, start: i });
        i = stop;
      }
      continue;
    }
    let j = src.indexOf('<', i + 1);
    if (j < 0) j = n;
    tokens.push({ type: 'text', text: decodeEntities(src.slice(i, j)), start: i });
    i = j;
  }
  return tokens;
}

// ------------------------------------------------------------- events ----

export class StubEvent {
  constructor(type, init = {}) {
    this.type = type;
    this.bubbles = !!init.bubbles;
    this.cancelable = init.cancelable !== false;
    this.defaultPrevented = false;
    this.target = null;
    this.currentTarget = null;
    this.propagationStopped = false;
    Object.assign(this, init.detail !== undefined ? { detail: init.detail } : {});
    if (init.key !== undefined) this.key = init.key;
    if (init.submitter !== undefined) this.submitter = init.submitter;
  }
  preventDefault() {
    if (this.cancelable) this.defaultPrevented = true;
  }
  stopPropagation() {
    this.propagationStopped = true;
  }
  stopImmediatePropagation() {
    this.propagationStopped = true;
  }
}

class EventHost {
  constructor() {
    this._listeners = new Map();
  }
  addEventListener(type, fn, opts) {
    if (typeof fn !== 'function' && !(fn && typeof fn.handleEvent === 'function')) return;
    const list = this._listeners.get(type) || [];
    if (list.some((l) => l.fn === fn)) return;
    list.push({ fn, once: !!(opts && typeof opts === 'object' && opts.once) });
    this._listeners.set(type, list);
  }
  removeEventListener(type, fn) {
    const list = this._listeners.get(type);
    if (list) this._listeners.set(type, list.filter((l) => l.fn !== fn));
  }
  _fire(evt) {
    const list = (this._listeners.get(evt.type) || []).slice();
    for (const l of list) {
      if (l.once) this.removeEventListener(evt.type, l.fn);
      evt.currentTarget = this;
      const ret = typeof l.fn === 'function' ? l.fn.call(this, evt) : l.fn.handleEvent(evt);
      if (ret && typeof ret.catch === 'function') ret.catch((e) => this._ownerWindow()?._pageErrors.push(e));
    }
  }
  _ownerWindow() {
    return null;
  }
}

// -------------------------------------------------------------- nodes ----

class StubNode extends EventHost {
  constructor(doc) {
    super();
    this.ownerDocument = doc;
    this.parentNode = null;
    this.childNodes = [];
  }
  get parentElement() {
    return this.parentNode && this.parentNode.nodeType === 1 ? this.parentNode : null;
  }
  get firstChild() {
    return this.childNodes[0] || null;
  }
  get lastChild() {
    return this.childNodes[this.childNodes.length - 1] || null;
  }
  get nextSibling() {
    if (!this.parentNode) return null;
    const sibs = this.parentNode.childNodes;
    return sibs[sibs.indexOf(this) + 1] || null;
  }
  get previousSibling() {
    if (!this.parentNode) return null;
    const sibs = this.parentNode.childNodes;
    return sibs[sibs.indexOf(this) - 1] || null;
  }
  get isConnected() {
    let n = this;
    while (n.parentNode) n = n.parentNode;
    return n === this.ownerDocument;
  }
  _ownerWindow() {
    return this.ownerDocument ? this.ownerDocument.defaultView : null;
  }
  contains(other) {
    for (let n = other; n; n = n.parentNode) if (n === this) return true;
    return false;
  }
  _adopt(child) {
    if (child === null || child === undefined) throw new TypeError('appendChild: node is null');
    if (typeof child !== 'object' || typeof child.nodeType !== 'number') throw new TypeError('appendChild: not a Node');
    if (child.contains && child.contains(this)) throw new Error('HierarchyRequestError: cannot insert an ancestor');
    if (child.nodeType === 11) {
      const kids = child.childNodes.slice();
      child.childNodes = [];
      for (const k of kids) k.parentNode = null;
      return kids;
    }
    if (child.parentNode) child.parentNode.removeChild(child);
    return [child];
  }
  appendChild(child) {
    for (const c of this._adopt(child)) {
      c.parentNode = this;
      this.childNodes.push(c);
    }
    return child;
  }
  insertBefore(child, ref) {
    if (!ref) return this.appendChild(child);
    const nodes = this._adopt(child);
    const idx = this.childNodes.indexOf(ref);
    if (idx < 0) throw new Error('NotFoundError: reference node is not a child');
    for (const c of nodes) c.parentNode = this;
    this.childNodes.splice(idx, 0, ...nodes);
    return child;
  }
  removeChild(child) {
    const idx = this.childNodes.indexOf(child);
    if (idx < 0) throw new Error('NotFoundError: not a child');
    this.childNodes.splice(idx, 1);
    child.parentNode = null;
    return child;
  }
  replaceChild(next, old) {
    this.insertBefore(next, old);
    return this.removeChild(old);
  }
  _toNodes(items) {
    return items.flatMap((it) => (typeof it === 'object' && it !== null && typeof it.nodeType === 'number' ? [it] : [this.ownerDocument.createTextNode(String(it))]));
  }
  append(...items) {
    for (const n of this._toNodes(items)) this.appendChild(n);
  }
  prepend(...items) {
    const first = this.firstChild;
    for (const n of this._toNodes(items)) this.insertBefore(n, first && first.parentNode === this ? first : null);
  }
  replaceChildren(...items) {
    for (const c of this.childNodes.slice()) this.removeChild(c);
    this.append(...items);
  }
  remove() {
    if (this.parentNode) this.parentNode.removeChild(this);
  }
  before(...items) {
    if (!this.parentNode) return;
    for (const n of this._toNodes(items)) this.parentNode.insertBefore(n, this);
  }
  after(...items) {
    if (!this.parentNode) return;
    const next = this.nextSibling;
    for (const n of this._toNodes(items)) this.parentNode.insertBefore(n, next);
  }
  replaceWith(...items) {
    if (!this.parentNode) return;
    this.before(...items);
    this.remove();
  }
  get textContent() {
    return this.childNodes.map((c) => c.textContent).join('');
  }
  set textContent(v) {
    for (const c of this.childNodes.slice()) this.removeChild(c);
    const s = v === null || v === undefined ? '' : String(v);
    if (s) this.appendChild(this.ownerDocument.createTextNode(s));
  }
  dispatchEvent(evt) {
    if (!evt.target) evt.target = this;
    const path = [];
    for (let n = this; n; n = n.parentNode) path.push(n);
    if (evt.bubbles && this.isConnected && this.ownerDocument.defaultView) path.push(this.ownerDocument.defaultView);
    for (const n of evt.bubbles ? path : [this]) {
      n._fire(evt);
      if (evt.propagationStopped) break;
    }
    return !evt.defaultPrevented;
  }
}

class StubText extends StubNode {
  constructor(doc, data) {
    super(doc);
    this.nodeType = 3;
    this.nodeName = '#text';
    this.data = String(data);
  }
  get textContent() {
    return this.data;
  }
  set textContent(v) {
    this.data = v === null || v === undefined ? '' : String(v);
  }
  get nodeValue() {
    return this.data;
  }
}

class StubFragment extends StubNode {
  constructor(doc) {
    super(doc);
    this.nodeType = 11;
    this.nodeName = '#document-fragment';
  }
  get children() {
    return this.childNodes.filter((c) => c.nodeType === 1);
  }
  querySelector(sel) {
    return querySelectorAll(this, sel)[0] || null;
  }
  querySelectorAll(sel) {
    return querySelectorAll(this, sel);
  }
}

function toKebab(s) {
  return s.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`);
}

function toCamel(s) {
  return s.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
}

const REFLECT = {
  id: 'id',
  className: 'class',
  htmlFor: 'for',
  name: 'name',
  placeholder: 'placeholder',
  title: 'title',
  href: 'href',
  src: 'src',
  alt: 'alt',
  rel: 'rel',
  target: 'target',
  role: 'role',
  autocomplete: 'autocomplete',
  inputMode: 'inputmode',
  pattern: 'pattern',
  min: 'min',
  max: 'max',
  step: 'step',
  lang: 'lang',
  dir: 'dir',
  action: 'action',
  method: 'method',
  enterKeyHint: 'enterkeyhint',
  autocapitalize: 'autocapitalize',
  dateTime: 'datetime',
  scope: 'scope',
  colSpan: 'colspan',
};

const VALUE_ATTR_TYPES = new Set(['checkbox', 'radio', 'hidden', 'button', 'submit', 'reset', 'image']);

const BOOLEAN_ATTRS = { hidden: 'hidden', disabled: 'disabled', required: 'required', readOnly: 'readonly', multiple: 'multiple', autofocus: 'autofocus', noValidate: 'novalidate', open: 'open', selected: 'selected' };

class StubClassList {
  constructor(el) {
    this.el = el;
  }
  _get() {
    return (this.el.getAttribute('class') || '').split(/\s+/).filter(Boolean);
  }
  _set(list) {
    this.el.setAttribute('class', list.join(' '));
  }
  add(...names) {
    const l = this._get();
    for (const n of names) if (!l.includes(n)) l.push(n);
    this._set(l);
  }
  remove(...names) {
    this._set(this._get().filter((c) => !names.includes(c)));
  }
  contains(name) {
    return this._get().includes(name);
  }
  toggle(name, force) {
    const on = force === undefined ? !this.contains(name) : !!force;
    if (on) this.add(name);
    else this.remove(name);
    return on;
  }
  replace(a, b) {
    if (!this.contains(a)) return false;
    this._set(this._get().map((c) => (c === a ? b : c)));
    return true;
  }
  get length() {
    return this._get().length;
  }
  get value() {
    return this.el.getAttribute('class') || '';
  }
  [Symbol.iterator]() {
    return this._get()[Symbol.iterator]();
  }
  toString() {
    return this.value;
  }
}

function makeStyle() {
  const props = new Map();
  return new Proxy(
    {
      setProperty(k, v) {
        props.set(k, String(v));
      },
      removeProperty(k) {
        props.delete(k);
      },
      getPropertyValue(k) {
        return props.get(k) || '';
      },
    },
    {
      get(t, k) {
        if (k in t) return t[k];
        if (k === 'cssText') throw new Error('style.cssText is not allowed (CSP: no inline styles)');
        return typeof k === 'string' ? props.get(k) || '' : undefined;
      },
      set(t, k, v) {
        if (k === 'cssText') throw new Error('style.cssText is not allowed (CSP: no inline styles)');
        props.set(k, String(v));
        return true;
      },
    },
  );
}

class StubElement extends StubNode {
  constructor(doc, tagName, ns = HTML_NS) {
    super(doc);
    this.nodeType = 1;
    this.namespaceURI = ns;
    this.localName = ns === HTML_NS ? tagName.toLowerCase() : tagName;
    this.tagName = ns === HTML_NS ? tagName.toUpperCase() : tagName;
    this.nodeName = this.tagName;
    this._attrs = new Map();
    this._value = undefined;
    this._checked = undefined;
    this.style = makeStyle();
    this.classList = new StubClassList(this);
    const el = this;
    this.dataset = new Proxy(
      {},
      {
        get(_, k) {
          return typeof k === 'string' ? el.getAttribute(`data-${toKebab(k)}`) ?? undefined : undefined;
        },
        set(_, k, v) {
          el.setAttribute(`data-${toKebab(k)}`, String(v));
          return true;
        },
        deleteProperty(_, k) {
          el.removeAttribute(`data-${toKebab(k)}`);
          return true;
        },
        has(_, k) {
          return el.hasAttribute(`data-${toKebab(k)}`);
        },
        ownKeys() {
          return [...el._attrs.keys()].filter((a) => a.startsWith('data-')).map((a) => toCamel(a.slice(5)));
        },
        getOwnPropertyDescriptor(_, k) {
          return el.hasAttribute(`data-${toKebab(k)}`) ? { enumerable: true, configurable: true, value: el.getAttribute(`data-${toKebab(k)}`) } : undefined;
        },
      },
    );
    this.returnValue = '';
  }
  _norm(name) {
    return this.namespaceURI === HTML_NS ? String(name).toLowerCase() : String(name);
  }
  getAttribute(name) {
    const v = this._attrs.get(this._norm(name));
    return v === undefined ? null : v;
  }
  setAttribute(name, value) {
    const n = this._norm(name);
    if (n === 'style') throw new Error("setAttribute('style') is not allowed (CSP: no inline styles)");
    if (/^on/i.test(n)) throw new Error(`setAttribute('${n}') is not allowed (CSP: no inline handlers)`);
    this._attrs.set(n, String(value));
  }
  removeAttribute(name) {
    this._attrs.delete(this._norm(name));
  }
  hasAttribute(name) {
    return this._attrs.has(this._norm(name));
  }
  toggleAttribute(name, force) {
    const on = force === undefined ? !this.hasAttribute(name) : !!force;
    if (on) this._attrs.set(this._norm(name), '');
    else this.removeAttribute(name);
    return on;
  }
  getAttributeNames() {
    return [...this._attrs.keys()];
  }
  get attributes() {
    return [...this._attrs.entries()].map(([name, value]) => ({ name, value }));
  }
  get children() {
    return this.childNodes.filter((c) => c.nodeType === 1);
  }
  get childElementCount() {
    return this.children.length;
  }
  get firstElementChild() {
    return this.children[0] || null;
  }
  get lastElementChild() {
    const c = this.children;
    return c[c.length - 1] || null;
  }
  get nextElementSibling() {
    if (!this.parentNode) return null;
    const sibs = this.parentNode.childNodes.filter((c) => c.nodeType === 1);
    return sibs[sibs.indexOf(this) + 1] || null;
  }
  get previousElementSibling() {
    if (!this.parentNode) return null;
    const sibs = this.parentNode.childNodes.filter((c) => c.nodeType === 1);
    return sibs[sibs.indexOf(this) - 1] || null;
  }
  // HTML strings are forbidden by the CSP posture (B §10); fail loudly.
  get innerHTML() {
    throw new Error('innerHTML is not available in the test DOM — pages must not use it');
  }
  set innerHTML(_) {
    throw new Error('innerHTML is not allowed — build nodes with h()/textContent');
  }
  get outerHTML() {
    throw new Error('outerHTML is not available in the test DOM');
  }
  set outerHTML(_) {
    throw new Error('outerHTML is not allowed');
  }
  insertAdjacentHTML() {
    throw new Error('insertAdjacentHTML is not allowed');
  }
  get type() {
    const t = this.getAttribute('type');
    if (this.localName === 'input') return (t || 'text').toLowerCase();
    if (this.localName === 'button') return (t || 'submit').toLowerCase();
    return t || '';
  }
  set type(v) {
    this.setAttribute('type', v);
  }
  get value() {
    if (this.localName === 'select') {
      if (this._value !== undefined) return this._value;
      const opts = querySelectorAll(this, 'option');
      const sel = opts.find((o) => o.hasAttribute('selected')) || opts[0];
      return sel ? sel.value : '';
    }
    if (this.localName === 'option') return this.hasAttribute('value') ? this.getAttribute('value') : this.textContent.trim();
    if (this._value !== undefined) return this._value;
    if (this.localName === 'textarea') return this.textContent;
    return this.getAttribute('value') || '';
  }
  set value(v) {
    const s = v === null || v === undefined ? '' : String(v);
    // As in browsers: <option>.value, and the value of inputs in the "default"
    // and "default/on" modes (checkbox, radio, hidden, buttons), IS the
    // content attribute — so [value=…] selectors and select.value see it.
    if (this.localName === 'option' || (this.localName === 'input' && VALUE_ATTR_TYPES.has(this.type))) {
      this.setAttribute('value', s);
      return;
    }
    this._value = s;
  }
  get checked() {
    return this._checked !== undefined ? this._checked : this.hasAttribute('checked');
  }
  set checked(v) {
    this._checked = !!v;
    // A radio group: checking one unchecks the others with the same name in
    // the same form (or the document, outside a form), as browsers do.
    if (this._checked && this.localName === 'input' && this.type === 'radio' && this.getAttribute('name')) {
      const scope = this.closest('form') || this.ownerDocument;
      if (scope) {
        for (const other of querySelectorAll(scope, 'input')) {
          if (other !== this && other.type === 'radio' && other.getAttribute('name') === this.getAttribute('name')) other._checked = false;
        }
      }
    }
  }
  get maxLength() {
    const v = this.getAttribute('maxlength');
    return v === null ? -1 : Number(v);
  }
  set maxLength(v) {
    this.setAttribute('maxlength', String(v));
  }
  get tabIndex() {
    const v = this.getAttribute('tabindex');
    if (v !== null) return Number(v);
    return ['a', 'button', 'input', 'select', 'textarea'].includes(this.localName) ? 0 : -1;
  }
  set tabIndex(v) {
    this.setAttribute('tabindex', String(v));
  }
  get form() {
    return this.closest('form');
  }
  get labels() {
    if (!this.id || !this.ownerDocument) return [];
    return querySelectorAll(this.ownerDocument, 'label').filter((l) => l.getAttribute('for') === this.id);
  }
  get options() {
    return querySelectorAll(this, 'option');
  }
  get elements() {
    return querySelectorAll(this, 'input, select, textarea, button');
  }
  matches(sel) {
    return parseSelectorList(sel).some((complex) => matchComplex(this, complex));
  }
  closest(sel) {
    for (let n = this; n && n.nodeType === 1; n = n.parentNode) if (n.matches(sel)) return n;
    return null;
  }
  querySelector(sel) {
    return querySelectorAll(this, sel)[0] || null;
  }
  querySelectorAll(sel) {
    return querySelectorAll(this, sel);
  }
  getElementsByTagName(tag) {
    return querySelectorAll(this, tag);
  }
  getBoundingClientRect() {
    return { x: 0, y: 0, top: 0, left: 0, right: 0, bottom: 0, width: 0, height: 0 };
  }
  scrollIntoView(opts) {
    this.ownerDocument?._calls.scrolls.push({ id: this.id, opts });
  }
  focus() {
    const doc = this.ownerDocument;
    if (!doc || this.disabled) return;
    const prev = doc._active;
    if (prev === this) return;
    doc._active = this;
    if (prev && prev !== doc.body) prev._fire(new StubEvent('blur'));
    this._fire(new StubEvent('focus'));
    this.dispatchEvent(new StubEvent('focusin', { bubbles: true }));
  }
  blur() {
    const doc = this.ownerDocument;
    if (doc && doc._active === this) {
      doc._active = null;
      this._fire(new StubEvent('blur'));
    }
  }
  select() {}
  setSelectionRange() {}
  setCustomValidity(msg) {
    this.validationMessage = String(msg || '');
  }
  checkValidity() {
    return true;
  }
  reportValidity() {
    return true;
  }
  click() {
    if (this.disabled) return;
    const evt = new StubEvent('click', { bubbles: true, cancelable: true });
    const notPrevented = this.dispatchEvent(evt);
    if (!notPrevented) return;
    const doc = this.ownerDocument;
    if (this.localName === 'input' && (this.type === 'checkbox' || this.type === 'radio')) {
      if (this.type === 'checkbox') this.checked = !this.checked;
      else this.checked = true;
      this.dispatchEvent(new StubEvent('input', { bubbles: true }));
      this.dispatchEvent(new StubEvent('change', { bubbles: true }));
      return;
    }
    if ((this.localName === 'button' && this.type === 'submit') || (this.localName === 'input' && this.type === 'submit')) {
      const form = this.form;
      if (form) form.requestSubmit(this);
      return;
    }
    if (this.localName === 'summary' && this.parentNode && this.parentNode.localName === 'details') {
      const d = this.parentNode;
      d.toggleAttribute('open');
      d._fire(new StubEvent('toggle'));
      return;
    }
    const link = this.closest('a[href]');
    if (link && doc) doc._calls.nav.push({ type: 'link', url: link.getAttribute('href') });
  }
  requestSubmit(submitter) {
    const evt = new StubEvent('submit', { bubbles: true, cancelable: true, submitter: submitter || null });
    if (this.dispatchEvent(evt)) this.ownerDocument?._calls.nav.push({ type: 'form', url: this.getAttribute('action') || '(native form submit — missing preventDefault?)' });
  }
  submit() {
    this.ownerDocument?._calls.nav.push({ type: 'form', url: this.getAttribute('action') || '(form.submit())' });
  }
  reset() {
    for (const el of querySelectorAll(this, 'input, textarea, select')) {
      el._value = undefined;
      el._checked = undefined;
    }
  }
  // <dialog>
  showModal() {
    if (this.localName !== 'dialog') throw new Error('showModal on a non-dialog');
    this.setAttribute('open', '');
    this.ownerDocument?._calls.dialogs.push({ action: 'showModal', el: this });
  }
  show() {
    this.setAttribute('open', '');
  }
  close(returnValue) {
    if (returnValue !== undefined) this.returnValue = String(returnValue);
    const wasOpen = this.hasAttribute('open');
    this.removeAttribute('open');
    if (wasOpen) {
      this.ownerDocument?._calls.dialogs.push({ action: 'close', el: this });
      this._fire(new StubEvent('close'));
    }
  }
  // Canvas is deliberately absent: fp.js must survive a browser without it.
}

for (const [prop, attr] of Object.entries(REFLECT)) {
  Object.defineProperty(StubElement.prototype, prop, {
    get() {
      return this.getAttribute(attr) ?? '';
    },
    set(v) {
      this.setAttribute(attr, v === null || v === undefined ? '' : String(v));
    },
    configurable: true,
  });
}

for (const [prop, attr] of Object.entries(BOOLEAN_ATTRS)) {
  Object.defineProperty(StubElement.prototype, prop, {
    get() {
      return this.hasAttribute(attr);
    },
    set(v) {
      if (v) this._attrs.set(attr, '');
      else this._attrs.delete(attr);
    },
    configurable: true,
  });
}

// ---------------------------------------------------------- selectors ----

function parseCompound(s) {
  const c = { tag: null, id: null, classes: [], attrs: [], pseudos: [] };
  const re = /([a-zA-Z][\w-]*|\*)|#([\w-]+)|\.([\w-]+)|\[\s*([\w:-]+)\s*(?:([~^$*|]?=)\s*(?:"([^"]*)"|'([^']*)'|([^\]\s]*)))?\s*\]|:([\w-]+)(?:\(([^)]*)\))?/gy;
  let m;
  let pos = 0;
  while (pos < s.length) {
    re.lastIndex = pos;
    m = re.exec(s);
    if (!m) throw new Error(`test DOM: unsupported selector '${s}'`);
    pos = re.lastIndex;
    if (m[1]) c.tag = m[1] === '*' ? null : m[1].toLowerCase();
    else if (m[2]) c.id = m[2];
    else if (m[3]) c.classes.push(m[3]);
    else if (m[4]) c.attrs.push({ name: m[4].toLowerCase(), op: m[5] || null, value: m[6] ?? m[7] ?? m[8] ?? '' });
    else if (m[9]) c.pseudos.push({ name: m[9], arg: m[10] });
  }
  return c;
}

// Splits on `sep` characters that sit outside [...], (...) and quotes.
function splitTop(s, isSep) {
  const parts = [];
  let cur = '';
  let depth = 0;
  let quote = '';
  for (const ch of s) {
    if (quote) {
      cur += ch;
      if (ch === quote) quote = '';
      continue;
    }
    if (ch === '"' || ch === "'") quote = ch;
    else if (ch === '[' || ch === '(') depth++;
    else if (ch === ']' || ch === ')') depth--;
    if (depth === 0 && isSep(ch)) {
      parts.push(cur);
      parts.push(ch);
      cur = '';
      continue;
    }
    cur += ch;
  }
  parts.push(cur);
  return parts;
}

function parseSelectorList(sel) {
  return splitTop(String(sel), (ch) => ch === ',')
    .filter((p) => p !== ',')
    .map((part) => {
      const pieces = splitTop(part.trim(), (ch) => ch === '>' || /\s/.test(ch));
      const steps = [];
      let comb = ' ';
      for (const raw of pieces) {
        const t = raw.trim();
        if (!t) continue;
        if (t === '>') {
          comb = '>';
          continue;
        }
        steps.push({ comb, compound: parseCompound(t) });
        comb = ' ';
      }
      if (!steps.length) throw new Error(`test DOM: empty selector '${sel}'`);
      return steps;
    });
}

function matchCompound(el, c) {
  if (!el || el.nodeType !== 1) return false;
  if (c.tag && el.localName.toLowerCase() !== c.tag) return false;
  if (c.id && el.getAttribute('id') !== c.id) return false;
  for (const cls of c.classes) if (!el.classList.contains(cls)) return false;
  for (const a of c.attrs) {
    const v = el.getAttribute(a.name);
    if (v === null) return false;
    if (a.op === '=' && v !== a.value) return false;
    if (a.op === '^=' && !v.startsWith(a.value)) return false;
    if (a.op === '$=' && !v.endsWith(a.value)) return false;
    if (a.op === '*=' && !v.includes(a.value)) return false;
    if (a.op === '~=' && !v.split(/\s+/).includes(a.value)) return false;
  }
  for (const p of c.pseudos) {
    if (p.name === 'checked' && !el.checked) return false;
    if (p.name === 'disabled' && !el.disabled) return false;
    if (p.name === 'not' && el.matches(p.arg)) return false;
    if (!['checked', 'disabled', 'not'].includes(p.name)) throw new Error(`test DOM: unsupported pseudo-class :${p.name}`);
  }
  return true;
}

function matchComplex(el, steps, i = steps.length - 1) {
  if (!matchCompound(el, steps[i].compound)) return false;
  if (i === 0) return true;
  const comb = steps[i].comb;
  if (comb === '>') return matchComplex(el.parentNode, steps, i - 1);
  for (let p = el.parentNode; p && p.nodeType === 1; p = p.parentNode) if (matchComplex(p, steps, i - 1)) return true;
  return false;
}

function walk(root, fn) {
  for (const c of root.childNodes) {
    if (c.nodeType === 1) {
      fn(c);
      walk(c, fn);
    }
  }
}

function querySelectorAll(root, sel) {
  const list = parseSelectorList(sel);
  const out = [];
  walk(root, (el) => {
    if (list.some((steps) => matchComplex(el, steps))) out.push(el);
  });
  return out;
}

// ----------------------------------------------------------- document ----

class StubDocument extends StubNode {
  constructor() {
    super(null);
    this.ownerDocument = this;
    this.nodeType = 9;
    this.nodeName = '#document';
    this._active = null;
    this._visibility = 'visible';
    this.readyState = 'complete';
    this.cookie = '';
    this.defaultView = null;
    this._calls = { nav: [], scrolls: [], dialogs: [], execCommand: [] };
  }
  get documentElement() {
    return this.childNodes.find((c) => c.nodeType === 1) || null;
  }
  get head() {
    return this.documentElement ? this.documentElement.querySelector('head') : null;
  }
  get body() {
    return this.documentElement ? this.documentElement.querySelector('body') : null;
  }
  get title() {
    const t = this.documentElement && this.documentElement.querySelector('title');
    return t ? t.textContent : '';
  }
  set title(v) {
    let t = this.documentElement && this.documentElement.querySelector('title');
    if (!t && this.head) {
      t = this.createElement('title');
      this.head.appendChild(t);
    }
    if (t) t.textContent = v;
  }
  get activeElement() {
    return this._active && this._active.isConnected ? this._active : this.body;
  }
  get visibilityState() {
    return this._visibility;
  }
  get hidden() {
    return this._visibility === 'hidden';
  }
  get children() {
    return this.childNodes.filter((c) => c.nodeType === 1);
  }
  createElement(tag) {
    return new StubElement(this, String(tag));
  }
  createElementNS(ns, tag) {
    return new StubElement(this, String(tag), ns === HTML_NS ? HTML_NS : ns);
  }
  createTextNode(text) {
    return new StubText(this, text);
  }
  createDocumentFragment() {
    return new StubFragment(this);
  }
  createComment() {
    return new StubText(this, '');
  }
  getElementById(id) {
    let found = null;
    walk(this, (el) => {
      if (!found && el.getAttribute('id') === id) found = el;
    });
    return found;
  }
  querySelector(sel) {
    return querySelectorAll(this, sel)[0] || null;
  }
  querySelectorAll(sel) {
    return querySelectorAll(this, sel);
  }
  getElementsByTagName(tag) {
    return querySelectorAll(this, tag);
  }
  execCommand(cmd) {
    this._calls.execCommand.push(cmd);
    return true;
  }
  hasFocus() {
    return true;
  }
}

// Builds a document from HTML source. SVG children get the SVG namespace.
export function parseHtml(src) {
  const doc = new StubDocument();
  const stack = [doc];
  for (const t of tokenizeHtml(src)) {
    const parent = stack[stack.length - 1];
    if (t.type === 'start') {
      const inSvg = t.name === 'svg' || (parent.namespaceURI === SVG_NS && parent.localName !== 'foreignObject');
      const el = inSvg ? new StubElement(doc, t.rawName, SVG_NS) : new StubElement(doc, t.name);
      for (const a of t.attrs) el._attrs.set(inSvg ? a.name : a.name.toLowerCase(), a.value);
      parent.appendChild(el);
      if (!VOID.has(t.name) && !t.selfClose) stack.push(el);
    } else if (t.type === 'end') {
      for (let i = stack.length - 1; i > 0; i--) {
        if (stack[i].localName.toLowerCase() === t.name) {
          stack.length = i;
          break;
        }
      }
    } else if (t.type === 'text') {
      parent.appendChild(new StubText(doc, t.text));
    }
  }
  return doc;
}

// ------------------------------------------------------------ globals ----

export function reply(status, body, { headers = {}, networkError = false, delayMs = 0 } = {}) {
  return { __reply: true, status, body, headers, networkError, delayMs };
}

function makeStorage(mode) {
  const map = new Map();
  const deny = () => {
    const e = new Error('The operation is insecure.');
    e.name = 'SecurityError';
    throw e;
  };
  const api = {
    getItem: (k) => (mode === 'throw' ? deny() : map.has(String(k)) ? map.get(String(k)) : null),
    setItem: (k, v) => (mode === 'throw' ? deny() : void map.set(String(k), String(v))),
    removeItem: (k) => (mode === 'throw' ? deny() : void map.delete(String(k))),
    clear: () => (mode === 'throw' ? deny() : map.clear()),
    key: (i) => (mode === 'throw' ? deny() : [...map.keys()][i] ?? null),
    get length() {
      return mode === 'throw' ? deny() : map.size;
    },
  };
  return api;
}

function makeLocation(href, calls, onChange) {
  let url = new URL(href);
  const loc = {
    get href() {
      return url.href;
    },
    set href(v) {
      calls.nav.push({ type: 'assign', url: String(v) });
    },
    get origin() {
      return url.origin;
    },
    get protocol() {
      return url.protocol;
    },
    get host() {
      return url.host;
    },
    get hostname() {
      return url.hostname;
    },
    get port() {
      return url.port;
    },
    get pathname() {
      return url.pathname;
    },
    get search() {
      return url.search;
    },
    get hash() {
      return url.hash;
    },
    set hash(v) {
      url.hash = v;
    },
    assign(v) {
      calls.nav.push({ type: 'assign', url: String(v) });
    },
    replace(v) {
      calls.nav.push({ type: 'replace', url: String(v) });
    },
    reload() {
      calls.nav.push({ type: 'reload', url: url.href });
    },
    toString() {
      return url.href;
    },
    _set(v) {
      url = new URL(v, url);
      onChange?.();
    },
  };
  return loc;
}

const INSTALLED = [];
let current = null;

function install(key, value) {
  const prior = Object.getOwnPropertyDescriptor(globalThis, key);
  INSTALLED.push({ key, prior });
  Object.defineProperty(globalThis, key, { value, configurable: true, writable: true, enumerable: true });
}

function restoreGlobals() {
  while (INSTALLED.length) {
    const { key, prior } = INSTALLED.pop();
    if (prior) Object.defineProperty(globalThis, key, prior);
    else delete globalThis[key];
  }
}

let importSeq = 0;

export function drain(rounds = 20) {
  return (async () => {
    for (let i = 0; i < rounds; i++) {
      await new Promise((r) => realSetImmediate(r));
      await new Promise((r) => realSetTimeout(r, 0));
    }
  })();
}

function textOf(el) {
  return el ? el.textContent.replace(/\s+/g, ' ').trim() : null;
}

function isVisible(el) {
  if (!el) return false;
  for (let n = el; n && n.nodeType === 1; n = n.parentNode) {
    if (n.hasAttribute('hidden') || n.classList.contains('hidden')) return false;
    if (n.localName === 'dialog' && !n.hasAttribute('open')) return false;
  }
  return el.isConnected;
}

function resolvePublic(file) {
  return path.isAbsolute(file) ? file : path.join(PUBLIC_DIR, file);
}

export function pageScriptOf(doc) {
  const s = doc.querySelectorAll('script').find((x) => x.getAttribute('type') === 'module' && x.getAttribute('src'));
  return s ? s.getAttribute('src') : null;
}

export async function loadPage(htmlFile, scriptFile, opts = {}) {
  if (scriptFile && typeof scriptFile === 'object') {
    opts = scriptFile;
    scriptFile = undefined;
  }
  if (current) current.dispose();

  const htmlPath = resolvePublic(htmlFile);
  const html = readFileSync(htmlPath, 'utf8');
  const doc = parseHtml(html);
  const pageName = path.basename(htmlPath, '.html');
  const calls = {
    fetch: [],
    unmatched: [],
    nav: doc._calls.nav,
    scrolls: doc._calls.scrolls,
    dialogs: doc._calls.dialogs,
    execCommand: doc._calls.execCommand,
    clipboard: [],
    timers: [],
    pageErrors: [],
  };
  const startUrl = opts.url || (typeof opts.location === 'string' ? opts.location : opts.location && opts.location.href) || `https://staff.example.com/${pageName === 'index' ? '' : pageName}`;
  const location = makeLocation(startUrl, calls);

  // window IS globalThis, as in a browser.
  const win = globalThis;
  const winListeners = new EventHost();
  winListeners._pageErrors = calls.pageErrors;
  doc.defaultView = {
    _fire: (evt) => winListeners._fire(evt),
    _pageErrors: calls.pageErrors,
  };

  const routes = { ...(opts.fetch || {}) };
  const seqIndex = new Map();
  // opts.live: a (url, init) => Response handler, or a tests/helpers/http.js
  // Client (bridged by tests/helpers/live.js) — see live.js.
  let live = null;
  if (typeof opts.live === 'function') live = opts.live;
  else if (opts.live && typeof opts.live.request === 'function') live = (await import('./live.js')).liveFetch(opts.live);
  else if (opts.live) throw new TypeError('test DOM: opts.live must be a function or a Client');
  async function fetchStub(input, init = {}) {
    const url = new URL(typeof input === 'string' ? input : input.url, location.href);
    const method = String(init.method || 'GET').toUpperCase();
    let body = init.body;
    if (typeof body === 'string') {
      try {
        body = JSON.parse(body);
      } catch {
        // keep the raw string
      }
    }
    const record = { method, path: url.pathname, url: url.pathname + url.search, body, headers: { ...(init.headers || {}) }, init, live: false, status: null, response: undefined, done: false };
    calls.fetch.push(record);
    const keys = [`${method} ${url.pathname}${url.search}`, `${method} ${url.pathname}`, `${url.pathname}`];
    const key = keys.find((k) => Object.hasOwn(routes, k));
    if (!key && live) {
      // tests/helpers/live.js: the real worker answers. The record keeps the
      // status and the parsed reply so a suite can compare what the page
      // shows with what the API really said.
      record.live = true;
      try {
        const res = await live(url, init);
        record.status = res.status;
        const text = await res.clone().text();
        try {
          record.response = text ? JSON.parse(text) : null;
        } catch {
          record.response = text;
        }
        return res;
      } finally {
        record.done = true;
      }
    }
    if (!key) {
      record.done = true;
      calls.unmatched.push(`${method} ${url.pathname}${url.search}`);
      return new Response(JSON.stringify({ error: 'unstubbed in test' }), { status: 404, headers: { 'content-type': 'application/json' } });
    }
    let r = routes[key];
    if (Array.isArray(r)) {
      const i = seqIndex.get(key) || 0;
      seqIndex.set(key, i + 1);
      r = r[Math.min(i, r.length - 1)];
    }
    if (typeof r === 'function') r = await r(record);
    if (!r || r.__reply !== true) throw new Error(`test DOM: route '${key}' must give reply(status, body) — got ${JSON.stringify(r)}`);
    if (r.delayMs) await new Promise((res) => realSetTimeout(res, r.delayMs));
    record.done = true;
    if (r.networkError) throw new TypeError('Failed to fetch');
    const payload = r.body === undefined || r.body === null ? null : typeof r.body === 'string' ? r.body : JSON.stringify(r.body);
    const status = r.status;
    record.status = status;
    record.response = r.body;
    return new Response(status === 204 || status === 304 ? null : payload, { status, headers: { 'content-type': 'application/json', ...r.headers } });
  }

  const timers = new Map();
  let timerSeq = 0;
  function addTimer(kind, fn, ms, args) {
    timerSeq += 1;
    const id = timerSeq;
    const delay = typeof ms === 'number' && ms > 0 ? ms : 0;
    const run = () => {
      if (kind === 'timeout') timers.delete(id);
      try {
        fn(...args);
      } catch (e) {
        calls.pageErrors.push(e);
      }
    };
    const handle = kind === 'timeout' ? realSetTimeout(run, delay) : realSetInterval(run, delay);
    if (delay >= 5000 && handle && typeof handle.unref === 'function') handle.unref();
    timers.set(id, { id, kind, fn: run, delay, handle });
    calls.timers.push({ id, kind, delay });
    return id;
  }
  function clearTimer(id) {
    const t = timers.get(id);
    if (!t) return;
    if (t.kind === 'timeout') realClearTimeout(t.handle);
    else realClearInterval(t.handle);
    timers.delete(id);
  }

  const credentials = opts.webauthn
    ? {
        get: async (o) => opts.webauthn.get(o),
        create: async (o) => (opts.webauthn.create ? opts.webauthn.create(o) : Promise.reject(Object.assign(new Error('not stubbed'), { name: 'NotSupportedError' }))),
      }
    : undefined;
  const navigatorStub = {
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',
    platform: 'MacIntel',
    vendor: 'Google Inc.',
    language: 'en-US',
    languages: ['en-US', 'en'],
    cookieEnabled: true,
    webdriver: false,
    hardwareConcurrency: 8,
    maxTouchPoints: 0,
    plugins: { length: 5 },
    onLine: true,
    clipboard: {
      writeText: async (t) => {
        calls.clipboard.push(String(t));
      },
    },
    ...(credentials ? { credentials } : {}),
    ...(opts.navigator || {}),
  };

  const media = opts.matchMedia || {};
  const matchMedia = (q) => ({ matches: !!media[q], media: q, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {} });

  const historyStub = {
    length: 1,
    state: null,
    pushState(state, _t, url) {
      this.state = state;
      if (url !== undefined && url !== null) location._set(String(url));
      calls.nav.push({ type: 'pushState', url: String(url) });
    },
    replaceState(state, _t, url) {
      this.state = state;
      if (url !== undefined && url !== null) location._set(String(url));
    },
    back() {
      calls.nav.push({ type: 'back' });
    },
  };

  install('window', win);
  install('self', win);
  install('document', doc);
  install('location', location);
  install('history', historyStub);
  install('navigator', navigatorStub);
  install('localStorage', makeStorage(opts.localStorage));
  install('sessionStorage', makeStorage(opts.localStorage));
  install('matchMedia', matchMedia);
  install('fetch', fetchStub);
  install('setTimeout', (fn, ms, ...args) => addTimer('timeout', fn, ms, args));
  install('clearTimeout', clearTimer);
  install('setInterval', (fn, ms, ...args) => addTimer('interval', fn, ms, args));
  install('clearInterval', clearTimer);
  install('requestAnimationFrame', (fn) => addTimer('timeout', fn, 16, [0]));
  install('cancelAnimationFrame', clearTimer);
  install('addEventListener', (t, f, o) => winListeners.addEventListener(t, f, o));
  install('removeEventListener', (t, f) => winListeners.removeEventListener(t, f));
  install('dispatchEvent', (evt) => {
    if (!evt.target) evt.target = win;
    winListeners._fire(evt);
    return !evt.defaultPrevented;
  });
  install('innerWidth', 1280);
  install('innerHeight', 800);
  install('outerWidth', 1280);
  install('outerHeight', 900);
  install('devicePixelRatio', 2);
  install('isSecureContext', true);
  install('scrollTo', () => {});
  install('alert', (m) => calls.nav.push({ type: 'alert', url: String(m) }));
  install('confirm', () => true);
  install('prompt', () => null);
  install('print', () => calls.nav.push({ type: 'print' }));
  install('Event', StubEvent);
  install('CustomEvent', StubEvent);
  if (opts.webauthn) {
    install('PublicKeyCredential', function PublicKeyCredential() {});
    globalThis.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = async () => true;
  } else if ('PublicKeyCredential' in globalThis) {
    install('PublicKeyCredential', undefined);
  }
  for (const [k, v] of Object.entries(opts.globals || {})) install(k, v);

  const page = {
    document: doc,
    window: win,
    location,
    calls,
    module: null,
    $: (id) => doc.getElementById(id),
    text: (id) => textOf(typeof id === 'string' ? doc.getElementById(id) : id),
    visible: (id) => isVisible(typeof id === 'string' ? doc.getElementById(id) : id),
    el(id) {
      const e = typeof id === 'string' ? doc.getElementById(id) : id;
      if (!e) throw new Error(`test DOM: no element #${id}`);
      return e;
    },
    fill(id, value) {
      const e = page.el(id);
      e.value = value;
      e.dispatchEvent(new StubEvent('input', { bubbles: true }));
      e.dispatchEvent(new StubEvent('change', { bubbles: true }));
      return e;
    },
    check(id, on = true) {
      const e = page.el(id);
      e.checked = on;
      e.dispatchEvent(new StubEvent('change', { bubbles: true }));
      return e;
    },
    async click(id) {
      page.el(id).click();
      await drain();
    },
    async submit(id) {
      const f = page.el(id);
      if (f.localName !== 'form') throw new Error(`test DOM: #${id} is not a form`);
      f.requestSubmit();
      await drain();
    },
    async key(id, key) {
      page.el(id).dispatchEvent(new StubEvent('keydown', { bubbles: true, key }));
      await drain();
    },
    drain,
    requests(prefix = '', method = null) {
      return calls.fetch.filter((c) => c.path.startsWith(prefix) && (!method || c.method === method));
    },
    setRoute(key, r) {
      routes[key] = r;
      seqIndex.delete(key);
    },
    async setVisibility(state) {
      doc._visibility = state;
      doc.dispatchEvent(new StubEvent('visibilitychange', { bubbles: false }));
      await drain();
    },
    async fireTimers(minDelay = 0) {
      for (const t of [...timers.values()]) {
        if (t.delay < minDelay) continue;
        if (t.kind === 'timeout') {
          realClearTimeout(t.handle);
          timers.delete(t.id);
        }
        t.fn();
      }
      await drain();
    },
    pendingTimers(minDelay = 0) {
      return [...timers.values()].filter((t) => t.delay >= minDelay).map(({ id, kind, delay }) => ({ id, kind, delay }));
    },
    dispose() {
      for (const t of timers.values()) {
        if (t.kind === 'timeout') realClearTimeout(t.handle);
        else realClearInterval(t.handle);
      }
      timers.clear();
      restoreGlobals();
      if (current === page) current = null;
    },
  };
  current = page;

  if (opts.import !== false) {
    const src = scriptFile || pageScriptOf(doc);
    if (!src) throw new Error(`test DOM: ${htmlFile} has no <script type="module" src>`);
    const scriptPath = path.isAbsolute(src) && existsSync(src) ? src : path.join(PUBLIC_DIR, src.replace(/^\//, ''));
    importSeq += 1;
    page.module = await import(`${pathToFileURL(scriptPath).href}?v=${importSeq}`);
    await drain();
  }
  return page;
}

// Import a public/js module (e.g. common.js) against an already-installed
// page, cache-busted so module state starts fresh.
export async function importFresh(rel) {
  importSeq += 1;
  return import(`${pathToFileURL(path.join(PUBLIC_DIR, rel)).href}?v=${importSeq}`);
}

// ----------------------------------------------- finding by text ----
// For pages that build their controls on the fly (dashboard, account,
// admin): find an element by the words a person would read on it.
//
//   byText(page.document, 'button', 'Remove')        // first match or null
//   byText(panel, 'button', /^Revert/)
//   allByText(page.document, '.item-row', 'Chrome')  // every match
//   texts(page.document, '#strip .strip-day')        // normalised texts

function textMatches(el, match) {
  const t = el.textContent.replace(/\s+/g, ' ').trim();
  return match instanceof RegExp ? match.test(t) : t === match || t.includes(String(match));
}

export function allByText(root, selector, match) {
  return root.querySelectorAll(selector).filter((el) => textMatches(el, match));
}

export function byText(root, selector, match) {
  return allByText(root, selector, match)[0] || null;
}

export function texts(root, selector) {
  return root.querySelectorAll(selector).map((el) => el.textContent.replace(/\s+/g, ' ').trim());
}
