// Static checks over EVERYTHING in public/ — including pages written later
// (A §13.4, §13.6; CONTRACTS §0.5, §0.6, §7.8, §8.2, §10).
//
//   * every id a script looks up ($('…'), getElementById('…'),
//     querySelector('#…')) exists in its page's HTML or is created by the
//     script or a module it imports (h(…, { id: '…' }), el.id = '…');
//   * label[for] targets exist, no id is declared twice, every form control
//     has a label;
//   * no HTML strings or eval in public/js; no on*= / style= / <style> /
//     inline <script> in markup;
//   * every <script> is type=module, src under /js/, and the file exists;
//     every page links /css/app.css and loads exactly one module;
//   * every href/src/url() is same-origin; no http:, https: or // reference
//     anywhere outside comments (the SVG namespace URI is not a reference);
//   * a shell page's static import graph stays inside the asset list its
//     shell allows — otherwise the gate refuses a module and the page dies.

import { readdirSync, readFileSync, statSync, existsSync } from 'node:fs';
import path from 'node:path';
import { test, assert, run } from '../helpers/t.js';
import { tokenizeHtml, parseHtml, loadPage, reply, PUBLIC_DIR } from '../helpers/dom.js';

const NAMESPACES = new Set(['http://www.w3.org/2000/svg', 'http://www.w3.org/1999/xlink', 'http://www.w3.org/1999/xhtml', 'http://www.w3.org/XML/1998/namespace']);

// Shell asset lists from CONTRACTS §7.8 (common.js is allowed in every shell).
const SHELL_ASSETS = {
  'setup.html': ['setup.js'],
  'request.html': ['request.js', 'fp.js'],
  'login.html': ['login.js', 'fp.js', 'webauthn.js'],
  'invite.html': ['invite.js', 'fp.js'],
  'pending.html': ['pending.js'],
};

function listFiles(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = path.join(dir, name);
    if (statSync(p).isDirectory()) out.push(...listFiles(p));
    else out.push(p);
  }
  return out.sort();
}

const ALL = listFiles(PUBLIC_DIR);
const rel = (p) => path.relative(PUBLIC_DIR, p);
const HTML = ALL.filter((f) => f.endsWith('.html'));
const JS = ALL.filter((f) => f.endsWith('.js'));
const CSS = ALL.filter((f) => f.endsWith('.css'));
const SVG = ALL.filter((f) => f.endsWith('.svg'));

// ------------------------------------------------------------- JS lexer ----

// Splits JS source into code (comments removed, strings and regexes kept)
// and the list of string-literal values. Good enough for our own modules:
// handles // and /* */ comments, '…', "…", `…${expr}…` (recursively) and
// regex literals after an operator or keyword.
export function lexJs(src) {
  const strings = [];
  let code = '';
  let i = 0;
  const n = src.length;
  let last = '';
  const REGEX_AFTER_WORDS = new Set(['return', 'typeof', 'case', 'do', 'else', 'in', 'of', 'new', 'delete', 'void', 'throw', 'instanceof', 'yield', 'await']);
  while (i < n) {
    const c = src[i];
    const d = src[i + 1];
    if (c === '/' && d === '/') {
      const e = src.indexOf('\n', i);
      i = e < 0 ? n : e;
      continue;
    }
    if (c === '/' && d === '*') {
      const e = src.indexOf('*/', i + 2);
      i = e < 0 ? n : e + 2;
      code += ' ';
      continue;
    }
    if (c === '"' || c === "'" || c === '`') {
      let j = i + 1;
      let val = '';
      while (j < n && src[j] !== c) {
        if (src[j] === '\\') {
          val += src[j + 1] === undefined ? '' : src[j + 1];
          j += 2;
          continue;
        }
        if (c === '`' && src[j] === '$' && src[j + 1] === '{') {
          let depth = 1;
          j += 2;
          let expr = '';
          while (j < n && depth) {
            if (src[j] === '{') depth++;
            else if (src[j] === '}') depth--;
            if (depth) expr += src[j];
            j++;
          }
          const inner = lexJs(expr);
          strings.push(...inner.strings);
          code += ` ${inner.code} `;
          val += '\u0000';
          continue;
        }
        val += src[j];
        j++;
      }
      strings.push(val);
      code += c + val.replace(/\u0000/g, '') + c;
      i = j + 1;
      last = 'operand';
      continue;
    }
    if (c === '/') {
      const regexOk = last === '' || last === 'keyword' || (last.length === 1 && '(,=:[!&|?{};+-*%<>~^'.includes(last));
      if (regexOk) {
        let j = i + 1;
        let inClass = false;
        while (j < n) {
          if (src[j] === '\\') {
            j += 2;
            continue;
          }
          if (src[j] === '[') inClass = true;
          else if (src[j] === ']') inClass = false;
          else if (src[j] === '/' && !inClass) break;
          else if (src[j] === '\n') break;
          j++;
        }
        j++;
        while (j < n && /[a-z]/i.test(src[j])) j++;
        code += src.slice(i, j);
        i = j;
        last = 'operand';
        continue;
      }
      code += c;
      last = c;
      i++;
      continue;
    }
    if (/[A-Za-z_$]/.test(c)) {
      let j = i;
      while (j < n && /[\w$]/.test(src[j])) j++;
      const word = src.slice(i, j);
      code += word;
      last = REGEX_AFTER_WORDS.has(word) ? 'keyword' : 'operand';
      i = j;
      continue;
    }
    if (/[0-9]/.test(c)) {
      let j = i;
      while (j < n && /[\w.]/.test(src[j])) j++;
      code += src.slice(i, j);
      last = 'operand';
      i = j;
      continue;
    }
    code += c;
    if (!/\s/.test(c)) last = c === ')' || c === ']' ? 'operand' : c;
    i++;
  }
  return { code, strings };
}

const jsInfo = new Map();
function js(file) {
  if (!jsInfo.has(file)) {
    const src = readFileSync(file, 'utf8');
    const { code, strings } = lexJs(src);
    const lookups = new Set();
    for (const m of code.matchAll(/(?<![\w.])\$\(\s*(['"])([^'"]+)\1\s*\)/g)) lookups.add(m[2]);
    for (const m of code.matchAll(/getElementById\(\s*(['"])([^'"]+)\1\s*\)/g)) lookups.add(m[2]);
    for (const m of code.matchAll(/querySelector(?:All)?\(\s*(['"])#([\w-]+)\1\s*\)/g)) lookups.add(m[2]);
    const created = new Set();
    for (const m of code.matchAll(/(?<![\w$])(?:id|'id'|"id")\s*:\s*(['"])([^'"]+)\1/g)) created.add(m[2]);
    for (const m of code.matchAll(/\.id\s*=\s*(['"])([^'"]+)\1/g)) created.add(m[2]);
    for (const m of code.matchAll(/setAttribute\(\s*(['"])id\1\s*,\s*(['"])([^'"]+)\2/g)) created.add(m[3]);
    const imports = [...code.matchAll(/(?:^|[\s;}])import\s+(?:[^'"()]*?\s+from\s+)?(['"])(\.\/[^'"]+)\1/g)].map((m) => path.resolve(path.dirname(file), m[2]));
    const dynamicImports = [...code.matchAll(/\bimport\(\s*(['"])(\.\/[^'"]+)\1\s*\)/g)].map((m) => path.resolve(path.dirname(file), m[2]));
    jsInfo.set(file, { src, code, strings, lookups, created, imports, dynamicImports });
  }
  return jsInfo.get(file);
}

function closure(entry) {
  const seen = new Set();
  const stack = [entry];
  while (stack.length) {
    const f = stack.pop();
    if (seen.has(f)) continue;
    seen.add(f);
    if (!existsSync(f)) continue;
    for (const dep of js(f).imports) stack.push(dep);
  }
  return [...seen];
}

// ----------------------------------------------------------- HTML info ----

function htmlInfo(file) {
  const src = readFileSync(file, 'utf8');
  const tokens = tokenizeHtml(src);
  const elements = [];
  const stack = [];
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t.type === 'start') {
      const attrs = Object.fromEntries(t.attrs.map((a) => [a.name.toLowerCase(), a.value]));
      const el = { name: t.name, attrs, rawAttrs: t.attrs, ancestors: stack.map((s) => s.name), ancestorEls: stack.slice(), inner: '' };
      if (t.name === 'script' || t.name === 'style') {
        const next = tokens[i + 1];
        el.inner = next && next.type === 'text' ? next.text : '';
      }
      elements.push(el);
      const VOID = ['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'source', 'track', 'wbr'];
      if (!VOID.includes(t.name) && !t.selfClose) stack.push(el);
    } else if (t.type === 'end') {
      for (let k = stack.length - 1; k >= 0; k--) {
        if (stack[k].name === t.name) {
          stack.length = k;
          break;
        }
      }
    }
  }
  const comments = tokens.filter((t) => t.type === 'comment');
  let noComments = src;
  for (const c of comments) noComments = noComments.replace(`<!--${c.text}-->`, '');
  return { src, tokens, elements, noComments };
}

const pages = HTML.map((f) => ({ file: f, ...htmlInfo(f) }));

// ---------------------------------------------------------------- tests ----

test('public/ has the pages this work owns', () => {
  for (const p of ['login.html', 'setup.html', 'invite.html', 'request.html', 'pending.html', 'favicon.svg', 'css/app.css', 'js/common.js', 'js/webauthn.js', 'js/fp.js']) {
    assert.ok(existsSync(path.join(PUBLIC_DIR, p)), `missing public/${p}`);
  }
});

test('the lexer separates comments, strings and regexes', () => {
  const { code, strings } = lexJs("const a = 'x//y'; // note innerHTML\n/* block https://evil */ const r = /\\/\\//g; const t = `a${b ? `c${d}` : 'e'}f`; x = y / 2 / 3;");
  assert.ok(!code.includes('innerHTML'));
  assert.ok(!code.includes('https://evil'));
  assert.deepEqual(strings.filter((s) => s === 'x//y').length, 1);
  assert.ok(strings.includes('e'));
  assert.ok(code.includes('/\\/\\//g'));
  assert.ok(code.includes('y / 2 / 3'));
});

test('every page: one module script under /js/, it exists, and /css/app.css is linked', () => {
  for (const p of pages) {
    const scripts = p.elements.filter((e) => e.name === 'script');
    assert.equal(scripts.length, 1, `${rel(p.file)}: expected exactly one <script>, found ${scripts.length}`);
    const s = scripts[0];
    assert.equal(s.attrs.type, 'module', `${rel(p.file)}: <script> must be type=module`);
    assert.match(s.attrs.src || '', /^\/js\/[\w-]+\.js$/, `${rel(p.file)}: script src must be /js/<name>.js`);
    assert.equal(s.inner.trim(), '', `${rel(p.file)}: inline script content`);
    assert.ok(existsSync(path.join(PUBLIC_DIR, s.attrs.src)), `${rel(p.file)}: ${s.attrs.src} does not exist`);
    const css = p.elements.filter((e) => e.name === 'link' && (e.attrs.rel || '').split(/\s+/).includes('stylesheet'));
    assert.ok(css.some((e) => e.attrs.href === '/css/app.css'), `${rel(p.file)}: does not link /css/app.css`);
    for (const c of css) assert.equal(c.attrs.href, '/css/app.css', `${rel(p.file)}: extra stylesheet ${c.attrs.href}`);
  }
});

test('every page: lang, viewport, charset and a title', () => {
  for (const p of pages) {
    const html = p.elements.find((e) => e.name === 'html');
    assert.ok(html && html.attrs.lang, `${rel(p.file)}: <html lang> missing`);
    assert.ok(p.elements.some((e) => e.name === 'meta' && e.attrs.name === 'viewport' && /width=device-width/.test(e.attrs.content || '')), `${rel(p.file)}: viewport meta missing`);
    assert.ok(p.elements.some((e) => e.name === 'meta' && (e.attrs.charset || '').toLowerCase() === 'utf-8'), `${rel(p.file)}: charset missing`);
    assert.match(p.src, /<title>[^<]+<\/title>/, `${rel(p.file)}: empty or missing <title>`);
  }
});

test('markup has no inline handlers, inline styles, <style> blocks or inline scripts', () => {
  for (const p of pages) {
    for (const e of p.elements) {
      for (const a of e.rawAttrs) {
        assert.ok(!/^on/i.test(a.name), `${rel(p.file)}: <${e.name} ${a.name}=…> inline handler`);
        assert.notEqual(a.name.toLowerCase(), 'style', `${rel(p.file)}: <${e.name} style=…> inline style`);
      }
      assert.notEqual(e.name, 'style', `${rel(p.file)}: <style> block`);
      if (e.name === 'script') assert.ok(e.attrs.src, `${rel(p.file)}: inline <script>`);
    }
  }
  for (const f of SVG) {
    const info = htmlInfo(f);
    for (const e of info.elements) {
      assert.notEqual(e.name, 'script', `${rel(f)}: <script> in SVG`);
      for (const a of e.rawAttrs) {
        assert.ok(!/^on/i.test(a.name), `${rel(f)}: inline handler`);
        assert.notEqual(a.name.toLowerCase(), 'style', `${rel(f)}: style attribute`);
      }
    }
  }
});

test('no duplicate ids; every label[for] points at an element', () => {
  for (const p of pages) {
    const ids = p.elements.map((e) => e.attrs.id).filter((v) => v !== undefined);
    const seen = new Set();
    for (const id of ids) {
      assert.ok(!seen.has(id), `${rel(p.file)}: duplicate id '${id}'`);
      seen.add(id);
    }
    for (const l of p.elements.filter((e) => e.name === 'label' && e.attrs.for !== undefined)) {
      assert.ok(seen.has(l.attrs.for), `${rel(p.file)}: <label for="${l.attrs.for}"> has no target`);
    }
  }
});

test('every form control has a label', () => {
  for (const p of pages) {
    const forIds = new Set(p.elements.filter((e) => e.name === 'label').map((e) => e.attrs.for));
    for (const e of p.elements.filter((x) => ['input', 'select', 'textarea'].includes(x.name))) {
      if (['hidden', 'submit', 'button', 'reset'].includes((e.attrs.type || '').toLowerCase())) continue;
      const ok = (e.attrs.id && forIds.has(e.attrs.id)) || e.attrs['aria-label'] || e.attrs['aria-labelledby'] || e.ancestors.includes('label');
      assert.ok(ok, `${rel(p.file)}: <${e.name} id="${e.attrs.id || ''}"> has no label`);
    }
  }
});

test('every id a script looks up exists in the page or is created by the script', () => {
  for (const p of pages) {
    const s = p.elements.find((e) => e.name === 'script' && e.attrs.src);
    if (!s) continue;
    const entry = path.join(PUBLIC_DIR, s.attrs.src);
    const files = closure(entry).filter((f) => existsSync(f));
    const htmlIds = new Set(p.elements.map((e) => e.attrs.id).filter(Boolean));
    const created = new Set(files.flatMap((f) => [...js(f).created]));
    for (const f of files) {
      for (const id of js(f).lookups) {
        assert.ok(htmlIds.has(id) || created.has(id), `${rel(p.file)} via ${rel(f)}: looks up #${id}, which is neither in the markup nor created by the script`);
      }
    }
  }
});

test('every relative import in public/js resolves to a file', () => {
  for (const f of JS) {
    for (const dep of [...js(f).imports, ...js(f).dynamicImports]) assert.ok(existsSync(dep), `${rel(f)} imports ${path.relative(path.dirname(f), dep)}, which does not exist`);
  }
});

test('no HTML strings, eval or inline styles in public/js', () => {
  const BANNED = [
    [/innerHTML/, 'innerHTML'],
    [/outerHTML/, 'outerHTML'],
    [/insertAdjacentHTML/, 'insertAdjacentHTML'],
    [/document\.write(?:ln)?\s*\(/, 'document.write'],
    [/(?<![\w.$])eval\s*\(/, 'eval('],
    [/new\s+Function\s*\(/, 'new Function('],
    [/setAttribute\(\s*['"`]style['"`]/, "setAttribute('style')"],
    [/setAttribute\(\s*['"`]on/i, "setAttribute('on…')"],
    [/\.cssText\b/, 'style.cssText'],
    [/setTimeout\(\s*['"`]/, 'setTimeout(string)'],
    [/setInterval\(\s*['"`]/, 'setInterval(string)'],
    [/createContextualFragment/, 'createContextualFragment'],
    [/DOMParser/, 'DOMParser'],
  ];
  for (const f of JS) {
    const { code, strings } = js(f);
    for (const [re, name] of BANNED) assert.ok(!re.test(code), `${rel(f)}: uses ${name}`);
    for (const s of strings) assert.ok(!/^\s*javascript:/i.test(s), `${rel(f)}: javascript: URL literal`);
  }
});

function assertSameOrigin(where, value) {
  const v = String(value).trim();
  if (!v || v.startsWith('#')) return;
  if (/^(mailto|tel):/i.test(v)) return;
  if (/^data:image\//i.test(v)) return;
  assert.ok(!/^[a-z][a-z0-9+.-]*:/i.test(v), `${where}: '${v}' is not a same-origin reference`);
  assert.ok(!/^[/\\]{2}/.test(v), `${where}: '${v}' is protocol-relative`);
}

test('every href/src/url() in public/ is same-origin', () => {
  const URL_ATTRS = ['href', 'src', 'action', 'formaction', 'poster', 'data', 'xlink:href', 'srcset', 'manifest', 'cite', 'background'];
  for (const f of [...HTML, ...SVG]) {
    const info = htmlInfo(f);
    for (const e of info.elements) {
      for (const a of e.rawAttrs) {
        const name = a.name.toLowerCase();
        if (name === 'xmlns' || name.startsWith('xmlns:')) {
          assert.ok(NAMESPACES.has(a.value), `${rel(f)}: unexpected namespace ${a.value}`);
          continue;
        }
        if (URL_ATTRS.includes(name)) assertSameOrigin(`${rel(f)} <${e.name} ${name}>`, a.value);
        for (const m of a.value.matchAll(/url\(\s*(['"]?)([^'")]*)\1\s*\)/g)) assertSameOrigin(`${rel(f)} <${e.name} ${name}> url()`, m[2]);
      }
    }
  }
  for (const f of CSS) {
    const src = readFileSync(f, 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');
    assert.ok(!/@import/i.test(src), `${rel(f)}: @import`);
    for (const m of src.matchAll(/url\(\s*(['"]?)([^'")]*)\1\s*\)/g)) assertSameOrigin(`${rel(f)} url()`, m[2]);
  }
});

test('no http:, https: or // references anywhere outside comments', () => {
  const check = (where, text) => {
    for (const m of text.matchAll(/https?:\/\/[^\s'"<>)]*/gi)) {
      assert.ok(NAMESPACES.has(m[0]), `${where}: external reference ${m[0]}`);
    }
  };
  for (const f of [...HTML, ...SVG]) check(rel(f), htmlInfo(f).noComments);
  for (const f of CSS) check(rel(f), readFileSync(f, 'utf8').replace(/\/\*[\s\S]*?\*\//g, ''));
  for (const f of JS) {
    const { code, strings } = js(f);
    check(rel(f), code);
    for (const s of strings) {
      if (NAMESPACES.has(s)) continue;
      assert.ok(!/^\s*(https?:)?\/\/[^/]/i.test(s), `${rel(f)}: string literal '${s}' is an off-site reference`);
    }
  }
});

test('shell pages only import what their shell serves (CONTRACTS §7.8)', () => {
  for (const [page, allowed] of Object.entries(SHELL_ASSETS)) {
    const file = path.join(PUBLIC_DIR, page);
    if (!existsSync(file)) continue;
    const info = htmlInfo(file);
    const s = info.elements.find((e) => e.name === 'script');
    const files = closure(path.join(PUBLIC_DIR, s.attrs.src)).map((f) => path.basename(f));
    for (const f of files) {
      assert.ok(f === 'common.js' || allowed.includes(f), `${page}: imports ${f}, which the ${page.replace('.html', '')} shell does not serve — the page would fail to load`);
    }
  }
});

test('common.js has no static imports (every shell loads it)', () => {
  const { imports } = js(path.join(PUBLIC_DIR, 'js', 'common.js'));
  assert.deepEqual(imports, []);
});

test('fp.js and webauthn.js import nothing', () => {
  for (const f of ['fp.js', 'webauthn.js']) assert.deepEqual(js(path.join(PUBLIC_DIR, 'js', f)).imports, [], f);
});

test('the stylesheet defines the design tokens, light and dark', () => {
  const css = readFileSync(path.join(PUBLIC_DIR, 'css', 'app.css'), 'utf8');
  const TOKENS = ['--bg', '--surface', '--surface-2', '--border', '--text', '--text-muted', '--accent', '--accent-contrast', '--ok', '--warn', '--danger', '--focus', '--flame-1', '--flame-2', '--flame-3', '--rest'];
  const root = css.slice(css.indexOf(':root {'), css.indexOf('}', css.indexOf(':root {')));
  const darkStart = css.indexOf('@media (prefers-color-scheme: dark)');
  assert.ok(darkStart > 0, 'no dark-mode block');
  const dark = css.slice(darkStart, css.indexOf('}\n}', darkStart));
  for (const t of TOKENS) {
    assert.ok(new RegExp(`${t}:`).test(root), `${t} missing from :root`);
    assert.ok(new RegExp(`${t}:`).test(dark), `${t} missing from the dark block`);
  }
  assert.match(css, /prefers-reduced-motion/);
  assert.match(css, /:focus-visible/);
  assert.match(css, /\[hidden\]\s*\{\s*display:\s*none !important/);
  assert.match(css, /\.qr-plate\s*\{[^}]*background:\s*var\(--qr-plate\)/);
  assert.match(css, /--qr-plate:\s*#ffffff/);
});

test('the test DOM: seeded from the real markup, and it refuses HTML strings and inline styles', async () => {
  const doc = parseHtml(readFileSync(path.join(PUBLIC_DIR, 'login.html'), 'utf8'));
  assert.equal(doc.getElementById('pane-choose').hidden, true, 'hidden comes from the markup');
  assert.equal(doc.getElementById('pane-password').hidden, false);
  assert.equal(doc.getElementById('password').type, 'password');
  assert.equal(doc.getElementById('title').textContent, 'Sign in');
  assert.equal(doc.querySelector('label[for=identifier]').textContent, 'Email or username');
  assert.equal(doc.body.dataset.page, 'login');
  assert.equal(doc.querySelector('svg linearGradient').namespaceURI, 'http://www.w3.org/2000/svg');
  const el = doc.getElementById('title');
  assert.throws(() => {
    el.innerHTML = '<b>x</b>';
  }, /not allowed/);
  assert.throws(() => el.insertAdjacentHTML('beforeend', '<b>x</b>'), /not allowed/);
  assert.throws(() => el.setAttribute('style', 'color:red'), /not allowed/);
  assert.throws(() => el.setAttribute('onclick', 'x()'), /not allowed/);
  assert.throws(() => {
    el.style.cssText = 'color:red';
  }, /not allowed/);
  el.textContent = 'New';
  assert.equal(el.childNodes.length, 1);
  el.textContent = '';
  assert.equal(el.childNodes.length, 0, 'setting textContent removes children');

  const page = await loadPage('pending.html', { import: false, location: 'https://staff.example.com/pending?x=1', localStorage: 'throw', fetch: { 'GET /api/x': [reply(401, { a: 1 }), reply(200, { b: 2 })] } });
  assert.equal(location.search, '?x=1');
  assert.throws(() => localStorage.getItem('k'), /insecure/);
  const r1 = await fetch('/api/x');
  const r2 = await fetch('/api/x');
  const r3 = await fetch('/api/x');
  assert.deepEqual([r1.status, r2.status, r3.status], [401, 200, 200], 'sequences; the last reply repeats');
  await fetch('/api/unstubbed', { method: 'POST' });
  assert.deepEqual(page.calls.unmatched, ['POST /api/unstubbed']);
  page.dispose();
  assert.equal(typeof globalThis.document, 'undefined', 'dispose restores the globals');
});

await run();
