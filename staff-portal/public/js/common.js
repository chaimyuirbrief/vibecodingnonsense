// common.js — the shared front-end kit for every page (CONTRACTS §10).
//
// Rules this module keeps, and every page built on it must keep too:
//   * The CSP is `script-src 'self'` with no 'unsafe-inline' (CONTRACTS D1).
//     Nothing here assigns HTML strings or inline styles: elements are built
//     with h()/svg(), text goes in with textContent, handlers with
//     addEventListener.
//   * No module-level DOM state. Every function reads `document`, `location`,
//     `fetch` and `navigator` when it is CALLED, so the test DOM stub
//     (tests/helpers/dom.js) can swap them between pages.
//   * No static imports. A shell page (setup, request, invite, pending) may
//     load only its own script plus this file (CONTRACTS §7.8), so
//     webauthn.js is imported dynamically, and only by stepUp().
//
// Exports (all named):
//
//   DOM
//     h(tag, attrs?, ...children)   element builder. attrs: class (string or
//                                   array), id, for, data-*, aria-*, role, any
//                                   attribute; boolean true → present, false/
//                                   null/undefined → omitted; value → .value;
//                                   dataset: {…}; on<event>: fn →
//                                   addEventListener. 'style' and *html keys
//                                   throw. children: strings/numbers → text
//                                   nodes, arrays flattened, null/false skipped.
//     svg(tag, attrs?, ...children) the same through createElementNS (SVG).
//     $(id)                         document.getElementById
//     show(elOrId, visible = true)  toggles the `hidden` attribute
//     icon(name, { label, size })   inline SVG icon (see ICONS for names)
//     flameIcon({ size, out })      the streak flame (gradient --flame-1..3)
//     emptyState({ icon, title, body, action })
//     skeleton(lines = 3)           shimmering placeholder block
//     badge(text, kind)             <span class="badge badge-…">
//     dataTable({ columns, rows, empty, caption })
//                                   table.table.table-cards that collapses to
//                                   cards under 640px (td[data-label])
//     topBar({ user, active, orgName, admin, streak })
//                                   header with brand, nav, streak chip, user,
//                                   sign-out. active: 'dashboard'|'account'|'admin'
//     tabs(root, { onChange, hash }) wires [role=tablist]/[role=tab]/[role=tabpanel]
//     modal({ title, body, actions, onClose }) → { dialog, close }
//     confirmDialog({ title, body, confirmLabel, danger }) → Promise<bool>
//
//   Network
//     ApiError                      { status, body, message, redirected? }
//     api(method, path, body?, opts?)
//                                   JSON in/out, same-origin. 403
//                                   step_up_required → stepUp() then ONE retry;
//                                   401 on a session route + whoami confirms
//                                   signed out → /login?next=… (never on the
//                                   login page). opts:
//                                   { stepUp: false, redirect: false }
//     stepUp()                      <dialog> that satisfies a step-up; → bool
//     confirmSignedIn()             after a sign-in: true | false (cookie did
//                                   not stick) | null (could not tell)
//     signOut(button?)
//
//   Feedback
//     errorMessage(err)             a sentence for any error (429 → "Try again
//                                   in 5 minutes.", network → connection hint)
//     retryText(seconds)
//     showError(elOrId, err)        fills + reveals an error element; null hides
//     setFieldError(input, msg)     inline field error (#<id>-error) + aria-invalid
//     toast(message, kind = 'info', { timeout })   kinds: info ok warn danger
//     busy(button, promiseOrFn)     disables + spinner while work runs
//     copyText(text) → Promise<bool>
//
//   Formatting
//     fmtDate(v, tzOrOpts), fmtDateTime(v, tzOrOpts), fmtTime(v, tzOrOpts),
//     fmtRelative(v, { now }), fmtNumber(n), fmtHours(h)  — Intl, '—' for junk
//     plural(n, one, many?)
//
//   Navigation
//     safeNext(raw, fallback = '/') same-origin path or fallback (A §7.5)
//     param(name)                   query-string value or null
//     go(url, { replace })          location.assign/replace through safeNext
//
//   Passwords
//     passwordFeedback(pw, { email, username, name }) → { ok, score 0–4, label, message }
//     bindPasswordStrength({ input, confirm, meter, hint, context })
//
//   Signed-in pages (dashboard, account, admin)
//     ADMIN_CONSOLE_PERMS           the permissions that open /admin (CONTRACTS §8.3)
//     permSet(perms) → Set          from GET /api/me `permissions` ('*' expands)
//     hasPerm(perms, key), canSeeAdmin(perms)
//     mountTopBar(slotOrId, { me, active, streak, locked })
//                                   renders topBar() into the page's slot from
//                                   GET /api/me; locked → nav inert (pinned)
//     STREAK_STATE_LABELS           { active: 'Active', … } one word per state
//     dayLabel('YYYY-MM-DD', { weekday, year }) → 'Fri Jan 9' (no zone shift)
//     describeCalendar({ weeklyDays, hebrew, israel, extraCount })
//                                   'Shabbos and Yom Tov (diaspora)' — mirrors streak.js
//     streakRulesSentence(rules)    GET /api/me/streak `rules` → one plain sentence
//     downloadText(filename, text)  Blob + object URL + <a download>; → bool
//     uid(prefix)                   a fresh element id for built forms

const SVG_NS = 'http://www.w3.org/2000/svg';

// ---------------------------------------------------------------- DOM ----

const BOOL_PROPS = {
  disabled: 'disabled',
  checked: 'checked',
  hidden: 'hidden',
  required: 'required',
  readonly: 'readOnly',
  multiple: 'multiple',
  selected: 'selected',
  open: 'open',
  autofocus: 'autofocus',
  novalidate: 'noValidate',
};

function isNode(x) {
  return x !== null && typeof x === 'object' && typeof x.nodeType === 'number';
}

function isAttrs(x) {
  return x !== null && typeof x === 'object' && !Array.isArray(x) && !isNode(x);
}

function applyAttrs(el, attrs, isSvg) {
  for (const key of Object.keys(attrs)) {
    const value = attrs[key];
    if (value === null || value === undefined || value === false) continue;
    const lower = key.toLowerCase();
    if (lower === 'style' || lower.endsWith('html')) {
      throw new TypeError(`h(): '${key}' is not allowed — the CSP forbids it`);
    }
    if (lower.startsWith('on')) {
      if (typeof value !== 'function') throw new TypeError(`h(): '${key}' must be a function`);
      el.addEventListener(lower.slice(2), value);
      continue;
    }
    if (key === 'class' || key === 'className') {
      const cls = Array.isArray(value) ? value.filter(Boolean).join(' ') : String(value);
      if (isSvg) el.setAttribute('class', cls);
      else el.className = cls;
      continue;
    }
    if (!isSvg && (key === 'for' || key === 'htmlFor')) {
      el.htmlFor = String(value);
      continue;
    }
    if (key === 'dataset' && typeof value === 'object') {
      for (const k of Object.keys(value)) {
        if (value[k] !== null && value[k] !== undefined) el.dataset[k] = String(value[k]);
      }
      continue;
    }
    if (!isSvg && key === 'value') {
      el.value = String(value);
      continue;
    }
    if (value === true) {
      el.setAttribute(key, '');
      if (!isSvg && BOOL_PROPS[lower]) el[BOOL_PROPS[lower]] = true;
      continue;
    }
    el.setAttribute(key, String(value));
  }
}

function appendChildren(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false || c === true) continue;
    el.appendChild(isNode(c) ? c : document.createTextNode(String(c)));
  }
}

export function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  if (isAttrs(attrs)) applyAttrs(el, attrs, false);
  else if (attrs !== undefined) children.unshift(attrs);
  appendChildren(el, children);
  return el;
}

export function svg(tag, attrs, ...children) {
  const el = document.createElementNS(SVG_NS, tag);
  if (isAttrs(attrs)) applyAttrs(el, attrs, true);
  else if (attrs !== undefined) children.unshift(attrs);
  appendChildren(el, children);
  return el;
}

export function $(id) {
  return document.getElementById(id);
}

function resolveEl(elOrId) {
  return typeof elOrId === 'string' ? document.getElementById(elOrId) : elOrId || null;
}

export function show(elOrId, visible = true) {
  const el = resolveEl(elOrId);
  if (el) el.hidden = !visible;
  return el;
}

// 24×24 stroke icons, drawn for this portal (no icon library — A §12).
const ICONS = {
  check: [['path', { d: 'M5 12.5l4.5 4.5L19 7.5' }]],
  x: [['path', { d: 'M6 6l12 12M18 6L6 18' }]],
  'chevron-right': [['path', { d: 'M9 6l6 6-6 6' }]],
  'chevron-down': [['path', { d: 'M6 9l6 6 6-6' }]],
  'arrow-left': [['path', { d: 'M19 12H5M11 6l-6 6 6 6' }]],
  info: [['circle', { cx: 12, cy: 12, r: 9 }], ['path', { d: 'M12 11v5M12 7.5v.5' }]],
  alert: [['path', { d: 'M12 3.5l9 16H3z' }], ['path', { d: 'M12 10v4M12 17v.5' }]],
  lock: [['rect', { x: 5, y: 11, width: 14, height: 9, rx: 2 }], ['path', { d: 'M8 11V8a4 4 0 0 1 8 0v3' }]],
  key: [['circle', { cx: 8, cy: 15, r: 4 }], ['path', { d: 'M11 12l8-8M16 7l3 3M14 9l2 2' }]],
  passkey: [['circle', { cx: 9, cy: 8, r: 4 }], ['path', { d: 'M3 20c0-3.5 2.7-6 6-6 1.2 0 2.3.3 3.2.9' }], ['circle', { cx: 17.5, cy: 14.5, r: 2.5 }], ['path', { d: 'M17.5 17v4M17.5 19.5h2' }]],
  app: [['rect', { x: 7, y: 2.5, width: 10, height: 19, rx: 2.5 }], ['path', { d: 'M12 8v4l2 1.5' }], ['path', { d: 'M11 18.5h2' }]],
  phone: [['rect', { x: 7, y: 2.5, width: 10, height: 19, rx: 2.5 }], ['path', { d: 'M11 18.5h2' }]],
  mail: [['rect', { x: 3, y: 5.5, width: 18, height: 13, rx: 2 }], ['path', { d: 'M3.5 7l8.5 6 8.5-6' }]],
  sms: [['path', { d: 'M4 5h16v11H9l-5 4z' }], ['path', { d: 'M8 10h8M8 13h5' }]],
  backup: [['rect', { x: 4, y: 3, width: 16, height: 18, rx: 2 }], ['path', { d: 'M8 8h8M8 12h8M8 16h5' }]],
  shield: [['path', { d: 'M12 3l7 3v5.5c0 4.6-3 8-7 9.5-4-1.5-7-4.9-7-9.5V6z' }], ['path', { d: 'M9 12l2 2 4-4' }]],
  copy: [['rect', { x: 9, y: 9, width: 11, height: 11, rx: 2 }], ['path', { d: 'M5 15V6a2 2 0 0 1 2-2h8' }]],
  user: [['circle', { cx: 12, cy: 8, r: 4 }], ['path', { d: 'M4 21c0-4 3.6-6.5 8-6.5s8 2.5 8 6.5' }]],
  users: [['circle', { cx: 9, cy: 8, r: 3.5 }], ['path', { d: 'M2.5 20c0-3.5 2.9-6 6.5-6s6.5 2.5 6.5 6' }], ['path', { d: 'M15.5 4.8a3.5 3.5 0 0 1 0 6.4M18 14.4c2 .9 3.5 2.9 3.5 5.6' }]],
  logout: [['path', { d: 'M15 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3' }], ['path', { d: 'M10 17l-5-5 5-5M5 12h11' }]],
  refresh: [['path', { d: 'M20 11a8 8 0 1 0-2.3 5.7' }], ['path', { d: 'M20 4v7h-7' }]],
  clock: [['circle', { cx: 12, cy: 12, r: 9 }], ['path', { d: 'M12 7v5l3 2' }]],
  calendar: [['rect', { x: 3.5, y: 5, width: 17, height: 15, rx: 2 }], ['path', { d: 'M3.5 10h17M8 3v4M16 3v4' }]],
  rest: [['path', { d: 'M19.5 14.5A8 8 0 1 1 9.5 4.5a6.5 6.5 0 0 0 10 10z' }]],
  device: [['rect', { x: 4, y: 5, width: 16, height: 11, rx: 1.5 }], ['path', { d: 'M2 19h20' }]],
  globe: [['circle', { cx: 12, cy: 12, r: 9 }], ['path', { d: 'M3 12h18M12 3c3 3.5 3 14.5 0 18M12 3c-3 3.5-3 14.5 0 18' }]],
  eye: [['path', { d: 'M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z' }], ['circle', { cx: 12, cy: 12, r: 3 }]],
  search: [['circle', { cx: 11, cy: 11, r: 7 }], ['path', { d: 'M16.5 16.5L21 21' }]],
  plus: [['path', { d: 'M12 5v14M5 12h14' }]],
  trash: [['path', { d: 'M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13' }]],
  edit: [['path', { d: 'M4 20h4L19 9l-4-4L4 16z' }]],
  undo: [['path', { d: 'M9 14L4 9l5-5' }], ['path', { d: 'M4 9h10a6 6 0 0 1 0 12h-3' }]],
  trophy: [['path', { d: 'M7 4h10v5a5 5 0 0 1-10 0z' }], ['path', { d: 'M7 6H4v1a3 3 0 0 0 3 3M17 6h3v1a3 3 0 0 1-3 3M12 14v3M8 21h8M9.5 17h5v4h-5z' }]],
  candle: [['path', { d: 'M9 21h6V10.5H9z' }], ['path', { d: 'M12 10.5V8.5' }], ['path', { d: 'M12 3c1.1 1.3 1.7 2.3 1.7 3.1a1.7 1.7 0 0 1-3.4 0c0-.8.6-1.8 1.7-3.1z' }]],
  download: [['path', { d: 'M12 4v11M7 10.5l5 5 5-5' }], ['path', { d: 'M4 19.5h16' }]],
  print: [['path', { d: 'M7 9V3.5h10V9' }], ['rect', { x: 3.5, y: 9, width: 17, height: 8, rx: 1.5 }], ['path', { d: 'M7 14h10v6.5H7z' }]],
  link: [['path', { d: 'M10 14a4.5 4.5 0 0 0 6.4 0l3-3a4.5 4.5 0 0 0-6.4-6.4l-1 1' }], ['path', { d: 'M14 10a4.5 4.5 0 0 0-6.4 0l-3 3a4.5 4.5 0 0 0 6.4 6.4l1-1' }]],
  pause: [['circle', { cx: 12, cy: 12, r: 9 }], ['path', { d: 'M10 9v6M14 9v6' }]],
  settings: [['circle', { cx: 12, cy: 12, r: 3 }], ['path', { d: 'M12 2.5v3M12 18.5v3M2.5 12h3M18.5 12h3M5.3 5.3l2.1 2.1M16.6 16.6l2.1 2.1M5.3 18.7l2.1-2.1M16.6 7.4l2.1-2.1' }]],
};

export function icon(name, { label = '', size = 20, className = '' } = {}) {
  const parts = ICONS[name] || ICONS.info;
  return svg(
    'svg',
    {
      class: ['icon', className],
      viewBox: '0 0 24 24',
      width: size,
      height: size,
      fill: 'none',
      stroke: 'currentColor',
      'stroke-width': 1.8,
      'stroke-linecap': 'round',
      'stroke-linejoin': 'round',
      focusable: 'false',
      'aria-hidden': label ? null : 'true',
      role: label ? 'img' : null,
      'aria-label': label || null,
    },
    parts.map(([tag, attrs]) => svg(tag, attrs)),
  );
}

let flameSeq = 0;

// The streak flame: amber → orange → red. `out` greys it (a lapsed streak).
export function flameIcon({ size = 24, out = false, label = '' } = {}) {
  flameSeq += 1;
  const gid = `flame-grad-${flameSeq}`;
  return svg(
    'svg',
    {
      class: ['flame', out ? 'is-out' : ''],
      viewBox: '0 0 24 24',
      width: size,
      height: size,
      focusable: 'false',
      'aria-hidden': label ? null : 'true',
      role: label ? 'img' : null,
      'aria-label': label || null,
    },
    svg(
      'defs',
      null,
      svg(
        'linearGradient',
        { id: gid, x1: 0, y1: 1, x2: 0, y2: 0 },
        svg('stop', { offset: 0, class: 'flame-stop-3' }),
        svg('stop', { offset: 0.55, class: 'flame-stop-2' }),
        svg('stop', { offset: 1, class: 'flame-stop-1' }),
      ),
    ),
    svg('path', {
      class: 'flame-body',
      fill: `url(#${gid})`,
      d: 'M12 2.5c.6 3.1 2.9 4.9 4.6 7 1.4 1.7 2.4 3.6 2.4 5.9A7 7 0 0 1 5 15.4c0-2.6 1.3-4.6 3-6.1.2 1.6.9 2.9 2.2 3.6-.4-3.9.3-7.4 1.8-10.4z',
    }),
    svg('path', {
      class: 'flame-core',
      d: 'M12 21a3.6 3.6 0 0 1-3.6-3.6c0-1.9 1.2-3.1 2.4-4.3.3 1 .9 1.7 1.8 2 .1-1.5.5-2.6 1.3-3.6 1.1 1.6 1.7 3.4 1.7 5.6A3.6 3.6 0 0 1 12 21z',
    }),
  );
}

export function emptyState({ icon: iconName = 'info', title = 'Nothing here yet', body = '', action = null } = {}) {
  return h(
    'div',
    { class: 'empty' },
    h('span', { class: 'empty-icon' }, icon(iconName, { size: 28 })),
    h('p', { class: 'empty-title' }, title),
    body ? h('p', { class: 'empty-body' }, body) : null,
    action,
  );
}

export function skeleton(lines = 3) {
  const n = Number.isInteger(lines) && lines > 0 && lines < 50 ? lines : 3;
  const rows = [];
  for (let i = 0; i < n; i++) rows.push(h('span', { class: 'skeleton-line' }));
  return h('div', { class: 'skeleton', 'aria-hidden': 'true' }, rows);
}

export function badge(text, kind = 'neutral') {
  return h('span', { class: `badge badge-${kind}` }, text);
}

// columns: [{ key, label, num?, render?(row) → Node|string, className? }]
export function dataTable({ columns = [], rows = [], empty = null, caption = '' } = {}) {
  if (!rows.length) return empty || emptyState({ title: 'Nothing to show' });
  return h(
    'div',
    { class: 'table-wrap' },
    h(
      'table',
      { class: 'table table-cards' },
      caption ? h('caption', { class: 'sr-only' }, caption) : null,
      h('thead', null, h('tr', null, columns.map((c) => h('th', { scope: 'col', class: c.num ? 'num' : c.className }, c.label)))),
      h(
        'tbody',
        null,
        rows.map((row) =>
          h(
            'tr',
            null,
            columns.map((c) => {
              const v = c.render ? c.render(row) : row[c.key];
              return h('td', { 'data-label': c.label, class: [c.num ? 'num' : '', c.className] }, v === null || v === undefined || v === '' ? '—' : v);
            }),
          ),
        ),
      ),
    ),
  );
}

function initials(name) {
  const parts = String(name || '').trim().split(/\s+/).filter(Boolean);
  if (!parts.length) return '?';
  const first = parts[0][0] || '';
  const last = parts.length > 1 ? parts[parts.length - 1][0] || '' : '';
  return (first + last).toUpperCase();
}

export async function signOut(button = null) {
  await busy(button, async () => {
    try {
      await api('POST', '/api/auth/logout', {}, { redirect: false, stepUp: false });
    } catch {
      // Signed out or not, the next page is the login page.
    }
    go('/login', { replace: true });
  });
}

// locked: the session is pinned to one task (CONTRACTS §7.7 setPin), so every
// other destination is inert and says why rather than bouncing back.
export function topBar({ user = null, active = '', orgName = '', admin = false, streak = null, locked = false } = {}) {
  const link = (href, label, key) =>
    locked && active !== key
      ? h('span', { class: 'topnav-link is-disabled', 'aria-disabled': 'true', title: 'Finish the step on this page first' }, label)
      : h('a', { href, class: 'topnav-link', 'aria-current': active === key ? 'page' : null }, label);
  let chip = null;
  if (streak && typeof streak.current === 'number' && !locked) {
    const n = streak.current;
    const state = typeof streak.state === 'string' ? streak.state : 'none';
    chip = h(
      'a',
      { href: '/#streak', class: `topbar-streak streak-${state}`, 'aria-label': `Streak: ${plural(n, 'day')}` },
      flameIcon({ size: 18, out: state === 'lapsed' || n === 0 }),
      h('span', { class: 'num' }, String(n)),
    );
  }
  const signOutBtn = h(
    'button',
    { type: 'button', class: 'btn btn-ghost btn-sm', 'aria-label': 'Sign out', onclick: () => signOut(signOutBtn) },
    icon('logout', { size: 18 }),
    h('span', { class: 'hide-narrow' }, 'Sign out'),
  );
  const name = user ? user.full_name || user.email || '' : '';
  return h(
    'header',
    { class: 'topbar' },
    h(
      'div',
      { class: 'topbar-inner' },
      h('a', { href: '/', class: 'brand' }, h('span', { class: 'brand-mark' }, flameIcon({ size: 18 })), h('span', { class: 'brand-name' }, orgName || 'Staff portal')),
      h('nav', { class: 'topnav', 'aria-label': 'Main' }, link('/', 'Dashboard', 'dashboard'), link('/account', 'Account', 'account'), admin ? link('/admin', 'Admin', 'admin') : null),
      h(
        'div',
        { class: 'topbar-end' },
        chip,
        user ? h('span', { class: 'topbar-user', title: name }, h('span', { class: 'avatar', 'aria-hidden': 'true' }, initials(name)), h('span', { class: 'topbar-name hide-narrow' }, name)) : null,
        signOutBtn,
      ),
    ),
  );
}

// Wires a tab set: root contains [role=tablist] > [role=tab][aria-controls],
// and the panels those ids name. Arrow keys / Home / End move between tabs.
// With { hash: true } the selected tab follows location.hash ('#tab-id').
export function tabs(root, { onChange = null, hash = false } = {}) {
  const tabList = [...root.querySelectorAll('[role=tab]')];
  if (!tabList.length) return { select() {} };
  const select = (tab, { focus = false, silent = false } = {}) => {
    for (const t of tabList) {
      const on = t === tab;
      t.setAttribute('aria-selected', on ? 'true' : 'false');
      t.tabIndex = on ? 0 : -1;
      const panel = document.getElementById(t.getAttribute('aria-controls'));
      if (panel) panel.hidden = !on;
    }
    if (focus) tab.focus();
    if (hash && tab.id) {
      try {
        history.replaceState(null, '', `#${tab.id}`);
      } catch {
        // History can be unavailable in sandboxed frames; the tab still works.
      }
    }
    if (!silent && onChange) onChange(tab.id, tab);
  };
  tabList.forEach((t, i) => {
    t.addEventListener('click', () => select(t));
    t.addEventListener('keydown', (e) => {
      let j = -1;
      if (e.key === 'ArrowRight' || e.key === 'ArrowDown') j = (i + 1) % tabList.length;
      else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') j = (i - 1 + tabList.length) % tabList.length;
      else if (e.key === 'Home') j = 0;
      else if (e.key === 'End') j = tabList.length - 1;
      if (j >= 0) {
        e.preventDefault();
        select(tabList[j], { focus: true });
      }
    });
  });
  const fromHash = hash && location.hash ? tabList.find((t) => `#${t.id}` === location.hash) : null;
  const initial = fromHash || tabList.find((t) => t.getAttribute('aria-selected') === 'true') || tabList[0];
  select(initial, { silent: !fromHash });
  return { select: (id) => select(tabList.find((t) => t.id === id) || tabList[0]) };
}

let modalSeq = 0;

// A <dialog> built on the fly. actions: [Node]. Returns { dialog, close }.
export function modal({ title = '', body = null, actions = [], onClose = null, labelId = '' } = {}) {
  modalSeq += 1;
  const titleId = labelId || `modal-title-${modalSeq}`;
  const dialog = h(
    'dialog',
    { class: 'modal', 'aria-labelledby': titleId },
    h('div', { class: 'modal-head' }, h('h2', { id: titleId, class: 'modal-title' }, title)),
    h('div', { class: 'modal-body' }, body),
    actions.length ? h('div', { class: 'modal-actions' }, actions) : null,
  );
  let closed = false;
  const close = (value) => {
    if (closed) return;
    closed = true;
    try {
      dialog.close();
    } catch {
      // Already closed.
    }
    dialog.remove();
    if (onClose) onClose(value);
  };
  dialog.addEventListener('cancel', (e) => {
    e.preventDefault();
    close(null);
  });
  dialog.addEventListener('close', () => close(null));
  document.body.appendChild(dialog);
  if (typeof dialog.showModal === 'function') dialog.showModal();
  else dialog.setAttribute('open', '');
  return { dialog, close };
}

export function confirmDialog({ title = 'Are you sure?', body = '', confirmLabel = 'Confirm', danger = false } = {}) {
  return new Promise((resolve) => {
    let answer = false;
    const ok = h('button', { type: 'button', class: ['btn', danger ? 'btn-danger' : 'btn-primary'], onclick: () => { answer = true; m.close(true); } }, confirmLabel);
    const cancel = h('button', { type: 'button', class: 'btn btn-secondary', onclick: () => m.close(false) }, 'Cancel');
    const m = modal({
      title,
      body: typeof body === 'string' ? h('p', null, body) : body,
      actions: [cancel, ok],
      onClose: () => resolve(answer),
    });
    cancel.focus();
  });
}

// ------------------------------------------------------------ Network ----

export class ApiError extends Error {
  constructor(status, body, message, { redirected = false, cancelled = false } = {}) {
    super(message || `Request failed (${status}).`);
    this.name = 'ApiError';
    this.status = status;
    this.body = body;
    this.redirected = redirected;
    // The person dismissed the step-up dialog: say that, not the server's
    // "confirm it's you" sentence they just declined.
    this.cancelled = cancelled;
  }
}

export function retryText(seconds) {
  const s = typeof seconds === 'number' && Number.isFinite(seconds) && seconds > 0 ? Math.ceil(seconds) : 0;
  if (!s) return 'Try again later.';
  if (s < 60) return `Try again in ${plural(s, 'second')}.`;
  if (s < 3600) return `Try again in ${plural(Math.ceil(s / 60), 'minute')}.`;
  return `Try again in about ${plural(Math.round(s / 3600), 'hour')}.`;
}

function messageFor(status, body) {
  if (status === 0) return 'We couldn’t reach the server. Check your connection and try again.';
  if (status === 429) return `Too many attempts. ${retryText(body && body.retry_after)}`;
  if (body && typeof body.error === 'string' && body.error.trim()) return body.error.trim().slice(0, 300);
  if (status >= 500) return 'Something went wrong on our side. Try again in a moment.';
  if (status === 404) return 'That couldn’t be found.';
  if (status === 403) return 'You don’t have access to that.';
  if (status === 401) return 'You’re signed out. Sign in again to continue.';
  return `That didn’t work (error ${status}).`;
}

export function errorMessage(err) {
  if (err === null || err === undefined) return '';
  if (typeof err === 'string') return err;
  if (err instanceof ApiError) return err.cancelled ? err.message : messageFor(err.status, err.body);
  if (err && typeof err.message === 'string' && err.message) return err.message;
  return 'Something went wrong.';
}

function onLoginPage() {
  const page = document.body && document.body.dataset ? document.body.dataset.page : '';
  return page === 'login';
}

function isSessionRoute(path) {
  const p = String(path).split('?')[0];
  return /^\/api\/(me|admin|directory)(\/|$)/.test(p) || p === '/api/auth/logout';
}

export async function api(method, path, body, opts = {}) {
  const init = {
    method,
    headers: { accept: 'application/json' },
    credentials: 'same-origin',
    cache: 'no-store',
  };
  if (body !== undefined) {
    init.headers['content-type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch(path, init);
  } catch {
    throw new ApiError(0, null, messageFor(0, null));
  }
  let data = null;
  try {
    const text = await res.text();
    data = text ? JSON.parse(text) : null;
  } catch {
    data = null;
  }
  if (res.ok) return data === null ? {} : data;

  if (res.status === 403 && data && data.step_up_required === true && opts.stepUp !== false && !opts.retried) {
    const confirmed = await stepUp();
    if (confirmed) return api(method, path, body, { ...opts, retried: true });
    throw new ApiError(403, data, 'Cancelled. Confirm it’s you to make this change.', { cancelled: true });
  }
  // A 401 from a session route usually means the session is gone — but a
  // wrong step-up code or a wrong current password can be a 401 too. Ask
  // whoami: only a confirmed signed-out state goes to the login page.
  if (res.status === 401 && isSessionRoute(path) && opts.redirect !== false && !onLoginPage()) {
    if ((await confirmSignedIn()) === false) {
      const here = `${location.pathname}${location.search}`;
      go(`/login?next=${encodeURIComponent(here)}`, { replace: true });
      throw new ApiError(401, data, messageFor(401, data), { redirected: true });
    }
  }
  throw new ApiError(res.status, data, messageFor(res.status, data));
}

// Asked after any sign-in, BEFORE navigating (A §5): if the server does not
// know us, the browser refused the cookie (private mode, blocked cookies, an
// in-app browser) and navigating would only loop back to the login page.
//   true  → the session cookie came home
//   false → it did not: say so
//   null  → could not tell (whoami refused or unreachable): carry on
export async function confirmSignedIn() {
  try {
    const who = await api('GET', '/api/auth/whoami', undefined, { redirect: false, stepUp: false });
    if (who && who.authenticated === true) return true;
    if (who && who.authenticated === false) return false;
    return null;
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) return false;
    return null;
  }
}

const DEST_WORDS = { sms: 'Text', email: 'Email' };

function destLabel(d) {
  const verb = DEST_WORDS[d.kind] || 'Send';
  return `${verb} a code to ${d.hint || (d.kind === 'email' ? 'your email' : 'your phone')}`;
}

let stepUpInFlight = null;

// The step-up modal: resolves true once the server has marked this session
// freshly verified, false if the person cancels.
export function stepUp() {
  if (!stepUpInFlight) {
    stepUpInFlight = runStepUp().finally(() => {
      stepUpInFlight = null;
    });
  }
  return stepUpInFlight;
}

async function runStepUp() {
  let info;
  try {
    info = await api('GET', '/api/me/step-up', undefined, { stepUp: false });
  } catch (err) {
    if (!(err instanceof ApiError && err.redirected)) toast(errorMessage(err), 'danger');
    return false;
  }
  const methods = Array.isArray(info.methods) ? info.methods : [];
  const dests = Array.isArray(info.destinations) ? info.destinations.filter((d) => d && d.id !== undefined && d.id !== null) : [];
  let wa = null;
  if (methods.includes('passkey')) {
    try {
      wa = await import('./webauthn.js');
    } catch {
      wa = null;
    }
  }
  const canPasskey = !!(wa && wa.supportsPasskeys());
  const canCode = methods.includes('totp') || methods.includes('backup');

  return new Promise((resolve) => {
    let result = false;
    let otpDest = null;
    const error = h('p', { id: 'stepup-error', class: 'form-error', role: 'alert', hidden: true });
    const done = () => {
      result = true;
      m.close(true);
    };
    const fail = (err) => showError(error, err);

    const parts = [h('p', { class: 'muted' }, 'For your security, confirm it’s you before making this change.'), error];

    if (canPasskey) {
      const btn = h('button', { type: 'button', class: 'btn btn-primary btn-block', id: 'stepup-passkey' }, icon('passkey'), 'Use a passkey');
      btn.addEventListener('click', () =>
        busy(btn, async () => {
          showError(error, null);
          try {
            const options = await api('POST', '/api/me/step-up/passkey/options', {}, { stepUp: false });
            const cred = await wa.getPasskey(options);
            if (cred.cancelled) return;
            if (cred.error) return fail(`Your browser couldn’t use a passkey: ${cred.error}`);
            await api('POST', '/api/me/step-up/passkey/verify', { credential: cred }, { stepUp: false });
            done();
          } catch (err) {
            fail(err);
          }
        }),
      );
      parts.push(btn);
    }

    if (canCode) {
      const input = h('input', {
        id: 'stepup-code',
        name: 'code',
        class: 'code-input',
        autocomplete: 'one-time-code',
        inputmode: methods.includes('totp') ? 'numeric' : 'text',
        spellcheck: 'false',
        autocapitalize: 'characters',
        maxlength: 32,
        required: true,
      });
      const submit = h('button', { type: 'submit', class: 'btn btn-secondary btn-block' }, 'Confirm');
      const form = h(
        'form',
        { class: 'stack', novalidate: true },
        h('div', { class: 'field' }, h('label', { for: 'stepup-code' }, methods.includes('totp') ? 'Code from your authenticator app, or a backup code' : 'A backup code'), input),
        submit,
      );
      form.addEventListener('submit', (e) => {
        e.preventDefault();
        const code = input.value.trim();
        if (!code) return fail('Enter the code first.');
        busy(submit, async () => {
          showError(error, null);
          try {
            await api('POST', '/api/me/step-up/code', { code }, { stepUp: false });
            done();
          } catch (err) {
            input.value = '';
            fail(err);
            input.focus();
          }
        });
      });
      parts.push(form);
    }

    if (dests.length) {
      const otpInput = h('input', { id: 'stepup-otp', name: 'otp', class: 'code-input', autocomplete: 'one-time-code', inputmode: 'numeric', maxlength: 12, required: true });
      const otpSubmit = h('button', { type: 'submit', class: 'btn btn-primary btn-block' }, 'Confirm code');
      const otpNote = h('p', { class: 'muted', 'aria-live': 'polite' });
      const otpForm = h('form', { class: 'stack', novalidate: true, hidden: true }, otpNote, h('div', { class: 'field' }, h('label', { for: 'stepup-otp' }, 'Code'), otpInput), otpSubmit);
      otpForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const code = otpInput.value.trim();
        if (!code) return fail('Enter the code first.');
        busy(otpSubmit, async () => {
          showError(error, null);
          try {
            await api('POST', '/api/me/step-up/otp', { code, destination_id: otpDest }, { stepUp: false });
            done();
          } catch (err) {
            otpInput.value = '';
            fail(err);
          }
        });
      });
      const sendList = h(
        'div',
        { class: 'stack-sm' },
        dests.map((d) => {
          const b = h('button', { type: 'button', class: 'btn btn-ghost btn-block' }, icon(d.kind === 'email' ? 'mail' : 'sms'), destLabel(d));
          b.addEventListener('click', () =>
            busy(b, async () => {
              showError(error, null);
              try {
                const r = await api('POST', '/api/me/step-up/send', { destination_id: d.id }, { stepUp: false });
                otpDest = d.id;
                const hint = (r && r.sent && r.sent.hint) || d.hint || '';
                otpNote.textContent = `We sent a code to ${hint}.`;
                otpForm.hidden = false;
                otpInput.focus();
              } catch (err) {
                fail(err);
              }
            }),
          );
          return b;
        }),
      );
      parts.push(sendList, otpForm);
    }

    if (!canPasskey && !canCode && !dests.length) {
      parts.push(
        h(
          'p',
          { class: 'banner banner-warn' },
          methods.includes('passkey')
            ? 'Your account confirms changes with a passkey, and this browser can’t use passkeys. Try a current version of Chrome, Edge, Safari or Firefox, or ask an administrator to add a phone number or email address to your account.'
            : 'Your account has no way to confirm it’s you yet. Set up an authenticator app or a passkey on your account page first.',
        ),
      );
    }

    const cancel = h('button', { type: 'button', class: 'btn btn-secondary', id: 'stepup-cancel' }, 'Cancel');
    const m = modal({ title: 'Confirm it’s you', labelId: 'stepup-title', body: parts, actions: [cancel], onClose: () => resolve(result) });
    m.dialog.classList.add('modal-stepup');
    cancel.addEventListener('click', () => m.close(false));
    const first = m.dialog.querySelector('#stepup-passkey') || m.dialog.querySelector('#stepup-code') || cancel;
    first.focus();
  });
}

// ----------------------------------------------------------- Feedback ----

export function showError(elOrId, err) {
  const el = resolveEl(elOrId);
  if (!el) return;
  const msg = err instanceof ApiError && err.redirected ? '' : errorMessage(err);
  el.textContent = msg;
  el.hidden = !msg;
}

export function setFieldError(input, message) {
  if (!input) return;
  const id = input.id ? `${input.id}-error` : '';
  let el = id ? document.getElementById(id) : null;
  if (!el && message && id) {
    el = h('p', { id, class: 'field-error' });
    input.after(el);
  }
  if (message) {
    input.setAttribute('aria-invalid', 'true');
    if (id) input.setAttribute('aria-describedby', [input.getAttribute('aria-describedby') || '', id].join(' ').trim().split(/\s+/).filter((v, i, a) => a.indexOf(v) === i).join(' '));
  } else {
    input.removeAttribute('aria-invalid');
  }
  if (el) {
    el.textContent = message || '';
    el.hidden = !message;
  }
}

const TOAST_KINDS = { info: 'info', ok: 'ok', success: 'ok', warn: 'warn', warning: 'warn', danger: 'danger', error: 'danger' };
const TOAST_ICONS = { info: 'info', ok: 'check', warn: 'alert', danger: 'alert' };

// Every page ships an empty #toasts live region: a region created together
// with its first message is often not announced at all. A failure is an
// alert of its own, not something to read out when convenient.
export function toast(message, kind = 'info', { timeout = 5000 } = {}) {
  const k = TOAST_KINDS[kind] || 'info';
  let region = document.getElementById('toasts');
  if (!region) {
    region = h('div', { id: 'toasts', class: 'toasts', role: 'status', 'aria-live': 'polite' });
    document.body.appendChild(region);
  }
  const close = h('button', { type: 'button', class: 'toast-close', 'aria-label': 'Dismiss' }, icon('x', { size: 16 }));
  const t = h('div', { class: `toast toast-${k}`, role: k === 'danger' ? 'alert' : null }, icon(TOAST_ICONS[k], { size: 18 }), h('span', { class: 'toast-msg' }, message), close);
  close.addEventListener('click', () => t.remove());
  region.appendChild(t);
  if (timeout > 0) setTimeout(() => t.remove(), timeout);
  return t;
}

export async function busy(button, work) {
  const btn = button || null;
  if (btn) {
    btn.disabled = true;
    btn.setAttribute('aria-busy', 'true');
    btn.classList.add('is-busy');
  }
  try {
    return await (typeof work === 'function' ? work() : work);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.removeAttribute('aria-busy');
      btn.classList.remove('is-busy');
    }
  }
}

export async function copyText(text) {
  const value = String(text ?? '');
  try {
    if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
      await navigator.clipboard.writeText(value);
      return true;
    }
  } catch {
    // Fall through to the selection fallback.
  }
  try {
    const ta = h('textarea', { class: 'sr-only', readonly: true, 'aria-hidden': 'true', tabindex: -1 });
    ta.value = value;
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    ta.remove();
    return !!ok;
  } catch {
    return false;
  }
}

// --------------------------------------------------------- Formatting ----

function toDate(v) {
  let d = null;
  if (v instanceof Date) d = v;
  else if (typeof v === 'number' && Number.isFinite(v)) d = new Date(v);
  else if (typeof v === 'string' && v.trim()) d = new Date(v.trim());
  return d && Number.isFinite(d.getTime()) ? d : null;
}

function tzOpts(tzOrOpts) {
  if (typeof tzOrOpts === 'string') return { tz: tzOrOpts };
  return tzOrOpts && typeof tzOrOpts === 'object' ? tzOrOpts : {};
}

function fmt(value, tzOrOpts, base) {
  const d = toDate(value);
  if (!d) return '—';
  const { tz, ...rest } = tzOpts(tzOrOpts);
  const options = { ...base, ...rest };
  if (tz) {
    try {
      return new Intl.DateTimeFormat(undefined, { ...options, timeZone: tz }).format(d);
    } catch {
      // Unknown zone: fall through to the browser's own.
    }
  }
  return new Intl.DateTimeFormat(undefined, options).format(d);
}

export function fmtDate(value, tzOrOpts) {
  return fmt(value, tzOrOpts, { dateStyle: 'medium' });
}

export function fmtDateTime(value, tzOrOpts) {
  return fmt(value, tzOrOpts, { dateStyle: 'medium', timeStyle: 'short' });
}

export function fmtTime(value, tzOrOpts) {
  return fmt(value, tzOrOpts, { timeStyle: 'short' });
}

const REL_UNITS = [
  ['year', 31557600],
  ['month', 2629800],
  ['week', 604800],
  ['day', 86400],
  ['hour', 3600],
  ['minute', 60],
];

export function fmtRelative(value, { now } = {}) {
  const d = toDate(value);
  if (!d) return '—';
  const nowMs = typeof now === 'number' && Number.isFinite(now) ? now : Date.now();
  const diff = (d.getTime() - nowMs) / 1000;
  const abs = Math.abs(diff);
  if (abs < 45) return diff <= 0 ? 'just now' : 'in a moment';
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
  for (const [unit, secs] of REL_UNITS) {
    if (abs >= secs * 0.9 || unit === 'minute') return rtf.format(Math.round(diff / secs), unit);
  }
  return rtf.format(Math.round(diff / 60), 'minute');
}

export function fmtNumber(n) {
  return typeof n === 'number' && Number.isFinite(n) ? new Intl.NumberFormat().format(n) : '—';
}

// 18.5 → '18h 30m', 0.4 → '24m', 50 → '2d 2h'
export function fmtHours(hours) {
  if (typeof hours !== 'number' || !Number.isFinite(hours) || hours < 0) return '—';
  const totalMin = Math.round(hours * 60);
  const d = Math.floor(totalMin / 1440);
  const hh = Math.floor((totalMin % 1440) / 60);
  const mm = totalMin % 60;
  if (d) return hh ? `${d}d ${hh}h` : `${d}d`;
  if (hh) return mm ? `${hh}h ${mm}m` : `${hh}h`;
  return `${mm}m`;
}

export function plural(n, one, many = `${one}s`) {
  return `${fmtNumber(n)} ${n === 1 ? one : many}`;
}

// --------------------------------------------------------- Navigation ----

// Same-origin destinations only (A §7.5). Refuses off-site URLs, protocol-
// relative and backslash forms, javascript:/data:, an http: downgrade of our
// own host, control characters and junk — all become `fallback`.
export function safeNext(raw, fallback = '/') {
  if (typeof raw !== 'string') return fallback;
  if (raw.length === 0 || raw.length > 2048) return fallback;
  if (raw !== raw.trim()) return fallback;
  if (/[\u0000-\u001f\u007f\\]/.test(raw)) return fallback;
  const origin = location.origin;
  if (raw[0] === '/') {
    if (raw[1] === '/') return fallback;
  } else if (!/^[a-z][a-z0-9+.-]*:/i.test(raw)) {
    return fallback;
  }
  let url;
  try {
    url = new URL(raw, origin);
  } catch {
    return fallback;
  }
  if (url.origin !== origin) return fallback;
  if (url.username || url.password) return fallback;
  const out = `${url.pathname}${url.search}${url.hash}`;
  // '/.//evil.example' normalises to a pathname that starts with two slashes.
  if (out[0] !== '/' || out[1] === '/' || out[1] === '\\') return fallback;
  return out;
}

export function param(name) {
  try {
    return new URLSearchParams(location.search).get(name);
  } catch {
    return null;
  }
}

export function go(url, { replace = false } = {}) {
  const dest = safeNext(url);
  if (replace) location.replace(dest);
  else location.assign(dest);
  return dest;
}

// ---------------------------------------------------------- Passwords ----

const COMMON = ['password', 'passw0rd', '123456', 'qwerty', 'letmein', 'welcome', 'iloveyou', 'admin', 'abc123', 'monkey', 'dragon', '111111', 'changeme'];
const LABELS = ['Too short', 'Weak', 'Fair', 'Good', 'Strong'];

function nameIn(lower, name) {
  const first = typeof name === 'string' ? name.trim().toLowerCase().split(/\s+/)[0] || '' : '';
  return first.length >= 3 && lower.includes(first);
}

// Mirrors users.validatePassword (12–1024 chars, not your email/username, not
// one repeated character) and adds a gentle strength estimate.
export function passwordFeedback(pw, { email = '', username = '', name = '' } = {}) {
  const s = typeof pw === 'string' ? pw : '';
  if (s.length < 12) {
    const more = 12 - s.length;
    return { ok: false, score: 0, label: LABELS[0], message: s.length ? `Use at least 12 characters — ${more} more ${more === 1 ? 'character' : 'characters'} to go.` : 'Use at least 12 characters. A few unrelated words works well.' };
  }
  if (s.length > 1024) return { ok: false, score: 0, label: 'Too long', message: 'Use at most 1024 characters.' };
  const lower = s.toLowerCase();
  if ([email, username].some((v) => typeof v === 'string' && v && lower === v.toLowerCase())) {
    return { ok: false, score: 0, label: LABELS[1], message: 'Don’t use your email address or username as your password.' };
  }
  if (new Set(s).size === 1) return { ok: false, score: 0, label: LABELS[1], message: 'Use more than one repeated character.' };
  let score = s.length >= 20 ? 4 : s.length >= 16 ? 3 : 2;
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(s)).length;
  if (classes >= 3 && score < 4) score += 1;
  const weak = COMMON.some((w) => lower.includes(w)) || nameIn(lower, name) || new Set(s).size < 5;
  if (weak) score = Math.min(score, 1);
  const message = weak ? 'That’s easy to guess. Avoid common words, names and repeats.' : score >= 3 ? 'Looks good.' : 'Fine. Longer is stronger — try a few unrelated words.';
  return { ok: true, score, label: LABELS[score], message };
}

// Live strength feedback for a password field (+ optional confirm field).
// context() → { email, username, name } for the checks above.
export function bindPasswordStrength({ input, confirm = null, meter = null, hint = null, context = () => ({}) }) {
  const update = () => {
    const f = passwordFeedback(input.value, context());
    if (meter) {
      meter.value = input.value ? Math.max(f.score, 0.4) : 0;
      meter.dataset.score = String(f.score);
    }
    if (hint) {
      hint.textContent = input.value ? `${f.label}. ${f.message}` : 'Use at least 12 characters. A few unrelated words works well.';
      hint.dataset.ok = f.ok ? 'true' : 'false';
    }
    if (confirm && confirm.value) setFieldError(confirm, confirm.value === input.value ? '' : 'The passwords don’t match yet.');
    return f;
  };
  input.addEventListener('input', update);
  if (confirm) confirm.addEventListener('input', update);
  update();
  return update;
}

// -------------------------------------------------- signed-in pages ----

// Holding any of these opens the admin console (CONTRACTS §8.3). The nav
// shows the Admin link only then — a link that redirects home is a lie.
export const ADMIN_CONSOLE_PERMS = Object.freeze([
  'users.view',
  'team.view',
  'directory.view',
  'devices.view',
  'network.view',
  'audit.view',
  'settings.view',
  'roles.view',
  'visitors.view',
  'sessions.view',
  'streaks.view_all',
  'requests.manage',
  'users.invite',
]);

// GET /api/me sends `permissions` already expanded; '*' is honoured anyway
// so a Super Admin is never shown less than they hold.
export function permSet(perms) {
  const list = perms instanceof Set ? [...perms] : Array.isArray(perms) ? perms : [];
  return new Set(list.filter((p) => typeof p === 'string'));
}

export function hasPerm(perms, key) {
  const set = perms instanceof Set ? perms : permSet(perms);
  return set.has('*') || set.has(key);
}

export function canSeeAdmin(perms) {
  const set = permSet(perms);
  return ADMIN_CONSOLE_PERMS.some((p) => hasPerm(set, p));
}

let uidSeq = 0;

export function uid(prefix = 'f') {
  uidSeq += 1;
  return `${prefix}-${uidSeq}`;
}

// Renders the top bar into the page's slot (a `display: contents` wrapper,
// so the bar stays sticky against the body).
export function mountTopBar(slotOrId, { me = null, active = '', streak = null, locked = false } = {}) {
  const slot = resolveEl(slotOrId);
  if (!slot) return null;
  const user = me && me.user && typeof me.user === 'object' ? me.user : null;
  const orgName = me && typeof me.org_name === 'string' ? me.org_name : '';
  const bar = topBar({ user, active, orgName, admin: !!me && canSeeAdmin(me.permissions), streak, locked });
  slot.replaceChildren(bar);
  return bar;
}

export const STREAK_STATE_LABELS = Object.freeze({
  none: 'Not started',
  active: 'Active',
  at_risk: 'At risk',
  paused: 'Paused',
  lapsed: 'Lapsed',
  held: 'Held',
});

const DAY_RE = /^(\d{4})-(\d{2})-(\d{2})$/;
const WD_SHORT = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const MON_SHORT = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const WD_LONG = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];

// 'YYYY-MM-DD' is a portal-local DAY, not an instant: format it in UTC so no
// browser zone can move it to the day before.
export function parseDay(day) {
  const m = typeof day === 'string' ? DAY_RE.exec(day) : null;
  if (!m) return null;
  const ms = Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
  const d = new Date(ms);
  if (d.getUTCFullYear() !== Number(m[1]) || d.getUTCMonth() !== Number(m[2]) - 1 || d.getUTCDate() !== Number(m[3])) return null;
  return { ms, year: d.getUTCFullYear(), month: d.getUTCMonth(), date: d.getUTCDate(), weekday: d.getUTCDay() };
}

export function dayLabel(day, { weekday = true, year = false } = {}) {
  const p = parseDay(day);
  if (!p) return '—';
  const base = `${MON_SHORT[p.month]} ${p.date}`;
  return `${weekday ? `${WD_SHORT[p.weekday]} ` : ''}${base}${year ? `, ${p.year}` : ''}`;
}

export const WEEKDAYS = Object.freeze({ short: Object.freeze([...WD_SHORT]), long: Object.freeze([...WD_LONG]), months: Object.freeze([...MON_SHORT]) });

function joinAnd(parts) {
  if (parts.length <= 1) return parts.join('');
  return `${parts.slice(0, -1).join(', ')} and ${parts[parts.length - 1]}`;
}

// The same words streak.js uses for `rules.calendar`, so the settings form can
// show the sentence a change will produce before it is saved.
export function describeCalendar({ weeklyDays = [], hebrew = false, israel = false, extraCount = 0 } = {}) {
  const days = [...new Set((Array.isArray(weeklyDays) ? weeklyDays : []).filter((d) => Number.isInteger(d) && d >= 0 && d <= 6))].sort((a, b) => a - b);
  const parts = days.map((d) => (d === 6 && hebrew ? 'Shabbos' : `${WD_LONG[d]}s`));
  if (hebrew) parts.push(`Yom Tov (${israel ? 'Israel' : 'diaspora'})`);
  const n = Number.isInteger(extraCount) && extraCount > 0 ? extraCount : 0;
  if (n) parts.push(`${n} extra date${n === 1 ? '' : 's'}`);
  return parts.length ? joinAnd(parts) : 'No protected days';
}

function ruleInt(v, min, max) {
  return typeof v === 'number' && Number.isInteger(v) && v >= min && v <= max ? v : null;
}

// The rules in one plain sentence, generated from the configuration — never
// a rule of thumb (SPEC §10.4, §10.17). '' when the rules are unreadable.
export function streakRulesSentence(rules) {
  const r = rules && typeof rules === 'object' ? rules : {};
  const w = ruleInt(r.window_hours, 1, 1000);
  if (w === null) return '';
  const grace = ruleInt(r.reentry_grace_hours, 0, 1000) ?? 0;
  const leeway = ruleInt(r.max_leeway_days, 0, 100) ?? 0;
  const cal = typeof r.calendar === 'string' && r.calendar.trim() ? r.calendar.trim() : 'No protected days';
  let s = `Sign in at least once every ${plural(w, 'hour')} to keep your streak`;
  if (/^no protected days$/i.test(cal)) return `${s}.`;
  s += leeway > 0
    ? `; ${cal} don’t count against you — each one adds a day to the window, up to ${plural(leeway, 'day')}`
    : `; ${cal} are marked on your history but don’t stretch the window`;
  if (grace > 0) s += `, and after a protected stretch you get ${plural(grace, 'hour')} to sign back in`;
  return `${s}.`;
}

// A text file the browser saves. Downloads are not fetches or images, so the
// CSP's connect-src/img-src do not apply; if anything here throws, say false
// and let the caller offer copy and print instead.
export function downloadText(filename, text) {
  try {
    const blob = new Blob([String(text ?? '')], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = h('a', { href: url, download: filename, class: 'sr-only', tabindex: -1, 'aria-hidden': 'true' });
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => {
      try {
        URL.revokeObjectURL(url);
      } catch {
        // Already gone.
      }
    }, 30000);
    return true;
  } catch {
    return false;
  }
}
