// admin.js — the admin console (CONTRACTS §8.3, §8.4 Admin, §5, §8.5;
// A §4, §8, §9; B §6, §7; SPEC §3.2, §8, §10.18, §11, §12).
//
// What a person sees is decided by the permissions GET /api/me returns: a tab
// appears only when they hold one of its permissions, and every control that
// changes something is built only when they hold the permission it needs
// (A §9: hide what they can't use rather than offer a button that will be
// refused). Every such control carries data-write="<perm>", so the tests can
// prove an auditor is shown none.
//
// Dangerous writes need a fresh step-up; api() runs the dialog and retries.
// Guard refusals from the server (409 self_lockout, rank, last superuser)
// are shown verbatim — they are the explanation (B trap 8).

import {
  $,
  h,
  icon,
  api,
  ApiError,
  busy,
  setFieldError,
  toast,
  copyText,
  confirmDialog,
  modal,
  mountTopBar,
  tabs,
  dataTable,
  emptyState,
  skeleton,
  badge,
  fmtDateTime,
  fmtRelative,
  fmtNumber,
  plural,
  go,
  permSet,
  hasPerm,
  canSeeAdmin,
  ADMIN_CONSOLE_PERMS,
  uid,
  dayLabel,
  describeCalendar,
  streakRulesSentence,
  errorMessage,
  STREAK_STATE_LABELS,
  WEEKDAYS,
} from './common.js';

// ---------------------------------------------------------------- state ----

export const TABS = Object.freeze([
  { id: 'overview', any: ADMIN_CONSOLE_PERMS },
  { id: 'people', any: ['users.view', 'team.view'] },
  { id: 'invitations', any: ['users.invite', 'requests.manage'] },
  { id: 'roles', any: ['roles.view'] },
  { id: 'devices', any: ['devices.view'] },
  { id: 'network', any: ['network.view'] },
  { id: 'security', any: ['settings.view', 'gate.open'] },
  { id: 'settings', any: ['settings.view'] },
  { id: 'visitors', any: ['visitors.view'] },
  { id: 'sessions', any: ['sessions.view'] },
  { id: 'streaks', any: ['streaks.view_all', 'team.view'] },
  { id: 'audit', any: ['audit.view'] },
]);

const WRITE_PERMS = [
  'users.invite', 'users.edit', 'users.suspend', 'users.disable', 'users.roles', 'users.reset_mfa', 'users.reset_password',
  'destinations.manage', 'requests.manage', 'roles.manage', 'devices.approve', 'devices.manage', 'network.manage',
  'sessions.revoke', 'settings.manage', 'security.manage', 'gate.open', 'audit.revert', 'streaks.manage',
];

const SYSTEM_ROLE_KEYS = ['super_admin', 'admin', 'auditor', 'manager', 'employee', 'guest'];

const S = {
  me: null,
  perms: new Set(),
  meId: null,
  myRank: 0,
  isSuper: false,
  tabsCtl: null,
  loaded: new Set(),
  cache: {},
  gateTimer: null,
};

const can = (perm) => hasPerm(S.perms, perm);
const canAny = (list) => list.some(can);

// ------------------------------------------------------------- builders ----

function listOf(r, key) {
  if (Array.isArray(r)) return r.filter((x) => x && typeof x === 'object');
  if (r && typeof r === 'object' && Array.isArray(r[key])) return r[key].filter((x) => x && typeof x === 'object');
  return [];
}

function str(v) {
  return typeof v === 'string' ? v : v === null || v === undefined ? '' : String(v);
}

function humanize(key) {
  const s = str(key).replace(/[_.]+/g, ' ').trim();
  return s ? s[0].toUpperCase() + s.slice(1) : '';
}

function when(v) {
  return v ? h('time', { datetime: str(v), title: fmtRelative(v) }, fmtDateTime(v)) : '—';
}

function ago(v) {
  return v ? h('time', { datetime: str(v), title: fmtDateTime(v) }, fmtRelative(v)) : '—';
}

function banner(kind, title, body, ...extra) {
  const ic = kind === 'ok' ? 'check' : kind === 'info' || kind === 'rest' ? 'info' : 'alert';
  return h(
    'div',
    { class: `banner banner-${kind}`, role: kind === 'danger' ? 'alert' : null },
    icon(ic),
    h('div', { class: 'banner-body' }, title ? h('p', { class: 'banner-title' }, title) : null, body ? h('p', null, body) : null, extra),
  );
}

function card(title, sub, ...children) {
  return h(
    'section',
    { class: 'card stack' },
    title || sub ? h('div', null, title ? h('h3', { class: 'card-title' }, title) : null, sub ? h('p', { class: 'card-sub' }, sub) : null) : null,
    children,
  );
}

function field(label, input, hint = '', { wide = false } = {}) {
  if (!input.id) input.id = uid('f');
  return h('div', { class: ['field', wide ? 'field-wide' : ''] }, h('label', { for: input.id }, label), input, hint ? h('p', { class: 'hint' }, hint) : null);
}

function select(options, value, attrs = {}) {
  return h(
    'select',
    attrs,
    options.map((o) => h('option', { value: str(o.value), selected: str(o.value) === str(value), disabled: o.disabled || false }, o.label)),
  );
}

function check(label, checked, attrs = {}) {
  const input = h('input', { type: 'checkbox', checked: !!checked, ...attrs });
  return { input, el: h('label', { class: 'check' }, input, h('span', null, label)) };
}

// A control that changes something. Built only for someone who may use it.
function writeBtn(perm, label, handler, { kind = 'secondary', size = 'sm', id = null, ariaLabel = null, iconName = null } = {}) {
  if (!can(perm)) return null;
  const b = h(
    'button',
    { type: 'button', id, class: ['btn', `btn-${kind}`, size ? `btn-${size}` : ''], dataset: { write: perm }, 'aria-label': ariaLabel },
    iconName ? icon(iconName, { size: 18 }) : null,
    label,
  );
  b.addEventListener('click', () => busy(b, () => handler(b)));
  return b;
}

function submitBtn(perm, label, { kind = 'primary', id = null } = {}) {
  return h('button', { type: 'submit', id, class: ['btn', `btn-${kind}`], dataset: { write: perm } }, label);
}

function resultArea(id) {
  return h('div', { id, class: 'result-area', role: 'status', 'aria-live': 'polite' });
}

// A guard's refusal is the explanation: show the server's sentence as it is.
export function refusalText(err) {
  if (err instanceof ApiError && err.body && typeof err.body.error === 'string' && err.body.error) return err.body.error;
  return errorMessage(err);
}

function isSelfLockout(err) {
  return err instanceof ApiError && err.status === 409 && err.body && err.body.code === 'self_lockout';
}

function showFailure(area, err, title = 'That didn’t work') {
  if (!area || (err instanceof ApiError && err.redirected)) return;
  if (isSelfLockout(err)) area.replaceChildren(banner('danger', 'Refused — this would lock you out', refusalText(err)));
  else if (err instanceof ApiError && err.cancelled) area.replaceChildren(banner('warn', null, err.message));
  else area.replaceChildren(banner('danger', title, refusalText(err)));
}

function messages(list) {
  return (Array.isArray(list) ? list : [])
    .map((m) => (typeof m === 'string' ? m : m && typeof m === 'object' ? str(m.message || m.text || m.error) : ''))
    .filter(Boolean);
}

async function confirmed(opts) {
  return confirmDialog({ confirmLabel: 'Confirm', ...opts });
}

function copyRow(label, value) {
  const input = h('input', { type: 'text', readonly: true, value, class: 'mono' });
  const btn = h('button', { type: 'button', class: 'btn btn-secondary' }, icon('copy', { size: 18 }), 'Copy');
  btn.addEventListener('click', async () => {
    const ok = await copyText(value);
    toast(ok ? 'Copied.' : 'Couldn’t copy — select it and copy by hand.', ok ? 'ok' : 'warn');
  });
  const f = field(label, input);
  f.appendChild(h('div', { class: 'cluster' }, btn));
  return f;
}

// An invitation link the admin hands over (D11). Shown, copied, gone.
function showLink({ title = 'Invitation link', url, expires = null, who = '' }) {
  if (typeof url !== 'string' || !url) {
    toast('Done — but the server sent no link. Reissue it from the person’s page.', 'warn');
    return;
  }
  const close = h('button', { type: 'button', class: 'btn btn-primary' }, 'Done');
  const m = modal({
    title,
    body: [
      h('p', null, `Send this link to ${who || 'them'} yourself — by chat or in person. Anyone holding it can set the password, so treat it like one. It works once${expires ? ` and expires ${fmtDateTime(expires)}` : ''}.`),
      copyRow('Link', url),
    ],
    actions: [close],
  });
  close.addEventListener('click', () => m.close(true));
  return m;
}

async function guarded(body, fn) {
  body.replaceChildren(skeleton(5));
  try {
    await fn();
  } catch (err) {
    if (err instanceof ApiError && err.redirected) return;
    const retry = h('button', { type: 'button', class: 'btn btn-secondary btn-sm' }, icon('refresh', { size: 18 }), 'Try again');
    body.replaceChildren(banner('danger', 'This section couldn’t be loaded', errorMessage(err), h('div', { class: 'banner-actions' }, retry)));
    retry.addEventListener('click', () => guarded(body, fn));
  }
}

function bodyOf(tab) {
  return document.getElementById(`${tab}-body`);
}

function reload(tab) {
  S.loaded.delete(tab);
  const sel = document.getElementById(`tab-${tab}`);
  if (sel && sel.getAttribute('aria-selected') === 'true') return loadTab(tab);
  return null;
}

const STATUS_BADGE = { active: ['Active', 'ok'], invited: ['Invited', 'accent'], suspended: ['Suspended', 'warn'], disabled: ['Disabled', 'danger'] };
const OUTCOME_KIND = { success: 'ok', failure: 'warn', denied: 'danger' };
const SEVERITY_KIND = { info: 'neutral', notice: 'accent', warning: 'warn', critical: 'danger' };

function statusBadge(status) {
  const [t, k] = STATUS_BADGE[status] || [humanize(status) || 'Unknown', 'neutral'];
  return badge(t, k);
}

function personName(u) {
  if (!u || typeof u !== 'object') return '—';
  return str(u.full_name).trim() || str(u.email) || str(u.username) || `#${u.id}`;
}

// ----------------------------------------------------- shared lookups ----

async function getRoles(force = false) {
  if (!force && S.cache.roles) return S.cache.roles;
  if (!can('roles.view')) return (S.cache.roles = []);
  return (S.cache.roles = listOf(await api('GET', '/api/admin/roles'), 'roles'));
}

async function getCatalog() {
  if (S.cache.catalog) return S.cache.catalog;
  if (!can('roles.view')) return (S.cache.catalog = []);
  return (S.cache.catalog = listOf(await api('GET', '/api/admin/permissions'), 'permissions'));
}

async function getSettings(force = false) {
  if (!force && S.cache.settings) return S.cache.settings;
  const rows = listOf(await api('GET', '/api/admin/settings'), 'settings');
  return (S.cache.settings = rows);
}

function roleRank(r) {
  return typeof r.rank === 'number' ? r.rank : 0;
}

// Roles this admin may hand out: below their own rank, never '*' (D4).
function assignable(roles) {
  if (S.isSuper) return roles;
  return roles.filter((r) => roleRank(r) < S.myRank && !(Array.isArray(r.permissions) && r.permissions.includes('*')));
}

function roleOptions(roles, current = null, { blank = null } = {}) {
  const ok = new Set(assignable(roles).map((r) => r.id));
  const opts = roles.map((r) => ({ value: r.id, label: `${r.name} (rank ${roleRank(r)})`, disabled: !ok.has(r.id) && r.id !== current }));
  return blank ? [{ value: '', label: blank }, ...opts] : opts;
}

function defaultRoleId(roles) {
  const list = assignable(roles);
  const emp = list.find((r) => r.key === 'employee');
  return emp ? emp.id : list.length ? list[list.length - 1].id : '';
}

// ------------------------------------------------------------- overview ----

const COUNT_LABELS = {
  users_active: ['Active people', 'people'],
  users_invited: ['Invited, not yet joined', 'invitations'],
  users_suspended: ['Suspended', 'people'],
  users_disabled: ['Disabled', 'people'],
  users_total: ['People', 'people'],
  devices_pending: ['Devices waiting for approval', 'devices'],
  devices_approved: ['Approved devices', 'devices'],
  devices_blocked: ['Blocked devices', 'devices'],
  requests_pending: ['Access requests waiting', 'invitations'],
  invitations_pending: ['Open invitations', 'invitations'],
  sessions_active: ['Signed in now', 'sessions'],
  allow_entries: ['Allowlist entries', 'network'],
  block_entries: ['Blocklist entries', 'network'],
  visitors_24h: ['Visitors, last 24 hours', 'visitors'],
  denied_24h: ['Refused, last 24 hours', 'visitors'],
  streaks_active: ['Streaks going', 'streaks'],
  audit_entries: ['Audit entries', 'audit'],
};

function selectTab(id) {
  if (S.tabsCtl && document.getElementById(`tab-${id}`)) S.tabsCtl.select(`tab-${id}`);
}

async function loadOverview(body) {
  const r = await api('GET', '/api/admin/overview');
  const counts = r && typeof r.counts === 'object' && r.counts ? r.counts : {};
  const tiles = Object.entries(counts)
    .filter(([, v]) => typeof v === 'number' && Number.isFinite(v))
    .map(([k, v]) => {
      const [label, tab] = COUNT_LABELS[k] || [humanize(k), null];
      const inner = [h('span', { class: 'stat-value' }, fmtNumber(v)), h('span', { class: 'stat-label' }, label)];
      if (tab && document.getElementById(`tab-${tab}`)) {
        const a = h('a', { href: `#tab-${tab}`, class: 'stat tile-link', dataset: { count: k } }, inner);
        a.addEventListener('click', (e) => {
          e.preventDefault();
          selectTab(tab);
        });
        return a;
      }
      return h('div', { class: 'stat', dataset: { count: k } }, inner);
    });
  const parts = [];
  const gate = r && r.gate && typeof r.gate === 'object' ? r.gate : null;
  if (gate && gate.open) parts.push(banner('warn', 'The portal is open to the internet', gate.forever ? 'Until someone closes it.' : `Until ${fmtDateTime(gate.until)}.`));
  if (counts.devices_pending > 0 && can('devices.approve')) parts.push(banner('info', `${plural(counts.devices_pending, 'device is', 'devices are')} waiting for approval`, null));
  parts.push(tiles.length ? h('div', { id: 'overview-tiles', class: 'stat-tiles' }, tiles) : emptyState({ title: 'Nothing to count yet' }));
  const recent = listOf(r && (r.recent_audit || r.recent || r.audit), 'entries');
  if (recent.length) {
    parts.push(
      card(
        'Recent changes',
        can('audit.view') ? null : 'From the audit log.',
        dataTable({
          caption: 'Recent audit entries',
          columns: [
            { key: 'at', label: 'When', render: (e) => ago(e.at) },
            { key: 'actor_label', label: 'Who' },
            { key: 'detail', label: 'What', render: (e) => str(e.detail) || str(e.action) },
            { key: 'outcome', label: 'Outcome', render: (e) => badge(str(e.outcome) || 'success', OUTCOME_KIND[e.outcome] || 'neutral') },
          ],
          rows: recent.slice(0, 10),
        }),
      ),
    );
  }
  body.replaceChildren(...parts);
}

// --------------------------------------------------------------- people ----

const PEOPLE = { q: '', status: '', role: '', offset: 0, users: [], total: 0, selected: null };

async function loadPeople(body) {
  const roles = await getRoles().catch(() => []);
  const q = h('input', { id: 'people-q', type: 'search', value: PEOPLE.q, autocomplete: 'off', placeholder: 'Name, email, username or number' });
  const status = select(
    [
      { value: '', label: 'Any status' },
      { value: 'active', label: 'Active' },
      { value: 'invited', label: 'Invited' },
      { value: 'suspended', label: 'Suspended' },
      { value: 'disabled', label: 'Disabled' },
    ],
    PEOPLE.status,
    { id: 'people-status' },
  );
  const role = roles.length ? select([{ value: '', label: 'Any role' }, ...roles.map((r) => ({ value: r.id, label: r.name }))], PEOPLE.role, { id: 'people-role' }) : null;
  const form = h(
    'form',
    { id: 'people-search', class: 'toolbar', role: 'search', novalidate: true },
    field('Search', q),
    field('Status', status),
    role ? field('Role', role) : null,
    h('button', { type: 'submit', class: 'btn btn-secondary' }, icon('search', { size: 18 }), 'Search'),
    writeBtn('users.invite', 'Invite someone', () => openInvite(), { kind: 'primary', size: '', iconName: 'plus' }),
  );
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    PEOPLE.q = q.value.trim();
    PEOPLE.status = status.value;
    PEOPLE.role = role ? role.value : '';
    PEOPLE.offset = 0;
    fetchPeople().catch((err) => $('people-list').replaceChildren(banner('danger', null, errorMessage(err))));
  });
  const scope = !can('users.view') && can('team.view') ? banner('info', null, 'You can see the people who report to you.') : null;
  const layout = h(
    'div',
    { id: 'people-layout', class: 'people-layout' },
    h('div', { class: 'card card-flush' }, h('div', { id: 'people-list' })),
    h('div', { id: 'person-detail', class: 'stack', tabindex: -1, hidden: true }),
  );
  body.replaceChildren(...[scope, form, layout].filter(Boolean));
  await fetchPeople();
}

async function fetchPeople({ append = false } = {}) {
  const params = new URLSearchParams();
  if (PEOPLE.q) params.set('q', PEOPLE.q);
  if (PEOPLE.status) params.set('status', PEOPLE.status);
  if (PEOPLE.role) params.set('role', PEOPLE.role);
  params.set('limit', '50');
  params.set('offset', String(PEOPLE.offset));
  const r = await api('GET', `/api/admin/users?${params}`);
  const users = listOf(r, 'users');
  PEOPLE.users = append ? [...PEOPLE.users, ...users] : users;
  PEOPLE.total = r && typeof r.total === 'number' ? r.total : PEOPLE.users.length;
  const list = $('people-list');
  if (!list) return;
  const table = dataTable({
    caption: 'People',
    columns: [
      {
        key: 'name',
        label: 'Name',
        render: (u) => {
          const b = h('button', { type: 'button', class: 'linkish', dataset: { userId: u.id } }, personName(u));
          b.addEventListener('click', () => openPerson(u.id));
          return b;
        },
      },
      { key: 'email', label: 'Email' },
      { key: 'role', label: 'Role', render: (u) => (u.role && u.role.name) || '—' },
      { key: 'status', label: 'Status', render: (u) => statusBadge(u.status) },
      { key: 'last_login_at', label: 'Last sign-in', render: (u) => ago(u.last_login_at) },
    ],
    rows: PEOPLE.users,
    empty: emptyState({ icon: 'users', title: 'Nobody matches', body: PEOPLE.q || PEOPLE.status || PEOPLE.role ? 'Try a different search.' : 'Invite someone to get started.' }),
  });
  const more = PEOPLE.users.length < PEOPLE.total ? h('button', { type: 'button', class: 'btn btn-ghost btn-block' }, `Show more (${fmtNumber(PEOPLE.total - PEOPLE.users.length)} left)`) : null;
  if (more) {
    more.addEventListener('click', () =>
      busy(more, async () => {
        PEOPLE.offset = PEOPLE.users.length;
        await fetchPeople({ append: true });
      }),
    );
  }
  list.replaceChildren(table, ...(more ? [more] : []));
}

async function openPerson(id) {
  const detail = $('person-detail');
  if (!detail) return;
  PEOPLE.selected = id;
  detail.hidden = false;
  $('people-layout').classList.add('has-detail');
  detail.replaceChildren(skeleton(8));
  let d;
  try {
    d = await api('GET', `/api/admin/users/${encodeURIComponent(id)}`);
  } catch (err) {
    detail.replaceChildren(banner('danger', 'This person couldn’t be loaded', errorMessage(err)));
    return;
  }
  await renderPerson(d);
  detail.focus();
}

async function refreshPerson() {
  if (PEOPLE.selected === null) return;
  await Promise.allSettled([openPerson(PEOPLE.selected), fetchPeople()]);
}

function closePerson() {
  PEOPLE.selected = null;
  const detail = $('person-detail');
  detail.hidden = true;
  detail.replaceChildren();
  $('people-layout').classList.remove('has-detail');
}

// One action, one confirmation, one sentence back; then reload the person.
async function personAction(area, { title, body, confirmLabel, danger = false, method = 'POST', path, payload = {}, done }) {
  const ok = await confirmed({ title, body, confirmLabel, danger });
  if (!ok) return null;
  try {
    const r = await api(method, path, method === 'DELETE' ? undefined : payload);
    if (done) toast(done, 'ok');
    await refreshPerson();
    return r || {};
  } catch (err) {
    showFailure(area, err);
    return null;
  }
}

async function renderPerson(d) {
  const user = d && d.user && typeof d.user === 'object' ? d.user : d || {};
  const id = user.id;
  const self = id === S.meId;
  const area = resultArea('person-result');
  const base = `/api/admin/users/${encodeURIComponent(id)}`;
  const cards = [];

  const closeBtn = h('button', { type: 'button', class: 'btn btn-ghost btn-sm', 'aria-label': 'Close' }, icon('x', { size: 18 }));
  closeBtn.addEventListener('click', closePerson);
  cards.push(
    h(
      'section',
      { class: 'card stack' },
      h(
        'div',
        { class: 'split' },
        h(
          'div',
          { class: 'detail-head' },
          h('span', { class: 'avatar', 'aria-hidden': 'true' }, personName(user).split(/\s+/).map((p) => p[0] || '').join('').slice(0, 2).toUpperCase()),
          h('div', null, h('h3', { id: 'person-name', class: 'card-title' }, personName(user)), h('p', { class: 'card-sub' }, [str(user.email), str(user.employee_no)].filter(Boolean).join(' · '))),
          statusBadge(user.status),
          user.role ? badge(user.role.name, 'accent') : null,
          user.locked ? badge('Locked after failed sign-ins', 'warn') : null,
          self ? badge('You', 'neutral') : null,
        ),
        closeBtn,
      ),
      area,
    ),
  );

  cards.push(profileCard(user, base, area));
  cards.push(statusCard(user, base, area, self));
  cards.push(await accessCard(d, user, base, area, self));
  if (can('users.reset_mfa') || can('users.reset_password') || can('users.suspend') || d.factors) cards.push(securityCard(d, user, base, area, self));
  if (can('destinations.manage')) cards.push(await destinationsCard(user, base, area));
  if (d.streak || can('streaks.manage')) cards.push(streakCard(d.streak, user, base, area));
  if (user.status === 'invited' && can('users.invite')) {
    cards.push(
      card(
        'Invitation',
        d.invitation && d.invitation.expires_at ? `The current link expires ${fmtDateTime(d.invitation.expires_at)}.` : 'They haven’t joined yet.',
        h(
          'div',
          { class: 'cluster' },
          writeBtn('users.invite', 'Reissue the link', async () => {
            try {
              const r = await api('POST', `${base}/invitation`, {});
              showLink({ url: r.url || (r.invitation && r.invitation.url), expires: r.expires_at || (r.invitation && r.invitation.expires_at), who: personName(user) });
              await refreshPerson();
            } catch (err) {
              showFailure(area, err);
            }
          }),
        ),
      ),
    );
  }
  $('person-detail').replaceChildren(...cards.filter(Boolean));
}

const PROFILE_FIELDS = [
  ['full_name', 'Full name'],
  ['username', 'Username'],
  ['employee_no', 'Employee number'],
  ['job_title', 'Job title'],
  ['department', 'Department'],
  ['manager_id', 'Manager (person number)'],
];

function profileCard(user, base, area) {
  if (!can('users.edit')) {
    return card('Profile', null, h('dl', { class: 'kv' }, PROFILE_FIELDS.flatMap(([k, label]) => [h('dt', null, label), h('dd', null, str(user[k]) || '—')])));
  }
  const inputs = {};
  const grid = h(
    'div',
    { class: 'form-grid' },
    PROFILE_FIELDS.map(([k, label]) => {
      inputs[k] = h('input', { id: `person-${k}`, type: 'text', value: str(user[k]), inputmode: k === 'manager_id' ? 'numeric' : null, autocomplete: 'off' });
      return field(label, inputs[k]);
    }),
  );
  const form = h('form', { id: 'person-profile', novalidate: true }, grid, h('div', { class: 'form-actions form-actions-row' }, submitBtn('users.edit', 'Save profile')));
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const patch = {};
    let bad = false;
    for (const [k] of PROFILE_FIELDS) {
      const v = inputs[k].value.trim();
      setFieldError(inputs[k], '');
      if (v === str(user[k])) continue;
      if (k === 'full_name' && !v) {
        setFieldError(inputs[k], 'A name is required.');
        bad = true;
        continue;
      }
      if (k === 'manager_id') {
        if (v && !/^\d+$/.test(v)) {
          setFieldError(inputs[k], 'Use the manager’s person number, or leave it empty.');
          bad = true;
          continue;
        }
        patch[k] = v ? Number(v) : null;
      } else patch[k] = v || null;
    }
    if (bad) return;
    if (!Object.keys(patch).length) {
      area.replaceChildren(banner('info', null, 'Nothing has changed.'));
      return;
    }
    busy(form.querySelector('button[type=submit]'), async () => {
      try {
        await api('PATCH', base, patch);
        toast('Profile saved.', 'ok');
        await refreshPerson();
      } catch (err) {
        const f = err instanceof ApiError && err.body && typeof err.body.field === 'string' ? inputs[err.body.field] : null;
        if (f) setFieldError(f, refusalText(err));
        else showFailure(area, err);
      }
    });
  });
  return card('Profile', null, form);
}

function statusCard(user, base, area, self) {
  const statusBtn = (status, label, verb, perm, danger, body) =>
    writeBtn(
      perm,
      label,
      () =>
        personAction(area, {
          title: `${label} ${personName(user)}?`,
          body,
          confirmLabel: label,
          danger,
          path: `${base}/status`,
          payload: { status },
          done: `${personName(user)} ${verb}.`,
        }),
      { kind: danger ? 'danger' : 'secondary' },
    );
  const buttons = [];
  if (!self) {
    if (user.status === 'active') {
      buttons.push(statusBtn('suspended', 'Suspend', 'suspended', 'users.suspend', true, 'They are signed out everywhere and can’t sign in until reinstated. Nothing is deleted.'));
      buttons.push(statusBtn('disabled', 'Disable', 'disabled', 'users.disable', true, 'For leavers: they are signed out and can’t sign in. Their record and audit trail are kept, and you can enable them again.'));
    } else if (user.status === 'suspended') {
      buttons.push(statusBtn('active', 'Reinstate', 'reinstated', 'users.suspend', false, 'They can sign in again.'));
      buttons.push(statusBtn('disabled', 'Disable', 'disabled', 'users.disable', true, 'For leavers: their record and audit trail are kept.'));
    } else if (user.status === 'disabled') {
      buttons.push(statusBtn('active', 'Enable', 'enabled', 'users.disable', false, 'They can sign in again with their existing password and factors.'));
    }
  }
  const live = buttons.filter(Boolean);
  if (!live.length && !self) return null;
  return card('Status', self ? 'You can’t change your own status.' : null, live.length ? h('div', { class: 'cluster' }, live) : null);
}

const SOURCE_TEXT = { account: 'Super Admin', role: 'Role', temp_role: 'Temporary role', flag: 'Granted to them' };

async function accessCard(d, user, base, area, self) {
  const [roles, catalog] = await Promise.all([getRoles().catch(() => []), getCatalog().catch(() => [])]);
  const effective = permSet(Array.isArray(d.permissions) ? d.permissions : []);
  const sources = d.sources && typeof d.sources === 'object' ? d.sources : {};
  const denied = permSet(Array.isArray(d.denied) ? d.denied : []);
  const grants = permSet(d.perm_grants || user.perm_grants || []);
  const denies = permSet(d.perm_denies || user.perm_denies || []);
  const editable = can('users.roles') && !self;
  const perms = catalog.length
    ? catalog
    : [...new Set([...effective, ...grants, ...denies])].sort().map((key) => ({ key, label: key, group: humanize(key.split('.')[0]) }));

  const boxes = [];
  const rows = [];
  let group = null;
  for (const p of perms) {
    if (p.group !== group) {
      group = p.group;
      rows.push(h('tr', { class: 'perm-group' }, h('th', { scope: 'rowgroup', colspan: editable ? 5 : 3 }, str(group))));
    }
    const has = effective.has(p.key) || effective.has('*');
    const src = has ? sources[p.key] || (effective.has('*') ? 'account' : 'role') : denied.has(p.key) ? 'denied' : null;
    const cells = [
      h('td', null, h('span', null, str(p.label) || p.key), h('br'), h('code', { class: 'small muted' }, p.key), p.danger ? [' ', badge('Needs step-up', 'warn')] : null),
      h('td', null, has ? h('span', { class: 'badge badge-ok' }, icon('check', { size: 14 }), 'Yes') : h('span', { class: 'muted' }, 'No')),
      h('td', null, src ? h('span', { class: `source-chip source-${src}` }, src === 'denied' ? 'Denied for them' : SOURCE_TEXT[src] || humanize(src)) : '—'),
    ];
    if (editable) {
      const g = h('input', { type: 'checkbox', checked: grants.has(p.key), disabled: !!p.reserved, 'aria-label': `Grant ${p.key}`, dataset: { perm: p.key, kind: 'grant' }, title: p.reserved ? 'Only a Super Admin holds this; it can’t be granted.' : null });
      const x = h('input', { type: 'checkbox', checked: denies.has(p.key), 'aria-label': `Deny ${p.key}`, dataset: { perm: p.key, kind: 'deny' } });
      boxes.push(g, x);
      cells.push(h('td', null, g), h('td', null, x));
    }
    rows.push(h('tr', { dataset: { perm: p.key } }, cells));
  }
  const table = h(
    'div',
    { class: 'table-wrap' },
    h(
      'table',
      { class: 'table perm-table' },
      h('caption', { class: 'sr-only' }, 'Permissions and where each comes from'),
      h('thead', null, h('tr', null, h('th', { scope: 'col' }, 'Permission'), h('th', { scope: 'col' }, 'Has it'), h('th', { scope: 'col' }, 'Because'), editable ? [h('th', { scope: 'col' }, 'Grant'), h('th', { scope: 'col' }, 'Deny')] : null)),
      h('tbody', null, rows),
    ),
  );

  const parts = [];
  const currentRoleId = user.role ? user.role.id : null;
  if (editable && roles.length) {
    const roleSel = select(roleOptions(roles, currentRoleId), currentRoleId, { id: 'person-role' });
    const save = writeBtn('users.roles', 'Save role and permissions', async () => {
      const perm_grants = boxes.filter((b) => b.dataset.kind === 'grant' && b.checked).map((b) => b.dataset.perm);
      const perm_denies = boxes.filter((b) => b.dataset.kind === 'deny' && b.checked).map((b) => b.dataset.perm);
      try {
        await api('POST', `${base}/role`, { role_id: Number(roleSel.value), perm_grants, perm_denies });
        toast('Access saved.', 'ok');
        await refreshPerson();
      } catch (err) {
        showFailure(area, err);
      }
    }, { kind: 'primary', size: '' });
    parts.push(h('div', { class: 'toolbar' }, field('Role', roleSel, 'Roles at or above your own rank can’t be assigned.'), save));
  } else {
    parts.push(h('p', null, 'Role: ', h('strong', null, (user.role && user.role.name) || '—')));
  }
  parts.push(h('p', { class: 'hint' }, 'Denies beat grants. Reserved capabilities belong to Super Admins alone and can’t be granted to anyone.'), table);
  parts.push(tempRoles(d, roles, base, area, self));
  return card('Access', 'What they can do, and why.', ...parts);
}

function tempRoles(d, roles, base, area, self) {
  const temp = listOf(d.temp_roles, 'temp_roles');
  const list = temp.length
    ? h(
        'ul',
        { class: 'item-list' },
        temp.map((t) => {
          const name = (t.role && t.role.name) || (roles.find((r) => r.id === t.role_id) || {}).name || `Role ${t.role_id}`;
          const expired = t.expires_at && Date.parse(t.expires_at) < Date.now();
          return h(
            'li',
            { class: 'item-row' },
            h('span', { class: 'item-main' }, h('span', { class: 'item-title' }, name), h('span', { class: 'item-sub' }, expired ? `Expired ${fmtDateTime(t.expires_at)}` : `Until ${fmtDateTime(t.expires_at)}`)),
            self
              ? null
              : writeBtn('users.roles', 'Revoke', () =>
                  personAction(area, {
                    title: `Revoke the temporary ${name} role?`,
                    body: 'It ends now instead of at its expiry.',
                    confirmLabel: 'Revoke',
                    method: 'DELETE',
                    path: `${base}/temp-role/${encodeURIComponent(t.role_id)}`,
                    done: 'Temporary role revoked.',
                  }),
                ),
          );
        }),
      )
    : h('p', { class: 'muted' }, 'No temporary roles.');
  let form = null;
  if (can('users.roles') && !self && roles.length) {
    const roleSel = select(roleOptions(roles, null, { blank: 'Choose a role' }), '', { id: 'temp-role' });
    const until = h('input', { id: 'temp-until', type: 'datetime-local' });
    form = h('form', { class: 'toolbar', novalidate: true }, field('Role', roleSel), field('Until', until, 'Up to 90 days.'), submitBtn('users.roles', 'Grant for a while', { kind: 'secondary' }));
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      setFieldError(roleSel, '');
      setFieldError(until, '');
      if (!roleSel.value) return setFieldError(roleSel, 'Choose a role.');
      const ms = until.value ? new Date(until.value).getTime() : NaN;
      if (!Number.isFinite(ms)) return setFieldError(until, 'Choose when it ends — a temporary role always ends.');
      if (ms <= Date.now()) return setFieldError(until, 'Choose a time in the future.');
      if (ms > Date.now() + 90 * 86400000) return setFieldError(until, 'At most 90 days from now.');
      busy(form.querySelector('button[type=submit]'), async () => {
        try {
          await api('POST', `${base}/temp-role`, { role_id: Number(roleSel.value), expires_at: new Date(ms).toISOString() });
          toast('Temporary role granted.', 'ok');
          await refreshPerson();
        } catch (err) {
          showFailure(area, err);
        }
      });
    });
  }
  return h('div', { class: 'sub-section stack-sm' }, h('h4', { class: 'sub-title' }, 'Temporary roles'), list, form);
}

function securityCard(d, user, base, area, self) {
  const f = d.factors && typeof d.factors === 'object' ? d.factors : null;
  const facts = f
    ? [
        ['Passkeys', fmtNumber(f.passkeys || 0)],
        ['Authenticator app', f.totpUnreadable ? 'Unreadable — reset it' : f.totp ? 'On' : 'Not set up'],
        ['Backup codes', fmtNumber(f.backup || 0)],
        ['Code destinations', fmtNumber(f.destinations || 0)],
      ]
    : [];
  const name = personName(user);
  const buttons = self
    ? []
    : [
        writeBtn('users.reset_mfa', 'Reset second factors', () =>
          personAction(area, {
            title: `Reset ${name}’s second factors?`,
            body: 'For “I’ve lost my phone”: clears their authenticator app, every passkey and their backup codes, and drops their grace windows. It’s refused if they’d be left with no way to get a code — add a phone number or email first. A Super Admin can revert it.',
            confirmLabel: 'Reset factors',
            danger: true,
            path: `${base}/reset-mfa`,
            done: 'Second factors cleared.',
          }), { kind: 'danger' }),
        writeBtn('users.reset_password', 'Reset password', async () => {
          const ok = await confirmed({ title: `Reset ${name}’s password?`, body: 'They are signed out everywhere and get a temporary password, shown to you once. They must choose a new one when they sign in. This can’t be reverted.', confirmLabel: 'Reset password', danger: true });
          if (!ok) return;
          try {
            const r = await api('POST', `${base}/reset-password`, {});
            const pw = r && typeof r.temporary_password === 'string' ? r.temporary_password : '';
            const done = h('button', { type: 'button', class: 'btn btn-primary' }, 'I’ve passed it on');
            const m = modal({
              title: 'Temporary password',
              body: [h('p', null, `Give this to ${name} in person or by phone. It is shown once, and they’ll choose their own when they sign in.`), h('p', { id: 'temp-password', class: 'device-code' }, pw), copyRow('Copy it', pw)],
              actions: [done],
            });
            done.addEventListener('click', () => m.close(true));
            await refreshPerson();
          } catch (err) {
            showFailure(area, err);
          }
        }, { kind: 'danger' }),
        writeBtn('users.suspend', 'Sign out everywhere', () =>
          personAction(area, { title: `Sign ${name} out everywhere?`, body: 'Every session they have ends now. They can sign in again.', confirmLabel: 'Sign out', path: `${base}/logout`, done: `${name} signed out everywhere.` }),
        ),
        writeBtn('users.suspend', 'Revoke their devices', () =>
          personAction(area, { title: `Revoke ${name}’s devices?`, body: 'Every device they’ve used goes back to waiting for approval, their grace windows are dropped and their sessions end.', confirmLabel: 'Revoke devices', danger: true, path: `${base}/revoke-devices`, done: 'Devices revoked.' }),
        ),
      ].filter(Boolean);
  if (!facts.length && !buttons.length) return null;
  return card(
    'Sign-in security',
    self ? 'Manage your own sign-in methods from your account page.' : null,
    facts.length ? h('dl', { class: 'kv' }, facts.flatMap(([k, v]) => [h('dt', null, k), h('dd', null, v)])) : null,
    buttons.length ? h('div', { class: 'cluster' }, buttons) : null,
  );
}

async function destinationsCard(user, base, area) {
  let rows = [];
  let loadErr = null;
  try {
    rows = listOf(await api('GET', `${base}/destinations`), 'destinations');
  } catch (err) {
    loadErr = err;
  }
  const list = rows.length
    ? h(
        'ul',
        { class: 'item-list' },
        rows.map((x) =>
          h(
            'li',
            { class: 'item-row' },
            h('span', { class: 'item-icon' }, icon(x.kind === 'email' ? 'mail' : 'sms')),
            h('span', { class: 'item-main' }, h('span', { class: 'item-title' }, str(x.hint) || str(x.label) || x.kind, x.is_primary ? [' ', badge('Primary', 'accent')] : null), h('span', { class: 'item-sub' }, [x.kind === 'email' ? 'Email' : 'Text message', str(x.label)].filter(Boolean).join(' · '))),
            writeBtn('destinations.manage', 'Remove', () =>
              personAction(area, { title: 'Remove this destination?', body: 'Codes stop going there. The portal won’t remove the last way this person has to confirm it’s them.', confirmLabel: 'Remove', danger: true, method: 'DELETE', path: `${base}/destinations/${encodeURIComponent(x.id)}`, done: 'Destination removed.' }),
            ),
          ),
        ),
      )
    : h('p', { class: 'muted' }, loadErr ? errorMessage(loadErr) : 'None.');
  const kind = select([{ value: 'sms', label: 'Text message' }, { value: 'email', label: 'Email' }], 'sms', { id: 'dest-kind' });
  const address = h('input', { id: 'dest-address', type: 'text', autocomplete: 'off' });
  const label = h('input', { id: 'dest-label', type: 'text', maxlength: 60, autocomplete: 'off' });
  const form = h('form', { class: 'form-grid', novalidate: true }, field('Kind', kind), field('Number or address', address), field('Label (optional)', label), h('div', { class: 'field' }, submitBtn('destinations.manage', 'Add destination', { kind: 'secondary' })));
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const a = address.value.trim();
    setFieldError(address, '');
    if (!a) return setFieldError(address, kind.value === 'email' ? 'Enter the email address.' : 'Enter the phone number, with its country code.');
    busy(form.querySelector('button[type=submit]'), async () => {
      try {
        await api('POST', `${base}/destinations`, { kind: kind.value, address: a, label: label.value.trim() || undefined });
        toast('Destination added.', 'ok');
        await refreshPerson();
      } catch (err) {
        showFailure(area, err);
      }
    });
  });
  return card('Where sign-in codes go', 'Adding a number or address hands this person a second factor: codes sent there sign them in. Make sure it is really theirs.', list, form);
}

function intOrError(input, { min, max, required = true, label = 'This' }) {
  const raw = input.value.trim();
  if (!raw) return required ? { ok: false, error: `Enter a whole number from ${min} to ${max}.` } : { ok: true, value: undefined };
  if (!/^-?\d+$/.test(raw)) return { ok: false, error: `${label} must be a whole number.` };
  const n = Number(raw);
  if (n < min || n > max) return { ok: false, error: `Use a number from ${min} to ${max}.` };
  return { ok: true, value: n };
}

function streakCard(st, user, base, area) {
  const s = st && typeof st === 'object' ? st : null;
  const facts = s
    ? h('dl', { class: 'kv' }, [
        h('dt', null, 'State'), h('dd', null, STREAK_STATE_LABELS[s.state] || humanize(s.state) || '—'),
        h('dt', null, 'Current'), h('dd', null, plural(s.current || 0, 'day')),
        h('dt', null, 'Longest'), h('dd', null, plural(s.longest || 0, 'day')),
        h('dt', null, 'Last day'), h('dd', null, s.last_day ? dayLabel(s.last_day, { year: true }) : '—'),
      ])
    : h('p', { class: 'muted' }, 'No streak yet.');
  let form = null;
  if (can('streaks.manage')) {
    const cur = h('input', { id: 'streak-current', type: 'text', inputmode: 'numeric', value: s ? str(s.current) : '' });
    const lon = h('input', { id: 'streak-longest', type: 'text', inputmode: 'numeric', value: s ? str(s.longest) : '' });
    const why = h('input', { id: 'streak-reason', type: 'text', maxlength: 200, placeholder: 'e.g. Portal outage on Oct 1' });
    form = h('form', { class: 'form-grid', novalidate: true }, field('Current', cur), field('Longest', lon, 'Leave empty to keep it.'), field('Reason', why, 'Recorded in the audit log.', { wide: true }), h('div', { class: 'field' }, submitBtn('streaks.manage', 'Adjust streak', { kind: 'secondary' })));
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      for (const i of [cur, lon, why]) setFieldError(i, '');
      const c = intOrError(cur, { min: 0, max: 100000, label: 'Current' });
      const l = intOrError(lon, { min: 0, max: 100000, required: false, label: 'Longest' });
      let bad = false;
      if (!c.ok) {
        setFieldError(cur, c.error);
        bad = true;
      }
      if (!l.ok) {
        setFieldError(lon, l.error);
        bad = true;
      }
      if (!why.value.trim()) {
        setFieldError(why, 'Say why — it goes in the audit log.');
        bad = true;
      }
      if (bad) return;
      const payload = { current: c.value, reason: why.value.trim() };
      if (l.value !== undefined) payload.longest = l.value;
      busy(form.querySelector('button[type=submit]'), async () => {
        try {
          await api('POST', `${base}/streak`, payload);
          toast('Streak adjusted.', 'ok');
          S.loaded.delete('streaks');
          await refreshPerson();
        } catch (err) {
          showFailure(area, err);
        }
      });
    });
  }
  return card('Streak', can('streaks.manage') ? 'Restore one after an outage, a clock problem or a closure longer than the leeway. A Super Admin can revert it.' : null, facts, form);
}

// --------------------------------------------- invitations and requests ----

async function openInvite() {
  const roles = await getRoles().catch(() => []);
  const email = h('input', { id: 'invite-email', type: 'email', autocomplete: 'off', required: true });
  const name = h('input', { id: 'invite-name', type: 'text', autocomplete: 'off', required: true });
  const role = roles.length ? select(roleOptions(roles), defaultRoleId(roles), { id: 'invite-role' }) : null;
  const err = h('p', { class: 'form-error', role: 'alert', hidden: true });
  const send = h('button', { type: 'submit', class: 'btn btn-primary', dataset: { write: 'users.invite' } }, 'Create invitation');
  const cancel = h('button', { type: 'button', class: 'btn btn-secondary' }, 'Cancel');
  const form = h('form', { id: 'invite-form', class: 'stack', novalidate: true }, field('Email', email), field('Full name', name), role ? field('Role', role) : null, err);
  const m = modal({ title: 'Invite someone', body: [h('p', { class: 'muted' }, 'They get a one-time link to set their own password. Nobody else ever knows it.'), form], actions: [cancel, send] });
  cancel.addEventListener('click', () => m.close(false));
  send.addEventListener('click', () => form.requestSubmit());
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    setFieldError(email, '');
    setFieldError(name, '');
    const em = email.value.trim();
    const nm = name.value.trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em)) return setFieldError(email, 'Enter their email address.');
    if (!nm) return setFieldError(name, 'Enter their name.');
    busy(send, async () => {
      try {
        const body = { email: em, full_name: nm };
        if (role && role.value) body.role_id = Number(role.value);
        const r = await api('POST', '/api/admin/users', body);
        m.close(true);
        showLink({ url: r && r.invitation && r.invitation.url, expires: r && r.invitation && r.invitation.expires_at, who: nm });
        S.loaded.delete('invitations');
        if ($('people-list')) fetchPeople().catch(() => {});
        if (document.getElementById('tab-invitations') && document.getElementById('tab-invitations').getAttribute('aria-selected') === 'true') reload('invitations');
      } catch (e2) {
        err.textContent = refusalText(e2);
        err.hidden = false;
      }
    });
  });
  email.focus();
}

function invitationState(inv) {
  if (inv.used_at) return ['Used', 'ok'];
  if (inv.revoked_at) return ['Revoked', 'neutral'];
  if (inv.expires_at && Date.parse(inv.expires_at) < Date.now()) return ['Expired', 'warn'];
  return ['Waiting', 'accent'];
}

async function loadInvitations(body) {
  const parts = [];
  const area = resultArea('invitations-result');
  parts.push(area);
  if (can('users.invite')) {
    const rows = listOf(await api('GET', '/api/admin/invitations'), 'invitations');
    parts.push(
      card(
        'Invitations',
        'One-time links. Accepting one also approves the device it was accepted on.',
        h('div', { class: 'cluster' }, writeBtn('users.invite', 'Invite someone', () => openInvite(), { kind: 'primary', iconName: 'plus' })),
        dataTable({
          caption: 'Invitations',
          columns: [
            { key: 'email', label: 'Email' },
            { key: 'full_name', label: 'Name' },
            { key: 'created_at', label: 'Sent', render: (i) => ago(i.created_at) },
            { key: 'expires_at', label: 'Expires', render: (i) => when(i.expires_at) },
            { key: 'state', label: 'Status', render: (i) => badge(...invitationState(i)) },
            {
              key: 'actions',
              label: '',
              render: (i) =>
                invitationState(i)[0] === 'Waiting'
                  ? writeBtn('users.invite', 'Revoke', async () => {
                      const ok = await confirmed({ title: 'Revoke this invitation?', body: 'The link stops working. You can reissue one from the person’s page.', confirmLabel: 'Revoke', danger: true });
                      if (!ok) return;
                      try {
                        await api('POST', `/api/admin/invitations/${encodeURIComponent(i.id)}/revoke`, {});
                        toast('Invitation revoked.', 'ok');
                        await reload('invitations');
                      } catch (err) {
                        showFailure(area, err);
                      }
                    })
                  : null,
            },
          ],
          rows,
          empty: emptyState({ icon: 'mail', title: 'No invitations', body: 'Invite someone and their link shows here until it’s used.' }),
        }),
      ),
    );
  }
  if (can('requests.manage')) {
    const [reqs, roles] = await Promise.all([api('GET', '/api/admin/requests').then((r) => listOf(r, 'requests')), getRoles().catch(() => [])]);
    const pending = reqs.filter((r) => !r.status || r.status === 'pending');
    const done = reqs.filter((r) => r.status && r.status !== 'pending');
    parts.push(
      card(
        'Access requests',
        'Approving one creates the account and an invitation link for you to send.',
        pending.length
          ? h(
              'ul',
              { id: 'request-list', class: 'item-list' },
              pending.map((r) => {
                const role = roles.length ? select(roleOptions(roles), defaultRoleId(roles), { 'aria-label': `Role for ${str(r.email)}` }) : null;
                const from = [str(r.ip), str(r.country)].filter(Boolean).join(' · ');
                return h(
                  'li',
                  { class: 'item-row', dataset: { requestId: r.id } },
                  h(
                    'span',
                    { class: 'item-main' },
                    h('span', { class: 'item-title' }, str(r.full_name) || str(r.email), ' ', h('span', { class: 'muted' }, str(r.email))),
                    r.reason ? h('span', { class: 'item-sub' }, `“${str(r.reason)}”`) : null,
                    h('span', { class: 'item-sub' }, [fmtRelative(r.created_at), from, typeof r.risk === 'number' ? `risk ${r.risk}` : ''].filter(Boolean).join(' · ')),
                  ),
                  h(
                    'span',
                    { class: 'item-actions' },
                    role,
                    writeBtn('requests.manage', 'Approve', async () => {
                      try {
                        const out = await api('POST', `/api/admin/requests/${encodeURIComponent(r.id)}/approve`, role && role.value ? { role_id: Number(role.value) } : {});
                        showLink({ title: 'Approved — send the invitation', url: out && out.invitation && out.invitation.url, expires: out && out.invitation && out.invitation.expires_at, who: str(r.full_name) || str(r.email) });
                        await reload('invitations');
                      } catch (err) {
                        showFailure(area, err);
                      }
                    }, { kind: 'primary' }),
                    writeBtn('requests.manage', 'Deny', async () => {
                      const ok = await confirmed({ title: 'Deny this request?', body: 'They aren’t told; the request is closed.', confirmLabel: 'Deny', danger: true });
                      if (!ok) return;
                      try {
                        await api('POST', `/api/admin/requests/${encodeURIComponent(r.id)}/deny`, {});
                        toast('Request denied.', 'ok');
                        await reload('invitations');
                      } catch (err) {
                        showFailure(area, err);
                      }
                    }),
                  ),
                );
              }),
            )
          : h('p', { class: 'muted' }, 'No requests waiting.'),
        done.length ? h('p', { class: 'hint' }, `${plural(done.length, 'earlier request')} already handled.`) : null,
      ),
    );
  }
  body.replaceChildren(...parts);
}

// ---------------------------------------------------------------- roles ----

async function loadRoles(body) {
  const [roles, catalog] = await Promise.all([getRoles(true), getCatalog()]);
  const editor = h('div', { id: 'role-editor' });
  const isSystem = (r) => r.system === true || r.is_system === true || SYSTEM_ROLE_KEYS.includes(r.key);
  const table = dataTable({
    caption: 'Roles',
    columns: [
      { key: 'name', label: 'Role', render: (r) => h('span', null, h('strong', null, str(r.name)), r.description ? [h('br'), h('span', { class: 'small muted' }, str(r.description))] : null) },
      { key: 'rank', label: 'Rank', num: true },
      { key: 'permissions', label: 'Grants', render: (r) => (Array.isArray(r.permissions) && r.permissions.includes('*') ? 'Everything' : plural(Array.isArray(r.permissions) ? r.permissions.length : 0, 'permission')) },
      { key: 'holders', label: 'People', num: true, render: (r) => (typeof r.holders === 'number' ? fmtNumber(r.holders) : '—') },
      { key: 'type', label: 'Type', render: (r) => (isSystem(r) ? badge('System', 'neutral') : badge('Custom', 'accent')) },
      {
        key: 'open',
        label: '',
        render: (r) => {
          const b = h('button', { type: 'button', class: 'btn btn-ghost btn-sm' }, isSystem(r) || !can('roles.manage') ? 'View' : 'Edit');
          b.addEventListener('click', () => openRole(editor, r, catalog, isSystem(r)));
          return b;
        },
      },
    ],
    rows: [...roles].sort((a, b) => roleRank(b) - roleRank(a)),
  });
  body.replaceChildren(
    card('All roles', 'Rank is the whole authority model: you act only on people of a lower rank, and assign only roles below your own.', h('div', { class: 'cluster' }, writeBtn('roles.manage', 'New role', () => openRole(editor, null, catalog, false), { kind: 'primary', iconName: 'plus' })), table),
    editor,
  );
}

function groupCatalog(catalog) {
  const groups = new Map();
  for (const p of catalog) {
    const g = str(p.group) || 'Other';
    if (!groups.has(g)) groups.set(g, []);
    groups.get(g).push(p);
  }
  return groups;
}

function openRole(editor, role, catalog, system) {
  const area = resultArea('role-result');
  const perms = new Set(role && Array.isArray(role.permissions) ? role.permissions : []);
  if (system || !can('roles.manage')) {
    const all = perms.has('*');
    editor.replaceChildren(
      card(
        role ? str(role.name) : 'Role',
        system ? 'A system role: fixed, so every portal means the same thing by it.' : 'Only a Super Admin can edit roles.',
        all
          ? h('p', null, 'Everything, including the reserved capabilities nobody else can be granted.')
          : perms.size
            ? h('ul', { class: 'flag-list' }, [...groupCatalog(catalog.filter((p) => perms.has(p.key))).entries()].flatMap(([g, list]) => list.map((p) => h('li', null, h('span', null, str(p.label) || p.key), h('span', { class: 'muted small' }, g)))))
            : h('p', { class: 'muted' }, 'No permissions — signed in, little else.'),
      ),
    );
    return;
  }
  const name = h('input', { id: 'role-name', type: 'text', value: role ? str(role.name) : '', maxlength: 60 });
  const rank = h('input', { id: 'role-rank', type: 'text', inputmode: 'numeric', value: role ? str(role.rank) : '' });
  const desc = h('input', { id: 'role-desc', type: 'text', value: role ? str(role.description) : '', maxlength: 200 });
  const boxes = [];
  const groups = [...groupCatalog(catalog).entries()].map(([g, list]) =>
    h(
      'fieldset',
      { class: 'stack-sm' },
      h('legend', null, g),
      list.map((p) => {
        const c = check(p.reserved ? `${str(p.label) || p.key} — Super Admin only` : str(p.label) || p.key, perms.has(p.key), { disabled: !!p.reserved, dataset: { perm: p.key } });
        if (!p.reserved) boxes.push(c.input);
        return c.el;
      }),
    ),
  );
  const form = h(
    'form',
    { id: 'role-form', class: 'stack', novalidate: true },
    h('div', { class: 'form-grid' }, field('Name', name), field('Rank', rank, S.isSuper ? '1–99.' : `Below your own (${S.myRank}).`), field('Description', desc, '', { wide: true })),
    groups,
    area,
    h('div', { class: 'form-actions form-actions-row' }, role ? writeBtn('roles.manage', 'Delete role', async () => {
      const ok = await confirmed({ title: `Delete ${str(role.name)}?`, body: 'Refused while anyone holds it. A Super Admin can revert the deletion.', confirmLabel: 'Delete', danger: true });
      if (!ok) return;
      try {
        await api('DELETE', `/api/admin/roles/${encodeURIComponent(role.id)}`);
        toast('Role deleted.', 'ok');
        S.cache.roles = null;
        await reload('roles');
      } catch (err) {
        showFailure(area, err);
      }
    }, { kind: 'ghost', size: '' }) : null, submitBtn('roles.manage', role ? 'Save role' : 'Create role')),
  );
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    setFieldError(name, '');
    setFieldError(rank, '');
    const nm = name.value.trim();
    const rk = intOrError(rank, { min: 1, max: 99, label: 'Rank' });
    if (!nm) return setFieldError(name, 'Give the role a name.');
    if (!rk.ok) return setFieldError(rank, rk.error);
    if (!S.isSuper && rk.value >= S.myRank) return setFieldError(rank, `Use a rank below your own (${S.myRank}).`);
    const payload = { name: nm, rank: rk.value, description: desc.value.trim(), permissions: boxes.filter((b) => b.checked).map((b) => b.dataset.perm) };
    busy(form.querySelector('button[type=submit]'), async () => {
      try {
        await api(role ? 'PATCH' : 'POST', role ? `/api/admin/roles/${encodeURIComponent(role.id)}` : '/api/admin/roles', payload);
        toast(role ? 'Role saved.' : 'Role created.', 'ok');
        S.cache.roles = null;
        await reload('roles');
      } catch (err) {
        showFailure(area, err);
      }
    });
  });
  editor.replaceChildren(card(role ? `Edit ${str(role.name)}` : 'New role', 'Editing a role changes it for everyone who holds it.', form));
  name.focus();
}

// -------------------------------------------------------------- devices ----

const DEVICE_STATUS = { approved: ['Approved', 'ok'], pending: ['Waiting', 'warn'], blocked: ['Blocked', 'danger'] };

function normCode(s) {
  return str(s).toUpperCase().replace(/[^A-Z0-9]/g, '');
}

function deviceUsers(d) {
  const users = listOf(d.users, 'users');
  return users.length ? users.map(personName).join(', ') : '—';
}

async function deviceAction(area, d, verb, path, { method = 'POST', payload = {}, confirm = null } = {}) {
  if (confirm) {
    const ok = await confirmed(confirm);
    if (!ok) return;
  }
  try {
    await api(method, path, method === 'DELETE' ? undefined : payload);
    toast(`${str(d.label) || 'Device'} ${verb}.`, 'ok');
    await reload('devices');
  } catch (err) {
    showFailure(area, err);
  }
}

async function loadDevices(body) {
  const devices = listOf(await api('GET', '/api/admin/devices'), 'devices');
  const area = resultArea('devices-result');
  const pending = devices.filter((d) => d.status === 'pending');
  const base = (d) => `/api/admin/devices/${encodeURIComponent(d.id)}`;
  const approve = (d) => deviceAction(area, d, 'approved', `${base(d)}/approve`, { payload: { code: d.code } });
  const actions = (d) =>
    [
      d.status === 'pending' ? writeBtn('devices.approve', 'Approve', () => approve(d), { kind: 'primary' }) : null,
      d.status === 'blocked'
        ? writeBtn('devices.manage', 'Unblock', () => deviceAction(area, d, 'unblocked', `${base(d)}/unblock`))
        : writeBtn('devices.manage', 'Block', () => deviceAction(area, d, 'blocked', `${base(d)}/block`, { confirm: { title: 'Block this device?', body: 'It is refused at the gate in every mode, its sessions end and its grace windows are dropped.', confirmLabel: 'Block', danger: true } })),
      writeBtn('devices.manage', 'Rename', () => renameDevice(area, d)),
      d.status === 'approved' ? writeBtn('devices.manage', 'Revoke', () => deviceAction(area, d, 'revoked', base(d), { method: 'DELETE', confirm: { title: 'Revoke this device?', body: 'It goes back to waiting for approval; its sessions end and its grace windows are dropped.', confirmLabel: 'Revoke', danger: true } })) : null,
    ].filter(Boolean);

  const parts = [area];
  // The queue first: the codes people read out over the phone.
  let codeForm = null;
  if (can('devices.approve')) {
    const input = h('input', { id: 'device-code', type: 'text', class: 'code-input', autocomplete: 'off', autocapitalize: 'characters', spellcheck: 'false', maxlength: 16, placeholder: 'K7F3-9QX2' });
    const err = h('p', { id: 'device-code-error', class: 'form-error', role: 'alert', hidden: true });
    codeForm = h('form', { id: 'device-code-form', class: 'stack-sm', novalidate: true }, h('div', { class: 'toolbar' }, field('Approve by code', input, 'The code the waiting device shows. Ask the person to read it to you.'), submitBtn('devices.approve', 'Approve')), err);
    codeForm.addEventListener('submit', (e) => {
      e.preventDefault();
      err.hidden = true;
      const code = normCode(input.value);
      if (!code) {
        err.textContent = 'Type the code the device shows.';
        err.hidden = false;
        return;
      }
      const match = pending.find((d) => normCode(d.code) === code);
      if (!match) {
        err.textContent = `No device waiting for approval shows ${input.value.trim().toUpperCase()}. Check it with the person — codes look like K7F3-9QX2.`;
        err.hidden = false;
        return;
      }
      busy(codeForm.querySelector('button[type=submit]'), () => approve(match));
    });
  }
  parts.push(
    card(
      `Waiting for approval${pending.length ? ` (${pending.length})` : ''}`,
      null,
      codeForm,
      pending.length
        ? h(
            'ul',
            { id: 'pending-devices', class: 'item-list' },
            pending.map((d) =>
              h(
                'li',
                { class: 'item-row', dataset: { deviceId: d.id } },
                h('span', { class: 'code-chars badge badge-warn' }, str(d.code) || '—'),
                h('span', { class: 'item-main' }, h('span', { class: 'item-title' }, str(d.label) || 'Unnamed device'), h('span', { class: 'item-sub' }, [str(d.ip), str(d.country), d.created_at ? `first seen ${fmtRelative(d.created_at)}` : ''].filter(Boolean).join(' · '))),
                h('span', { class: 'item-actions' }, actions(d)),
              ),
            ),
          )
        : h('p', { class: 'muted' }, 'Nothing waiting.'),
    ),
  );
  parts.push(
    card(
      'All devices',
      null,
      dataTable({
        caption: 'All devices',
        columns: [
          { key: 'label', label: 'Device', render: (d) => str(d.label) || 'Unnamed device' },
          { key: 'status', label: 'Status', render: (d) => badge(...(DEVICE_STATUS[d.status] || [humanize(d.status) || 'Unknown', 'neutral'])) },
          { key: 'users', label: 'People', render: deviceUsers },
          { key: 'last_seen_at', label: 'Last seen', render: (d) => ago(d.last_seen_at) },
          { key: 'ip', label: 'From', render: (d) => [str(d.ip), str(d.country)].filter(Boolean).join(' · ') || '—' },
          { key: 'actions', label: '', render: (d) => h('span', { class: 'row-actions' }, actions(d)) },
        ],
        rows: devices,
        empty: emptyState({ icon: 'device', title: 'No devices yet' }),
      }),
    ),
  );
  body.replaceChildren(...parts);
}

function renameDevice(area, d) {
  return new Promise((resolve) => {
    const input = h('input', { id: 'device-rename', type: 'text', value: str(d.label), maxlength: 60 });
    const save = h('button', { type: 'button', class: 'btn btn-primary', dataset: { write: 'devices.manage' } }, 'Save');
    const cancel = h('button', { type: 'button', class: 'btn btn-secondary' }, 'Cancel');
    const m = modal({ title: 'Rename device', body: [field('Name', input, 'So people recognise it: “Reception iPad”, “Jane’s laptop”.')], actions: [cancel, save], onClose: () => resolve() });
    cancel.addEventListener('click', () => m.close(false));
    save.addEventListener('click', () =>
      busy(save, async () => {
        const v = input.value.trim();
        if (!v) return setFieldError(input, 'Give it a name.');
        m.close(true);
        await deviceAction(area, d, 'renamed', `/api/admin/devices/${encodeURIComponent(d.id)}/rename`, { payload: { label: v } });
      }),
    );
    input.focus();
  });
}

// -------------------------------------------------------------- network ----

// A §8: what each tier buys. Shown next to the choice, not in a manual.
export const TIERS = Object.freeze({
  1: ['Core admin network', 'nobody else is on it — a second factor every 7 days'],
  2: ['Trusted', 'others are on it — a second factor every 24 hours'],
  3: ['Shared', 'used often but shared with many — every 2 hours'],
  4: ['Temporary', 'a second factor every time, and the entry expires (24 hours unless you say)'],
});

function tierText(t) {
  const x = TIERS[t];
  return x ? `Tier ${t} · ${x[0]}` : `Tier ${str(t) || '?'}`;
}

function coveredByText(c) {
  if (!c) return '';
  if (typeof c === 'string') return c;
  if (typeof c === 'object') return [str(c.cidr), c.label ? `“${str(c.label)}”` : '', c.tier ? `(tier ${c.tier})` : ''].filter(Boolean).join(' ');
  return '';
}

function expiresInput(id) {
  return h('input', { id, type: 'text', inputmode: 'numeric', autocomplete: 'off', placeholder: 'Never' });
}

async function loadNetwork(body) {
  const r = await api('GET', '/api/admin/network');
  const allow = listOf(r && r.allow, 'allow');
  const block = listOf(r && r.block, 'block');
  const you = r && r.you && typeof r.you === 'object' ? r.you : {};
  const area = resultArea('network-result');
  const liveCovering = allow.filter((a) => a.active !== false && a.covers_ip);
  const covered = coveredByText(you.covered_by);
  const here = h(
    'div',
    { id: 'you-are-here', class: `banner ${covered ? 'banner-info' : 'banner-warn'}` },
    icon('globe'),
    h(
      'div',
      { class: 'banner-body' },
      h('p', { class: 'banner-title' }, `You are here: ${str(you.ip) || 'unknown address'}${you.country ? ` (${you.country})` : ''}`),
      h('p', null, covered ? `Covered by ${covered}.` : 'Not on the allowlist — you reach the portal through an approved device or the open gate.'),
    ),
  );

  const removeAllow = async (row) => {
    const onlyCover = row.covers_ip && liveCovering.filter((a) => a.id !== row.id).length === 0;
    const ok = await confirmed({
      title: `Remove ${str(row.cidr)}?`,
      body: onlyCover
        ? `This entry is what lets you in from ${str(you.ip)}. Removing it would remove your cover — the portal will refuse unless another entry covers you. Add your new address first.`
        : 'Addresses in this range lose their place on the allowlist and their grace windows. A Super Admin can revert it.',
      confirmLabel: 'Remove',
      danger: true,
    });
    if (!ok) return;
    try {
      await api('DELETE', `/api/admin/network/allow/${encodeURIComponent(row.id)}`);
      toast('Removed from the allowlist.', 'ok');
      await reload('network');
    } catch (err) {
      showFailure(area, err);
    }
  };
  const removeBlock = async (row) => {
    const ok = await confirmed({ title: `Unblock ${str(row.cidr)}?`, body: 'Visitors from this range are no longer refused outright.', confirmLabel: 'Unblock' });
    if (!ok) return;
    try {
      await api('DELETE', `/api/admin/network/block/${encodeURIComponent(row.id)}`);
      toast('Removed from the blocklist.', 'ok');
      await reload('network');
    } catch (err) {
      showFailure(area, err);
    }
  };

  const allowTable = dataTable({
    caption: 'Allowlist',
    columns: [
      { key: 'cidr', label: 'Range', render: (a) => h('code', null, str(a.cidr)) },
      { key: 'tier', label: 'Tier', render: (a) => tierText(a.tier) },
      { key: 'label', label: 'Label', render: (a) => [str(a.label), a.owner ? h('span', { class: 'muted small' }, ` · ${str(a.owner)}`) : null] },
      { key: 'expires_at', label: 'Expires', render: (a) => (a.expires_at ? when(a.expires_at) : 'Never') },
      { key: 'state', label: 'Status', render: (a) => [a.active === false ? badge('Expired', 'neutral') : badge('Live', 'ok'), a.covers_ip ? [' ', badge('Covers you', 'accent')] : null] },
      { key: 'actions', label: '', render: (a) => writeBtn('network.manage', 'Remove', () => removeAllow(a), { ariaLabel: `Remove ${str(a.cidr)}` }) },
    ],
    rows: allow,
    empty: emptyState({ icon: 'globe', title: 'The allowlist is empty' }),
  });
  const blockTable = dataTable({
    caption: 'Blocklist',
    columns: [
      { key: 'cidr', label: 'Range', render: (b) => h('code', null, str(b.cidr)) },
      { key: 'label', label: 'Reason', render: (b) => str(b.label || b.reason) || '—' },
      { key: 'expires_at', label: 'Expires', render: (b) => (b.expires_at ? when(b.expires_at) : 'Never') },
      { key: 'state', label: 'Status', render: (b) => [b.active === false ? badge('Expired', 'neutral') : badge('Live', 'danger'), b.covers_ip ? [' ', badge('Contains you', 'warn')] : null] },
      { key: 'actions', label: '', render: (b) => writeBtn('network.manage', 'Unblock', () => removeBlock(b), { ariaLabel: `Unblock ${str(b.cidr)}` }) },
    ],
    rows: block,
    empty: emptyState({ icon: 'shield', title: 'Nothing blocked' }),
  });

  let allowForm = null;
  let blockForm = null;
  if (can('network.manage')) {
    const cidr = h('input', { id: 'allow-cidr', type: 'text', autocomplete: 'off', spellcheck: 'false', placeholder: '81.2.69.0/24' });
    const tier = select([1, 2, 3, 4].map((t) => ({ value: t, label: `${t} — ${TIERS[t][0]}` })), 2, { id: 'allow-tier' });
    const label = h('input', { id: 'allow-label', type: 'text', maxlength: 60, placeholder: 'Office' });
    const owner = h('input', { id: 'allow-owner', type: 'text', maxlength: 60 });
    const expires = expiresInput('allow-expires');
    allowForm = h(
      'form',
      { id: 'allow-form', class: 'stack', novalidate: true },
      h('div', { class: 'form-grid' }, field('Address or range', cidr, 'A public address or CIDR. Private ranges and 0.0.0.0/0 are refused — use the gate for that.'), field('Tier', tier), field('Label', label), field('Owner', owner), field('Expires after (hours)', expires, 'Leave empty for never — tier 4 gets 24 hours.')),
      h('ul', { class: 'tier-help' }, [1, 2, 3, 4].map((t) => h('li', null, h('strong', null, `Tier ${t}, ${TIERS[t][0].toLowerCase()}: `), TIERS[t][1]))),
      h('div', { class: 'form-actions form-actions-row' }, submitBtn('network.manage', 'Add to allowlist')),
    );
    allowForm.addEventListener('submit', (e) => {
      e.preventDefault();
      setFieldError(cidr, '');
      setFieldError(expires, '');
      const c = cidr.value.trim();
      if (!c) return setFieldError(cidr, 'Enter an address or range.');
      const ex = intOrError(expires, { min: 1, max: 8760, required: false, label: 'Expiry' });
      if (!ex.ok) return setFieldError(expires, ex.error);
      const payload = { cidr: c, tier: Number(tier.value), label: label.value.trim() || undefined, owner: owner.value.trim() || undefined };
      if (ex.value !== undefined) payload.expires_in_hours = ex.value;
      busy(allowForm.querySelector('button[type=submit]'), async () => {
        try {
          await api('POST', '/api/admin/network/allow', payload);
          toast(`${c} added to the allowlist.`, 'ok');
          await reload('network');
        } catch (err) {
          showFailure(area, err);
        }
      });
    });

    const bcidr = h('input', { id: 'block-cidr', type: 'text', autocomplete: 'off', spellcheck: 'false', placeholder: '185.15.56.0/24' });
    const blabel = h('input', { id: 'block-label', type: 'text', maxlength: 60, placeholder: 'Credential stuffing' });
    const bexp = expiresInput('block-expires');
    blockForm = h(
      'form',
      { id: 'block-form', class: 'stack', novalidate: true },
      h('div', { class: 'form-grid' }, field('Address or range', bcidr), field('Reason', blabel), field('Expires after (hours)', bexp, 'Leave empty for never.')),
      h('div', { class: 'form-actions form-actions-row' }, submitBtn('network.manage', 'Block', { kind: 'danger' })),
    );
    blockForm.addEventListener('submit', (e) => {
      e.preventDefault();
      setFieldError(bcidr, '');
      setFieldError(bexp, '');
      const c = bcidr.value.trim();
      if (!c) return setFieldError(bcidr, 'Enter an address or range.');
      const ex = intOrError(bexp, { min: 1, max: 8760, required: false, label: 'Expiry' });
      if (!ex.ok) return setFieldError(bexp, ex.error);
      const payload = { cidr: c, label: blabel.value.trim() || undefined };
      if (ex.value !== undefined) payload.expires_in_hours = ex.value;
      busy(blockForm.querySelector('button[type=submit]'), async () => {
        try {
          await api('POST', '/api/admin/network/block', payload);
          toast(`${c} blocked.`, 'ok');
          await reload('network');
        } catch (err) {
          showFailure(area, err);
        }
      });
    });
  }

  body.replaceChildren(
    here,
    area,
    card('Allowlist', 'Most specific entry wins; on a tie, the stricter tier. Expired entries grant nothing.', allowTable, allowForm),
    card('Blocklist', 'Refused before anything else, in every mode.', blockTable, blockForm),
  );
}

// ---------------------------------------------------- security, settings ----

// B §6: what a stranger sees in each mode.
export const MODES = Object.freeze({
  public: ['Public', 'Anyone reaches the sign-in page. Every visit is still fingerprinted and logged.'],
  fingerprint_gate: ['Fingerprint gate', 'Strangers get the sign-in page only after their browser reports a fingerprint that scores under the risk threshold.'],
  request_access: ['Request access', 'Strangers see a form to ask for access; approving a request sends them an invitation.'],
  allowlist: ['Allowlist (default)', 'Strangers see nothing unless their network is on the allowlist or their device is approved.'],
  invite_only: ['Invite only', 'Strangers see nothing without a valid invitation link.'],
  lockdown: ['Lockdown', 'Nothing — except a Super Admin on an approved device from an allowlisted network. Everyone else’s sessions stop working.'],
});

const DENY_STYLES = {
  empty: ['Empty 403', 'An honest refusal with nothing in it.'],
  decoy: ['Decoy 404', 'Looks like a stock web server page, so the site doesn’t advertise that it exists.'],
};

const MFA_POLICIES = {
  prompt: ['Prompt', 'Ask everyone without a second factor to add one at every sign-in, but let them skip it.'],
  required: ['Required', 'Hold the session on the enrolment page until a passkey or authenticator app is confirmed. Never refuses the session.'],
};

const SECURITY_KEYS = ['access_mode', 'deny_style', 'country_allow', 'country_deny', 'block_tor', 'block_datacenter', 'block_automation', 'risk_threshold', 'mfa_policy', 'mfa_grace'];
const GENERAL_KEYS = ['device_gating', 'step_up_minutes', 'session_idle_minutes', 'session_absolute_hours', 'timezone', 'privacy_notice', 'privacy_notice_text'];
const STREAK_KEYS = ['streak_enabled', 'streak_window_hours', 'streak_reentry_grace_hours', 'streak_max_leeway_days', 'streak_weekly_days', 'streak_hebrew_holidays', 'streak_region', 'streak_extra_dates', 'streak_leaderboard'];

const LEADERBOARD = { all: 'Everyone', managers: 'Only people who can already see others’ streaks', off: 'Nobody — no leaderboard' };

function sameValue(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

function radioList(name, options, value, disabled) {
  const inputs = [];
  const list = h(
    'ul',
    { class: 'mode-list' },
    Object.entries(options).map(([v, [title, desc]]) => {
      const id = `${name}-${v}`;
      const input = h('input', { type: 'radio', id, name, value: v, checked: v === value, disabled });
      inputs.push(input);
      return h('li', null, h('label', { class: 'mode-option', for: id }, input, h('span', null, h('span', { class: 'choice-title' }, title), h('span', { class: 'choice-sub' }, desc))));
    }),
  );
  return { list, inputs, read: () => (inputs.find((i) => i.checked) || {}).value };
}

// One editable setting: its control, how to read it back, and what it was.
// read() → { ok: true, value } | { ok: false, error }. Blank numbers are an
// error, never a default; an explicit 0 stays 0 (A §14.1, §14.11).
function settingField(s) {
  const key = s.key;
  const editable = s.can_edit === true;
  const id = `set-${key}`;
  const label = str(s.label) || humanize(key.replace(/^streak_/, ''));
  const hint = [str(s.description), editable ? '' : 'Read-only for you.'].filter(Boolean).join(' ');
  const out = { key, editable, original: s.value, input: null, el: null, read: null };

  if (key === 'access_mode' || key === 'deny_style' || key === 'mfa_policy') {
    const opts = key === 'access_mode' ? MODES : key === 'deny_style' ? DENY_STYLES : MFA_POLICIES;
    const r = radioList(id, opts, s.value, !editable);
    out.input = r.inputs[0];
    out.el = h('fieldset', { class: 'stack-sm', id }, h('legend', null, label), r.list, h('p', { class: 'hint' }, editable ? '' : 'Read-only for you.'));
    out.read = () => {
      const v = r.read();
      return v ? { ok: true, value: v } : { ok: false, error: 'Choose one.' };
    };
    return out;
  }
  if (s.type === 'flag') {
    const c = check(label, s.value === true, { id, disabled: !editable });
    out.input = c.input;
    out.el = h('div', { class: 'field' }, c.el, hint ? h('p', { class: 'hint' }, hint) : null);
    out.read = () => ({ ok: true, value: c.input.checked });
    return out;
  }
  if (s.type === 'int') {
    const input = h('input', { id, type: 'text', inputmode: 'numeric', value: str(s.value), disabled: !editable, autocomplete: 'off' });
    out.input = input;
    out.el = field(label, input, [hint, `${s.min}–${s.max}.`].filter(Boolean).join(' '));
    out.read = () => {
      const r = intOrError(input, { min: typeof s.min === 'number' ? s.min : 0, max: typeof s.max === 'number' ? s.max : 1e9, label });
      return r;
    };
    return out;
  }
  if (s.type === 'timezone') {
    let zones = [];
    try {
      zones = typeof Intl.supportedValuesOf === 'function' ? Intl.supportedValuesOf('timeZone') : [];
    } catch {
      zones = [];
    }
    const cur = str(s.value) || 'UTC';
    if (!zones.includes(cur)) zones = [cur, ...zones];
    const input = zones.length > 1 ? select(zones.map((z) => ({ value: z, label: z.replace(/_/g, ' ') })), cur, { id, disabled: !editable }) : h('input', { id, type: 'text', value: cur, disabled: !editable });
    out.input = input;
    out.el = field(label, input, hint);
    out.read = () => (input.value.trim() ? { ok: true, value: input.value.trim() } : { ok: false, error: 'Choose a time zone.' });
    return out;
  }
  if (s.type === 'string') {
    const input = h('textarea', { id, maxlength: typeof s.max === 'number' ? s.max : 500, disabled: !editable });
    input.value = str(s.value);
    out.input = input;
    out.el = field(label, input, hint, { wide: true });
    out.read = () => (input.value.trim() ? { ok: true, value: input.value.trim() } : { ok: false, error: 'Write something, or turn the notice off instead.' });
    return out;
  }
  if (key === 'streak_weekly_days') {
    const days = new Set(Array.isArray(s.value) ? s.value : []);
    const boxes = WEEKDAYS.long.map((d, i) => check(d, days.has(i), { id: `${id}-${i}`, disabled: !editable, dataset: { day: i } }));
    out.input = boxes[0].input;
    out.el = h('fieldset', { id, class: 'field-wide' }, h('legend', null, 'Weekly protected days'), h('div', { class: 'weekday-checks' }, boxes.map((b) => b.el)), h('p', { class: 'hint' }, 'The clock pauses on these days every week.'));
    out.read = () => ({ ok: true, value: boxes.map((b, i) => (b.input.checked ? i : -1)).filter((i) => i >= 0) });
    return out;
  }
  if (key === 'streak_extra_dates') return extraDatesField(s, id, editable, out);
  if (s.type === 'json-list') {
    // Country lists: two-letter codes, comma separated.
    const v = Array.isArray(s.value) ? s.value.join(', ') : '';
    const input = h('input', { id, type: 'text', value: v, disabled: !editable, autocomplete: 'off', spellcheck: 'false', placeholder: key === 'country_allow' ? 'Empty: no restriction' : 'e.g. KP, RU' });
    out.input = input;
    out.original = Array.isArray(s.value) ? s.value : [];
    out.el = field(label, input, hint);
    out.read = () => {
      const list = input.value.split(/[\s,;]+/).map((c) => c.trim().toUpperCase()).filter(Boolean);
      const bad = list.find((c) => !/^[A-Z]{2}$/.test(c));
      if (bad) return { ok: false, error: `“${bad}” isn’t a two-letter country code.` };
      return { ok: true, value: [...new Set(list)].sort() };
    };
    return out;
  }
  if (s.type === 'enum') {
    const opts = (Array.isArray(s.options) ? s.options : []).map((o) => ({ value: o, label: key === 'streak_leaderboard' ? LEADERBOARD[o] || o : key === 'streak_region' ? (o === 'israel' ? 'Israel (one-day Yom Tov)' : 'Diaspora (two-day Yom Tov)') : humanize(o) }));
    const input = select(opts, s.value, { id, disabled: !editable });
    out.input = input;
    out.el = field(label, input, hint);
    out.read = () => ({ ok: true, value: input.value });
    return out;
  }
  return null;
}

function extraDatesField(s, id, editable, out) {
  let dates = (Array.isArray(s.value) ? s.value : []).filter((x) => x && typeof x === 'object').map((x) => ({ date: str(x.date), label: str(x.label) }));
  const list = h('ul', { id: `${id}-list`, class: 'extra-dates' });
  const render = () => {
    list.replaceChildren(
      ...(dates.length
        ? dates.map((d, i) => {
            const rm = editable ? h('button', { type: 'button', class: 'btn btn-ghost btn-sm', 'aria-label': `Remove ${d.date}` }, 'Remove') : null;
            if (rm) {
              rm.addEventListener('click', () => {
                dates = dates.filter((_, j) => j !== i);
                render();
                list.dispatchEvent(new Event('change', { bubbles: true }));
              });
            }
            return h('li', null, h('span', null, h('strong', null, dayLabel(d.date, { year: true })), ` · ${d.label}`), rm);
          })
        : [h('li', { class: 'muted' }, 'None.')]),
    );
  };
  render();
  let adder = null;
  if (editable) {
    const date = h('input', { id: `${id}-date`, type: 'date' });
    const label = h('input', { id: `${id}-label`, type: 'text', maxlength: 60, placeholder: 'Office closed' });
    const add = h('button', { type: 'button', class: 'btn btn-secondary' }, 'Add date');
    add.addEventListener('click', () => {
      setFieldError(date, '');
      setFieldError(label, '');
      const dv = date.value.trim();
      if (!/^\d{4}-\d{2}-\d{2}$/.test(dv) || dayLabel(dv) === '—') return setFieldError(date, 'Choose a date.');
      if (!label.value.trim()) return setFieldError(label, 'Say what it is — people see it on their dashboard.');
      if (dates.some((d) => d.date === dv)) return setFieldError(date, 'That date is already on the list.');
      dates = [...dates, { date: dv, label: label.value.trim() }].sort((a, b) => (a.date < b.date ? -1 : 1));
      date.value = '';
      label.value = '';
      render();
      list.dispatchEvent(new Event('change', { bubbles: true }));
    });
    adder = h('div', { class: 'toolbar' }, field('Date', date), field('Label', label), add);
  }
  out.input = list;
  out.original = (Array.isArray(s.value) ? s.value : []).map((x) => ({ date: str(x.date), label: str(x.label) }));
  out.el = h('fieldset', { id, class: 'field-wide stack-sm' }, h('legend', null, 'Extra protected dates'), h('p', { class: 'hint' }, 'One-off closures: the clock pauses on these too.'), list, adder);
  out.read = () => ({ ok: true, value: dates.map((d) => ({ date: d.date, label: d.label })) });
  out.count = () => dates.length;
  return out;
}

// The sentence a change will produce, before it is saved.
function rulePreview(fields) {
  const get = (k) => fields.find((f) => f.key === k);
  const read = (k) => {
    const f = get(k);
    if (!f) return { ok: true, value: undefined };
    return f.read();
  };
  const w = read('streak_window_hours');
  const g = read('streak_reentry_grace_hours');
  const l = read('streak_max_leeway_days');
  if (!w.ok || !g.ok || !l.ok) return 'Fix the highlighted numbers to see the rule.';
  const enabled = read('streak_enabled');
  if (enabled.ok && enabled.value === false) return 'Streaks are off: nobody’s streak is counted or shown.';
  const weekly = read('streak_weekly_days');
  const hebrew = read('streak_hebrew_holidays');
  const region = read('streak_region');
  const extra = get('streak_extra_dates');
  const calendar = describeCalendar({ weeklyDays: weekly.value || [], hebrew: hebrew.value === true, israel: region.value === 'israel', extraCount: extra && extra.count ? extra.count() : 0 });
  return streakRulesSentence({ window_hours: w.value, reentry_grace_hours: g.value, max_leeway_days: l.value, calendar });
}

async function saveSettings(fields, area, button) {
  area.replaceChildren();
  const changes = {};
  let bad = 0;
  for (const f of fields) {
    if (!f.editable) continue;
    const r = f.read();
    if (f.input && f.input.id) setFieldError(f.input, r.ok ? '' : r.error);
    if (!r.ok) {
      bad += 1;
      continue;
    }
    if (!sameValue(r.value, f.original)) changes[f.key] = r.value;
  }
  if (bad) {
    area.replaceChildren(banner('danger', null, `Fix the ${bad === 1 ? 'highlighted field' : `${bad} highlighted fields`} first. Nothing was saved.`));
    return null;
  }
  if (!Object.keys(changes).length) {
    area.replaceChildren(banner('info', null, 'Nothing has changed.'));
    return null;
  }
  return busy(button, async () => {
    try {
      const r = await api('PUT', '/api/admin/settings', { changes });
      return { ok: true, r, changes };
    } catch (err) {
      const f = err instanceof ApiError && err.body && typeof err.body.field === 'string' ? fields.find((x) => x.key === err.body.field) : null;
      if (f && f.input && f.input.id) setFieldError(f.input, refusalText(err));
      showFailure(area, err, 'Not saved');
      return { ok: false };
    }
  });
}

function savedBanners(r, changes) {
  const out = [banner('ok', null, `Saved ${plural(Object.keys(changes).length, 'change')}.`)];
  const warnings = messages(r && r.warnings);
  const notices = messages(r && r.notices);
  if (warnings.length) out.push(banner('warn', 'Saved, with a warning', null, h('ul', { class: 'stack-sm' }, warnings.map((w) => h('li', null, w)))));
  if (notices.length) out.push(banner('info', null, null, h('ul', { class: 'stack-sm' }, notices.map((n) => h('li', null, n)))));
  return out;
}

function settingsForm({ formId, resultId, groups, onSaved, preview = false }) {
  const all = groups.flatMap((g) => g.fields);
  const editable = all.some((f) => f.editable);
  const area = resultArea(resultId);
  const previewEl = preview ? h('p', { id: 'rule-preview', class: 'banner banner-rest', 'aria-live': 'polite' }) : null;
  const perm = groups.some((g) => g.perm === 'security.manage') ? 'security.manage' : 'settings.manage';
  const save = editable ? submitBtn(perm, 'Save changes', { id: `${formId}-save` }) : null;
  const form = h(
    'form',
    { id: formId, class: 'stack-lg', novalidate: true },
    groups.map((g) => h('div', { class: 'stack' }, h('h3', { class: 'sub-title' }, g.title), g.sub ? h('p', { class: 'hint' }, g.sub) : null, h('div', { class: 'form-grid' }, g.fields.map((f) => f.el)), g.preview ? previewEl : null)),
    area,
    save ? h('div', { class: 'form-actions form-actions-row' }, save) : null,
  );
  const refresh = () => {
    if (previewEl) previewEl.textContent = rulePreview(all);
  };
  refresh();
  form.addEventListener('input', refresh);
  form.addEventListener('change', refresh);
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!save) return;
    const res = await saveSettings(all, area, save);
    if (res && res.ok) {
      toast('Settings saved.', 'ok');
      S.cache.settings = null;
      await onSaved(savedBanners(res.r, res.changes));
    }
  });
  return { form, area };
}

function fieldsFor(settings, keys) {
  return keys
    .map((k) => settings.find((s) => s.key === k))
    .filter(Boolean)
    .map(settingField)
    .filter(Boolean);
}

async function loadSettings(body, banners = null) {
  const settings = await getSettings();
  const general = fieldsFor(settings, GENERAL_KEYS);
  const streak = fieldsFor(settings, STREAK_KEYS);
  const known = new Set([...SECURITY_KEYS, ...GENERAL_KEYS, ...STREAK_KEYS, 'gate_open']);
  const other = settings.filter((s) => !known.has(s.key)).map(settingField).filter(Boolean);
  const groups = [
    { title: 'General', sub: 'Sessions, step-up, device approval and the privacy notice.', fields: general },
    { title: 'Streak calendar', sub: 'Days nobody can sign in never count against anyone.', fields: streak, preview: true },
  ];
  if (other.length) groups.push({ title: 'Other', fields: other });
  const { form, area } = settingsForm({ formId: 'settings-form', resultId: 'settings-result', groups, preview: true, onSaved: (b) => reloadWith('settings', b) });
  body.replaceChildren(card(null, null, form));
  if (banners) area.replaceChildren(...banners);
}

async function reloadWith(tab, banners) {
  S.loaded.add(tab);
  const body = bodyOf(tab);
  await guarded(body, () => (tab === 'settings' ? loadSettings(body, banners) : loadSecurity(body, banners)));
  S.loaded.delete(tab === 'settings' ? 'security' : 'settings');
}

async function loadSecurity(body, banners = null) {
  const parts = [];
  if (can('gate.open')) parts.push(await gateCard());
  if (can('settings.view')) {
    const settings = await getSettings();
    const fields = fieldsFor(settings, SECURITY_KEYS);
    if (!can('gate.open')) {
      const g = settings.find((s) => s.key === 'gate_open');
      const v = g && g.value && typeof g.value === 'object' ? g.value : null;
      parts.push(card('Open to the internet', null, h('p', { id: 'gate-state' }, v && v.open ? (v.forever ? 'Open until a Super Admin closes it.' : `Open until ${fmtDateTime(v.until)}.`) : 'Closed.'), h('p', { class: 'hint' }, 'Only a Super Admin can open or close it.')));
    }
    const groups = [
      { title: 'Who may reach the portal', fields: fields.filter((f) => ['access_mode', 'deny_style'].includes(f.key)), perm: 'security.manage' },
      { title: 'Refuse outright', sub: 'An allowlisted network skips these, by design.', fields: fields.filter((f) => ['country_allow', 'country_deny', 'block_tor', 'block_datacenter', 'block_automation', 'risk_threshold'].includes(f.key)), perm: 'security.manage' },
      { title: 'Second factors', fields: fields.filter((f) => ['mfa_policy', 'mfa_grace'].includes(f.key)), perm: 'security.manage' },
    ].filter((g) => g.fields.length);
    if (groups.length) {
      const { form, area } = settingsForm({ formId: 'security-form', resultId: 'security-result', groups, onSaved: (b) => reloadWith('security', b) });
      parts.push(card(null, null, form));
      if (banners) area.replaceChildren(...banners);
    }
  }
  body.replaceChildren(...parts);
}

function countdownText(untilMs) {
  const left = Math.max(0, untilMs - Date.now());
  const s = Math.floor(left / 1000);
  const hh = Math.floor(s / 3600);
  const mm = Math.floor((s % 3600) / 60);
  const ss = s % 60;
  return `${hh}h ${String(mm).padStart(2, '0')}m ${String(ss).padStart(2, '0')}s`;
}

async function gateCard() {
  if (S.gateTimer) {
    clearInterval(S.gateTimer);
    S.gateTimer = null;
  }
  const g = await api('GET', '/api/admin/gate');
  const open = !!(g && g.open);
  const until = g && g.until ? (typeof g.until === 'number' ? g.until : Date.parse(g.until)) : NaN;
  const area = resultArea('gate-result');
  const state = h('div', { id: 'gate-state', class: 'gate-state' });
  if (open) {
    const cd = h('span', { id: 'gate-countdown', class: 'countdown' });
    state.append(badge('Open to the internet', 'danger'), ' ', g.forever ? h('span', null, 'until someone closes it') : h('span', null, `until ${fmtDateTime(until)} — closes in `, cd));
    if (!g.forever && Number.isFinite(until)) {
      const tick = () => {
        cd.textContent = countdownText(until);
        if (until <= Date.now() && S.gateTimer) {
          clearInterval(S.gateTimer);
          S.gateTimer = null;
          reload('security');
        }
      };
      tick();
      S.gateTimer = setInterval(tick, 1000);
    }
  } else state.append(badge('Closed', 'ok'), ' ', h('span', null, 'Only trusted networks and devices get in.'));

  const parts = [state, area];
  if (open) {
    parts.push(
      h(
        'div',
        { class: 'cluster' },
        writeBtn('gate.open', 'Close it now', async () => {
          try {
            await api('POST', '/api/admin/gate/close', {});
            toast('The portal is closed to the internet again.', 'ok');
            await reload('security');
          } catch (err) {
            showFailure(area, err);
          }
        }, { kind: 'primary', id: 'gate-close' }),
      ),
    );
  } else {
    // An explicit choice, every time: no default duration, and "until I close
    // it" is its own option (CONTRACTS §8.4: { forever: true }).
    const hoursRadio = h('input', { type: 'radio', id: 'gate-choice-hours', name: 'gate-choice', value: 'hours' });
    const foreverRadio = h('input', { type: 'radio', id: 'gate-choice-forever', name: 'gate-choice', value: 'forever' });
    const hours = h('input', { id: 'gate-hours', type: 'text', inputmode: 'numeric', autocomplete: 'off', placeholder: '1–168', 'aria-label': 'Hours to stay open' });
    const err = h('p', { id: 'gate-error', class: 'form-error', role: 'alert', hidden: true });
    const fail = (m) => {
      err.textContent = m;
      err.hidden = false;
    };
    const form = h(
      'form',
      { id: 'gate-form', class: 'stack', novalidate: true },
      h(
        'fieldset',
        { class: 'stack-sm' },
        h('legend', null, 'Open the portal to the whole internet'),
        h('ul', { class: 'mode-list' }, [
          h(
            'li',
            { class: 'stack-sm' },
            h('label', { class: 'mode-option', for: 'gate-choice-hours' }, hoursRadio, h('span', null, h('span', { class: 'choice-title' }, 'For a number of hours'), h('span', { class: 'choice-sub' }, 'Closes by itself. 1 to 168 hours.'))),
            h('div', { class: 'gate-hours' }, hours),
          ),
          h('li', null, h('label', { class: 'mode-option', for: 'gate-choice-forever' }, foreverRadio, h('span', null, h('span', { class: 'choice-title' }, 'Until I close it'), h('span', { class: 'choice-sub' }, 'Stays open until a Super Admin closes it. Easy to forget.')))),
        ]),
      ),
      err,
      h('div', { class: 'form-actions form-actions-row' }, submitBtn('gate.open', 'Open the portal', { kind: 'danger' })),
    );
    hours.addEventListener('focus', () => {
      hoursRadio.checked = true;
    });
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      err.hidden = true;
      let payload;
      if (hoursRadio.checked) {
        const r = intOrError(hours, { min: 1, max: 168, label: 'Hours' });
        if (!r.ok) return fail(r.error === 'Enter a whole number from 1 to 168.' ? 'Enter how many hours: a whole number from 1 to 168.' : r.error);
        payload = { hours: r.value };
      } else if (foreverRadio.checked) {
        payload = { forever: true };
      } else {
        return fail('Choose how long: a number of hours, or until you close it.');
      }
      const ok = await confirmed({
        title: 'Open the portal to the internet?',
        body: payload.forever ? 'Anyone can reach the sign-in page until you close it. Passwords and second factors still apply.' : `Anyone can reach the sign-in page for the next ${plural(payload.hours, 'hour')}. Passwords and second factors still apply.`,
        confirmLabel: 'Open it',
        danger: true,
      });
      if (!ok) return;
      await busy(form.querySelector('button[type=submit]'), async () => {
        try {
          await api('POST', '/api/admin/gate/open', payload);
          toast('The portal is open to the internet.', 'warn');
          await reload('security');
        } catch (e2) {
          showFailure(area, e2);
        }
      });
    });
    parts.push(form);
  }
  return h('section', { id: 'gate-card', class: 'card stack' }, h('div', null, h('h3', { class: 'card-title' }, 'Open to the internet'), h('p', { class: 'card-sub' }, 'Takes the network gate down for everyone, for a bounded time. Never applies in lockdown.')), parts);
}

// ------------------------------------------------------------- visitors ----

function riskChip(score, threshold = 70) {
  if (typeof score !== 'number' || !Number.isFinite(score)) return badge('—', 'neutral');
  const kind = score >= threshold ? 'danger' : score >= 30 ? 'warn' : 'ok';
  return h('span', { class: `badge badge-${kind} risk-chip`, title: `Risk ${score} of 100` }, String(score));
}

function flagReasons(v) {
  const flags = listOf((v.risk && v.risk.flags) || v.flags, 'flags');
  if (!flags.length) return h('span', { class: 'muted' }, 'Nothing raised it');
  return h(
    'details',
    { class: 'row-details' },
    h('summary', null, plural(flags.length, 'reason')),
    h('ul', { class: 'flag-list' }, flags.map((f) => h('li', null, h('span', null, str(f.reason) || str(f.key)), h('span', { class: 'flag-weight' }, `+${typeof f.weight === 'number' ? f.weight : 0}`)))),
  );
}

async function loadVisitors(body) {
  const r = await api('GET', '/api/admin/visitors');
  const visitors = listOf(r, 'visitors');
  const threshold = r && typeof r.threshold === 'number' ? r.threshold : 70;
  const decision = select(
    [
      { value: '', label: 'Every decision' },
      { value: 'allow', label: 'Let in' },
      { value: 'shell', label: 'Shown a limited page' },
      { value: 'deny', label: 'Refused' },
    ],
    '',
    { id: 'visit-decision' },
  );
  const visitsBox = h('div', { id: 'visits-list' });
  const loadVisits = async () => {
    visitsBox.replaceChildren(skeleton(3));
    try {
      const q = decision.value ? `?decision=${encodeURIComponent(decision.value)}` : '';
      const visits = listOf(await api('GET', `/api/admin/visits${q}`), 'visits');
      visitsBox.replaceChildren(
        dataTable({
          caption: 'Visit log',
          columns: [
            { key: 'at', label: 'When', render: (v) => ago(v.at) },
            { key: 'decision', label: 'Decision', render: (v) => badge(str(v.decision) || '—', v.decision === 'deny' ? 'danger' : v.decision === 'shell' ? 'warn' : 'ok') },
            { key: 'reason', label: 'Why', render: (v) => str(v.reason) || '—' },
            { key: 'path', label: 'Asked for', render: (v) => h('code', null, `${str(v.method) || 'GET'} ${str(v.path)}`) },
            { key: 'ip', label: 'From', render: (v) => [str(v.ip), str(v.country)].filter(Boolean).join(' · ') || '—' },
            { key: 'risk', label: 'Risk', render: (v) => riskChip(v.risk, threshold) },
          ],
          rows: visits,
          empty: emptyState({ icon: 'eye', title: 'No visits match' }),
        }),
      );
    } catch (err) {
      visitsBox.replaceChildren(banner('danger', null, errorMessage(err)));
    }
  };
  decision.addEventListener('change', loadVisits);
  body.replaceChildren(
    card(
      'Fingerprints',
      `Each browser’s risk score, with the reasons behind it. ${threshold} or more is refused.`,
      dataTable({
        caption: 'Visitor fingerprints',
        columns: [
          { key: 'visitor_id', label: 'Visitor', render: (v) => h('code', { title: str(v.visitor_id) }, str(v.visitor_id).slice(0, 10) || '—') },
          { key: 'last_seen', label: 'Last seen', render: (v) => ago(v.last_seen) },
          { key: 'from', label: 'From', render: (v) => [str(v.ip), str(v.country), str(v.as_org)].filter(Boolean).join(' · ') || '—' },
          { key: 'risk', label: 'Risk', render: (v) => riskChip(typeof v.risk === 'number' ? v.risk : v.risk && v.risk.score, threshold) },
          { key: 'why', label: 'Why', render: flagReasons },
        ],
        rows: visitors,
        empty: emptyState({ icon: 'eye', title: 'No fingerprints yet' }),
      }),
    ),
    card('Visit log', null, h('div', { class: 'toolbar' }, field('Show', decision)), visitsBox),
  );
  await loadVisits();
}

// ------------------------------------------------------------- sessions ----

async function loadSessions(body) {
  const rows = listOf(await api('GET', '/api/admin/sessions'), 'sessions');
  const area = resultArea('sessions-result');
  body.replaceChildren(
    area,
    card(
      null,
      null,
      dataTable({
        caption: 'Active sessions',
        columns: [
          { key: 'person', label: 'Person', render: (s) => personName(s.user || s) },
          { key: 'created_at', label: 'Signed in', render: (s) => ago(s.created_at) },
          { key: 'last_seen_at', label: 'Last active', render: (s) => ago(s.last_seen_at) },
          { key: 'ip', label: 'From', render: (s) => str(s.ip) || '—' },
          { key: 'aal', label: 'Second step', render: (s) => (s.aal === 2 ? badge('Yes', 'ok') : badge('Password only', 'neutral')) },
          {
            key: 'actions',
            label: '',
            render: (s) =>
              s.current
                ? badge('This is you', 'accent')
                : writeBtn('sessions.revoke', 'End', async () => {
                    const ok = await confirmed({ title: `End ${personName(s.user || s)}’s session?`, body: 'They are signed out of that browser now.', confirmLabel: 'End session', danger: true });
                    if (!ok) return;
                    try {
                      await api('DELETE', `/api/admin/sessions/${encodeURIComponent(str(s.id_ref))}`);
                      toast('Session ended.', 'ok');
                      await reload('sessions');
                    } catch (err) {
                      showFailure(area, err);
                    }
                  }, { ariaLabel: `End session for ${personName(s.user || s)}` }),
          },
        ],
        rows,
        empty: emptyState({ icon: 'device', title: 'Nobody is signed in' }),
      }),
    ),
  );
}

// -------------------------------------------------------------- streaks ----

const STREAK_SORT = { key: 'current', dir: 'desc' };
const STATE_ORDER = { at_risk: 0, paused: 1, active: 2, held: 3, lapsed: 4, none: 5 };

export function sortStreaks(rows, { key, dir }) {
  const sign = dir === 'asc' ? 1 : -1;
  const val = (r) => {
    if (key === 'name') return personName(r).toLowerCase();
    if (key === 'state') return STATE_ORDER[r.state] ?? 9;
    if (key === 'last_day') return str(r.last_day);
    return typeof r[key] === 'number' ? r[key] : -1;
  };
  return [...rows].sort((a, b) => {
    const x = val(a);
    const y = val(b);
    if (x < y) return -1 * sign;
    if (x > y) return 1 * sign;
    return personName(a).localeCompare(personName(b));
  });
}

async function loadStreaks(body) {
  const r = await api('GET', '/api/admin/streaks');
  const rows = listOf(r, 'streaks');
  const area = resultArea('streaks-result');
  const holder = h('div', { id: 'streaks-table', class: 'table-wrap' });
  const cols = [
    ['name', 'Person'],
    ['state', 'State'],
    ['current', 'Current'],
    ['longest', 'Longest'],
    ['last_day', 'Last day'],
  ];
  const draw = () => {
    const sorted = sortStreaks(rows, STREAK_SORT);
    const head = cols.map(([k, label]) => {
      const btn = h('button', { type: 'button', class: 'sort-btn', dataset: { sort: k } }, label, icon('chevron-down', { size: 14 }));
      btn.addEventListener('click', () => {
        if (STREAK_SORT.key === k) STREAK_SORT.dir = STREAK_SORT.dir === 'asc' ? 'desc' : 'asc';
        else {
          STREAK_SORT.key = k;
          STREAK_SORT.dir = k === 'name' || k === 'state' ? 'asc' : 'desc';
        }
        draw();
      });
      return h('th', { scope: 'col', class: ['current', 'longest'].includes(k) ? 'num' : null, 'aria-sort': STREAK_SORT.key === k ? (STREAK_SORT.dir === 'asc' ? 'ascending' : 'descending') : 'none' }, btn);
    });
    if (can('streaks.manage')) head.push(h('th', { scope: 'col' }, h('span', { class: 'sr-only' }, 'Actions')));
    holder.replaceChildren(
      rows.length
        ? h(
            'table',
            { class: 'table table-cards' },
            h('caption', { class: 'sr-only' }, 'Streaks'),
            h('thead', null, h('tr', null, head)),
            h(
              'tbody',
              null,
              sorted.map((s) =>
                h(
                  'tr',
                  { dataset: { userId: s.user_id } },
                  h('td', { 'data-label': 'Person' }, personName(s)),
                  h('td', { 'data-label': 'State' }, badge(STREAK_STATE_LABELS[s.state] || humanize(s.state) || '—', s.state === 'at_risk' ? 'warn' : s.state === 'active' ? 'flame' : s.state === 'paused' || s.state === 'held' ? 'rest' : 'neutral')),
                  h('td', { 'data-label': 'Current', class: 'num' }, fmtNumber(typeof s.current === 'number' ? s.current : 0)),
                  h('td', { 'data-label': 'Longest', class: 'num' }, fmtNumber(typeof s.longest === 'number' ? s.longest : 0)),
                  h('td', { 'data-label': 'Last day' }, s.last_day ? dayLabel(s.last_day) : '—'),
                  can('streaks.manage') ? h('td', { 'data-label': '' }, writeBtn('streaks.manage', 'Adjust', () => adjustStreak(area, s), { ariaLabel: `Adjust ${personName(s)}’s streak` })) : null,
                ),
              ),
            ),
          )
        : emptyState({ icon: 'trophy', title: 'No streaks yet' }),
    );
  };
  draw();
  body.replaceChildren(area, card(null, r && r.scope === 'team' ? 'Your direct reports.' : 'Everyone.', holder));
}

function adjustStreak(area, s) {
  return new Promise((resolve) => {
    const cur = h('input', { id: 'adjust-current', type: 'text', inputmode: 'numeric', value: str(s.current) });
    const lon = h('input', { id: 'adjust-longest', type: 'text', inputmode: 'numeric', value: str(s.longest) });
    const why = h('input', { id: 'adjust-reason', type: 'text', maxlength: 200 });
    const save = h('button', { type: 'button', class: 'btn btn-primary', dataset: { write: 'streaks.manage' } }, 'Adjust');
    const cancel = h('button', { type: 'button', class: 'btn btn-secondary' }, 'Cancel');
    const m = modal({ title: `Adjust ${personName(s)}’s streak`, body: [field('Current', cur), field('Longest', lon, 'Leave empty to keep it.'), field('Reason', why, 'Recorded in the audit log.')], actions: [cancel, save], onClose: () => resolve() });
    cancel.addEventListener('click', () => m.close(false));
    save.addEventListener('click', () =>
      busy(save, async () => {
        for (const i of [cur, lon, why]) setFieldError(i, '');
        const c = intOrError(cur, { min: 0, max: 100000, label: 'Current' });
        const l = intOrError(lon, { min: 0, max: 100000, required: false, label: 'Longest' });
        if (!c.ok) return setFieldError(cur, c.error);
        if (!l.ok) return setFieldError(lon, l.error);
        if (!why.value.trim()) return setFieldError(why, 'Say why — it goes in the audit log.');
        const payload = { current: c.value, reason: why.value.trim() };
        if (l.value !== undefined) payload.longest = l.value;
        try {
          await api('POST', `/api/admin/users/${encodeURIComponent(s.user_id)}/streak`, payload);
          m.close(true);
          toast('Streak adjusted.', 'ok');
          await reload('streaks');
        } catch (err) {
          setFieldError(why, refusalText(err));
        }
      }),
    );
    cur.focus();
  });
}

// ---------------------------------------------------------------- audit ----

const AUDIT = { filters: {}, entries: [], next: null };

const BREAK_REASONS = {
  seq_gap: 'a sequence number is missing or out of order there',
  prev_mismatch: 'it doesn’t point at the entry before it',
  hash_mismatch: 'its contents don’t match its hash — it was edited',
};

export function verifyText(r) {
  if (!r || typeof r !== 'object') return { ok: false, text: 'The check gave no answer.' };
  const checked = typeof r.checked === 'number' ? r.checked : 0;
  if (r.ok === true) return { ok: true, text: `Intact across ${plural(checked, 'entry', 'entries')}.` };
  const b = r.broken_at && typeof r.broken_at === 'object' ? r.broken_at : {};
  const seq = typeof b.seq === 'number' || typeof b.seq === 'string' ? b.seq : '?';
  const why = BREAK_REASONS[b.reason] || 'it doesn’t match';
  return { ok: false, text: `Broken at entry #${seq} — ${why}. ${plural(checked, 'entry', 'entries')} before it check out.` };
}

function auditRow(e, area) {
  const target = e.target_type ? `${str(e.target_type)} ${str(e.target_id)}`.trim() : '—';
  const details = h(
    'details',
    { class: 'row-details' },
    h('summary', null, 'Details'),
    h(
      'div',
      { class: 'stack-sm' },
      h('dl', { class: 'kv' }, [
        h('dt', null, 'Entry'), h('dd', null, `#${str(e.seq)} (id ${str(e.id)})`),
        h('dt', null, 'From'), h('dd', null, [str(e.ip), e.device_id ? `device ${str(e.device_id)}` : ''].filter(Boolean).join(' · ') || '—'),
        e.reverts_id ? [h('dt', null, 'Reverts'), h('dd', null, `entry id ${str(e.reverts_id)}`)] : null,
        e.error ? [h('dt', null, 'Error'), h('dd', null, h('code', null, str(e.error)))] : null,
      ]),
      e.before ? [h('p', { class: 'small muted' }, 'Before'), h('pre', { class: 'json-block' }, JSON.stringify(e.before, null, 2))] : null,
      e.after ? [h('p', { class: 'small muted' }, 'After'), h('pre', { class: 'json-block' }, JSON.stringify(e.after, null, 2))] : null,
    ),
  );
  // Offered only when the server says the reverter catalogue can keep the
  // promise (A §9, §14.9) — never from "undo_kind is set".
  const revert =
    e.revertible === true
      ? writeBtn('audit.revert', 'Revert', () => revertEntry(e, area), { ariaLabel: `Revert entry #${str(e.seq)}`, iconName: 'undo' })
      : null;
  return h(
    'tr',
    { dataset: { seq: e.seq, id: e.id } },
    h('td', { 'data-label': '#', class: 'num' }, str(e.seq)),
    h('td', { 'data-label': 'When' }, ago(e.at)),
    h('td', { 'data-label': 'Who' }, str(e.actor_label) || (e.actor_id ? `#${e.actor_id}` : 'System')),
    h('td', { 'data-label': 'What' }, h('code', { class: 'small' }, str(e.action)), h('br'), str(e.detail)),
    h('td', { 'data-label': 'Target' }, target),
    h('td', { 'data-label': 'Outcome' }, badge(str(e.outcome) || 'success', OUTCOME_KIND[e.outcome] || 'neutral'), ' ', badge(str(e.severity) || 'info', SEVERITY_KIND[e.severity] || 'neutral'), e.reverted_by ? [' ', badge(`Reverted by #${str(e.reverted_by)}`, 'rest')] : null),
    h('td', { 'data-label': '' }, h('div', { class: 'row-actions' }, revert, details)),
  );
}

async function revertEntry(e, area) {
  const ok = await confirmed({
    title: `Revert entry #${str(e.seq)}?`,
    body: h('div', { class: 'stack-sm' }, h('p', null, str(e.detail) || str(e.action)), h('p', { class: 'muted' }, 'This writes a new audit entry that puts things back; the original stays in the log. The same permission and safety checks run again, so it can still be refused.')),
    confirmLabel: 'Revert',
    danger: true,
  });
  if (!ok) return;
  try {
    await api('POST', `/api/admin/audit/${encodeURIComponent(e.id)}/revert`, {});
    toast(`Entry #${str(e.seq)} reverted.`, 'ok');
    AUDIT.entries = [];
    await reload('audit');
  } catch (err) {
    showFailure(area, err, 'Not reverted');
  }
}

async function fetchAudit({ append = false } = {}) {
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(AUDIT.filters)) if (v !== '' && v !== undefined && v !== null) params.set(k, String(v));
  if (append && AUDIT.next !== null) params.set('before_seq', String(AUDIT.next));
  params.set('limit', '50');
  const r = await api('GET', `/api/admin/audit?${params}`);
  const entries = listOf(r, 'entries');
  AUDIT.entries = append ? [...AUDIT.entries, ...entries] : entries;
  AUDIT.next = r && (typeof r.next_before_seq === 'number' || typeof r.next_before_seq === 'string') ? r.next_before_seq : null;
}

function drawAudit(area) {
  const box = $('audit-list');
  if (!box) return;
  const more = AUDIT.next !== null ? h('button', { id: 'audit-more', type: 'button', class: 'btn btn-ghost btn-block' }, 'Load older entries') : null;
  if (more) {
    more.addEventListener('click', () =>
      busy(more, async () => {
        try {
          await fetchAudit({ append: true });
          drawAudit(area);
        } catch (err) {
          showFailure(area, err);
        }
      }),
    );
  }
  box.replaceChildren(
    AUDIT.entries.length
      ? h(
          'div',
          { class: 'table-wrap' },
          h(
            'table',
            { class: 'table table-cards' },
            h('caption', { class: 'sr-only' }, 'Audit log'),
            h('thead', null, h('tr', null, ['#', 'When', 'Who', 'What', 'Target', 'Outcome', ''].map((t) => h('th', { scope: 'col', class: t === '#' ? 'num' : null }, t)))),
            h('tbody', null, AUDIT.entries.map((e) => auditRow(e, area))),
          ),
        )
      : emptyState({ icon: 'search', title: 'No entries match' }),
    ...(more ? [more] : []),
  );
}

async function loadAudit(body) {
  const area = resultArea('audit-result');
  const verifyOut = h('div', { id: 'verify-result', 'aria-live': 'polite' });
  const action = h('input', { id: 'audit-action', type: 'text', value: str(AUDIT.filters.action), placeholder: 'e.g. user. or network.allow', autocomplete: 'off' });
  const outcome = select([{ value: '', label: 'Any' }, { value: 'success', label: 'Success' }, { value: 'failure', label: 'Failure' }, { value: 'denied', label: 'Denied' }], AUDIT.filters.outcome || '', { id: 'audit-outcome' });
  const severity = select([{ value: '', label: 'Any' }, { value: 'info', label: 'Info' }, { value: 'notice', label: 'Notice' }, { value: 'warning', label: 'Warning' }, { value: 'critical', label: 'Critical' }], AUDIT.filters.severity || '', { id: 'audit-severity' });
  const actor = h('input', { id: 'audit-actor', type: 'text', inputmode: 'numeric', value: str(AUDIT.filters.actor), autocomplete: 'off' });
  const q = h('input', { id: 'audit-q', type: 'search', value: str(AUDIT.filters.q), autocomplete: 'off' });
  const filters = h('form', { id: 'audit-filters', class: 'toolbar', role: 'search', novalidate: true }, field('Action starts with', action), field('Outcome', outcome), field('Severity', severity), field('Actor (person number)', actor), field('Detail contains', q), h('button', { type: 'submit', class: 'btn btn-secondary' }, 'Filter'));
  filters.addEventListener('submit', (e) => {
    e.preventDefault();
    setFieldError(actor, '');
    if (actor.value.trim() && !/^\d+$/.test(actor.value.trim())) return setFieldError(actor, 'A person number, like 12.');
    AUDIT.filters = { action: action.value.trim(), outcome: outcome.value, severity: severity.value, actor: actor.value.trim(), q: q.value.trim() };
    busy(filters.querySelector('button[type=submit]'), async () => {
      try {
        await fetchAudit();
        drawAudit(area);
      } catch (err) {
        showFailure(area, err);
      }
    });
  });
  let verify = null;
  if (can('audit.verify')) {
    verify = h('button', { id: 'audit-verify', type: 'button', class: 'btn btn-secondary', dataset: { action: 'audit.verify' } }, icon('shield', { size: 18 }), 'Verify integrity');
    verify.addEventListener('click', () =>
      busy(verify, async () => {
        verifyOut.replaceChildren();
        try {
          const v = verifyText(await api('POST', '/api/admin/audit/verify', {}));
          verifyOut.replaceChildren(banner(v.ok ? 'ok' : 'danger', v.ok ? 'The audit log is intact' : 'The audit log has been tampered with', v.text));
        } catch (err) {
          showFailure(verifyOut, err, 'The check couldn’t run');
        }
      }),
    );
  }
  body.replaceChildren(
    h('div', { class: 'split' }, h('p', { class: 'muted' }, 'Each entry’s hash covers the one before it, so editing or deleting anything breaks every hash after it.'), verify),
    verifyOut,
    area,
    filters,
    h('div', { id: 'audit-list', class: 'card card-flush' }),
  );
  await fetchAudit();
  drawAudit(area);
}

// ----------------------------------------------------------------- tabs ----

const LOADERS = {
  overview: loadOverview,
  people: loadPeople,
  invitations: loadInvitations,
  roles: loadRoles,
  devices: loadDevices,
  network: loadNetwork,
  security: loadSecurity,
  settings: loadSettings,
  visitors: loadVisitors,
  sessions: loadSessions,
  streaks: loadStreaks,
  audit: loadAudit,
};

export function allowedTabs(perms) {
  const set = permSet(perms);
  return TABS.filter((t) => t.any.some((p) => hasPerm(set, p))).map((t) => t.id);
}

function loadTab(id) {
  if (!LOADERS[id] || S.loaded.has(id)) return null;
  S.loaded.add(id);
  const body = bodyOf(id);
  if (!body) return null;
  return guarded(body, () => LOADERS[id](body));
}

async function main() {
  let me;
  try {
    me = await api('GET', '/api/me');
  } catch (err) {
    if (!(err instanceof ApiError && err.redirected)) {
      $('load-error').textContent = errorMessage(err);
      $('load-error').hidden = false;
    }
    return;
  }
  S.me = me && typeof me === 'object' ? me : {};
  if (typeof S.me.pinned === 'string' && S.me.pinned) {
    go(`/account?pin=${encodeURIComponent(S.me.pinned)}`, { replace: true });
    return;
  }
  S.perms = permSet(S.me.permissions);
  const user = S.me.user && typeof S.me.user === 'object' ? S.me.user : {};
  S.meId = user.id ?? null;
  S.myRank = typeof S.me.rank === 'number' ? S.me.rank : user.role && typeof user.role.rank === 'number' ? user.role.rank : 0;
  S.isSuper = (user.role && user.role.key === 'super_admin') || ['users.reset_password', 'roles.manage', 'gate.open', 'audit.revert'].every(can);
  const org = typeof S.me.org_name === 'string' && S.me.org_name ? S.me.org_name : '';
  document.title = org ? `Admin console · ${org}` : 'Admin console';
  mountTopBar('topbar-slot', { me: S.me, active: 'admin' });

  const allowed = allowedTabs(S.perms);
  if (!canSeeAdmin(S.perms) || !allowed.length) {
    $('admin-sub').textContent = 'You don’t have access to the admin console.';
    $('load-error').textContent = 'Your account has no admin permissions, so there’s nothing for you here. Taking you to your dashboard…';
    $('load-error').hidden = false;
    go('/', { replace: true });
    return;
  }
  for (const t of TABS) {
    if (allowed.includes(t.id)) {
      document.getElementById(`tab-${t.id}`).hidden = false;
    } else {
      document.getElementById(`tab-${t.id}`).remove();
      document.getElementById(`panel-${t.id}`).remove();
    }
  }
  const readOnly = !WRITE_PERMS.some(can);
  $('admin-sub').textContent = `${personName(user)}${user.role ? ` — ${user.role.name}` : ''}.${readOnly ? ' Read-only: you can look, not change.' : ''}`;
  $('admin-tabs').hidden = false;
  S.tabsCtl = tabs($('admin-tabs'), { hash: true, onChange: (tabId) => loadTab(tabId.replace(/^tab-/, '')) });
  const selected = $('admin-tabs').querySelector('[role=tab][aria-selected="true"]');
  if (selected) await loadTab(selected.id.replace(/^tab-/, ''));
}

main();
