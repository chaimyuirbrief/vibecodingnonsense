// The permission catalogue and the seeded roles. Data only — the logic that
// reads it lives in rbac.js.
//
// Rank is the whole authority model (SPEC §9): you act only on people of
// strictly lower rank, and you cannot assign a role at or above your own.
//
// `danger: true`  → the action demands a fresh step-up (MFA within
//                   step_up_minutes) or the API answers 403 {step_up_required}.
// `reserved: true` → can never be granted, by role or by flag. Only the
//                   implicit '*' of a Super Admin holds it. Each of these is a
//                   path by which an admin could mint a second, more powerful
//                   login, take the outer wall down, or rewrite history.

export const PERMISSIONS = Object.freeze([
  // People
  { key: 'directory.view', group: 'People', label: 'See the staff directory' },
  { key: 'team.view', group: 'People', label: "See your direct reports' status, sign-ins and streaks" },
  { key: 'users.view', group: 'People', label: 'See every account, including status and security posture' },
  { key: 'users.invite', group: 'People', label: 'Invite new people with a one-time link' },
  { key: 'users.edit', group: 'People', label: 'Edit profile fields (name, title, department, manager, employee no.)' },
  { key: 'users.suspend', group: 'People', label: 'Suspend and reinstate, force sign-out, revoke devices', danger: true },
  { key: 'users.disable', group: 'People', label: 'Disable leavers (soft delete) and re-enable them', danger: true },
  { key: 'users.roles', group: 'People', label: 'Change roles, temporary roles and per-user grants', danger: true },
  { key: 'users.reset_mfa', group: 'People', label: "Clear someone's second factors after a lost phone", danger: true },
  { key: 'users.reset_password', group: 'People', label: "Reset someone else's password", danger: true, reserved: true },
  { key: 'destinations.manage', group: 'People', label: 'Choose which numbers and addresses may receive sign-in codes', danger: true, reserved: true },
  { key: 'requests.manage', group: 'People', label: 'Approve or deny access requests' },

  // Roles
  { key: 'roles.view', group: 'Roles', label: 'See roles and what they grant' },
  { key: 'roles.manage', group: 'Roles', label: 'Create, edit and delete custom roles', danger: true, reserved: true },

  // Devices and network
  { key: 'devices.view', group: 'Devices', label: 'See the device inventory and approval queue' },
  { key: 'devices.approve', group: 'Devices', label: 'Approve pending devices', danger: true },
  { key: 'devices.manage', group: 'Devices', label: 'Rename, block and revoke devices', danger: true },
  { key: 'network.view', group: 'Network', label: 'See the IP allowlist and blocklist' },
  { key: 'network.manage', group: 'Network', label: 'Add, edit and remove allowlist and blocklist entries', danger: true },
  { key: 'visitors.view', group: 'Network', label: 'See visitor fingerprints, risk scores and the visit log' },

  // Sessions
  { key: 'sessions.view', group: 'Sessions', label: 'See active sessions' },
  { key: 'sessions.revoke', group: 'Sessions', label: "End other people's sessions", danger: true },

  // Settings and security posture
  { key: 'settings.view', group: 'Settings', label: 'See portal settings' },
  { key: 'settings.manage', group: 'Settings', label: 'Change general settings: timezone, device gating, session lengths, streak calendar', danger: true },
  { key: 'security.manage', group: 'Settings', label: 'Change the access mode, country/ASN/Tor/automation rules and the risk threshold', danger: true, reserved: true },
  { key: 'gate.open', group: 'Settings', label: 'Open the portal to the whole internet for a bounded time', danger: true, reserved: true },

  // Audit
  { key: 'audit.view', group: 'Audit', label: 'Read the audit log' },
  { key: 'audit.verify', group: 'Audit', label: 'Verify the audit hash chain' },
  { key: 'audit.revert', group: 'Audit', label: 'Revert audited changes', danger: true, reserved: true },

  // Streaks
  { key: 'streaks.view_all', group: 'Streaks', label: "See everyone's streaks" },
  { key: 'streaks.manage', group: 'Streaks', label: 'Restore or adjust a streak (for example after an outage)', danger: true },
]);

export const PERMISSION_KEYS = Object.freeze(PERMISSIONS.map((p) => p.key));
export const PERMISSION_BY_KEY = Object.freeze(Object.fromEntries(PERMISSIONS.map((p) => [p.key, p])));
export const RESERVED = Object.freeze(new Set(PERMISSIONS.filter((p) => p.reserved).map((p) => p.key)));
export const DANGER = Object.freeze(new Set(PERMISSIONS.filter((p) => p.danger).map((p) => p.key)));

export const SUPER_RANK = 100;

const grantable = PERMISSION_KEYS.filter((k) => !RESERVED.has(k));

export const SYSTEM_ROLES = Object.freeze([
  {
    key: 'super_admin',
    name: 'Super Admin',
    rank: SUPER_RANK,
    permissions: ['*'],
    description: 'The owner. Everything, including the reserved capabilities nobody else can be granted.',
  },
  {
    key: 'admin',
    name: 'Administrator',
    rank: 80,
    permissions: grantable,
    description: 'Day-to-day operations. Not role editing, security policy, audit revert, password resets or opening the gate.',
  },
  {
    key: 'auditor',
    name: 'Auditor',
    rank: 60,
    permissions: [
      'directory.view', 'team.view', 'users.view', 'roles.view', 'devices.view', 'network.view',
      'visitors.view', 'sessions.view', 'settings.view', 'audit.view', 'audit.verify', 'streaks.view_all',
    ],
    description: 'Read-only everywhere, including the audit log.',
  },
  {
    key: 'manager',
    name: 'Manager',
    rank: 50,
    permissions: ['directory.view', 'team.view', 'users.invite'],
    description: 'The directory, their own people, and invitations.',
  },
  {
    key: 'employee',
    name: 'Employee',
    rank: 20,
    permissions: [],
    description: 'Own profile, own second factors, own sessions, own streak.',
  },
  {
    key: 'guest',
    name: 'Guest',
    rank: 10,
    permissions: [],
    description: 'Signed in, little else.',
  },
]);
