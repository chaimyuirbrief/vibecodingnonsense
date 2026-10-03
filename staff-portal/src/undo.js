// The undo catalogue (CONTRACTS §4.2.1). The kinds that may RECORD an undo
// and the kinds reverters.js can REVERT must be one set (A §9, §14.9):
// reverters.js throws at import if its REVERTERS keys differ from this list,
// and undoFor refuses anything else, so the panel can never offer a Revert
// button the code cannot honour.

export const UNDO_KINDS = Object.freeze([
  'user.status',
  'user.role',
  'user.temp_role',
  'user.profile',
  'device.status',
  'device.label',
  'network.allow.add',
  'network.allow.remove',
  'network.allow.edit',
  'network.block.add',
  'network.block.remove',
  'setting',
  'mfa.reset',
  'role.create',
  'role.edit',
  'role.delete',
  'streak',
  'destination.add',
  'destination.remove',
]);

const KIND_SET = new Set(UNDO_KINDS);

export function isUndoKind(kind) {
  return typeof kind === 'string' && KIND_SET.has(kind);
}

// Throws — recording an undo nobody can revert is a programming error, and it
// should surface in tests rather than as a dead button in production.
export function undoFor(kind, payload) {
  if (!isUndoKind(kind)) throw new Error(`undoFor: no reverter for kind '${String(kind)}'`);
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new Error(`undoFor: '${kind}' needs an object payload (the prior state)`);
  }
  // Opening the gate is deliberately not revertible (§4.2.1): a revert could
  // re-open a closed portal.
  if (kind === 'setting' && payload.key === 'gate_open') throw new Error("undoFor: 'gate_open' is never recorded as an undo");
  return { kind, payload };
}
