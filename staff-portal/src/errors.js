// Errors that carry an HTTP answer. The worker turns any of these into
// `json(status, body)`; anything else becomes a 500 with a polite sentence
// and the REAL exception goes to the audit log (SPEC trap B2).

export class HttpError extends Error {
  constructor(status, body) {
    super(typeof body?.error === 'string' ? body.error : `HTTP ${status}`);
    this.name = 'HttpError';
    this.status = status;
    this.body = body;
  }
}

// A refusal by a guard: rank, minting authority, last superuser, self-lockout,
// self-action. `code` is stable and machine-readable; `message` is for people.
export class GuardError extends HttpError {
  constructor(code, message, status = 403, extra = {}) {
    super(status, { error: message, code, ...extra });
    this.name = 'GuardError';
    this.code = code;
  }
}

export class ValidationError extends HttpError {
  constructor(message, field) {
    super(400, field ? { error: message, field } : { error: message });
    this.name = 'ValidationError';
  }
}

export function stepUpRequired() {
  return new HttpError(403, { error: 'Confirm it’s you to continue.', step_up_required: true });
}

export function forbidden(message = 'You don’t have permission to do that.') {
  return new HttpError(403, { error: message, code: 'forbidden' });
}

export function notFound(message = 'Not found.') {
  return new HttpError(404, { error: message, code: 'not_found' });
}

export function tooMany(retryAfterSec) {
  return new HttpError(429, { error: 'Too many attempts. Try again later.', retry_after: retryAfterSec });
}
