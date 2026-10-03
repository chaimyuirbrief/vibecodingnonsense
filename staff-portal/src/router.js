// A tiny router. API modules export `register(router)` and add routes:
//
//   router.add('POST', '/api/admin/users/:id/status', handler, {
//     auth: 'session',          // 'none' | 'session' | 'pinned-ok'
//     perm: 'users.suspend',    // string or array (ALL required); optional
//   });
//
// handler: async (rc, params) => Response
//
// The worker enforces `auth` and `perm` before calling the handler, and
// demands a fresh step-up for any non-GET route whose perm is marked danger
// in the catalogue (rbac.routeNeedsStepUp). Handlers re-check anything
// target-specific (rank, last superuser, self-lockout) themselves — usually by
// calling a domain function that does it, so a revert re-runs the same guard.

const PARAM_RE = /:([a-zA-Z_][a-zA-Z0-9_]*)/g;

function compile(pattern) {
  const names = [];
  const src = pattern
    .replace(/[.*+?^${}()|[\]\\]/g, (c) => (c === ':' ? c : '\\' + c))
    .replace(PARAM_RE, (_, name) => {
      names.push(name);
      return '([^/]+)';
    });
  return { re: new RegExp('^' + src + '$'), names };
}

export class Router {
  constructor() {
    this.routes = [];
  }

  add(method, pattern, handler, opts = {}) {
    if (typeof handler !== 'function') throw new TypeError(`route ${method} ${pattern}: handler is not a function`);
    const auth = opts.auth ?? 'session';
    if (!['none', 'session', 'pinned-ok'].includes(auth)) throw new TypeError(`route ${method} ${pattern}: bad auth '${auth}'`);
    const { re, names } = compile(pattern);
    this.routes.push({ method: method.toUpperCase(), pattern, re, names, handler, opts: { ...opts, auth } });
    return this;
  }

  // { route, params } | { methodNotAllowed: true } | null
  match(method, pathname) {
    let pathMatched = false;
    for (const r of this.routes) {
      const m = r.re.exec(pathname);
      if (!m) continue;
      pathMatched = true;
      if (r.method !== method.toUpperCase()) continue;
      const params = {};
      r.names.forEach((n, i) => {
        try {
          params[n] = decodeURIComponent(m[i + 1]);
        } catch {
          params[n] = m[i + 1];
        }
      });
      return { route: r, params };
    }
    return pathMatched ? { methodNotAllowed: true } : null;
  }
}
