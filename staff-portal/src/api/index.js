// Every API module registers its routes here. A module that fails to import
// fails the bundle check and every e2e suite — loudly, which is the point.

import * as publicApi from './public.js';
import * as auth from './auth.js';
import * as me from './me.js';
import * as admin from './admin.js';
import * as adminSecurity from './admin-security.js';

export const MODULES = [publicApi, auth, me, admin, adminSecurity];

export function registerAll(router) {
  for (const m of MODULES) m.register(router);
  return router;
}
