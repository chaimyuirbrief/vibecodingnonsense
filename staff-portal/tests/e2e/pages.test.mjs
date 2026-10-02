// Pages decided on the server (CONTRACTS §8.3; B §10): no flash of the wrong
// page, no page reachable by its file name, nothing before the gate.

import { test, assert, run } from '../helpers/t.js';
import { freshEnv, client, bootstrap, makeUser, pageText, signOut, OWNER_IP } from '../helpers/flows.js';

async function world() {
  const env = freshEnv();
  const owner = await bootstrap(env);
  return { env, owner };
}

async function served(r, name) {
  assert.equal(r.status, 200, `${name}: ${r.status}`);
  assert.equal(r.headers.get('content-type'), 'text/html; charset=utf-8');
  assert.equal(r.text, await pageText(name), `expected ${name}`);
}

function redirected(r, to) {
  assert.equal(r.status, 302);
  assert.equal(r.headers.get('location'), to);
  assert.equal(r.text, '');
}

test('/ is the dashboard when signed in and the sign-in page when not', async () => {
  const { env, owner } = await world();
  await served(await owner.client.get('/'), 'dashboard.html');
  await signOut(owner.client);
  await served(await owner.client.get('/'), 'login.html');
  await served(await client(env, { ip: OWNER_IP }).get('/'), 'login.html');
});

test('/login sends a signed-in visitor on; /account and /admin send a signed-out one to sign in', async () => {
  const { env, owner } = await world();
  redirected(await owner.client.get('/login'), '/');
  await served(await owner.client.get('/account'), 'account.html');
  await served(await owner.client.get('/admin'), 'admin.html');
  const anon = client(env, { ip: OWNER_IP });
  await served(await anon.get('/login'), 'login.html');
  redirected(await anon.get('/admin'), '/login?next=/admin');
  redirected(await anon.get('/account'), '/login?next=/account');
  redirected(await anon.get('/account?pin=mfa_enroll'), '/login?next=/account%3Fpin%3Dmfa_enroll');
});

test('/admin needs an admin-console permission; an employee goes home, a manager gets the console', async () => {
  const { env, owner } = await world();
  const emp = await makeUser(env, owner.client, { role: 'employee' });
  const mgr = await makeUser(env, owner.client, { role: 'manager' });
  redirected(await emp.client.get('/admin'), '/');
  await served(await mgr.client.get('/admin'), 'admin.html');
  await served(await emp.client.get('/'), 'dashboard.html');
});

test('page files are not pages, and unknown paths are an empty 404', async () => {
  const { owner } = await world();
  for (const p of ['/dashboard.html', '/login.html', '/admin.html', '/account.html', '/setup.html', '/index.html', '/DASHBOARD.HTML', '/dashboard', '/js/', '/css/', '/worker.js', '/js/../worker.js', '/js/x/../../package.json']) {
    const r = await owner.client.get(p);
    assert.equal(r.status, 404, p);
    assert.equal(r.text, '', p);
  }
});

test('setup, request and pending pages exist only in their shells', async () => {
  const { owner } = await world();
  assert.equal((await owner.client.get('/setup')).status, 404);
  redirected(await owner.client.get('/request-access'), '/');
  redirected(await owner.client.get('/pending'), '/');
  await served(await owner.client.get('/invite'), 'invite.html');
});

test('assets only after the gate', async () => {
  const { env, owner } = await world();
  const css = await owner.client.get('/css/app.css');
  assert.equal(css.status, 200);
  assert.equal(css.headers.get('content-type'), 'text/css; charset=utf-8');
  const js = await owner.client.get('/js/dashboard.js');
  assert.equal(js.headers.get('content-type'), 'text/javascript; charset=utf-8');
  assert.equal((await owner.client.get('/favicon.svg')).headers.get('content-type'), 'image/svg+xml');
  assert.equal((await owner.client.get('/js/nope.js')).status, 404);
  const stranger = client(env);
  for (const p of ['/css/app.css', '/js/common.js', '/js/dashboard.js', '/favicon.svg']) {
    const r = await stranger.get(p);
    assert.equal(r.status, 403, p);
    assert.equal(r.text, '', p);
  }
});

test('writes to pages and assets are not a thing', async () => {
  const { owner } = await world();
  for (const p of ['/', '/login', '/css/app.css']) {
    const r = await owner.client.post(p, {});
    assert.equal(r.status, 404, p);
  }
});

await run();
