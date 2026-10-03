// GET /api/admin/users/:id/streak — one person's day log, for the
// administrator who must answer "why did my streak reset?" before restoring
// it (SPEC §10.18). Scoped like the streaks list: streaks.view_all sees
// anyone, team.view only direct reports, everyone else nothing.

import { test, assert, run } from '../helpers/t.js';
import { freshEnv, bootstrap, makeUser, signIn, advanceDays, q } from '../helpers/flows.js';

async function world() {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const manager = await makeUser(env, owner.client, { role: 'manager', full_name: 'Max Manager' });
  const report = await makeUser(env, owner.client, { role: 'employee', full_name: 'Rita Report', totp: true });
  const other = await makeUser(env, owner.client, { role: 'employee', full_name: 'Otto Other' });
  const auditor = await makeUser(env, owner.client, { role: 'auditor', full_name: 'Aud Itor' });
  const r = await owner.client.patch(`/api/admin/users/${report.user.id}`, { manager_id: manager.user.id });
  assert.equal(r.status, 200, r.text);
  return { env, owner, manager, report, other, auditor };
}

test('the day log shows counted, protected and missed days, and when they joined', async () => {
  const w = await world();
  // Rita signs in on three more days; one day in between is skipped.
  for (const step of [1, 1, 2]) {
    advanceDays(w.env, step);
    await signIn(w.env, w.report.client, w.report.user.email, w.report.password);
  }
  // Days have passed: the auditor signs in again (sessions last 8 hours).
  await signIn(w.env, w.auditor.client, w.auditor.user.email, w.auditor.password);
  const r = await w.auditor.client.get(`/api/admin/users/${w.report.user.id}/streak?days=28`);
  assert.equal(r.status, 200, r.text);
  assert.deepEqual(Object.keys(r.body).sort(), ['enabled', 'history', 'rules', 'since', 'status', 'user']);
  assert.equal(r.body.history.length, 28);
  assert.match(r.body.since, /^\d{4}-\d{2}-\d{2}$/);
  const counted = r.body.history.filter((d) => d.counted).map((d) => d.day);
  const stored = q(w.env, 'SELECT day FROM streak_days WHERE user_id = ? ORDER BY day', w.report.user.id).map((x) => x.day);
  assert.deepEqual(counted, stored.filter((d) => d >= r.body.history[0].day), 'the log is the stored day rows');
  assert.ok(r.body.history.some((d) => d.protected), 'protected days are marked');
  assert.equal(r.body.user.full_name, 'Rita Report');
  assert.ok(!JSON.stringify(r.body).includes('password'), 'nothing but the streak');
});

test('scope: a manager sees their report only; an employee sees nobody; unknown ids are 404', async () => {
  const w = await world();
  assert.equal((await w.manager.client.get(`/api/admin/users/${w.report.user.id}/streak`)).status, 200);
  assert.equal((await w.manager.client.get(`/api/admin/users/${w.other.user.id}/streak`)).status, 404, 'not their report: as if absent');
  assert.equal((await w.other.client.get(`/api/admin/users/${w.report.user.id}/streak`)).status, 403);
  assert.equal((await w.auditor.client.get('/api/admin/users/99999/streak')).status, 404);
  for (const days of ['0', '-1', 'abc', '401', '']) {
    const r = await w.auditor.client.get(`/api/admin/users/${w.report.user.id}/streak?days=${days}`);
    assert.equal(r.status, 200, `days=${days}`);
    assert.equal(r.body.history.length, 84, `days=${days} falls back to 84`);
  }
});

test('a broken streaks table answers without a log instead of failing the page', async () => {
  const w = await world();
  w.env.DB.q('DROP TABLE streaks');
  const r = await w.auditor.client.get(`/api/admin/users/${w.report.user.id}/streak`);
  assert.equal(r.status, 200, r.text);
  assert.equal(r.body.status, null);
  assert.equal(r.body.history, null);
});

await run();
