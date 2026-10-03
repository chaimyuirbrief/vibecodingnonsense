import { test, assert, run } from '../helpers/t.js';
import { makeEnv } from '../helpers/env.js';
import {
  smsConfigured, emailConfigured, usableKinds, sendSms, sendEmail, maskPhone, maskEmail, NOTIFY_TIMEOUT_MS,
} from '../../src/notify.js';

const HOSTILE = [null, undefined, NaN, Infinity, '', '   ', 'abc', {}, [], true, 0, Symbol('x')];
const show = (v) => (typeof v === 'symbol' ? 'Symbol' : JSON.stringify(v) ?? String(v));

const TWILIO = { TWILIO_ACCOUNT_SID: 'test-twilio-account-sid', TWILIO_AUTH_TOKEN: 'twilio-token-secret', TWILIO_FROM: '+15005550006' };
const RESEND = { RESEND_API_KEY: 're_test_key_secret', MAIL_FROM: 'Acme Portal <portal@acme.com>' };
const PHONE = '+447700900123';
const EMAIL = 'jane.doe@acme.com';

function fakeFetch(reply = () => new Response('{"sid":"SM1","to":"+447700900123"}', { status: 201 })) {
  const calls = [];
  const f = async (url, init) => {
    calls.push({ url: String(url), init });
    return reply(url, init);
  };
  f.calls = calls;
  return f;
}

function envWith(vars = {}, reply) {
  const env = makeEnv({ vars });
  env.__fetch = fakeFetch(reply);
  return env;
}

// Captures console output so a test can assert what was NOT logged.
async function captureLogs(fn) {
  const lines = [];
  const saved = { error: console.error, log: console.log, warn: console.warn, info: console.info };
  for (const k of Object.keys(saved)) console[k] = (...a) => lines.push(a.map(String).join(' '));
  try {
    await fn();
  } finally {
    Object.assign(console, saved);
  }
  return lines.join('\n');
}

test('configured only when every required setting is a non-blank string', () => {
  assert.equal(smsConfigured(makeEnv()), false);
  assert.equal(emailConfigured(makeEnv()), false);
  assert.equal(smsConfigured(makeEnv({ vars: TWILIO })), true);
  assert.equal(emailConfigured(makeEnv({ vars: RESEND })), true);
  assert.equal(emailConfigured(makeEnv({ vars: { ...RESEND, MAIL_FROM: 'portal@acme.com' } })), true);
  for (const k of Object.keys(TWILIO)) {
    for (const v of ['', '   ', undefined, 42, true]) assert.equal(smsConfigured(makeEnv({ vars: { ...TWILIO, [k]: v } })), false, `${k}=${show(v)}`);
  }
  for (const k of Object.keys(RESEND)) {
    for (const v of ['', '   ', undefined, 42]) assert.equal(emailConfigured(makeEnv({ vars: { ...RESEND, [k]: v } })), false, `${k}=${show(v)}`);
  }
  assert.equal(emailConfigured(makeEnv({ vars: { ...RESEND, MAIL_FROM: 'not an address' } })), false);
  for (const v of [null, undefined, {}, 'x']) {
    assert.equal(smsConfigured(v), false);
    assert.equal(emailConfigured(v), false);
  }
});

test('usableKinds follows configuration', () => {
  assert.deepEqual(usableKinds(makeEnv()), []);
  assert.deepEqual(usableKinds(makeEnv({ vars: TWILIO })), ['sms']);
  assert.deepEqual(usableKinds(makeEnv({ vars: RESEND })), ['email']);
  assert.deepEqual(usableKinds(makeEnv({ vars: { ...TWILIO, ...RESEND } })), ['email', 'sms']);
});

test('sendSms: one Twilio POST with basic auth and a form-encoded To/From/Body', async () => {
  const env = envWith(TWILIO);
  const r = await sendSms(env, PHONE, 'Your code: 123456');
  assert.deepEqual(r, { sent: true, provider: 'twilio' });
  assert.equal(env.__fetch.calls.length, 1);
  const { url, init } = env.__fetch.calls[0];
  assert.equal(url, `https://api.twilio.com/2010-04-01/Accounts/${TWILIO.TWILIO_ACCOUNT_SID}/Messages.json`);
  assert.equal(init.method, 'POST');
  assert.equal(init.headers.authorization, 'Basic ' + Buffer.from(`${TWILIO.TWILIO_ACCOUNT_SID}:${TWILIO.TWILIO_AUTH_TOKEN}`).toString('base64'));
  assert.equal(init.headers['content-type'], 'application/x-www-form-urlencoded');
  const body = new URLSearchParams(init.body);
  assert.deepEqual([...body.keys()].sort(), ['Body', 'From', 'To']);
  assert.equal(body.get('To'), PHONE);
  assert.equal(body.get('From'), TWILIO.TWILIO_FROM);
  assert.equal(body.get('Body'), 'Your code: 123456');
  assert.ok(init.signal instanceof AbortSignal, 'a deadline is attached');
});

test('sendEmail: one Resend POST with a bearer key and {from, to: [to], subject, text}', async () => {
  const env = envWith(RESEND, () => new Response('{"id":"x"}', { status: 200 }));
  const r = await sendEmail(env, 'Jane.Doe@ACME.com', 'Acme sign-in code', 'Your code is 123456.');
  assert.deepEqual(r, { sent: true, provider: 'resend' });
  assert.equal(env.__fetch.calls.length, 1);
  const { url, init } = env.__fetch.calls[0];
  assert.equal(url, 'https://api.resend.com/emails');
  assert.equal(init.method, 'POST');
  assert.equal(init.headers.authorization, `Bearer ${RESEND.RESEND_API_KEY}`);
  assert.equal(init.headers['content-type'], 'application/json');
  assert.deepEqual(JSON.parse(init.body), { from: RESEND.MAIL_FROM, to: [EMAIL], subject: 'Acme sign-in code', text: 'Your code is 123456.' });
});

test('not configured → not sent and NO outbound call at all', async () => {
  const env = envWith({});
  assert.deepEqual(await sendSms(env, PHONE, 'x'), { sent: false, provider: 'twilio', error: 'not_configured' });
  assert.deepEqual(await sendEmail(env, EMAIL, 's', 't'), { sent: false, provider: 'resend', error: 'not_configured' });
  assert.equal(env.__fetch.calls.length, 0);
});

test('hostile recipients and bodies: never throws, never calls out', async () => {
  const env = envWith({ ...TWILIO, ...RESEND });
  for (const v of [...HOSTILE, '447700900123', '+0447700900', '+44 7700 900123', `${PHONE}\n`, '+1234567', '+1234567890123456']) {
    const r = await sendSms(env, v, 'body');
    assert.equal(r.sent, false, `to ${show(v)}`);
  }
  for (const v of [...HOSTILE, 'not-an-email', 'a@b', '<a@b.com>']) {
    const r = await sendEmail(env, v, 's', 't');
    assert.equal(r.sent, false, `to ${show(v)}`);
  }
  for (const v of HOSTILE.filter((x) => typeof x !== 'string' || !x.trim())) {
    assert.equal((await sendSms(env, PHONE, v)).sent, false, `body ${show(v)}`);
    assert.equal((await sendEmail(env, EMAIL, v, 't')).sent, false, `subject ${show(v)}`);
    assert.equal((await sendEmail(env, EMAIL, 's', v)).sent, false, `text ${show(v)}`);
  }
  assert.equal(env.__fetch.calls.length, 0);
});

test('provider failures become { sent: false } with a status — never a throw, never the response body', async () => {
  const cases = [
    [() => new Response('{"message":"The To number +447700900123 is invalid; code 123456"}', { status: 400 }), 'http_400'],
    [() => new Response('down', { status: 503 }), 'http_503'],
    [() => { throw new TypeError('fetch failed'); }, 'network'],
    [() => Promise.reject(new Error('ECONNRESET')), 'network'],
    [() => null, 'http_0'],
    [() => ({ status: 'weird' }), 'http_0'],
  ];
  for (const [reply, error] of cases) {
    const env = envWith({ ...TWILIO, ...RESEND }, reply);
    const a = await sendSms(env, PHONE, 'Your code: 123456');
    assert.deepEqual(a, { sent: false, provider: 'twilio', error });
    const b = await sendEmail(env, EMAIL, 's', 'Your code: 123456');
    assert.deepEqual(b, { sent: false, provider: 'resend', error });
  }
});

test('a broken credential (btoa refuses non-Latin-1) is "not sent", not an exception', async () => {
  const env = envWith({ ...TWILIO, TWILIO_AUTH_TOKEN: 'tökén-✓' });
  const r = await sendSms(env, PHONE, 'x');
  assert.equal(r.sent, false);
  assert.equal(r.error, 'exception');
  assert.equal(env.__fetch.calls.length, 0);
});

test('failure logs carry the masked hint and the status — never the code, the body, the number or the address', async () => {
  const env = envWith({ ...TWILIO, ...RESEND }, () => new Response('nope', { status: 500 }));
  const out = await captureLogs(async () => {
    await sendSms(env, PHONE, 'Acme sign-in code: 482915. Never share it.');
    await sendEmail(env, EMAIL, 'Acme sign-in code', 'Your sign-in code is 482915.');
  });
  assert.ok(out.includes('•••• 0123'), out);
  assert.ok(out.includes('j•••@acme.com'), out);
  assert.ok(out.includes('http_500'));
  for (const secret of ['482915', PHONE, '7700900123', EMAIL, 'jane.doe', TWILIO.TWILIO_AUTH_TOKEN, RESEND.RESEND_API_KEY]) {
    assert.ok(!out.includes(secret), `logged ${secret}`);
  }
});

test('a provider that never answers is abandoned after 5 s, the request aborted', async () => {
  assert.equal(NOTIFY_TIMEOUT_MS, 5000);
  let signal = null;
  const env = envWith(TWILIO, (url, init) => {
    signal = init.signal;
    return new Promise(() => {}); // ignores the signal entirely
  });
  const started = Date.now();
  const r = await sendSms(env, PHONE, 'x');
  const took = Date.now() - started;
  assert.deepEqual(r, { sent: false, provider: 'twilio', error: 'timeout' });
  assert.ok(took >= 4900 && took < 7000, `took ${took} ms`);
  assert.equal(signal.aborted, true);
});

test('maskPhone / maskEmail: last four digits, first letter + domain; junk never throws', () => {
  assert.equal(maskPhone(PHONE), '•••• 0123');
  assert.equal(maskPhone('+15550101234'), '•••• 1234');
  assert.equal(maskEmail(EMAIL), 'j•••@acme.com');
  assert.equal(maskEmail('A@Example.COM'), 'a•••@example.com');
  for (const v of HOSTILE) {
    assert.equal(maskPhone(v), '••••', show(v));
    assert.equal(maskEmail(v), '•••', show(v));
  }
  assert.ok(!maskPhone(PHONE).includes('7700'));
  assert.ok(!maskEmail(EMAIL).includes('doe'));
});

await run();
