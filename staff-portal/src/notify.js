// Outbound texts and email (CONTRACTS §7.6; SPEC §7.6). Twilio for SMS,
// Resend for email, each one `fetch` with a 5-second deadline.
//
// Nothing here throws: a provider that is down, slow or misconfigured is
// "could not send", never a 500. And nothing here logs a code, a message
// body or a full number/address — only the masked hint and a status (A §11
// "what must never be logged").

import { str, normEmail } from './util.js';

export const NOTIFY_TIMEOUT_MS = 5000;
export const E164_RE = /^\+[1-9]\d{7,14}$/;

const TWILIO_BASE = 'https://api.twilio.com/2010-04-01/Accounts/';
const RESEND_URL = 'https://api.resend.com/emails';
const SMS_BODY_MAX = 1600; // Twilio's own ceiling
const SUBJECT_MAX = 200;
const TEXT_MAX = 10000;

function secret(env, name) {
  const v = env && env[name];
  return typeof v === 'string' && v.trim() !== '' ? v.trim() : null;
}

export function smsConfigured(env) {
  return !!(secret(env, 'TWILIO_ACCOUNT_SID') && secret(env, 'TWILIO_AUTH_TOKEN') && secret(env, 'TWILIO_FROM'));
}

export function emailConfigured(env) {
  return !!(secret(env, 'RESEND_API_KEY') && normEmail(fromAddress(env)));
}

// The destination kinds that can receive a code right now. The one place
// "usable" is decided, shared by otp.js and factors.js (A §14.8).
export function usableKinds(env) {
  const out = [];
  if (emailConfigured(env)) out.push('email');
  if (smsConfigured(env)) out.push('sms');
  return out;
}

// MAIL_FROM may be `Name <addr@host>`; Resend accepts either form.
function fromAddress(env) {
  const raw = secret(env, 'MAIL_FROM');
  if (!raw) return null;
  const m = /<([^<>]+)>\s*$/.exec(raw);
  return m ? m[1] : raw;
}

export function maskPhone(s) {
  const digits = typeof s === 'string' ? s.replace(/\D/g, '') : '';
  return digits.length >= 4 ? `•••• ${digits.slice(-4)}` : '••••';
}

export function maskEmail(s) {
  const e = normEmail(s);
  if (!e) return '•••';
  const at = e.lastIndexOf('@');
  return `${e[0]}•••${e.slice(at)}`;
}

// fetch with a hard deadline. The race, not only the abort signal, decides:
// a fetch implementation that ignores the signal still cannot hold the
// request open past the deadline.
async function post(env, url, init) {
  const doFetch = typeof env?.__fetch === 'function' ? env.__fetch : fetch;
  const ctl = new AbortController();
  let timer;
  const deadline = new Promise((resolve) => {
    timer = setTimeout(() => {
      ctl.abort();
      resolve({ timedOut: true });
    }, NOTIFY_TIMEOUT_MS);
  });
  try {
    const res = await Promise.race([doFetch(url, { ...init, signal: ctl.signal }), deadline]);
    if (res && res.timedOut === true) return { ok: false, error: 'timeout' };
    const status = typeof res?.status === 'number' ? res.status : 0;
    // Never read the body: providers echo the recipient (and our message) back.
    try {
      await res?.body?.cancel?.();
    } catch {
      /* already consumed */
    }
    return status >= 200 && status < 300 ? { ok: true } : { ok: false, error: `http_${status}` };
  } catch (e) {
    return { ok: false, error: e?.name === 'AbortError' ? 'timeout' : 'network' };
  } finally {
    clearTimeout(timer);
  }
}

function logFailure(kind, hint, error) {
  try {
    console.error(`notify: ${kind} to ${hint} not sent (${error})`);
  } catch {
    /* logging must not throw either */
  }
}

export async function sendSms(env, to, body) {
  const provider = 'twilio';
  try {
    if (!smsConfigured(env)) return { sent: false, provider, error: 'not_configured' };
    if (typeof to !== 'string' || !E164_RE.test(to)) return { sent: false, provider, error: 'bad_address' };
    const text = str(body, SMS_BODY_MAX);
    if (!text) return { sent: false, provider, error: 'empty_body' };
    const sid = secret(env, 'TWILIO_ACCOUNT_SID');
    const auth = btoa(`${sid}:${secret(env, 'TWILIO_AUTH_TOKEN')}`);
    const r = await post(env, `${TWILIO_BASE}${encodeURIComponent(sid)}/Messages.json`, {
      method: 'POST',
      headers: { authorization: `Basic ${auth}`, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ To: to, From: secret(env, 'TWILIO_FROM'), Body: text }).toString(),
    });
    if (r.ok) return { sent: true, provider };
    logFailure('SMS', maskPhone(to), r.error);
    return { sent: false, provider, error: r.error };
  } catch {
    // e.g. btoa on a non-Latin-1 token: a configuration fault, not the caller's.
    logFailure('SMS', maskPhone(to), 'exception');
    return { sent: false, provider, error: 'exception' };
  }
}

export async function sendEmail(env, to, subject, text) {
  const provider = 'resend';
  try {
    if (!emailConfigured(env)) return { sent: false, provider, error: 'not_configured' };
    const addr = normEmail(to);
    if (!addr) return { sent: false, provider, error: 'bad_address' };
    const subj = str(subject, SUBJECT_MAX);
    const body = str(text, TEXT_MAX);
    if (!subj || !body) return { sent: false, provider, error: 'empty_body' };
    const r = await post(env, RESEND_URL, {
      method: 'POST',
      headers: { authorization: `Bearer ${secret(env, 'RESEND_API_KEY')}`, 'content-type': 'application/json' },
      body: JSON.stringify({ from: secret(env, 'MAIL_FROM'), to: [addr], subject: subj, text: body }),
    });
    if (r.ok) return { sent: true, provider };
    logFailure('email', maskEmail(addr), r.error);
    return { sent: false, provider, error: r.error };
  } catch {
    logFailure('email', maskEmail(to), 'exception');
    return { sent: false, provider, error: 'exception' };
  }
}
