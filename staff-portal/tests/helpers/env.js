// A complete test `env`: real SQLite behind the D1 surface, an ASSETS binding
// that serves ./public, test secrets, and an injectable clock.
//
//   const env = makeEnv();                 // clock starts 2026-01-06T15:00Z (a Tuesday)
//   env.__setNow(Date.UTC(2026, 0, 10));   // jump
//   env.__advance(3 * HOUR);               // move forward
//
// Pass { schema: true } to run ensureSchema up front.

import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { FakeD1 } from './d1.js';
import { ensureSchema } from '../../src/schema.js';

const here = path.dirname(fileURLToPath(import.meta.url));
export const ROOT = path.resolve(here, '..', '..');
export const PUBLIC_DIR = path.join(ROOT, 'public');

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.json': 'application/json',
  '.txt': 'text/plain; charset=utf-8',
  '.webmanifest': 'application/manifest+json',
};

export function assetsStub(dir = PUBLIC_DIR) {
  return {
    async fetch(input) {
      const url = new URL(typeof input === 'string' ? input : input.url);
      const rel = path.normalize(decodeURIComponent(url.pathname)).replace(/^([/\\])+/, '');
      const file = path.join(dir, rel);
      if (!file.startsWith(dir + path.sep)) return new Response('Not found', { status: 404 });
      try {
        const body = await readFile(file);
        const type = TYPES[path.extname(file)] || 'application/octet-stream';
        return new Response(body, { status: 200, headers: { 'content-type': type } });
      } catch {
        return new Response('Not found', { status: 404 });
      }
    },
  };
}

export const TEST_START_MS = Date.UTC(2026, 0, 6, 15, 0, 0); // Tue 2026-01-06 10:00 America/New_York

export function makeEnv(overrides = {}) {
  let clock = overrides.startMs ?? TEST_START_MS;
  const env = {
    DB: new FakeD1(),
    ASSETS: assetsStub(),
    SESSION_SECRET: 'test-session-secret-0123456789abcdef0123456789abcdef',
    DATA_KEY: 'test-data-key-0123456789abcdef0123456789abcdef01234567',
    SETUP_KEY: 'test-setup-key-0123456789abcdef0123456789abcdef',
    ORG_NAME: 'Acme Inc.',
    ORG_CODE: 'ACME',
    RP_ID: 'staff.example.com',
    ORIGIN: 'https://staff.example.com',
    PBKDF2_ITERATIONS: '100000',
    __clock: () => clock,
    ...overrides.vars,
  };
  delete env.startMs;
  env.__setNow = (ms) => {
    clock = ms;
  };
  env.__advance = (ms) => {
    clock += ms;
  };
  return env;
}

export async function makeEnvWithSchema(overrides = {}) {
  const env = makeEnv(overrides);
  await ensureSchema(env);
  return env;
}
