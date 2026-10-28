import { describe, it, expect, afterEach } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { gunzipSync } from 'node:zlib';
import { createServer } from './server.js';
import { prisma } from '../db/client.js';

const API_KEY = 'test-api-key'; // matches vitest.integration.config.ts

describe('CORS', () => {
  let app: FastifyInstance | undefined;

  afterEach(async () => {
    delete process.env.ALLOWED_ORIGINS;
    await app?.close();
    app = undefined;
  });

  // CORS only governs whether a browser is allowed to read a cross-origin
  // response; it has no bearing on server-to-server callers (which never
  // enforce it), so these tests are only meaningful as "would a browser be
  // allowed to expose this response to page script."
  it('reflects no origin by default (ALLOWED_ORIGINS unset)', async () => {
    delete process.env.ALLOWED_ORIGINS;
    app = await createServer();

    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/vulnerabilities/search?package=lodash',
      headers: { 'x-api-key': API_KEY, origin: 'https://evil.example.com' },
    });

    expect(res.statusCode).toBe(200); // the request itself still succeeds server-side
    expect(res.headers['access-control-allow-origin']).toBeUndefined();
  });

  it('reflects an origin from ALLOWED_ORIGINS, and rejects one not listed', async () => {
    process.env.ALLOWED_ORIGINS = 'https://trusted.example.com, https://also-trusted.example.com';
    app = await createServer();

    const allowed = await app.inject({
      method: 'GET',
      url: '/api/v1/vulnerabilities/search?package=lodash',
      headers: { 'x-api-key': API_KEY, origin: 'https://trusted.example.com' },
    });
    expect(allowed.headers['access-control-allow-origin']).toBe('https://trusted.example.com');

    const notAllowed = await app.inject({
      method: 'GET',
      url: '/api/v1/vulnerabilities/search?package=lodash',
      headers: { 'x-api-key': API_KEY, origin: 'https://evil.example.com' },
    });
    expect(notAllowed.headers['access-control-allow-origin']).toBeUndefined();
  });

  it('does not affect same-origin requests (no Origin header, the common case)', async () => {
    delete process.env.ALLOWED_ORIGINS;
    app = await createServer();

    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/vulnerabilities/search?package=lodash',
      headers: { 'x-api-key': API_KEY },
    });
    expect(res.statusCode).toBe(200);
  });
});

describe('response compression', () => {
  let app: FastifyInstance | undefined;

  afterEach(async () => {
    await app?.close();
    app = undefined;
  });

  // A request that sends no Accept-Encoding gets the body as it always was, so a client that
  // cannot decompress is unaffected; one that asks for gzip (Go's net/http, Node's fetch do by
  // default) gets it compressed and reads it back the same.
  const search = (headers: Record<string, string>) => app!.inject({
    method: 'POST',
    url: '/api/v1/vulnerabilities/search/batch',
    headers: { 'x-api-key': API_KEY, ...headers },
    payload: { packages: Array.from({ length: 40 }, (_, i) => ({ package: `lodash-${i}`, version: '4.17.20', ecosystem: 'npm' })) },
  });

  it('gzips a response for a client that asks for it, and the body reads back the same', async () => {
    app = await createServer();

    const plain = await search({ 'accept-encoding': 'identity' });
    const zipped = await search({ 'accept-encoding': 'gzip' });

    expect(plain.statusCode).toBe(200);
    expect(plain.headers['content-encoding']).toBeUndefined();
    expect(zipped.statusCode).toBe(200);
    expect(zipped.headers['content-encoding']).toBe('gzip');
    expect(zipped.headers.vary).toMatch(/accept-encoding/i);
    expect(JSON.parse(gunzipSync(zipped.rawPayload).toString())).toEqual(JSON.parse(plain.payload));
  });

  it('sends a client that does not say what it accepts the body uncompressed', async () => {
    app = await createServer();
    const res = await search({});
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-encoding']).toBeUndefined();
  });

  it('leaves a small response alone', async () => {
    app = await createServer();
    const res = await app.inject({ method: 'GET', url: '/health', headers: { 'accept-encoding': 'gzip' } });
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-encoding']).toBeUndefined();
  });
});

describe('error responses', () => {
  let app: FastifyInstance | undefined;

  afterEach(async () => {
    await app?.close();
    app = undefined;
  });

  const get = (url: string) => app!.inject({ method: 'GET', url, headers: { 'x-api-key': API_KEY } });

  it('answers a request that fails the input check with 400 and what was wrong, nothing of the validator', async () => {
    app = await createServer();
    const res = await get('/api/v1/vulnerabilities/search');
    expect(res.statusCode).toBe(400);
    expect(res.json()).toEqual({ error: 'Invalid request', issues: [expect.objectContaining({ path: 'package' })] });
    expect(res.body).not.toMatch(/ZodError|stack|"code"/);
  });

  it('refuses a NUL, which Postgres would have refused with a 500 carrying its message', async () => {
    app = await createServer();
    expect((await get('/api/v1/vulnerabilities/search?package=a%00b')).statusCode).toBe(400);
    expect((await get('/api/v1/vulnerabilities/CVE-2026-1%00')).statusCode).toBe(400);
  });

  it('refuses text longer than any real name', async () => {
    app = await createServer();
    expect((await get(`/api/v1/vulnerabilities/search?package=${'a'.repeat(257)}`)).statusCode).toBe(400);
    expect((await get(`/api/v1/vulnerabilities/search?package=${'a'.repeat(256)}`)).statusCode).toBe(200);
    const batch = await app.inject({
      method: 'POST',
      url: '/api/v1/vulnerabilities/search/batch',
      headers: { 'x-api-key': API_KEY },
      payload: { packages: [{ package: 'lodash', version: '1.0.0', ecosystem: 'x'.repeat(129) }] },
    });
    expect(batch.statusCode).toBe(400);
  });

  it('keeps the status and message of an error Fastify raises for the client, such as malformed JSON', async () => {
    app = await createServer();
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/vulnerabilities/search/batch',
      headers: { 'x-api-key': API_KEY, 'content-type': 'application/json' },
      payload: '{"packages": [',
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().message).toBeTruthy();
  });

  it('answers an unexpected error with a bare 500 and keeps the detail out of the response', async () => {
    app = await createServer();
    app.get('/boom', async () => {
      throw new Error('relation "SecretTable" does not exist');
    });
    const res = await app.inject({ method: 'GET', url: '/boom' });
    expect(res.statusCode).toBe(500);
    expect(res.json()).toEqual({ error: 'Internal Server Error' });
  });
});

describe('security headers', () => {
  let app: FastifyInstance | undefined;

  afterEach(async () => {
    await app?.close();
    app = undefined;
  });

  it('sends nosniff, no framing, no referrer, and a CSP that allows nothing on an API response', async () => {
    app = await createServer();
    for (const res of [
      await app.inject({ method: 'GET', url: '/health' }),
      await app.inject({ method: 'GET', url: '/api/v1/vulnerabilities/search?package=lodash' }), // 401
    ]) {
      expect(res.headers['x-content-type-options']).toBe('nosniff');
      expect(res.headers['x-frame-options']).toBe('DENY');
      expect(res.headers['referrer-policy']).toBe('no-referrer');
      expect(res.headers['content-security-policy']).toBe("default-src 'none'; frame-ancestors 'none'");
    }
  });
});

describe('admin key', () => {
  let app: FastifyInstance | undefined;
  const ADMIN_API_KEY = 'test-admin-key'; // matches vitest.integration.config.ts

  afterEach(async () => {
    process.env.ADMIN_API_KEY = ADMIN_API_KEY;
    await prisma.jobConfig.deleteMany({ where: { source: { in: ['kev', 'no-such-job'] } } });
    await app?.close();
    app = undefined;
  });

  const patch = (source: string, key: string) => app!.inject({
    method: 'PATCH',
    url: `/api/v1/jobs/${source}`,
    headers: { 'x-api-key': key },
    payload: { enabled: false },
  });

  it('runs and switches jobs with the admin key only, not the shared key every client holds', async () => {
    app = await createServer();
    expect((await patch('kev', API_KEY)).statusCode).toBe(401);
    const run = await app.inject({ method: 'POST', url: '/api/v1/jobs/kev/run', headers: { 'x-api-key': API_KEY } });
    expect(run.statusCode).toBe(401);

    const res = await patch('kev', ADMIN_API_KEY);
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ source: 'kev', enabled: false });
  });

  it('does not open the search to the admin key', async () => {
    app = await createServer();
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/vulnerabilities/search?package=lodash',
      headers: { 'x-api-key': ADMIN_API_KEY },
    });
    expect(res.statusCode).toBe(401);
  });

  it('closes the admin routes when ADMIN_API_KEY is not set', async () => {
    delete process.env.ADMIN_API_KEY;
    app = await createServer();
    expect((await patch('kev', '')).statusCode).toBe(401);
    expect((await patch('kev', API_KEY)).statusCode).toBe(401);
    const status = await app.inject({ method: 'GET', url: '/api/v1/import-status', headers: { 'x-api-key': API_KEY } });
    expect(status.statusCode).toBe(401);
  });

  it('answers 404 for a job that does not exist, and stores nothing for it', async () => {
    app = await createServer();
    expect((await patch('no-such-job', ADMIN_API_KEY)).statusCode).toBe(404);
    expect(await prisma.jobConfig.findUnique({ where: { source: 'no-such-job' } })).toBeNull();
  });
});
