import { describe, it, expect, afterEach } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { createServer } from './server.js';

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
      url: '/api/v1/import-status',
      headers: { 'x-api-key': API_KEY },
    });
    expect(res.statusCode).toBe(200);
  });
});
