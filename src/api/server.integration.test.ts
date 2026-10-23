import { describe, it, expect, afterEach } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { gunzipSync } from 'node:zlib';
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
