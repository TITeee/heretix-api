import { describe, it, expect, afterEach } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { createServer } from './server.js';

const API_KEY = 'test-api-key'; // matches vitest.integration.config.ts
const headers = { 'x-api-key': API_KEY, 'content-type': 'application/json' };

const LIMIT_ENV = ['RATE_LIMIT_MAX', 'RATE_LIMIT_BATCH_MAX', 'BATCH_SEARCH_MAX_CONCURRENT', 'BATCH_SEARCH_TIMEOUT_MS'];

function batchOf(n: number) {
  return { packages: Array.from({ length: n }, (_, i) => ({ package: `pkg-${i}`, version: '1.0.0' })) };
}

describe('request limits', () => {
  let app: FastifyInstance | undefined;

  afterEach(async () => {
    for (const name of LIMIT_ENV) delete process.env[name];
    await app?.close();
    app = undefined;
  });

  const search = () => app!.inject({ method: 'GET', url: '/api/v1/vulnerabilities/search?package=lodash', headers });
  const batch = (n: number) => app!.inject({ method: 'POST', url: '/api/v1/vulnerabilities/search/batch', headers, payload: batchOf(n) });

  it('refuses requests past RATE_LIMIT_MAX per minute with 429 and a Retry-After, and never limits /health', async () => {
    process.env.RATE_LIMIT_MAX = '3';
    app = await createServer();

    for (let i = 0; i < 3; i++) expect((await search()).statusCode).toBe(200);
    const refused = await search();
    expect(refused.statusCode).toBe(429);
    expect(refused.headers['retry-after']).toBeDefined();

    for (let i = 0; i < 10; i++) {
      expect((await app.inject({ method: 'GET', url: '/health' })).statusCode).toBe(200);
    }
  });

  it('does not limit when RATE_LIMIT_MAX is 0', async () => {
    process.env.RATE_LIMIT_MAX = '0';
    app = await createServer();
    for (let i = 0; i < 20; i++) expect((await search()).statusCode).toBe(200);
  });

  it('limits batch searches on their own, RATE_LIMIT_BATCH_MAX per minute', async () => {
    process.env.RATE_LIMIT_BATCH_MAX = '2';
    app = await createServer();

    expect((await batch(1)).statusCode).toBe(200);
    expect((await batch(1)).statusCode).toBe(200);
    expect((await batch(1)).statusCode).toBe(429);
    // the other endpoints are not held back by the batch limit
    expect((await search()).statusCode).toBe(200);
  });

  it('refuses a batch search while BATCH_SEARCH_MAX_CONCURRENT are running, and lets the next one in when they finish', async () => {
    process.env.BATCH_SEARCH_MAX_CONCURRENT = '1';
    app = await createServer();

    // Started together: the first is still working through its chunks when the second arrives.
    const [first, second] = await Promise.all([batch(400), batch(400)]);
    const statuses = [first.statusCode, second.statusCode].sort();
    expect(statuses).toEqual([200, 429]);
    const refused = first.statusCode === 429 ? first : second;
    expect(refused.headers['retry-after']).toBe('5');

    expect((await batch(1)).statusCode).toBe(200);
  });

  it('answers 503 to a batch that runs past BATCH_SEARCH_TIMEOUT_MS and frees its slot', async () => {
    process.env.BATCH_SEARCH_MAX_CONCURRENT = '1';
    process.env.BATCH_SEARCH_TIMEOUT_MS = '1';
    app = await createServer();

    // Names not searched before: a repeat is answered from the 30 s result cache without waiting on the database,
    // too fast for a timer to fire.
    const fresh = () => ({ packages: Array.from({ length: 400 }, (_, i) => ({ package: `timeout-${Date.now()}-${i}`, version: '1.0.0' })) });
    const send = () => app!.inject({ method: 'POST', url: '/api/v1/vulnerabilities/search/batch', headers, payload: fresh() });
    const timedOut = await send();
    expect(timedOut.statusCode).toBe(503);
    expect(timedOut.headers['retry-after']).toBeDefined();
    // A slot still held would answer the next batch with 429.
    expect((await send()).statusCode).toBe(503);
  });

  it('releases the slot when a batch is rejected as invalid', async () => {
    process.env.BATCH_SEARCH_MAX_CONCURRENT = '1';
    app = await createServer();

    const invalid = await app.inject({ method: 'POST', url: '/api/v1/vulnerabilities/search/batch', headers, payload: { packages: [] } });
    expect(invalid.statusCode).toBeGreaterThanOrEqual(400);
    expect((await batch(1)).statusCode).toBe(200);
  });
});
