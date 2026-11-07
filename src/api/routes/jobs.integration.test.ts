import { describe, it, expect, afterAll, beforeAll, beforeEach, vi } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { createServer } from '../server.js';
import { prisma } from '../../db/client.js';
import { resetDb } from '../../test-utils/db.js';
import * as runnerModule from '../../jobs/runner.js';
import * as ecosystems from '../../jobs/osv-ecosystems.js';
import { importNVDData } from '../../worker/nvd-fetcher.js';

const ADMIN = { 'x-api-key': 'test-admin-key' }; // matches vitest.integration.config.ts

describe('jobs', () => {
  let app: FastifyInstance;
  const request = vi.fn();

  beforeAll(async () => {
    app = await createServer();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(async () => {
    await resetDb();
    request.mockReset().mockResolvedValue('started');
    vi.spyOn(runnerModule, 'getJobRunner').mockReturnValue({ request } as never);
    vi.spyOn(ecosystems, 'fetchOsvEcosystems').mockResolvedValue(['Debian', 'GIT', 'PyPI', 'Red Hat', 'Ubuntu', 'npm']);
  });

  const run = (source: string) => app.inject({ method: 'POST', url: `/api/v1/jobs/${encodeURIComponent(source)}/run`, headers: ADMIN });
  const add = (name: unknown) => app.inject({ method: 'POST', url: '/api/v1/jobs/osv-ecosystems', headers: ADMIN, payload: { name } });

  describe('POST /jobs/:source/run', () => {
    it('loads a source that was never loaded in full', async () => {
      const res = await run('nvd');
      expect(res.statusCode).toBe(202);
      expect(res.json()).toMatchObject({ source: 'nvd', mode: 'full' });
      expect(request).toHaveBeenCalledWith(expect.objectContaining({ source: 'nvd' }), 'full');
    });

    it('runs the delta once the source is loaded', async () => {
      await importNVDData({ id: 'CVE-2026-0001', published: '2026-01-01T00:00:00.000', lastModified: '2026-01-02T00:00:00.000', descriptions: [{ lang: 'en', value: 'x' }], configurations: [] } as never);
      await prisma.collectionJob.create({ data: { source: 'nvd', status: 'completed', startedAt: new Date(), completedAt: new Date() } });

      expect((await run('nvd')).json()).toMatchObject({ mode: 'delta' });
    });

    it('loads CVE Records and Microsoft in full too, until they are loaded', async () => {
      expect((await run('cna')).json()).toMatchObject({ source: 'cna', mode: 'full' });
      expect((await run('advisory-microsoft')).json()).toMatchObject({ source: 'advisory-microsoft', mode: 'full' });
    });

    it('reads a loaded source in full again when asked to (a reload), without emptying it', async () => {
      await importNVDData({ id: 'CVE-2026-0001', published: '2026-01-01T00:00:00.000', lastModified: '2026-01-02T00:00:00.000', descriptions: [{ lang: 'en', value: 'x' }], configurations: [] } as never);
      await prisma.collectionJob.create({ data: { source: 'nvd', status: 'completed', startedAt: new Date(), completedAt: new Date() } });

      const res = await app.inject({ method: 'POST', url: '/api/v1/jobs/nvd/run?full=true', headers: ADMIN });
      expect(res.statusCode).toBe(202);
      expect(res.json()).toMatchObject({ source: 'nvd', mode: 'full' });
      expect(request).toHaveBeenCalledWith(expect.objectContaining({ source: 'nvd' }), 'full');
      expect(await prisma.nVDVulnerability.count()).toBe(1);
    });

    it('refuses a reload of a source that has no full load, and queues nothing', async () => {
      const res = await app.inject({ method: 'POST', url: '/api/v1/jobs/kev/run?full=true', headers: ADMIN });
      expect(res.statusCode).toBe(400);
      expect(request).not.toHaveBeenCalled();
    });

    it('refuses a value of full that is not true or false', async () => {
      const res = await app.inject({ method: 'POST', url: '/api/v1/jobs/nvd/run?full=yes', headers: ADMIN });
      expect(res.statusCode).toBe(400);
      expect(request).not.toHaveBeenCalled();
    });

    it('treats a source that has no first load as a delta', async () => {
      expect((await run('kev')).json()).toMatchObject({ mode: 'delta' });
    });

    it('accepts an OSV ecosystem that has no records here yet', async () => {
      expect((await run('osv-PyPI')).json()).toMatchObject({ source: 'osv-PyPI', mode: 'full' });
    });

    it('refuses to run the job of an ecosystem that is not for import', async () => {
      expect((await run('osv-Red Hat')).statusCode).toBe(404);
      expect(request).not.toHaveBeenCalled();
    });

    it('refuses a name OSV does not list', async () => {
      expect((await run('osv-NoSuchThing')).statusCode).toBe(404);
    });
  });

  describe('OSV ecosystems', () => {
    it('lists OSV\'s names, marking the ones that have a job', async () => {
      await prisma.collectionJob.create({ data: { source: 'osv-npm', status: 'completed', startedAt: new Date(), completedAt: new Date() } });
      await prisma.collectionJob.create({ data: { source: 'osv-full-Debian', status: 'completed', startedAt: new Date(), completedAt: new Date() } });

      const res = await app.inject({ method: 'GET', url: '/api/v1/jobs/osv-ecosystems', headers: ADMIN });

      expect(res.json().ecosystems).toEqual([
        { name: 'Debian', added: true, group: 'recommended' },
        { name: 'PyPI', added: false, group: 'recommended' },
        { name: 'Ubuntu', added: false, group: 'recommended' },
        { name: 'npm', added: true, group: 'recommended' },
      ]);
    });

    it('adds an ecosystem: the daily job on, and its full load queued', async () => {
      const res = await add('PyPI');

      expect(res.statusCode).toBe(202);
      expect(res.json()).toMatchObject({ source: 'osv-PyPI', mode: 'full' });
      expect((await prisma.jobConfig.findUniqueOrThrow({ where: { source: 'osv-PyPI' } })).enabled).toBe(true);
      expect(request).toHaveBeenCalledWith(expect.objectContaining({ source: 'osv-PyPI' }), 'full');
    });

    it('takes a release of a distro as its shared ecosystem', async () => {
      expect((await add('Ubuntu:22.04:LTS')).json()).toMatchObject({ source: 'osv-Ubuntu' });
    });

    it('answers a wrong name with the right one, and starts nothing', async () => {
      const res = await add('pypi');

      expect(res.statusCode).toBe(400);
      expect(res.json().error).toContain('Did you mean "PyPI"');
      expect(request).not.toHaveBeenCalled();
      expect(await prisma.jobConfig.count()).toBe(0);
    });

    it('does not list or add an ecosystem that is not for import, and says why', async () => {
      const list = await app.inject({ method: 'GET', url: '/api/v1/jobs/osv-ecosystems', headers: ADMIN });
      expect(list.json().ecosystems.map((e: { name: string }) => e.name)).not.toContain('Red Hat');

      const res = await add('Red Hat');
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toContain('OVAL');
      expect(request).not.toHaveBeenCalled();
      expect(await prisma.jobConfig.count()).toBe(0);
    });

    it('rejects a body without a name', async () => {
      expect((await add(undefined)).statusCode).toBe(400);
    });

    it('says when OSV\'s list cannot be fetched', async () => {
      vi.spyOn(ecosystems, 'fetchOsvEcosystems').mockResolvedValue(null);
      expect((await add('PyPI')).statusCode).toBe(503);
    });

    it('needs the admin key', async () => {
      expect((await app.inject({ method: 'POST', url: '/api/v1/jobs/osv-ecosystems', payload: { name: 'PyPI' } })).statusCode).toBe(401);
    });
  });
});
