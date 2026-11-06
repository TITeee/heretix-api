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
    vi.spyOn(ecosystems, 'fetchOsvEcosystems').mockResolvedValue(['Debian', 'PyPI', 'Ubuntu', 'npm']);
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

    it('treats a source that has no first load as a delta', async () => {
      expect((await run('kev')).json()).toMatchObject({ mode: 'delta' });
    });

    it('accepts an OSV ecosystem that has no records here yet', async () => {
      expect((await run('osv-PyPI')).json()).toMatchObject({ source: 'osv-PyPI', mode: 'full' });
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
        { name: 'Debian', added: true },
        { name: 'PyPI', added: false },
        { name: 'Ubuntu', added: false },
        { name: 'npm', added: true },
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
