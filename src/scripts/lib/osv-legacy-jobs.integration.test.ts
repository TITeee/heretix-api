import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import { prisma } from '../../db/client.js';
import { resetDb } from '../../test-utils/db.js';
import { tidyLegacyOsvJobs } from './osv-legacy-jobs.js';

const job = (source: string, status = 'completed') => ({ source, status, startedAt: new Date('2026-10-01T00:00:00Z'), completedAt: new Date('2026-10-01T00:00:00Z') });
const enabled = async (source: string) => (await prisma.jobConfig.findUnique({ where: { source } }))?.enabled;
const jobSources = async () => (await prisma.collectionJob.findMany({ select: { source: true } })).map((j) => j.source).sort();

describe('tidyLegacyOsvJobs', () => {
  beforeEach(async () => {
    await resetDb();
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  it('switches on the bucket an old per-release setting had on, and removes the old settings and job rows', async () => {
    await prisma.jobConfig.createMany({ data: [
      { source: 'osv-Debian:12', enabled: true }, { source: 'osv-Debian:13', enabled: false },
      { source: 'osv-Ubuntu:22.04:LTS', enabled: true }, { source: 'osv-Alpine:v3.21', enabled: false },
    ] });
    await prisma.collectionJob.createMany({ data: [job('osv-Debian:12'), job('osv-Debian:12'), job('osv-Ubuntu:22.04:LTS'), job('osv-Alpine:v3.21', 'failed')] });

    const result = await tidyLegacyOsvJobs(prisma);

    expect(result).toEqual({ switchedOn: ['osv-Debian', 'osv-Ubuntu'], configsRemoved: 4, jobsRemoved: 4 });
    expect(await enabled('osv-Debian')).toBe(true);
    expect(await enabled('osv-Ubuntu')).toBe(true);
    // All of Alpine's old settings were off: nothing to carry over.
    expect(await enabled('osv-Alpine')).toBeUndefined();
    expect(await prisma.jobConfig.count({ where: { source: { contains: ':' } } })).toBe(0);
    expect(await jobSources()).toEqual([]);
  });

  it('leaves alone a setting the bucket already has: what was chosen on the new version stands', async () => {
    await prisma.jobConfig.createMany({ data: [{ source: 'osv-Debian:12', enabled: true }, { source: 'osv-Debian', enabled: false }] });
    const result = await tidyLegacyOsvJobs(prisma);
    expect(result.switchedOn).toEqual([]);
    expect(await enabled('osv-Debian')).toBe(false);
    expect(await enabled('osv-Debian:12')).toBeUndefined();
  });

  it('does not touch the jobs and settings of a bucket, of other ecosystems, or of full loads', async () => {
    await prisma.jobConfig.createMany({ data: [{ source: 'osv-Debian', enabled: true }, { source: 'osv-npm', enabled: true }, { source: 'osv-mal', enabled: false }, { source: 'nvd', enabled: true }] });
    await prisma.collectionJob.createMany({ data: [job('osv-Debian'), job('osv-npm'), job('osv-full-Debian:12'), job('nvd')] });

    const result = await tidyLegacyOsvJobs(prisma);

    expect(result).toEqual({ switchedOn: [], configsRemoved: 0, jobsRemoved: 0 });
    expect(await jobSources()).toEqual(['nvd', 'osv-Debian', 'osv-full-Debian:12', 'osv-npm']);
    expect(await prisma.jobConfig.count()).toBe(4);
  });

  it('keeps a job that is queued or running', async () => {
    await prisma.collectionJob.createMany({ data: [job('osv-Debian:12', 'running'), job('osv-Debian:13', 'queued'), job('osv-Debian:11')] });
    const result = await tidyLegacyOsvJobs(prisma);
    expect(result.jobsRemoved).toBe(1);
    expect(await jobSources()).toEqual(['osv-Debian:12', 'osv-Debian:13']);
  });

  it('does nothing on a database without old rows, and again after it has run', async () => {
    await prisma.jobConfig.create({ data: { source: 'osv-Debian:12', enabled: true } });
    await tidyLegacyOsvJobs(prisma);
    expect(await tidyLegacyOsvJobs(prisma)).toEqual({ switchedOn: [], configsRemoved: 0, jobsRemoved: 0 });
    expect(await enabled('osv-Debian')).toBe(true);
  });
});
