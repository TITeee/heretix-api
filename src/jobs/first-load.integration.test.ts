import { describe, it, expect, beforeEach, afterEach, afterAll, vi } from 'vitest';
import axios from 'axios';
import { prisma } from '../db/client.js';
import { resetDb } from '../test-utils/db.js';
import { importNVDData } from '../worker/nvd-fetcher.js';
import { isCnaLoaded, isMsrcLoaded, isNvdLoaded, isOsvLoaded, runNvdFullLoad } from './first-load.js';

async function seedNvdRecord() {
  await importNVDData({
    id: 'CVE-2026-0001',
    published: '2026-01-01T00:00:00.000',
    lastModified: '2026-01-02T00:00:00.000',
    descriptions: [{ lang: 'en', value: 'x' }],
    configurations: [],
  } as never);
}

const done = (source: string) =>
  prisma.collectionJob.create({ data: { source, status: 'completed', startedAt: new Date(), completedAt: new Date() } });

describe('first load checks', () => {
  beforeEach(async () => {
    await resetDb();
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  it('NVD: not loaded on an empty database', async () => {
    expect(await isNvdLoaded()).toBe(false);
  });

  it('NVD: not loaded when a run "completed" but nothing is there (a delta on an empty install)', async () => {
    await done('nvd');
    expect(await isNvdLoaded()).toBe(false);
  });

  it('NVD: not loaded when records are there but no run completed (an interrupted load)', async () => {
    await seedNvdRecord();
    expect(await isNvdLoaded()).toBe(false);
  });

  it('NVD: loaded when a run completed and records are there', async () => {
    await seedNvdRecord();
    await done('nvd');
    expect(await isNvdLoaded()).toBe(true);
  });

  it('OSV: loaded after the full import command or a daily run, with records of that bucket', async () => {
    await prisma.oSVVulnerability.create({ data: { osvId: 'GHSA-aaaa-bbbb-cccc', ecosystem: 'Debian:12', rawData: {} } });
    expect(await isOsvLoaded('Debian')).toBe(false);
    await done('osv-full-Debian');
    expect(await isOsvLoaded('Debian')).toBe(true);
    expect(await isOsvLoaded('npm')).toBe(false);
  });
});

describe('first load checks: CVE Records and Microsoft', () => {
  beforeEach(async () => {
    await resetDb();
  });

  it('CVE Records: loaded only when a run completed and records are there', async () => {
    expect(await isCnaLoaded()).toBe(false);
    await prisma.cnaVulnerability.create({ data: { cveId: 'CVE-2026-0001', cnaShortName: 'x', rawAffected: [] } });
    expect(await isCnaLoaded()).toBe(false);
    await done('cna');
    expect(await isCnaLoaded()).toBe(true);
  });

  it('Microsoft: loaded only when a run completed and its advisories are there', async () => {
    expect(await isMsrcLoaded()).toBe(false);
    await done('advisory-microsoft');
    expect(await isMsrcLoaded()).toBe(false);
    await prisma.advisoryVulnerability.create({ data: { source: 'advisory-microsoft', externalId: 'CVE-2026-0002', rawData: {} } });
    expect(await isMsrcLoaded()).toBe(true);
  });
});

describe('runNvdFullLoad', () => {
  beforeEach(async () => {
    await resetDb();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  const page = (totalResults: number) => ({ data: { resultsPerPage: 2000, startIndex: 0, totalResults, format: 'NVD_CVE', version: '2.0', timestamp: '', vulnerabilities: [] } });

  it('starts at 0 in its own row, and keeps the row\'s mode', async () => {
    const row = await prisma.collectionJob.create({ data: { source: 'nvd', status: 'running', startedAt: new Date(), metadata: { mode: 'full' } } });
    const get = vi.spyOn(axios, 'get').mockResolvedValue(page(0));

    await runNvdFullLoad(row.id);

    expect(get).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ params: expect.objectContaining({ startIndex: 0 }) }));
    expect(await prisma.collectionJob.count({ where: { source: 'nvd' } })).toBe(1);
    expect((await prisma.collectionJob.findUniqueOrThrow({ where: { id: row.id } })).status).toBe('completed');
  });

  it('carries on from where the last failed download stopped', async () => {
    await prisma.collectionJob.create({
      data: { source: 'nvd', status: 'failed', startedAt: new Date(), metadata: { mode: 'full', lastStartIndex: 6000, totalResults: 8000 }, totalInserted: 5, totalUpdated: 1 },
    });
    const row = await prisma.collectionJob.create({ data: { source: 'nvd', status: 'running', startedAt: new Date(), metadata: { mode: 'full' } } });
    const get = vi.spyOn(axios, 'get').mockResolvedValue(page(6000));

    const result = await runNvdFullLoad(row.id);

    expect(get).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ params: expect.objectContaining({ startIndex: 6000 }) }));
    expect(result).toMatchObject({ inserted: 5, updated: 1 });
  });

  it('does not resume a download that failed before the last completed load', async () => {
    await prisma.collectionJob.create({
      data: { source: 'nvd', status: 'failed', startedAt: new Date(Date.now() - 3_000), createdAt: new Date(Date.now() - 3_000), metadata: { lastStartIndex: 6000, totalResults: 8000 } },
    });
    await prisma.collectionJob.create({ data: { source: 'nvd', status: 'completed', startedAt: new Date(Date.now() - 2_000), completedAt: new Date(Date.now() - 1_000) } });
    const row = await prisma.collectionJob.create({ data: { source: 'nvd', status: 'running', startedAt: new Date(), metadata: { mode: 'full' } } });
    const get = vi.spyOn(axios, 'get').mockResolvedValue(page(0));

    await runNvdFullLoad(row.id);

    expect(get).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ params: expect.objectContaining({ startIndex: 0 }) }));
  });
});
