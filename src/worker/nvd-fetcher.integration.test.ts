import { describe, it, expect, beforeEach, afterEach, afterAll, vi } from 'vitest';
import axios from 'axios';
import { prisma } from '../db/client.js';
import { resetDb } from '../test-utils/db.js';
import { fullDownloadNVD, importNVDData, type NVDCveItem } from './nvd-fetcher.js';

// A non-axios error is not classed as transient, so it surfaces on the first
// attempt instead of going through the multi-second retry backoff.
const FETCH_ERROR = new Error('aborted');

function emptyPage(totalResults: number) {
  return { data: { resultsPerPage: 2000, startIndex: 0, totalResults, format: 'NVD_CVE', version: '2.0', timestamp: '', vulnerabilities: [] } };
}

describe('fullDownloadNVD — failure handling', () => {
  beforeEach(async () => {
    await resetDb();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  it('marks the job failed and rethrows when a page cannot be fetched, instead of reporting completion', async () => {
    vi.spyOn(axios, 'get').mockRejectedValue(FETCH_ERROR);

    await expect(fullDownloadNVD()).rejects.toThrow(/aborted at startIndex 0/);

    const job = await prisma.collectionJob.findFirst({ where: { source: 'nvd' } });
    expect(job?.status).toBe('failed');
    expect(job?.completedAt).not.toBeNull();
    expect(job?.errorMessage).toContain('aborted');
    // The message must carry the job id so the run can be resumed.
    expect(job?.errorMessage).toContain(job!.id);
  });

  it('does not let a failed run become the baseline for the incremental update', async () => {
    vi.spyOn(axios, 'get').mockRejectedValue(FETCH_ERROR);
    await expect(fullDownloadNVD()).rejects.toThrow();

    // import:nvd update starts from the latest *completed* job.
    const baseline = await prisma.collectionJob.findFirst({ where: { source: 'nvd', status: 'completed' } });
    expect(baseline).toBeNull();
  });

  it('resumes a failed job from its checkpoint, carries its counts forward, and completes it', async () => {
    const failedJob = await prisma.collectionJob.create({
      data: {
        source: 'nvd',
        status: 'failed',
        startedAt: new Date(),
        completedAt: new Date(),
        errorMessage: 'aborted',
        totalInserted: 3,
        totalUpdated: 2,
        totalFailed: 1,
        metadata: { lastStartIndex: 4000, totalResults: 4000 },
      },
    });
    const get = vi.spyOn(axios, 'get').mockResolvedValue(emptyPage(4000));

    const result = await fullDownloadNVD(failedJob.id);

    expect(get).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ params: expect.objectContaining({ startIndex: 4000 }) }));
    expect(result).toEqual({ total: 6, succeeded: 5, failed: 1 });

    const job = await prisma.collectionJob.findUnique({ where: { id: failedJob.id } });
    expect(job?.status).toBe('completed');
    expect(job?.errorMessage).toBeNull();
    expect(job?.totalInserted).toBe(3);
    expect(job?.totalUpdated).toBe(2);
  });

  it('keeps the checkpoint when a resumed run fails again', async () => {
    const failedJob = await prisma.collectionJob.create({
      data: { source: 'nvd', status: 'failed', startedAt: new Date(), metadata: { lastStartIndex: 4000, totalResults: 396949 } },
    });
    vi.spyOn(axios, 'get').mockRejectedValue(FETCH_ERROR);

    await expect(fullDownloadNVD(failedJob.id)).rejects.toThrow(/aborted at startIndex 4000/);

    const job = await prisma.collectionJob.findUnique({ where: { id: failedJob.id } });
    expect(job?.status).toBe('failed');
    expect(job?.metadata).toEqual({ lastStartIndex: 4000, totalResults: 396949 });
  });

  it('rejects an unknown resume job id instead of silently restarting from zero', async () => {
    const get = vi.spyOn(axios, 'get');

    await expect(fullDownloadNVD('does-not-exist')).rejects.toThrow(/job not found/);
    expect(get).not.toHaveBeenCalled();
  });
});

describe('importNVDData — severity/CVSS priority merge', () => {
  const CVE = 'CVE-2026-5151';
  const item = (metrics?: NVDCveItem['metrics']): NVDCveItem => ({
    id: CVE,
    published: '2026-01-01T00:00:00.000',
    lastModified: '2026-01-02T00:00:00.000',
    descriptions: [{ lang: 'en', value: 'Test CVE' }],
    metrics,
    configurations: [],
  });

  beforeEach(async () => {
    await resetDb();
    // What the OSV importer leaves for a CVE NVD has not analyzed yet.
    await prisma.vulnerability.create({
      data: { cveId: CVE, severity: 'MEDIUM', cvssScore: 5.4, cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N' },
    });
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  it('keeps the lower-priority rating when NVD has none yet', async () => {
    await importNVDData(item());

    const master = await prisma.vulnerability.findUnique({ where: { cveId: CVE } });
    expect(master).toMatchObject({ severity: 'MEDIUM', cvssScore: 5.4 });
  });

  it('replaces it with NVD\'s rating once NVD has one', async () => {
    const vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
    await importNVDData(item({
      cvssMetricV31: [{
        source: 'nvd@nist.gov',
        type: 'Primary',
        cvssData: { version: '3.1', vectorString: vector, baseScore: 9.8, baseSeverity: 'CRITICAL' },
      }],
    } as NVDCveItem['metrics']));

    const master = await prisma.vulnerability.findUnique({ where: { cveId: CVE } });
    expect(master).toMatchObject({ severity: 'CRITICAL', cvssScore: 9.8, cvssVector: vector });
  });
});
