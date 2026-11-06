/**
 * The first load of the sources whose schedule reads only changes (NVD, OSV).
 *
 * A manual Run on a source that was never loaded does the full import itself
 * (JobDefinition.firstLoad), so nobody has to start `pnpm import:...` by hand
 * first. These are the checks and the loads behind that.
 */
import type { Prisma } from '@prisma/client';
import { prisma } from '../db/client.js';
import { fullDownloadNVD } from '../worker/nvd-fetcher.js';
import { importOSVEcosystemStreaming } from '../worker/osv-fetcher.js';
import { bootstrapCna, CNA_BOOTSTRAP_YEARS } from '../worker/cna-importer.js';
import { MsrcFetcher } from '../worker/msrc-fetcher.js';
import { runAdvisoryFetcher } from '../worker/advisory-fetcher.js';
import { SHARED_BUCKET_ECOSYSTEMS } from './osv-bucket.js';
import type { JobResult } from './types.js';

/**
 * Loaded means a full or delta run completed AND records are there. The second
 * half matters for a database emptied since, or one a delta once "completed"
 * on while it was still empty (the schedule used to run a delta on any install).
 */
async function completedWithData(sources: string[], hasData: () => Promise<boolean>): Promise<boolean> {
  const done = await prisma.collectionJob.findFirst({
    where: { source: { in: sources }, status: 'completed' },
    select: { id: true },
  });
  return !!done && (await hasData());
}

export function isNvdLoaded(): Promise<boolean> {
  return completedWithData(['nvd'], async () => !!(await prisma.nVDVulnerability.findFirst({ select: { id: true } })));
}

export function isCnaLoaded(): Promise<boolean> {
  return completedWithData(['cna'], async () => !!(await prisma.cnaVulnerability.findFirst({ select: { id: true } })));
}

export function isMsrcLoaded(): Promise<boolean> {
  return completedWithData(['advisory-microsoft'], async () =>
    !!(await prisma.advisoryVulnerability.findFirst({ where: { source: 'advisory-microsoft' }, select: { id: true } })));
}

/** Where the records of an OSV bucket are in the database ("Debian" holds "Debian:12", ...). */
export function osvEcosystemWhere(bucket: string): Prisma.OSVVulnerabilityWhereInput {
  return SHARED_BUCKET_ECOSYSTEMS.includes(bucket) ? { ecosystem: { startsWith: bucket } } : { ecosystem: bucket };
}

export function isOsvLoaded(bucket: string): Promise<boolean> {
  return completedWithData(
    // `osv-full-` is what `pnpm import:osv ecosystem` records.
    [`osv-${bucket}`, `osv-full-${bucket}`],
    async () => !!(await prisma.oSVVulnerability.findFirst({ where: osvEcosystemWhere(bucket), select: { id: true } })),
  );
}

/**
 * The full NVD download, into the job's own row. A download that failed part
 * way left its place in its row (`lastStartIndex`); this one carries on from
 * there instead of starting over, as `pnpm import:nvd full <id>` does.
 */
export async function runNvdFullLoad(jobId: string): Promise<JobResult> {
  const lastDone = await prisma.collectionJob.findFirst({
    where: { source: 'nvd', status: 'completed' },
    orderBy: { completedAt: 'desc' },
    select: { completedAt: true },
  });
  const previous = await prisma.collectionJob.findFirst({
    where: {
      source: 'nvd',
      status: 'failed',
      id: { not: jobId },
      ...(lastDone?.completedAt ? { createdAt: { gt: lastDone.completedAt } } : {}),
    },
    orderBy: { createdAt: 'desc' },
  });
  const checkpoint = previous?.metadata as { lastStartIndex?: number; totalResults?: number } | null;
  if (previous && checkpoint?.lastStartIndex && checkpoint.lastStartIndex > 0) {
    await prisma.collectionJob.update({
      where: { id: jobId },
      data: {
        metadata: { mode: 'full', lastStartIndex: checkpoint.lastStartIndex, totalResults: checkpoint.totalResults ?? 0 },
        totalInserted: previous.totalInserted,
        totalUpdated: previous.totalUpdated,
        totalFailed: previous.totalFailed,
      },
    });
  }
  const result = await fullDownloadNVD(jobId);
  return { fetched: result.total, inserted: result.inserted, updated: result.updated, failed: result.failed };
}

/** The full import of one OSV bucket. */
export async function runOsvFullLoad(bucket: string): Promise<JobResult> {
  const result = await importOSVEcosystemStreaming(bucket);
  return { fetched: result.total, updated: result.succeeded, failed: result.failed };
}

/** The ~600 MB CVE Records bundle; what `pnpm import:cna` does on an empty database. */
export async function runCnaFullLoad(): Promise<JobResult> {
  const result = await bootstrapCna(CNA_BOOTSTRAP_YEARS);
  return { fetched: result.scanned, inserted: result.inserted, updated: result.updated, failed: result.failed };
}

/** Every MSRC document since March 2021; what `pnpm import:msrc` does. */
export async function runMsrcFullLoad(): Promise<JobResult> {
  const result = await runAdvisoryFetcher(new MsrcFetcher({ full: true }));
  return { fetched: result.total, inserted: result.inserted, updated: result.updated, failed: result.failed };
}
