import cron from 'node-cron';
import { logger } from './utils/logger.js';
import { prisma } from './db/client.js';
import { importNVDByDateRange } from './worker/nvd-fetcher.js';
import { fullImportKEV } from './worker/kev-fetcher.js';
import { fullImportEPSS } from './worker/epss-fetcher.js';
import { runAdvisoryFetcher } from './worker/advisory-fetcher.js';
import { FortinetFetcher } from './worker/fortinet-fetcher.js';
import { PanFetcher } from './worker/pan-fetcher.js';
import { CiscoFetcher } from './worker/cisco-fetcher.js';
import { importOSVEcosystemDelta, importMALDelta } from './worker/osv-fetcher.js';

// Lock flag to prevent concurrent execution of the same job
const running = new Set<string>();

async function runJob(name: string, fn: () => Promise<unknown>): Promise<void> {
  if (running.has(name)) {
    logger.warn({ job: name }, 'Scheduler: job already running, skipping');
    return;
  }
  running.add(name);
  logger.info({ job: name }, 'Scheduler: job started');
  try {
    await fn();
    logger.info({ job: name }, 'Scheduler: job completed');
  } catch (err) {
    logger.error({ job: name, err }, 'Scheduler: job failed');
  } finally {
    running.delete(name);
  }
}

export function startScheduler(): void {
  // NVD delta update: every 2 hours
  // Uses CollectionJob to track the last successful run, so any downtime gap is
  // covered on the next execution rather than silently dropped.
  cron.schedule('0 */2 * * *', () => {
    void runJob('nvd-delta', async () => {
      const lastJob = await prisma.collectionJob.findFirst({
        where: { source: 'nvd-delta', status: 'completed' },
        orderBy: { completedAt: 'desc' },
      });
      const end = new Date();
      const start = lastJob?.completedAt ?? new Date(end.getTime() - 2 * 60 * 60 * 1000);

      const job = await prisma.collectionJob.create({
        data: { source: 'nvd-delta', status: 'running', startedAt: new Date() },
      });
      try {
        await importNVDByDateRange(start, end);
        await prisma.collectionJob.update({
          where: { id: job.id },
          data: { status: 'completed', completedAt: new Date() },
        });
      } catch (err) {
        await prisma.collectionJob.update({
          where: { id: job.id },
          data: {
            status: 'failed',
            completedAt: new Date(),
            errorMessage: err instanceof Error ? err.message : String(err),
          },
        });
        throw err;
      }
    });
  });

  // KEV full replace: daily at 09:00 UTC
  cron.schedule('0 9 * * *', () => {
    void runJob('kev', fullImportKEV);
  });

  // EPSS bulk update: daily at 10:00 UTC
  cron.schedule('0 10 * * *', () => {
    void runJob('epss', fullImportEPSS);
  });

  // Vendor advisories: daily from 11:00 UTC (15-minute intervals)
  cron.schedule('0 11 * * *',  () => void runJob('advisory-fortinet', () => runAdvisoryFetcher(new FortinetFetcher())));
  cron.schedule('15 11 * * *', () => void runJob('advisory-pan',      () => runAdvisoryFetcher(new PanFetcher())));
  cron.schedule('30 11 * * *', () => void runJob('advisory-cisco',    () => runAdvisoryFetcher(new CiscoFetcher())));

  // OSV delta: daily at 08:00 UTC — update all ecosystems already in the DB
  cron.schedule('0 8 * * *', () => {
    void runJob('osv-delta', async () => {
      const ecosystems = await prisma.oSVVulnerability.groupBy({
        by: ['ecosystem'],
        where: { ecosystem: { not: null } },
      });
      for (const { ecosystem } of ecosystems) {
        if (!ecosystem) continue;
        const sourceKey = `osv-${ecosystem}`;
        const lastJob = await prisma.collectionJob.findFirst({
          where: { source: sourceKey, status: 'completed' },
          orderBy: { completedAt: 'desc' },
        });
        const since = lastJob?.completedAt ?? new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
        await importOSVEcosystemDelta(ecosystem, since);
      }
    });
  });

  // MAL delta: daily at 08:30 UTC
  cron.schedule('30 8 * * *', () => {
    void runJob('osv-malware-delta', async () => {
      const lastJob = await prisma.collectionJob.findFirst({
        where: { source: 'osv-mal', status: 'completed' },
        orderBy: { completedAt: 'desc' },
      });
      const since = lastJob?.completedAt ?? new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      await importMALDelta(since);
    });
  });

  logger.info('Scheduler started');
}
