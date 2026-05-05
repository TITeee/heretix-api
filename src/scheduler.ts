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
import { OracleLinuxFetcher } from './worker/oracle-linux-fetcher.js';
import { SophosFetcher } from './worker/sophos-fetcher.js';
import { SonicWallFetcher } from './worker/sonicwall-fetcher.js';
import { OracleCpuFetcher } from './worker/oracle-cpu-fetcher.js';
import { BroadcomFetcher } from './worker/broadcom-fetcher.js';
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
    void runJob('kev', async () => {
      const job = await prisma.collectionJob.create({
        data: { source: 'kev', status: 'running', startedAt: new Date() },
      });
      try {
        const result = await fullImportKEV();
        await prisma.collectionJob.update({
          where: { id: job.id },
          data: { status: 'completed', completedAt: new Date(), totalUpdated: result.updated },
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

  // EPSS bulk update: daily at 10:00 UTC
  cron.schedule('0 10 * * *', () => {
    void runJob('epss', async () => {
      const job = await prisma.collectionJob.create({
        data: { source: 'epss', status: 'running', startedAt: new Date() },
      });
      try {
        const result = await fullImportEPSS();
        await prisma.collectionJob.update({
          where: { id: job.id },
          data: { status: 'completed', completedAt: new Date(), totalUpdated: result.updated },
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

  // Vendor advisories: daily from 11:00 UTC (15-minute intervals)
  const advisoryJobs = [
    { source: 'advisory-fortinet',     fetcher: () => new FortinetFetcher(),     cron: '0 11 * * *' },
    { source: 'advisory-pan',          fetcher: () => new PanFetcher(),          cron: '15 11 * * *' },
    { source: 'advisory-cisco',        fetcher: () => new CiscoFetcher(),        cron: '30 11 * * *' },
    { source: 'advisory-oracle-linux', fetcher: () => new OracleLinuxFetcher(), cron: '45 11 * * *' },
    { source: 'advisory-sophos',       fetcher: () => new SophosFetcher(),       cron: '0 12 * * *' },
    { source: 'advisory-sonicwall',    fetcher: () => new SonicWallFetcher(),    cron: '15 12 * * *' },
    { source: 'advisory-oracle-cpu',   fetcher: () => new OracleCpuFetcher(),   cron: '30 12 * * *' },
    { source: 'advisory-broadcom',     fetcher: () => new BroadcomFetcher(),     cron: '0 13 * * *'  },
  ] as const;

  for (const { source, fetcher, cron: schedule } of advisoryJobs) {
    cron.schedule(schedule, () => {
      void runJob(source, async () => {
        const job = await prisma.collectionJob.create({
          data: { source, status: 'running', startedAt: new Date() },
        });
        try {
          await runAdvisoryFetcher(fetcher());
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
  }

  // OSV delta: daily at 08:00 UTC — run per-ecosystem so each gets its own CollectionJob
  cron.schedule('0 8 * * *', () => {
    void (async () => {
      const ecosystems = await prisma.oSVVulnerability.groupBy({
        by: ['ecosystem'],
        where: { ecosystem: { not: null } },
      });
      for (const { ecosystem } of ecosystems) {
        if (!ecosystem) continue;
        const sourceKey = `osv-${ecosystem}`;
        await runJob(sourceKey, async () => {
          const lastJob = await prisma.collectionJob.findFirst({
            where: { source: sourceKey, status: 'completed' },
            orderBy: { completedAt: 'desc' },
          });
          const since = lastJob?.completedAt ?? new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
          const job = await prisma.collectionJob.create({
            data: { source: sourceKey, status: 'running', startedAt: new Date() },
          });
          try {
            await importOSVEcosystemDelta(ecosystem, since);
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
      }
    })();
  });

  // MAL delta: daily at 08:30 UTC
  cron.schedule('30 8 * * *', () => {
    void runJob('osv-malware-delta', async () => {
      const lastJob = await prisma.collectionJob.findFirst({
        where: { source: 'osv-mal', status: 'completed' },
        orderBy: { completedAt: 'desc' },
      });
      const since = lastJob?.completedAt ?? new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      const job = await prisma.collectionJob.create({
        data: { source: 'osv-mal', status: 'running', startedAt: new Date() },
      });
      try {
        await importMALDelta(since);
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

  logger.info('Scheduler started');
}
