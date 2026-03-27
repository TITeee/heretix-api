import cron from 'node-cron';
import { logger } from './utils/logger.js';
import { importNVDByDateRange } from './worker/nvd-fetcher.js';
import { fullImportKEV } from './worker/kev-fetcher.js';
import { fullImportEPSS } from './worker/epss-fetcher.js';
import { runAdvisoryFetcher } from './worker/advisory-fetcher.js';
import { FortinetFetcher } from './worker/fortinet-fetcher.js';
import { PanFetcher } from './worker/pan-fetcher.js';
import { CiscoFetcher } from './worker/cisco-fetcher.js';

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
  cron.schedule('0 */2 * * *', () => {
    void runJob('nvd-delta', () => {
      const end = new Date();
      const start = new Date(end.getTime() - 2 * 60 * 60 * 1000);
      return importNVDByDateRange(start, end);
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

  logger.info('Scheduler started');
}
