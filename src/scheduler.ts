import cron from 'node-cron';
import { logger } from './utils/logger.js';
import { STATIC_JOBS, listOsvEcosystemJobs } from './jobs/registry.js';
import { executeJob } from './jobs/executor.js';
import { isEnabled } from './jobs/config.js';

// OSV per-ecosystem discovery runs on this schedule; each ecosystem is a
// separate CollectionJob but they share one cron trigger.
const OSV_ECOSYSTEM_CRON = '0 8 * * *';

export function startScheduler(): void {
  // Static jobs: register cron per registry entry. The enabled flag is checked
  // at fire time so toggling takes effect immediately without re-registering.
  for (const def of STATIC_JOBS) {
    cron.schedule(def.cron, () => {
      void (async () => {
        if (!(await isEnabled(def.source))) {
          logger.info({ job: def.source }, 'Scheduler: job disabled, skipping');
          return;
        }
        await executeJob(def);
      })();
    });
  }

  // OSV ecosystems: discovered dynamically. Each enabled ecosystem runs as its
  // own CollectionJob (osv-<ecosystem>).
  cron.schedule(OSV_ECOSYSTEM_CRON, () => {
    void (async () => {
      const jobs = await listOsvEcosystemJobs();
      for (const def of jobs) {
        if (!(await isEnabled(def.source))) {
          logger.info({ job: def.source }, 'Scheduler: job disabled, skipping');
          continue;
        }
        await executeJob(def);
      }
    })();
  });

  logger.info('Scheduler started');
}
