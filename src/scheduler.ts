import cron, { type ScheduledTask } from 'node-cron';
import { logger } from './utils/logger.js';
import { STATIC_JOBS, listOsvEcosystemJobs } from './jobs/registry.js';
import { getJobRunner } from './jobs/runner.js';
import type { JobDefinition } from './jobs/types.js';
import { isEnabled } from './jobs/config.js';

// OSV per-ecosystem discovery runs on this schedule; each ecosystem is a
// separate CollectionJob but they share one cron trigger.
const OSV_ECOSYSTEM_CRON = '0 8 * * *';

const tasks: ScheduledTask[] = [];

/** Hand a job to the runner, which starts it as soon as a slot is free. */
async function enqueue(def: JobDefinition): Promise<void> {
  const outcome = await getJobRunner().request(def);
  if (outcome === 'busy') logger.warn({ job: def.source }, 'Scheduler: job already queued or running, skipping');
}

/**
 * Run a cron tick without ever rejecting.
 *
 * node-cron invokes these callbacks with no handler attached, so anything that
 * escapes becomes an unhandled rejection and kills the process. The job runner's
 * request() already guarantees this for itself, but the enabled-flag lookup and the OSV
 * ecosystem discovery around it are plain DB reads that can fail on their own.
 */
function tick(name: string, run: () => Promise<void>): () => void {
  return () => {
    void run().catch(err => logger.error({ job: name, err }, 'Scheduler tick failed'));
  };
}

export function startScheduler(): void {
  // Static jobs: register cron per registry entry. The enabled flag is checked
  // at fire time so toggling takes effect immediately without re-registering.
  for (const def of STATIC_JOBS) {
    tasks.push(cron.schedule(def.cron, tick(def.source, async () => {
      if (!(await isEnabled(def.source))) {
        logger.info({ job: def.source }, 'Scheduler: job disabled, skipping');
        return;
      }
      await enqueue(def);
    })));
  }

  // OSV ecosystems: discovered dynamically. Each enabled ecosystem runs as its
  // own CollectionJob (osv-<ecosystem>); the runner works through them a few at a time.
  tasks.push(cron.schedule(OSV_ECOSYSTEM_CRON, tick('osv-ecosystems', async () => {
    const jobs = await listOsvEcosystemJobs();
    for (const def of jobs) {
      if (!(await isEnabled(def.source))) {
        logger.info({ job: def.source }, 'Scheduler: job disabled, skipping');
        continue;
      }
      await enqueue(def);
    }
  })));

  logger.info('Scheduler started');
}

/**
 * Stop firing new jobs. Jobs already queued or running are the runner's to
 * stop (JobRunner.stop()).
 */
export async function stopScheduler(): Promise<void> {
  // stop() is typed `void | Promise<void>`; awaiting keeps a rejecting
  // implementation from escaping as an unhandled rejection mid-shutdown.
  await Promise.all(tasks.map(task => task.stop()));
  tasks.length = 0;
  logger.info('Scheduler stopped');
}
