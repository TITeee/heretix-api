/**
 * Job executor
 *
 * Wraps every job with a uniform CollectionJob lifecycle:
 *   running lock -> create CollectionJob(running) -> run() -> completed/failed.
 * This replaces the ~6 duplicated lifecycle blocks previously inlined in the
 * scheduler cron closures.
 */
import { prisma } from '../db/client.js';
import { logger } from '../utils/logger.js';
import type { JobDefinition } from './types.js';

// In-memory lock to prevent concurrent execution of the same source
const running = new Set<string>();

export function isJobRunning(source: string): boolean {
  return running.has(source);
}

/**
 * Resolve the delta cursor for a source: the completedAt of its last completed
 * CollectionJob, or now - fallbackMs if none exists.
 */
export async function getDeltaCursor(source: string, fallbackMs: number): Promise<Date> {
  const lastJob = await prisma.collectionJob.findFirst({
    where: { source, status: 'completed' },
    orderBy: { completedAt: 'desc' },
  });
  return lastJob?.completedAt ?? new Date(Date.now() - fallbackMs);
}

/**
 * Execute a job with full CollectionJob lifecycle tracking.
 * Skips (no-op) if the same source is already running.
 */
export async function executeJob(def: JobDefinition): Promise<void> {
  if (running.has(def.source)) {
    logger.warn({ job: def.source }, 'Job already running, skipping');
    return;
  }
  running.add(def.source);
  logger.info({ job: def.source }, 'Job started');

  const startedAt = new Date();
  const job = await prisma.collectionJob.create({
    data: { source: def.source, status: 'running', startedAt },
  });

  try {
    const result = await def.run();
    await prisma.collectionJob.update({
      where: { id: job.id },
      data: {
        status: 'completed',
        completedAt: new Date(),
        totalFetched: result.fetched ?? 0,
        totalInserted: result.inserted ?? 0,
        totalUpdated: result.updated ?? 0,
        totalFailed: result.failed ?? 0,
      },
    });
    logger.info({ job: def.source, ...result }, 'Job completed');
  } catch (err) {
    await prisma.collectionJob.update({
      where: { id: job.id },
      data: {
        status: 'failed',
        completedAt: new Date(),
        errorMessage: err instanceof Error ? err.message : String(err),
      },
    });
    logger.error({ job: def.source, err }, 'Job failed');
  } finally {
    running.delete(def.source);
  }
}
