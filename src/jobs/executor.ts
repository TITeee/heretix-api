/**
 * Job executor
 *
 * Wraps every job with a uniform CollectionJob lifecycle:
 *   running lock -> create CollectionJob(running) -> run() -> completed/failed.
 * This replaces the ~6 duplicated lifecycle blocks previously inlined in the
 * scheduler cron closures.
 */
import type { Prisma } from '@prisma/client';
import { prisma } from '../db/client.js';
import { logger } from '../utils/logger.js';
import type { JobDefinition } from './types.js';

// In-memory lock to prevent concurrent execution of the same source
const running = new Set<string>();

export function isJobRunning(source: string): boolean {
  return running.has(source);
}

/**
 * Mark any CollectionJob still 'running' as 'failed'. Call once at process
 * startup, before the scheduler registers anything: the in-memory `running`
 * lock above is always empty right after boot, so a row still marked
 * 'running' at that point can't belong to this process — it was orphaned by
 * a previous process that died mid-run (e.g. a host/sandbox restart) without
 * going through either of executeJob()'s own completed/failed paths, and
 * would otherwise sit in the dashboard forever with no completedAt.
 */
export async function reconcileOrphanedJobs(): Promise<number> {
  const { count } = await prisma.collectionJob.updateMany({
    // 'queued': waiting for a free slot in the job runner when that process ended.
    where: { status: { in: ['running', 'queued'] } },
    data: {
      status: 'failed',
      completedAt: new Date(),
      errorMessage: 'Orphaned: process restarted before the job completed',
    },
  });
  if (count > 0) {
    logger.warn({ count }, 'Reconciled orphaned running jobs from a previous process');
  }
  return count;
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
 * Record a job's terminal outcome. Never throws: the DB being unreachable is
 * frequently *why* a job failed, and letting the bookkeeping write fail on top
 * of that would replace the real error with a less useful one and escape to a
 * caller that has no handler (see executeJob()'s contract below).
 */
async function recordOutcome(
  jobId: string,
  source: string,
  data: Prisma.CollectionJobUpdateInput,
): Promise<void> {
  try {
    await prisma.collectionJob.update({ where: { id: jobId }, data });
  } catch (err) {
    logger.error({ job: source, err }, 'Failed to record job outcome');
  }
}

/**
 * Execute a job with full CollectionJob lifecycle tracking.
 * Skips (no-op) if the same source is already running.
 *
 * Never rejects. Every caller is fire-and-forget -- `void executeJob(def)` from
 * both the scheduler's cron closures and the manual-trigger route -- so an
 * escaping rejection has no handler and takes the whole process down with it.
 * The `running` lock is released in a finally for the same reason: it used to
 * be acquired before the first DB write, so a single transient failure there
 * left the source locked until the next restart.
 */
export async function executeJob(def: JobDefinition): Promise<void> {
  if (running.has(def.source)) {
    logger.warn({ job: def.source }, 'Job already running, skipping');
    return;
  }
  running.add(def.source);

  try {
    logger.info({ job: def.source }, 'Job started');

    let job: { id: string };
    try {
      job = await prisma.collectionJob.create({
        data: { source: def.source, status: 'running', startedAt: new Date() },
        select: { id: true },
      });
    } catch (err) {
      // No row means no progress tracking and no delta-cursor advance, so the
      // run is skipped rather than performed untracked -- the next scheduled
      // run then re-fetches the same window, which is the safe direction.
      logger.error({ job: def.source, err }, 'Failed to record job start, skipping run');
      return;
    }

    await runRecordedJob(def, job.id);
  } finally {
    running.delete(def.source);
  }
}

/**
 * Run a job whose CollectionJob row already exists (status 'running') and
 * record how it ended on that row. Never rejects. What executeJob() runs in
 * this process, and what a job process (scripts/run-job.ts) runs for the job
 * runner, which creates the row itself.
 *
 * `metadata` is merged into the row's own on completion or failure, for what
 * only the caller knows (a job process's peak memory).
 */
export async function runRecordedJob(
  def: JobDefinition,
  jobId: string,
  metadata?: () => Record<string, unknown>,
): Promise<'completed' | 'failed'> {
  const withMetadata = async (data: Prisma.CollectionJobUpdateInput): Promise<Prisma.CollectionJobUpdateInput> => {
    if (!metadata) return data;
    const current = await prisma.collectionJob.findUnique({ where: { id: jobId }, select: { metadata: true } }).catch(() => null);
    const base = current?.metadata && typeof current.metadata === 'object' ? (current.metadata as Record<string, unknown>) : {};
    return { ...data, metadata: { ...base, ...metadata() } as Prisma.InputJsonValue };
  };

  try {
    const result = await def.run();
    await recordOutcome(jobId, def.source, await withMetadata({
      status: 'completed',
      completedAt: new Date(),
      totalFetched: result.fetched ?? 0,
      totalInserted: result.inserted ?? 0,
      totalUpdated: result.updated ?? 0,
      totalFailed: result.failed ?? 0,
    }));
    logger.info({ job: def.source, ...result }, 'Job completed');
    return 'completed';
  } catch (err) {
    await recordOutcome(jobId, def.source, await withMetadata({
      status: 'failed',
      completedAt: new Date(),
      errorMessage: err instanceof Error ? err.message : String(err),
    }));
    logger.error({ job: def.source, err }, 'Job failed');
    return 'failed';
  }
}
