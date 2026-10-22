/**
 * One collection job, in a process of its own.
 *
 * Started by the job runner (src/jobs/runner.ts), never by hand:
 *   node dist/scripts/run-job.js <source> <collectionJobId>
 *
 * The runner has already created the job's CollectionJob row and set it to
 * 'running'; this process runs the job and records how it ended on that row,
 * with its peak memory. A job that blocks the event loop, leaks a rejection or
 * runs out of memory takes down only this process, never the API.
 */
import 'dotenv/config';
import { prisma, closeDb } from '../db/client.js';
import { resolveJob } from '../jobs/registry.js';
import { runRecordedJob } from '../jobs/executor.js';
import { logger } from '../utils/logger.js';

const [, , source, jobId] = process.argv;

let finishing = false;

/** Peak resident memory of this process so far, for the CollectionJob row. */
function peakMemory(): Record<string, unknown> {
  return { peakMemoryMb: Math.round(process.resourceUsage().maxRSS / 1024) };
}

/** Record a failure this process caught itself; best effort, never throws. */
async function recordFailure(message: string): Promise<void> {
  try {
    await prisma.collectionJob.updateMany({
      where: { id: jobId, status: 'running' },
      data: { status: 'failed', completedAt: new Date(), errorMessage: message, metadata: peakMemory() as object },
    });
  } catch (err) {
    logger.error({ job: source, err }, 'Failed to record job failure');
  }
}

// The runner talks to this process over IPC. Once that channel closes the
// runner is gone (the API stopped or crashed); stop rather than run on
// unsupervised, where nothing would notice if this process hung.
process.on('disconnect', () => {
  if (finishing) return;
  logger.warn({ job: source }, 'Job runner went away; stopping the job');
  process.exit(1);
});

for (const event of ['unhandledRejection', 'uncaughtException'] as const) {
  process.on(event, (reason: unknown) => {
    logger.fatal({ job: source, reason }, `Job process: ${event}`);
    void recordFailure(`Job process: ${event}: ${reason instanceof Error ? reason.message : String(reason)}`)
      .finally(() => process.exit(1));
  });
}

async function main(): Promise<number> {
  if (!source || !jobId) {
    logger.error('Usage: run-job <source> <collectionJobId>');
    return 2;
  }
  const def = await resolveJob(source);
  if (!def) {
    await recordFailure(`Unknown job source: ${source}`);
    return 1;
  }
  logger.info({ job: source, pid: process.pid }, 'Job process started');
  const outcome = await runRecordedJob(def, jobId, peakMemory);
  return outcome === 'completed' ? 0 : 1;
}

void main().then(async (code) => {
  finishing = true;
  await closeDb().catch(() => {});
  process.exitCode = code;
  // Closing the IPC channel is the last thing keeping the event loop alive.
  process.disconnect?.();
});
