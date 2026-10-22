/**
 * A job process for the job runner's tests (src/jobs/runner.integration.test.ts),
 * standing in for scripts/run-job.ts. What it does depends on the source name:
 *   fake-fail        the job throws
 *   fake-crash       the process exits with code 3 without recording anything
 *   fake-oom         the process allocates until its heap limit kills it
 *   fake-slow-<ms>…  the job takes <ms> milliseconds (anything may follow)
 *   anything else    the job succeeds at once
 */
import { runRecordedJob } from '../jobs/executor.js';
import { closeDb } from '../db/client.js';
import type { JobDefinition } from '../jobs/types.js';

const [, , source, jobId] = process.argv;

process.on('disconnect', () => process.exit(1));

async function main(): Promise<number> {
  if (source === 'fake-crash') process.exit(3);
  if (source === 'fake-oom') {
    const hog: number[][] = [];
    for (;;) hog.push(new Array(1_000_000).fill(Math.random()));
  }
  const delayMs = Number(source.match(/^fake-slow-(\d+)/)?.[1] ?? 0);
  const def: JobDefinition = {
    source,
    label: source,
    cron: '',
    run: async () => {
      if (delayMs) await new Promise((resolve) => setTimeout(resolve, delayMs));
      if (source === 'fake-fail') throw new Error('boom');
      return { fetched: 3, inserted: 1 };
    },
  };
  const outcome = await runRecordedJob(def, jobId, () => ({ peakMemoryMb: Math.round(process.resourceUsage().maxRSS / 1024) }));
  return outcome === 'completed' ? 0 : 1;
}

void main().then(async (code) => {
  await closeDb().catch(() => {});
  process.exitCode = code;
  process.removeAllListeners('disconnect');
  process.disconnect?.();
});
