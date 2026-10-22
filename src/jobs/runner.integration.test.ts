import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { prisma } from '../db/client.js';
import { resetDb } from '../test-utils/db.js';
import { JobRunner, exitReason, runnerConfigFromEnv, type RunnerConfig } from './runner.js';
import { reconcileOrphanedJobs } from './executor.js';
import type { JobDefinition } from './types.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const FAKE = path.join(here, '..', 'test-utils', 'fake-job-process.ts');

function runner(over: Partial<RunnerConfig> = {}): JobRunner {
  return new JobRunner({
    maxConcurrent: 2,
    maxHeavy: 1,
    maxOldSpaceMb: 3072,
    childPoolMax: 2,
    script: FAKE,
    execArgv: ['--import', 'tsx'],
    stopGraceMs: 3_000,
    ...over,
  });
}

// The fake process decides what to do from the source; run() is never called here.
const job = (source: string, heavy = false): JobDefinition => ({
  source, label: source, cron: '', heavy, run: async () => ({}),
});

const rowOf = (source: string) => prisma.collectionJob.findFirstOrThrow({ where: { source } });

describe('JobRunner', () => {
  beforeEach(async () => {
    await resetDb();
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  it('runs a job in its own process and records its outcome and peak memory', async () => {
    const r = runner();
    expect(await r.request(job('fake-ok'))).toBe('started');
    await r.idle();

    const row = await rowOf('fake-ok');
    expect(row).toMatchObject({ status: 'completed', totalFetched: 3, totalInserted: 1 });
    expect(row.startedAt).not.toBeNull();
    expect((row.metadata as { peakMemoryMb: number }).peakMemoryMb).toBeGreaterThan(0);
  }, 60_000);

  it('records a job that throws as failed, with its error', async () => {
    const r = runner();
    await r.request(job('fake-fail'));
    await r.idle();
    expect(await rowOf('fake-fail')).toMatchObject({ status: 'failed', errorMessage: 'boom' });
  }, 60_000);

  it('records a process that dies without recording anything', async () => {
    const r = runner();
    await r.request(job('fake-crash'));
    await r.idle();
    const row = await rowOf('fake-crash');
    expect(row.status).toBe('failed');
    expect(row.errorMessage).toContain('exited with code 3');
  }, 60_000);

  it('survives a job that runs out of memory, and records it', async () => {
    const r = runner({ maxOldSpaceMb: 64 });
    await r.request(job('fake-oom'));
    await r.idle();
    const row = await rowOf('fake-oom');
    expect(row.status).toBe('failed');
    expect(row.errorMessage).toContain('most likely out of memory (heap limit 64 MB');
  }, 60_000);

  it('never queues the same source twice', async () => {
    const r = runner();
    expect(await r.request(job('fake-slow-500-dup'))).toBe('started');
    expect(await r.request(job('fake-slow-500-dup'))).toBe('busy');
    expect(r.isBusy('fake-slow-500-dup')).toBe(true);
    await r.idle();
    expect(await prisma.collectionJob.count({ where: { source: 'fake-slow-500-dup' } })).toBe(1);
  }, 60_000);

  it('runs at most maxConcurrent jobs at once and queues the rest', async () => {
    const r = runner({ maxConcurrent: 2 });
    expect(await r.request(job('fake-slow-1500-a'))).toBe('started');
    expect(await r.request(job('fake-slow-1500-b'))).toBe('started');
    expect(await r.request(job('fake-slow-1500-c'))).toBe('queued');
    expect((await rowOf('fake-slow-1500-c')).status).toBe('queued');
    await r.idle();

    const [a, b, c] = await Promise.all(['a', 'b', 'c'].map((x) => rowOf(`fake-slow-1500-${x}`)));
    for (const row of [a, b, c]) expect(row.status).toBe('completed');
    // c started only once a or b had finished.
    expect(c.startedAt!.getTime()).toBeGreaterThanOrEqual(Math.min(a.completedAt!.getTime(), b.completedAt!.getTime()));
  }, 60_000);

  it('runs one heavy job at a time, letting a light one through meanwhile', async () => {
    const r = runner({ maxConcurrent: 2, maxHeavy: 1 });
    expect(await r.request(job('fake-slow-1500-heavy1', true))).toBe('started');
    expect(await r.request(job('fake-slow-1500-heavy2', true))).toBe('queued');
    expect(await r.request(job('fake-slow-200-light'))).toBe('started');
    await r.idle();

    const [h1, h2] = await Promise.all([rowOf('fake-slow-1500-heavy1'), rowOf('fake-slow-1500-heavy2')]);
    expect(h2.startedAt!.getTime()).toBeGreaterThanOrEqual(h1.completedAt!.getTime());
  }, 60_000);

  it('on stop, records running jobs as interrupted and waiting ones as not started', async () => {
    const r = runner({ maxConcurrent: 1 });
    await r.request(job('fake-slow-30000-running'));
    await r.request(job('fake-slow-30000-waiting'));
    // Let the first process get going before stopping it.
    await new Promise((resolve) => setTimeout(resolve, 1500));
    await r.stop();

    expect(await rowOf('fake-slow-30000-running')).toMatchObject({ status: 'failed', errorMessage: 'Interrupted: the API was shutting down' });
    expect(await rowOf('fake-slow-30000-waiting')).toMatchObject({ status: 'failed', errorMessage: 'Not started: the API was shutting down' });
    expect(await r.request(job('fake-ok'))).toBe('stopped');
  }, 60_000);

  it('records an unknown source as failed when run by the real job process', async () => {
    const r = new JobRunner({ ...runnerConfigFromEnv(), execArgv: ['--import', 'tsx'], childPoolMax: 2 });
    await r.request(job('no-such-source'));
    await r.idle();
    expect(await rowOf('no-such-source')).toMatchObject({ status: 'failed', errorMessage: 'Unknown job source: no-such-source' });
  }, 60_000);
});

describe('reconcileOrphanedJobs', () => {
  beforeEach(async () => {
    await resetDb();
  });

  it('fails jobs left queued or running by a previous process', async () => {
    await prisma.collectionJob.createMany({
      data: [
        { source: 'a', status: 'queued' },
        { source: 'b', status: 'running', startedAt: new Date() },
        { source: 'c', status: 'completed' },
      ],
    });
    expect(await reconcileOrphanedJobs()).toBe(2);
    expect((await rowOf('a')).status).toBe('failed');
    expect((await rowOf('c')).status).toBe('completed');
  });
});

describe('exitReason', () => {
  it('names running out of memory', () => {
    expect(exitReason(134, null, 3072)).toContain('out of memory (heap limit 3072 MB');
    expect(exitReason(null, 'SIGABRT', 3072)).toContain('out of memory');
  });

  it('says how the process ended otherwise', () => {
    expect(exitReason(3, null, 3072)).toBe('Job process exited with code 3 before recording an outcome');
    expect(exitReason(null, 'SIGKILL', 3072)).toBe('Job process was killed (SIGKILL) before recording an outcome');
  });
});
