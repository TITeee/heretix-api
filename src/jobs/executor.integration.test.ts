import { describe, it, expect, beforeEach, afterAll, vi } from 'vitest';
import { prisma } from '../db/client.js';
import { resetDb } from '../test-utils/db.js';
import { executeJob, getDeltaCursor, isJobRunning, reconcileOrphanedJobs } from './executor.js';
import type { JobDefinition } from './types.js';

describe('executeJob', () => {
  beforeEach(async () => {
    await resetDb();
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  it('records a completed CollectionJob with counts on success', async () => {
    const def: JobDefinition = {
      source: 'test-source-success',
      label: 'Test',
      cron: '0 0 * * *',
      run: async () => ({ fetched: 10, inserted: 3, updated: 5, failed: 2 }),
    };

    await executeJob(def);

    const job = await prisma.collectionJob.findFirst({ where: { source: 'test-source-success' } });
    expect(job?.status).toBe('completed');
    expect(job?.totalFetched).toBe(10);
    expect(job?.totalInserted).toBe(3);
    expect(job?.totalUpdated).toBe(5);
    expect(job?.totalFailed).toBe(2);
    expect(job?.completedAt).not.toBeNull();
  });

  it('records a failed CollectionJob with the error message when run() throws', async () => {
    const def: JobDefinition = {
      source: 'test-source-failure',
      label: 'Test',
      cron: '0 0 * * *',
      run: async () => { throw new Error('boom'); },
    };

    await executeJob(def);

    const job = await prisma.collectionJob.findFirst({ where: { source: 'test-source-failure' } });
    expect(job?.status).toBe('failed');
    expect(job?.errorMessage).toBe('boom');
    expect(job?.completedAt).not.toBeNull();
  });

  it('does not throw to the caller when run() rejects (failure is recorded, not propagated)', async () => {
    const def: JobDefinition = {
      source: 'test-source-swallow',
      label: 'Test',
      cron: '0 0 * * *',
      run: async () => { throw new Error('should be swallowed'); },
    };

    await expect(executeJob(def)).resolves.toBeUndefined();
  });

  it('releases the running lock when recording the job start fails', async () => {
    // Regression: the lock used to be taken before this write, outside the
    // try/finally, so one transient DB failure here left the source locked
    // until the process restarted -- and rejected into a fire-and-forget caller.
    const run = vi.fn(async () => ({ fetched: 1 }));
    const def: JobDefinition = { source: 'test-source-start-fails', label: 'Test', cron: '0 0 * * *', run };

    const spy = vi.spyOn(prisma.collectionJob, 'create')
      .mockRejectedValueOnce(new Error('connection terminated'));

    await expect(executeJob(def)).resolves.toBeUndefined();
    spy.mockRestore();

    expect(isJobRunning('test-source-start-fails')).toBe(false);
    // The run is skipped rather than performed untracked.
    expect(run).not.toHaveBeenCalled();

    // A later run of the same source is not blocked by the failed one.
    await executeJob(def);
    expect(run).toHaveBeenCalledTimes(1);
    expect(isJobRunning('test-source-start-fails')).toBe(false);
  });

  it('does not propagate a failure to record the outcome', async () => {
    // The DB being unreachable is frequently why a job failed in the first
    // place; the bookkeeping write failing on top of that must not escape.
    const def: JobDefinition = {
      source: 'test-source-outcome-fails',
      label: 'Test',
      cron: '0 0 * * *',
      run: async () => ({ fetched: 1 }),
    };

    const spy = vi.spyOn(prisma.collectionJob, 'update')
      .mockRejectedValueOnce(new Error('connection terminated'));

    await expect(executeJob(def)).resolves.toBeUndefined();
    spy.mockRestore();

    expect(isJobRunning('test-source-outcome-fails')).toBe(false);
  });
});

describe('reconcileOrphanedJobs', () => {
  beforeEach(async () => {
    await resetDb();
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  it('marks a stale running job as failed with completedAt set', async () => {
    const job = await prisma.collectionJob.create({
      data: { source: 'orphan-source', status: 'running', startedAt: new Date() },
    });

    const count = await reconcileOrphanedJobs();

    expect(count).toBe(1);
    const updated = await prisma.collectionJob.findUnique({ where: { id: job.id } });
    expect(updated?.status).toBe('failed');
    expect(updated?.completedAt).not.toBeNull();
    expect(updated?.errorMessage).toMatch(/orphaned/i);
  });

  it('leaves completed and failed jobs untouched', async () => {
    await prisma.collectionJob.create({
      data: { source: 'done-source', status: 'completed', startedAt: new Date(), completedAt: new Date() },
    });
    await prisma.collectionJob.create({
      data: { source: 'already-failed-source', status: 'failed', startedAt: new Date(), completedAt: new Date(), errorMessage: 'boom' },
    });

    const count = await reconcileOrphanedJobs();

    expect(count).toBe(0);
  });
});

describe('getDeltaCursor', () => {
  beforeEach(async () => {
    await resetDb();
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  it('returns the fallback time when no completed job exists for the source', async () => {
    const before = Date.now();
    const cursor = await getDeltaCursor('never-run-source', 60_000);
    const after = Date.now();

    expect(cursor.getTime()).toBeGreaterThanOrEqual(before - 60_000 - 1000);
    expect(cursor.getTime()).toBeLessThanOrEqual(after - 60_000 + 1000);
  });

  it('returns the completedAt of the most recent completed job', async () => {
    const older = new Date(Date.now() - 2 * 60 * 60 * 1000);
    const newer = new Date(Date.now() - 30 * 60 * 1000);

    await prisma.collectionJob.create({
      data: { source: 'delta-source', status: 'completed', startedAt: older, completedAt: older },
    });
    await prisma.collectionJob.create({
      data: { source: 'delta-source', status: 'completed', startedAt: newer, completedAt: newer },
    });
    // A running (incomplete) job must not be picked as the cursor.
    await prisma.collectionJob.create({
      data: { source: 'delta-source', status: 'running', startedAt: new Date() },
    });

    const cursor = await getDeltaCursor('delta-source', 60_000);
    expect(cursor.getTime()).toBe(newer.getTime());
  });
});
