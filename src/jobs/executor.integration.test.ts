import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import { prisma } from '../db/client.js';
import { resetDb } from '../test-utils/db.js';
import { executeJob, getDeltaCursor } from './executor.js';
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
