import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import cron from 'node-cron';
import { enqueue, startScheduler, stopScheduler } from './scheduler.js';
import * as runnerModule from './jobs/runner.js';
import type { JobDefinition } from './jobs/types.js';

describe('stopScheduler', () => {
  afterEach(async () => {
    await stopScheduler();
  });

  it('stops every task startScheduler registered', async () => {
    const before = cron.getTasks().size;
    startScheduler();
    const registered = cron.getTasks().size;
    expect(registered).toBeGreaterThan(before);

    await stopScheduler();

    // node-cron keeps stopped tasks in its registry, so assert on their state
    // rather than the registry size. Nothing left running is what lets the
    // process exit on its own during shutdown instead of hitting the timeout.
    const statuses = await Promise.all([...cron.getTasks().values()].map(t => t.getStatus()));
    expect(statuses.every(s => s !== 'running' && s !== 'idle')).toBe(true);
  });

  it('is safe to call twice', async () => {
    startScheduler();
    await stopScheduler();
    await expect(stopScheduler()).resolves.toBeUndefined();
  });
});

describe('enqueue', () => {
  const request = vi.fn().mockResolvedValue('started');

  beforeEach(() => {
    request.mockClear();
    vi.spyOn(runnerModule, 'getJobRunner').mockReturnValue({ request } as never);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  const job = (isLoaded?: () => Promise<boolean>): JobDefinition => ({
    source: 'x', label: 'x', cron: '', run: async () => ({}), ...(isLoaded ? { firstLoad: { isLoaded } } : {}),
  });

  it('skips a source that was never loaded: its first load is a person\'s call', async () => {
    await enqueue(job(async () => false));
    expect(request).not.toHaveBeenCalled();
  });

  it('runs a loaded source, and one with no first load', async () => {
    await enqueue(job(async () => true));
    await enqueue(job());
    expect(request).toHaveBeenCalledTimes(2);
  });
});
