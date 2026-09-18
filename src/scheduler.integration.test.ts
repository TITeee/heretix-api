import { describe, it, expect, afterEach } from 'vitest';
import cron from 'node-cron';
import { startScheduler, stopScheduler } from './scheduler.js';

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
