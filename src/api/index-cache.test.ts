import { describe, it, expect } from 'vitest';
import { createIndexCache } from './index-cache.js';

// A load whose result the test resolves by hand, to line builds up the way
// concurrent requests do on a cold cache.
function deferred<V>() {
  let resolve!: (v: V) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<V>((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

const sizeOf = (v: number[]) => v.length;
const rows = (n: number) => Array.from({ length: n }, (_, i) => i);

describe('createIndexCache', () => {
  it('builds a key once for concurrent callers', async () => {
    const cache = createIndexCache<number[]>({ sizeOf, maxSize: 100, ttlMs: 1000 });
    let loads = 0;
    const load = async () => { loads++; return rows(3); };
    const [a, b] = await Promise.all([cache.get('k', load), cache.get('k', load)]);
    expect(loads).toBe(1);
    expect(a).toBe(b);
  });

  it('does not hang when builds over the budget finish in any order', async () => {
    // Each build, finishing, evicted the other still-running one and awaited it, so
    // two over-budget builds waited for each other forever.
    const cache = createIndexCache<number[]>({ sizeOf, maxSize: 10, ttlMs: 1000 });
    const a = deferred<number[]>();
    const b = deferred<number[]>();
    const c = deferred<number[]>();
    const all = Promise.all([
      cache.get('a', () => a.promise),
      cache.get('b', () => b.promise),
      cache.get('c', () => c.promise),
    ]);
    c.resolve(rows(8));
    a.resolve(rows(8));
    b.resolve(rows(8));
    await expect(all).resolves.toHaveLength(3);
  });

  it('keeps the total within the budget, evicting finished entries only', async () => {
    const cache = createIndexCache<number[]>({ sizeOf, maxSize: 10, ttlMs: 1000 });
    let loadsA = 0;
    await cache.get('a', async () => { loadsA++; return rows(6); });
    await cache.get('b', async () => rows(6)); // does not fit next to a: a goes
    expect(cache.size).toBe(6);
    await cache.get('a', async () => { loadsA++; return rows(6); });
    expect(loadsA).toBe(2);
    expect(cache.size).toBe(6);
  });

  it('leaves a build in flight alone when making room', async () => {
    const cache = createIndexCache<number[]>({ sizeOf, maxSize: 10, ttlMs: 1000 });
    const slow = deferred<number[]>();
    const slowResult = cache.get('slow', () => slow.promise);
    await cache.get('big', async () => rows(20));
    slow.resolve(rows(2));
    await slowResult;
    let loads = 0;
    await cache.get('slow', async () => { loads++; return rows(2); });
    expect(loads).toBe(0); // still cached, not evicted while it was building
  });

  it('rebuilds an expired entry without counting the old one twice', async () => {
    let t = 0;
    const cache = createIndexCache<number[]>({ sizeOf, maxSize: 100, ttlMs: 1000, now: () => t });
    await cache.get('k', async () => rows(5));
    t = 2000;
    await cache.get('k', async () => rows(5));
    expect(cache.size).toBe(5);
  });

  it('rebuilds an expired entry once for concurrent callers', async () => {
    let t = 0;
    const cache = createIndexCache<number[]>({ sizeOf, maxSize: 100, ttlMs: 1000, now: () => t });
    await cache.get('k', async () => rows(1));
    t = 2000;
    let loads = 0;
    const load = async () => { loads++; return rows(1); };
    await Promise.all([cache.get('k', load), cache.get('k', load), cache.get('k', load)]);
    expect(loads).toBe(1);
  });

  it('does not loop on a ttl of zero', async () => {
    const cache = createIndexCache<number[]>({ sizeOf, maxSize: 100, ttlMs: 0 });
    await expect(cache.get('k', async () => rows(1))).resolves.toHaveLength(1);
  });

  it('does not keep a failed build, so the next call tries again', async () => {
    const cache = createIndexCache<number[]>({ sizeOf, maxSize: 100, ttlMs: 1000 });
    await expect(cache.get('k', async () => { throw new Error('db down'); })).rejects.toThrow('db down');
    expect(cache.size).toBe(0);
    await expect(cache.get('k', async () => rows(2))).resolves.toHaveLength(2);
  });
});
