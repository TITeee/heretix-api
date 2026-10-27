/**
 * A cache of expensive-to-build values, held under a total size budget.
 *
 * It caches the in-flight build as well as the finished value: on a cold cache
 * (right after a restart) 20 concurrent requests for the same key would otherwise
 * each start their own build. Callers of one key wait for the one build.
 *
 * Eviction is synchronous and never waits for anything. A build in flight holds no
 * size yet, so it is left alone; only finished entries are dropped to make room.
 * Waiting on another build from inside a build made two builds wait for each
 * other forever (each evicted the other and awaited it), which held every batch
 * search slot and turned all later batches into 429.
 */
export interface IndexCache<V> {
  /** The value for `key`, built with `load` when it is missing, expired or being built. */
  get(key: string, load: () => Promise<V>): Promise<V>;
  /** Total size of the finished entries held. */
  readonly size: number;
}

export interface IndexCacheOptions<V> {
  /** Size of a finished value, in whatever unit `maxSize` is in (rows). */
  sizeOf(value: V): number;
  maxSize: number;
  ttlMs: number;
  now?: () => number;
}

interface Slot<V> {
  promise: Promise<V>;
  /** Infinity while the build runs; it is the finished entry's expiry afterwards. */
  expiresAt: number;
  /** Set once the finished entry is counted against the budget. */
  size: number | undefined;
}

export function createIndexCache<V>(opts: IndexCacheOptions<V>): IndexCache<V> {
  const now = opts.now ?? Date.now;
  const slots = new Map<string, Slot<V>>();
  let total = 0;

  // Removes the slot from the cache (if it is still the one cached for the key)
  // and gives back the size it was counted for.
  function drop(key: string, slot: Slot<V>): void {
    if (slots.get(key) === slot) slots.delete(key);
    if (slot.size !== undefined) {
      total -= slot.size;
      slot.size = undefined;
    }
  }

  function register(key: string, slot: Slot<V>, value: V): void {
    const size = opts.sizeOf(value);
    // Deleting from a Map while iterating it is safe.
    for (const [k, other] of slots) {
      if (total + size <= opts.maxSize) break;
      if (other === slot || other.size === undefined) continue; // still being built: holds nothing to free
      drop(k, other);
    }
    slot.size = size;
    slot.expiresAt = now() + opts.ttlMs;
    total += size;
  }

  function start(key: string, load: () => Promise<V>): Slot<V> {
    const slot: Slot<V> = { promise: undefined as unknown as Promise<V>, expiresAt: Infinity, size: undefined };
    slot.promise = load().then(
      (value) => {
        if (slots.get(key) === slot) register(key, slot, value);
        return value;
      },
      (err) => {
        drop(key, slot);
        throw err;
      },
    );
    slots.set(key, slot);
    return slot;
  }

  return {
    async get(key, load) {
      for (;;) {
        let slot = slots.get(key);
        const built = slot === undefined;
        if (!slot) slot = start(key, load);
        const value = await slot.promise;
        // What this call built itself is returned even when the ttl is so short it
        // has already run out; otherwise the loop would never end.
        if (built || slot.expiresAt > now()) return value;
        // Expired: drop it unless a concurrent caller already replaced it, then take
        // that replacement or build a new one.
        drop(key, slot);
      }
    },
    get size() {
      return total;
    },
  };
}
