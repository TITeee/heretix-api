/**
 * Caps how many requests of one kind run at once.
 *
 * A batch search keeps Node's single JS thread busy for seconds (a 300-package
 * batch measured about 5 s of CPU, and a single search issued while two batches ran
 * took 1.4 s instead of 2 ms), so concurrent batches do not add throughput, they
 * add latency for every other request. A request over the cap is refused at once
 * instead of queued: a queue would hold its connection and its parsed body for the
 * whole wait.
 */
export interface ConcurrencyGate {
  /** A release function, or null when the cap is reached. Call release exactly once. */
  tryAcquire(): (() => void) | null;
  readonly active: number;
}

/** `max` of 0 or less means no cap. */
export function createConcurrencyGate(max: number): ConcurrencyGate {
  let active = 0;
  return {
    tryAcquire() {
      if (max > 0 && active >= max) return null;
      active++;
      let released = false;
      return () => {
        if (released) return;
        released = true;
        active--;
      };
    },
    get active() {
      return active;
    },
  };
}

/** A non-negative integer from the environment, or the default when unset or not one. */
export function envInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === '') return fallback;
  const n = Number(raw);
  return Number.isInteger(n) && n >= 0 ? n : fallback;
}
