import { describe, it, expect, afterEach } from 'vitest';
import { createConcurrencyGate, envInt } from './concurrency-gate.js';

describe('createConcurrencyGate', () => {
  it('lets max requests in and refuses the next one', () => {
    const gate = createConcurrencyGate(2);
    const a = gate.tryAcquire();
    const b = gate.tryAcquire();
    expect(a).not.toBeNull();
    expect(b).not.toBeNull();
    expect(gate.tryAcquire()).toBeNull();
    expect(gate.active).toBe(2);
  });

  it('lets another in once one is released', () => {
    const gate = createConcurrencyGate(1);
    const release = gate.tryAcquire()!;
    expect(gate.tryAcquire()).toBeNull();
    release();
    expect(gate.active).toBe(0);
    expect(gate.tryAcquire()).not.toBeNull();
  });

  it('counts a release once, however often it is called', () => {
    const gate = createConcurrencyGate(1);
    const release = gate.tryAcquire()!;
    release();
    release();
    expect(gate.active).toBe(0);
    const again = gate.tryAcquire();
    expect(again).not.toBeNull();
    expect(gate.tryAcquire()).toBeNull();
  });

  it('has no cap when max is 0', () => {
    const gate = createConcurrencyGate(0);
    for (let i = 0; i < 50; i++) expect(gate.tryAcquire()).not.toBeNull();
  });
});

describe('envInt', () => {
  afterEach(() => {
    delete process.env.TEST_ENV_INT;
  });

  it('reads a non-negative integer', () => {
    process.env.TEST_ENV_INT = '7';
    expect(envInt('TEST_ENV_INT', 3)).toBe(7);
    process.env.TEST_ENV_INT = '0';
    expect(envInt('TEST_ENV_INT', 3)).toBe(0);
  });

  it('falls back when unset, empty, negative or not an integer', () => {
    expect(envInt('TEST_ENV_INT', 3)).toBe(3);
    for (const v of ['', ' ', '-1', '2.5', 'abc']) {
      process.env.TEST_ENV_INT = v;
      expect(envInt('TEST_ENV_INT', 3), v).toBe(3);
    }
  });
});
