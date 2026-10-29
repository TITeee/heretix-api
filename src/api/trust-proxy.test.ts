import { describe, it, expect } from 'vitest';
import { trustProxyFromEnv } from './trust-proxy.js';

describe('trustProxyFromEnv', () => {
  it('trusts no proxy when unset, so a client cannot pick its address with X-Forwarded-For', () => {
    expect(trustProxyFromEnv(undefined)).toBe(false);
    expect(trustProxyFromEnv('')).toBe(false);
    expect(trustProxyFromEnv('false')).toBe(false);
  });

  it('reads true, or a list of proxy addresses', () => {
    expect(trustProxyFromEnv('true')).toBe(true);
    expect(trustProxyFromEnv('10.0.0.5')).toEqual(['10.0.0.5']);
    expect(trustProxyFromEnv('10.0.0.5, 10.0.1.0/24')).toEqual(['10.0.0.5', '10.0.1.0/24']);
  });
});
