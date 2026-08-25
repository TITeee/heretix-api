import { describe, it, expect } from 'vitest';
import { computeExactVersion } from './nvd-helpers.js';

describe('computeExactVersion', () => {
  it('returns null for a genuine CPE wildcard (no point version at all)', () => {
    // parseCPE() already resolves "*"/"-" to null before this is ever called.
    expect(computeExactVersion(null)).toBeNull();
  });

  it('returns null when the point version normalizes fine', () => {
    expect(computeExactVersion('1.2.3')).toBeNull();
  });

  it('returns the raw string for a real version normalizeVersion() cannot encode (Huawei V/R/C/SPC scheme)', () => {
    expect(computeExactVersion('v200r007c00spcb00')).toBe('v200r007c00spcb00');
  });

  it('returns the raw string for a Jenkins plugin build id', () => {
    expect(computeExactVersion('1365.v4778ca_84b_de5')).toBe('1365.v4778ca_84b_de5');
  });
});
