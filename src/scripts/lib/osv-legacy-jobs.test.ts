import { describe, it, expect } from 'vitest';
import { isLegacyOsvSource } from './osv-legacy-jobs.js';

describe('isLegacyOsvSource', () => {
  it('is true for a job named after one release of a distro', () => {
    for (const s of ['osv-Debian:12', 'osv-Ubuntu:22.04:LTS', 'osv-Alpine:v3.21', 'osv-AlmaLinux:9', 'osv-Red Hat:9']) {
      expect(isLegacyOsvSource(s), s).toBe(true);
    }
  });

  it('is false for a job named after a bucket, an ecosystem of its own, or a full load', () => {
    for (const s of ['osv-Debian', 'osv-Ubuntu', 'osv-npm', 'osv-PyPI', 'osv-mal', 'osv-full-Debian:12', 'osv-full-npm', 'nvd', 'advisory-fortinet']) {
      expect(isLegacyOsvSource(s), s).toBe(false);
    }
  });
});
