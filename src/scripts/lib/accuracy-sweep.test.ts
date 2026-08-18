import { describe, it, expect } from 'vitest';
import { indexByProduct, expectedCVEsRpm } from './accuracy-sweep.js';

describe('expectedCVEsRpm', () => {
  it('does not expect a module-stream CVE to match a query below its versionStart', () => {
    // CVE-2026-6575 only affects postgresql:18 (versionStart="18.0"); postgresql 13.7
    // predates that stream entirely and must not be expected to match.
    const index = indexByProduct([
      {
        cveId: 'CVE-2026-6575',
        affectedProducts: [
          { product: 'postgresql', versionStart: '18.0', versionEnd: '18.4-2.module+el9.8.0' },
        ],
      },
    ]);

    expect(expectedCVEsRpm('postgresql', '13.7-1.el9_0', index)).toEqual(new Set());
    expect(expectedCVEsRpm('postgresql', '18.3-1.el9_8', index)).toEqual(new Set(['CVE-2026-6575']));
  });

  it('still expects a match with no versionStart at all (bare row, matches matchesRpmVersionRange)', () => {
    const index = indexByProduct([
      {
        cveId: 'CVE-2024-1234',
        affectedProducts: [{ product: 'nginx', versionEnd: '1.24.0-1.el9' }],
      },
    ]);

    expect(expectedCVEsRpm('nginx', '1.20.0-1.el9', index)).toEqual(new Set(['CVE-2024-1234']));
  });

  it('excludes a version at or past versionEnd (exclusive upper bound)', () => {
    const index = indexByProduct([
      {
        cveId: 'CVE-2024-5678',
        affectedProducts: [{ product: 'nodejs', versionStart: '20.0', versionEnd: '20.8.1-1.module+el9' }],
      },
    ]);

    expect(expectedCVEsRpm('nodejs', '20.8.1-1.module+el9', index)).toEqual(new Set());
    expect(expectedCVEsRpm('nodejs', '19.9.0-1.module+el9', index)).toEqual(new Set());
  });
});
