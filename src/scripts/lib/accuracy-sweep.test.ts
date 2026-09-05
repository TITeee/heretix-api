import { describe, it, expect } from 'vitest';
import { indexByProduct, expectedCVEsRpm, dedupeSiblingProducts, type RpmFixEntry } from './accuracy-sweep.js';

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

describe('dedupeSiblingProducts', () => {
  it('collapses products with an identical fix history to the alphabetically-first name', () => {
    const sharedHistory: RpmFixEntry[] = [
      { cveId: 'CVE-2024-1', versionStart: null, versionEnd: '5.14.0-500.el9' },
      { cveId: 'CVE-2024-2', versionStart: '5.14.0-400.el9', versionEnd: '5.14.0-450.el9' },
    ];
    const index = new Map<string, RpmFixEntry[]>([
      ['kernel-rt-devel', sharedHistory],
      ['kernel-rt', sharedHistory],
      ['kernel-rt-core', sharedHistory],
    ]);

    const deduped = dedupeSiblingProducts(index);

    expect(deduped.size).toBe(1);
    expect(deduped.has('kernel-rt')).toBe(true);
    expect(deduped.get('kernel-rt')).toEqual(sharedHistory);
  });

  it('keeps products with genuinely different fix histories separate', () => {
    const index = new Map<string, RpmFixEntry[]>([
      ['kernel', [{ cveId: 'CVE-2024-1', versionStart: null, versionEnd: '5.14.0-500.el9' }]],
      ['nodejs', [{ cveId: 'CVE-2024-2', versionStart: null, versionEnd: '20.8.1-1.el9' }]],
    ]);

    const deduped = dedupeSiblingProducts(index);

    expect(deduped.size).toBe(2);
    expect(deduped.has('kernel')).toBe(true);
    expect(deduped.has('nodejs')).toBe(true);
  });

  it('treats entry order within a product as insignificant', () => {
    const index = new Map<string, RpmFixEntry[]>([
      ['a-package', [
        { cveId: 'CVE-2024-1', versionStart: null, versionEnd: '1.0' },
        { cveId: 'CVE-2024-2', versionStart: null, versionEnd: '2.0' },
      ]],
      ['b-package', [
        { cveId: 'CVE-2024-2', versionStart: null, versionEnd: '2.0' },
        { cveId: 'CVE-2024-1', versionStart: null, versionEnd: '1.0' },
      ]],
    ]);

    const deduped = dedupeSiblingProducts(index);

    expect(deduped.size).toBe(1);
    expect(deduped.has('a-package')).toBe(true);
  });
});
