import { describe, it, expect } from 'vitest';
import { compareIvantiVersions, ivantiLine, ivantiVersionToInt, parseIvantiVersion } from './ivanti-version.js';
import { encodeAdvisoryVersion, IVANTI_VENDOR } from './advisory-version.js';
import { normalizeVersion } from './version.js';

describe('parseIvantiVersion', () => {
  it('reads each shape Ivanti publishes', () => {
    expect(parseIvantiVersion('12.7.0.1')?.parts).toEqual([12, 7, 0, 1]);
    expect(parseIvantiVersion('6.4.8.8008')?.parts).toEqual([6, 4, 8, 8008]);
    expect(parseIvantiVersion('22.7R2.5')?.parts).toEqual([22, 7, 2, 5]);
    expect(parseIvantiVersion('9.1R18.9')?.parts).toEqual([9, 1, 18, 9]);
    expect(parseIvantiVersion('22.8R1')?.parts).toEqual([22, 8, 1, 0]);
    expect(parseIvantiVersion('22.3r2')?.parts).toEqual([22, 3, 2, 0]);
    expect(parseIvantiVersion('R10.8.1')?.parts).toEqual([10, 8, 1, 0]);
    expect(parseIvantiVersion('5.0.5')?.parts).toEqual([5, 0, 5, 0]);
    expect(parseIvantiVersion('2026.2')?.parts).toEqual([2026, 2, 0, 0]);
  });

  it('reads Endpoint Manager service updates', () => {
    expect(parseIvantiVersion('2024 SU4')?.parts).toEqual([2024, 4, 0, 0]);
    expect(parseIvantiVersion('2024 SU4 SR1')?.parts).toEqual([2024, 4, 1, 0]);
    expect(parseIvantiVersion('2022 SU8 Security Update 1')?.parts).toEqual([2022, 8, 1, 0]);
    // A bare year is that year's first release.
    expect(parseIvantiVersion('2024')?.parts).toEqual([2024, 0, 0, 0]);
  });

  it('returns null for what cannot be ordered', () => {
    expect(parseIvantiVersion('2025.2 Sept 2026 Security Patch')).toBeNull();
    expect(parseIvantiVersion('mo2026.2')).toBeNull();
    expect(parseIvantiVersion('Download Portal')).toBeNull();
    expect(parseIvantiVersion('22.7R2.5.1')).toBeNull();
    expect(parseIvantiVersion('12')).toBeNull();
    expect(parseIvantiVersion('1.2.3.20240101')).toBeNull();
  });
});

describe('ivantiVersionToInt', () => {
  const ordered = (...versions: string[]) => {
    const ints = versions.map(v => ivantiVersionToInt(v) as bigint);
    for (let i = 1; i < ints.length; i++) expect(ints[i - 1], `${versions[i - 1]} < ${versions[i]}`).toBeLessThan(ints[i]);
  };

  it('tells apart versions that differ only in the 4th component (EPMM)', () => {
    // normalizeVersion() drops the 4th component, so 12.7.0.0 (affected) and
    // 12.7.0.1 (fixed) came out equal and the affected one read as fixed.
    expect(normalizeVersion('12.7.0.0')).toBe(normalizeVersion('12.7.0.1'));
    ordered('12.7.0.0', '12.7.0.1', '12.8.0.1');
  });

  it('orders Connect Secure releases and builds, including two-digit releases', () => {
    ordered('22.7R2.4', '22.7R2.5', '22.7R2.6', '22.8R1');
    // The old reading put 9.1R18 above 9.2R1 (minor 118 against 21).
    ordered('9.1R18.9', '9.2R1', '22.3R2', '22.3R3', '22.7R1.3');
  });

  it('orders Sentry, Avalanche, Xtraction and Endpoint Manager versions', () => {
    ordered('R10.6.4', 'R10.7.3', 'R10.8.1', 'R10.8.2');
    ordered('6.4.6', '6.4.8.8008', '6.5.0');
    ordered('2026.2', '2026.2.1', '2026.3');
    ordered('2022 SU8', '2022 SU8 SR1', '2024', '2024 SU1', '2024 SU3', '2024 SU4', '2024 SU4 SR1');
  });

  it('is what a search encodes both sides with for Ivanti rows, and only for them', () => {
    expect(encodeAdvisoryVersion(IVANTI_VENDOR, '12.7.0.1')).toBe(ivantiVersionToInt('12.7.0.1'));
    expect(encodeAdvisoryVersion('fortinet', '12.7.0.1')).toBe(normalizeVersion('12.7.0.1'));
  });
});

describe('compareIvantiVersions / ivantiLine', () => {
  it('compares and names the release line', () => {
    const a = parseIvantiVersion('22.7R2.5')!;
    const b = parseIvantiVersion('22.7R2.6')!;
    expect(compareIvantiVersions(a, b)).toBeLessThan(0);
    expect(ivantiLine(a)).toBe('22.7');
    expect(ivantiLine(parseIvantiVersion('R10.8.1')!)).toBe('10.8');
  });
});
