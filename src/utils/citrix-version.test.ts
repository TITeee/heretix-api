import { describe, it, expect } from 'vitest';
import { citrixBranch, citrixVersionToInt, compareCitrixVersions, nextCitrixBranch, parseCitrixVersion } from './citrix-version.js';
import { CITRIX_VENDOR, encodeAdvisoryVersion } from './advisory-version.js';
import { normalizeVersion } from './version.js';

describe('parseCitrixVersion', () => {
  it('reads a branch and its build', () => {
    expect(parseCitrixVersion('14.1-73.32')?.parts).toEqual([14, 1, 73, 32]);
    expect(parseCitrixVersion('12.1-55.328')?.parts).toEqual([12, 1, 55, 328]);
    expect(parseCitrixVersion('13.0-92.19')?.parts).toEqual([13, 0, 92, 19]);
  });

  it('reads a branch on its own as the start of its builds', () => {
    expect(parseCitrixVersion('14.1')?.parts).toEqual([14, 1, 0, 0]);
  });

  it('ignores the FIPS / NDcPP label and reads the older "build" wording', () => {
    expect(parseCitrixVersion('13.1-37.235-FIPS')?.parts).toEqual([13, 1, 37, 235]);
    expect(parseCitrixVersion('13.1-37.235-FIPS and NDcPP')?.parts).toEqual([13, 1, 37, 235]);
    expect(parseCitrixVersion('13.0 build 58.30')?.parts).toEqual([13, 0, 58, 30]);
  });

  it('returns null for what it cannot place', () => {
    // A bare "X.Y" is a branch, so it is accepted ("14.1"); the order is only ever applied to NetScaler rows.
    for (const v of ['', 'ADC', '14', '14.1-73', '14.1-73.32.1', '14.1-abc', '10.2.2.2-92sv', '22.7R2.5']) {
      expect(parseCitrixVersion(v), v).toBeNull();
    }
  });
});

describe('citrixVersionToInt', () => {
  const ordered = (...versions: string[]) => {
    const ints = versions.map(v => citrixVersionToInt(v) as bigint);
    for (let i = 1; i < ints.length; i++) expect(ints[i - 1], `${versions[i - 1]} < ${versions[i]}`).toBeLessThan(ints[i]);
  };

  it('tells apart builds that normalizeVersion() makes equal (14.1-73.32 against 14.1-73.99)', () => {
    expect(normalizeVersion('14.1-73.32')).toBe(normalizeVersion('14.1-73.99'));
    ordered('14.1-73.32', '14.1-73.99');
  });

  it('orders builds within a branch and branches against each other', () => {
    ordered('14.1-8.50', '14.1-43.56', '14.1-56.72', '14.1-56.73', '14.1-60.52', '14.1-73.32');
    ordered('12.1-55.300', '12.1-55.328', '13.0-92.19', '13.1-37.235', '13.1-63.21', '14.1', '14.1-0.1', '14.1-8.50');
  });

  it('puts a branch before all of its builds, and the next branch after them', () => {
    ordered('14.1', '14.1-8.50', '14.1-73.32', '14.2');
  });

  it('is what a search encodes both sides with for NetScaler rows, and only for them', () => {
    expect(encodeAdvisoryVersion(CITRIX_VENDOR, '14.1-56.73')).toBe(citrixVersionToInt('14.1-56.73'));
    expect(encodeAdvisoryVersion('fortinet', '14.1-56.73')).toBe(normalizeVersion('14.1-56.73'));
  });
});

describe('compareCitrixVersions / branch helpers', () => {
  it('compares, and names a branch and the one after it', () => {
    const a = parseCitrixVersion('13.1-37.235')!;
    const b = parseCitrixVersion('13.1-63.21')!;
    expect(compareCitrixVersions(a, b)).toBeLessThan(0);
    expect(citrixBranch(a)).toBe('13.1');
    expect(nextCitrixBranch(parseCitrixVersion('12.1')!)).toBe('12.2');
  });
});
