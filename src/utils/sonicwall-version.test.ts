import { describe, it, expect } from 'vitest';
import { parseSonicWallVersion, sonicWallVersionToInt } from './sonicwall-version.js';
import { encodeAdvisoryVersion, SONICWALL_VENDOR } from './advisory-version.js';
import { normalizeVersion } from './version.js';

describe('parseSonicWallVersion', () => {
  it('reads a release and the numbers of its build', () => {
    expect(parseSonicWallVersion('7.0.1-5161')).toEqual({ release: [7, 0, 1], build: [5161] });
    expect(parseSonicWallVersion('7.0.1-R1456')).toEqual({ release: [7, 0, 1], build: [1456] });
    expect(parseSonicWallVersion('6.5.4.15-117n')).toEqual({ release: [6, 5, 4, 15], build: [117] });
    expect(parseSonicWallVersion('6.5.4.4-44v-21-2457')).toEqual({ release: [6, 5, 4, 4], build: [44, 21, 2457] });
    expect(parseSonicWallVersion('12.4.3-03245')).toEqual({ release: [12, 4, 3], build: [3245] });
    expect(parseSonicWallVersion('10.2.1.13')).toEqual({ release: [10, 2, 1, 13], build: [] });
  });

  it('returns null for what it cannot place', () => {
    for (const v of ['', 'SonicOS', '7.0.1 5161', '7.0.1-', '7.0.1_5161']) {
      expect(parseSonicWallVersion(v), v).toBeNull();
    }
  });
});

describe('sonicWallVersionToInt', () => {
  const ordered = (...versions: string[]) => {
    const ints = versions.map(v => sonicWallVersionToInt(v) as bigint);
    for (let i = 1; i < ints.length; i++) expect(ints[i - 1], `${versions[i - 1]} < ${versions[i]}`).toBeLessThan(ints[i]);
  };

  it('tells apart builds that normalizeVersion() makes equal (7.0.1-5161 against 7.0.1-5165)', () => {
    expect(normalizeVersion('7.0.1-5161')).toBe(normalizeVersion('7.0.1-5165'));
    ordered('7.0.1-5161', '7.0.1-5165');
    expect(normalizeVersion('12.4.3-03245')).toBe(normalizeVersion('12.4.3-03387'));
    ordered('12.4.3-03245', '12.4.3-03387');
  });

  it('orders builds within a release, and releases against each other', () => {
    ordered('7.0.0', '7.0.1', '7.0.1-R1262', '7.0.1-R1456', '7.0.1-5151', '7.0.1-5161', '7.1.1-7051', '7.1.2-7019');
    ordered('6.5.4.4-44v-21-2457', '6.5.4.4-44v-21-2472', '6.5.4.15-117n', '6.5.5.1-6n');
    ordered('6.5.1.12', '6.5.1.12-3n', '6.5.1.13-1n');
  });

  it('orders the other products\' shapes: a long third or fourth number, a two-part build', () => {
    ordered('2.5.2518', '2.5.2519');
    ordered('10.0.33.8195', '10.0.34.8223', '10.0.35.8405');
    ordered('10.2.336', '10.2.337', '10.2.341');
    ordered('7.0.1-5030-R2007', '7.0.1-5051-R2624');
    ordered('4.9.0', '4.10.4.0314', '4.10.5.1021', '5.0.0');
  });

  it('returns null where a slot would overflow', () => {
    expect(sonicWallVersionToInt('47.0.0')).toBeNull();
    expect(sonicWallVersionToInt('7.20.0')).toBeNull();
    expect(sonicWallVersionToInt('9.0.1.19899')).toBeNull();
    expect(sonicWallVersionToInt('7.0.1-12345')).toBeNull();
    expect(sonicWallVersionToInt('7.0.1-1-2-3-4')).toBeNull();
  });

  it('is what a search encodes both sides with for SonicWall rows, and only for them', () => {
    expect(encodeAdvisoryVersion(SONICWALL_VENDOR, '7.0.1-5161')).toBe(sonicWallVersionToInt('7.0.1-5161'));
    expect(encodeAdvisoryVersion('fortinet', '7.0.1-5161')).toBe(normalizeVersion('7.0.1-5161'));
  });
});
