import { describe, it, expect } from 'vitest';
import { comparePanVersions, panVersionToInt, panVersionsBelow, parsePanVersion, type PanVersion } from './pan-version.js';
import { normalizeVersion } from './version.js';

const p = (s: string) => parsePanVersion(s) as PanVersion;

describe('parsePanVersion', () => {
  it.each([
    ['10.2.9', { major: 10, minor: 2, patch: 9, sub: 0 }],
    ['10.2.9-h13', { major: 10, minor: 2, patch: 9, sub: 13 }],
    ['6.2.6-c857', { major: 6, minor: 2, patch: 6, sub: 857 }],
    ['6.5.3-b15', { major: 6, minor: 5, patch: 3, sub: 15 }],
    ['6.2.7-1077', { major: 6, minor: 2, patch: 7, sub: 1077 }],
    ['6.3.3-h2 (6.3.3-c676)', { major: 6, minor: 3, patch: 3, sub: 2 }],
    ['6.2.8-h2 [6.2.8-c243]', { major: 6, minor: 2, patch: 8, sub: 2 }],
    ['8.7.101-CE', { major: 8, minor: 7, patch: 101, sub: 0 }],
    ['7.5-CE.0', { major: 7, minor: 5, patch: 0, sub: 0 }],
    ['135.16.8.96', { major: 135, minor: 16, patch: 8, sub: 96 }],
    ['2.1', { major: 2, minor: 1, patch: 0, sub: 0 }],
    ['6.1.1.', { major: 6, minor: 1, patch: 1, sub: 0 }],
  ])('parses %s', (input, expected) => {
    expect(parsePanVersion(input)).toEqual(expected);
  });

  it.each(['All', '5.1*', '8.3.101-CE HF', 'None', '', '10.2.9-beta', '1.2.3.4-h1'])('rejects %s', input => {
    expect(parsePanVersion(input)).toBeNull();
  });
});

describe('comparePanVersions', () => {
  it('orders a hotfix after its base release and before the next maintenance release', () => {
    const ordered = ['10.2.8', '10.2.9', '10.2.9-h1', '10.2.9-h3', '10.2.9-h13', '10.2.10', '10.2.10-h1', '11.0.0'];
    for (let i = 1; i < ordered.length; i++) {
      expect(comparePanVersions(p(ordered[i - 1]), p(ordered[i])), `${ordered[i - 1]} < ${ordered[i]}`).toBeLessThan(0);
    }
  });

  it('treats hotfixes of one release as distinct, unlike normalizeVersion()', () => {
    expect(comparePanVersions(p('10.2.9-h1'), p('10.2.9-h3'))).toBeLessThan(0);
    // The generic encoding reads "-h1" as a pre-release: below its base, and
    // equal to every other hotfix of that release.
    expect(normalizeVersion('10.2.9-h1')).toBeLessThan(normalizeVersion('10.2.9')!);
    expect(normalizeVersion('10.2.9-h1')).toBe(normalizeVersion('10.2.9-h3'));
  });
});

describe('panVersionToInt', () => {
  it('is monotonic in comparePanVersions() order', () => {
    const ordered = ['9.1.15', '10.2.0', '10.2.0-h3', '10.2.9', '10.2.9-h1', '10.2.9-h13', '10.2.10', '11.1.2-h3', '12.1.0'];
    const ints = ordered.map(v => panVersionToInt(v)!);
    for (let i = 1; i < ints.length; i++) expect(ints[i - 1]).toBeLessThan(ints[i]);
  });

  it('returns null for a version it cannot order', () => {
    expect(panVersionToInt('All')).toBeNull();
  });
});

describe('panVersionsBelow', () => {
  it.each([
    ['10.2.9-h13', ['10.2.9-h12', '10.2.9']],
    ['10.2.9-h1', ['10.2.9']],
    ['11.2.3', ['11.2.2']],
    ['11.2.0', []],
  ])('%s -> %j', (input, expected) => {
    expect(panVersionsBelow(input)).toEqual(expected);
  });
});
