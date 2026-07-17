import { describe, it, expect } from 'vitest';
import { parseAffects } from './apache-fetcher.js';

describe('parseAffects', () => {
  it('parses "before X" with no lower bound', () => {
    expect(parseAffects('before 2.4.66')).toEqual({
      versionStart: undefined,
      versionEnd: '2.4.66',
    });
  });

  it('parses "X before Y" with explicit lower bound', () => {
    expect(parseAffects('2.4.0 before 2.4.66')).toEqual({
      versionStart: '2.4.0',
      versionEnd: '2.4.66',
    });
  });

  it('parses "through X" with no lower bound', () => {
    expect(parseAffects('through 2.4.67')).toEqual({
      versionStart: undefined,
      lastAffected: '2.4.67',
    });
  });

  it('parses "X through Y" with explicit lower bound', () => {
    expect(parseAffects('2.4.0 through 2.4.67')).toEqual({
      versionStart: '2.4.0',
      lastAffected: '2.4.67',
    });
  });

  it('parses ">=X, <=Y" inclusive range', () => {
    expect(parseAffects('>=2.4.7, <=2.4.51')).toEqual({
      versionStart: '2.4.7',
      lastAffected: '2.4.51',
    });
  });

  it('parses "<=X" with no lower bound', () => {
    expect(parseAffects('<=2.4.48')).toEqual({
      versionStart: undefined,
      lastAffected: '2.4.48',
    });
  });

  it('parses "<=X, !<Y" using !< as the inclusive lower bound', () => {
    expect(parseAffects('<=2.4.48, !<2.4.17')).toEqual({
      versionStart: '2.4.17',
      lastAffected: '2.4.48',
    });
  });

  it('parses a comma-separated exact version list, keeping only 2.4.x tokens', () => {
    expect(parseAffects('2.4.10, 2.4.9, 2.2.31, 2.0.65')).toEqual({
      affectedVersions: ['2.4.10', '2.4.9'],
    });
  });

  it('returns null when the comma list has no 2.4.x tokens', () => {
    expect(parseAffects('2.2.31, 2.0.65, 1.3.42')).toBeNull();
  });

  it('returns null for unparseable text', () => {
    expect(parseAffects('see vendor advisory')).toBeNull();
  });

  it('returns null for empty input', () => {
    expect(parseAffects('')).toBeNull();
  });
});
