import { describe, it, expect } from 'vitest';
import { normalizeSeverity, severityFromCvssScore } from './severity.js';

describe('normalizeSeverity', () => {
  it.each([
    ['MODERATE', 'MEDIUM'],
    ['moderate', 'MEDIUM'],
    ['CRITICAL', 'CRITICAL'],
    ['High', 'HIGH'],
    ['LOW', 'LOW'],
    ['NONE', 'NONE'],
    ['INFORMATIONAL', 'INFORMATIONAL'],
  ])('%s -> %s', (raw, expected) => {
    expect(normalizeSeverity(raw)).toBe(expected);
  });

  it.each(['CVSS_V3', 'CVSS_V4', 'Ubuntu', '', 'unknown'])('rejects %j, which is not a rating', raw => {
    expect(normalizeSeverity(raw)).toBeNull();
  });

  it('rejects non-strings', () => {
    expect(normalizeSeverity(undefined)).toBeNull();
    expect(normalizeSeverity(7.5)).toBeNull();
  });
});

describe('severityFromCvssScore', () => {
  it.each([
    [10, 'CRITICAL'], [9.0, 'CRITICAL'], [8.9, 'HIGH'], [7.0, 'HIGH'],
    [6.9, 'MEDIUM'], [4.0, 'MEDIUM'], [3.9, 'LOW'], [0.1, 'LOW'], [0, 'NONE'],
  ])('%d -> %s', (score, expected) => {
    expect(severityFromCvssScore(score)).toBe(expected);
  });
});
