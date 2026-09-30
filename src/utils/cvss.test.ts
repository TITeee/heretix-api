import { describe, it, expect } from 'vitest';
import { cvssBaseScore, cvssFromOsvSeverity } from './cvss.js';

describe('cvssBaseScore', () => {
  it.each([
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N', 5.4],
    ['CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N', 6.4],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N', 0],
    ['CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N', 9.3],
  ])('%s -> %d', (vector, score) => {
    expect(cvssBaseScore(vector)).toEqual({ score, vector });
  });

  it.each([
    'garbage',
    'CVSS:3.1/AV:X/garbage',
    // CVSS 2.0 is deliberately not scored (see the function's doc comment).
    'AV:N/AC:L/Au:N/C:P/I:P/A:P',
  ])('returns null for %s', vector => {
    expect(cvssBaseScore(vector)).toBeNull();
  });
});

describe('cvssFromOsvSeverity', () => {
  const v3 = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N';
  const v4 = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N';

  it('prefers CVSS_V3 over CVSS_V4, like the NVD importer', () => {
    expect(cvssFromOsvSeverity([{ type: 'CVSS_V4', score: v4 }, { type: 'CVSS_V3', score: v3 }]))
      .toEqual({ score: 5.4, vector: v3 });
  });

  it('falls back to CVSS_V4 when there is no usable CVSS_V3 vector', () => {
    expect(cvssFromOsvSeverity([{ type: 'CVSS_V3', score: 'broken' }, { type: 'CVSS_V4', score: v4 }]))
      .toEqual({ score: 9.3, vector: v4 });
  });

  it('ignores non-CVSS entries such as Ubuntu priorities', () => {
    expect(cvssFromOsvSeverity([{ type: 'Ubuntu', score: 'medium' }])).toBeNull();
    expect(cvssFromOsvSeverity(undefined)).toBeNull();
  });
});
