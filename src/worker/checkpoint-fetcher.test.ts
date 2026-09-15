import { describe, it, expect } from 'vitest';
import { parseVersionLine, parseAffected, buildCheckpointAffectedProducts } from './checkpoint-fetcher.js';

// Every fixture below is a shape taken from the live getAllActive feed
// (https://iapi-services-ucs.checkpoint.com/public/api/support-center-mms/api/securityAdvisories/getAllActive).

describe('parseVersionLine', () => {
  it('extracts a plain release-line floor', () => {
    expect(parseVersionLine('R81.20')).toBe('81.20');
  });

  it('pads a bare-major line to two components (so a later take number lands in the patch slot, not the minor slot)', () => {
    // Real data: sk1000118 lists both "R82" and "R82.10" for the same product in
    // the same advisory -- a bare "82" floor would let R82's own take number
    // collide with R82.10's minor once a take number is appended.
    expect(parseVersionLine('R82')).toBe('82.0');
  });

  it('extracts the floor from a whole dot-line ("X" is a literal placeholder)', () => {
    expect(parseVersionLine('R81.10.X')).toBe('81.10');
    expect(parseVersionLine('R82.00.X')).toBe('82.00');
  });

  it('strips the end-of-support annotation, padding a bare major the same way', () => {
    expect(parseVersionLine('R80 (EOS)')).toBe('80.0');
    expect(parseVersionLine('R81.10 (EOS)')).toBe('81.10');
  });

  it('returns undefined for non-release-line categories', () => {
    for (const v of ['Hardware', 'Other', 'Cloud']) {
      expect(parseVersionLine(v), v).toBeUndefined();
    }
  });

  it('returns undefined for the Harmony Endpoint client scheme (a different major-number axis)', () => {
    expect(parseVersionLine('E86.x')).toBeUndefined();
    expect(parseVersionLine('E89.x')).toBeUndefined();
  });
});

describe('parseAffected', () => {
  it('reads "None" as an explicit not-affected declaration', () => {
    // Real data: the same advisory (168) lists Multi-Domain Security
    // Management R82 as "None" while R81.10/R81.20 carry real take numbers --
    // this must never become a row, or an explicit negative becomes a false positive.
    expect(parseAffected('None', '82')).toEqual({ kind: 'not-affected' });
  });

  it('reads the "not this product\'s CVE" disclaimer as not-affected', () => {
    expect(parseAffected("Not Check Point's product CVE. See SK for details", '81.20'))
      .toEqual({ kind: 'not-affected' });
  });

  it('bounds "All" to the top of this release line\'s own take-number range', () => {
    // Confirmed live: an unbounded floor here previously let sk1000118's "R81
    // (EOS)"/All match a probe version belonging to the same advisory's
    // separately-listed "R82.10" line, and even a nonexistent future line.
    expect(parseAffected('All', '80.0')).toEqual({ kind: 'range', lastAffected: '80.0.999' });
  });

  it('gives "Details in SK" the same floor-bounded treatment as "All"', () => {
    // Deliberate, not the conservative default -- see parseAffected()'s doc
    // comment: every real advisory using this phrase has a normal release-line
    // version, and several (an OpenSSH sshd race condition, a RADIUS MD5
    // collision) are current mainstream issues, not just legacy Wi-Fi advisories.
    expect(parseAffected('Details in SK', '81.20')).toEqual({ kind: 'range', lastAffected: '81.20.999' });
  });

  it('reads "Prior to JHF Take N" as an exclusive upper bound', () => {
    // The single most common real value (149 occurrences).
    expect(parseAffected('Prior to JHF Take 22', '81.10')).toEqual({
      kind: 'range', versionEnd: '81.10.22',
    });
  });

  it('reads "Below take N" as an exclusive upper bound', () => {
    expect(parseAffected('Below take 40', '81.20')).toEqual({
      kind: 'range', versionEnd: '81.20.40',
    });
  });

  it('reads "Take N or below" as an inclusive upper bound', () => {
    expect(parseAffected('Take 36 or below', '81.20')).toEqual({
      kind: 'range', lastAffected: '81.20.36',
    });
  });

  it('leaves a bare number unparseable', () => {
    // Real sk1000117 data: the documented fix is "take 24", but `affected`
    // carries 10/17/44/126/166 for other release lines on the same CVE --
    // a bare number's relationship to the fix boundary isn't a simple ceiling.
    expect(parseAffected('17', '81.10')).toEqual({ kind: 'unparseable' });
    expect(parseAffected('166', '81.20')).toEqual({ kind: 'unparseable' });
  });
});

describe('buildCheckpointAffectedProducts', () => {
  // Real products[] for advisory 191 / CVE-2026-85102 / sk1000117.
  const sk1000117Products = [
    { name: 'Security Gateway', version: 'R80 (EOS)', affected: 'All' },
    { name: 'Security Gateway', version: 'R80.10 (EOS)', affected: 'All' },
    { name: 'Security Gateway', version: 'R80.20 (EOS)', affected: 'All' },
    { name: 'Security Gateway', version: 'R80.30 (EOS)', affected: 'All' },
    { name: 'Security Gateway', version: 'R80.40 (EOS)', affected: 'All' },
    { name: 'Security Gateway', version: 'R81 (EOS)', affected: 'All' },
    { name: 'Security Gateway', version: 'R81.10 (EOS)', affected: 'All' },
    { name: 'Security Gateway', version: 'R81.10.X', affected: '17' },
    { name: 'Security Gateway', version: 'R81.20', affected: '166' },
    { name: 'Security Gateway', version: 'R82', affected: '126' },
    { name: 'Security Gateway', version: 'R82.00.X', affected: '10' },
    { name: 'Security Gateway', version: 'R82.10', affected: '44' },
  ];

  it('keeps only the 7 "All" rows out of 12, dropping the 5 bare-number rows, each bounded to its own line', () => {
    const rows = buildCheckpointAffectedProducts(sk1000117Products);
    expect(rows).toHaveLength(7);
    expect(rows.every(r => r.vendor === 'checkpoint' && r.product === 'Security Gateway')).toBe(true);
    expect(rows.every(r => r.versionEnd === undefined)).toBe(true);
    expect(rows.map(r => r.versionStart)).toEqual(['80.0', '80.10', '80.20', '80.30', '80.40', '81.0', '81.10']);
    expect(rows.map(r => r.lastAffected)).toEqual(['80.0.999', '80.10.999', '80.20.999', '80.30.999', '80.40.999', '81.0.999', '81.10.999']);
  });

  it('drops a "None" row while keeping the rest of the same advisory (real data: advisory 168)', () => {
    const rows = buildCheckpointAffectedProducts([
      { name: 'Multi-Domain Security Management', version: 'R81.10', affected: 'Prior to JHF Take 158' },
      { name: 'Multi-Domain Security Management', version: 'R81.20', affected: 'Prior to JHF Take 79' },
      { name: 'Multi-Domain Security Management', version: 'R82', affected: 'None' },
    ]);
    expect(rows).toHaveLength(2);
    expect(rows.map(r => r.versionStart)).toEqual(['81.10', '81.20']);
    expect(rows.map(r => r.versionEnd)).toEqual(['81.10.158', '81.20.79']);
  });

  it('bounds a bare-major take number to the patch slot, not the minor slot (real data: sk1000118 lists both "R82" and "R82.10")', () => {
    const rows = buildCheckpointAffectedProducts([
      { name: 'Security Gateway', version: 'R82', affected: 'Prior to JHF Take 103' },
      { name: 'Security Gateway', version: 'R82.10', affected: '44' },
    ]);
    // R82.10's own row is dropped (bare number, unparseable) -- but the point of
    // this test is that R82's bound doesn't reach into R82.10's numeric space.
    expect(rows).toHaveLength(1);
    expect(rows[0].versionStart).toBe('82.0');
    expect(rows[0].versionEnd).toBe('82.0.103');
  });

  it('skips a row with a missing name/version/affected instead of throwing', () => {
    expect(buildCheckpointAffectedProducts([{ name: 'Security Gateway', version: 'R81.20' }])).toEqual([]);
    expect(buildCheckpointAffectedProducts([{ version: 'R81.20', affected: 'All' }])).toEqual([]);
  });

  it('returns nothing for a product list with only Hardware/Endpoint-scheme rows', () => {
    const rows = buildCheckpointAffectedProducts([
      { name: 'CloudGuard Network for Azure', version: 'Hardware', affected: 'Details in SK' },
      { name: 'Harmony Endpoint', version: 'E86.x', affected: 'Prior to E87.10' },
    ]);
    expect(rows).toEqual([]);
  });
});
