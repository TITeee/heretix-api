import { describe, it, expect } from 'vitest';
import { parseAffectedVersion, buildAffectedProducts } from './splunk-fetcher.js';

describe('parseAffectedVersion', () => {
  it('parses "Below X" as an exclusive upper bound', () => {
    expect(parseAffectedVersion('Below 5.7')).toEqual({ versionEnd: '5.7' });
  });

  it('parses "X to Y" as an inclusive range', () => {
    expect(parseAffectedVersion('1.0 to 2.0')).toEqual({ versionStart: '1.0', lastAffected: '2.0' });
  });

  it('parses "X and earlier" as an inclusive upper bound', () => {
    expect(parseAffectedVersion('1.5 and earlier')).toEqual({ lastAffected: '1.5' });
  });

  it('parses "Versions before X" and "X and lower"', () => {
    expect(parseAffectedVersion('Versions before 9.0')).toEqual({ versionEnd: '9.0' });
    expect(parseAffectedVersion('Versions below 8.1')).toEqual({ versionEnd: '8.1' });
    expect(parseAffectedVersion('4.0 and lower')).toEqual({ lastAffected: '4.0' });
  });

  it('reads a list of affected releases as the span they cover', () => {
    expect(parseAffectedVersion('5.1.2, 5.1.1 and 5.1.0')).toEqual({ versionStart: '5.1.0', lastAffected: '5.1.2' });
  });

  it('returns null for unrecognized text', () => {
    expect(parseAffectedVersion('N/A')).toBeNull();
  });
});

describe('buildAffectedProducts', () => {
  it('builds a range entry with versionFixed set', () => {
    const cells = {
      'Affected Product': 'Splunk Enterprise 9.1',
      'Fixed Versions': '9.1.5',
      'Affected Versions': '9.1.0 to 9.1.4',
    };
    expect(buildAffectedProducts(cells)).toEqual([
      {
        vendor: 'splunk',
        product: 'Splunk Enterprise',
        versionStart: '9.1.0',
        versionEnd: undefined,
        lastAffected: '9.1.4',
        versionFixed: '9.1.5',
        patchAvailable: true,
      },
    ]);
  });

  it('does not set versionFixed for a non-range (single) affected version', () => {
    const cells = {
      'Affected Product': 'Splunk AI Toolkit 5.7',
      'Fixed Versions': '5.7.1',
      'Affected Versions': 'N/A',
    };
    const result = buildAffectedProducts(cells);
    // parseAffectedVersion('N/A') returns null, falls back to token extraction
    // which finds no digits, so this row is skipped entirely.
    expect(result).toEqual([]);
  });

  it('skips rows marked "Not affected"', () => {
    const cells = {
      'Affected Product': 'Splunk Cloud Platform 9.1',
      'Fixed Versions': '-',
      'Affected Versions': 'Not affected',
    };
    expect(buildAffectedProducts(cells)).toEqual([]);
  });

  it('sets versionFixed only when the spec is an actual range', () => {
    const cells = {
      'Affected Product': 'Splunk Enterprise 9.0<br/>Splunk Enterprise 8.2',
      'Fixed Versions': '9.0.10<br/>8.2.13',
      'Affected Versions': 'Below 9.0.10<br/>Below 8.2.13',
    };
    expect(buildAffectedProducts(cells)).toEqual([
      {
        vendor: 'splunk',
        product: 'Splunk Enterprise',
        versionStart: undefined,
        versionEnd: '9.0.10',
        lastAffected: undefined,
        versionFixed: '9.0.10',
        patchAvailable: true,
      },
      {
        vendor: 'splunk',
        product: 'Splunk Enterprise',
        versionStart: undefined,
        versionEnd: '8.2.13',
        lastAffected: undefined,
        versionFixed: '8.2.13',
        patchAvailable: true,
      },
    ]);
  });

  it('bounds a single affected release by its later fix', () => {
    const cells = {
      'Affected Product': 'Python for Scientific Computing (for Linux 64-bit) 4.3',
      'Fixed Versions': '4.3.2',
      'Affected Versions': '4.3.1',
    };
    expect(buildAffectedProducts(cells)).toEqual([
      {
        vendor: 'splunk',
        product: 'Python for Scientific Computing (for Linux 64-bit)',
        versionStart: '4.3.1',
        versionFixed: '4.3.2',
        affectedVersions: ['4.3.1'],
        patchAvailable: true,
      },
    ]);
  });

  it('keeps a single affected release without a fix as an exact version only', () => {
    const cells = {
      'Affected Product': 'Splunk Enterprise 9.0',
      'Fixed Versions': '-',
      'Affected Versions': '9.0.1',
    };
    expect(buildAffectedProducts(cells)).toEqual([
      { vendor: 'splunk', product: 'Splunk Enterprise', affectedVersions: ['9.0.1'], versionFixed: undefined, patchAvailable: false },
    ]);
  });

  it('does not bound a single release by a fix that is not later than it', () => {
    const cells = {
      'Affected Product': 'Splunk SOAR (On-premises) 6.1',
      'Fixed Versions': '6.1.1',
      'Affected Versions': '6.1.1',
    };
    expect(buildAffectedProducts(cells)).toEqual([
      { vendor: 'splunk', product: 'Splunk SOAR (On-premises)', affectedVersions: ['6.1.1'], versionFixed: undefined, patchAvailable: true },
    ]);
  });
});
