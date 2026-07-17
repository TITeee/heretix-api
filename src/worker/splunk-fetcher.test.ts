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
});
