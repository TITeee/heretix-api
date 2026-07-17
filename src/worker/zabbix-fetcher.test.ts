import { describe, it, expect } from 'vitest';
import { parseAffectsEntry, buildAffectedProducts, type ZabbixDocument } from './zabbix-fetcher.js';

describe('parseAffectsEntry', () => {
  it('parses a clean range', () => {
    expect(parseAffectsEntry('6.0.0-6.0.44')).toEqual({ versionStart: '6.0.0', lastAffected: '6.0.44' });
  });

  it('parses a spaced en-dash range', () => {
    expect(parseAffectsEntry('5.0.0 – 5.0.18')).toEqual({ versionStart: '5.0.0', lastAffected: '5.0.18' });
  });

  it('parses a single exact version (no dash)', () => {
    expect(parseAffectsEntry('5.0.18')).toEqual({ version: '5.0.18' });
  });

  it('parses a wildcard upper bound as open-ended', () => {
    expect(parseAffectsEntry('4.4.4-4.4.*')).toEqual({ versionStart: '4.4.4' });
  });

  it('returns null for the "-" placeholder', () => {
    expect(parseAffectsEntry('-')).toBeNull();
  });

  it('returns null for free-text legacy notation', () => {
    expect(parseAffectsEntry('MSI pkg. (29.oct.22 - 2.dec.22)')).toBeNull();
  });
});

describe('buildAffectedProducts', () => {
  it('sets versionFixed for a range entry', () => {
    const doc: ZabbixDocument = {
      cve_id: 'ZBV-2026-01-01-1',
      version_affected: ['6.0.0-6.0.44'],
      version_fixed: ['6.0.45'],
    };
    expect(buildAffectedProducts(doc)).toEqual([
      {
        vendor: 'zabbix',
        product: 'zabbix',
        versionStart: '6.0.0',
        lastAffected: '6.0.44',
        affectedVersions: undefined,
        versionFixed: '6.0.45',
        patchAvailable: true,
      },
    ]);
  });

  it('does not set versionFixed for a single exact-version entry (but patchAvailable still reflects a clean fixed value)', () => {
    const doc: ZabbixDocument = {
      cve_id: 'ZBV-2026-01-01-2',
      version_affected: ['5.0.18'],
      version_fixed: ['5.0.19'],
    };
    expect(buildAffectedProducts(doc)).toEqual([
      {
        vendor: 'zabbix',
        product: 'zabbix',
        versionStart: undefined,
        lastAffected: undefined,
        affectedVersions: ['5.0.18'],
        versionFixed: undefined,
        patchAvailable: true,
      },
    ]);
  });

  it('skips entries that fail to parse', () => {
    const doc: ZabbixDocument = {
      cve_id: 'ZBV-2026-01-01-3',
      version_affected: ['-'],
      version_fixed: ['-'],
    };
    expect(buildAffectedProducts(doc)).toEqual([]);
  });
});
