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

  it('bounds a wildcard upper bound at the next minor branch rather than leaving it open-ended', () => {
    // Real data (ZBV-2023-07-27-1 / CVE-2023-29449): "4.4.4-4.4.*" previously
    // parsed to { versionStart: '4.4.4' } with no upper bound at all, which
    // incorrectly matched every later zabbix version forever (e.g. 7.0.0).
    expect(parseAffectsEntry('4.4.4-4.4.*')).toEqual({ versionStart: '4.4.4', versionEnd: '4.5.0' });
    expect(parseAffectsEntry('5.2.0alpha1-5.2.*')).toEqual({ versionStart: '5.2.0alpha1', versionEnd: '5.3.0' });
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

  it('bounds a wildcard branch entry instead of leaving it unmatched-forever (CVE-2023-29449 shape)', () => {
    const doc: ZabbixDocument = {
      cve_id: 'ZBV-2023-07-27-1',
      version_affected: ['4.4.4-4.4.*'],
      version_fixed: ['-'],
    };
    expect(buildAffectedProducts(doc)).toEqual([
      {
        vendor: 'zabbix',
        product: 'zabbix',
        versionStart: '4.4.4',
        versionEnd: '4.5.0',
        lastAffected: undefined,
        affectedVersions: undefined,
        versionFixed: undefined,
        patchAvailable: false,
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
