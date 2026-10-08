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
    // A pre-release label is dropped: normalizeVersion() would read "5.2.0alpha1" as patch 1.
    expect(parseAffectsEntry('5.2.0alpha1-5.2.*')).toEqual({ versionStart: '5.2.0', versionEnd: '5.3.0' });
  });

  it('drops pre-release labels from a range', () => {
    expect(parseAffectsEntry('6.2alpha1-6.2beta3')).toEqual({ versionStart: '6.2', lastAffected: '6.2' });
  });

  it('parses "=>X" as an affected-from version', () => {
    expect(parseAffectsEntry('=>4.0.23rc1')).toEqual({ versionStart: '4.0.23' });
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

  it('bounds a single exact-version entry by its later fix, so versionFixed cannot open it up to version zero', () => {
    const doc: ZabbixDocument = {
      cve_id: 'ZBV-2026-01-01-2',
      version_affected: ['5.0.18'],
      version_fixed: ['5.0.19'],
    };
    expect(buildAffectedProducts(doc)).toEqual([
      {
        vendor: 'zabbix',
        product: 'zabbix',
        versionStart: '5.0.18',
        lastAffected: undefined,
        affectedVersions: ['5.0.18'],
        versionFixed: '5.0.19',
        patchAvailable: true,
      },
    ]);
  });

  it('keeps a single exact-version entry exact-only when the fix is not later than it', () => {
    const doc: ZabbixDocument = {
      cve_id: 'ZBV-2026-01-01-3',
      version_affected: ['5.0.19'],
      version_fixed: ['5.0.19'],
    };
    expect(buildAffectedProducts(doc)[0]).toMatchObject({ versionStart: undefined, versionFixed: undefined });
  });

  it('reads the "=>X" / "rc1" spelling of fixed versions (ZBV-2022-09-1 shape)', () => {
    const doc: ZabbixDocument = {
      cve_id: 'ZBV-2022-09-1',
      version_affected: ['6.0.0-6.0.11', '6.2.0-6.2.5'],
      version_fixed: ['=>6.0.12rc1', '=>6.2.6rc1'],
    };
    expect(buildAffectedProducts(doc)).toMatchObject([
      { versionStart: '6.0.0', lastAffected: '6.0.11', versionFixed: '6.0.12' },
      { versionStart: '6.2.0', lastAffected: '6.2.5', versionFixed: '6.2.6' },
    ]);
  });

  it('bounds an "=>X" affected-from entry by its fix, and skips it when there is none', () => {
    const doc: ZabbixDocument = {
      cve_id: 'ZBV-2022-04-1',
      version_affected: ['=>4.0.0', '=>5.0.0'],
      version_fixed: ['=>4.0.43rc1', '-'],
    };
    expect(buildAffectedProducts(doc)).toMatchObject([
      { versionStart: '4.0.0', versionFixed: '4.0.43' },
    ]);
  });

  it('leaves a range without a fix (the "-" placeholder) unfixed', () => {
    const doc: ZabbixDocument = {
      cve_id: 'ZBV-2022-10-1',
      version_affected: ['4.0.0-4.0.44', '5.0.0-5.0.29'],
      version_fixed: ['-', '=>5.0.30rc1'],
    };
    expect(buildAffectedProducts(doc)).toMatchObject([
      { versionStart: '4.0.0', versionFixed: undefined, patchAvailable: false },
      { versionStart: '5.0.0', versionFixed: '5.0.30', patchAvailable: true },
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
