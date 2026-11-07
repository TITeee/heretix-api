import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import AdmZip from 'adm-zip';
import { extractCnaRows, parseCnaTexts, parseCveRecord, parseSsvc, cveIdOf, isUsableVersion, recordsFromZip, recordsFromBundle, findDeltaBundles, findFullBundle } from './cna-fetcher.js';
import { normalizeVersion } from '../utils/version.js';

// Every fixture below is a shape taken from real cvelistV5 data.

describe('isUsableVersion', () => {
  it('accepts dotted numeric versions, including vendor suffixes', () => {
    for (const v of ['5.6.0', '9.16.50-S1', '2.0.3-150000.3.6.1', '16-qpr2', '1.26.0-0', '6.5.24']) {
      expect(isUsableVersion(v), v).toBe(true);
    }
  });

  it('rejects the placeholders normalizeVersion() silently turns into 0', () => {
    for (const v of ['unspecified', 'n/a', '?', '*', '-', 'All versions', 'unknown', '']) {
      // The reason this guard has to exist: normalizeVersion() does not fail on these.
      expect(normalizeVersion(v), `${v} normalizes`).not.toBeNull();
      expect(isUsableVersion(v), v).toBe(false);
    }
  });

  it('rejects free text that normalizeVersion() would turn into a confident wrong number', () => {
    // Real CVE-2021-41773 declaration; normalizeVersion() reads it as 2.42.4.
    expect(normalizeVersion('Apache HTTP Server 2.4 2.4.49')).toBe(normalizeVersion('2.42.4'));
    expect(isUsableVersion('Apache HTTP Server 2.4 2.4.49')).toBe(false);

    // "below 2.0" would be stored as the version 2.0 itself.
    expect(isUsableVersion('before 2.0')).toBe(false);
    expect(isUsableVersion('Prior to 1.2.3')).toBe(false);
  });

  it('rejects "0", which is a placeholder lower bound rather than a real version', () => {
    expect(isUsableVersion('0')).toBe(false);
  });

  it('rejects non-strings', () => {
    expect(isUsableVersion(undefined)).toBe(false);
    expect(isUsableVersion(123)).toBe(false);
  });
});

describe('extractCnaRows', () => {
  it('maps lessThan to versionEnd (exclusive) and drops the "0" lower bound', () => {
    const { rows } = extractCnaRows([{
      vendor: 'SUSE', product: 'neuvector',
      versions: [{ version: '0', lessThan: '5.4.5', status: 'affected', versionType: 'semver' }],
    }]);
    expect(rows).toEqual([{
      vendor: 'SUSE', product: 'neuvector', packageName: undefined, versionType: 'semver',
      versionStart: undefined, versionEnd: '5.4.5', lastAffected: undefined,
    }]);
  });

  it('maps lessThanOrEqual to lastAffected (inclusive) and keeps a real lower bound', () => {
    const { rows } = extractCnaRows([{
      vendor: 'ISC', product: 'BIND 9',
      versions: [{ version: '9.21.0', lessThanOrEqual: '9.21.19', status: 'affected', versionType: 'custom' }],
    }]);
    expect(rows[0]).toMatchObject({ versionStart: '9.21.0', lastAffected: '9.21.19', versionEnd: undefined });
  });

  it('stores a single declared version for equality matching only, never as a range', () => {
    const { rows } = extractCnaRows([{
      vendor: 'Google', product: 'Android',
      versions: [{ version: '16-qpr2', status: 'affected' }],
    }]);
    // No range field is set at all -- the version is matched by equality only.
    expect(rows).toEqual([{
      vendor: 'Google', product: 'Android', packageName: undefined, versionType: undefined,
      affectedVersions: ['16-qpr2'],
    }]);
  });

  it('drops an entry whose defaultStatus is "affected" with no versions (matches everything)', () => {
    const { rows, dropped } = extractCnaRows([{
      vendor: 'Acme', product: 'Widget', defaultStatus: 'affected',
    }]);
    expect(rows).toEqual([]);
    expect(dropped.defaultAffectedNoVersions).toBe(1);
  });

  it('produces nothing for the unaffected-product declarations in CVE-2024-3094 (xz)', () => {
    const { rows } = extractCnaRows([
      { vendor: 'Red Hat', product: 'Red Hat Enterprise Linux 9', packageName: 'xz', defaultStatus: 'unaffected' },
      { vendor: 'Red Hat', product: 'Red Hat Enterprise Linux 8', packageName: 'xz', defaultStatus: 'unaffected' },
    ]);
    expect(rows).toEqual([]);
  });

  it('keeps only the affected entries when a versions list mixes statuses', () => {
    const { rows } = extractCnaRows([{
      vendor: 'Acme', product: 'Widget',
      defaultStatus: 'unaffected',
      versions: [
        { version: '1.0.0', lessThan: '1.2.0', status: 'affected' },
        { version: '1.2.0', lessThan: '2.0.0', status: 'unaffected' },
      ],
    }]);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ versionStart: '1.0.0', versionEnd: '1.2.0' });
  });

  it('drops git-typed versions, whose bounds are commit hashes', () => {
    const { rows, dropped } = extractCnaRows([{
      vendor: 'Linux', product: 'Linux',
      versions: [{
        version: 'cc3ed80ae69f454c3d904af9f65394a540099723',
        lessThan: '0004ecb798b30e90d7ebfe74efae2d9423315a64',
        status: 'affected', versionType: 'git',
      }],
    }]);
    expect(rows).toEqual([]);
    expect(dropped.gitVersionType).toBe(1);
  });

  it('drops a free-text version (real CVE-2021-41773 CNA declaration)', () => {
    const { rows, dropped } = extractCnaRows([{
      vendor: 'Apache Software Foundation', product: 'Apache HTTP Server',
      versions: [{ version: 'Apache HTTP Server 2.4 2.4.49', status: 'affected' }],
    }]);
    expect(rows).toEqual([]);
    expect(dropped.exactVersionUnusable).toBe(1);
  });

  it('drops a row whose lower bound is free text even when the upper bound is valid', () => {
    const { rows, dropped } = extractCnaRows([{
      vendor: 'Acme', product: 'Widget',
      versions: [{ version: 'Prior to 1.2.3', lessThan: '2.0.0', status: 'affected' }],
    }]);
    expect(rows).toEqual([]);
    expect(dropped.unusableVersionString).toBe(1);
  });

  it('drops a range whose bound looks numeric but normalizeVersion() cannot encode (real Weintek/Jenkins data)', () => {
    // "20210218" (a YYYYMMDD date used as a version) parses as major=20210218,
    // which normalizeVersion() rejects as garbage -- but it passes the plain
    // dotted-numeric syntax check, so without this rule the row would be
    // stored with a null upper bound: unbounded, matching every version.
    expect(normalizeVersion('20210218')).toBeNull();
    let dropped = extractCnaRows([{
      vendor: 'Weintek', product: 'cMT3092X firmware',
      versions: [{ version: '0', lessThan: '20210218', status: 'affected', versionType: 'custom' }],
    }]).dropped;
    expect(dropped.unencodableRangeBound).toBe(1);

    // Jenkins plugin versioning ("4.618.v441a_27fa_46d2") is real
    // lastAffected data that is likewise unencodable.
    expect(normalizeVersion('4.618.v441a_27fa_46d2')).toBeNull();
    dropped = extractCnaRows([{
      vendor: 'Jenkins Project', product: 'Jenkins SAML Plugin',
      versions: [{ version: '0', lessThanOrEqual: '4.618.v441a_27fa_46d2', status: 'affected', versionType: 'maven' }],
    }]).dropped;
    expect(dropped.unencodableRangeBound).toBe(1);
  });

  it('drops a range whose lower bound looks numeric but is unencodable, even with a good upper bound', () => {
    const { rows, dropped } = extractCnaRows([{
      vendor: 'Acme', product: 'Widget',
      versions: [{ version: '20210218', lessThan: '2.0.0', status: 'affected' }],
    }]);
    expect(rows).toEqual([]);
    expect(dropped.unencodableRangeBound).toBe(1);
  });

  it('drops a row whose upper bound is unusable', () => {
    const { rows, dropped } = extractCnaRows([{
      vendor: 'SUSE', product: 'Image SLES15-SP7-SAPCAL-GCE',
      versions: [{ version: '?', lessThan: 'unspecified', status: 'affected', versionType: 'custom' }],
    }]);
    expect(rows).toEqual([]);
    expect(dropped.unusableVersionString).toBe(1);
  });

  describe('"lessThan: *" with a real starting version (no fix yet)', () => {
    // CVE-2025-48500's shape: one entry per branch, none fixed.
    const f5 = (versions: object[]) => extractCnaRows([{
      vendor: 'F5', product: 'BIG-IP', defaultStatus: 'unaffected',
      versions: versions.map(v => ({ status: 'affected', versionType: 'custom', ...v })),
    }]);

    it('stores the range from its start and ends it where the next branch of the record begins', () => {
      const { rows, dropped } = f5([
        { version: '17.5.0', lessThan: '*' },
        { version: '17.1.0', lessThan: '*' },
        { version: '16.1.0', lessThan: '*' },
        { version: '15.1.0', lessThan: '*' },
      ]);
      expect(dropped.unusableVersionString).toBeUndefined();
      expect(rows.map(r => [r.versionStart, r.versionEnd, r.lastAffected])).toEqual([
        ['17.5.0', undefined, undefined],
        ['17.1.0', '17.5.0', undefined],
        ['16.1.0', '17.1.0', undefined],
        ['15.1.0', '16.1.0', undefined],
      ]);
    });

    it('is capped by a fixed branch as well, so it does not run on into a branch that has its fix', () => {
      const { rows } = f5([
        { version: '17.1.0', lessThan: '17.1.3.1' },
        { version: '16.1.0', lessThan: '*' },
      ]);
      expect(rows.map(r => [r.versionStart, r.versionEnd])).toEqual([['17.1.0', '17.1.3.1'], ['16.1.0', '17.1.0']]);
    });

    it('is capped by an unaffected branch too (21.1.0 and up are not affected)', () => {
      const { rows } = extractCnaRows([{
        vendor: 'F5', product: 'BIG-IP',
        versions: [
          { version: '21.1.0', lessThan: '*', status: 'unaffected' },
          { version: '17.1.0', lessThan: '*', status: 'affected' },
        ],
      }]);
      expect(rows.map(r => [r.versionStart, r.versionEnd])).toEqual([['17.1.0', '21.1.0']]);
    });

    it('does not cap by another release of its own branch', () => {
      const { rows } = f5([
        { version: '16.1.0', lessThan: '*' },
        { version: '16.1.5', lessThan: '16.1.6' },
      ]);
      expect(rows.map(r => [r.versionStart, r.versionEnd])).toEqual([['16.1.0', undefined], ['16.1.5', '16.1.6']]);
    });

    it('is cut off by a branch the record lists in another entry of the same product (WatchGuard)', () => {
      const { rows } = extractCnaRows([
        { vendor: 'WatchGuard', product: 'Fireware OS', versions: [
          { version: '2025.1', lessThan: '2026.2.1', status: 'affected' },
          { version: '12.0', lessThan: '12.12.1', status: 'affected' },
        ] },
        { vendor: 'WatchGuard', product: 'Fireware OS', versions: [{ version: '12.0', lessThan: '*', status: 'affected' }] },
      ]);
      expect(rows.map(r => [r.versionStart, r.versionEnd])).toEqual([['2025.1', '2026.2.1'], ['12.0', '12.12.1'], ['12.0', '2025.1']]);
    });

    it('is not cut off by the branches of another product', () => {
      const { rows } = extractCnaRows([
        { vendor: 'Acme', product: 'Alpha', versions: [{ version: '1.0', lessThan: '*', status: 'affected' }] },
        { vendor: 'Acme', product: 'Beta', versions: [{ version: '2.0', lessThan: '2.3', status: 'affected' }] },
      ]);
      expect(rows.map(r => [r.product, r.versionStart, r.versionEnd])).toEqual([['Alpha', '1.0', undefined], ['Beta', '2.0', '2.3']]);
    });

    it('reads "22.2*" as the whole train, ending where the next one starts (Juniper)', () => {
      const { rows, dropped } = extractCnaRows([{
        vendor: 'Juniper', product: 'Junos OS',
        versions: [
          { version: '22.2', lessThan: '22.2*', status: 'affected', versionType: 'semver' },
          { version: '21.4R1', lessThan: '21.4*', status: 'affected', versionType: 'semver' },
          { version: '22.4', lessThan: '22.4R3-S5', status: 'affected', versionType: 'semver' },
        ],
      }]);
      expect(dropped.unusableVersionString).toBeUndefined();
      expect(rows.map(r => [r.versionStart, r.versionEnd])).toEqual([['22.2', '22.3'], ['21.4R1', '21.5'], ['22.4', '22.4R3-S5']]);
    });

    describe('a list of fixed releases (Juniper)', () => {
      const junos = (version: string, lessThan: string, vendor = 'Juniper') => extractCnaRows([{
        vendor, product: 'Junos OS', versions: [{ version, lessThan, status: 'affected', versionType: 'semver' }],
      }]);

      it('reads "23.4R1-S2, 23.4R2" as 23.4 up to 23.4R1-S2: R1 is fixed at S2 and R2 is fixed outright', () => {
        const { rows, dropped } = junos('23.4', '23.4R1-S2, 23.4R2');
        expect(dropped.unusableVersionString).toBeUndefined();
        expect(rows.map(r => [r.versionStart, r.versionEnd])).toEqual([['23.4', '23.4R1-S2']]);
      });

      it('adds the range of a later line that has its own service-release fix', () => {
        const { rows } = junos('22.4', '22.4R1-S3, 22.4R2-S2, 22.4R3');
        expect(rows.map(r => [r.versionStart, r.versionEnd])).toEqual([['22.4', '22.4R1-S3'], ['22.4R2', '22.4R2-S2']]);
      });

      it('sorts the fixes and takes a "0" start as no lower bound', () => {
        const { rows } = junos('0', '24.2R2, 24.2R1-S2');
        expect(rows.map(r => [r.versionStart, r.versionEnd])).toEqual([[undefined, '24.2R1-S2']]);
      });

      it('drops a list with fixes in more than one train, or that is not Junos releases', () => {
        expect(junos('23.2', '23.2R2-S3, 23.4R1').rows).toEqual([]);
        expect(junos('23.4', '23.4R1-S2, soon').rows).toEqual([]);
      });

      it('leaves other vendors\' lists alone: Palo Alto and Microsoft mean something else by them', () => {
        expect(junos('10.2', '10.2.10-h29, 10.2.4-h43', 'Palo Alto Networks').rows).toEqual([]);
        expect(junos('23.4', '23.4R1-S2, 23.4R2', 'Microsoft').rows).toEqual([]);
      });
    });

    it('reads a dotted wildcard as the whole line, in lessThan or lessThanOrEqual (Drupal "11.2.*", MongoDB "8.1.*")', () => {
      const { rows, dropped } = extractCnaRows([{
        vendor: 'Drupal', product: 'Drupal core',
        versions: [
          { version: '0.0.0', lessThan: '11.0.*', status: 'affected', versionType: 'semver' },
          { version: '0.0.0', lessThan: '11.2.*', status: 'affected', versionType: 'semver' },
          { version: '8.1.0', lessThanOrEqual: '8.1.*', status: 'affected', versionType: 'semver' },
          { version: '2.0.0', lessThan: '2.4.1.*', status: 'affected', versionType: 'semver' },
        ],
      }]);
      expect(dropped.unusableVersionString).toBeUndefined();
      expect(rows.map(r => [r.versionStart, r.versionEnd, r.lastAffected])).toEqual([
        ['0.0.0', '11.1', undefined],
        ['0.0.0', '11.3', undefined],
        ['8.1.0', '8.2', undefined],
        ['2.0.0', '2.4.2', undefined],
      ]);
    });

    it('still drops a bare "*" bound, which is every version', () => {
      const { rows } = extractCnaRows([{
        vendor: 'Acme', product: 'Widget',
        versions: [{ version: '1.0', lessThanOrEqual: '*', status: 'affected' }],
      }]);
      expect(rows).toEqual([]);
    });

    it('still drops a placeholder start with "*", which is every version', () => {
      for (const version of ['0', '*', 'unspecified']) {
        const { rows, dropped } = f5([{ version, lessThan: '*' }]);
        expect(rows).toEqual([]);
        expect(dropped.unusableVersionString).toBe(1);
      }
    });

    it('leaves "lessThanOrEqual: *" alone', () => {
      const { rows } = f5([{ version: '16.1.0', lessThanOrEqual: '*' }]);
      expect(rows).toEqual([]);
    });
  });

  describe('NetScaler build ranges', () => {
    // CVE-2025-12101 as the CNA wrote it: the branch is the version, the build the bound.
    const netscaler = (versions: unknown[], vendor = 'NetScaler', product = 'ADC') =>
      [{ vendor, product, defaultStatus: 'unaffected', versions }];

    it('drops the branch + build ranges, which would read 14.1 up to 56.73 and so flag the fixed builds', () => {
      const { rows, dropped } = extractCnaRows(netscaler([
        { status: 'affected', version: '14.1', lessThan: '56.73', versionType: 'patch' },
        { status: 'affected', version: '13.1', lessThan: '60.32', versionType: 'patch' },
        { status: 'affected', version: '13.1-FIPS and NDcPP', lessThan: '37.250', versionType: 'patch' },
      ]));
      expect(rows).toEqual([]);
      expect(dropped.netscalerBuildBound).toBe(3);
    });

    it('drops the other spelling too, where the bound is the whole version ("14.1-73.37" loses its 37)', () => {
      const { rows } = extractCnaRows(netscaler(
        [{ status: 'affected', version: '0', lessThan: '14.1-73.37', versionType: 'Patch' }],
        'Citrix NetScaler', 'Gateway',
      ));
      expect(rows).toEqual([]);
    });

    it('also covers the other NetScaler products (SDX, Console)', () => {
      const { rows } = extractCnaRows(netscaler(
        [{ status: 'affected', version: '13.1', lessThan: '58.32', versionType: 'patch' }], 'NetScaler', 'Console',
      ));
      expect(rows).toEqual([]);
    });

    it('keeps a NetScaler version with no bound, which is stored for equality matching only', () => {
      const { rows } = extractCnaRows(netscaler([{ status: 'affected', version: '14.1-56.73', versionType: 'patch' }]));
      expect(rows).toEqual([expect.objectContaining({ affectedVersions: ['14.1-56.73'] })]);
    });

    it('leaves other vendors that use versionType "patch" for ordinary ranges alone', () => {
      const { rows } = extractCnaRows([{
        vendor: 'Concrete CMS', product: 'Concrete CMS', defaultStatus: 'unaffected',
        versions: [{ status: 'affected', version: '5.6', lessThan: '9.4.3', versionType: 'patch' }],
      }]);
      expect(rows).toEqual([expect.objectContaining({ versionStart: '5.6', versionEnd: '9.4.3' })]);
    });

    it('leaves the Citrix client apps alone: they are not NetScaler and their versions are plain', () => {
      const { rows } = extractCnaRows([{
        vendor: 'Citrix', product: 'Secure Access Client for Windows', defaultStatus: 'unaffected',
        versions: [{ status: 'affected', version: '1', lessThan: '26.6.1.20', versionType: 'patch' }],
      }]);
      expect(rows).toHaveLength(1);
    });
  });

  it('drops entries with a missing or single-character product name', () => {
    const { rows, dropped } = extractCnaRows([
      { vendor: 'Acme', product: 'i', versions: [{ version: '7.6', status: 'affected' }] },
      { product: 'Widget', versions: [{ version: '1.0', status: 'affected' }] },
      { vendor: 'Acme', product: 'n/a', versions: [{ version: '1.0', status: 'affected' }] },
    ]);
    expect(rows).toEqual([]);
    expect(dropped.noVendorOrProduct).toBe(3);
  });

  it('falls back to packageName when no product is given', () => {
    const { rows } = extractCnaRows([{
      vendor: 'tukaani', packageName: 'xz',
      versions: [{ version: '5.6.0', status: 'affected' }],
    }]);
    expect(rows[0]).toMatchObject({ product: 'xz', packageName: 'xz', affectedVersions: ['5.6.0'] });
  });

  it('returns nothing for a missing or non-array affected list', () => {
    expect(extractCnaRows(undefined).rows).toEqual([]);
    expect(extractCnaRows({}).rows).toEqual([]);
  });

  describe('Zyxel version text', () => {
    const row = (version: string, vendor = 'Zyxel') => extractCnaRows([
      { vendor, product: 'ATP series firmware', versions: [{ status: 'affected', version }] },
    ]);

    it('reads "versions V5.00 through V5.38" as an inclusive range', () => {
      const { rows } = row('versions V5.00 through V5.38');
      expect(rows).toEqual([expect.objectContaining({ versionStart: '5.00', lastAffected: '5.38' })]);
    });

    it('reads the other spellings of a firewall range, with or without "from" and a trailing patch', () => {
      for (const text of ['from V4.32 through V5.42 Patch 1', 'versions from V4.32 through V5.42', '4.32 through 5.42 Patch 1']) {
        expect(row(text).rows).toEqual([expect.objectContaining({ versionStart: '4.32', lastAffected: '5.42' })]);
      }
    });

    it('reads a plain "<= 5.37" as an upper bound', () => {
      const { rows } = row('<= 5.37');
      expect(rows).toEqual([expect.objectContaining({ lastAffected: '5.37' })]);
      expect(rows[0].versionStart).toBeUndefined();
    });

    it('drops a bound that carries a firmware build, which would flag the fixed builds of that release', () => {
      expect(row('<= 7.10(ABRM.4)C0').rows).toEqual([]);
      expect(row('versions V5.00(ABXX.0) through V5.38(ABXX.2)').rows).toEqual([]);
    });

    it('does not read the text for other vendors', () => {
      expect(row('versions V5.00 through V5.38', 'Acme').rows).toEqual([]);
      expect(row('<= 5.37', 'Acme').rows).toEqual([]);
    });
  });
});

describe('parseCveRecord', () => {
  const record = {
    cveMetadata: {
      cveId: 'CVE-2026-12345',
      datePublished: '2026-09-01T00:00:00.000Z',
      dateUpdated: '2026-09-02T00:00:00.000Z',
    },
    containers: {
      cna: {
        providerMetadata: { shortName: 'acme' },
        affected: [{ vendor: 'Acme', product: 'Widget', versions: [{ version: '0', lessThan: '1.2.3', status: 'affected' }] }],
      },
    },
  };

  it('parses id, CNA short name, dates and rows', () => {
    const parsed = parseCveRecord(record);
    expect(parsed).toMatchObject({ cveId: 'CVE-2026-12345', cnaShortName: 'acme' });
    expect(parsed?.datePublished?.toISOString()).toBe('2026-09-01T00:00:00.000Z');
    expect(parsed?.rows).toHaveLength(1);
  });

  it('returns null when no row survives filtering, so nothing empty is stored', () => {
    expect(parseCveRecord({
      cveMetadata: { cveId: 'CVE-2026-12345' },
      containers: { cna: { affected: [{ vendor: 'Acme', product: 'Widget', defaultStatus: 'affected' }] } },
    })).toBeNull();
  });

  it('returns null for a REJECTED record', () => {
    expect(parseCveRecord({ ...record, cveMetadata: { ...record.cveMetadata, state: 'REJECTED' } })).toBeNull();
  });

  it('returns null without a CVE id', () => {
    expect(parseCveRecord({ containers: record.containers })).toBeNull();
  });

  it('cveIdOf finds the id even when parseCveRecord itself would return null', () => {
    // The importer relies on this to tell "no id, nothing to do" apart from
    // "id present, but this revision has nothing usable" -- the second case
    // needs whatever was previously stored for that id to be pruned.
    expect(cveIdOf({ cveMetadata: { cveId: 'CVE-2026-1' }, containers: { cna: { affected: [] } } })).toBe('CVE-2026-1');
    expect(cveIdOf({ cveMetadata: { cveId: 'CVE-2026-1', state: 'REJECTED' } })).toBe('CVE-2026-1');
    expect(cveIdOf({})).toBeNull();
  });

  it('defaults the CNA short name when the record omits providerMetadata', () => {
    const parsed = parseCveRecord({
      cveMetadata: { cveId: 'CVE-2026-1' },
      containers: { cna: { affected: record.containers.cna.affected } },
    });
    expect(parsed?.cnaShortName).toBe('unknown');
  });
});

describe('parseCnaTexts', () => {
  // Shapes as the Palo Alto (CVE-2024-3400) and other CNA records carry them.
  it('reads the workaround and solution verbatim, with the CNA that wrote them', () => {
    expect(parseCnaTexts({
      cveMetadata: { cveId: 'CVE-2024-3400' },
      containers: { cna: {
        providerMetadata: { shortName: 'palo_alto' },
        workarounds: [{ lang: 'en', value: 'Recommended Mitigation: block Threat IDs 95187.' }],
        solutions: [{ lang: 'en', value: 'This issue is fixed in PAN-OS 10.2.9-h1.' }],
      } },
    })).toEqual({
      workaround: 'Recommended Mitigation: block Threat IDs 95187.',
      solution: 'This issue is fixed in PAN-OS 10.2.9-h1.',
      provider: 'palo_alto',
    });
  });

  it('keeps a statement that there is no workaround, and prefers English entries, each once', () => {
    expect(parseCnaTexts({
      containers: { cna: {
        providerMetadata: { shortName: 'juniper' },
        workarounds: [
          { lang: 'eng', value: 'There are no known workarounds for this issue.' },
          { lang: 'es', value: 'No hay soluciones.' },
          { lang: 'en-US', value: 'There are no known workarounds for this issue. ' },
        ],
      } },
    })).toEqual({ workaround: 'There are no known workarounds for this issue.', solution: null, provider: 'juniper' });
  });

  it('returns nothing for a record without them, or a REJECTED one', () => {
    expect(parseCnaTexts({ containers: { cna: { providerMetadata: { shortName: 'acme' }, affected: [] } } }))
      .toEqual({ workaround: null, solution: null, provider: null });
    expect(parseCnaTexts({
      cveMetadata: { state: 'REJECTED' },
      containers: { cna: { workarounds: [{ lang: 'en', value: 'Disable it.' }] } },
    })).toEqual({ workaround: null, solution: null, provider: null });
  });
});

describe('parseSsvc', () => {
  // Shape taken from the live CVE-2024-3400 record (containers.adp), confirmed
  // identical to the same CVE's entry in cisagov/vulnrichment.
  const cisaAdpRecord = {
    containers: {
      adp: [
        {
          metrics: [
            {
              other: {
                type: 'ssvc',
                content: {
                  id: 'CVE-2024-3400',
                  role: 'CISA Coordinator',
                  options: [
                    { Exploitation: 'active' },
                    { Automatable: 'yes' },
                    { 'Technical Impact': 'total' },
                  ],
                  version: '2.0.3',
                  timestamp: '2024-04-17T04:00:13.543064Z',
                },
              },
            },
            { other: { type: 'kev', content: { dateAdded: '2024-04-12' } } },
          ],
          title: 'CISA ADP Vulnrichment',
          providerMetadata: { orgId: '134c704f-9b21-4f2e-91b3-4a467353bcc0', shortName: 'CISA-ADP' },
        },
        {
          title: 'CVE Program Container',
          providerMetadata: { orgId: 'af854a3a-2127-422b-91ae-364da2661108', shortName: 'CVE' },
        },
      ],
    },
  };

  it('reads the three SSVC decision points from the CISA-ADP container', () => {
    expect(parseSsvc(cisaAdpRecord)).toEqual({
      exploitation: 'active',
      automatable: 'yes',
      technicalImpact: 'total',
      timestamp: new Date('2024-04-17T04:00:13.543064Z'),
    });
  });

  it('returns undefined when there is no adp container at all', () => {
    expect(parseSsvc({ containers: { cna: {} } })).toBeUndefined();
  });

  it('returns undefined when adp is present but has no CISA-ADP entry', () => {
    expect(parseSsvc({
      containers: { adp: [{ providerMetadata: { shortName: 'CVE' } }] },
    })).toBeUndefined();
  });

  it('returns undefined when the CISA-ADP container has no ssvc metric', () => {
    expect(parseSsvc({
      containers: {
        adp: [{ providerMetadata: { shortName: 'CISA-ADP' }, metrics: [{ other: { type: 'kev', content: {} } }] }],
      },
    })).toBeUndefined();
  });

  it('returns undefined when a decision point is missing or has an unrecognized value', () => {
    const missingAutomatable = {
      containers: {
        adp: [{
          providerMetadata: { shortName: 'CISA-ADP' },
          metrics: [{ other: { type: 'ssvc', content: { options: [{ Exploitation: 'active' }, { 'Technical Impact': 'total' }] } } }],
        }],
      },
    };
    expect(parseSsvc(missingAutomatable)).toBeUndefined();

    const unrecognizedValue = {
      containers: {
        adp: [{
          providerMetadata: { shortName: 'CISA-ADP' },
          metrics: [{
            other: {
              type: 'ssvc',
              content: { options: [{ Exploitation: 'maybe' }, { Automatable: 'yes' }, { 'Technical Impact': 'total' }] },
            },
          }],
        }],
      },
    };
    expect(parseSsvc(unrecognizedValue)).toBeUndefined();
  });
});

describe('recordsFromZip', () => {
  function zipOf(entries: Record<string, unknown>): AdmZip {
    const zip = new AdmZip();
    for (const [name, body] of Object.entries(entries)) {
      zip.addFile(name, Buffer.from(typeof body === 'string' ? body : JSON.stringify(body), 'utf8'));
    }
    return zip;
  }

  const record = (cveId: string) => ({ cveMetadata: { cveId } });

  // The two bundle kinds ship different layouts, and reading the year from the
  // path instead of the id silently yielded zero records from one of them.
  it('reads both the flat delta layout and the nested full-bundle layout', () => {
    const zip = zipOf({
      'deltaCves/CVE-2026-1111.json': record('CVE-2026-1111'),
      'cves/2026/1xxx/CVE-2026-2222.json': record('CVE-2026-2222'),
    });
    const ids = [...recordsFromZip(zip, null)].map(r => r.cveMetadata?.cveId);
    expect(ids).toEqual(['CVE-2026-1111', 'CVE-2026-2222']);
  });

  // The full snapshot ships as a zip wrapping a single cves.zip; reading only
  // the outer archive found no records at all and imported nothing silently.
  it('unwraps a nested archive (the full snapshot\'s cves.zip)', () => {
    const inner = zipOf({ 'cves/2026/1xxx/CVE-2026-1111.json': record('CVE-2026-1111') });
    const outer = new AdmZip();
    outer.addFile('cves.zip', inner.toBuffer());

    const ids = [...recordsFromZip(outer, null)].map(r => r.cveMetadata?.cveId);
    expect(ids).toEqual(['CVE-2026-1111']);
  });

  it('applies the year filter inside a nested archive too', () => {
    const inner = zipOf({
      'cves/2019/1xxx/CVE-2019-1111.json': record('CVE-2019-1111'),
      'cves/2026/2xxx/CVE-2026-2222.json': record('CVE-2026-2222'),
    });
    const outer = new AdmZip();
    outer.addFile('cves.zip', inner.toBuffer());

    const ids = [...recordsFromZip(outer, new Set(['2026']))].map(r => r.cveMetadata?.cveId);
    expect(ids).toEqual(['CVE-2026-2222']);
  });

  it('filters by the year in the CVE id, in either layout', () => {
    const zip = zipOf({
      'deltaCves/CVE-2016-4117.json': record('CVE-2016-4117'),
      'deltaCves/CVE-2025-1111.json': record('CVE-2025-1111'),
      'cves/2019/1xxx/CVE-2019-2222.json': record('CVE-2019-2222'),
      'cves/2026/3xxx/CVE-2026-3333.json': record('CVE-2026-3333'),
    });
    const ids = [...recordsFromZip(zip, new Set(['2025', '2026']))].map(r => r.cveMetadata?.cveId);
    expect(ids).toEqual(['CVE-2025-1111', 'CVE-2026-3333']);
  });

  it('skips manifests and unparseable entries without aborting the bundle', () => {
    const zip = zipOf({
      'deltaCves/delta.json': { note: 'manifest, not a record' },
      'deltaCves/deltaLog.json': [{ note: 'also a manifest' }],
      'deltaCves/CVE-2026-1111.json': 'this is not json',
      'deltaCves/CVE-2026-2222.json': record('CVE-2026-2222'),
    });
    const ids = [...recordsFromZip(zip, null)].map(r => r.cveMetadata?.cveId);
    expect(ids).toEqual(['CVE-2026-2222']);
  });
});

describe('release asset selection', () => {
  const release = (published: string, assetNames: string[]) => ({
    tag_name: `cve_${published}`,
    published_at: published,
    assets: assetNames.map(name => ({ name, browser_download_url: `https://example.test/${name}`, size: 1 })),
  });

  it('picks the full snapshot asset, ignoring deltas', () => {
    const asset = findFullBundle([
      release('2026-09-11T01:00:00Z', ['2026-09-11_delta_CVEs_at_0100Z.zip', 'release_notes.md']),
      release('2026-09-11T00:00:00Z', ['2026-09-10_all_CVEs_at_midnight.zip.zip']),
    ]);
    expect(asset?.name).toBe('2026-09-10_all_CVEs_at_midnight.zip.zip');
  });

  it('returns only deltas published after the cursor, oldest first', () => {
    const assets = findDeltaBundles([
      release('2026-09-11T02:00:00Z', ['2026-09-11_delta_CVEs_at_0200Z.zip']),
      release('2026-09-11T01:00:00Z', ['2026-09-11_delta_CVEs_at_0100Z.zip']),
      release('2026-09-10T23:00:00Z', ['2026-09-10_delta_CVEs_at_2300Z.zip']),
    ], new Date('2026-09-11T00:30:00Z'));
    expect(assets.map(a => a.name)).toEqual([
      '2026-09-11_delta_CVEs_at_0100Z.zip',
      '2026-09-11_delta_CVEs_at_0200Z.zip',
    ]);
  });

  it('skips a release that carries no delta asset', () => {
    const assets = findDeltaBundles([
      release('2026-09-11T01:00:00Z', ['release_notes.md']),
    ], new Date('2026-09-10T00:00:00Z'));
    expect(assets).toEqual([]);
  });
});

// The full snapshot is read from a file, one entry at a time (AdmZip needed 3.9 GB for it).
describe('recordsFromBundle', () => {
  let dir: string;
  beforeEach(async () => { dir = await mkdtemp(path.join(os.tmpdir(), 'cna-bundle-test-')); });
  afterEach(async () => { await rm(dir, { recursive: true, force: true }); });

  const record = (cveId: string) => ({ cveMetadata: { cveId } });
  async function bundle(entries: Record<string, unknown>, name = 'bundle.zip'): Promise<string> {
    const zip = new AdmZip();
    for (const [n, body] of Object.entries(entries)) zip.addFile(n, Buffer.from(typeof body === 'string' ? body : JSON.stringify(body), 'utf8'));
    const file = path.join(dir, name);
    await writeFile(file, zip.toBuffer());
    return file;
  }
  async function ids(file: string, years: Set<string> | null = null): Promise<string[]> {
    const out: string[] = [];
    for await (const r of recordsFromBundle(file, years, dir)) out.push(String(r.cveMetadata?.cveId));
    return out.sort(); // the order of entries in an archive is not what is tested
  }

  it('reads the flat delta layout and the full-bundle layout alike', async () => {
    const file = await bundle({
      'deltaCves/CVE-2026-1111.json': record('CVE-2026-1111'),
      'cves/2026/2xxx/CVE-2026-2222.json': record('CVE-2026-2222'),
    });
    expect(await ids(file)).toEqual(['CVE-2026-1111', 'CVE-2026-2222']);
  });

  it('unwraps the nested cves.zip of the full snapshot, and leaves no file behind', async () => {
    const innerFile = await bundle({ 'cves/2026/1xxx/CVE-2026-1111.json': record('CVE-2026-1111') }, 'inner-source.zip');
    const outer = new AdmZip();
    outer.addFile('cves.zip', await readFile(innerFile));
    const outerFile = path.join(dir, 'outer.zip');
    await writeFile(outerFile, outer.toBuffer());

    expect(await ids(outerFile)).toEqual(['CVE-2026-1111']);
    expect((await readdir(dir)).filter((f) => f.startsWith('nested-'))).toEqual([]);
  });

  it('takes the year from the CVE id, not from the path, and skips what is not a record', async () => {
    const file = await bundle({
      'cves/2025/0xxx/CVE-2025-0001.json': record('CVE-2025-0001'),
      'cves/2024/0xxx/CVE-2024-0001.json': record('CVE-2024-0001'),
      'cves/delta.json': { not: 'a record' },
      'cves/2025/0xxx/': '',
    });
    expect(await ids(file, new Set(['2025', '2026']))).toEqual(['CVE-2025-0001']);
  });

  it('skips a record that is not valid JSON instead of stopping', async () => {
    const file = await bundle({
      'cves/2026/0xxx/CVE-2026-0001.json': '{ broken',
      'cves/2026/0xxx/CVE-2026-0002.json': record('CVE-2026-0002'),
    });
    expect(await ids(file)).toEqual(['CVE-2026-0002']);
  });

  it('gives the same records as recordsFromZip', async () => {
    const entries = { 'cves/2026/0xxx/CVE-2026-0001.json': record('CVE-2026-0001'), 'cves/2025/0xxx/CVE-2025-0009.json': record('CVE-2025-0009') };
    const zip = new AdmZip();
    for (const [n, b] of Object.entries(entries)) zip.addFile(n, Buffer.from(JSON.stringify(b)));
    expect(await ids(await bundle(entries))).toEqual([...recordsFromZip(zip, null)].map((r) => String(r.cveMetadata?.cveId)).sort());
  });
});
