import { describe, it, expect } from 'vitest';
import AdmZip from 'adm-zip';
import { extractCnaRows, parseCveRecord, cveIdOf, isUsableVersion, recordsFromZip, findDeltaBundles, findFullBundle } from './cna-fetcher.js';
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
    expect(normalizeVersion('Apache HTTP Server 2.4 2.4.49')).toBe(2042004000n);
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
