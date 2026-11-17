import { describe, it, expect, beforeEach, afterEach, afterAll, vi } from 'vitest';
import axios from 'axios';
import AdmZip from 'adm-zip';
import { prisma } from '../db/client.js';
import { resetDb } from '../test-utils/db.js';
import { importOSVData, importOSVEcosystemDelta } from './osv-fetcher.js';

// OSVVulnerability isn't exported from osv-fetcher.ts; a plain object literal
// satisfies the parameter's structural type without needing that import.
function makeOsv(overrides: Record<string, unknown> = {}) {
  return {
    id: 'GHSA-test-0001',
    modified: '2026-01-01T00:00:00Z',
    summary: 'Test OSV entry',
    aliases: [] as string[],
    affected: [{ package: { ecosystem: 'npm', name: 'test-pkg' } }],
    ...overrides,
  };
}

describe('importOSVData — orphaned master row regression', () => {
  beforeEach(async () => {
    await resetDb();
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  it('creates an osvId-keyed master row when no CVE alias is present', async () => {
    await importOSVData(makeOsv());

    const master = await prisma.vulnerability.findUnique({ where: { osvId: 'GHSA-test-0001' } });
    expect(master).not.toBeNull();
    expect(master?.cveId).toBeNull();
  });

  it('migrates to the NVD-created master row and deletes the orphaned osvId-keyed row when a CVE is assigned later', async () => {
    // 1. Initial import with no CVE — creates an osvId-keyed master row.
    await importOSVData(makeOsv());
    const orphanCandidate = await prisma.vulnerability.findUnique({ where: { osvId: 'GHSA-test-0001' } });
    expect(orphanCandidate).not.toBeNull();

    // 2. NVD imports the same vulnerability under its CVE ID (independent master row).
    const nvdMaster = await prisma.vulnerability.create({
      data: { cveId: 'CVE-2026-3333', severity: 'HIGH', cvssScore: 8.1 },
    });

    // 3. OSV re-import now carries the CVE as an alias.
    await importOSVData(makeOsv({ aliases: ['CVE-2026-3333'] }));

    // The OSV record must now point at the NVD master row...
    const osvRecord = await prisma.oSVVulnerability.findUnique({ where: { osvId: 'GHSA-test-0001' } });
    expect(osvRecord?.masterVulnId).toBe(nvdMaster.id);

    // ...and the old osvId-keyed master row must be gone (not left as an orphan).
    const stale = await prisma.vulnerability.findUnique({ where: { id: orphanCandidate!.id } });
    expect(stale).toBeNull();

    // Exactly one master row should remain for this vulnerability.
    const allMasters = await prisma.vulnerability.findMany();
    expect(allMasters).toHaveLength(1);
    expect(allMasters[0].cveId).toBe('CVE-2026-3333');
  });

  it('does not delete an NVD-linked master row even if masterVulnId briefly matches during re-import', async () => {
    // Import directly with a CVE present from the start (no orphan scenario) —
    // guards against the cleanup logic firing when it shouldn't.
    await importOSVData(makeOsv({ aliases: ['CVE-2026-4444'] }));

    const master = await prisma.vulnerability.findUnique({ where: { cveId: 'CVE-2026-4444' } });
    expect(master).not.toBeNull();

    const allMasters = await prisma.vulnerability.findMany();
    expect(allMasters).toHaveLength(1);
  });
});

describe('importOSVData — withdrawn records', () => {
  beforeEach(async () => {
    await resetDb();
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  it('creates no OSVAffectedPackage rows for a withdrawn record', async () => {
    await importOSVData(makeOsv({
      withdrawn: '2026-09-01T18:35:34Z',
      affected: [{
        package: { ecosystem: 'npm', name: 'test-pkg' },
        ranges: [{ type: 'SEMVER', events: [{ introduced: '1.0.0' }] }],
      }],
    }));

    const vuln = await prisma.oSVVulnerability.findUnique({ where: { osvId: 'GHSA-test-0001' } });
    const packages = await prisma.oSVAffectedPackage.findMany({ where: { vulnerabilityId: vuln!.id } });
    expect(packages).toHaveLength(0);
  });

  it('removes previously-imported OSVAffectedPackage rows once a record becomes withdrawn', async () => {
    // 1. Initial import while still active — creates affected-package rows.
    await importOSVData(makeOsv({
      affected: [{
        package: { ecosystem: 'npm', name: 'test-pkg' },
        ranges: [{ type: 'SEMVER', events: [{ introduced: '1.0.0' }, { fixed: '2.0.0' }] }],
      }],
    }));
    const vuln = await prisma.oSVVulnerability.findUnique({ where: { osvId: 'GHSA-test-0001' } });
    const before = await prisma.oSVAffectedPackage.findMany({ where: { vulnerabilityId: vuln!.id } });
    expect(before.length).toBeGreaterThan(0);

    // 2. Upstream withdraws the record (e.g. marked a duplicate) — re-import should clear it out.
    await importOSVData(makeOsv({
      withdrawn: '2026-09-01T18:35:34Z',
      affected: [{
        package: { ecosystem: 'npm', name: 'test-pkg' },
        ranges: [{ type: 'SEMVER', events: [{ introduced: '1.0.0' }, { fixed: '2.0.0' }] }],
      }],
    }));
    const after = await prisma.oSVAffectedPackage.findMany({ where: { vulnerabilityId: vuln!.id } });
    expect(after).toHaveLength(0);
  });
});

describe('importOSVData — severity and CVSS', () => {
  const V3 = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N'; // 5.4
  const V4 = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'; // 9.3

  beforeEach(async () => {
    await resetDb();
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  it('stores GHSA\'s MODERATE as MEDIUM and computes the CVSS score from the vector', async () => {
    // GHSA-6ccv-8fgf-cjpw (drupal/core) shape: a GHSA rating plus a vector, no CVE.
    await importOSVData(makeOsv({
      database_specific: { severity: 'MODERATE' },
      severity: [{ type: 'CVSS_V3', score: V3 }],
    }));

    const master = await prisma.vulnerability.findUnique({ where: { osvId: 'GHSA-test-0001' } });
    expect(master).toMatchObject({ severity: 'MEDIUM', cvssScore: 5.4, cvssVector: V3 });
    const source = await prisma.oSVVulnerability.findUnique({ where: { osvId: 'GHSA-test-0001' } });
    expect(source).toMatchObject({ severity: 'MEDIUM', cvssScore: 5.4 });
  });

  it('derives the severity from a CVSS 4.0 score when the record has no rating of its own', async () => {
    await importOSVData(makeOsv({ severity: [{ type: 'CVSS_V4', score: V4 }] }));

    const master = await prisma.vulnerability.findUnique({ where: { osvId: 'GHSA-test-0001' } });
    expect(master).toMatchObject({ severity: 'CRITICAL', cvssScore: 9.3, cvssVector: V4 });
  });

  it('replaces a non-rating severity left by an earlier importer, but keeps an existing score', async () => {
    await prisma.vulnerability.create({ data: { cveId: 'CVE-2026-4444', severity: 'CVSS_V3', cvssScore: 7.5 } });

    await importOSVData(makeOsv({
      aliases: ['CVE-2026-4444'],
      database_specific: { severity: 'HIGH' },
      severity: [{ type: 'CVSS_V3', score: V3 }],
    }));

    const master = await prisma.vulnerability.findUnique({ where: { cveId: 'CVE-2026-4444' } });
    expect(master).toMatchObject({ severity: 'HIGH', cvssScore: 7.5 });
  });
});

describe('importOSVEcosystemDelta — a bucket that is missing or no longer written to', () => {
  const debianRecord = (id: string, modified: string) => makeOsv({
    id,
    modified,
    aliases: [id.replace('DEBIAN-', '')],
    affected: [{ package: { ecosystem: 'Debian:13', name: 'util-linux' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '2.41.5-0+deb13u1' }] }] }],
  });

  function zipOf(records: Array<ReturnType<typeof makeOsv>>): ArrayBuffer {
    const zip = new AdmZip();
    for (const r of records) zip.addFile(`${r.id}.json`, Buffer.from(JSON.stringify(r)));
    const buf = zip.toBuffer();
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer;
  }

  beforeEach(async () => {
    await resetDb();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('imports the records newer than the cursor from a live bucket', async () => {
    const recent = new Date(Date.now() - 60 * 60 * 1000).toISOString();
    vi.spyOn(axios, 'get').mockResolvedValue({ data: zipOf([debianRecord('DEBIAN-CVE-2026-0001', recent), debianRecord('DEBIAN-CVE-2025-0001', '2025-01-01T00:00:00Z')]) });

    const result = await importOSVEcosystemDelta('Debian', new Date(Date.now() - 24 * 60 * 60 * 1000));

    expect(result).toMatchObject({ total: 2, skipped: 1, inserted: 1, failed: 0 });
    expect(await prisma.oSVVulnerability.count({ where: { osvId: 'DEBIAN-CVE-2026-0001' } })).toBe(1);
  });

  it('fails the job on a 404 instead of reporting an empty success', async () => {
    vi.spyOn(axios, 'get').mockRejectedValue(Object.assign(new Error('Request failed with status code 404'), { isAxiosError: true, response: { status: 404 } }));
    vi.spyOn(axios, 'isAxiosError').mockReturnValue(true);

    await expect(importOSVEcosystemDelta('Alpine:v3.24', new Date(0))).rejects.toThrow(/OSV has no bucket "Alpine:v3.24".*SHARED_BUCKET_ECOSYSTEMS/);
  });

  // This is what Debian:12, Debian:13, Alpine:* and Ubuntu:* looked like from October 2024: the
  // file answers 200, holds records, and none of them has changed since.
  it('fails the job when the newest record of a distro bucket is old, after importing what it holds', async () => {
    vi.spyOn(axios, 'get').mockResolvedValue({ data: zipOf([debianRecord('DEBIAN-CVE-2024-0001', '2024-10-04T14:58:33Z')]) });

    await expect(importOSVEcosystemDelta('Debian:13', new Date('2024-01-01T00:00:00Z'))).rejects.toThrow(
      /fetched 1 records and imported 1, but the newest record in the OSV bucket "Debian:13" is \d+ days old/,
    );
    expect(await prisma.oSVVulnerability.count({ where: { osvId: 'DEBIAN-CVE-2024-0001' } })).toBe(1);
  });

  it('fails the job on an empty bucket', async () => {
    vi.spyOn(axios, 'get').mockResolvedValue({ data: zipOf([]) });
    await expect(importOSVEcosystemDelta('Debian', new Date(0))).rejects.toThrow(/holds no records/);
  });
});

describe('importOSVEcosystemDelta — a bucket read from its modified-ID list (Ubuntu)', () => {
  const BASE = 'https://storage.googleapis.com/osv-vulnerabilities/Ubuntu';
  const hoursAgo = (h: number) => new Date(Date.now() - h * 60 * 60 * 1000).toISOString();

  const usn = (id: string, modified: string) => makeOsv({
    id,
    modified,
    aliases: [],
    affected: [{ package: { ecosystem: 'Ubuntu:22.04:LTS', name: 'openssl' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '3.0.2-0ubuntu1.19' }] }] }],
  });

  /** Serves a modified_id.csv and the single records the way the bucket does. */
  function serveBucket(list: Array<{ id: string; modified: string }>, records: Record<string, unknown>) {
    return vi.spyOn(axios, 'get').mockImplementation(async (url: string) => {
      if (url === `${BASE}/modified_id.csv`) return { data: list.map((e) => `${e.modified},${e.id}`).join('\n') + '\n' };
      const id = decodeURIComponent(url.slice(BASE.length + 1).replace(/\.json$/, ''));
      if (records[id]) return { data: records[id] };
      throw Object.assign(new Error('Request failed with status code 404'), { isAxiosError: true, response: { status: 404 } });
    });
  }

  beforeEach(async () => {
    await resetDb();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('fetches only the records listed as modified after the cursor, and never the zip', async () => {
    const list = [
      { id: 'USN-9002-1', modified: hoursAgo(1) },
      { id: 'USN-9001-1', modified: hoursAgo(5) },
      { id: 'USN-1000-1', modified: '2025-01-01T00:00:00Z' },
    ];
    const spy = serveBucket(list, { 'USN-9002-1': usn('USN-9002-1', list[0].modified), 'USN-9001-1': usn('USN-9001-1', list[1].modified), 'USN-1000-1': usn('USN-1000-1', list[2].modified) });

    const result = await importOSVEcosystemDelta('Ubuntu', new Date(Date.now() - 24 * 60 * 60 * 1000));

    expect(result).toMatchObject({ total: 3, skipped: 1, inserted: 2, failed: 0 });
    expect(await prisma.oSVVulnerability.count({ where: { osvId: { in: ['USN-9002-1', 'USN-9001-1'] } } })).toBe(2);
    expect(await prisma.oSVVulnerability.count({ where: { osvId: 'USN-1000-1' } })).toBe(0);
    const urls = spy.mock.calls.map((c) => String(c[0]));
    expect(urls.some((u) => u.endsWith('all.zip'))).toBe(false);
    expect(urls.filter((u) => u.endsWith('.json'))).toHaveLength(2);
  });

  it('counts a record that cannot be fetched as failed and goes on with the rest', async () => {
    const list = [{ id: 'USN-9002-1', modified: hoursAgo(1) }, { id: 'USN-9001-1', modified: hoursAgo(2) }];
    serveBucket(list, { 'USN-9001-1': usn('USN-9001-1', list[1].modified) });

    const result = await importOSVEcosystemDelta('Ubuntu', new Date(Date.now() - 24 * 60 * 60 * 1000));

    expect(result).toMatchObject({ inserted: 1, failed: 1 });
  });

  it('fails the job when the newest entry of the list is old, as the per-release Ubuntu buckets were from 2024-10-09', async () => {
    serveBucket([{ id: 'USN-6000-1', modified: '2024-10-09T02:28:48Z' }], { 'USN-6000-1': usn('USN-6000-1', '2024-10-09T02:28:48Z') });

    await expect(importOSVEcosystemDelta('Ubuntu', new Date('2024-01-01T00:00:00Z'))).rejects.toThrow(
      /listed 1 records and imported 1, but the newest record in the OSV bucket "Ubuntu" is \d+ days old/,
    );
  });

  it('fails the job when the list is missing (404)', async () => {
    serveBucket([], {});
    vi.spyOn(axios, 'get').mockRejectedValue(Object.assign(new Error('Request failed with status code 404'), { isAxiosError: true, response: { status: 404 } }));
    vi.spyOn(axios, 'isAxiosError').mockReturnValue(true);

    await expect(importOSVEcosystemDelta('Ubuntu', new Date(0))).rejects.toThrow(/OSV has no bucket "Ubuntu"/);
  });
});

// Some records are named by their CVE and list no aliases (the Debian ecosystem
// has a few hundred). Read only from the aliases, they got no CVE and a master
// row of their own beside the CVE's.
describe('importOSVData — a record named by its CVE', () => {
  beforeEach(async () => {
    await resetDb();
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  it('joins the CVE master that NVD made, with no master of its own', async () => {
    const cve = await prisma.vulnerability.create({ data: { cveId: 'CVE-2023-53025', severity: 'HIGH', cvssScore: 7.8 } });

    await importOSVData(makeOsv({
      id: 'CVE-2023-53025',
      aliases: [],
      affected: [{ package: { ecosystem: 'Debian:11', name: 'linux' } }],
    }));

    const osv = await prisma.oSVVulnerability.findUnique({ where: { osvId: 'CVE-2023-53025' } });
    expect(osv?.cveId).toBe('CVE-2023-53025');
    expect(osv?.masterVulnId).toBe(cve.id);
    expect(await prisma.vulnerability.findUnique({ where: { osvId: 'CVE-2023-53025' } })).toBeNull();
    // The CVE master keeps its own rating.
    const master = await prisma.vulnerability.findUnique({ where: { id: cve.id } });
    expect(master).toMatchObject({ severity: 'HIGH', cvssScore: 7.8 });
  });

  it('does not take an id that only starts like one for a CVE', async () => {
    await importOSVData(makeOsv({ id: 'CVE-NOT-A-CVE', aliases: [] }));
    const osv = await prisma.oSVVulnerability.findUnique({ where: { osvId: 'CVE-NOT-A-CVE' } });
    expect(osv?.cveId).toBeNull();
  });
});

describe('moveOsvRecordsOntoTheirCve — records imported before the fix', () => {
  beforeEach(async () => {
    await resetDb();
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  it('moves the record and the rows on its master onto the CVE master, and deletes the twin', async () => {
    const { moveOsvRecordsOntoTheirCve } = await import('./osv-own-cve-ids.js');
    const cve = await prisma.vulnerability.create({ data: { cveId: 'CVE-2023-53025', severity: 'HIGH', cvssScore: 7.8, epssScore: 0.01 } });
    // The state the old importer left: a master keyed by the CVE as an osvId,
    // made from the record (so the record's rawData holds all the twin had).
    const twin = await prisma.vulnerability.create({ data: { osvId: 'CVE-2023-53025', summary: 'from Debian' } });
    const osv = await prisma.oSVVulnerability.create({
      data: {
        osvId: 'CVE-2023-53025', cveId: null, source: 'osv', ecosystem: 'Debian:11', aliases: [],
        rawData: { id: 'CVE-2023-53025', modified: '2026-01-01T00:00:00Z', aliases: [], summary: 'from Debian' },
        masterVulnId: twin.id,
      },
    });

    const first = await moveOsvRecordsOntoTheirCve();
    expect(first).toEqual({ moved: 1, skipped: 0 });

    const after = await prisma.oSVVulnerability.findUnique({ where: { id: osv.id } });
    expect(after).toMatchObject({ cveId: 'CVE-2023-53025', masterVulnId: cve.id });
    expect(await prisma.vulnerability.findUnique({ where: { id: twin.id } })).toBeNull();
    // The CVE master keeps its values and gains only what it lacked.
    const master = await prisma.vulnerability.findUnique({ where: { id: cve.id } });
    expect(master).toMatchObject({ severity: 'HIGH', cvssScore: 7.8, epssScore: 0.01, summary: 'from Debian' });

    // Run again: nothing left to do.
    expect(await moveOsvRecordsOntoTheirCve()).toEqual({ moved: 0, skipped: 0 });
  });

  it('turns the record into the CVE master when the CVE has none yet', async () => {
    const { moveOsvRecordsOntoTheirCve } = await import('./osv-own-cve-ids.js');
    const twin = await prisma.vulnerability.create({ data: { osvId: 'CVE-2024-0001' } });
    await prisma.oSVVulnerability.create({
      data: {
        osvId: 'CVE-2024-0001', cveId: null, source: 'osv', ecosystem: 'Debian:12', aliases: [],
        rawData: { id: 'CVE-2024-0001', modified: '2026-01-01T00:00:00Z' },
        masterVulnId: twin.id,
      },
    });

    await moveOsvRecordsOntoTheirCve();

    const master = await prisma.vulnerability.findUnique({ where: { cveId: 'CVE-2024-0001' } });
    expect(master).not.toBeNull();
    expect(await prisma.vulnerability.findUnique({ where: { osvId: 'CVE-2024-0001' } })).toBeNull();
    const osv = await prisma.oSVVulnerability.findUnique({ where: { osvId: 'CVE-2024-0001' } });
    expect(osv?.masterVulnId).toBe(master?.id);
  });
});

// One vulnerability published under several ids with no CVE used to get a
// master per id, and a search reports one finding per master.
describe('importOSVData — aliased records without a CVE share one master', () => {
  beforeEach(async () => {
    await resetDb();
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  const pkg = [{ package: { ecosystem: 'PyPI', name: 'certifi' }, versions: ['2026.1.1'] }];

  it('keys the master by GHSA whichever record comes first', async () => {
    await importOSVData(makeOsv({ id: 'PYSEC-2026-4320', aliases: ['GHSA-6q48-6c7w-9gw2'], affected: pkg }));
    await importOSVData(makeOsv({ id: 'GHSA-6q48-6c7w-9gw2', aliases: ['PYSEC-2026-4320'], affected: pkg, summary: 'from GHSA' }));

    const masters = await prisma.vulnerability.findMany();
    expect(masters).toHaveLength(1);
    expect(masters[0]).toMatchObject({ osvId: 'GHSA-6q48-6c7w-9gw2', summary: 'from GHSA' });
    const rows = await prisma.oSVVulnerability.findMany({ select: { masterVulnId: true } });
    expect(rows.every((r) => r.masterVulnId === masters[0].id)).toBe(true);
  });

  it('ranks the source id above MAL', async () => {
    await importOSVData(makeOsv({ id: 'MAL-2025-6794', aliases: ['PYSEC-2025-72'], affected: pkg }));
    await importOSVData(makeOsv({ id: 'PYSEC-2025-72', aliases: ['MAL-2025-6794'], affected: pkg }));
    const masters = await prisma.vulnerability.findMany();
    expect(masters.map((m) => m.osvId)).toEqual(['PYSEC-2025-72']);
  });

  it('keeps its own id when the better ranked alias is not in the database', async () => {
    await importOSVData(makeOsv({ id: 'PYSEC-2026-1', aliases: ['GHSA-not-imported'], affected: pkg }));
    const masters = await prisma.vulnerability.findMany();
    expect(masters.map((m) => m.osvId)).toEqual(['PYSEC-2026-1']);
  });

  it('joins the CVE master of an aliased record that knows its CVE', async () => {
    await importOSVData(makeOsv({ id: 'GHSA-with-cve1', aliases: ['CVE-2026-7001'], affected: pkg }));
    await importOSVData(makeOsv({ id: 'MAL-2026-1', aliases: ['GHSA-with-cve1'], affected: pkg }));

    const cve = await prisma.vulnerability.findUnique({ where: { cveId: 'CVE-2026-7001' } });
    const mal = await prisma.oSVVulnerability.findUnique({ where: { osvId: 'MAL-2026-1' } });
    expect(mal?.masterVulnId).toBe(cve?.id);
    expect(await prisma.vulnerability.count()).toBe(1);
  });
});

describe('mergeOsvAliasGroups and pruneOrphanOsvMasters — data imported before', () => {
  beforeEach(async () => {
    await resetDb();
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  it('folds an aliased pair onto one master keyed by GHSA, once', async () => {
    const { mergeOsvAliasGroups } = await import('./osv-alias-groups.js');
    // The state the old importer left: one master per id.
    const pysecMaster = await prisma.vulnerability.create({ data: { osvId: 'PYSEC-2026-4320' } });
    const ghsaMaster = await prisma.vulnerability.create({ data: { osvId: 'GHSA-6q48-6c7w-9gw2', severity: 'HIGH' } });
    const raw = (id: string, alias: string) => ({ id, modified: '2026-01-01T00:00:00Z', aliases: [alias] });
    await prisma.oSVVulnerability.create({ data: { osvId: 'PYSEC-2026-4320', source: 'osv', aliases: ['GHSA-6q48-6c7w-9gw2'], rawData: raw('PYSEC-2026-4320', 'GHSA-6q48-6c7w-9gw2'), masterVulnId: pysecMaster.id } });
    await prisma.oSVVulnerability.create({ data: { osvId: 'GHSA-6q48-6c7w-9gw2', source: 'osv', aliases: ['PYSEC-2026-4320'], rawData: raw('GHSA-6q48-6c7w-9gw2', 'PYSEC-2026-4320'), masterVulnId: ghsaMaster.id } });

    expect((await mergeOsvAliasGroups()).records).toBeGreaterThan(0);

    const masters = await prisma.vulnerability.findMany();
    expect(masters).toHaveLength(1);
    expect(masters[0]).toMatchObject({ id: ghsaMaster.id, osvId: 'GHSA-6q48-6c7w-9gw2', severity: 'HIGH' });
    expect(await mergeOsvAliasGroups()).toEqual({ records: 0 });
  });

  it('deletes a master keyed by an OSV id that no record points at, and keeps the rest', async () => {
    const { pruneOrphanOsvMasters } = await import('./osv-alias-groups.js');
    await prisma.vulnerability.create({ data: { osvId: 'RHEA-2024:5245', severity: 'HIGH' } });
    await importOSVData(makeOsv({ id: 'GHSA-kept-0001' }));
    await prisma.vulnerability.create({ data: { cveId: 'CVE-2026-7002' } });

    expect(await pruneOrphanOsvMasters()).toEqual({ deleted: 1 });
    expect(await prisma.vulnerability.findUnique({ where: { osvId: 'RHEA-2024:5245' } })).toBeNull();
    expect(await prisma.vulnerability.findUnique({ where: { osvId: 'GHSA-kept-0001' } })).not.toBeNull();
    expect(await prisma.vulnerability.findUnique({ where: { cveId: 'CVE-2026-7002' } })).not.toBeNull();
  });
});
