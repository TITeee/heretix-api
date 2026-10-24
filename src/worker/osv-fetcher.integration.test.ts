import { describe, it, expect, beforeEach, afterEach, afterAll, vi } from 'vitest';
import axios from 'axios';
import AdmZip from 'adm-zip';
import { prisma } from '../db/client.js';
import { resetDb } from '../test-utils/db.js';
import { importOSVData, importOSVEcosystemDelta, importMALDelta } from './osv-fetcher.js';

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

describe('importMALDelta — the files changed in the commits since the last run', () => {
  const API = 'https://api.github.com/repos/ossf/malicious-packages';
  const RAW = 'https://raw.githubusercontent.com/ossf/malicious-packages';
  const mal = (id: string, name: string) => makeOsv({
    id,
    modified: '2026-10-23T00:00:00Z',
    aliases: [],
    affected: [{ package: { ecosystem: 'npm', name }, versions: ['1.0.0'] }],
  });

  type Commit = { sha: string; files: Array<{ filename: string; status: string; previous_filename?: string }> };

  /** A repository with these commits, newest first the way GitHub lists them. */
  function serveRepo(commits: Commit[], records: Record<string, unknown>, rateLimit?: { failures: number }) {
    let limited = rateLimit?.failures ?? 0;
    return vi.spyOn(axios, 'get').mockImplementation(async (url: string) => {
      if (limited > 0 && url.startsWith(API)) {
        limited--;
        throw Object.assign(new Error('rate limited'), { isAxiosError: true, response: { status: 403, headers: { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': String(Math.floor(Date.now() / 1000)) } } });
      }
      if (url.startsWith(`${API}/commits?`)) {
        const page = Number(new URL(url).searchParams.get('page'));
        return { data: commits.slice((page - 1) * 100, page * 100).map((c) => ({ sha: c.sha })) };
      }
      const commit = url.match(new RegExp(`^${API}/commits/([0-9a-z]+)[?]`));
      if (commit) {
        const page = Number(new URL(url).searchParams.get('page'));
        return { data: { files: commits.find((c) => c.sha === commit[1])!.files.slice((page - 1) * 100, page * 100) } };
      }
      const raw = url.match(new RegExp(`^${RAW}/[0-9a-z]+/(.+)$`));
      if (raw && records[raw[1]]) return { data: records[raw[1]] };
      throw Object.assign(new Error('Request failed with status code 404'), { isAxiosError: true, response: { status: 404, headers: {} } });
    });
  }

  beforeEach(async () => {
    await resetDb();
    vi.spyOn(axios, 'isAxiosError').mockImplementation((e: unknown) => !!(e as { isAxiosError?: boolean })?.isAxiosError);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('imports the files the commits added or changed, and no other file of the repository', async () => {
    const calls = serveRepo(
      [
        { sha: 'c3', files: [{ filename: 'osv/malicious/npm/b/MAL-2026-2.json', status: 'modified' }, { filename: 'README.md', status: 'modified' }] },
        { sha: 'c2', files: [{ filename: 'osv/malicious/pypi/a/MAL-2026-1.json', status: 'added' }] },
      ],
      { 'osv/malicious/pypi/a/MAL-2026-1.json': mal('MAL-2026-1', 'a'), 'osv/malicious/npm/b/MAL-2026-2.json': mal('MAL-2026-2', 'b'), 'osv/malicious/npm/c/MAL-2026-3.json': mal('MAL-2026-3', 'c') },
    );

    const result = await importMALDelta(new Date('2026-10-22T00:00:00Z'));

    expect(result).toMatchObject({ total: 2, inserted: 2, failed: 0 });
    expect(await prisma.oSVVulnerability.count({ where: { osvId: { in: ['MAL-2026-1', 'MAL-2026-2'] } } })).toBe(2);
    expect(await prisma.oSVVulnerability.count({ where: { osvId: 'MAL-2026-3' } })).toBe(0);
    // Pinned to the newest commit, and the repository's file tree is never read.
    const urls = calls.mock.calls.map((c) => String(c[0]));
    expect(urls.some((u) => u.includes('/git/trees'))).toBe(false);
    expect(urls.filter((u) => u.startsWith(RAW)).every((u) => u.includes('/c3/'))).toBe(true);
  });

  it('leaves out a file that a later commit removed, and follows a rename', async () => {
    serveRepo(
      [
        { sha: 'c3', files: [{ filename: 'osv/malicious/npm/z/MAL-2026-9.json', status: 'renamed', previous_filename: 'osv/malicious/npm/y/MAL-2026-9.json' }] },
        { sha: 'c2', files: [{ filename: 'osv/malicious/npm/x/MAL-2026-8.json', status: 'removed' }] },
        { sha: 'c1', files: [{ filename: 'osv/malicious/npm/x/MAL-2026-8.json', status: 'added' }, { filename: 'osv/malicious/npm/y/MAL-2026-9.json', status: 'added' }] },
      ],
      { 'osv/malicious/npm/z/MAL-2026-9.json': mal('MAL-2026-9', 'z') },
    );

    const result = await importMALDelta(new Date('2026-10-22T00:00:00Z'));

    expect(result).toMatchObject({ total: 1, inserted: 1, failed: 0 });
  });

  it('reads every page of the commit list and of the files of a commit, not the first 100 or 300', async () => {
    const many = Array.from({ length: 250 }, (_, i) => ({ filename: `osv/malicious/npm/p${i}/MAL-2026-${1000 + i}.json`, status: 'added' }));
    const records = Object.fromEntries(many.map((f, i) => [f.filename, mal(`MAL-2026-${1000 + i}`, `p${i}`)]));
    const filler = Array.from({ length: 120 }, (_, i) => ({ sha: `f${i}`, files: [] as Commit['files'] }));
    serveRepo([...filler, { sha: 'big', files: many }], records);

    const result = await importMALDelta(new Date('2026-10-22T00:00:00Z'));

    expect(result).toMatchObject({ total: 250, inserted: 250, failed: 0 });
  });

  it('waits out GitHub\'s rate limit and goes on, rather than failing or skipping', async () => {
    serveRepo(
      [{ sha: 'c1', files: [{ filename: 'osv/malicious/npm/a/MAL-2026-5.json', status: 'added' }] }],
      { 'osv/malicious/npm/a/MAL-2026-5.json': mal('MAL-2026-5', 'a') },
      { failures: 2 },
    );
    // The limit "resets" now, so each of the two refusals costs the one second the run adds to be sure.
    expect(await importMALDelta(new Date('2026-10-22T00:00:00Z'))).toMatchObject({ total: 1, inserted: 1 });
  });

  it('fails the run when a file cannot be read, and counts it', async () => {
    serveRepo([{ sha: 'c1', files: [{ filename: 'osv/malicious/npm/a/MAL-2026-6.json', status: 'added' }] }], {});

    expect(await importMALDelta(new Date('2026-10-22T00:00:00Z'))).toMatchObject({ total: 1, inserted: 0, failed: 1 });
  });

  it('finds nothing to do when no commit was made since', async () => {
    serveRepo([], {});
    expect(await importMALDelta(new Date('2026-10-22T00:00:00Z'))).toMatchObject({ total: 0, inserted: 0, failed: 0 });
  });
});
