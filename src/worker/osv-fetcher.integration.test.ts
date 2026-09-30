import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import { prisma } from '../db/client.js';
import { resetDb } from '../test-utils/db.js';
import { importOSVData } from './osv-fetcher.js';

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
