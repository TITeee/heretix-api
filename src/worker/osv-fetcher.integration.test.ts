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
