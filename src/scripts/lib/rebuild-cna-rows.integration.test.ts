import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import { prisma } from '../../db/client.js';
import { resetDb } from '../../test-utils/db.js';
import { rebuildCnaRows } from './rebuild-cna-rows.js';

describe('rebuildCnaRows: the ends heretix set on open ranges', () => {
  beforeEach(async () => {
    await resetDb();
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  it('marks the rows stored before noFix existed, and leaves a record already right alone', async () => {
    const rawAffected = [{
      vendor: 'F5', product: 'BIG-IP',
      versions: [
        { version: '17.5.0', lessThan: '*', status: 'affected', versionType: 'custom' },
        { version: '17.1.0', lessThan: '*', status: 'affected', versionType: 'custom' },
      ],
    }];
    const master = await prisma.vulnerability.create({ data: { cveId: 'CVE-2026-7501' } });
    const rec = await prisma.cnaVulnerability.create({
      data: { cveId: 'CVE-2026-7501', cnaShortName: 'f5', rawAffected, masterVulnId: master.id },
    });
    // As an earlier version stored them: the same ranges, unmarked.
    await prisma.cnaAffectedProduct.createMany({ data: [
      { vulnerabilityId: rec.id, vendor: 'F5', product: 'BIG-IP', versionType: 'custom', versionStart: '17.5.0' },
      { vulnerabilityId: rec.id, vendor: 'F5', product: 'BIG-IP', versionType: 'custom', versionStart: '17.1.0', versionEnd: '17.5.0' },
    ] });

    const records = [{ id: rec.id, cveId: rec.cveId, rawAffected }];
    expect(await rebuildCnaRows(records, false)).toEqual({ before: 2, after: 2, changed: 1 });
    const rows = await prisma.cnaAffectedProduct.findMany({ where: { vulnerabilityId: rec.id }, orderBy: { versionStart: 'asc' } });
    expect(rows.map(r => [r.versionStart, r.versionEnd, r.noFix])).toEqual([['17.1.0', '17.5.0', true], ['17.5.0', null, true]]);

    expect(await rebuildCnaRows(records, false)).toEqual({ before: 2, after: 2, changed: 0 });
  });

  it("stores F5's Engineering Hotfixes on the rows of a record stored before they were read", async () => {
    const rawAffected = [{
      vendor: 'F5', product: 'BIG-IP',
      versions: [{ version: '17.1.0', lessThan: '*', status: 'affected', versionType: 'custom',
        changes: [{ at: 'BIGIP-17.1.3.7.0.21.4-ENG', status: 'unaffected' }] }],
    }];
    const master = await prisma.vulnerability.create({ data: { cveId: 'CVE-2026-7502' } });
    const rec = await prisma.cnaVulnerability.create({
      data: { cveId: 'CVE-2026-7502', cnaShortName: 'f5', rawAffected, masterVulnId: master.id },
    });
    await prisma.cnaAffectedProduct.create({
      data: { vulnerabilityId: rec.id, vendor: 'F5', product: 'BIG-IP', versionType: 'custom', versionStart: '17.1.0', noFix: true },
    });

    expect((await rebuildCnaRows([{ id: rec.id, cveId: rec.cveId, rawAffected }], false)).changed).toBe(1);
    const [row] = await prisma.cnaAffectedProduct.findMany({ where: { vulnerabilityId: rec.id } });
    expect(row.hotfixes).toEqual(['BIGIP-17.1.3.7.0.21.4-ENG']);
  });
});
