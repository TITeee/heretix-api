import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import { prisma } from '../db/client.js';
import { resetDb } from '../test-utils/db.js';
import { importAdvisoryData, type NormalizedAdvisory } from './advisory-fetcher.js';

function makeAdvisory(overrides: Partial<NormalizedAdvisory> = {}): NormalizedAdvisory {
  return {
    externalId: 'FG-IR-26-001',
    summary: 'Test advisory',
    severity: 'HIGH',
    cvssScore: 7.5,
    affectedProducts: [
      { vendor: 'fortinet', product: 'FortiOS', versionStart: '7.0.0', versionEnd: '7.0.5' },
    ],
    rawData: { raw: true },
    ...overrides,
  };
}

describe('importAdvisoryData', () => {
  beforeEach(async () => {
    await resetDb();
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  it('creates a master row and affected products on first import (no CVE)', async () => {
    const result = await importAdvisoryData(makeAdvisory(), 'fortinet');
    expect(result).toBe('inserted');

    const master = await prisma.vulnerability.findUnique({ where: { advisoryId: 'FG-IR-26-001' } });
    expect(master).not.toBeNull();
    expect(master?.severity).toBe('HIGH');

    const advisory = await prisma.advisoryVulnerability.findUnique({
      where: { source_externalId: { source: 'fortinet', externalId: 'FG-IR-26-001' } },
      include: { affectedProducts: true },
    });
    expect(advisory?.masterVulnId).toBe(master?.id);
    expect(advisory?.affectedProducts).toHaveLength(1);
    expect(advisory?.affectedProducts[0].product).toBe('FortiOS');
  });

  it('updates on re-import and replaces affected products (delete-then-recreate)', async () => {
    await importAdvisoryData(makeAdvisory(), 'fortinet');

    const updated = makeAdvisory({
      severity: 'CRITICAL',
      affectedProducts: [
        { vendor: 'fortinet', product: 'FortiOS', versionStart: '7.0.0', versionEnd: '7.0.9' },
        { vendor: 'fortinet', product: 'FortiProxy', versionStart: '7.2.0', versionEnd: '7.2.3' },
      ],
    });
    const result = await importAdvisoryData(updated, 'fortinet');
    expect(result).toBe('updated');

    const advisory = await prisma.advisoryVulnerability.findUnique({
      where: { source_externalId: { source: 'fortinet', externalId: 'FG-IR-26-001' } },
      include: { affectedProducts: true },
    });
    expect(advisory?.severity).toBe('CRITICAL');
    // Old single-product row must be gone, replaced by the new two-product set.
    expect(advisory?.affectedProducts).toHaveLength(2);
    expect(advisory?.affectedProducts.map(p => p.product).sort()).toEqual(['FortiOS', 'FortiProxy']);
  });

  it('links to an existing NVD-created master row instead of creating a new one when cveId matches', async () => {
    const nvdMaster = await prisma.vulnerability.create({
      data: { cveId: 'CVE-2026-1111', severity: 'CRITICAL', cvssScore: 9.8 },
    });

    const adv = makeAdvisory({ cveId: 'CVE-2026-1111' });
    await importAdvisoryData(adv, 'fortinet');

    const advisory = await prisma.advisoryVulnerability.findUnique({
      where: { source_externalId: { source: 'fortinet', externalId: 'FG-IR-26-001' } },
    });
    expect(advisory?.masterVulnId).toBe(nvdMaster.id);

    // NVD's authoritative severity must not be overwritten by the advisory import.
    const master = await prisma.vulnerability.findUnique({ where: { id: nvdMaster.id } });
    expect(master?.severity).toBe('CRITICAL');

    const allMasters = await prisma.vulnerability.count();
    expect(allMasters).toBe(1);
  });

  it('creates a placeholder master row when cveId is present but no NVD record exists yet', async () => {
    const adv = makeAdvisory({ cveId: 'CVE-2026-2222' });
    await importAdvisoryData(adv, 'fortinet');

    const master = await prisma.vulnerability.findUnique({ where: { cveId: 'CVE-2026-2222' } });
    expect(master).not.toBeNull();
    expect(master?.severity).toBe('HIGH');
  });

  it('upserts by advisoryId when no CVE is present, without creating duplicate master rows', async () => {
    await importAdvisoryData(makeAdvisory(), 'fortinet');
    await importAdvisoryData(makeAdvisory({ severity: 'LOW' }), 'fortinet');

    const masters = await prisma.vulnerability.findMany({ where: { advisoryId: 'FG-IR-26-001' } });
    expect(masters).toHaveLength(1);
    expect(masters[0].severity).toBe('LOW');
  });
});
