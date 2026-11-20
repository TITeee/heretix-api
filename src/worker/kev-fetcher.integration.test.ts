import { describe, it, expect, beforeEach } from 'vitest';
import { prisma } from '../db/client.js';
import { resetDb } from '../test-utils/db.js';
import { importKEVData } from './kev-fetcher.js';

const entry = (cveID: string, dateAdded = '2026-11-18') => ({
  cveID,
  vendorProject: 'Vendor',
  product: 'Product',
  vulnerabilityName: 'Name',
  dateAdded,
  shortDescription: 'Description',
  requiredAction: 'Apply updates',
  dueDate: '2026-12-09',
  knownRansomwareCampaignUse: 'Unknown',
  notes: '',
  cwes: [],
});

const kevOf = (cveId: string) =>
  prisma.vulnerability.findUnique({ where: { cveId }, select: { isKev: true, kevVendor: true } });

describe('importKEVData', () => {
  beforeEach(async () => {
    await resetDb();
  });

  it('flags the catalog entries that are in the master table and counts the rest as not found', async () => {
    await prisma.vulnerability.create({ data: { cveId: 'CVE-2026-0001' } });

    const result = await importKEVData([entry('CVE-2026-0001'), entry('CVE-2026-0002')]);

    expect(result).toEqual({ updated: 1, notFound: 1 });
    expect(await kevOf('CVE-2026-0001')).toEqual({ isKev: true, kevVendor: 'Vendor' });
  });

  it('clears an entry CISA has removed from the catalog', async () => {
    await prisma.vulnerability.create({ data: { cveId: 'CVE-2026-0001', isKev: true, kevVendor: 'Vendor' } });
    await prisma.vulnerability.create({ data: { cveId: 'CVE-2026-0002' } });

    await importKEVData([entry('CVE-2026-0002')]);

    expect(await kevOf('CVE-2026-0001')).toEqual({ isKev: false, kevVendor: null });
    expect((await kevOf('CVE-2026-0002'))?.isKev).toBe(true);
  });

  it('leaves the flags as they were when the import fails part way', async () => {
    await prisma.vulnerability.create({ data: { cveId: 'CVE-2026-0001', isKev: true, kevVendor: 'Vendor' } });
    await prisma.vulnerability.create({ data: { cveId: 'CVE-2026-0002' } });

    // An unreadable date makes the second write throw, after the reset has run.
    await expect(importKEVData([entry('CVE-2026-0002', 'not a date')])).rejects.toThrow();

    expect(await kevOf('CVE-2026-0001')).toEqual({ isKev: true, kevVendor: 'Vendor' });
    expect((await kevOf('CVE-2026-0002'))?.isKev).toBe(false);
  });
});
