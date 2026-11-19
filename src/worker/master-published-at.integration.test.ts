import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import { prisma } from '../db/client.js';
import { resetDb } from '../test-utils/db.js';
import { fillMissingPublishedAt } from './master-published-at.js';

const dateOf = async (cveId: string) =>
  (await prisma.vulnerability.findUnique({ where: { cveId } }))?.publishedAt?.toISOString() ?? null;

describe('fillMissingPublishedAt', () => {
  beforeEach(async () => {
    await resetDb();
    await prisma.cnaVulnerability.deleteMany();
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  async function master(cveId: string, publishedAt: string | null, nvd: string | null | undefined, cna: string | null | undefined) {
    const m = await prisma.vulnerability.create({ data: { cveId, publishedAt: publishedAt ? new Date(publishedAt) : null } });
    if (nvd !== undefined) {
      await prisma.nVDVulnerability.create({
        data: { cveId, source: 'nvd', rawData: {}, publishedAt: nvd ? new Date(nvd) : null, masterVulnId: m.id },
      });
    }
    if (cna !== undefined) {
      await prisma.cnaVulnerability.create({
        data: { cveId, cnaShortName: 'acme', datePublished: cna ? new Date(cna) : null, rawAffected: [], masterVulnId: m.id },
      });
    }
  }

  it("fills an empty date from NVD first, then from the CVE Record, and leaves set dates and dateless sources alone", async () => {
    await master('CVE-2026-1', null, '2026-11-18T16:18:04Z', '2026-11-18T15:23:29Z');
    await master('CVE-2026-2', null, undefined, '2026-11-17T10:00:00Z');
    await master('CVE-2026-3', null, null, '2026-11-16T10:00:00Z');
    await master('CVE-2026-4', '2020-01-01T00:00:00Z', '2026-11-18T00:00:00Z', undefined);
    await master('CVE-2026-5', null, null, null);

    expect(await fillMissingPublishedAt()).toEqual({ fromNvd: 1, fromCna: 2 });
    expect(await dateOf('CVE-2026-1')).toBe('2026-11-18T16:18:04.000Z');
    expect(await dateOf('CVE-2026-2')).toBe('2026-11-17T10:00:00.000Z');
    expect(await dateOf('CVE-2026-3')).toBe('2026-11-16T10:00:00.000Z');
    expect(await dateOf('CVE-2026-4')).toBe('2020-01-01T00:00:00.000Z');
    expect(await dateOf('CVE-2026-5')).toBeNull();

    // Run again: nothing left to do.
    expect(await fillMissingPublishedAt()).toEqual({ fromNvd: 0, fromCna: 0 });
  });
});
