import { prisma } from '../db/client.js';
import { upsertMasterFromOSV, type OSVVulnerability } from './osv-fetcher.js';

/**
 * Bring each group of aliased OSV records that names no CVE onto one master, for
 * the records imported before importOSVData() did so (see upsertAliasGroupMaster).
 *
 * The candidates are the CVE-less records with an alias whose record hangs off
 * another master. Each goes through upsertMasterFromOSV() again, which folds the
 * group's masters into one. Idempotent: once a group shares a master, none of
 * its records is a candidate.
 */
export async function mergeOsvAliasGroups(): Promise<{ records: number }> {
  const candidates = await prisma.$queryRaw<{ id: string; osvId: string; rawData: unknown }[]>`
    SELECT o.id, o."osvId", o."rawData"
    FROM "OSVVulnerability" o
    WHERE o."cveId" IS NULL AND EXISTS (
      SELECT 1 FROM jsonb_array_elements_text(coalesce(o.aliases, '[]'::jsonb)) AS al(a)
      JOIN "OSVVulnerability" t ON t."osvId" = al.a
      WHERE t."masterVulnId" IS DISTINCT FROM o."masterVulnId")
    ORDER BY o."osvId"`;

  let records = 0;
  for (const row of candidates) {
    const osvData = { ...(row.rawData as OSVVulnerability), id: row.osvId };
    await prisma.$transaction(async (tx) => {
      // Re-read: an earlier record of the same group may have merged this one already.
      const current = await tx.oSVVulnerability.findUnique({ where: { id: row.id }, select: { cveId: true } });
      if (!current || current.cveId) return;
      await upsertMasterFromOSV(tx, { id: row.id, cveId: null, osvId: row.osvId }, osvData);
    });
    records++;
  }
  return { records };
}

/**
 * Delete masters keyed by an OSV id that no record points at any more. They are
 * left when OSV records are removed outside the importer (an ecosystem's records
 * deleted by hand once it was refused, Red Hat on one install), and still answer
 * a lookup by that id with data nothing backs.
 */
export async function pruneOrphanOsvMasters(): Promise<{ deleted: number }> {
  const { count } = await prisma.vulnerability.deleteMany({
    where: {
      cveId: null,
      advisoryId: null,
      osvId: { not: null },
      osvVulnerabilities: { none: {} },
      advisoryVulnerabilities: { none: {} },
      // No condition on NVD or CNA rows: they hang off CVE-keyed masters only, so a
      // master with no cveId has none. Prisma writes `nvdVulnerability: { is: null }` as
      // NOT IN (SELECT ...), which PostgreSQL could not hash over 435,000 NVD rows: it
      // compared each of 88,000 candidates against all of them, for hours, while the
      // server waited for this migration to start.
    },
  });
  return { deleted: count };
}
