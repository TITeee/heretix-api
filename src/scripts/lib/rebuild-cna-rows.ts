import { prisma } from '../../db/client.js';
import { extractCnaRows } from '../../worker/cna-fetcher.js';
import { normalizeVersion } from '../../utils/version.js';

export interface CnaRecord { id: string; cveId: string; rawAffected: unknown }

type RowLike = {
  vendor: string; product: string; packageName?: string | null; versionType?: string | null;
  versionStart?: string | null; versionEnd?: string | null; lastAffected?: string | null; affectedVersions?: string[] | null;
};

// A row's identity for comparing what is stored with what the extractor makes now: a range can
// change its end alone, so the count is not enough.
const keyOf = (row: RowLike) =>
  JSON.stringify([
    row.vendor, row.product, row.packageName ?? null, row.versionType ?? null,
    row.versionStart ?? null, row.versionEnd ?? null, row.lastAffected ?? null, [...(row.affectedVersions ?? [])].sort(),
  ]);

/**
 * Replace the CnaAffectedProduct rows of each record with what extractCnaRows() makes of its
 * stored declaration now, for the records whose rows differ. A record whose rows are already
 * right is not rewritten, which keeps a start-up short when the selection is wide (the Linux
 * kernel's ten thousand records match the wildcard patterns and never change). The
 * CnaVulnerability rows are untouched: their rawAffected is the input.
 */
export async function rebuildCnaRows(records: CnaRecord[], dryRun: boolean): Promise<{ before: number; after: number; changed: number }> {
  let before = 0;
  let after = 0;
  let changed = 0;

  for (const rec of records) {
    const { rows } = extractCnaRows(rec.rawAffected);
    const stored = await prisma.cnaAffectedProduct.findMany({ where: { vulnerabilityId: rec.id } });
    before += stored.length;
    after += rows.length;
    const storedKeys = stored.map(keyOf).sort();
    const nextKeys = rows.map(keyOf).sort();
    if (storedKeys.length === nextKeys.length && storedKeys.every((k, i) => k === nextKeys[i])) continue;
    changed++;
    if (dryRun) continue;

    await prisma.$transaction(async (tx) => {
      await tx.cnaAffectedProduct.deleteMany({ where: { vulnerabilityId: rec.id } });
      if (rows.length === 0) return;
      await tx.cnaAffectedProduct.createMany({
        data: rows.map(row => ({
          vulnerabilityId: rec.id,
          vendor: row.vendor,
          product: row.product,
          packageName: row.packageName ?? null,
          versionType: row.versionType ?? null,
          versionStart: row.versionStart ?? null,
          versionEnd: row.versionEnd ?? null,
          lastAffected: row.lastAffected ?? null,
          versionStartInt: row.versionStart ? (normalizeVersion(row.versionStart) ?? null) : null,
          versionEndInt: row.versionEnd ? (normalizeVersion(row.versionEnd) ?? null) : null,
          lastAffectedInt: row.lastAffected ? (normalizeVersion(row.lastAffected) ?? null) : null,
          affectedVersions: row.affectedVersions ?? [],
        })),
      });
    });
  }

  return { before, after, changed };
}
