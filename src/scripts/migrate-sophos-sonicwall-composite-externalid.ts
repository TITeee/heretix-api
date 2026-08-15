/**
 * One-time migration: clear out old-format Sophos/SonicWall advisory rows
 * ahead of the composite-externalId fix.
 *
 * Both fetchers used to emit one AdvisoryVulnerability per advisory page
 * (externalId = the sitemap id / advisory_id) keeping only the first CVE
 * when a page bundled several. They now emit one row per CVE with a
 * composite externalId ("sophos-sa-.../CVE-...", "SNWLID-2026-0001/CVE-..."),
 * matching the pattern already used by redhat-fetcher.ts / oracle-linux-fetcher.ts
 * / broadcom-fetcher.ts (see migrate-broadcom-composite-externalid.ts for the
 * same migration applied to Broadcom).
 *
 * Rows in the old plain-id format that also carry a cveId are exactly the
 * ones the new code replaces with one-or-more composite-id rows. Delete them
 * now rather than waiting out isCompleteSnapshot() pruning (3 runs), so old
 * and new rows don't show up side by side in search results in the
 * meantime. (Rows with no CVE at all keep the plain id unchanged by the
 * fetcher fix and are not touched here. AdvisoryAffectedProduct cascades;
 * the linked Vulnerability master row is untouched since these all have a
 * cveId.)
 *
 * Usage:
 *   pnpm migrate:sophos-sonicwall-composite-externalid
 */
import 'dotenv/config';
import { prisma } from '../db/client.js';

const SOURCES = ['advisory-sophos', 'advisory-sonicwall'];

async function main() {
  for (const source of SOURCES) {
    const stale = await prisma.advisoryVulnerability.findMany({
      where: {
        source,
        cveId: { not: null },
        externalId: { not: { contains: '/' } },
      },
      select: { id: true },
    });

    console.log(`[${source}] Found ${stale.length} old-format advisory rows to remove.`);
    if (stale.length === 0) continue;

    const result = await prisma.advisoryVulnerability.deleteMany({
      where: { id: { in: stale.map(r => r.id) } },
    });
    console.log(`[${source}] Deleted ${result.count} rows (AdvisoryAffectedProduct cascaded).`);
  }

  await prisma.$disconnect();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
