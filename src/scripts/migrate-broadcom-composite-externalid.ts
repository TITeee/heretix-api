/**
 * One-time migration: clear out old-format Broadcom advisory rows ahead of
 * the composite-externalId fix.
 *
 * broadcom-fetcher.ts used to emit one AdvisoryVulnerability per VMSA
 * (externalId = the VMSA id, e.g. "VMSA-2026-0006") keeping only the first
 * CVE when a VMSA bundled several -- see buildBroadcomAdvisories(). It now
 * emits one row per CVE with a composite externalId ("VMSA-2026-0006/CVE-...",
 * matching the pattern already used by redhat-fetcher.ts / oracle-linux-fetcher.ts).
 *
 * Rows in the old plain-VMSA-id format that also carry a cveId are exactly
 * the ones the new code replaces with one-or-more composite-id rows. Left in
 * place, isCompleteSnapshot() pruning would eventually remove them, but only
 * after 3 consecutive runs -- so old and new rows would show up side by side
 * in search results in the meantime. Delete them now instead. (Rows with no
 * CVE at all keep the plain VMSA id unchanged by the fetcher fix and are not
 * touched here. AdvisoryAffectedProduct cascades; the linked Vulnerability
 * master row is untouched since these all have a cveId, so pruneStaleAdvisories's
 * "unlink was the sole owner" condition never applied to them anyway.)
 *
 * Usage:
 *   pnpm migrate:broadcom-composite-externalid
 */
import 'dotenv/config';
import { prisma } from '../db/client.js';

async function main() {
  const stale = await prisma.advisoryVulnerability.findMany({
    where: {
      source: 'advisory-broadcom',
      cveId: { not: null },
      externalId: { not: { contains: '/' } },
    },
    select: { id: true, externalId: true },
  });

  console.log(`Found ${stale.length} old-format Broadcom advisory rows to remove.`);
  if (stale.length === 0) {
    console.log('Nothing to do.');
    await prisma.$disconnect();
    return;
  }

  const result = await prisma.advisoryVulnerability.deleteMany({
    where: { id: { in: stale.map(r => r.id) } },
  });
  console.log(`Deleted ${result.count} rows (AdvisoryAffectedProduct cascaded). They'll be recreated in composite form on the next Broadcom fetch.`);

  await prisma.$disconnect();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
