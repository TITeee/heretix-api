/**
 * One-time migration: delete Vulnerability master rows keyed only by advisoryId
 * (no cveId, no osvId) that no AdvisoryVulnerability row references anymore.
 *
 * Background:
 *   These are placeholders importAdvisoryData() created for an advisory before it
 *   had a CVE. Once a CVE was assigned, the advisory's own row was repointed to a
 *   new (or existing) cveId-keyed master, leaving the placeholder behind with
 *   nothing pointing at it. importAdvisoryData() now cleans this up going forward
 *   at the moment of reassignment; this backfills the rows that were already
 *   orphaned before that fix existed.
 *
 *   Safe to delete: GET /vulnerabilities/:id falls back to
 *   AdvisoryVulnerability.externalId directly when no master row matches by id,
 *   so a lookup by one of these placeholders' advisoryId still resolves through
 *   the advisory's current master — none of these rows are the only way left to
 *   reach anything.
 *
 * Usage:
 *   pnpm migrate:prune-orphaned-advisory-masters
 */
import 'dotenv/config';
import { prisma } from '../db/client.js';

async function main() {
  const candidates = await prisma.vulnerability.findMany({
    where: { cveId: null, osvId: null, advisoryId: { not: null } },
    select: { id: true, advisoryId: true },
  });

  console.log(`Found ${candidates.length} advisoryId-only master row(s) to check.`);

  let deleted = 0;
  let skipped = 0;

  for (const row of candidates) {
    const refCount = await prisma.advisoryVulnerability.count({ where: { masterVulnId: row.id } });
    if (refCount > 0) {
      skipped++;
      continue;
    }
    await prisma.vulnerability.delete({ where: { id: row.id } });
    deleted++;
  }

  console.log(`Done: ${deleted} orphaned master row(s) deleted, ${skipped} still referenced and left alone.`);
}

main()
  .catch((err) => {
    console.error(err);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
