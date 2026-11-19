/**
 * One-time migration: mark the CNA ranges whose end heretix set itself, so a search no
 * longer shows that end as the fixed version (CnaAffectedRow.noFix in cna-fetcher.ts).
 *
 * A range the CNA left open ("version: 17.1.0, lessThan: *", F5's way of saying no
 * release of the branch is fixed) ends where the record's next branch begins, and a
 * whole line ("22.2*", "11.2.*") ends where the next line begins. Both ends were
 * returned as fixedVersion: CVE-2026-123637's 17.1 branch said "fixed in 17.5.0", a
 * branch the same record lists as affected. This re-reads every CVE record whose stored
 * declaration has such a bound and rewrites its CnaAffectedProduct rows when they differ
 * from what the extractor makes now. Other CVEs are not touched.
 *
 * Idempotent: a record whose rows are already right is not rewritten.
 *
 * Usage:
 *   pnpm migrate:cna-no-fix-ends             # rewrite
 *   pnpm migrate:cna-no-fix-ends --dry-run   # count only
 */
import 'dotenv/config';
import { closeDb, prisma } from '../db/client.js';
import { rebuildCnaRows, type CnaRecord } from './lib/rebuild-cna-rows.js';

const dryRun = process.argv.includes('--dry-run');

async function main() {
  const records = await prisma.$queryRaw<CnaRecord[]>`
    SELECT id, "cveId", "rawAffected" FROM "CnaVulnerability"
    WHERE "rawAffected"::text ~ '"lessThan(OrEqual)?": "[0-9.]*[*]"'
  `;
  console.log(`${records.length} CVE record(s) declare a "lessThan: *" or whole-line bound.`);

  const { before, after, changed } = await rebuildCnaRows(records, dryRun);
  console.log(`${dryRun ? 'Would rewrite' : 'Rewrote'} ${changed} CVE(s); rows ${before} -> ${after} (${after >= before ? '+' : ''}${after - before}).`);
}

main()
  .catch((err) => {
    console.error(err);
    process.exit(1);
  })
  .finally(async () => {
    await closeDb();
    process.exit(0);
  });
