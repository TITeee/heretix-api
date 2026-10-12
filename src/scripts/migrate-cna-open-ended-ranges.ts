/**
 * One-time migration: store the CNA ranges written "lessThan: *", as a whole train
 * ("lessThan: 22.2*"), or as Juniper's list of fixed releases ("lessThan: 23.4R1-S2,
 * 23.4R2") that extractCnaRows() used to drop (cna-fetcher.ts, nextBranchStart(),
 * junosFixListRanges()).
 *
 * A CNA that has not fixed a branch writes it "version: 16.1.0, lessThan: *":
 * that release and every later one in its branch. F5 does this for each
 * end-of-life BIG-IP branch, so a search at 15.1.x or 16.1.x missed CVEs F5 itself
 * says affect them. The extractor now keeps such a range (from its start, ending
 * where the record's next branch begins); this re-reads every CVE record whose
 * stored declaration has one and replaces that CVE's CnaAffectedProduct rows with
 * what the extractor now makes of it. Other CVEs are not touched.
 *
 * Idempotent: running it again rebuilds the same rows. The CnaVulnerability rows
 * stay as they are (their rawAffected is the input).
 *
 * The dotted wildcards ("11.2.*", "8.1.*") came later and have their own migration,
 * migrate-cna-dotted-wildcard-ranges, so that a database that has already run this one
 * runs that one too.
 *
 * Usage:
 *   pnpm migrate:cna-open-ended-ranges             # rewrite
 *   pnpm migrate:cna-open-ended-ranges --dry-run   # count only
 */
import 'dotenv/config';
import { closeDb, prisma } from '../db/client.js';
import { rebuildCnaRows, type CnaRecord } from './lib/rebuild-cna-rows.js';

const dryRun = process.argv.includes('--dry-run');

async function main() {
  const records = await prisma.$queryRaw<CnaRecord[]>`
    SELECT id, "cveId", "rawAffected" FROM "CnaVulnerability"
    WHERE "rawAffected"::text ~ '"lessThan": "([0-9]+[.][0-9]+)?[*]"'
       OR "rawAffected"::text ~ '"lessThan": "[^"]*,[^"]*"'
  `;
  console.log(`${records.length} CVE record(s) declare a "lessThan: *", whole-train or list-of-fixes range.`);

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
