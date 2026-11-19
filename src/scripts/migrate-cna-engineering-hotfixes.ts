/**
 * One-time migration: store F5's Engineering Hotfixes on the CNA rows of the records
 * stored before they were read (CnaAffectedRow.hotfixes in cna-fetcher.ts).
 *
 * F5 lists the hotfixes for a branch in the record's `changes`
 * ("BIGIP-17.1.3.7.0.21.4-ENG"). They are shown beside the affected range so an
 * operator sees which hotfix to apply; they are never a fix version. This re-reads the
 * records whose stored declaration names one and rewrites their CnaAffectedProduct rows
 * when they differ from what the extractor makes now. Other CVEs are not touched.
 *
 * Idempotent: a record whose rows are already right is not rewritten.
 *
 * Usage:
 *   pnpm migrate:cna-engineering-hotfixes             # rewrite
 *   pnpm migrate:cna-engineering-hotfixes --dry-run   # count only
 */
import 'dotenv/config';
import { closeDb, prisma } from '../db/client.js';
import { rebuildCnaRows, type CnaRecord } from './lib/rebuild-cna-rows.js';

const dryRun = process.argv.includes('--dry-run');

async function main() {
  const records = await prisma.$queryRaw<CnaRecord[]>`
    SELECT id, "cveId", "rawAffected" FROM "CnaVulnerability"
    WHERE "rawAffected"::text ~* '"at": "[^"]*-ENG"'
  `;
  console.log(`${records.length} CVE record(s) name an Engineering Hotfix.`);

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
