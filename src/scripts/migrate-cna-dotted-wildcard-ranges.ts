/**
 * One-time migration: store the CNA ranges whose bound is a dotted wildcard that
 * extractCnaRows() used to drop (cna-fetcher.ts, "wildLine").
 *
 * Drupal writes its unsupported lines "version: 0.0.0, lessThan: 11.2.*", MongoDB
 * "lessThanOrEqual: 8.1.*", Node.js (through HackerOne) "version: 4.0, lessThan: 4.*" and RTI
 * "5.3.0 to 5.3.*". The "*" made the bound unusable, so the range was dropped, and for a CVE
 * NVD has not enriched nothing else found it. A wildcard bound now covers its line up to the
 * start of the next (below 11.3, 8.2, 5, 5.4).
 *
 * This re-reads every CVE record whose stored declaration has one and replaces that CVE's
 * CnaAffectedProduct rows with what the extractor now makes of it, for the records whose rows
 * change (about 70 on the development data). Other CVEs are not touched.
 *
 * Idempotent: running it again changes nothing. The CnaVulnerability rows stay as they are.
 *
 * Usage:
 *   pnpm migrate:cna-dotted-wildcard-ranges             # rewrite
 *   pnpm migrate:cna-dotted-wildcard-ranges --dry-run   # count only
 */
import 'dotenv/config';
import { closeDb, prisma } from '../db/client.js';
import { rebuildCnaRows, type CnaRecord } from './lib/rebuild-cna-rows.js';

const dryRun = process.argv.includes('--dry-run');

async function main() {
  const records = await prisma.$queryRaw<CnaRecord[]>`
    SELECT id, "cveId", "rawAffected" FROM "CnaVulnerability"
    WHERE "rawAffected"::text ~ '"lessThan": "[0-9]+([.][0-9]+)*[.]?[*]"'
       OR "rawAffected"::text ~ '"lessThanOrEqual": "[0-9]+([.][0-9]+)*[.]?[*]"'
  `;
  console.log(`${records.length} CVE record(s) declare a dotted wildcard bound.`);

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
