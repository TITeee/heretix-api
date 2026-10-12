/**
 * One-time migration: store the CNA ranges written "lessThan: *", as a whole line
 * ("lessThan: 22.2*", "lessThan: 11.2.*", "lessThanOrEqual: 8.1.*"), or as Juniper's list of fixed releases ("lessThan: 23.4R1-S2,
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
 * Usage:
 *   pnpm migrate:cna-open-ended-ranges             # rewrite
 *   pnpm migrate:cna-open-ended-ranges --dry-run   # count only
 */
import 'dotenv/config';
import { closeDb, prisma } from '../db/client.js';
import { extractCnaRows } from '../worker/cna-fetcher.js';
import { normalizeVersion } from '../utils/version.js';

const dryRun = process.argv.includes('--dry-run');

async function main() {
  const records = await prisma.$queryRaw<{ id: string; cveId: string; rawAffected: unknown }[]>`
    SELECT id, "cveId", "rawAffected" FROM "CnaVulnerability"
    WHERE "rawAffected"::text ~ '"lessThan": "([0-9]+([.][0-9]+)*[.]?)?[*]"'
       OR "rawAffected"::text ~ '"lessThanOrEqual": "[0-9]+([.][0-9]+)*[.]?[*]"'
       OR "rawAffected"::text ~ '"lessThan": "[^"]*,[^"]*"'
  `;
  console.log(`${records.length} CVE record(s) declare a "lessThan: *", whole-train or list-of-fixes range.`);

  let before = 0;
  let after = 0;
  let changed = 0;
  // A row's identity for comparing what is stored with what the extractor makes now: a range can
  // change its end alone, so the count is not enough; and a record whose rows are already right
  // (the Linux kernel's, nearly ten thousand of them, match the pattern and never change) is not
  // rewritten, which keeps the run short on a start-up.
  const keyOf = (row: { vendor: string; product: string; packageName?: string | null; versionType?: string | null; versionStart?: string | null; versionEnd?: string | null; lastAffected?: string | null; affectedVersions?: string[] | null }) =>
    JSON.stringify([row.vendor, row.product, row.packageName ?? null, row.versionType ?? null, row.versionStart ?? null, row.versionEnd ?? null, row.lastAffected ?? null, [...(row.affectedVersions ?? [])].sort()]);

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
