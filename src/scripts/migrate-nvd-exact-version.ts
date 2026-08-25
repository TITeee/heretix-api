/**
 * One-time migration: populate NVDAffectedPackage.exactVersion for rows
 * already imported before that column existed.
 *
 * These are rows whose introducedInt/fixedInt/lastAffectedInt are all null
 * for the wrong reason: not a genuine CPE wildcard ("*"/"-", which
 * versionRangeWhere() is meant to match unconditionally by design -- see
 * README.md), but a real, specific version (Huawei's "v200r007c00spcb00"
 * V/R/C/SPC scheme, Jenkins plugin build ids like "1365.v4778ca_84b_de5")
 * that normalizeVersion() can't range-encode. Found via
 * validate-version-encoding.ts: 14,609 rows / 1,459 CVEs where this silently
 * made the row match every queried version instead of just its own.
 *
 * A row qualifies when versionStartIncluding and versionEndIncluding hold
 * the exact same non-null string with no versionStartExcluding/
 * versionEndExcluding -- the shape nvd-fetcher.ts's pointVersion path
 * produces -- and that string isn't a real CPE wildcard marker. The
 * distinguishing wildcard check itself is `cpe`'s own version field (index
 * 5): "*" or "-" means NVD said "all versions", anything else that still
 * failed to normalize is the genuine gap this migration fixes.
 *
 * Usage:
 *   pnpm migrate:nvd-exact-version
 */
import 'dotenv/config';
import { prisma } from '../db/client.js';
import { computeExactVersion } from '../worker/nvd-helpers.js';

async function main() {
  console.log('Finding NVDAffectedPackage rows with an unresolved point version...');

  const candidates = await prisma.nVDAffectedPackage.findMany({
    where: {
      introducedInt: null,
      fixedInt: null,
      lastAffectedInt: null,
      versionStartExcluding: null,
      versionEndExcluding: null,
      exactVersion: null,
      NOT: { versionStartIncluding: null },
    },
    select: { id: true, cpe: true, versionStartIncluding: true, versionEndIncluding: true },
  });

  console.log(`Found ${candidates.length} candidate rows.`);

  let updated = 0;
  let skippedWildcard = 0;
  let skippedMismatch = 0;

  for (const row of candidates) {
    // Only the pointVersion shape: start and end are the same string (see
    // nvd-fetcher.ts's `vsi = ... ?? pointVersion`, `vei = ... ?? pointVersion`).
    if (row.versionStartIncluding !== row.versionEndIncluding) {
      skippedMismatch++;
      continue;
    }

    // Confirm this wasn't a genuine wildcard via the row's own raw CPE string
    // (cpe:2.3:<part>:<vendor>:<product>:<version>:...) -- belt-and-suspenders
    // alongside computeExactVersion()'s own normalizeVersion() check.
    const cpeVersion = row.cpe?.split(':')[5];
    if (cpeVersion === '*' || cpeVersion === '-' || cpeVersion === undefined) {
      skippedWildcard++;
      continue;
    }

    const exactVersion = computeExactVersion(row.versionStartIncluding);
    if (!exactVersion) continue; // normalized fine after all; nothing to backfill

    await prisma.nVDAffectedPackage.update({
      where: { id: row.id },
      data: { exactVersion },
    });
    updated++;
  }

  console.log(`Done: ${updated} updated, ${skippedWildcard} skipped (genuine CPE wildcard), ${skippedMismatch} skipped (start != end, not a point version).`);
  await prisma.$disconnect();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
