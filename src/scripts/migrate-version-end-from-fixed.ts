/**
 * One-time migration: backfill versionEndInt from versionFixed
 *
 * For AdvisoryAffectedProduct records where versionEndInt IS NULL
 * and versionFixed IS NOT NULL, derive versionEndInt = normalizeVersion(versionFixed).
 *
 * Background:
 *   versionFixed ("fixed in X.Y.Z") is semantically equivalent to an exclusive
 *   upper bound (versionEnd). Without versionEndInt, the advisory matches ALL
 *   versions >= versionStart, causing false positives after a package upgrade.
 *
 * Usage:
 *   pnpm migrate:version-end
 */
import 'dotenv/config';
import { prisma } from '../db/client.js';
import { normalizeVersion } from '../utils/version.js';

async function main() {
  console.log('Finding AdvisoryAffectedProduct records with versionFixed but no versionEndInt...');

  const records = await prisma.advisoryAffectedProduct.findMany({
    where: {
      versionFixed: { not: null },
      versionEndInt: null,
      lastAffectedInt: null,
    },
    select: { id: true, versionFixed: true, product: true },
  });

  console.log(`Found ${records.length} records to migrate.`);
  if (records.length === 0) {
    console.log('Nothing to do.');
    return;
  }

  let updated = 0;
  let skipped = 0;

  for (const record of records) {
    const versionEndInt = normalizeVersion(record.versionFixed!);
    if (versionEndInt === null) {
      console.warn(`  SKIP [${record.id}] product=${record.product} versionFixed="${record.versionFixed}" — normalizeVersion returned null`);
      skipped++;
      continue;
    }

    await prisma.advisoryAffectedProduct.update({
      where: { id: record.id },
      data: { versionEndInt },
    });
    updated++;
  }

  console.log(`Done: ${updated} updated, ${skipped} skipped (normalizeVersion failed).`);
}

main()
  .catch(err => {
    console.error(err);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
