/**
 * One-time migration: backfill versionStart for existing DNF module-stream rows
 *
 * RedHatFetcher/OracleLinuxFetcher now extract versionStart directly from the
 * OVAL "Module <name>:<stream> is enabled" criterion at import time (see
 * collectCriteria() in both fetchers), so newly-imported rows get it
 * automatically. This backfills rows imported before that change, in two
 * passes:
 *
 * 1. product in BARE_ROW_FALLBACK_PRODUCTS (advisory-helpers.ts -- nodejs,
 *    postgresql, httpd, and the mysql/mariadb/php families, each confirmed
 *    safe via a live query): recomputed via inferBareVersionStart()
 *    unconditionally, regardless of the row's current versionStart or
 *    whether it carries the ".module+" marker. This is safe (not just a
 *    backfill-the-nulls pass) because inferBareVersionStart()'s per-product
 *    logic was designed to reproduce exactly what the primary
 *    extractModuleMajor()-based extraction would derive for these products'
 *    module rows too -- so it doubles as the correction pass for rows an
 *    earlier, cruder version of this script (or extractModuleMajor(), before
 *    it learned to read dotted stream labels like "8.4"/"10.11") already
 *    wrote a too-coarse floor into.
 * 2. Any other AdvisoryAffectedProduct with versionStart IS NULL and a
 *    versionEnd containing the DNF module-build marker (".module+") -- for
 *    the ~150 other module-stream products not individually verified, the
 *    row's own versionEnd leading digit is used directly (the same
 *    single-component guess the fetchers themselves fall back to for an
 *    unrecognized product).
 *
 * Usage:
 *   pnpm migrate:module-version-start
 */
import 'dotenv/config';
import { prisma } from '../db/client.js';
import { normalizeVersion } from '../utils/version.js';
import { inferBareVersionStart, moduleStreamVersionStart, BARE_ROW_FALLBACK_PRODUCTS } from '../worker/advisory-helpers.js';

async function main() {
  console.log('Finding AdvisoryAffectedProduct records a Module criterion or the bare-row fallback would now (re)cover...');

  const records = await prisma.advisoryAffectedProduct.findMany({
    where: {
      OR: [
        { product: { in: [...BARE_ROW_FALLBACK_PRODUCTS] } },
        { versionStart: null, versionEnd: { contains: '.module+' } },
      ],
    },
    select: { id: true, product: true, versionEnd: true, versionStart: true },
  });

  console.log(`Found ${records.length} records to migrate.`);
  if (records.length === 0) {
    console.log('Nothing to do.');
    return;
  }

  let updated = 0;
  let skipped = 0;
  let unchanged = 0;

  for (const record of records) {
    const versionEnd = record.versionEnd;
    if (!versionEnd) {
      console.warn(`  SKIP [${record.id}] product=${record.product} — no versionEnd`);
      skipped++;
      continue;
    }
    const stream = inferBareVersionStart(record.product, versionEnd) ?? versionEnd.match(/^(\d+)\./)?.[1];
    if (!stream) {
      console.warn(`  SKIP [${record.id}] product=${record.product} versionEnd="${versionEnd}" — no leading version component`);
      skipped++;
      continue;
    }

    const versionStart = moduleStreamVersionStart(stream);
    if (versionStart === record.versionStart) {
      unchanged++;
      continue;
    }
    const versionStartInt = normalizeVersion(versionStart);

    await prisma.advisoryAffectedProduct.update({
      where: { id: record.id },
      data: { versionStart, versionStartInt },
    });
    updated++;
  }

  console.log(`Done: ${updated} updated, ${unchanged} already correct, ${skipped} skipped (no parseable leading version component).`);
}

main()
  .catch(err => {
    console.error(err);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
