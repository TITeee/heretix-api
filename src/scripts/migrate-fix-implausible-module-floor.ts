/**
 * One-time migration: fix AdvisoryAffectedProduct rows whose versionStart was
 * set from a DNF module stream label numerically incompatible with the row's
 * own versionEnd -- a floor above the ceiling that makes the row permanently
 * unmatchable by any query.
 *
 * RedHatFetcher/OracleLinuxFetcher extract versionStart from the OVAL
 * "Module <name>:<stream> is enabled" criterion (collectCriteria() in both
 * fetchers), assuming the stream label reflects the packaged software's own
 * version. That holds for nodejs/postgresql/mysql/mariadb/... and even
 * calendar-versioned packages like python-pytz, but not for RHEL8's
 * javapackages-tools module, which bundles several independently-versioned
 * Java build tools (ant, xmvn, an older maven line, ...) under one stream
 * labeled by build generation ("201801") -- unrelated to any of the bundled
 * packages' own versions (xmvn's real version is "3.0.0..."). Confirmed via
 * a full RHEL boundary-value re-sweep after the fix shipped: this alone
 * accounted for ~230k of the sweep's false negatives, affecting 510 distinct
 * product names.
 *
 * moduleStreamVersionStart() (advisory-helpers.ts) now guards against this
 * going forward (returns undefined, falling back to inferBareVersionStart(),
 * when floor > versionEnd) -- this migration applies the same correction to
 * rows already written by the live fetcher before that guard existed.
 *
 * Usage:
 *   pnpm migrate:fix-implausible-module-floor
 */
import 'dotenv/config';
import { prisma } from '../db/client.js';
import { normalizeVersion } from '../utils/version.js';
import { inferBareVersionStart } from '../worker/advisory-helpers.js';

async function main() {
  console.log('Scanning AdvisoryAffectedProduct for versionStart > versionEnd (implausible module-stream floor)...');

  const records = await prisma.advisoryAffectedProduct.findMany({
    where: { versionStart: { not: null }, versionEnd: { not: null } },
    select: { id: true, product: true, versionStart: true, versionEnd: true },
  });

  const implausible = records.filter((r) => {
    const startInt = normalizeVersion(r.versionStart!);
    const endInt = normalizeVersion(r.versionEnd!);
    return startInt !== null && endInt !== null && startInt > endInt;
  });

  console.log(`Found ${implausible.length} rows with versionStart > versionEnd (out of ${records.length} rows checked).`);
  if (implausible.length === 0) {
    console.log('Nothing to do.');
    await prisma.$disconnect();
    return;
  }

  let clearedToBareFallback = 0;
  let clearedToNull = 0;

  for (const record of implausible) {
    const fallback = inferBareVersionStart(record.product, record.versionEnd!);
    const versionStartInt = fallback ? normalizeVersion(fallback) : null;

    await prisma.advisoryAffectedProduct.update({
      where: { id: record.id },
      data: { versionStart: fallback ?? null, versionStartInt },
    });

    if (fallback) clearedToBareFallback++;
    else clearedToNull++;
  }

  console.log(`Done: ${clearedToBareFallback} recomputed via inferBareVersionStart(), ${clearedToNull} cleared to no floor (unverified product, matches pre-fix behavior).`);
  await prisma.$disconnect();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
