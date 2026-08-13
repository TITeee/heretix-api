/**
 * One-time migration: backfill versionStart for existing DNF module-stream rows
 *
 * RedHatFetcher/OracleLinuxFetcher now extract versionStart directly from the
 * OVAL "Module <name>:N is enabled" criterion at import time (see
 * collectCriteria() in both fetchers), so newly-imported rows get it
 * automatically. This backfills rows imported before that change, plus one
 * correction pass:
 *
 * 1. Any AdvisoryAffectedProduct with versionStart IS NULL and a versionEnd
 *    containing the DNF module-build marker (".module+") -- the row's own
 *    versionEnd already encodes its major version (e.g.
 *    "20.8.1-1.module+el9.3.0.z+..." -> major 20) -- no live OVAL re-fetch is
 *    needed, this is exactly the value the fetcher would have extracted from
 *    the Module criterion for that same build.
 * 2. product="nodejs"/"postgresql" rows with no ".module+" marker at all
 *    (pre-modularization advisories with no Module criterion to extract from
 *    in the first place -- e.g. RHSA-2022:6595 on RHEL9 for nodejs; RHEL7
 *    pre-DNF, RHEL9's pre-modularization baseline, and RHEL10's unmodularized
 *    postgresql for postgresql) -- mirrors inferBareVersionStart()
 *    (advisory-helpers.ts), scoped to these two confirmed products; not
 *    applied to other products (see that function's doc comment for why).
 * 3. product="postgresql" rows already backfilled to the coarse "9.0" floor
 *    by an earlier run of this script (before inferBareVersionStart() learned
 *    PostgreSQL's pre-10 two-component majors) -- re-derives the precise
 *    "9.{minor}" floor so e.g. postgresql:9.6-only fixes stop matching a
 *    9.2.x query.
 *
 * Usage:
 *   pnpm migrate:module-version-start
 */
import 'dotenv/config';
import { prisma } from '../db/client.js';
import { normalizeVersion } from '../utils/version.js';
import { inferBareVersionStart } from '../worker/advisory-helpers.js';

async function main() {
  console.log('Finding AdvisoryAffectedProduct records a Module criterion or the bare-row fallback would now (re)cover...');

  const records = await prisma.advisoryAffectedProduct.findMany({
    where: {
      OR: [
        { versionStart: null, versionEnd: { contains: '.module+' } },
        { versionStart: null, product: { in: ['nodejs', 'postgresql'] } },
        { product: 'postgresql', versionStart: '9.0' },
      ],
    },
    select: { id: true, product: true, versionEnd: true },
  });

  console.log(`Found ${records.length} records to migrate.`);
  if (records.length === 0) {
    console.log('Nothing to do.');
    return;
  }

  let updated = 0;
  let skipped = 0;

  for (const record of records) {
    const versionEnd = record.versionEnd!;
    const major = inferBareVersionStart(record.product, versionEnd) ?? versionEnd.match(/^(\d+)\./)?.[1];
    if (!major) {
      console.warn(`  SKIP [${record.id}] product=${record.product} versionEnd="${versionEnd}" — no leading major version`);
      skipped++;
      continue;
    }

    const versionStart = major.includes('.') ? major : `${major}.0`;
    const versionStartInt = normalizeVersion(versionStart);

    await prisma.advisoryAffectedProduct.update({
      where: { id: record.id },
      data: { versionStart, versionStartInt },
    });
    updated++;
  }

  console.log(`Done: ${updated} updated, ${skipped} skipped (no parseable major version).`);
}

main()
  .catch(err => {
    console.error(err);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
