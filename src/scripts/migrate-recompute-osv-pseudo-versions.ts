/**
 * One-time migration: recompute *Int columns for OSVAffectedPackage rows
 * whose introduced/fixed/lastAffected version is a Go module pseudo-version.
 *
 * Before the fix to normalizeVersion() (src/utils/version.ts), a pseudo-version
 * ("vX.Y.Z-yyyymmddhhmmss-abcdefabcdef") misparsed the 14-digit timestamp as an
 * RPM release number: a digit-led commit hash overflowed MAX_COMPONENT and
 * returned null (read as "no fix yet" -- matches every version forever), a
 * letter-led one collapsed to 0 (matches no version -- the row is invisible to
 * every search). Existing rows were written with the old, wrong values and
 * need recomputing; new/updated OSV data already gets the fix going forward.
 *
 * Usage:
 *   pnpm migrate:recompute-osv-pseudo-versions
 */
import 'dotenv/config';
import { prisma } from '../db/client.js';
import { normalizeVersion } from '../utils/version.js';

const PSEUDO_VERSION_SUFFIX = /[-.]\d{14}-[0-9a-fA-F]{7,40}$/;

function isPseudoVersion(v: string | null): v is string {
  return v !== null && PSEUDO_VERSION_SUFFIX.test(v);
}

async function main() {
  console.log('Finding OSVAffectedPackage rows with a Go pseudo-version bound...');

  const records = await prisma.oSVAffectedPackage.findMany({
    where: {
      OR: [
        { introducedVersion: { contains: '-' } },
        { fixedVersion: { contains: '-' } },
        { lastAffectedVersion: { contains: '-' } },
      ],
    },
    select: {
      id: true, packageName: true,
      introducedVersion: true, fixedVersion: true, lastAffectedVersion: true,
      introducedInt: true, fixedInt: true, lastAffectedInt: true,
    },
  });

  const candidates = records.filter(r =>
    isPseudoVersion(r.introducedVersion) || isPseudoVersion(r.fixedVersion) || isPseudoVersion(r.lastAffectedVersion));

  console.log(`Found ${candidates.length} candidate row(s).`);
  if (candidates.length === 0) {
    console.log('Nothing to do.');
    return;
  }

  let updated = 0;
  let unchanged = 0;

  for (const r of candidates) {
    const introducedInt = r.introducedVersion ? normalizeVersion(r.introducedVersion) : null;
    const fixedInt = r.fixedVersion ? normalizeVersion(r.fixedVersion) : null;
    const lastAffectedInt = r.lastAffectedVersion ? normalizeVersion(r.lastAffectedVersion) : null;

    if (introducedInt === r.introducedInt && fixedInt === r.fixedInt && lastAffectedInt === r.lastAffectedInt) {
      unchanged++;
      continue;
    }

    await prisma.oSVAffectedPackage.update({
      where: { id: r.id },
      data: { introducedInt, fixedInt, lastAffectedInt },
    });
    updated++;
  }

  console.log(`Done: ${updated} updated, ${unchanged} already correct.`);
}

main()
  .catch(err => {
    console.error(err);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
