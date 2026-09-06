/**
 * One-time migration: delete OSVAffectedPackage rows for OSV records that have
 * since been withdrawn (typically as a duplicate of another advisory -- see
 * https://ossf.github.io/osv-schema/#withdrawn-field).
 *
 * importOSVData() didn't check this field until now, so a withdrawn record's
 * affected-package ranges kept matching search queries forever. This is
 * especially bad for a withdrawn duplicate: its own `fixed` event is often
 * missing (folded into the record it duplicates instead), leaving an unbounded
 * "introduced, never fixed" range. Confirmed live: GHSA-fqj3-h9pc-443h
 * (withdrawn as a duplicate of GHSA-mwf2-3pr3-8698 / CVE-2026-67318) kept
 * flagging axios >=1.13.0 as vulnerable, including 1.18.1, despite the real fix
 * landing at 1.18.0.
 *
 * The OSVVulnerability row itself is left in place (its rawData retains the
 * withdrawal info, and other rows may still reference it) -- only the
 * OSVAffectedPackage rows that make it surface in search are removed.
 *
 * Usage:
 *   pnpm migrate:remove-withdrawn-osv-packages
 */
import 'dotenv/config';
import { prisma } from '../db/client.js';

async function main() {
  const withdrawn = await prisma.$queryRaw<Array<{ id: string; osvId: string }>>`
    SELECT id, "osvId" FROM "OSVVulnerability" WHERE "rawData"->>'withdrawn' IS NOT NULL
  `;

  console.log(`Found ${withdrawn.length} withdrawn OSV record(s).`);

  let totalDeleted = 0;
  for (const v of withdrawn) {
    const { count } = await prisma.oSVAffectedPackage.deleteMany({ where: { vulnerabilityId: v.id } });
    if (count > 0) {
      console.log(`  ${v.osvId}: removed ${count} affected-package row(s)`);
      totalDeleted += count;
    }
  }

  console.log(`Done: ${totalDeleted} affected-package row(s) removed across ${withdrawn.length} withdrawn record(s).`);
}

main()
  .catch((err) => {
    console.error(err);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
