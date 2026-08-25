/**
 * One-time migration: recompute BigInt version columns after normalizeVersion()
 * started clamping minor/patch/release components >= 1000 instead of letting
 * them silently overflow into the next slot up (src/utils/version.ts).
 *
 * That overflow was non-monotonic, not just imprecise -- e.g. "67.9999.64"
 * (NVD's CPE convention for "any 9999.x build of major 67") previously
 * normalized to 76999064000, sorting *above* "68.0.15" (a different, later
 * major). Every AdvisoryAffectedProduct / OSVAffectedPackage /
 * NVDAffectedPackage row computed under the old logic needs its Int columns
 * recomputed from their own raw version strings; see
 * validate-version-encoding.ts for how these were found.
 *
 * Only rows whose raw string contains a run of 4+ digits are candidates (any
 * component reaching 1000 must have one) -- a safe superset used purely to
 * avoid re-touching the millions of unaffected rows; the actual old-vs-new
 * comparison still decides whether each row is written.
 *
 * Usage:
 *   pnpm migrate:clamp-version-components
 */
import 'dotenv/config';
import { prisma } from '../db/client.js';
import { normalizeVersion } from '../utils/version.js';

const CANDIDATE_PATTERN = '[0-9]{4,}';

interface ColumnSpec {
  rawCol: string;
  intCol: string;
}

async function migrateTable(table: string, idCol: string, columns: ColumnSpec[]): Promise<void> {
  for (const { rawCol, intCol } of columns) {
    const rows = await prisma.$queryRawUnsafe<{ id: string; raw: string; current: bigint | null }[]>(
      `SELECT "${idCol}" AS id, "${rawCol}" AS raw, "${intCol}" AS current
       FROM "${table}"
       WHERE "${rawCol}" IS NOT NULL AND "${rawCol}" ~ '${CANDIDATE_PATTERN}'`,
    );

    let updated = 0;
    for (const row of rows) {
      const recomputed = normalizeVersion(row.raw);
      if (recomputed === row.current) continue;
      await prisma.$executeRawUnsafe(
        `UPDATE "${table}" SET "${intCol}" = $1 WHERE "${idCol}" = $2`,
        recomputed,
        row.id,
      );
      updated++;
    }
    console.log(`  ${table}.${intCol} (from ${rawCol}): ${updated} updated / ${rows.length} candidates checked`);
  }
}

/**
 * AdvisoryAffectedProduct.versionEndInt is special: importAdvisoryData()
 * computes it from `versionEnd ?? versionFixed` (versionEnd wins when both are
 * present), not from either column independently -- migrating them as two
 * separate ColumnSpecs would let a stale versionFixed recomputation clobber a
 * row that actually has its own versionEnd.
 */
async function migrateAdvisoryVersionEnd(): Promise<void> {
  const rows = await prisma.$queryRaw<{ id: string; versionEnd: string | null; versionFixed: string | null; current: bigint | null }[]>`
    SELECT id, "versionEnd" AS "versionEnd", "versionFixed" AS "versionFixed", "versionEndInt" AS current
    FROM "AdvisoryAffectedProduct"
    WHERE (("versionEnd" IS NOT NULL AND "versionEnd" ~ '[0-9]{4,}')
        OR ("versionEnd" IS NULL AND "versionFixed" IS NOT NULL AND "versionFixed" ~ '[0-9]{4,}'))
  `;

  let updated = 0;
  for (const row of rows) {
    const effective = row.versionEnd ?? row.versionFixed;
    const recomputed = effective ? normalizeVersion(effective) : null;
    if (recomputed === row.current) continue;
    await prisma.advisoryAffectedProduct.update({
      where: { id: row.id },
      data: { versionEndInt: recomputed },
    });
    updated++;
  }
  console.log(`  AdvisoryAffectedProduct.versionEndInt (from versionEnd ?? versionFixed): ${updated} updated / ${rows.length} candidates checked`);
}

/**
 * NVDAffectedPackage.introducedInt is likewise computed from
 * `versionStartIncluding ?? versionStartExcluding` (Including wins), not from
 * either column independently.
 */
async function migrateNvdIntroduced(): Promise<void> {
  const rows = await prisma.$queryRaw<{ id: string; vsi: string | null; vse: string | null; current: bigint | null }[]>`
    SELECT id, "versionStartIncluding" AS vsi, "versionStartExcluding" AS vse, "introducedInt" AS current
    FROM "NVDAffectedPackage"
    WHERE (("versionStartIncluding" IS NOT NULL AND "versionStartIncluding" ~ '[0-9]{4,}')
        OR ("versionStartIncluding" IS NULL AND "versionStartExcluding" IS NOT NULL AND "versionStartExcluding" ~ '[0-9]{4,}'))
  `;

  let updated = 0;
  for (const row of rows) {
    const effective = row.vsi ?? row.vse;
    const recomputed = effective ? normalizeVersion(effective) : null;
    if (recomputed === row.current) continue;
    await prisma.nVDAffectedPackage.update({
      where: { id: row.id },
      data: { introducedInt: recomputed },
    });
    updated++;
  }
  console.log(`  NVDAffectedPackage.introducedInt (from versionStartIncluding ?? versionStartExcluding): ${updated} updated / ${rows.length} candidates checked`);
}

async function main() {
  console.log('Recomputing version-encoding columns for rows affected by the minor/patch/release clamp fix...\n');

  console.log('AdvisoryAffectedProduct:');
  await migrateTable('AdvisoryAffectedProduct', 'id', [
    { rawCol: 'versionStart', intCol: 'versionStartInt' },
    { rawCol: 'lastAffected', intCol: 'lastAffectedInt' },
  ]);
  await migrateAdvisoryVersionEnd();

  console.log('\nOSVAffectedPackage:');
  await migrateTable('OSVAffectedPackage', 'id', [
    { rawCol: 'introducedVersion', intCol: 'introducedInt' },
    { rawCol: 'fixedVersion', intCol: 'fixedInt' },
    { rawCol: 'lastAffectedVersion', intCol: 'lastAffectedInt' },
  ]);

  console.log('\nNVDAffectedPackage:');
  await migrateTable('NVDAffectedPackage', 'id', [
    { rawCol: 'versionEndExcluding', intCol: 'fixedInt' },
    { rawCol: 'versionEndIncluding', intCol: 'lastAffectedInt' },
  ]);
  await migrateNvdIntroduced();

  console.log('\nDone.');
  await prisma.$disconnect();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
