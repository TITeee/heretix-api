/**
 * One-time migration: recompute BigInt version columns after normalizeVersion()
 * started ordering a hyphen-joined pre-release by its stage and number
 * ("1.0.0-beta.10" < "1.0.0-beta.13" < "1.0.0-rc.0"), as it already did one
 * attached straight to the number ("1.0.0rc1"), instead of putting every
 * pre-release of a release on the same value (src/utils/version.ts).
 *
 * A range from one pre-release to a later one of the same release ended before
 * it began and matched nothing: about 500 OSV ranges (npm, Maven, Packagist,
 * crates.io) and 100 CNA ranges, among them the one electron 42.0.0-alpha.3
 * falls in.
 *
 * Only rows whose raw string ends in such a word, optionally with numbers, are
 * candidates: a superset of every version the new rule changes, used purely to
 * avoid re-reading the rows that cannot change. The old-vs-new comparison still
 * decides whether a row is written. Same columns, same encoders as
 * migrate-hyphen-update-versions.
 *
 * Usage:
 *   pnpm migrate:hyphen-pre-release-versions
 */
import 'dotenv/config';
import { closeDb, prisma } from '../db/client.js';
import { encodeAdvisoryVersion } from '../utils/advisory-version.js';
import { normalizeVersion } from '../utils/version.js';

const CANDIDATE = `~* '[0-9]-(dev|canary|next|alpha|ea|beta|pre|preview|m|milestone|rc|cr)([.-]?[0-9]+)?(\\.[0-9]+)*$'`;
const CHUNK = 5000;

interface Candidate {
  id: string;
  raw: string | null;
  current: bigint | null;
  vendor?: string;
}

/** Writes the changed values in chunks, one UPDATE per chunk rather than per row. */
async function writeChanged(
  table: string,
  intCol: string,
  rows: Candidate[],
  encode: (row: Candidate) => bigint | null,
): Promise<void> {
  const changed = rows
    .map(row => ({ id: row.id, value: row.raw ? encode(row) : null, current: row.current }))
    .filter(r => r.value !== r.current);

  for (let i = 0; i < changed.length; i += CHUNK) {
    const chunk = changed.slice(i, i + CHUNK);
    await prisma.$executeRawUnsafe(
      `UPDATE "${table}" AS t SET "${intCol}" = v.value
       FROM (SELECT unnest($1::text[]) AS id, unnest($2::bigint[]) AS value) AS v
       WHERE t.id = v.id`,
      chunk.map(r => r.id),
      chunk.map(r => (r.value === null ? null : r.value.toString())),
    );
  }
  console.log(`  ${table}.${intCol}: ${changed.length} updated / ${rows.length} candidates checked`);
}

/** A column whose Int is computed from one raw column alone. */
async function migrateColumn(table: string, rawCol: string, intCol: string): Promise<void> {
  const rows = await prisma.$queryRawUnsafe<Candidate[]>(
    `SELECT id, "${rawCol}" AS raw, "${intCol}" AS current
     FROM "${table}"
     WHERE "${rawCol}" ${CANDIDATE}`,
  );
  await writeChanged(table, intCol, rows, row => normalizeVersion(row.raw!));
}

/**
 * A column whose Int is computed from the first non-null of two raw columns,
 * so a candidate is decided by that effective value, not either column alone.
 */
async function migrateCoalesced(table: string, rawCols: [string, string], intCol: string): Promise<void> {
  const effective = `COALESCE("${rawCols[0]}", "${rawCols[1]}")`;
  const rows = await prisma.$queryRawUnsafe<Candidate[]>(
    `SELECT id, ${effective} AS raw, "${intCol}" AS current
     FROM "${table}"
     WHERE ${effective} ${CANDIDATE}`,
  );
  await writeChanged(table, intCol, rows, row => normalizeVersion(row.raw!));
}

/**
 * AdvisoryAffectedProduct encodes through encodeAdvisoryVersion(), which is
 * vendor-specific, and its versionEndInt comes from `versionEnd ?? versionFixed`
 * (see importAdvisoryData()).
 */
async function migrateAdvisory(): Promise<void> {
  const columns: [string, string][] = [
    ['"versionStart"', 'versionStartInt'],
    ['"lastAffected"', 'lastAffectedInt'],
    ['COALESCE("versionEnd", "versionFixed")', 'versionEndInt'],
  ];
  for (const [rawExpr, intCol] of columns) {
    const rows = await prisma.$queryRawUnsafe<Candidate[]>(
      `SELECT id, ${rawExpr} AS raw, "${intCol}" AS current, vendor
       FROM "AdvisoryAffectedProduct"
       WHERE ${rawExpr} ${CANDIDATE}`,
    );
    await writeChanged('AdvisoryAffectedProduct', intCol, rows, row => encodeAdvisoryVersion(row.vendor!.trim(), row.raw!));
  }
}

async function main() {
  console.log('Recomputing version-encoding columns for versions with a hyphen-joined pre-release...\n');

  console.log('AdvisoryAffectedProduct:');
  await migrateAdvisory();

  console.log('\nOSVAffectedPackage:');
  await migrateColumn('OSVAffectedPackage', 'introducedVersion', 'introducedInt');
  await migrateColumn('OSVAffectedPackage', 'fixedVersion', 'fixedInt');
  await migrateColumn('OSVAffectedPackage', 'lastAffectedVersion', 'lastAffectedInt');

  console.log('\nNVDAffectedPackage:');
  await migrateCoalesced('NVDAffectedPackage', ['versionStartIncluding', 'versionStartExcluding'], 'introducedInt');
  await migrateColumn('NVDAffectedPackage', 'versionEndExcluding', 'fixedInt');
  await migrateColumn('NVDAffectedPackage', 'versionEndIncluding', 'lastAffectedInt');

  console.log('\nCnaAffectedProduct:');
  await migrateColumn('CnaAffectedProduct', 'versionStart', 'versionStartInt');
  await migrateColumn('CnaAffectedProduct', 'versionEnd', 'versionEndInt');
  await migrateColumn('CnaAffectedProduct', 'lastAffected', 'lastAffectedInt');

  console.log('\nDone.');
  await closeDb();
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
