/**
 * Recompute every stored version-encoding column (*Int) from its raw version
 * string with the current encoders, and write the rows whose value differs.
 *
 * The importers encode a bound once, when they write the row, and rewrite a row
 * only when its source record changes. So whenever the encoding changes, the rows
 * of records that have not changed since keep the old values, and they no longer
 * compare against a queried version encoded the new way. The one-time migrations
 * for each encoding change read only the shapes that change covered; this covers
 * every row. Rows written before normalizeVersion() gained its fourth slot
 * (2026-04) still carried "1.2.11" as 1002011 instead of 1002011000: 8,782 OSV
 * fixed bounds, mostly Maven and npm, so a version just below such a fix (Spring
 * 3.2.14 against a fix in 3.2.15) matched no range.
 *
 * The values are exactly what the importers would write today: normalizeVersion()
 * for OSV, NVD and CVE records, encodeAdvisoryVersion() for vendor advisories,
 * from the same raw columns (NVD's start from the inclusive bound, else the
 * exclusive one; a vendor advisory's end from versionEnd, else versionFixed).
 * Safe to run again: a row already up to date is not written.
 *
 * Usage:
 *   pnpm migrate:recompute-version-ints            # write
 *   pnpm migrate:recompute-version-ints --dry-run  # count only
 */
import 'dotenv/config';
import { closeDb, prisma } from '../db/client.js';
import { encodeAdvisoryVersion } from '../utils/advisory-version.js';
import { normalizeVersion } from '../utils/version.js';

const PAGE = 50_000;
const DRY_RUN = process.argv.includes('--dry-run');

type Int = bigint | null;

interface TableSpec {
  table: string;
  /** Raw SQL expression per Int column, in the order of `ints`. */
  raws: string[];
  ints: string[];
  /** Extra column passed to the encoder (vendor advisories: the vendor). */
  vendor?: boolean;
}

const TABLES: TableSpec[] = [
  {
    table: 'OSVAffectedPackage',
    raws: ['"introducedVersion"', '"fixedVersion"', '"lastAffectedVersion"'],
    ints: ['introducedInt', 'fixedInt', 'lastAffectedInt'],
  },
  {
    table: 'NVDAffectedPackage',
    raws: ['COALESCE("versionStartIncluding", "versionStartExcluding")', '"versionEndExcluding"', '"versionEndIncluding"'],
    ints: ['introducedInt', 'fixedInt', 'lastAffectedInt'],
  },
  {
    table: 'CnaAffectedProduct',
    raws: ['"versionStart"', '"versionEnd"', '"lastAffected"'],
    ints: ['versionStartInt', 'versionEndInt', 'lastAffectedInt'],
  },
  {
    table: 'AdvisoryAffectedProduct',
    raws: ['"versionStart"', 'COALESCE("versionEnd", "versionFixed")', '"lastAffected"'],
    ints: ['versionStartInt', 'versionEndInt', 'lastAffectedInt'],
    vendor: true,
  },
];

/** Write one page of changes: ids and one bigint column per Int column, in a single statement. */
async function write(spec: TableSpec, changes: { id: string; vals: Int[] }[]): Promise<void> {
  if (changes.length === 0) return;
  const sets = spec.ints.map((c, k) => `"${c}" = v.c${k}`).join(', ');
  const arrays = spec.ints.map((_, k) => `$${k + 2}::bigint[]`).join(', ');
  const names = spec.ints.map((_, k) => `c${k}`).join(', ');
  await prisma.$executeRawUnsafe(
    `UPDATE "${spec.table}" t SET ${sets} FROM unnest($1::text[], ${arrays}) AS v(id, ${names}) WHERE t.id = v.id`,
    changes.map(c => c.id),
    ...spec.ints.map((_, k) => changes.map(c => (c.vals[k] === null ? null : c.vals[k]!.toString()))),
  );
}

async function recompute(spec: TableSpec): Promise<void> {
  const select = [
    'id',
    ...(spec.vendor ? ['vendor'] : []),
    ...spec.raws.map((r, k) => `${r} AS r${k}`),
    ...spec.ints.map((c, k) => `"${c}" AS i${k}`),
  ].join(', ');

  let after = '';
  let scanned = 0;
  let changed = 0;
  let nowNull = 0;
  for (;;) {
    const rows = await prisma.$queryRawUnsafe<Record<string, string | bigint | null>[]>(
      `SELECT ${select} FROM "${spec.table}" WHERE id > $1 ORDER BY id LIMIT ${PAGE}`,
      after,
    );
    if (rows.length === 0) break;

    const changes: { id: string; vals: Int[] }[] = [];
    for (const row of rows) {
      const vendor = spec.vendor ? String(row.vendor).trim() : '';
      const vals = spec.ints.map((_, k) => {
        const raw = row[`r${k}`] as string | null;
        if (!raw) return null;
        return spec.vendor ? encodeAdvisoryVersion(vendor, raw) : normalizeVersion(raw);
      });
      const current = spec.ints.map((_, k) => row[`i${k}`] as Int);
      if (vals.every((v, k) => v === current[k])) continue;
      if (vals.some((v, k) => v === null && current[k] !== null)) nowNull++;
      changes.push({ id: row.id as string, vals });
    }

    if (!DRY_RUN) await write(spec, changes);
    scanned += rows.length;
    changed += changes.length;
    after = rows[rows.length - 1].id as string;
  }
  console.log(`  ${spec.table}: ${changed} of ${scanned} rows ${DRY_RUN ? 'would change' : 'updated'} (${nowNull} lose an encoded bound)`);
}

async function main() {
  console.log(`Recomputing version-encoding columns from their raw versions${DRY_RUN ? ' (dry run)' : ''}...\n`);
  for (const spec of TABLES) await recompute(spec);
  console.log('\nDone.');
}

main()
  .catch(err => {
    console.error(err);
    process.exit(1);
  })
  .finally(async () => {
    await closeDb();
    process.exit(0);
  });
