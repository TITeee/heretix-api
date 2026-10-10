/**
 * One-time migration: recompute the *Int columns of rows whose version bound has
 * four dotted components ("15.1.10.8", "138.53.6.158").
 *
 * normalizeVersion() used to keep three components, so the 4th was dropped: a fix
 * in "15.1.10.8" was stored as "15.1.10" and the builds just below it
 * ("15.1.10.7") compared equal to the fix and were not reported. It now puts the
 * 4th component in the release slot; rows written before that carry the old
 * values and are recomputed here. New and updated rows already get the new values.
 *
 * Only the rows with a four-component bound are read, and only those whose value
 * changes are written (in batches). Rows whose third component is above 999, or
 * whose 4th is, keep their value.
 *
 * Usage:
 *   pnpm migrate:background-recompute-four-component-versions
 */
import 'dotenv/config';
import { closeDb, prisma } from '../db/client.js';
import { normalizeVersion } from '../utils/version.js';
import { encodeAdvisoryVersion } from '../utils/advisory-version.js';

const FOUR = '^[vV]?[0-9]+[.][0-9]+[.][0-9]+[.][0-9]{1,3}$';
const BATCH = 5000;

type Ver = string | null;
type Int = bigint | null;
type Change = { id: string; vals: (bigint | null)[] };

/** Write one batch of changes: ids and one bigint column per target, in a single statement. */
async function write(table: string, cols: string[], changes: Change[]): Promise<void> {
  for (let i = 0; i < changes.length; i += BATCH) {
    const chunk = changes.slice(i, i + BATCH);
    const sets = cols.map((c, k) => `"${c}" = v.c${k}`).join(', ');
    const arrays = cols.map((_, k) => `$${k + 2}::bigint[]`).join(', ');
    const names = cols.map((_, k) => `c${k}`).join(', ');
    await prisma.$executeRawUnsafe(
      `UPDATE "${table}" t SET ${sets} FROM unnest($1::text[], ${arrays}) AS v(id, ${names}) WHERE t.id = v.id`,
      chunk.map(c => c.id),
      ...cols.map((_, k) => chunk.map(c => c.vals[k])),
    );
  }
}

const same = (a: (bigint | null)[], b: (bigint | null)[]) => a.every((x, i) => x === b[i]);
const enc = (v: string | null) => (v ? normalizeVersion(v) : null);

async function main() {
  // NVD: the import stores introduced from the start bound, fixed from the exclusive end, last-affected from the inclusive end.
  const nvd = await prisma.$queryRawUnsafe<{ id: string; si: Ver; se: Ver; ei: Ver; ee: Ver; a: Int; b: Int; c: Int }[]>(
    `SELECT id, "versionStartIncluding" si, "versionStartExcluding" se, "versionEndIncluding" ei, "versionEndExcluding" ee, "introducedInt" a, "fixedInt" b, "lastAffectedInt" c
     FROM "NVDAffectedPackage"
     WHERE "versionStartIncluding" ~ '${FOUR}' OR "versionStartExcluding" ~ '${FOUR}' OR "versionEndIncluding" ~ '${FOUR}' OR "versionEndExcluding" ~ '${FOUR}'`);
  const nvdChanges: Change[] = [];
  for (const r of nvd) {
    const next = [enc(r.si ?? r.se), enc(r.ee), enc(r.ei)];
    if (!same([r.a, r.b, r.c], next)) nvdChanges.push({ id: r.id, vals: next });
  }
  await write('NVDAffectedPackage', ['introducedInt', 'fixedInt', 'lastAffectedInt'], nvdChanges);
  console.log(`NVD: ${nvdChanges.length} of ${nvd.length} candidate rows updated`);

  const cna = await prisma.$queryRawUnsafe<{ id: string; s: Ver; e: Ver; l: Ver; a: Int; b: Int; c: Int }[]>(
    `SELECT id, "versionStart" s, "versionEnd" e, "lastAffected" l, "versionStartInt" a, "versionEndInt" b, "lastAffectedInt" c
     FROM "CnaAffectedProduct"
     WHERE "versionStart" ~ '${FOUR}' OR "versionEnd" ~ '${FOUR}' OR "lastAffected" ~ '${FOUR}'`);
  const cnaChanges: Change[] = [];
  for (const r of cna) {
    const next = [enc(r.s), enc(r.e), enc(r.l)];
    if (!same([r.a, r.b, r.c], next)) cnaChanges.push({ id: r.id, vals: next });
  }
  await write('CnaAffectedProduct', ['versionStartInt', 'versionEndInt', 'lastAffectedInt'], cnaChanges);
  console.log(`CVE records: ${cnaChanges.length} of ${cna.length} candidate rows updated`);

  const osv = await prisma.$queryRawUnsafe<{ id: string; i: Ver; f: Ver; l: Ver; a: Int; b: Int; c: Int }[]>(
    `SELECT id, "introducedVersion" i, "fixedVersion" f, "lastAffectedVersion" l, "introducedInt" a, "fixedInt" b, "lastAffectedInt" c
     FROM "OSVAffectedPackage"
     WHERE "introducedVersion" ~ '${FOUR}' OR "fixedVersion" ~ '${FOUR}' OR "lastAffectedVersion" ~ '${FOUR}'`);
  const osvChanges: Change[] = [];
  for (const r of osv) {
    const next = [enc(r.i), enc(r.f), enc(r.l)];
    if (!same([r.a, r.b, r.c], next)) osvChanges.push({ id: r.id, vals: next });
  }
  await write('OSVAffectedPackage', ['introducedInt', 'fixedInt', 'lastAffectedInt'], osvChanges);
  console.log(`OSV: ${osvChanges.length} of ${osv.length} candidate rows updated`);

  // Vendor advisories: a vendor with its own version order keeps it (encodeAdvisoryVersion).
  const adv = await prisma.$queryRawUnsafe<{ id: string; vendor: string; s: Ver; e: Ver; f: Ver; l: Ver; a: Int; b: Int; c: Int }[]>(
    `SELECT id, vendor, "versionStart" s, "versionEnd" e, "versionFixed" f, "lastAffected" l, "versionStartInt" a, "versionEndInt" b, "lastAffectedInt" c
     FROM "AdvisoryAffectedProduct"
     WHERE "versionStart" ~ '${FOUR}' OR "versionEnd" ~ '${FOUR}' OR "versionFixed" ~ '${FOUR}' OR "lastAffected" ~ '${FOUR}'`);
  const advChanges: Change[] = [];
  for (const r of adv) {
    const e = (v: string | null) => (v ? encodeAdvisoryVersion(r.vendor, v) : null);
    const next = [e(r.s), e(r.e ?? r.f), e(r.l)];
    if (!same([r.a, r.b, r.c], next)) advChanges.push({ id: r.id, vals: next });
  }
  await write('AdvisoryAffectedProduct', ['versionStartInt', 'versionEndInt', 'lastAffectedInt'], advChanges);
  console.log(`Advisories: ${advChanges.length} of ${adv.length} candidate rows updated`);
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
