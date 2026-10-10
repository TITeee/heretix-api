/**
 * One-time migration: recompute the *Int columns of rows whose version bound is
 * a Junos release ("21.2R3-S9", "12.3X48-D105").
 *
 * normalizeVersion() used to drop the service release of such a version and read
 * "21.2R3-S9" as "21.2R3", so every S level of a release compared equal and a
 * service release just below a fix ("21.2R3-S8" against a fix in "21.2R3-S9") was
 * not reported. It now keeps the service release; rows written before that
 * carry the old values and are recomputed here. New and updated rows already get
 * the new values going forward.
 *
 * NVD's Junos rows are also rewritten: each affected release is its own CPE with
 * the service release in the update field ("junos:21.2:r1-s1"), which the import
 * dropped, leaving a row that read "21.2" for every one of them. The version is now
 * joined to the update field (21.2R1-S1), recovered here from the stored CPE.
 *
 * Usage:
 *   pnpm migrate:recompute-junos-versions
 */
import 'dotenv/config';
import { closeDb, prisma } from '../db/client.js';
import { normalizeVersion, qualifyJunosVersion } from '../utils/version.js';
import { encodeAdvisoryVersion } from '../utils/advisory-version.js';

const JUNOS_VERSION = /^\d{1,3}\.\d{1,3}[RrXx]\d{1,3}(?:-[SsDd]\d{1,3})?(?:-EVO)?$/;

// Junos versions always carry an upper-case R or X after the dotted number.
const mentionsJunosLabel = (field: string) => [
  { [field]: { contains: 'R' } },
  { [field]: { contains: 'X' } },
];

const isJunos = (v: string | null): v is string => v !== null && JUNOS_VERSION.test(v);
const encode = (v: string | null) => (v ? normalizeVersion(v) : null);

async function main() {
  let updated = 0;
  let unchanged = 0;

  // OSV: introduced / fixed / last affected
  for (const r of await prisma.oSVAffectedPackage.findMany({
    where: { OR: ['introducedVersion', 'fixedVersion', 'lastAffectedVersion'].flatMap(mentionsJunosLabel) },
    select: { id: true, introducedVersion: true, fixedVersion: true, lastAffectedVersion: true, introducedInt: true, fixedInt: true, lastAffectedInt: true },
  })) {
    if (![r.introducedVersion, r.fixedVersion, r.lastAffectedVersion].some(isJunos)) continue;
    const data = { introducedInt: encode(r.introducedVersion), fixedInt: encode(r.fixedVersion), lastAffectedInt: encode(r.lastAffectedVersion) };
    if (data.introducedInt === r.introducedInt && data.fixedInt === r.fixedInt && data.lastAffectedInt === r.lastAffectedInt) { unchanged++; continue; }
    await prisma.oSVAffectedPackage.update({ where: { id: r.id }, data });
    updated++;
  }

  // NVD Junos CPEs: join the version and the update field the import used to drop.
  for (const r of await prisma.nVDAffectedPackage.findMany({
    where: { cpe: { contains: ':juniper:junos' } },
    select: { id: true, cpe: true, versionStartIncluding: true, versionStartExcluding: true, versionEndIncluding: true, versionEndExcluding: true },
  })) {
    const parts = (r.cpe ?? '').split(':');
    const [base, update] = [parts[5], parts[6]];
    // Only the point rows (start = end = the CPE version): a range keeps its bounds.
    if (!base || !update || r.versionStartIncluding !== base || r.versionEndIncluding !== base || r.versionStartExcluding || r.versionEndExcluding) continue;
    const joined = qualifyJunosVersion(base, update);
    if (!joined) continue;
    await prisma.nVDAffectedPackage.update({
      where: { id: r.id },
      data: { versionStartIncluding: joined, versionEndIncluding: joined, introducedInt: normalizeVersion(joined), lastAffectedInt: normalizeVersion(joined) },
    });
    updated++;
  }

  // NVD: start / end bounds
  for (const r of await prisma.nVDAffectedPackage.findMany({
    where: { OR: ['versionStartIncluding', 'versionStartExcluding', 'versionEndIncluding', 'versionEndExcluding'].flatMap(mentionsJunosLabel) },
    select: { id: true, versionStartIncluding: true, versionStartExcluding: true, versionEndIncluding: true, versionEndExcluding: true, introducedInt: true, fixedInt: true, lastAffectedInt: true },
  })) {
    const start = r.versionStartIncluding ?? r.versionStartExcluding;
    const fixed = r.versionEndExcluding;
    const last = r.versionEndIncluding;
    if (![start, fixed, last].some(isJunos)) continue;
    const data = { introducedInt: encode(start), fixedInt: encode(fixed), lastAffectedInt: encode(last) };
    if (data.introducedInt === r.introducedInt && data.fixedInt === r.fixedInt && data.lastAffectedInt === r.lastAffectedInt) { unchanged++; continue; }
    await prisma.nVDAffectedPackage.update({ where: { id: r.id }, data });
    updated++;
  }

  // CVE Records (CNA)
  for (const r of await prisma.cnaAffectedProduct.findMany({
    where: { OR: ['versionStart', 'versionEnd', 'lastAffected'].flatMap(mentionsJunosLabel) },
    select: { id: true, versionStart: true, versionEnd: true, lastAffected: true, versionStartInt: true, versionEndInt: true, lastAffectedInt: true },
  })) {
    if (![r.versionStart, r.versionEnd, r.lastAffected].some(isJunos)) continue;
    const data = { versionStartInt: encode(r.versionStart), versionEndInt: encode(r.versionEnd), lastAffectedInt: encode(r.lastAffected) };
    if (data.versionStartInt === r.versionStartInt && data.versionEndInt === r.versionEndInt && data.lastAffectedInt === r.lastAffectedInt) { unchanged++; continue; }
    await prisma.cnaAffectedProduct.update({ where: { id: r.id }, data });
    updated++;
  }

  // Vendor advisories (a vendor with its own version order keeps it)
  for (const r of await prisma.advisoryAffectedProduct.findMany({
    where: { OR: ['versionStart', 'versionEnd', 'versionFixed', 'lastAffected'].flatMap(mentionsJunosLabel) },
    select: { id: true, vendor: true, versionStart: true, versionEnd: true, versionFixed: true, lastAffected: true, versionStartInt: true, versionEndInt: true, lastAffectedInt: true },
  })) {
    if (![r.versionStart, r.versionEnd, r.versionFixed, r.lastAffected].some(isJunos)) continue;
    const enc = (v: string | null) => (v ? encodeAdvisoryVersion(r.vendor, v) : null);
    const data = { versionStartInt: enc(r.versionStart), versionEndInt: enc(r.versionEnd ?? r.versionFixed), lastAffectedInt: enc(r.lastAffected) };
    if (data.versionStartInt === r.versionStartInt && data.versionEndInt === r.versionEndInt && data.lastAffectedInt === r.lastAffectedInt) { unchanged++; continue; }
    await prisma.advisoryAffectedProduct.update({ where: { id: r.id }, data });
    updated++;
  }

  console.log(`Done: ${updated} updated, ${unchanged} already correct.`);
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
