/**
 * Catalog audit: CVEs that match every version
 *
 * A search by a catalog name matches an NVD row whose version is unbounded (a CPE
 * wildcard: no start, no end, no exact version) for ANY queried version. That is
 * right for a CVE that really affects every release, and a false positive for one
 * whose CPE simply says nothing about versions (a module, an edition, an old
 * product name). This lists, per entry, the CVEs reached only through such rows,
 * with the CPEs that make them so, so each can be judged: genuine "all versions",
 * or a pair that drags in something that is not the entry's product.
 *
 * Reads only; never modifies data. Always exits 0: it is an audit, not a check.
 * Cisco entries are skipped, as in validate:catalog-kev.
 *
 * Usage:
 *   pnpm validate:catalog-unbounded             # every entry, summary
 *   pnpm validate:catalog-unbounded docker-engine   # one or more entries, with the CPEs
 */
import 'dotenv/config';
import { prisma, closeDb } from '../db/client.js';
import { CATALOG_ENTRIES } from '../config/product-catalog.js';
import { catalogCnaWhere, catalogNvdWhere } from '../utils/catalog-search.js';

const UNBOUNDED = {
  introducedInt: null, fixedInt: null, lastAffectedInt: null, exactVersion: null,
  versionStartIncluding: null, versionStartExcluding: null, versionEndIncluding: null, versionEndExcluding: null,
} as const;

async function main(): Promise<void> {
  const only = new Set(process.argv.slice(2));
  const detail = only.size > 0;
  const rows: { name: string; total: number; always: number; share: number }[] = [];

  for (const entry of CATALOG_ENTRIES) {
    if (entry.id.startsWith('cisco-')) continue;
    if (detail && !only.has(entry.id)) continue;

    const where = catalogNvdWhere(entry);
    const [all, bounded, unboundedRows] = await Promise.all([
      prisma.nVDAffectedPackage.findMany({ where, select: { vulnerabilityId: true }, distinct: ['vulnerabilityId'] }),
      prisma.nVDAffectedPackage.findMany({
        where: { AND: [where, { NOT: UNBOUNDED }] }, select: { vulnerabilityId: true }, distinct: ['vulnerabilityId'],
      }),
      prisma.nVDAffectedPackage.findMany({
        where: { AND: [where, UNBOUNDED] },
        select: { vulnerabilityId: true, cpe: true, vendor: true, packageName: true, vulnerability: { select: { cveId: true } } },
      }),
    ]);
    const boundedIds = new Set(bounded.map(b => b.vulnerabilityId));
    const always = unboundedRows.filter(r => !boundedIds.has(r.vulnerabilityId));
    const alwaysIds = new Set(always.map(r => r.vulnerabilityId));

    // The CNA rows of the same CVE can bound it: a CVE the CNA gives a range for is not always-hit.
    let alwaysCount = alwaysIds.size;
    if (entry.cna.length > 0 && alwaysIds.size > 0) {
      const cnaBounded = await prisma.cnaAffectedProduct.findMany({
        where: {
          AND: [
            catalogCnaWhere(entry),
            { vulnerability: { cveId: { in: [...new Set(always.map(r => r.vulnerability.cveId))] } } },
            { OR: [{ versionStartInt: { not: null } }, { versionEndInt: { not: null } }, { lastAffectedInt: { not: null } }] },
          ],
        },
        select: { vulnerability: { select: { cveId: true } } },
      });
      const cnaCves = new Set(cnaBounded.map(c => c.vulnerability.cveId));
      alwaysCount = new Set(always.filter(r => !cnaCves.has(r.vulnerability.cveId)).map(r => r.vulnerabilityId)).size;
    }

    const share = all.length === 0 ? 0 : alwaysCount / all.length;
    rows.push({ name: entry.name, total: all.length, always: alwaysCount, share });

    if (detail) {
      console.log(`${entry.name}: ${all.length} CVEs reached through NVD pairs, ${alwaysCount} only through version-less rows\n`);
      const byCpe = new Map<string, Set<string>>();
      for (const r of always) {
        const key = r.cpe ?? `${r.vendor}:${r.packageName}`;
        (byCpe.get(key) ?? byCpe.set(key, new Set()).get(key)!).add(r.vulnerability.cveId);
      }
      for (const [cpe, cves] of [...byCpe.entries()].sort((a, b) => b[1].size - a[1].size).slice(0, 25)) {
        console.log(`  ${String(cves.size).padStart(4)}  ${cpe}   e.g. ${[...cves].sort().slice(0, 3).join(', ')}`);
      }
    }
  }

  if (!detail) {
    console.log('entry                                     CVEs   version-less only   share');
    for (const r of rows.sort((a, b) => b.always - a.always)) {
      console.log(`${r.name.padEnd(40)} ${String(r.total).padStart(5)}   ${String(r.always).padStart(9)}        ${(100 * r.share).toFixed(1).padStart(5)}%`);
    }
  }
}

main()
  .catch((err) => { console.error(err); process.exitCode = 1; })
  .finally(() => closeDb());
