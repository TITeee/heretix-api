/**
 * Catalog reachability against CISA KEV
 *
 * For every catalog entry that has KEV rows (src/scripts/lib/catalog-kev-map.ts),
 * checks that a search by the entry's name can reach each of those CVEs: the CVE
 * must have an NVD or CNA row under one of the entry's pairs. A KEV CVE the entry
 * cannot reach is a detection the catalog silently loses (a pair missing, a
 * product spelled another way, or a CVE NVD files under a sibling product), so
 * every miss is listed with the pairs the CVE does have rows under.
 *
 * This checks that a CVE is reachable, not that a version is judged right: KEV
 * names no versions. Reads only; never modifies data.
 *
 * Fails (exit 1) when an entry cannot reach a KEV CVE it is mapped to. A CVE with
 * no NVD or CNA rows at all is reported apart: it is not a catalog fault.
 *
 * Usage:
 *   pnpm validate:catalog-kev            # every mapped entry
 *   pnpm validate:catalog-kev f5-big-ip  # one or more entries by id
 */
import 'dotenv/config';
import { prisma, closeDb } from '../db/client.js';
import { CATALOG_ENTRIES } from '../config/product-catalog.js';
import { catalogCnaWhere, catalogNvdWhere } from '../utils/catalog-search.js';
import { ACCEPTED_MISSES, KEV_MATCHES } from './lib/catalog-kev-map.js';

interface KevRow { cveId: string; vendor: string; product: string; added: Date | null }

async function main(): Promise<void> {
  const only = new Set(process.argv.slice(2));
  const ids = new Set(CATALOG_ENTRIES.map(e => e.id));
  const unknown = KEV_MATCHES.filter(m => !ids.has(m.entryId)).map(m => m.entryId);
  if (unknown.length > 0) {
    console.error(`catalog-kev-map.ts names entries the catalog does not have: ${unknown.join(', ')}`);
    process.exitCode = 1;
    return;
  }

  const kev = (await prisma.vulnerability.findMany({
    where: { isKev: true, cveId: { not: null } },
    select: { cveId: true, kevVendor: true, kevProduct: true, kevDateAdded: true },
  })).map(v => ({
    cveId: v.cveId!, vendor: (v.kevVendor ?? '').trim(), product: (v.kevProduct ?? '').trim(), added: v.kevDateAdded,
  } satisfies KevRow));

  let totalCves = 0;
  let totalReached = 0;
  let failed = false;

  for (const entry of CATALOG_ENTRIES) {
    if (only.size > 0 && !only.has(entry.id)) continue;
    const matches = KEV_MATCHES.filter(m => m.entryId === entry.id);
    if (matches.length === 0) continue;
    const rows = kev.filter(k => matches.some(m => m.vendor.test(k.vendor) && m.product.test(k.product)));
    if (rows.length === 0) continue;

    const missed: { row: KevRow; filedUnder: string[]; inDb: boolean }[] = [];
    let reached = 0;
    for (const row of rows) {
      const [nvd, cna] = await Promise.all([
        prisma.nVDAffectedPackage.count({ where: { vulnerability: { cveId: row.cveId }, ...catalogNvdWhere(entry) } }),
        entry.cna.length === 0
          ? 0
          : prisma.cnaAffectedProduct.count({ where: { vulnerability: { cveId: row.cveId }, ...catalogCnaWhere(entry) } }),
      ]);
      if (nvd + cna > 0) { reached++; continue; }

      const [nvdRows, cnaRows] = await Promise.all([
        prisma.nVDAffectedPackage.findMany({
          where: { vulnerability: { cveId: row.cveId } }, select: { vendor: true, packageName: true }, distinct: ['vendor', 'packageName'], take: 8,
        }),
        prisma.cnaAffectedProduct.findMany({
          where: { vulnerability: { cveId: row.cveId } }, select: { vendor: true, product: true }, distinct: ['vendor', 'product'], take: 8,
        }),
      ]);
      const filedUnder = [
        ...nvdRows.map(r => `nvd ${r.vendor}:${r.packageName}`),
        ...cnaRows.map(r => `cna ${r.vendor}:${r.product}`),
      ];
      missed.push({ row, filedUnder, inDb: filedUnder.length > 0 });
    }

    totalCves += rows.length;
    totalReached += reached;
    const mark = missed.length === 0 ? 'ok  ' : missed.every(m => !m.inDb || ACCEPTED_MISSES[m.row.cveId]) ? 'ok* ' : 'MISS';
    console.log(`${mark} ${entry.name.padEnd(40)} ${reached}/${rows.length} KEV CVEs reachable`);
    for (const m of missed) {
      const accepted = ACCEPTED_MISSES[m.row.cveId];
      if (m.inDb && !accepted) failed = true;
      console.log(`       ${m.row.cveId}  (${m.row.vendor} | ${m.row.product})`);
      console.log(m.inDb
        ? `         filed under: ${m.filedUnder.join(', ')}`
        : '         no NVD or CNA rows at all (not a catalog fault)');
      if (accepted) console.log(`         accepted: ${accepted}`);
    }
  }

  console.log(`\n${totalReached}/${totalCves} KEV CVEs reachable through their catalog entry.`);
  if (failed) {
    console.log('Some CVEs have rows under pairs the entry does not list: add the pair, or say why the CVE is another product.');
    process.exitCode = 1;
  }
}

main()
  .catch((err) => { console.error(err); process.exitCode = 1; })
  .finally(() => closeDb());
