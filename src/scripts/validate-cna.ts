/**
 * CNA affected-data quality report
 *
 * The CNA tables are populated but deliberately not wired into any search path
 * yet (see CnaVulnerability's schema comment). This report is what that
 * decision waits on: it measures how much detection the data would actually
 * add, and how much false-positive risk it would carry if exposed.
 *
 * Like validate-version-encoding.ts, this is detection-only -- it reads and
 * reports, and never modifies data.
 *
 * Sections:
 *   1. What was ingested          rows, CVEs, per-CNA and per-vendor spread
 *   2. Coverage gained            CVEs with no NVD CPE row that CNA data covers
 *   3. Collision risk             CNA product names that collide with names the
 *                                 existing search paths already match on
 *   4. Range sanity               collapsed/inverted bounds, unbounded rows
 *
 * Usage:
 *   pnpm validate:cna
 */
import 'dotenv/config';
import { prisma } from '../db/client.js';

function pct(n: number, d: number): string {
  return d === 0 ? 'n/a' : `${((100 * n) / d).toFixed(1)}%`;
}

function heading(title: string): void {
  console.log(`\n${'─'.repeat(72)}\n${title}\n${'─'.repeat(72)}`);
}

async function reportIngested(): Promise<number> {
  heading('1. Ingested');

  const [cves, rows] = await Promise.all([
    prisma.cnaVulnerability.count(),
    prisma.cnaAffectedProduct.count(),
  ]);
  console.log(`CVEs with usable CNA affected data: ${cves}`);
  console.log(`Affected-product rows:              ${rows}`);
  if (cves === 0) {
    console.log('\nNothing ingested yet -- run `pnpm import:cna` first.');
    return 0;
  }

  const [ranged, exact] = await Promise.all([
    prisma.cnaAffectedProduct.count({ where: { OR: [{ versionEnd: { not: null } }, { lastAffected: { not: null } }] } }),
    prisma.cnaAffectedProduct.count({ where: { versionEnd: null, lastAffected: null } }),
  ]);
  console.log(`  bounded ranges: ${ranged} (${pct(ranged, rows)})`);
  console.log(`  exact versions: ${exact} (${pct(exact, rows)})`);

  const distinctProducts = await prisma.cnaAffectedProduct.findMany({
    distinct: ['vendor', 'product'], select: { vendor: true }, take: 100000,
  });
  console.log(`Distinct vendor/product pairs:      ${distinctProducts.length}`);

  const topCnas = await prisma.cnaVulnerability.groupBy({
    by: ['cnaShortName'], _count: true, orderBy: { _count: { cnaShortName: 'desc' } }, take: 15,
  });
  console.log('\nTop CNAs by CVE count:');
  for (const c of topCnas) console.log(`  ${String(c._count).padStart(7)}  ${c.cnaShortName}`);

  const topVendors = await prisma.cnaAffectedProduct.groupBy({
    by: ['vendor'], _count: true, orderBy: { _count: { vendor: 'desc' } }, take: 15,
  });
  console.log('\nTop vendors by row count:');
  for (const v of topVendors) console.log(`  ${String(v._count).padStart(7)}  ${v.vendor}`);

  return cves;
}

async function reportCoverage(): Promise<void> {
  heading('2. Coverage gained (the reason for this import)');

  // CVEs whose NVD record carries no CPE row at all are invisible to the NVD
  // search path no matter what is queried. Those are what CNA data can recover.
  const [gap] = await prisma.$queryRaw<{ c: number }[]>`
    SELECT count(*)::int AS c
    FROM "CnaVulnerability" cna
    WHERE NOT EXISTS (
      SELECT 1 FROM "NVDVulnerability" nv
      JOIN "NVDAffectedPackage" np ON np."vulnerabilityId" = nv.id
      WHERE nv."cveId" = cna."cveId"
    )`;
  const total = await prisma.cnaVulnerability.count();
  console.log(`CVEs covered by CNA data but with no NVD CPE row: ${gap.c} / ${total} (${pct(gap.c, total)})`);

  // Of those, the ones with no vendor-advisory coverage either are the CVEs
  // that no other source in this database can currently match a product to.
  const [noSourceAtAll] = await prisma.$queryRaw<{ c: number }[]>`
    SELECT count(*)::int AS c
    FROM "CnaVulnerability" cna
    WHERE NOT EXISTS (
      SELECT 1 FROM "NVDVulnerability" nv
      JOIN "NVDAffectedPackage" np ON np."vulnerabilityId" = nv.id
      WHERE nv."cveId" = cna."cveId"
    )
    AND NOT EXISTS (
      SELECT 1 FROM "AdvisoryVulnerability" av
      JOIN "AdvisoryAffectedProduct" ap ON ap."advisoryId" = av.id
      WHERE av."cveId" = cna."cveId"
    )
    AND NOT EXISTS (
      SELECT 1 FROM "OSVVulnerability" ov
      JOIN "OSVAffectedPackage" op ON op."vulnerabilityId" = ov.id
      WHERE ov."cveId" = cna."cveId"
    )`;
  console.log(`  ...and no Advisory or OSV product data either:  ${noSourceAtAll.c} (${pct(noSourceAtAll.c, total)})`);
  console.log('  (this second number is the detection these tables would uniquely add)');
}

async function reportCollisions(): Promise<void> {
  heading('3. Collision risk (what exposing this to search would cost)');

  // searchAdvisory() matches AdvisoryAffectedProduct.product by name without
  // looking at the vendor, and searchNVD() matches NVDAffectedPackage.
  // packageName the same way. A CNA product name equal to one of those is a
  // name that would start returning extra CVEs if these rows joined that path.
  const [advisory] = await prisma.$queryRaw<{ names: number; rows: number }[]>`
    SELECT count(DISTINCT c.product)::int AS names, count(*)::int AS rows
    FROM "CnaAffectedProduct" c
    WHERE EXISTS (SELECT 1 FROM "AdvisoryAffectedProduct" a WHERE a.product = c.product)`;
  const [nvd] = await prisma.$queryRaw<{ names: number; rows: number }[]>`
    SELECT count(DISTINCT c.product)::int AS names, count(*)::int AS rows
    FROM "CnaAffectedProduct" c
    WHERE EXISTS (SELECT 1 FROM "NVDAffectedPackage" n WHERE n."packageName" = c.product)`;

  const rows = await prisma.cnaAffectedProduct.count();
  console.log(`CNA product names also used by AdvisoryAffectedProduct.product: ${advisory.names} names, ${advisory.rows} rows (${pct(advisory.rows, rows)})`);
  console.log(`CNA product names also used by NVDAffectedPackage.packageName:  ${nvd.names} names, ${nvd.rows} rows (${pct(nvd.rows, rows)})`);

  const overlap = await prisma.$queryRaw<{ product: string; cna: number; advisory: number }[]>`
    SELECT c.product,
           count(*)::int AS cna,
           (SELECT count(*)::int FROM "AdvisoryAffectedProduct" a WHERE a.product = c.product) AS advisory
    FROM "CnaAffectedProduct" c
    WHERE EXISTS (SELECT 1 FROM "AdvisoryAffectedProduct" a WHERE a.product = c.product)
    GROUP BY c.product
    ORDER BY count(*) DESC
    LIMIT 20`;
  if (overlap.length > 0) {
    console.log('\nMost-shared product names (CNA rows vs existing advisory rows):');
    for (const o of overlap) {
      console.log(`  ${String(o.cna).padStart(6)} CNA / ${String(o.advisory).padStart(6)} advisory   ${o.product}`);
    }
    console.log('\n  Each of these is a name an existing search already answers. Adding CNA');
    console.log('  rows behind it changes that answer -- review before exposing them.');
  }
}

async function reportRangeSanity(): Promise<void> {
  heading('4. Range sanity');

  const rows = await prisma.cnaAffectedProduct.count();

  // Same class of bug validate-version-encoding.ts looks for elsewhere: a range
  // no version can satisfy is a silent false negative.
  const collapsed = await prisma.$queryRaw<{ c: number }[]>`
    SELECT count(*)::int AS c FROM "CnaAffectedProduct"
    WHERE ("versionStartInt" IS NOT NULL AND "versionEndInt" IS NOT NULL AND "versionStartInt" >= "versionEndInt")
       OR ("versionStartInt" IS NOT NULL AND "lastAffectedInt" IS NOT NULL AND "versionStartInt" > "lastAffectedInt")`;
  console.log(`Collapsed/inverted ranges: ${collapsed[0].c} (${pct(collapsed[0].c, rows)})`);

  // A row with no encoded bound and no exact version would match everything if
  // it ever reached a search path. The ingest filters are meant to make this
  // impossible; a non-zero count here means one of them has a hole.
  const [unbounded] = await prisma.$queryRaw<{ c: number }[]>`
    SELECT count(*)::int AS c FROM "CnaAffectedProduct"
    WHERE "versionStartInt" IS NULL AND "versionEndInt" IS NULL AND "lastAffectedInt" IS NULL
      AND cardinality("affectedVersions") = 0`;
  console.log(`Rows with no usable bound at all: ${unbounded.c} (expected 0)`);
  if (unbounded.c > 0) console.log('  ^ ingest filter hole -- these would match every version queried');

  // Bounds that survived the string filter but that normalizeVersion() could
  // not encode. Harmless (they simply never match a range query) but worth
  // watching as a measure of how much the filter lets through unusably.
  const [unencodable] = await prisma.$queryRaw<{ c: number }[]>`
    SELECT count(*)::int AS c FROM "CnaAffectedProduct"
    WHERE ("versionEnd" IS NOT NULL AND "versionEndInt" IS NULL)
       OR ("lastAffected" IS NOT NULL AND "lastAffectedInt" IS NULL)
       OR ("versionStart" IS NOT NULL AND "versionStartInt" IS NULL)`;
  console.log(`Bounds accepted as strings but not encodable to BigInt: ${unencodable.c} (${pct(unencodable.c, rows)})`);
}

async function main() {
  const ingested = await reportIngested();
  if (ingested === 0) {
    await prisma.$disconnect();
    return;
  }
  await reportCoverage();
  await reportCollisions();
  await reportRangeSanity();
  console.log();
  await prisma.$disconnect();
}

main().catch(async (err) => {
  console.error(err);
  await prisma.$disconnect();
  process.exit(1);
});
