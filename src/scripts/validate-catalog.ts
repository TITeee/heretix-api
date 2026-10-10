/**
 * Product catalog validation
 *
 * Checks every pair in src/config/product-catalog.ts against the database: a
 * pair that matches no row means a detection the catalog promises and the data
 * cannot give (a typo, or a name NVD or the CNAs have since changed). Reads
 * only; never modifies data.
 *
 * Fails (exit 1) when:
 *   - the catalog is structurally unsound (duplicate names, a name that is a
 *     PRODUCT_ALIASES key, ... see catalogProblems());
 *   - a listed NVD product, a product prefix, or a CNA vendor or product has no
 *     row in the database.
 *
 * Warns, without failing, about NVD products of a listed vendor that start like
 * a listed product but are not covered (e.g. "websphere_application_server_nd"
 * when only "websphere_application_server" is listed): either add them or accept
 * that they are a different product.
 *
 * Usage:
 *   pnpm validate:catalog
 */
import 'dotenv/config';
import { prisma, closeDb } from '../db/client.js';
import { CATALOG_ENTRIES, catalogProblems, type CatalogEntry } from '../config/product-catalog.js';

function like(prefix: string): string {
  return `${prefix.replace(/[\\%_]/g, '\\$&')}%`;
}

interface Counted { name: string; cves: number }

async function nvdProducts(vendor: string, exact: string[], prefixes: string[], excludes: string[]): Promise<Counted[]> {
  const rows = await prisma.$queryRaw<{ name: string; cves: number }[]>`
    SELECT "packageName" AS name, count(DISTINCT "vulnerabilityId")::int AS cves
    FROM "NVDAffectedPackage"
    WHERE vendor = ${vendor}
      AND ("packageName" = ANY(${exact}::text[]) OR "packageName" LIKE ANY(${prefixes.map(like)}::text[]))
      AND NOT ("packageName" LIKE ANY(${excludes.map(like)}::text[]))
    GROUP BY 1 ORDER BY 1`;
  return rows;
}

async function nvdSiblings(vendor: string, exact: string[], covered: Set<string>): Promise<string[]> {
  const rows = await prisma.$queryRaw<{ name: string }[]>`
    SELECT DISTINCT "packageName" AS name FROM "NVDAffectedPackage"
    WHERE vendor = ${vendor} AND "packageName" LIKE ANY(${exact.map(like)}::text[])
    ORDER BY 1`;
  return rows.map(r => r.name).filter(n => !covered.has(n));
}

async function cnaRows(vendors: string[], products: string[]): Promise<{ vendor: string; product: string; rows: number }[]> {
  return prisma.$queryRaw<{ vendor: string; product: string; rows: number }[]>`
    SELECT vendor, product, count(*)::int AS rows FROM "CnaAffectedProduct"
    WHERE vendor = ANY(${vendors}::text[]) AND product = ANY(${products}::text[])
    GROUP BY 1, 2 ORDER BY 1, 2`;
}

async function validateEntry(e: CatalogEntry): Promise<{ errors: string[]; warnings: string[]; summary: string }> {
  const errors: string[] = [];
  const warnings: string[] = [];
  const parts: string[] = [];

  for (const p of e.nvd) {
    const exact = p.products ?? [];
    const prefixes = p.productPrefixes ?? [];
    const found = await nvdProducts(p.vendor, exact, prefixes, p.excludePrefixes ?? []);
    const foundNames = new Set(found.map(f => f.name));
    for (const x of exact) if (!foundNames.has(x)) errors.push(`${e.id}: NVD ${p.vendor}:${x} has no row`);
    for (const x of prefixes) {
      if (!found.some(f => f.name.startsWith(x))) errors.push(`${e.id}: NVD ${p.vendor}:${x}* matches no product`);
    }
    parts.push(`NVD ${p.vendor}: ${found.length} product${found.length === 1 ? '' : 's'}, ${found.reduce((n, f) => Math.max(n, f.cves), 0)}+ CVEs`);
    if (exact.length > 0) {
      const siblings = await nvdSiblings(p.vendor, exact, foundNames);
      if (siblings.length > 0) warnings.push(`${e.id}: not covered, but named like a listed product: ${p.vendor}:${siblings.slice(0, 6).join(', ')}${siblings.length > 6 ? ', ...' : ''}`);
    }
  }

  for (const p of e.cna) {
    const rows = await cnaRows(p.vendors, p.products);
    const vendors = new Set(rows.map(r => r.vendor));
    const products = new Set(rows.map(r => r.product));
    for (const v of p.vendors) if (!vendors.has(v)) errors.push(`${e.id}: CNA vendor "${v}" has no row with a listed product`);
    for (const x of p.products) if (!products.has(x)) errors.push(`${e.id}: CNA product "${x}" has no row with a listed vendor`);
    parts.push(`CNA: ${rows.reduce((n, r) => n + r.rows, 0)} rows`);
  }

  return { errors, warnings, summary: parts.join(' | ') };
}

async function main(): Promise<void> {
  const problems = catalogProblems();
  const errors: string[] = [...problems];
  const warnings: string[] = [];

  console.log(`Product catalog: ${CATALOG_ENTRIES.length} entries\n`);
  for (const e of CATALOG_ENTRIES) {
    const result = await validateEntry(e);
    errors.push(...result.errors);
    warnings.push(...result.warnings);
    console.log(`${result.errors.length === 0 ? 'ok  ' : 'FAIL'} ${e.name.padEnd(36)} ${result.summary}`);
  }

  if (warnings.length > 0) {
    console.log(`\nWarnings (${warnings.length}):`);
    for (const w of warnings) console.log(`  ${w}`);
  }
  if (errors.length > 0) {
    console.log(`\nProblems (${errors.length}):`);
    for (const x of errors) console.log(`  ${x}`);
    process.exitCode = 1;
  } else {
    console.log('\nEvery pair matches data.');
  }
}

main()
  .catch((err) => { console.error(err); process.exitCode = 1; })
  .finally(() => closeDb());
