import type { Prisma } from '@prisma/client';
import type { CatalogEntry } from '../config/product-catalog.js';
import { escapeLikePattern } from './search-helpers.js';

/**
 * The NVD rows a catalog entry stands for: its exact (vendor, product) pairs, so
 * a search for "Ivanti Automation" reaches ivanti's "automation" and not nintex's.
 * A vendor's product names are listed exactly, or by prefix for a family NVD
 * splits into many names (BIG-IP), minus the excluded prefixes.
 *
 * Prefixes go through escapeLikePattern: Prisma's startsWith leaves LIKE's
 * wildcards alone, and the "_" in "big-ip_next" would match any character.
 */
export function catalogNvdWhere(entry: CatalogEntry): Prisma.NVDAffectedPackageWhereInput {
  return {
    OR: entry.nvd.map((pair) => {
      const names: Prisma.NVDAffectedPackageWhereInput[] = [
        ...(pair.products?.length ? [{ packageName: { in: pair.products } }] : []),
        ...(pair.productPrefixes ?? []).map((p) => ({ packageName: { startsWith: escapeLikePattern(p) } })),
      ];
      return {
        vendor: pair.vendor,
        OR: names,
        ...(pair.excludePrefixes?.length
          ? { NOT: pair.excludePrefixes.map((p) => ({ packageName: { startsWith: escapeLikePattern(p) } })) }
          : {}),
      };
    }),
  };
}

/**
 * The CNA rows a catalog entry stands for. The CVE records spell one vendor
 * several ways, so a row matches when its vendor is any listed spelling and its
 * product any listed product. An entry with no CNA pairs matches no row.
 */
export function catalogCnaWhere(entry: CatalogEntry): Prisma.CnaAffectedProductWhereInput {
  return { OR: entry.cna.map((pair) => ({ vendor: { in: pair.vendors }, product: { in: pair.products } })) };
}

/** Lowercase, with spaces, "_", "-", "." and "/" read as one separator: "big-ip", "BIG IP" and "big_ip" alike. */
function normalizeForSearch(s: string): string {
  return s.toLowerCase().replace(/[\s_\-./]+/g, ' ').trim();
}

/** What the catalog endpoint returns for an entry: everything a picker shows, and the pairs it stands for. */
export interface CatalogListing {
  name: string;
  vendor: string;
  product: string;
  category: CatalogEntry['category'];
  aliases: string[];
  versionHint: string;
  /** Where a search by this name looks: "nvd", "cna". Shown so the source of a result is never hidden. */
  sources: ('nvd' | 'cna')[];
  nvd: CatalogEntry['nvd'];
  cna: CatalogEntry['cna'];
}

export function catalogListing(entry: CatalogEntry): CatalogListing {
  return {
    name: entry.name,
    vendor: entry.vendor,
    product: entry.product,
    category: entry.category,
    aliases: entry.aliases,
    versionHint: entry.versionHint,
    sources: [...(entry.nvd.length > 0 ? ['nvd' as const] : []), ...(entry.cna.length > 0 ? ['cna' as const] : [])],
    nvd: entry.nvd,
    cna: entry.cna,
  };
}

/**
 * The catalog entries matching what was typed, best first: the name or an alias
 * exactly, then a name or alias starting with it, then a vendor or product
 * starting with it, then any of those containing it. Case and separators do not
 * matter. With nothing typed, every entry, by category and name.
 */
export function searchCatalog(
  entries: CatalogEntry[],
  query: string | undefined,
  category?: string,
): CatalogEntry[] {
  const inCategory = category ? entries.filter((e) => e.category === category) : entries;
  const q = normalizeForSearch(query ?? '');
  const byName = (a: CatalogEntry, b: CatalogEntry) => a.category.localeCompare(b.category) || a.name.localeCompare(b.name);
  if (!q) return [...inCategory].sort(byName);

  const tier = (e: CatalogEntry): number => {
    const names = [e.name, ...e.aliases].map(normalizeForSearch);
    const parts = [e.vendor, e.product].map(normalizeForSearch);
    if (names.some((n) => n === q)) return 0;
    if (names.some((n) => n.startsWith(q))) return 1;
    if (parts.some((p) => p.startsWith(q))) return 2;
    if ([...names, ...parts].some((n) => n.includes(q))) return 3;
    return -1;
  };

  return inCategory
    .map((e) => ({ e, t: tier(e) }))
    .filter((x) => x.t >= 0)
    .sort((a, b) => a.t - b.t || a.e.name.localeCompare(b.e.name))
    .map((x) => x.e);
}
