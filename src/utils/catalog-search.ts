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
