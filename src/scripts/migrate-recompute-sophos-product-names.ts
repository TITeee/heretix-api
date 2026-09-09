/**
 * One-time migration: recompute AdvisoryAffectedProduct.product for existing
 * Sophos rows using the improved extractProduct() (sophos-fetcher.ts).
 *
 * Background:
 *   extractProduct() only recognized one title shape ("... in Sophos X
 *   Firmware/Software") until now, so ~80% of Sophos advisories fell back to
 *   the generic "Sophos" product name even when their title clearly named a
 *   specific product (e.g. "Sophos Firewall v18.5 MR3 Resolves Security
 *   Vulnerabilities", "Resolved RCE in SG UTM WebAdmin") -- confirmed live
 *   that UTM-related CVEs existed in the data but were unsearchable by
 *   product name because of this. extractProduct() derives its result purely
 *   from the advisory's title/summary text (already stored, no network
 *   re-fetch needed), so this just re-runs it against what's already in the DB.
 *
 * Usage:
 *   pnpm migrate:recompute-sophos-product-names
 */
import 'dotenv/config';
import { prisma } from '../db/client.js';
import { extractProduct } from '../worker/sophos-fetcher.js';

async function main() {
  const rows = await prisma.advisoryAffectedProduct.findMany({
    where: { vendor: 'sophos' },
    include: { advisory: { select: { summary: true } } },
  });

  console.log(`Found ${rows.length} Sophos AdvisoryAffectedProduct row(s) to check.`);

  let updated = 0;
  const byNewProduct = new Map<string, number>();

  for (const row of rows) {
    if (!row.advisory.summary) continue;
    const recomputed = extractProduct(row.advisory.summary);
    if (recomputed === row.product) continue;

    await prisma.advisoryAffectedProduct.update({
      where: { id: row.id },
      data: { product: recomputed },
    });
    updated++;
    byNewProduct.set(recomputed, (byNewProduct.get(recomputed) ?? 0) + 1);
  }

  console.log(`Done: ${updated} row(s) updated.`);
  for (const [product, count] of [...byNewProduct].sort((a, b) => b[1] - a[1])) {
    console.log(`  ${product}: ${count}`);
  }
}

main()
  .catch((err) => {
    console.error(err);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
