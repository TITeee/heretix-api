/**
 * One-time migration: rebuild every Palo Alto Networks AdvisoryAffectedProduct
 * row from the CSAF document already stored on its AdvisoryVulnerability
 * (rawData), with the reworked parseCsaf() and PAN-specific version encoding.
 *
 * Background:
 *   - parseCsaf() dropped every range bound carrying a hotfix suffix
 *     ("PAN-OS<10.2.9-h1") -- 829 of the feed's 2,090 range entries -- and
 *     read the remaining fix points as a single "< fixed" range per product,
 *     although PAN fixes each maintenance release separately. It also read
 *     PAN's "PAN-OS None" (affected: none) entries as affected-everywhere.
 *   - The *Int columns were encoded with normalizeVersion(), which orders a
 *     hotfix ("10.2.9-h1") *below* its base release; PAN rows now use
 *     panVersionToInt() (src/utils/pan-version.ts).
 * Both only change how already-stored data is interpreted, so no network
 * re-fetch is needed: this re-runs the production parse + import path against
 * rawData. An advisory that now yields no affected product at all (every entry
 * was a "None") has its old affected-product rows deleted -- those are exactly
 * the match-every-version rows this fixes -- while the advisory row itself is
 * left for the next complete PAN fetch to prune, as it would any advisory
 * parseCsaf() skips.
 *
 * Usage:
 *   pnpm migrate:reparse-pan-advisories
 */
import 'dotenv/config';
import { closeDb, prisma } from '../db/client.js';
import { importAdvisoryData } from '../worker/advisory-fetcher.js';
import { parseCsaf, type CsafDocument } from '../worker/pan-fetcher.js';

const SOURCE = 'paloalto';

async function main() {
  const advisories = await prisma.advisoryVulnerability.findMany({
    where: { source: SOURCE },
    select: { id: true, externalId: true, rawData: true, publishedAt: true },
  });
  console.log(`Found ${advisories.length} PAN advisory row(s) to reparse.`);

  let reparsed = 0;
  let noAffected = 0;
  let failed = 0;
  for (const adv of advisories) {
    try {
      const parsed = parseCsaf(adv.rawData as unknown as CsafDocument, adv.externalId, adv.publishedAt ?? undefined);
      if (!parsed) {
        const { count } = await prisma.advisoryAffectedProduct.deleteMany({ where: { advisoryId: adv.id } });
        console.log(`  ${adv.externalId}: no affected product any more, ${count} stale row(s) removed`);
        noAffected++;
        continue;
      }
      await importAdvisoryData(parsed, SOURCE);
      reparsed++;
    } catch (err) {
      failed++;
      console.error(`  ${adv.externalId}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  console.log(`Done: ${reparsed} reparsed, ${noAffected} with no affected product any more, ${failed} failed.`);
  if (failed > 0) process.exitCode = 1;
}

main()
  .catch((err) => {
    console.error(err);
    process.exitCode = 1;
  })
  .finally(async () => {
    await closeDb();
    process.exit(process.exitCode ?? 0);
  });
