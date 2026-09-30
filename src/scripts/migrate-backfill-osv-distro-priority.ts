/**
 * One-time migration: fill OSVVulnerability.distroPriority for rows imported
 * before the column existed.
 *
 * OSV's Ubuntu records carry Ubuntu's own priority for the CVE
 * (negligible/low/medium/high/critical) as a severity[] entry of type
 * "Ubuntu". It was not stored anywhere usable, so a CVE Ubuntu rates
 * "negligible" looked exactly as urgent as its CVE-wide (NVD) severity. The
 * importer now stores it (extractDistroPriority() in osv-fetcher.ts); this
 * applies the same extraction to what is already in rawData.
 *
 * Idempotent: only rows whose distroPriority is still null are touched.
 *
 * Usage:
 *   pnpm migrate:backfill-osv-distro-priority
 */
import 'dotenv/config';
import { closeDb, prisma } from '../db/client.js';

async function main() {
  // Same rule as extractDistroPriority(): the first "Ubuntu" entry, lowercased,
  // kept only when it is one of Ubuntu's five priorities.
  const updated = await prisma.$executeRawUnsafe(`
    UPDATE "OSVVulnerability" o
       SET "distroPriority" = p.priority
      FROM (
        SELECT o2.id,
               (SELECT lower(btrim(s->>'score'))
                  FROM jsonb_array_elements(o2."rawData"->'severity') WITH ORDINALITY AS e(s, i)
                 WHERE s->>'type' = 'Ubuntu'
                 ORDER BY i
                 LIMIT 1) AS priority
          FROM "OSVVulnerability" o2
         WHERE o2."distroPriority" IS NULL
           AND jsonb_typeof(o2."rawData"->'severity') = 'array'
      ) p
     WHERE o.id = p.id
       AND p.priority IN ('negligible', 'low', 'medium', 'high', 'critical')
  `);
  console.log(`Done: distroPriority set on ${updated} OSV row(s).`);
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
