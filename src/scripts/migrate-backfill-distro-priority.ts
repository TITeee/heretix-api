/**
 * One-time migration: fill the new distroPriority columns for rows imported
 * before they existed, from the source data already stored in rawData.
 *
 * Background: each distro publishes its own rating of a CVE for its own
 * packages, and none of it was stored anywhere usable, so a CVE a distro
 * rates "negligible"/"unimportant" looked exactly as urgent as its CVE-wide
 * (NVD) severity. The importers now store it verbatim; this applies the same
 * extraction to what is already in the DB:
 *
 *   - Ubuntu (OSVVulnerability): the record's severity[] entry of type
 *     "Ubuntu" -- one priority for the whole record
 *     (extractRecordDistroPriority()).
 *   - Debian (OSVAffectedPackage): each affected entry's
 *     ecosystem_specific.urgency -- per (release, package), matched to the
 *     rows by record + ecosystem + package name (extractDistroPriority()).
 *   - Red Hat OVAL (AdvisoryVulnerability, source "red-hat"): the matching
 *     `<cve impact="...">` element of the definition (parseRedHatImpact()).
 *
 * Red Hat VEX rows cannot be backfilled -- their rawData does not keep the
 * document -- and pick the value up on the next scheduled VEX run.
 *
 * The Debian step extracts the (record, ecosystem, package, urgency) tuples
 * from rawData once, up front, and joins the rows to that. Letting the planner
 * drive from OSVAffectedPackage instead re-read a record's rawData per row
 * (the first version of this step, over Ubuntu's 2.4M rows, ran 30+ minutes).
 *
 * Idempotent: only rows whose distroPriority is still null are touched.
 *
 * Usage:
 *   pnpm migrate:backfill-distro-priority
 */
import 'dotenv/config';
import { closeDb, prisma } from '../db/client.js';

async function main() {
  const ubuntu = await prisma.$executeRawUnsafe(`
    UPDATE "OSVVulnerability" o
       SET "distroPriority" = r.priority
      FROM (
        SELECT o2.id,
               (SELECT lower(btrim(s->>'score'))
                  FROM jsonb_array_elements(o2."rawData"->'severity') WITH ORDINALITY AS e(s, i)
                 WHERE s->>'type' = 'Ubuntu'
                 ORDER BY i
                 LIMIT 1) AS priority
          FROM "OSVVulnerability" o2
         WHERE o2.ecosystem LIKE 'Ubuntu%'
           AND o2."distroPriority" IS NULL
           AND jsonb_typeof(o2."rawData"->'severity') = 'array'
      ) r
     WHERE o.id = r.id
       AND r.priority IN ('negligible', 'low', 'medium', 'high', 'critical')
  `);
  console.log(`  Ubuntu: distroPriority set on ${ubuntu} OSV record(s).`);

  const debian = await prisma.$executeRawUnsafe(`
    WITH urgencies AS MATERIALIZED (
      SELECT DISTINCT ON (o.id, a->'package'->>'ecosystem', a->'package'->>'name')
             o.id AS "vulnerabilityId",
             a->'package'->>'ecosystem' AS ecosystem,
             a->'package'->>'name' AS "packageName",
             lower(btrim(a->'ecosystem_specific'->>'urgency')) AS urgency
        FROM "OSVVulnerability" o,
             jsonb_array_elements(o."rawData"->'affected') a
       WHERE o.ecosystem LIKE 'Debian%'
         AND jsonb_typeof(o."rawData"->'affected') = 'array'
         AND lower(btrim(a->'ecosystem_specific'->>'urgency'))
             IN ('unimportant', 'low', 'medium', 'high', 'end-of-life', 'not yet assigned')
    )
    UPDATE "OSVAffectedPackage" p
       SET "distroPriority" = u.urgency
      FROM urgencies u
     WHERE p."vulnerabilityId" = u."vulnerabilityId"
       AND p.ecosystem = u.ecosystem
       AND p."packageName" = u."packageName"
       AND p."distroPriority" IS NULL
  `);
  console.log(`  Debian: distroPriority set on ${debian} affected-package row(s).`);

  // <cve> is a single object or an array of them, depending on how many CVEs
  // the definition lists (fast-xml-parser only makes an array for repeats).
  const redHat = await prisma.$executeRawUnsafe(`
    UPDATE "AdvisoryVulnerability" v
       SET "distroPriority" = lower(btrim(c->>'@_impact'))
      FROM "AdvisoryVulnerability" v2,
           jsonb_array_elements(
             CASE jsonb_typeof(v2."rawData"->'metadata'->'advisory'->'cve')
               WHEN 'array' THEN v2."rawData"->'metadata'->'advisory'->'cve'
               WHEN 'object' THEN jsonb_build_array(v2."rawData"->'metadata'->'advisory'->'cve')
               ELSE '[]'::jsonb
             END) c
     WHERE v.id = v2.id
       AND v.source = 'red-hat'
       AND v."cveId" IS NOT NULL
       AND v."distroPriority" IS NULL
       AND c->>'#text' = v."cveId"
       AND lower(btrim(c->>'@_impact')) IN ('critical', 'important', 'moderate', 'low')
  `);
  console.log(`  Red Hat: distroPriority set on ${redHat} advisory row(s).`);
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
