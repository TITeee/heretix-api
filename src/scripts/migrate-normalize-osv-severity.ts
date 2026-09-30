/**
 * One-time migration: bring existing Vulnerability master rows in line with
 * the OSV severity/CVSS handling in osv-fetcher.ts and the priority merge in
 * nvd-fetcher.ts.
 *
 * Background:
 *   - GHSA's MODERATE (OSV database_specific.severity) was stored verbatim,
 *     although the API's scale -- and heretix-management, which counts
 *     anything else as N/A -- says MEDIUM.
 *   - An earlier OSV importer stored severity[].type ("CVSS_V3", "CVSS_V4",
 *     "Ubuntu") as the severity, and the importer never overwrote an existing
 *     value, so those rows kept it.
 *   - OSV's severity[].score holds only a CVSS vector, so no OSV-only
 *     vulnerability ever had a CVSS score; it is now computed from the vector.
 *   - The NVD importer overwrote severity/CVSS with null for CVEs NVD has not
 *     analyzed, erasing the rating OSV had filled in.
 *
 * For every master row that is affected, NVD's rating wins when NVD has one;
 * otherwise the row gets the OSV-derived values (extractOSVSeverityFields()):
 * a severity only where it has none or an invalid one, a score + vector only
 * where it has no score. Idempotent -- a second run finds nothing to change.
 *
 * Usage:
 *   pnpm migrate:normalize-osv-severity
 */
import 'dotenv/config';
import { closeDb, prisma } from '../db/client.js';
import { extractOSVSeverityFields, type OSVVulnerability } from '../worker/osv-fetcher.js';
import { normalizeSeverity } from '../utils/severity.js';

interface Candidate {
  id: string;
  severity: string | null;
  cvssScore: number | null;
  nvdSeverity: string | null;
  nvdScore: number | null;
  nvdVector: string | null;
  osv: OSVVulnerability[] | null;
}

const CANONICAL_SQL = `('CRITICAL','HIGH','MEDIUM','LOW','NONE','INFORMATIONAL')`;

async function main() {
  // The OSV side is the expensive part (rawData is JSONB), so it is only read
  // for rows that can change: an invalid severity, or a missing severity/score
  // with an OSV record that carries a rating or a vector.
  const candidates = await prisma.$queryRawUnsafe<Candidate[]>(`
    SELECT m.id, m.severity, m."cvssScore",
           n.severity AS "nvdSeverity", n."cvssScore" AS "nvdScore", n."cvssVector" AS "nvdVector",
           (SELECT jsonb_agg(o."rawData") FROM "OSVVulnerability" o
             WHERE o."masterVulnId" = m.id
               AND (o."rawData" ? 'severity' OR o."rawData"->'database_specific' ? 'severity')) AS osv
    FROM "Vulnerability" m
    LEFT JOIN "NVDVulnerability" n ON n."masterVulnId" = m.id
    WHERE (m.severity IS NOT NULL AND m.severity NOT IN ${CANONICAL_SQL})
       OR ((m.severity IS NULL OR m."cvssScore" IS NULL) AND EXISTS (
            SELECT 1 FROM "OSVVulnerability" o
             WHERE o."masterVulnId" = m.id
               AND (o."rawData" ? 'severity' OR o."rawData"->'database_specific' ? 'severity')))
  `);
  console.log(`Found ${candidates.length} candidate master row(s).`);

  const counts = { fromNvd: 0, severityFixed: 0, scoreAdded: 0, cleared: 0, unchanged: 0 };
  for (const c of candidates) {
    const data: { severity?: string | null; cvssScore?: number; cvssVector?: string | null } = {};

    if (c.nvdSeverity !== null || c.nvdScore !== null) {
      // NVD has a rating: it wins, exactly as the NVD importer now applies it.
      if (c.severity !== c.nvdSeverity) data.severity = c.nvdSeverity;
      if (c.cvssScore === null && c.nvdScore !== null) {
        data.cvssScore = c.nvdScore;
        data.cvssVector = c.nvdVector;
      }
      if (Object.keys(data).length > 0) counts.fromNvd++;
    } else {
      const derived = (c.osv ?? []).map(extractOSVSeverityFields);
      const osvSeverity = derived.find(d => d.severity !== null)?.severity ?? null;
      const osvScore = derived.find(d => d.cvssScore !== null);

      const severity = normalizeSeverity(c.severity) ?? osvSeverity;
      if (severity !== c.severity) {
        data.severity = severity;
        if (severity === null) counts.cleared++; else counts.severityFixed++;
      }
      if (c.cvssScore === null && osvScore) {
        data.cvssScore = osvScore.cvssScore!;
        data.cvssVector = osvScore.cvssVector;
        counts.scoreAdded++;
      }
    }

    if (Object.keys(data).length === 0) {
      counts.unchanged++;
      continue;
    }
    await prisma.vulnerability.update({ where: { id: c.id }, data });
  }

  // The OSV source rows' own severity column, which search does not read but
  // which should not keep a value the master rows no longer use.
  const osvRows = await prisma.$executeRawUnsafe(
    `UPDATE "OSVVulnerability" SET severity = 'MEDIUM' WHERE severity = 'MODERATE'`,
  );

  console.log(
    `Done: ${counts.fromNvd} set from NVD, ${counts.severityFixed} severity normalized/filled, ` +
    `${counts.scoreAdded} CVSS score(s) added, ${counts.cleared} invalid severity cleared, ` +
    `${counts.unchanged} already correct; ${osvRows} OSV source row(s) MODERATE -> MEDIUM.`,
  );
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
