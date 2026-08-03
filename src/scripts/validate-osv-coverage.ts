/**
 * OSV ecosystem coverage check
 *
 * Compares each tracked ecosystem's DB count against the live OSV.dev bulk
 * export (the same ZIP the import pipeline itself downloads) to detect
 * ecosystems whose initial full backfill (`pnpm import:osv ecosystem <name>`)
 * never actually completed. That command doesn't create a CollectionJob
 * record, so there's no audit trail of whether/when it ran — this script is
 * the only way to verify completeness after the fact.
 *
 * OSV's bulk-export buckets are keyed by the *base* ecosystem name only
 * (e.g. "Ubuntu", not "Ubuntu:22.04:LTS") — a single ZIP contains every
 * sub-version's vulnerabilities together. DB rows are grouped the same way
 * (by the part before the first ":") so the comparison is apples-to-apples,
 * using COUNT(DISTINCT) rather than summing per-sub-version counts, which
 * would double-count a vulnerability affecting multiple sub-versions.
 *
 * Usage:
 *   pnpm validate:osv-coverage              # check every tracked base ecosystem
 *   pnpm validate:osv-coverage Go PyPI       # check only the named ecosystem(s)
 */
import 'dotenv/config';
import axios from 'axios';
import AdmZip from 'adm-zip';
import { prisma } from '../db/client.js';
import { logger } from '../utils/logger.js';

interface CoverageRow {
  ecosystem: string;
  dbCount: number;
  liveCount: number | null; // null = bucket fetch failed (404 or error)
}

function baseEcosystem(ecosystem: string): string {
  const idx = ecosystem.indexOf(':');
  return idx === -1 ? ecosystem : ecosystem.slice(0, idx);
}

async function fetchLiveCount(ecosystem: string): Promise<number | null> {
  const url = `https://storage.googleapis.com/osv-vulnerabilities/${encodeURIComponent(ecosystem)}/all.zip`;
  try {
    const { data } = await axios.get<ArrayBuffer>(url, { responseType: 'arraybuffer', timeout: 300000 });
    const zip = new AdmZip(Buffer.from(data));
    return zip.getEntries().filter(e => e.entryName.endsWith('.json')).length;
  } catch (err) {
    if (axios.isAxiosError(err) && err.response?.status === 404) {
      logger.warn({ ecosystem }, 'No GCS bucket for this base ecosystem name');
      return null;
    }
    logger.error({ err, ecosystem }, 'Failed to fetch live ecosystem ZIP');
    return null;
  }
}

async function main() {
  const requested = process.argv.slice(2);

  const dbRows = await prisma.$queryRaw<{ ecosystem: string; count: bigint }[]>`
    SELECT ecosystem, COUNT(DISTINCT "vulnerabilityId") AS count
    FROM "OSVAffectedPackage"
    WHERE ecosystem IS NOT NULL
    GROUP BY ecosystem
  `;

  // Group DB rows by base ecosystem (e.g. all "Ubuntu:*" rows collapse into "Ubuntu"),
  // re-querying with a prefix match to get a correctly deduplicated total rather than
  // summing the per-sub-version counts (which would double-count shared vulnerabilities).
  const baseNames = [...new Set(dbRows.map(r => baseEcosystem(r.ecosystem)))]
    .filter(b => requested.length === 0 || requested.includes(b));

  console.log(`Checking ${baseNames.length} base ecosystem(s)...\n`);

  const results: CoverageRow[] = [];
  for (const base of baseNames.sort()) {
    const [{ count }] = await prisma.$queryRaw<{ count: bigint }[]>`
      SELECT COUNT(DISTINCT "vulnerabilityId") AS count
      FROM "OSVAffectedPackage"
      WHERE ecosystem = ${base} OR ecosystem LIKE ${base + ':%'}
    `;
    const dbCount = Number(count);

    process.stdout.write(`  ${base}... `);
    const liveCount = await fetchLiveCount(base);
    console.log(liveCount === null ? 'fetch failed' : `${liveCount} live`);

    results.push({ ecosystem: base, dbCount, liveCount });
  }

  console.log('\n' + '='.repeat(70));
  console.log('OSV ECOSYSTEM COVERAGE REPORT');
  console.log('='.repeat(70));
  console.log(
    'Ecosystem'.padEnd(20) + 'DB'.padStart(10) + 'Live'.padStart(10) + 'Fill %'.padStart(10),
  );

  const sorted = [...results].sort((a, b) => {
    const fillA = a.liveCount ? a.dbCount / a.liveCount : 1;
    const fillB = b.liveCount ? b.dbCount / b.liveCount : 1;
    return fillA - fillB;
  });

  for (const r of sorted) {
    const fillPct = r.liveCount ? ((r.dbCount / r.liveCount) * 100).toFixed(1) + '%' : 'n/a';
    const flag = r.liveCount !== null && r.dbCount / r.liveCount < 0.95 ? '  <-- incomplete' : '';
    console.log(
      r.ecosystem.padEnd(20) +
      String(r.dbCount).padStart(10) +
      (r.liveCount === null ? 'n/a' : String(r.liveCount)).padStart(10) +
      fillPct.padStart(10) +
      flag,
    );
  }
  console.log('='.repeat(70));

  const incomplete = sorted.filter(r => r.liveCount !== null && r.dbCount / r.liveCount < 0.95);
  console.log(`\n${incomplete.length} of ${sorted.length} ecosystems are below 95% fill.`);
  if (incomplete.length > 0) {
    console.log('Re-backfill with: pnpm import:osv ecosystem <name>');
    console.log(incomplete.map(r => r.ecosystem).join(', '));
  }

  await prisma.$disconnect();
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
