/**
 * Import CNA-declared affected products from CVE Records (cvelistV5).
 *
 * The first run bootstraps from the ~600MB full bundle, restricted to
 * BOOTSTRAP_YEARS. Every later run applies only the hourly delta bundles
 * published since the last completed job, which is a few MB a day.
 *
 * Usage:
 *   pnpm import:cna              # delta if already bootstrapped, else bootstrap
 *   pnpm import:cna --bootstrap  # force a full-bundle pass
 */
import 'dotenv/config';
import { prisma } from '../db/client.js';
import { bootstrapCna, importCnaDelta } from '../worker/cna-importer.js';
import { getDeltaCursor } from '../jobs/executor.js';

// Recent CVEs are where the NVD CPE gap is worst (roughly half of the last
// year's CVEs have no CPE row at all, against a fifth across all time), and
// older records mostly predate the structured `versions` conventions this
// import relies on. Widen this once the measured value justifies it.
const BOOTSTRAP_YEARS = ['2025', '2026'];
const DELTA_FALLBACK_MS = 25 * 60 * 60 * 1000;

async function main() {
  const force = process.argv.includes('--bootstrap');
  const alreadyImported = await prisma.cnaVulnerability.count();
  const bootstrap = force || alreadyImported === 0;

  const job = await prisma.collectionJob.create({
    data: { source: 'cna', status: 'running', startedAt: new Date() },
  });

  try {
    console.log(bootstrap
      ? `Bootstrapping CNA affected data for ${BOOTSTRAP_YEARS.join(', ')} (full bundle download)...`
      : 'Importing CNA affected data (delta bundles)...');

    const result = bootstrap
      ? await bootstrapCna(BOOTSTRAP_YEARS)
      : await importCnaDelta(await getDeltaCursor('cna', DELTA_FALLBACK_MS));

    await prisma.collectionJob.update({
      where: { id: job.id },
      data: {
        status: 'completed',
        completedAt: new Date(),
        totalFetched: result.scanned,
        totalInserted: result.inserted,
        totalUpdated: result.updated,
        totalFailed: result.failed,
        metadata: { bootstrap, rows: result.rows, usable: result.usable, pruned: result.pruned, dropped: result.dropped },
      },
    });

    console.log(
      `Done: ${result.scanned} records scanned, ${result.usable} usable, ` +
      `${result.inserted} inserted, ${result.updated} updated, ${result.pruned} pruned, ${result.failed} failed ` +
      `(${result.rows} affected-product rows)`,
    );
    console.log('Dropped by rule:', JSON.stringify(result.dropped));
  } catch (err) {
    await prisma.collectionJob.update({
      where: { id: job.id },
      data: {
        status: 'failed',
        completedAt: new Date(),
        errorMessage: err instanceof Error ? err.message : String(err),
      },
    });
    throw err;
  } finally {
    await prisma.$disconnect();
  }
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
