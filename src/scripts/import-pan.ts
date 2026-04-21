/**
 * Palo Alto Networks PSIRT advisory import
 *
 * Usage:
 *   pnpm import:pan          # Fetch all advisories (scrape all web pages)
 *   pnpm import:pan latest   # Fetch latest 25 only (RSS)
 */
import 'dotenv/config';
import { prisma } from '../db/client.js';
import { PanFetcher } from '../worker/pan-fetcher.js';
import { runAdvisoryFetcher } from '../worker/advisory-fetcher.js';

const [, , mode] = process.argv;

async function main() {
  const isLatest = mode === 'latest';
  console.log(`Fetching Palo Alto Networks PSIRT advisories (${isLatest ? 'latest RSS' : 'all pages'})...`);

  const job = await prisma.collectionJob.create({
    data: { source: 'advisory-pan', status: 'running', startedAt: new Date() },
  });

  try {
    const result = await runAdvisoryFetcher(new PanFetcher({ mode: isLatest ? 'latest' : 'all' }));
    await prisma.collectionJob.update({
      where: { id: job.id },
      data: {
        status: 'completed',
        completedAt: new Date(),
        totalFetched: result.total,
        totalInserted: result.succeeded,
        totalFailed: result.failed,
      },
    });
    console.log(`Done: ${result.succeeded} imported, ${result.failed} failed (total: ${result.total})`);
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
