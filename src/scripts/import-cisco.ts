/**
 * Cisco PSIRT advisory import
 *
 * Usage:
 *   pnpm import:cisco          # Fetch all advisories
 *   pnpm import:cisco latest   # Fetch latest 100 only
 *
 * Required environment variables:
 *   CISCO_CLIENT_ID
 *   CISCO_CLIENT_SECRET
 */
import 'dotenv/config';
import { prisma } from '../db/client.js';
import { CiscoFetcher } from '../worker/cisco-fetcher.js';
import { runAdvisoryFetcher } from '../worker/advisory-fetcher.js';

const [, , mode] = process.argv;

async function main() {
  const isLatest = mode === 'latest';
  console.log(`Fetching Cisco PSIRT advisories (${isLatest ? 'latest 100' : 'all'})...`);

  const job = await prisma.collectionJob.create({
    data: { source: 'advisory-cisco', status: 'running', startedAt: new Date() },
  });

  try {
    const result = await runAdvisoryFetcher(new CiscoFetcher({ mode: isLatest ? 'latest' : 'all' }));
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
