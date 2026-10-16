import 'dotenv/config';
import { prisma } from '../db/client.js';
import { MsrcFetcher } from '../worker/msrc-fetcher.js';
import { runAdvisoryFetcher } from '../worker/advisory-fetcher.js';

// Every MSRC document from March 2021 (the first with fix builds). The daily
// job reads only the recently revised ones, so run this once after deploying,
// and again to rebuild the data.
async function main() {
  console.log('Fetching Windows Server security updates from MSRC (all documents since March 2021)...');

  const job = await prisma.collectionJob.create({
    data: { source: 'advisory-microsoft', status: 'running', startedAt: new Date() },
  });

  try {
    const result = await runAdvisoryFetcher(new MsrcFetcher({ full: true }));
    await prisma.collectionJob.update({
      where: { id: job.id },
      data: {
        status: 'completed',
        completedAt: new Date(),
        totalFetched: result.total,
        totalInserted: result.inserted,
        totalUpdated: result.updated,
        totalFailed: result.failed,
        metadata: { fetchFailed: result.fetchFailed, pruned: result.pruned },
      },
    });
    console.log(`Done: ${result.succeeded} imported, ${result.failed} failed, ${result.fetchFailed} documents failed to fetch, ${result.pruned} pruned (total: ${result.total})`);
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
