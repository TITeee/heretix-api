import 'dotenv/config';
import { prisma } from '../db/client.js';
import { RedHatVexFetcher } from '../worker/redhat-vex-fetcher.js';
import { runAdvisoryFetcher } from '../worker/advisory-fetcher.js';

const source = 'advisory-redhat-vex';

async function main() {
  console.log('Fetching Red Hat CSAF VEX unfixed-vulnerability data...');

  const job = await prisma.collectionJob.create({
    data: { source, status: 'running', startedAt: new Date() },
  });

  try {
    const result = await runAdvisoryFetcher(new RedHatVexFetcher());
    await prisma.collectionJob.update({
      where: { id: job.id },
      data: {
        status: 'completed',
        completedAt: new Date(),
        totalFetched: result.total,
        totalInserted: result.inserted,
        totalUpdated: result.updated,
        totalFailed: result.failed,
        metadata: { fetchFailed: result.fetchFailed },
      },
    });
    console.log(`Done: ${result.succeeded} imported, ${result.failed} failed, ${result.fetchFailed} fetch failed (total: ${result.total})`);
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
  }

  await prisma.$disconnect();
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
