import 'dotenv/config';
import { prisma } from '../db/client.js';
import { NginxFetcher } from '../worker/nginx-fetcher.js';
import { runAdvisoryFetcher } from '../worker/advisory-fetcher.js';

async function main() {
  console.log('Fetching nginx security advisories...');

  const job = await prisma.collectionJob.create({
    data: { source: 'advisory-nginx', status: 'running', startedAt: new Date() },
  });

  try {
    const result = await runAdvisoryFetcher(new NginxFetcher());
    await prisma.collectionJob.update({
      where: { id: job.id },
      data: {
        status: 'completed',
        completedAt: new Date(),
        totalFetched: result.total,
        totalInserted: result.inserted,
        totalUpdated: result.updated,
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
