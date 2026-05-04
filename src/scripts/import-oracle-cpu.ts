import 'dotenv/config';
import { prisma } from '../db/client.js';
import { OracleCpuFetcher } from '../worker/oracle-cpu-fetcher.js';
import { runAdvisoryFetcher } from '../worker/advisory-fetcher.js';

// Optional: pass "latest" as arg to import only the most recent CPU
const latestOnly = process.argv[2] === 'latest';

async function main() {
  console.log(`Fetching Oracle Critical Patch Update advisories${latestOnly ? ' (latest only)' : ''}...`);

  const job = await prisma.collectionJob.create({
    data: { source: 'advisory-oracle-cpu', status: 'running', startedAt: new Date() },
  });

  try {
    const fetcher = new OracleCpuFetcher({ latestOnly });
    const result = await runAdvisoryFetcher(fetcher);
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
