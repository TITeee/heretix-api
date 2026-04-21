import 'dotenv/config';
import { prisma } from '../db/client.js';
import { OracleLinuxFetcher } from '../worker/oracle-linux-fetcher.js';
import { runAdvisoryFetcher } from '../worker/advisory-fetcher.js';

async function main() {
  // Optional variant argument: ol9, ol8, ol7, ...
  // e.g.  node dist/scripts/import-oracle-linux.js ol9
  const variant = process.argv[2];
  const source = variant ? `advisory-oracle-linux-${variant}` : 'advisory-oracle-linux';

  if (variant) {
    console.log(`Fetching Oracle Linux OVAL advisories for variant: ${variant}`);
  } else {
    console.log('Fetching Oracle Linux OVAL advisories (full feed)...');
  }

  const job = await prisma.collectionJob.create({
    data: { source, status: 'running', startedAt: new Date() },
  });

  try {
    const result = await runAdvisoryFetcher(new OracleLinuxFetcher(variant));
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
