import 'dotenv/config';
import { prisma } from '../db/client.js';
import { RedHatFetcher } from '../worker/redhat-fetcher.js';
import { runAdvisoryFetcher } from '../worker/advisory-fetcher.js';

const VARIANTS = ['rhel9', 'rhel8'] as const;

async function main() {
  const requested = process.argv[2] as string | undefined;
  const variants = requested ? [requested] : [...VARIANTS];

  for (const variant of variants) {
    const source = `advisory-redhat-${variant}`;
    console.log(`Fetching Red Hat OVAL advisories for ${variant}...`);

    const job = await prisma.collectionJob.create({
      data: { source, status: 'running', startedAt: new Date() },
    });

    try {
      const result = await runAdvisoryFetcher(new RedHatFetcher(variant));
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
      console.log(`Done (${variant}): ${result.succeeded} imported, ${result.failed} failed (total: ${result.total})`);
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
  }

  await prisma.$disconnect();
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
