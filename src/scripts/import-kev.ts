/**
 * Script to import the CISA KEV catalog
 *
 * Usage:
 *   pnpm import:kev full    # Fetch the KEV catalog and apply it to the master table
 *   pnpm import:kev stats   # Display KEV statistics from the DB
 */

import 'dotenv/config';
import { logger } from '../utils/logger.js';
import { prisma } from '../db/client.js';
import { fullImportKEV } from '../worker/kev-fetcher.js';

const [, , command = 'full'] = process.argv;

async function stats() {
  const [total, kevCount] = await Promise.all([
    prisma.vulnerability.count(),
    prisma.vulnerability.count({ where: { isKev: true } }),
  ]);
  console.log(`Vulnerability master total : ${total}`);
  console.log(`KEV count                  : ${kevCount}`);
  await prisma.$disconnect();
}

async function main() {
  switch (command) {
    case 'full': {
      logger.info('Starting KEV full import');
      const job = await prisma.collectionJob.create({
        data: { source: 'kev', status: 'running', startedAt: new Date() },
      });
      try {
        const result = await fullImportKEV();
        await prisma.collectionJob.update({
          where: { id: job.id },
          data: { status: 'completed', completedAt: new Date(), totalUpdated: result.updated },
        });
        logger.info(result, 'KEV import finished');
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
      break;
    }
    case 'stats':
      await stats();
      return;
    default:
      console.error(`Unknown command: ${command}`);
      console.error('Usage: pnpm import:kev [full|stats]');
      process.exit(1);
  }

  await prisma.$disconnect();
}

main().catch(err => {
  logger.error(err, 'KEV import failed');
  process.exit(1);
});
