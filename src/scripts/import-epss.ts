/**
 * Script to import EPSS scores
 *
 * Usage:
 *   pnpm import:epss full [YYYY-MM-DD]   # Fetch the daily dataset and apply it to the master table
 *   pnpm import:epss cve CVE-2021-44228  # Update the EPSS score for a single CVE
 */

import 'dotenv/config';
import { logger } from '../utils/logger.js';
import { prisma } from '../db/client.js';
import { fullImportEPSS, fetchEPSSForCVE, importEPSSData } from '../worker/epss-fetcher.js';

const [, , command = 'full', arg] = process.argv;

async function main() {
  switch (command) {
    case 'full': {
      logger.info({ date: arg ?? 'today' }, 'Starting EPSS full import');
      const job = await prisma.collectionJob.create({
        data: { source: 'epss', status: 'running', startedAt: new Date() },
      });
      try {
        const result = await fullImportEPSS(arg);
        await prisma.collectionJob.update({
          where: { id: job.id },
          data: { status: 'completed', completedAt: new Date(), totalUpdated: result.updated },
        });
        logger.info(result, 'EPSS import finished');
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
    case 'cve': {
      if (!arg) {
        console.error('CVE ID is required: pnpm import:epss cve CVE-YYYY-NNNNN');
        process.exit(1);
      }
      const score = await fetchEPSSForCVE(arg);
      if (!score) {
        console.log(`No EPSS data found for ${arg}`);
      } else {
        await importEPSSData([{ cve: arg, epss: score.epss, percentile: score.percentile }]);
        console.log(`Updated ${arg}: epss=${score.epss}, percentile=${score.percentile}`);
      }
      break;
    }
    default:
      console.error(`Unknown command: ${command}`);
      console.error('Usage: pnpm import:epss [full [YYYY-MM-DD]|cve <CVE-ID>]');
      process.exit(1);
  }

  await prisma.$disconnect();
}

main().catch(err => {
  logger.error(err, 'EPSS import failed');
  process.exit(1);
});
