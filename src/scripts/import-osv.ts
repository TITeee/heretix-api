import 'dotenv/config';
import { logger } from '../utils/logger.js';
import { prisma } from '../db/client.js';
import {
  fetchOSVById,
  queryOSVByPackage,
  importOSVData,
  batchImportOSV,
  importOSVEcosystemStreaming,
} from '../worker/osv-fetcher.js';

/**
 * Import sample vulnerabilities (for testing)
 */
async function importSampleVulnerabilities() {
  logger.info('Starting sample OSV import');

  // Import a few well-known vulnerabilities
  const sampleIds = [
    'GHSA-67hx-6x53-jw92', // npm: axios RCE
    'GHSA-c2qf-rxjj-qqgw', // npm: lodash prototype pollution
    'PYSEC-2021-66',       // Python: requests
  ];

  let succeeded = 0;
  let failed = 0;

  for (const osvId of sampleIds) {
    try {
      logger.info({ osvId }, 'Fetching vulnerability');
      const osvData = await fetchOSVById(osvId);

      logger.info({ osvId }, 'Importing vulnerability');
      await importOSVData(osvData);

      succeeded++;
      logger.info({ osvId }, 'Successfully imported vulnerability');
    } catch (error) {
      failed++;
      logger.error({ error, osvId }, 'Failed to import vulnerability');
    }
  }

  logger.info({ total: sampleIds.length, succeeded, failed }, 'Sample import completed');
}

/**
 * Collect vulnerabilities for a specific package
 * If packageName is not specified, collect the entire ecosystem
 */
async function importByPackage(ecosystem: string, packageName?: string) {
  if (!packageName) {
    logger.info({ ecosystem }, 'Importing all vulnerabilities for ecosystem (this may take a while)');
  } else {
    logger.info({ ecosystem, packageName }, 'Importing vulnerabilities for package');
  }

  try {
    const vulnerabilities = await queryOSVByPackage(ecosystem, packageName);

    logger.info({ count: vulnerabilities.length }, 'Found vulnerabilities');

    const result = await batchImportOSV(vulnerabilities);

    logger.info(result, 'Package import completed');
  } catch (error) {
    logger.error({ error, ecosystem, packageName }, 'Failed to import package vulnerabilities');
  }
}

/**
 * Main entry point
 */
async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    logger.info('Usage:');
    logger.info('  pnpm import:osv sample                     # Import sample vulnerabilities');
    logger.info('  pnpm import:osv package <ecosystem> [name] # Import by package (or entire ecosystem)');
    logger.info('  pnpm import:osv ecosystem <ecosystem>      # Import entire ecosystem');
    logger.info('  pnpm import:osv id <osv-id>                # Import specific vulnerability');
    logger.info('');
    logger.info('Examples:');
    logger.info('  pnpm import:osv sample');
    logger.info('  pnpm import:osv package npm lodash');
    logger.info('  pnpm import:osv package PyPI requests');
    logger.info('  pnpm import:osv ecosystem npm              # Import all npm vulnerabilities');
    logger.info('  pnpm import:osv id GHSA-67hx-6x53-jw92');
    process.exit(1);
  }

  const command = args[0];

  try {
    switch (command) {
      case 'sample':
        await importSampleVulnerabilities();
        break;

      case 'ecosystem':
        if (args.length < 2) {
          logger.error('Missing argument: ecosystem required');
          process.exit(1);
        }
        // ecosystem command: streaming import of entire ecosystem (memory-efficient)
        const ecosystemResult = await importOSVEcosystemStreaming(args[1]);
        console.log(`Done: ${ecosystemResult.succeeded} imported, ${ecosystemResult.failed} failed (total: ${ecosystemResult.total})`);
        break;

      case 'package':
        if (args.length < 2) {
          logger.error('Missing argument: ecosystem required');
          process.exit(1);
        }
        // package command: import by package name if provided, otherwise entire ecosystem
        await importByPackage(args[1], args[2]);
        break;

      case 'id':
        if (args.length < 2) {
          logger.error('Missing argument: OSV ID required');
          process.exit(1);
        }
        const osvData = await fetchOSVById(args[1]);
        await importOSVData(osvData);
        logger.info({ osvId: args[1] }, 'Successfully imported vulnerability');
        break;

      default:
        logger.error({ command }, 'Unknown command');
        process.exit(1);
    }

    logger.info('Import completed successfully');
  } catch (error) {
    logger.error({ error }, 'Import failed');
    process.exit(1);
  } finally {
    await prisma.$disconnect();
  }
}

main();
