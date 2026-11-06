import 'dotenv/config';
import { logger } from '../utils/logger.js';
import { prisma } from '../db/client.js';
import axios from 'axios';
import { OSV_ECOSYSTEMS_URL, osvBucketName, resolveOsvEcosystem } from '../jobs/osv-bucket.js';
import {
  fetchOSVById,
  queryOSVByPackage,
  importOSVData,
  batchImportOSV,
  importOSVEcosystemStreaming,
  importOSVEcosystemDelta,
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
 * The bucket to import for a typed ecosystem name, checked against OSV's list. A name that is
 * not on the list exits with what to type instead; if the list cannot be fetched the name is
 * used as given (OSV answers 404 for a wrong one).
 */
async function checkedBucket(input: string): Promise<string> {
  let official: string[];
  try {
    const res = await axios.get<string>(OSV_ECOSYSTEMS_URL, { responseType: 'text', timeout: 30000 });
    official = String(res.data).split('\n').map((l) => l.trim()).filter((l) => l && l !== '[EMPTY]');
  } catch {
    logger.warn('Could not fetch the list of OSV ecosystems; using the name as given');
    return osvBucketName(input);
  }
  const resolved = resolveOsvEcosystem(input, official);
  if (!resolved.ok) {
    logger.error(resolved.message);
    process.exit(1);
  }
  return resolved.bucket;
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
    logger.info('  pnpm import:osv ecosystem <ecosystem>      # Import entire ecosystem (full)');
    logger.info('  pnpm import:osv update <ecosystem>         # Delta update since last run (e.g. npm, PyPI)');
    logger.info('  pnpm import:osv update <ecosystem> --since=YYYY-MM-DD   # ...or since that day (backfill)');
    logger.info('  pnpm import:osv id <osv-id>                # Import specific vulnerability');
    logger.info('');
    logger.info('Examples:');
    logger.info('  pnpm import:osv sample');
    logger.info('  pnpm import:osv package npm lodash');
    logger.info('  pnpm import:osv package PyPI requests');
    logger.info('  pnpm import:osv ecosystem npm              # Full import of all npm vulnerabilities');
    logger.info('  pnpm import:osv update npm                 # Delta update for npm since last run');
    logger.info('  pnpm import:osv id GHSA-67hx-6x53-jw92');
    process.exit(1);
  }

  const command = args[0];

  try {
    switch (command) {
      case 'sample':
        await importSampleVulnerabilities();
        break;

      case 'ecosystem': {
        if (args.length < 2) {
          logger.error('Missing argument: ecosystem required');
          process.exit(1);
        }
        // "Ubuntu:22.04:LTS" is the "Ubuntu" bucket: OSV stopped writing per-release files in 2024.
        const ecosystem = await checkedBucket(args[1]);
        // Tracked under a distinct 'osv-full-<ecosystem>' source (not 'osv-<ecosystem>',
        // which is the daily delta job) so this doesn't clobber the delta job's dashboard
        // status. Recorded so completeness can be verified later — this command used to
        // leave no trace at all, which was the whole reason a partial/interrupted full
        // import could silently start feeding the delta job forever without anyone
        // noticing the initial backfill never actually finished (see ACCURACY history /
        // validate-osv-coverage.ts).
        const job = await prisma.collectionJob.create({
          data: { source: `osv-full-${ecosystem}`, status: 'running', startedAt: new Date() },
        });

        try {
          // ecosystem command: streaming import of entire ecosystem (memory-efficient)
          const ecosystemResult = await importOSVEcosystemStreaming(ecosystem);

          await prisma.collectionJob.update({
            where: { id: job.id },
            data: {
              status: 'completed',
              completedAt: new Date(),
              totalFetched: ecosystemResult.total,
              totalInserted: ecosystemResult.succeeded,
              totalFailed: ecosystemResult.failed,
            },
          });

          console.log(`Done: ${ecosystemResult.succeeded} imported, ${ecosystemResult.failed} failed (total: ${ecosystemResult.total})`);
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

      case 'package':
        if (args.length < 2) {
          logger.error('Missing argument: ecosystem required');
          process.exit(1);
        }
        // package command: import by package name if provided, otherwise entire ecosystem
        await importByPackage(args[1], args[2]);
        break;

      case 'id': {
        if (args.length < 2) {
          logger.error('Missing argument: OSV ID required');
          process.exit(1);
        }
        const osvData = await fetchOSVById(args[1]);
        await importOSVData(osvData);
        logger.info({ osvId: args[1] }, 'Successfully imported vulnerability');
        break;
      }

      case 'update': {
        if (args.length < 2) {
          logger.error('Missing argument: ecosystem required (e.g. npm, PyPI)');
          process.exit(1);
        }
        // "Debian:13" and "Debian" are the same job: the releases of a distro share one bucket.
        const ecosystem = await checkedBucket(args[1]);
        const sourceKey = `osv-${ecosystem}`;

        // --since=YYYY-MM-DD starts from that day instead of the last completed run, to
        // backfill what an earlier run missed (a job that read a frozen bucket for months).
        const sinceArg = args.find((a) => a.startsWith('--since='))?.slice('--since='.length);
        const sinceOverride = sinceArg ? new Date(sinceArg) : null;
        if (sinceOverride && Number.isNaN(sinceOverride.getTime())) {
          logger.error({ sinceArg }, 'Invalid --since, expected YYYY-MM-DD');
          process.exit(1);
        }

        const lastJob = await prisma.collectionJob.findFirst({
          where: { source: sourceKey, status: 'completed' },
          orderBy: { completedAt: 'desc' },
        });
        const since = sinceOverride ?? lastJob?.completedAt ?? new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

        logger.info({ ecosystem, since }, 'Starting OSV delta update');

        const job = await prisma.collectionJob.create({
          data: { source: sourceKey, status: 'running', startedAt: new Date() },
        });

        try {
          const result = await importOSVEcosystemDelta(ecosystem, since);

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

          console.log(`Done: ${result.succeeded} imported, ${result.skipped} skipped, ${result.failed} failed (total: ${result.total})`);
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
