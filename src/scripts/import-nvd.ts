import 'dotenv/config';
import {
  fetchNVDById,
  fetchNVDByDateRange,
  importNVDData,
  batchImportNVD,
  importNVDByDateRange,
  fullDownloadNVD,
} from '../worker/nvd-fetcher.js';
import { logger } from '../utils/logger.js';
import { prisma } from '../db/client.js';

const command = process.argv[2];
const args = process.argv.slice(3);

async function main() {
  switch (command) {
    case 'full': {
      // Initial full download (mirror all records)
      // If a previous run was interrupted, pass the job ID to resume
      const resumeJobId = args[0]; // optional
      console.log('Starting NVD full download...');
      if (resumeJobId) {
        console.log(`Resuming from job: ${resumeJobId}`);
      }
      const result = await fullDownloadNVD(resumeJobId);
      console.log(`Done: ${result.succeeded} imported, ${result.failed} failed (total: ${result.total})`);
      break;
    }

    case 'update': {
      // Incremental update: fetch from the completion date of the last CollectionJob
      const lastJob = await prisma.collectionJob.findFirst({
        where: { source: 'nvd', status: 'completed' },
        orderBy: { completedAt: 'desc' },
      });

      const startDate = lastJob?.completedAt ?? new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      const endDate = new Date();

      console.log(`Fetching NVD updates from ${startDate.toISOString()} to ${endDate.toISOString()}...`);
      const items = await fetchNVDByDateRange(startDate, endDate, { useLastMod: true });
      console.log(`Fetched ${items.length} CVEs, importing...`);
      const result = await batchImportNVD(items);
      console.log(`Done: ${result.succeeded} imported, ${result.failed} failed`);
      break;
    }

    case 'cve': {
      // Import a single CVE
      const cveId = args[0];
      if (!cveId) {
        console.error('Usage: import:nvd cve <CVE-ID>');
        process.exit(1);
      }
      console.log(`Fetching ${cveId}...`);
      const item = await fetchNVDById(cveId);
      await importNVDData(item);
      console.log(`Imported: ${cveId}`);
      break;
    }

    case 'year': {
      // Import by calendar year (e.g., pnpm import:nvd year 2024)
      const yearStr = args[0];
      if (!yearStr || !/^\d{4}$/.test(yearStr)) {
        console.error('Usage: import:nvd year <YYYY>');
        process.exit(1);
      }
      const year = parseInt(yearStr, 10);
      const start = new Date(`${year}-01-01T00:00:00Z`);
      const yearEnd = new Date(`${year}-12-31T23:59:59Z`);
      const end = yearEnd < new Date() ? yearEnd : new Date();
      console.log(`Fetching NVD CVEs published in ${year}...`);
      const items = await fetchNVDByDateRange(start, end);
      console.log(`Fetched ${items.length} CVEs, importing...`);
      const result = await batchImportNVD(items);
      console.log(`Done: ${result.succeeded} imported, ${result.failed} failed`);
      break;
    }

    case 'range': {
      // Import by date range
      const startStr = args[0];
      const endStr = args[1];
      if (!startStr || !endStr) {
        console.error('Usage: import:nvd range <YYYY-MM-DD> <YYYY-MM-DD>');
        process.exit(1);
      }
      const start = new Date(startStr);
      const end = new Date(endStr);
      if (isNaN(start.getTime()) || isNaN(end.getTime())) {
        console.error('Invalid date format. Use YYYY-MM-DD.');
        process.exit(1);
      }
      console.log(`Importing NVD CVEs published between ${startStr} and ${endStr}...`);
      const result = await importNVDByDateRange(start, end);
      console.log(`Done: ${result.succeeded} imported, ${result.failed} failed (total fetched: ${result.total})`);
      break;
    }

    default:
      console.error(`Unknown command: ${command}`);
      console.error('Usage:');
      console.error('  pnpm import:nvd full [resume-job-id]   # Full mirror (resumable)');
      console.error('  pnpm import:nvd update                 # Incremental update since last run');
      console.error('  pnpm import:nvd cve <CVE-ID>           # Single CVE');
      console.error('  pnpm import:nvd year <YYYY>             # Single year');
      console.error('  pnpm import:nvd range <start> <end>    # Date range (YYYY-MM-DD)');
      process.exit(1);
  }
}

main()
  .catch(err => {
    logger.error(err, 'import:nvd failed');
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
