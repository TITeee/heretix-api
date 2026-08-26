import 'dotenv/config';
import { startServer } from './api/server.js';
import { startScheduler } from './scheduler.js';
import { reconcileOrphanedJobs } from './jobs/executor.js';
import { logger } from './utils/logger.js';

async function main() {
  try {
    logger.info('Starting Heretix API...');
    await startServer();
    await reconcileOrphanedJobs();
    startScheduler();
  } catch (error) {
    logger.error(error, 'Failed to start server');
    process.exit(1);
  }
}

main();
