import 'dotenv/config';
import { startServer } from './api/server.js';
import { startScheduler } from './scheduler.js';
import { logger } from './utils/logger.js';

async function main() {
  try {
    logger.info('Starting Heretix API...');
    await startServer();
    startScheduler();
  } catch (error) {
    logger.error(error, 'Failed to start server');
    process.exit(1);
  }
}

main();
