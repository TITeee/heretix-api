import 'dotenv/config';
import type { FastifyInstance } from 'fastify';
import { startServer } from './api/server.js';
import { startScheduler, stopScheduler } from './scheduler.js';
import { reconcileOrphanedJobs } from './jobs/executor.js';
import { closeDb } from './db/client.js';
import { logger } from './utils/logger.js';

// Long enough for an in-flight HTTP request to finish, short enough to stay
// under a container runtime's own grace period before it escalates to SIGKILL.
const SHUTDOWN_TIMEOUT_MS = 10_000;

let shuttingDown = false;

/**
 * Stop firing jobs, drain HTTP, release the DB pool.
 *
 * A job already running is deliberately not waited on: imports take minutes,
 * well past any grace period, and its half-written CollectionJob row is
 * reconciled by reconcileOrphanedJobs() on the next boot. Without this, a
 * `docker compose restart` dropped in-flight requests and left Postgres
 * connections to time out on their own.
 */
async function shutdown(server: FastifyInstance, signal: string, exitCode = 0): Promise<void> {
  if (shuttingDown) return;
  shuttingDown = true;
  logger.info({ signal }, 'Shutting down');
  process.exitCode = exitCode;

  // Only the timeout path calls process.exit(). Releasing the cron timers, the
  // HTTP server and the DB pool leaves nothing holding the event loop, so the
  // process exits on its own with the code set above -- and pino's transport
  // (a worker thread) gets to flush first. process.exit() here would race it
  // and truncate exactly the shutdown lines worth having.
  //
  // closeDb() has to actually close the pool for that to be true: prisma's
  // own $disconnect() doesn't touch it (see closeDb()'s own comment), so a
  // pooled socket from any recent query kept the event loop alive until
  // node-postgres's own 10s idle timeout closed it -- indistinguishable from,
  // and often slower than, the forced timeout below.
  const timer = setTimeout(() => {
    logger.error({ timeoutMs: SHUTDOWN_TIMEOUT_MS }, 'Shutdown timed out, forcing exit');
    process.exit(exitCode || 1);
  }, SHUTDOWN_TIMEOUT_MS);
  timer.unref();

  try {
    await stopScheduler();
    await server.close();
    await closeDb();
    logger.info('Shutdown complete');
  } catch (err) {
    logger.error({ err }, 'Shutdown failed');
    process.exitCode = 1;
  }
}

async function main() {
  try {
    logger.info('Starting Heretix API...');
    const server = await startServer();
    await reconcileOrphanedJobs();
    startScheduler();

    for (const signal of ['SIGTERM', 'SIGINT'] as const) {
      process.on(signal, () => void shutdown(server, signal));
    }

    // Both handlers exit rather than continue. Every fire-and-forget path in
    // this process (cron ticks, the manual job trigger) now guards itself, so
    // anything still reaching here is an unanticipated bug, and carrying on
    // with unknown state risks writing bad data rather than just dropping a
    // request. Logging first is the point -- Node's own default would exit on
    // an unhandled rejection with far less context.
    process.on('unhandledRejection', (reason) => {
      logger.fatal({ reason }, 'Unhandled promise rejection');
      void shutdown(server, 'unhandledRejection', 1);
    });
    process.on('uncaughtException', (err) => {
      logger.fatal({ err }, 'Uncaught exception');
      void shutdown(server, 'uncaughtException', 1);
    });
  } catch (error) {
    logger.error(error, 'Failed to start server');
    process.exit(1);
  }
}

main();
