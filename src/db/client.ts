import { PrismaClient, type Prisma } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import pg from 'pg';
import { pino } from 'pino';

const logger = pino({ name: 'prisma' });

// Parse connection info from DATABASE_URL
const dbUrl = new URL(process.env.DATABASE_URL!);

// PostgreSQL connection pool
const pool = new pg.Pool({
  host: dbUrl.hostname,
  port: parseInt(dbUrl.port || '5432'),
  user: dbUrl.username,
  password: dbUrl.password,
  database: dbUrl.pathname.slice(1), // Remove leading /
  ssl: false,
  // A single /search issues up to 4 queries in parallel (OSV, NVD, advisory,
  // CNA) and the batch endpoint runs BATCH_CONCURRENCY of those at a time, so
  // peak demand is a multiple of this number, not equal to it -- the previous
  // "20 batch searches × 3 queries" comment stopped being true when the CNA
  // path was added. pg queues the excess rather than failing, which is fine
  // as long as no single job holds a large share of the pool for minutes at a
  // time (see importEPSSData()). Raise for a bigger Postgres or a higher
  // BATCH_CONCURRENCY.
  max: Number(process.env.DATABASE_POOL_MAX ?? 20),
});

// Prisma adapter
const adapter = new PrismaPg(pool);

const prisma = new PrismaClient({
  adapter,
  log: [
    { level: 'warn', emit: 'event' },
    { level: 'error', emit: 'event' },
  ],
});

prisma.$on('warn', (e: Prisma.LogEvent) => {
  logger.warn(e);
});

prisma.$on('error', (e: Prisma.LogEvent) => {
  logger.error(e);
});

export { prisma };

/**
 * Disconnect Prisma and close the underlying connection pool.
 *
 * prisma.$disconnect() alone does not do this: with a driver adapter, Prisma
 * never created the pool, so it never owns it and never calls pool.end() on
 * disconnect. A pool with any pooled socket left open keeps the event loop
 * alive until node-postgres's own idle timeout (10s by default) closes it --
 * confirmed at 10.35-10.40s per run against this app's pool. A one-shot
 * script (each migrate-*.ts backfill, run once per container boot) does its
 * actual work in well under a second and would then sit idle for that whole
 * stretch, and a graceful server shutdown would race the same wait against
 * SHUTDOWN_TIMEOUT_MS in index.ts. Call this instead of prisma.$disconnect()
 * wherever the process is meant to exit afterward.
 */
export async function closeDb(): Promise<void> {
  await prisma.$disconnect();
  await pool.end();
}
