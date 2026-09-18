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
