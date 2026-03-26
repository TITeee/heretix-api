import { PrismaClient } from '@prisma/client';
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
  max: 20, // supports BATCH_CONCURRENCY=20 concurrent batch searches × 3 queries each
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

prisma.$on('warn', (e: any) => {
  logger.warn(e);
});

prisma.$on('error', (e: any) => {
  logger.error(e);
});

export { prisma };
