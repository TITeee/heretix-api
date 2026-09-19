import Fastify from 'fastify';
import cors from '@fastify/cors';
import vulnerabilitiesRoute from './routes/vulnerabilities.js';
import dashboardRoute from './routes/dashboard.js';
import jobsRoute from './routes/jobs.js';
import { requireApiKey } from './auth.js';

const PORT = parseInt(process.env.PORT || '3001', 10);

// Global setting to make BigInt JSON-serializable
declare global {
  interface BigInt {
    toJSON(): string;
  }
}

BigInt.prototype.toJSON = function () {
  return this.toString();
};

export async function createServer() {
  const fastify = Fastify({
    logger: {
      transport: {
        target: 'pino-pretty',
        options: {
          colorize: true,
          translateTime: 'SYS:standard',
          ignore: 'pid,hostname',
        },
      },
    },
  });

  // CORS only governs whether a *browser* may read a cross-origin response;
  // it has no effect on server-to-server callers (heretix-management, curl,
  // scripts) regardless of this setting, since those never enforce it.
  // origin: true reflected every request's Origin header, which only matters
  // if a browser-based client ever calls this API cross-origin -- neither
  // known consumer does (heretix-management calls server-side via Prisma/
  // fetch, and the dashboard's own JS calls same-origin). Defaults closed;
  // set ALLOWED_ORIGINS to a comma-separated list to open it for a future
  // browser-based integration.
  const allowedOrigins = (process.env.ALLOWED_ORIGINS ?? '')
    .split(',')
    .map(o => o.trim())
    .filter(Boolean);
  await fastify.register(cors, {
    origin: allowedOrigins.length > 0 ? allowedOrigins : false,
  });

  // Health check
  fastify.get('/health', async () => {
    return { status: 'ok', timestamp: new Date().toISOString() };
  });

  // The dashboard HTML shell is public; the data endpoint it calls
  // (/api/v1/import-status) enforces the API key itself -- see dashboard.ts.
  await fastify.register(dashboardRoute);

  // Routes (API Key auth registered in the same scope)
  await fastify.register(async (app) => {
    app.addHook('onRequest', requireApiKey);
    await app.register(vulnerabilitiesRoute, { prefix: '/api/v1' });
    await app.register(jobsRoute, { prefix: '/api/v1' });
  });

  return fastify;
}

export async function startServer() {
  const fastify = await createServer();

  try {
    await fastify.listen({ port: PORT, host: '0.0.0.0' });
    console.log(`🚀 Server listening on http://localhost:${PORT}`);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }

  return fastify;
}
