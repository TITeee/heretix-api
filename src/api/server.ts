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

  // CORS configuration
  await fastify.register(cors, {
    origin: true,
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
