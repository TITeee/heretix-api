import Fastify from 'fastify';
import cors from '@fastify/cors';
import vulnerabilitiesRoute from './routes/vulnerabilities.js';

const PORT = parseInt(process.env.PORT || '3001', 10);

// Global setting to make BigInt JSON-serializable
(BigInt.prototype as any).toJSON = function() {
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

  // Routes (API Key auth registered in the same scope)
  await fastify.register(async (app) => {
    const API_KEY = process.env.API_KEY;
    app.addHook('onRequest', async (request, reply) => {
      const key = request.headers['x-api-key'];
      if (!API_KEY || !key || key !== API_KEY) {
        return reply.status(401).send({ error: 'Unauthorized' });
      }
    });
    await app.register(vulnerabilitiesRoute, { prefix: '/api/v1' });
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
