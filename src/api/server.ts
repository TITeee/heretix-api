import { STATUS_CODES } from 'node:http';
import Fastify, { type FastifyBaseLogger } from 'fastify';
import cors from '@fastify/cors';
import compress from '@fastify/compress';
import rateLimit from '@fastify/rate-limit';
import { ZodError } from 'zod';
import { envInt } from './concurrency-gate.js';
import vulnerabilitiesRoute from './routes/vulnerabilities.js';
import dashboardRoute from './routes/dashboard.js';
import jobsRoute from './routes/jobs.js';
import catalogRoute from './routes/catalog.js';
import { MIN_KEY_LENGTH, requireAdminKey, requireApiKey } from './auth.js';
import { trustProxyFromEnv } from './trust-proxy.js';

const PORT = parseInt(process.env.PORT || '3001', 10);

function warnAboutKeys(log: FastifyBaseLogger): void {
  for (const name of ['API_KEY', 'ADMIN_API_KEY']) {
    const key = process.env[name];
    if (!key) {
      log.warn(`${name} is not set: ${name === 'API_KEY' ? 'every API request' : 'the job endpoints and the dashboard data'} will be refused with 401`);
    } else if (key.length < MIN_KEY_LENGTH) {
      log.warn(`${name} is shorter than ${MIN_KEY_LENGTH} characters; generate one with: openssl rand -hex 32`);
    }
  }
}

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
    trustProxy: trustProxyFromEnv(process.env.TRUST_PROXY),
  });
  warnAboutKeys(fastify.log);

  // A request the client got wrong is told what was wrong with it; anything else is
  // logged here and answered with a bare 500. Fastify's own handler sent every error's
  // message to the client: a failed input check came back as 500 with the validator's
  // dump, and a database error with Postgres' text.
  fastify.setErrorHandler((err, request, reply) => {
    if (err instanceof ZodError) {
      return reply.status(400).send({
        error: 'Invalid request',
        issues: err.issues.map(i => ({ path: i.path.join('.'), message: i.message })),
      });
    }
    // Errors Fastify and its plugins raise on purpose (malformed JSON, a body too
    // large, a rate limit) carry their status code and a message meant for the client.
    const { statusCode: status, message } = err as { statusCode?: number; message?: string };
    if (status !== undefined && status >= 400 && status < 500) {
      return reply.status(status).send({ statusCode: status, error: STATUS_CODES[status], message });
    }
    request.log.error({ err }, 'request failed');
    return reply.status(500).send({ error: 'Internal Server Error' });
  });

  // Headers for every response. The CSP closes a JSON response to scripts and frames
  // altogether; the dashboard page sets its own, which this leaves alone.
  fastify.addHook('onSend', async (_request, reply) => {
    reply.header('x-content-type-options', 'nosniff');
    reply.header('x-frame-options', 'DENY');
    reply.header('referrer-policy', 'no-referrer');
    if (!reply.hasHeader('content-security-policy')) {
      reply.header('content-security-policy', "default-src 'none'; frame-ancestors 'none'");
    }
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

  // Compress responses for a client that asks for it (Accept-Encoding). A batch search over
  // a host with outdated kernels is over 100 MB of JSON, mostly the same CVE texts repeated
  // for each package, and gzip brings that to under a third. Go (heretix-cli) and Node's
  // fetch (heretix-management) ask for gzip and decompress on their own, so neither needed a
  // change. Level 1: the fastest, and most of the saving; compression runs on libuv's thread
  // pool, not on the event loop. Brotli is left off, being several times slower.
  await fastify.register(compress, {
    global: true,
    encodings: ['gzip', 'deflate'],
    threshold: 1024,
    zlibOptions: { level: 1 },
  });

  // Rate limit per client address, so a leaked key or a runaway client cannot keep
  // the API busy. heretix-management reaches this API from one address with one
  // shared key, so a limit cannot tell it from a misuser: the ceiling is set high
  // enough for normal use (autocomplete, scans) and is a backstop. The heavier
  // protection is the cap on concurrent batch searches (see routes/vulnerabilities.ts).
  // RATE_LIMIT_MAX=0 turns it off.
  const rateLimitMax = envInt('RATE_LIMIT_MAX', 1200);
  if (rateLimitMax > 0) {
    await fastify.register(rateLimit, { global: true, max: rateLimitMax, timeWindow: '1 minute' });
  }

  // Health check (monitoring polls it; never limited)
  fastify.get('/health', { config: { rateLimit: false } }, async () => {
    return { status: 'ok', timestamp: new Date().toISOString() };
  });

  // The dashboard HTML shell is public; the data endpoint it calls
  // (/api/v1/import-status) enforces the admin key itself -- see dashboard.ts.
  await fastify.register(dashboardRoute);

  // Routes (API Key auth registered in the same scope)
  await fastify.register(async (app) => {
    app.addHook('onRequest', requireApiKey);
    await app.register(vulnerabilitiesRoute, { prefix: '/api/v1' });
    await app.register(catalogRoute, { prefix: '/api/v1' });
  });

  // Running and switching jobs takes the admin key (see auth.ts).
  await fastify.register(async (app) => {
    app.addHook('onRequest', requireAdminKey);
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
