import { timingSafeEqual } from 'node:crypto';
import type { FastifyReply, FastifyRequest } from 'fastify';

/** Below this many characters a key is reported at startup as too weak (`openssl rand -hex 32` gives 64). */
export const MIN_KEY_LENGTH = 32;

function safeEqual(provided: string, configured: string): boolean {
  const a = Buffer.from(provided);
  const b = Buffer.from(configured);
  // timingSafeEqual throws on differing lengths, so that has to be checked
  // first -- it leaks only the key's length, which a comparison loop would
  // leak anyway and which isn't the secret.
  return a.length === b.length && timingSafeEqual(a, b);
}

// Fails closed on every ambiguous case: no key configured on the server, no
// header, or a header sent more than once (Fastify hands those over as an
// array, not a string).
function keyMatches(request: FastifyRequest, configured: string | undefined): boolean {
  const provided = request.headers['x-api-key'];
  return !!configured && typeof provided === 'string' && safeEqual(provided, configured);
}

/**
 * Fastify onRequest hook enforcing the shared API key: the key heretix-management,
 * heretix-cli and scripts search with.
 */
export async function requireApiKey(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  if (!keyMatches(request, process.env.API_KEY)) {
    return reply.status(401).send({ error: 'Unauthorized' });
  }
}

/**
 * Fastify onRequest hook enforcing the admin key, for running and switching jobs and
 * for the import dashboard's data. It is a key of its own so that the shared key,
 * which sits on every client, cannot start scrapers or stop the imports. API_KEY is
 * not accepted here, and with ADMIN_API_KEY unset these routes are closed.
 */
export async function requireAdminKey(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  if (!keyMatches(request, process.env.ADMIN_API_KEY)) {
    return reply.status(401).send({ error: 'Unauthorized' });
  }
}
