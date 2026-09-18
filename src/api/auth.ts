import { timingSafeEqual } from 'node:crypto';
import type { FastifyReply, FastifyRequest } from 'fastify';

function safeEqual(provided: string, configured: string): boolean {
  const a = Buffer.from(provided);
  const b = Buffer.from(configured);
  // timingSafeEqual throws on differing lengths, so that has to be checked
  // first -- it leaks only the key's length, which a comparison loop would
  // leak anyway and which isn't the secret.
  return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * Fastify onRequest hook enforcing the shared API key.
 *
 * Fails closed on every ambiguous case: no key configured on the server, no
 * header, or a header sent more than once (Fastify hands those over as an
 * array, not a string).
 */
export async function requireApiKey(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  const configured = process.env.API_KEY;
  const provided = request.headers['x-api-key'];

  if (!configured || typeof provided !== 'string' || !safeEqual(provided, configured)) {
    return reply.status(401).send({ error: 'Unauthorized' });
  }
}
