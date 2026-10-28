/**
 * Fastify's trustProxy from TRUST_PROXY. Unset (the default) trusts no proxy, so the
 * rate limits key on the connecting address and an X-Forwarded-For sent by a client
 * is ignored. Behind a TLS reverse proxy every request connects from the proxy, and
 * the limits would count all clients as one: set it to the proxy's address (or a
 * comma-separated list, CIDR allowed), or to "true" to trust whatever connects.
 */
export function trustProxyFromEnv(raw: string | undefined): boolean | string[] {
  const value = raw?.trim() ?? '';
  if (value === '' || value === 'false') return false;
  if (value === 'true') return true;
  return value.split(',').map(a => a.trim()).filter(Boolean);
}
