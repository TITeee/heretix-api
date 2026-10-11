import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { CATALOG_ENTRIES } from '../../config/product-catalog.js';
import { catalogListing, searchCatalog } from '../../utils/catalog-search.js';

const catalogSchema = z.object({
  q: z.string().optional(),
  category: z.enum(['network', 'middleware', 'database', 'devops', 'application']).optional(),
  // The picker asks for no limit and shows an empty box as the whole catalog, so the default is the most allowed.
  limit: z.coerce.number().int().positive().max(200).default(200),
});

/**
 * The product catalog (src/config/product-catalog.ts) for a picker. In memory, so
 * it is cheap enough to call on every keystroke.
 */
export default async function catalogRoute(fastify: FastifyInstance) {
  fastify.get('/catalog', async (request) => {
    const params = catalogSchema.parse(request.query);
    const found = searchCatalog(CATALOG_ENTRIES, params.q, params.category);
    return { total: found.length, entries: found.slice(0, params.limit).map(catalogListing) };
  });
}
