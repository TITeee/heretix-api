import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { resolveJob } from '../../jobs/registry.js';
import { executeJob, isJobRunning } from '../../jobs/executor.js';
import { setEnabled } from '../../jobs/config.js';

const enableSchema = z.object({
  enabled: z.boolean(),
});

export default async function jobsRoute(fastify: FastifyInstance) {
  // Manual trigger: fire-and-forget. Works regardless of enabled state.
  fastify.post<{ Params: { source: string } }>('/jobs/:source/run', async (request, reply) => {
    const { source } = request.params;

    const def = await resolveJob(source);
    if (!def) {
      return reply.status(404).send({ error: `Unknown job source: ${source}` });
    }
    if (isJobRunning(source)) {
      return reply.status(409).send({ error: `Job already running: ${source}` });
    }

    // Fire-and-forget; the CollectionJob row tracks progress.
    void executeJob(def);
    return reply.status(202).send({ status: 'started', source });
  });

  // Enable/disable a job (gates only the scheduler, not manual runs).
  fastify.patch<{ Params: { source: string } }>('/jobs/:source', async (request, reply) => {
    const { source } = request.params;
    const parsed = enableSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: 'Body must be { enabled: boolean }' });
    }

    await setEnabled(source, parsed.data.enabled);
    return reply.send({ source, enabled: parsed.data.enabled });
  });
}
