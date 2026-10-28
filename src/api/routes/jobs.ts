import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { resolveJob } from '../../jobs/registry.js';
import { getJobRunner } from '../../jobs/runner.js';
import { setEnabled } from '../../jobs/config.js';

const enableSchema = z.object({
  enabled: z.boolean(),
});

export default async function jobsRoute(fastify: FastifyInstance) {
  // Manual trigger: queued with the scheduled jobs, started when a slot is
  // free. Works regardless of enabled state.
  fastify.post<{ Params: { source: string } }>('/jobs/:source/run', async (request, reply) => {
    const { source } = request.params;

    const def = await resolveJob(source);
    if (!def) {
      return reply.status(404).send({ error: `Unknown job source: ${source}` });
    }
    // The CollectionJob row tracks progress from here: queued, then running.
    const outcome = await getJobRunner().request(def);
    if (outcome === 'busy') {
      return reply.status(409).send({ error: `Job already queued or running: ${source}` });
    }
    if (outcome === 'stopped') {
      return reply.status(503).send({ error: 'Shutting down' });
    }
    if (outcome === 'failed') {
      return reply.status(500).send({ error: `Could not queue job: ${source}` });
    }
    return reply.status(202).send({ status: outcome, source });
  });

  // Enable/disable a job (gates only the scheduler, not manual runs).
  fastify.patch<{ Params: { source: string } }>('/jobs/:source', async (request, reply) => {
    const { source } = request.params;
    const parsed = enableSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: 'Body must be { enabled: boolean }' });
    }
    // Only a job that exists gets a JobConfig row; any name was stored before.
    const def = await resolveJob(source);
    if (!def) {
      return reply.status(404).send({ error: `Unknown job source: ${source}` });
    }

    // Under the job's own name: "osv-Debian:13" switches the job "osv-Debian".
    await setEnabled(def.source, parsed.data.enabled);
    return reply.send({ source: def.source, enabled: parsed.data.enabled });
  });
}
