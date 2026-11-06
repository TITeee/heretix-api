import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { prisma } from '../../db/client.js';
import { resolveJob } from '../../jobs/registry.js';
import { fetchOsvEcosystems } from '../../jobs/osv-ecosystems.js';
import { resolveOsvEcosystem } from '../../jobs/osv-bucket.js';
import { getJobRunner } from '../../jobs/runner.js';
import { setEnabled } from '../../jobs/config.js';
import type { JobDefinition } from '../../jobs/types.js';

const enableSchema = z.object({
  enabled: z.boolean(),
});

const addEcosystemSchema = z.object({ name: z.string().min(1).max(100) });

/** Queue a job the way a Run does: the full load for a source never loaded, the delta after. */
async function runNow(def: JobDefinition) {
  const mode = def.firstLoad && !(await def.firstLoad.isLoaded()) ? 'full' : 'delta';
  return { mode, outcome: await getJobRunner().request(def, mode) } as const;
}

export default async function jobsRoute(fastify: FastifyInstance) {
  // The ecosystems OSV lists, for the dashboard's "add an ecosystem". `added` is true
  // for one that has a job here already (an import ran, or is queued).
  fastify.get('/jobs/osv-ecosystems', async (_request, reply) => {
    const official = await fetchOsvEcosystems();
    if (!official) return reply.status(503).send({ error: "OSV's list of ecosystems could not be fetched" });
    const rows = await prisma.collectionJob.findMany({
      where: { source: { startsWith: 'osv-' } },
      distinct: ['source'],
      select: { source: true },
    });
    const added = new Set(rows.map((r) => r.source.replace(/^osv-(full-)?/, '')));
    return reply.send({ ecosystems: official.map((name) => ({ name, added: added.has(name) })) });
  });

  // Add an OSV ecosystem: switch its daily job on and load it. Accepts the names the
  // import command does ("Ubuntu:22.04:LTS" is "Ubuntu"); a wrong one is answered with the right one.
  fastify.post('/jobs/osv-ecosystems', async (request, reply) => {
    const parsed = addEcosystemSchema.safeParse(request.body);
    if (!parsed.success) return reply.status(400).send({ error: 'Body must be { name: string }' });
    const official = await fetchOsvEcosystems();
    if (!official) return reply.status(503).send({ error: "OSV's list of ecosystems could not be fetched" });
    const resolved = resolveOsvEcosystem(parsed.data.name, official);
    if (!resolved.ok) return reply.status(400).send({ error: resolved.message });

    const def = await resolveJob(`osv-${resolved.bucket}`);
    if (!def) return reply.status(404).send({ error: `Unknown OSV ecosystem: ${resolved.bucket}` });
    await setEnabled(def.source, true);
    const { mode, outcome } = await runNow(def);
    if (outcome === 'busy') return reply.status(409).send({ error: `Job already queued or running: ${def.source}` });
    if (outcome === 'stopped') return reply.status(503).send({ error: 'Shutting down' });
    if (outcome === 'failed') return reply.status(500).send({ error: `Could not queue job: ${def.source}` });
    return reply.status(202).send({ status: outcome, source: def.source, mode });
  });

  // Manual trigger: queued with the scheduled jobs, started when a slot is
  // free. Works regardless of enabled state.
  fastify.post<{ Params: { source: string } }>('/jobs/:source/run', async (request, reply) => {
    const { source } = request.params;

    const def = await resolveJob(source);
    if (!def) {
      return reply.status(404).send({ error: `Unknown job source: ${source}` });
    }
    // The CollectionJob row tracks progress from here: queued, then running.
    const { mode, outcome } = await runNow(def);
    if (outcome === 'busy') {
      return reply.status(409).send({ error: `Job already queued or running: ${source}` });
    }
    if (outcome === 'stopped') {
      return reply.status(503).send({ error: 'Shutting down' });
    }
    if (outcome === 'failed') {
      return reply.status(500).send({ error: `Could not queue job: ${source}` });
    }
    return reply.status(202).send({ status: outcome, source, mode });
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
