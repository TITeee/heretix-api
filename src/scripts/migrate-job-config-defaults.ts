/**
 * One-time migration: make today's implicit "no JobConfig row = enabled"
 * state explicit for every non-core source, before the default flips.
 *
 * isEnabled()/defaultEnabled() (jobs/config.ts) used to fall back to `true`
 * for any source with no JobConfig row. It now falls back to `true` only for
 * core sources (nvd/kev/epss) and `false` for everything else (vendor
 * advisories, OSV ecosystems), so a clean environment doesn't auto-start
 * every scraper. That default only matters for *future* clean environments —
 * this script preserves current behavior in existing ones by writing an
 * explicit `enabled: true` row for every non-core source that doesn't
 * already have a JobConfig row, so their effective state doesn't change.
 *
 * Usage:
 *   pnpm migrate:job-config-defaults
 */
import 'dotenv/config';
import { prisma } from '../db/client.js';
import { STATIC_JOBS, listOsvEcosystemJobs } from '../jobs/registry.js';
import { defaultEnabled } from '../jobs/config.js';

async function main() {
  const osvJobs = await listOsvEcosystemJobs();
  const nonCoreSources = [...STATIC_JOBS, ...osvJobs]
    .map((j) => j.source)
    .filter((source) => !defaultEnabled(source));

  const existing = await prisma.jobConfig.findMany({ select: { source: true } });
  const existingSources = new Set(existing.map((r) => r.source));

  const toInsert = [...new Set(nonCoreSources)].filter((source) => !existingSources.has(source));

  console.log(`${nonCoreSources.length} non-core sources known, ${toInsert.length} missing an explicit JobConfig row`);

  if (toInsert.length > 0) {
    await prisma.jobConfig.createMany({
      data: toInsert.map((source) => ({ source, enabled: true })),
    });
    console.log(`Inserted enabled:true rows for: ${toInsert.join(', ')}`);
  }

  await prisma.$disconnect();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
