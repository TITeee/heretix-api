/**
 * One-time migration: tidy the per-release OSV jobs an older version left behind
 * (src/scripts/lib/osv-legacy-jobs.ts): an old name that was On switches its bucket on, and
 * the old settings and job rows are removed, so the dashboard lists each ecosystem once and
 * what ran daily before an upgrade still does.
 *
 * Usage:
 *   pnpm migrate:osv-legacy-job-names
 */
import 'dotenv/config';
import { closeDb, prisma } from '../db/client.js';
import { tidyLegacyOsvJobs } from './lib/osv-legacy-jobs.js';

async function main() {
  const { switchedOn, configsRemoved, jobsRemoved } = await tidyLegacyOsvJobs(prisma);
  console.log(
    `Done: ${switchedOn.length} OSV job(s) switched on from an old per-release setting` +
      `${switchedOn.length ? ` (${switchedOn.join(', ')})` : ''}, ` +
      `${configsRemoved} old setting(s) and ${jobsRemoved} old job row(s) removed.`,
  );
}

main()
  .catch((err) => {
    console.error(err);
    process.exit(1);
  })
  .finally(async () => {
    await closeDb();
    process.exit(0);
  });
