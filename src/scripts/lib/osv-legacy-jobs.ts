/**
 * Tidy what older versions left of the per-release OSV jobs.
 *
 * Before the releases of a distro shared one job, each had its own: "osv-Debian:12",
 * "osv-Ubuntu:22.04:LTS", "osv-Alpine:v3.21". The job is now the bucket ("osv-Debian",
 * osvBucketName() in jobs/osv-bucket.ts), and what an older version stored under the old
 * names is not read any more, but it still shows:
 *   - a CollectionJob row under the old name is listed on the dashboard as an ecosystem
 *     with no records, next to the real row of the same name;
 *   - a JobConfig row under the old name that said On does not switch on the bucket's job,
 *     so an ecosystem that ran daily before the upgrade is Off after it.
 *
 * An old name that was On switches its bucket on (unless the bucket already has a setting of
 * its own: what was chosen on the new version stands), then the old settings and the old job
 * rows go. Nothing imported is touched, and the bucket's first load stays a person's call. A
 * job that is queued or running is left alone. The per-release history is not carried over to
 * the bucket: those files were frozen when OSV moved to the shared buckets, so a delta cursor
 * taken from them would skip the months in between.
 */
import type { PrismaClient } from '@prisma/client';
import { osvBucketName } from '../../jobs/osv-bucket.js';

/** The name `osv-<ecosystem>` of a job, if its ecosystem is one of a bucket's releases. */
export function isLegacyOsvSource(source: string): boolean {
  if (!source.startsWith('osv-') || source.startsWith('osv-full-')) return false;
  const ecosystem = source.slice('osv-'.length);
  return osvBucketName(ecosystem) !== ecosystem;
}

export type LegacyOsvJobsResult = { switchedOn: string[]; configsRemoved: number; jobsRemoved: number };

export async function tidyLegacyOsvJobs(db: PrismaClient): Promise<LegacyOsvJobsResult> {
  const configs = (await db.jobConfig.findMany({ where: { source: { startsWith: 'osv-' } } }))
    .filter((c) => isLegacyOsvSource(c.source));
  const jobSources = (await db.collectionJob.groupBy({ by: ['source'], where: { source: { startsWith: 'osv-' } } }))
    .map((g) => g.source)
    .filter(isLegacyOsvSource);

  // The buckets an old name had switched on.
  const bucketsOn = [...new Set(configs.filter((c) => c.enabled).map((c) => `osv-${osvBucketName(c.source.slice('osv-'.length))}`))];
  const bucketsWithSetting = new Set(
    (await db.jobConfig.findMany({ where: { source: { in: bucketsOn } }, select: { source: true } })).map((c) => c.source),
  );
  const switchedOn = bucketsOn.filter((s) => !bucketsWithSetting.has(s));

  await db.$transaction([
    db.jobConfig.createMany({ data: switchedOn.map((source) => ({ source, enabled: true })), skipDuplicates: true }),
    db.jobConfig.deleteMany({ where: { source: { in: configs.map((c) => c.source) } } }),
  ]);
  const jobs = await db.collectionJob.deleteMany({
    where: { source: { in: jobSources }, status: { notIn: ['running', 'queued'] } },
  });

  return { switchedOn, configsRemoved: configs.length, jobsRemoved: jobs.count };
}
