/**
 * Pure OSV-bucket-name resolution logic extracted from registry.ts for unit
 * testability without pulling in the Prisma client (registry.ts imports it at
 * module scope for resolveJob()/listOsvEcosystemJobs(), which requires
 * DATABASE_URL to be set even just to load the module).
 */

// OSV ecosystems whose DB values are version-suffixed (e.g. "AlmaLinux:9") but
// which OSV.dev serves from a single shared GCS bucket named after the bare
// base ("AlmaLinux"), not a per-version one -- confirmed live: "AlmaLinux:9"
// 404s while "AlmaLinux" 200s and is a proper full feed for every version, not
// just an alias. Downloading the version-suffixed value 404s every single
// day -- every version under a base here shares one job against the base name
// instead, so they fetch (and dedupe) the same feed once rather than each
// re-fetching a URL that never exists.
//
// Debian and Alpine used to have per-release buckets ("Debian:12/all.zip"),
// and the code assumed they still did. OSV stopped writing them on 2024-10-04
// (09 for Alpine) and now serves every release from the shared "Debian" and
// "Alpine" buckets, which are current. The old per-release files still answer
// 200, frozen, so a delta job on them fetched the same 28,999 records every
// day, imported nothing and reported success: no Debian or Alpine record was
// updated for months. The list of live ecosystems is
// https://storage.googleapis.com/osv-vulnerabilities/ecosystems.txt; a distro
// listed there under its bare name belongs here.
//
// Ubuntu was in the same state (per-release buckets frozen on 2024-10-09), and its
// shared bucket is 792 MB, so its delta is read from the bucket's modified_id.csv
// (see usesModifiedList) rather than from the zip.
//
// "Packagist:https://packages.drupal.org/8" is the Drupal repository's name inside
// the Packagist feed; it has no bucket of its own (404) and its records arrive with
// the "Packagist" job.
export const SHARED_BUCKET_ECOSYSTEMS = ['AlmaLinux', 'Rocky Linux', 'Debian', 'Alpine', 'Ubuntu', 'Packagist'];

// Buckets whose delta is taken from `<bucket>/modified_id.csv` ("<time>,<id>" per record, newest
// first) plus one request per changed record, instead of downloading all.zip. Right for a bucket
// whose zip is too big to hold in memory every day (Ubuntu: 792 MB, against a few thousand
// records changed per day).
const MODIFIED_LIST_BUCKETS = new Set(['Ubuntu']);

export function usesModifiedList(bucket: string): boolean {
  return MODIFIED_LIST_BUCKETS.has(bucket);
}

/** Maps a DB ecosystem value to the OSV bucket name actually used to fetch it. */
export function osvBucketName(ecosystem: string): string {
  const shared = SHARED_BUCKET_ECOSYSTEMS.find((base) => ecosystem === base || ecosystem.startsWith(`${base}:`));
  return shared ?? ecosystem;
}

const DAY_MS = 24 * 60 * 60 * 1000;

// Distro feeds get new records nearly every day. A bucket whose newest record
// is older than this is not quiet, it is no longer being written -- which is
// what the frozen Debian/Alpine/Ubuntu per-release buckets looked like.
const DISTRO_MAX_AGE_MS = 14 * DAY_MS;
// Everything else can be quiet for a while (GitHub Actions went 28 days, SwiftURL
// 17), so only a long silence counts.
const DEFAULT_MAX_AGE_MS = 90 * DAY_MS;
const DISTRO_BASES = new Set(['Debian', 'Ubuntu', 'Alpine', 'AlmaLinux', 'Rocky Linux']);

/** How old the newest record of an ecosystem's bucket may be before its job is considered broken. */
export function maxBucketAgeMs(ecosystem: string): number {
  const base = ecosystem.split(':')[0];
  return DISTRO_BASES.has(base) ? DISTRO_MAX_AGE_MS : DEFAULT_MAX_AGE_MS;
}

/**
 * Why an ecosystem's bucket should not be trusted, or null when it looks alive.
 * `newestModified` is the newest `modified` of the records in the bucket (null for none).
 * An import from such a bucket "succeeds" with nothing new, so the job must fail instead.
 */
export function staleBucketProblem(ecosystem: string, newestModified: Date | null, now: Date = new Date()): string | null {
  if (!newestModified) {
    return `the OSV bucket "${ecosystem}" holds no records`;
  }
  const ageMs = now.getTime() - newestModified.getTime();
  if (ageMs <= maxBucketAgeMs(ecosystem)) return null;
  const days = Math.floor(ageMs / DAY_MS);
  return (
    `the newest record in the OSV bucket "${ecosystem}" is ${days} days old (${newestModified.toISOString().slice(0, 10)}): ` +
    'OSV no longer writes to it. Check https://storage.googleapis.com/osv-vulnerabilities/ecosystems.txt and ' +
    'SHARED_BUCKET_ECOSYSTEMS in src/jobs/osv-bucket.ts'
  );
}
