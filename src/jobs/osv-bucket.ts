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
//
// The vendors that publish one feed for several ecosystems are the same case: the "Echo" feed
// holds "Echo:PyPI", "Echo:Maven", "Echo:Go" and "Echo:NuGet", "Root" holds "Root:PyPI",
// "Root:Debian:13", ..., and "SUSE", "openSUSE", "openEuler", "TuxCare", "Mageia", "Alpaquita",
// "BellSoft Hardened Containers", "Azure Linux", "Red Hat" and "VSCode" likewise. A job on
// "Echo:Maven" asked for a bucket that does not exist and failed with 404 every day. Found by
// reading the records of every bucket in ecosystems.txt for ecosystem names unlike the bucket's.
export const SHARED_BUCKET_ECOSYSTEMS = [
  'AlmaLinux', 'Rocky Linux', 'Debian', 'Alpine', 'Ubuntu', 'Packagist',
  'Echo', 'Root', 'SUSE', 'openSUSE', 'openEuler', 'TuxCare', 'Mageia', 'Alpaquita',
  'BellSoft Hardened Containers', 'Azure Linux', 'Red Hat', 'VSCode',
];

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

export const OSV_ECOSYSTEMS_URL = 'https://storage.googleapis.com/osv-vulnerabilities/ecosystems.txt';

/**
 * OSV ecosystems that are not imported, and why. Each is on OSV's list, so it can be chosen
 * and would run; it would only do harm or nothing.
 */
export const OSV_NOT_FOR_IMPORT: Readonly<Record<string, string>> = {
  'Red Hat':
    "RHEL is imported from Red Hat's own OVAL and VEX (the advisory-redhat jobs). Its OSV records would duplicate them " +
    'and disagree with them, and the file holds tens of thousands of records for every stream and product',
  GIT: 'its records name no package, only git commit ranges, so no version can match them and nothing would be stored',
};

/** Why an ecosystem is not imported, or null when it can be. Takes a release too ("Red Hat:enterprise_linux:9"). */
export function osvImportBlock(ecosystem: string): string | null {
  return OSV_NOT_FOR_IMPORT[osvBucketName(ecosystem)] ?? null;
}

/**
 * Ecosystems worth a person's first look: the language ecosystems heretix is checked against, and
 * the distros in the support policy. The rest of OSV's list works on a best-effort basis.
 */
const RECOMMENDED_OSV_ECOSYSTEMS = new Set([
  'npm', 'PyPI', 'Go', 'Maven', 'NuGet', 'RubyGems', 'crates.io', 'Packagist',
  'Debian', 'Ubuntu', 'Alpine', 'AlmaLinux', 'Rocky Linux',
]);

export function osvEcosystemGroup(ecosystem: string): 'recommended' | 'other' {
  return RECOMMENDED_OSV_ECOSYSTEMS.has(osvBucketName(ecosystem)) ? 'recommended' : 'other';
}

export type EcosystemResolution = { ok: true; bucket: string } | { ok: false; message: string };

/**
 * Turns the name a person typed into the OSV bucket to import, or says what to type instead.
 * `official` is OSV's list of ecosystems (ecosystems.txt). Names are case-sensitive in OSV, so
 * "pypi" is a 404 there; here it is answered with "PyPI". A release suffix is accepted for the
 * distros that share one bucket ("Ubuntu:22.04:LTS" is the "Ubuntu" bucket).
 */
export function resolveOsvEcosystem(input: string, official: readonly string[]): EcosystemResolution {
  const bucket = osvBucketName(input);
  const blocked = osvImportBlock(bucket);
  if (blocked) return { ok: false, message: `OSV ecosystem "${bucket}" is not imported: ${blocked}` };
  if (official.includes(bucket)) return { ok: true, bucket };
  const lower = bucket.toLowerCase();
  const sameLetters = official.find((o) => o.toLowerCase() === lower);
  if (sameLetters) return { ok: false, message: `Unknown OSV ecosystem "${input}". Did you mean "${sameLetters}"? (names are case-sensitive)` };
  const near = official.filter((o) => o.toLowerCase().includes(lower) || lower.includes(o.toLowerCase())).slice(0, 5);
  const hint = near.length > 0 ? ` Similar: ${near.join(', ')}.` : '';
  return { ok: false, message: `Unknown OSV ecosystem "${input}".${hint} All names: ${OSV_ECOSYSTEMS_URL}` };
}
