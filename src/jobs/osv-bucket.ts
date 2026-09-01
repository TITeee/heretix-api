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
// just an alias (~6MB vs. Ubuntu's per-version buckets scaling into the
// hundreds of MB). Downloading the version-suffixed value 404s every single
// day and gets silently treated as a successful empty run (see the 'No GCS
// bucket found' error in osv-fetcher.ts) -- every version under a base here
// shares one job against the base name instead, so they fetch (and dedupe)
// the same feed once rather than each re-fetching a URL that never exists.
// Most distros (Ubuntu, Debian, Alpine, Red Hat once it has OSV data) do have
// a real per-version bucket and must keep using their DB value as-is.
export const SHARED_BUCKET_ECOSYSTEMS = ['AlmaLinux', 'Rocky Linux'];

/** Maps a DB ecosystem value to the OSV bucket name actually used to fetch it. */
export function osvBucketName(ecosystem: string): string {
  const shared = SHARED_BUCKET_ECOSYSTEMS.find((base) => ecosystem === base || ecosystem.startsWith(`${base}:`));
  return shared ?? ecosystem;
}
