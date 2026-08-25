/**
 * Pure NVD-import decision logic extracted from nvd-fetcher.ts for unit
 * testability without pulling in the Prisma client (nvd-fetcher.ts imports it
 * at module scope for its transaction logic, which requires DATABASE_URL to
 * be set even just to load the module).
 */
import { normalizeVersion } from '../utils/version.js';

/**
 * `pointVersion` is a real, specific CPE version -- parseCPE() (nvd-fetcher.ts)
 * already resolves "*"/"-" wildcards to null, so a non-null pointVersion here
 * is never a wildcard -- that normalizeVersion() failed to range-encode (e.g.
 * Huawei's "v200r007c00spcb00", a Jenkins plugin build id like
 * "1365.v4778ca_84b_de5"). Without capturing it, the row's
 * introducedInt/fixedInt/lastAffectedInt all end up null, indistinguishable
 * from a genuine CPE wildcard (which is *intentionally* unbounded) --
 * versionRangeWhere() (search-helpers.ts) would then match the row against
 * every queried version instead of just this one specific version. Returns
 * the raw string to store for exact-match search, or null when there's
 * nothing to preserve (either no point version at all, or it normalized fine).
 */
export function computeExactVersion(pointVersion: string | null): string | null {
  return pointVersion && normalizeVersion(pointVersion) === null ? pointVersion : null;
}
