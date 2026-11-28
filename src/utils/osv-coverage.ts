import { osvBucketName } from '../jobs/osv-bucket.js';
import {
  isDpkgStyleDistro, isLanguageEcosystem, isRpmStyleOsvDistro, normalizeEcosystem,
} from './search-helpers.js';
import { isWordPressEcosystem } from './wordpress.js';

/**
 * Whether a search for this ecosystem is answered by OSV, so that an ecosystem not loaded
 * means a search can only come back empty. WordPress, answered by the Wordfence feed alone,
 * is judged the same way. Distros and sources with their own
 * feeds (Red Hat, Oracle Linux, Windows, the vendor advisories) are not judged here:
 * their data is not in the OSV table to begin with.
 */
export function expectsOsvData(ecosystem: string): boolean {
  const eco = normalizeEcosystem(ecosystem) ?? ecosystem;
  if (eco.startsWith('Red Hat:')) return false;
  // Not OSV's, but answered by one source alone in the same way: the Wordfence feed.
  if (isWordPressEcosystem(eco)) return true;
  return isLanguageEcosystem(eco) || isDpkgStyleDistro(eco) || isRpmStyleOsvDistro(eco);
}

export interface NoDataEcosystem {
  ecosystem: string;
  /** How many of the searched packages are of this ecosystem. */
  packages: number;
}

// "Has data" is stable and kept longer. "No data" is kept briefly: a first load that has just
// completed should show within a minute.
const NO_DATA_TTL_MS = 60_000;
const HAS_DATA_TTL_MS = 5 * 60_000;
const known = new Map<string, { hasData: boolean; expiresAt: number }>();

/** For tests: forget what was found. */
export function resetOsvCoverageCache(): void {
  known.clear();
}

// Loaded means what the dashboard means by it: the ecosystem's job (or `pnpm import:osv`) has
// completed and its records are there. Counting any record would call an ecosystem loaded that
// only has the few a malicious-package (osv-mal) or an earlier test run left behind.
// The releases of a distro share one job, so "Alpine:v3.24" is asked as "Alpine".
async function osvHasData(ecosystem: string, now: number): Promise<boolean> {
  if (isWordPressEcosystem(normalizeEcosystem(ecosystem))) return wordfenceHasData(now);
  const bucket = osvBucketName(normalizeEcosystem(ecosystem) ?? ecosystem);
  const hit = known.get(bucket);
  if (hit && hit.expiresAt > now) return hit.hasData;
  // Loaded here, not at the top, so the pure parts of this module can be used without a database.
  const { isOsvLoaded } = await import('../jobs/first-load.js');
  const hasData = await isOsvLoaded(bucket);
  known.set(bucket, { hasData, expiresAt: now + (hasData ? HAS_DATA_TTL_MS : NO_DATA_TTL_MS) });
  return hasData;
}

// WordPress is loaded once the Wordfence job has stored a record.
async function wordfenceHasData(now: number): Promise<boolean> {
  const hit = known.get(WORDFENCE_KEY);
  if (hit && hit.expiresAt > now) return hit.hasData;
  const { prisma } = await import('../db/client.js');
  const { WORDFENCE_SOURCE } = await import('../worker/wordfence-fetcher.js');
  const hasData = (await prisma.advisoryVulnerability.findFirst({ where: { source: WORDFENCE_SOURCE }, select: { id: true } })) !== null;
  known.set(WORDFENCE_KEY, { hasData, expiresAt: now + (hasData ? HAS_DATA_TTL_MS : NO_DATA_TTL_MS) });
  return hasData;
}
const WORDFENCE_KEY = 'advisory-wordfence';

/**
 * The ecosystems of a search that OSV is expected to answer but has no record of at all:
 * an empty result for them says nothing about the packages. Sorted by package count.
 */
export async function ecosystemsWithoutData(
  ecosystems: Iterable<string | undefined>,
  hasData: (ecosystem: string, now: number) => Promise<boolean> = osvHasData,
  now: number = Date.now(),
): Promise<NoDataEcosystem[]> {
  const counts = new Map<string, number>();
  for (const eco of ecosystems) {
    if (eco && expectsOsvData(eco)) counts.set(eco, (counts.get(eco) ?? 0) + 1);
  }
  const missing: NoDataEcosystem[] = [];
  for (const [ecosystem, packages] of counts) {
    if (!(await hasData(ecosystem, now))) missing.push({ ecosystem, packages });
  }
  return missing.sort((a, b) => b.packages - a.packages || a.ecosystem.localeCompare(b.ecosystem));
}
