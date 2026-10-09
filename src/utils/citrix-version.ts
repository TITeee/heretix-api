/**
 * Version ordering for NetScaler (Citrix ADC / Gateway) builds.
 *
 * A NetScaler version is a release branch and a build: "14.1-73.32" is build
 * 73.32 of branch 14.1. normalizeVersion() cannot order it: it reads the build as
 * a "-N" release number, keeps only the 73 of 73.32 (so 14.1-73.32 and 14.1-73.99
 * compare equal), and a bound written as a branch plus a bare build ("14.1" up to
 * "56.73", the way the CVE records give it) comes out as 14.1.0 up to 56.73.0, which
 * covers every later build of the branch -- the fixed ones included.
 *
 * This module is the NetScaler-specific replacement, used both when
 * AdvisoryAffectedProduct rows are written (advisory-fetcher.ts) and when a search
 * compares against them (routes/vulnerabilities.ts), so the two sides always agree
 * -- the same arrangement as ivanti-version.ts and pan-version.ts.
 *
 * Shapes seen in the NetScaler bulletins (2022-2026):
 *   "14.1-73.32"                   branch 14.1, build 73.32
 *   "13.1-37.235-FIPS"             a FIPS / NDcPP build, labelled
 *   "13.1-37.235-FIPS and NDcPP"
 *   "14.1"                         a branch on its own: the start of its builds
 *   "13.0 build 58.30"             the older wording
 * The FIPS / NDcPP label does not take part in the order: those builds run on
 * their own numbering (13.1-37.x against 13.1-6x.x), so they are a separate
 * product (see citrix-fetcher.ts) and are compared only with each other.
 */

export interface CitrixVersion {
  /** Branch major, branch minor, build, sub-build. */
  parts: [number, number, number, number];
}

const BUILD = /^(\d+)\.(\d+)(?:(?:-|\s+build\s+)(\d+)\.(\d+))?(?:[\s-]+(?:FIPS|NDcPP)(?:[\s-]+and[\s-]+NDcPP)?)?$/i;

// Four-digit slots: builds reach three digits (12.1-55.328), sub-builds up to 3.
const SLOT = 10_000;

/** Parse a NetScaler version, or null when it is not one this module can order. */
export function parseCitrixVersion(input: string): CitrixVersion | null {
  const m = input.trim().match(BUILD);
  if (!m) return null;
  const parts = [m[1], m[2], m[3] ?? '0', m[4] ?? '0'].map(Number) as [number, number, number, number];
  return parts.some(n => n >= SLOT) ? null : { parts };
}

/** Negative / zero / positive, like Array.prototype.sort's comparator. */
export function compareCitrixVersions(a: CitrixVersion, b: CitrixVersion): number {
  for (let i = 0; i < 4; i++) {
    const d = a.parts[i] - b.parts[i];
    if (d !== 0) return d;
  }
  return 0;
}

/** "14.1": the release branch. */
export function citrixBranch(v: CitrixVersion): string {
  return `${v.parts[0]}.${v.parts[1]}`;
}

/** The first version of the next branch ("12.1" -> "12.2"): the exclusive end of a whole branch. */
export function nextCitrixBranch(v: CitrixVersion): string {
  return `${v.parts[0]}.${v.parts[1] + 1}`;
}

/** BigInt encoding for AdvisoryAffectedProduct's *Int columns: four four-digit slots, monotonic in compareCitrixVersions() order. */
export function citrixVersionToInt(input: string): bigint | null {
  const v = parseCitrixVersion(input);
  if (!v) return null;
  const [a, b, c, d] = v.parts.map(n => BigInt(n)) as [bigint, bigint, bigint, bigint];
  return a * 1_000_000_000_000n + b * 100_000_000n + c * 10_000n + d;
}
