/**
 * Version ordering for SonicWall products (SonicOS, SMA 100 / SMA 1000, Email
 * Security, the VPN clients).
 *
 * A SonicWall version is a dotted release, often with a build after a hyphen:
 * "7.0.1-5161" is build 5161 of SonicOS 7.0.1. normalizeVersion() cannot order
 * it: it reads a letter-led build ("7.0.1-R1456", "6.5.4.9-92n") as a
 * pre-release, below the release, and keeps only one build number of a build in
 * several parts ("6.5.4.4-44v-21-2457"). Until its slots were widened (2026-11)
 * it also capped every component at 999, so 7.0.1-5161 and 7.0.1-5165 encoded
 * the same and every 7.0.1 build went unmatched.
 *
 * This module is the SonicWall-specific replacement, used both when
 * AdvisoryAffectedProduct rows are written (advisory-fetcher.ts) and when a search
 * compares against them (routes/vulnerabilities.ts) -- the same arrangement as
 * citrix-version.ts. The order is the one sonicwall-fetcher.ts pairs versions by:
 * the dotted numbers, then the numbers of the build in turn.
 *
 * Shapes seen in the SonicWall advisories (2019-2026):
 *   "7.0.1-5161"            SonicOS release + build
 *   "7.0.1-R1456"           a build with a letter prefix
 *   "6.5.4.15-117n"         four-component Gen6 release + build with a letter suffix
 *   "6.5.4.4-44v-21-2457"   an NSv build in three parts
 *   "7.0.1-5030-R2007"      a build in two parts
 *   "12.4.3-03245"          SMA 1000, zero-padded build
 *   "10.0.34.8223"          Email Security, build as the fourth component
 *   "10.2.336"              NetExtender
 *   "10.2.1.13"             no build: before every build of the release
 */

export interface SonicWallVersion {
  /** The dotted release, up to four numbers. */
  release: number[];
  /** The numbers of the build, in order; empty when there is none. */
  build: number[];
}

const VERSION = /^(\d+(?:\.\d+){0,3})(?:-([0-9A-Za-z]+(?:-[0-9A-Za-z]+)*))?$/;

// Digit widths of the slots: major and minor together (major * 20 + minor; minors
// stay below 20), the third and fourth release numbers ("2.5.2518", "10.0.34.8223"),
// then two build numbers ("7.0.1-5030-R2007"). 19 digits in all, which fits a signed
// 64-bit column for every major up to 45.
const SLOT_DIGITS = [3, 4, 4, 4, 4];
const MINORS = 20;

/** Parse a SonicWall version, or null when it is not one this module can order. */
export function parseSonicWallVersion(input: string): SonicWallVersion | null {
  const m = input.trim().match(VERSION);
  if (!m) return null;
  return {
    release: m[1].split('.').map(Number),
    build: (m[2]?.match(/\d+/g) ?? []).map(Number),
  };
}

/**
 * BigInt encoding for AdvisoryAffectedProduct's *Int columns: fixed-width slots,
 * monotonic in the order above. A three-part build keeps its first and last
 * numbers: the middle one of an NSv build ("44v-21-2457", "8v-37-489") stays the
 * same between a series' affected and fixed builds, and there is no room for it.
 */
export function sonicWallVersionToInt(input: string): bigint | null {
  const v = parseSonicWallVersion(input);
  if (!v || v.release.length > 4 || v.build.length > 3) return null;
  const build = v.build.length === 3 ? [v.build[0], v.build[2]] : v.build;
  const [major, minor = 0, third = 0, fourth = 0] = v.release;
  if (minor >= MINORS) return null;
  const slots = [major * MINORS + minor, third, fourth, build[0] ?? 0, build[1] ?? 0];
  let n = 0n;
  for (let i = 0; i < slots.length; i++) {
    const width = 10 ** SLOT_DIGITS[i];
    if (slots[i] >= width) return null;
    n = n * BigInt(width) + BigInt(slots[i]);
  }
  return n <= 9_223_372_036_854_775_807n ? n : null;
}
