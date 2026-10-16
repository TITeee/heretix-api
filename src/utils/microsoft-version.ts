/**
 * Version ordering for Microsoft (MSRC) build numbers.
 *
 * A Windows OS build is four numbers, "10.0.20348.5761": major, minor, build and
 * the update build revision (UBR). Every Windows release keeps its build for its
 * whole life (20348 is Windows Server 2022) and each monthly cumulative update
 * raises only the UBR, so the UBR is what tells a patched system from an
 * unpatched one. normalizeVersion() cannot order these: it caps a component at
 * 999, so the build collapses to 999 and the UBR is dropped -- every Windows
 * Server 2022 build reads as the same version.
 *
 * This module is the Microsoft-specific replacement, used both when
 * AdvisoryAffectedProduct rows are written (advisory-fetcher.ts) and when a
 * search compares against them (routes/vulnerabilities.ts), so the two sides
 * always agree -- the same arrangement as citrix-version.ts.
 */

const BUILD = /^(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?$/;

// Slot sizes: major and minor stay small (10.0, 6.3); builds reach five digits
// (26100) and UBRs five (26100.33650), so both get six-digit slots. The largest
// value, 999.999.999999.999999, is about 1e18 and fits a signed 64-bit column.
const SMALL_SLOT = 1_000;
const LARGE_SLOT = 1_000_000;

/** Parse "10.0.20348.5761" (or "10.0.20348", UBR 0), or null when it is not a build number. */
export function parseMicrosoftVersion(input: string): [number, number, number, number] | null {
  const m = input.trim().match(BUILD);
  if (!m) return null;
  const parts = [m[1], m[2], m[3], m[4] ?? '0'].map(Number) as [number, number, number, number];
  if (parts[0] >= SMALL_SLOT || parts[1] >= SMALL_SLOT || parts[2] >= LARGE_SLOT || parts[3] >= LARGE_SLOT) return null;
  return parts;
}

/** BigInt encoding for AdvisoryAffectedProduct's *Int columns, monotonic in build order. */
export function microsoftVersionToInt(input: string): bigint | null {
  const parts = parseMicrosoftVersion(input);
  if (!parts) return null;
  const [major, minor, build, ubr] = parts.map(n => BigInt(n)) as [bigint, bigint, bigint, bigint];
  return ((major * BigInt(SMALL_SLOT) + minor) * BigInt(LARGE_SLOT) + build) * BigInt(LARGE_SLOT) + ubr;
}
