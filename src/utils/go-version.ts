/**
 * Version ordering for Go modules (https://go.dev/ref/mod#versions): semantic
 * versions, "v" optional, with "+incompatible" and other build metadata taking
 * no part in the order.
 *
 * The *Int columns cannot hold this order. A pseudo-version
 * ("0.0.0-20240527191746-e0fe7cc39172", "1.9.10-0.20250517140552-daee3ac7ade1")
 * is ordered by its timestamp, and normalizeVersion() has only the gap below the
 * release to put it in, so every pseudo-version of a release encodes the same
 * and a range between two of them -- or from 0 to one of an untagged module's --
 * matches nothing. OSV's Go ranges are compared with this instead
 * (routes/vulnerabilities.ts), the way dpkg and RPM ranges are.
 */

interface GoVersion {
  core: [number, number, number];
  pre: string[];
}

const SEMVER = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z.-]+)?$/;

/** Parse a Go module version, or null when it is not one (OSV's "0" is handled by compareGoVersions). */
export function parseGoVersion(input: string): GoVersion | null {
  const m = input.trim().match(SEMVER);
  if (!m) return null;
  return { core: [Number(m[1]), Number(m[2]), Number(m[3])], pre: m[4] ? m[4].split('.') : [] };
}

/** Semver's order of two pre-release identifiers: numbers by value, below any alphanumeric one. */
function compareIdentifiers(a: string, b: string): number {
  const na = /^\d+$/.test(a);
  const nb = /^\d+$/.test(b);
  if (na && nb) {
    const x = BigInt(a);
    const y = BigInt(b);
    return x > y ? 1 : x < y ? -1 : 0;
  }
  if (na) return -1;
  if (nb) return 1;
  return a > b ? 1 : a < b ? -1 : 0;
}

/**
 * Negative / zero / positive, or null when either side is not a Go module
 * version. OSV's introduced "0" is below every version.
 */
export function compareGoVersions(a: string, b: string): number | null {
  if (a === '0' || b === '0') return a === b ? 0 : a === '0' ? -1 : 1;
  const x = parseGoVersion(a);
  const y = parseGoVersion(b);
  if (!x || !y) return null;
  for (let i = 0; i < 3; i++) {
    if (x.core[i] !== y.core[i]) return x.core[i] > y.core[i] ? 1 : -1;
  }
  // A release is above its pre-releases.
  if (x.pre.length === 0 || y.pre.length === 0) return (y.pre.length > 0 ? 1 : 0) - (x.pre.length > 0 ? 1 : 0);
  for (let i = 0; i < Math.min(x.pre.length, y.pre.length); i++) {
    const c = compareIdentifiers(x.pre[i], y.pre[i]);
    if (c !== 0) return c;
  }
  return Math.sign(x.pre.length - y.pre.length);
}
