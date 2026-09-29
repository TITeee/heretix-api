/**
 * Version ordering for Palo Alto Networks products.
 *
 * PAN-OS (and Prisma Access, GlobalProtect, ...) ship hotfixes on top of a
 * maintenance release: "10.2.9-h1" is the first hotfix *after* 10.2.9, so the
 * order is 10.2.9 < 10.2.9-h1 < 10.2.9-h3 < 10.2.10. normalizeVersion() reads
 * any "-<letter>" suffix as a pre-release instead, which puts "10.2.9-h1"
 * *below* 10.2.9 and makes every hotfix of a line compare equal to every
 * other -- wrong in both directions for a vendor whose fixes are mostly
 * hotfixes. This module is the PAN-specific replacement, used both when
 * AdvisoryAffectedProduct rows are written (advisory-fetcher.ts) and when a
 * search compares against them (routes/vulnerabilities.ts), so the two sides
 * always agree.
 *
 * Shapes seen in PAN's CSAF feed (all 245 advisories, 2,090 range entries):
 *   "11.2.3"                     plain release
 *   "10.2.9-h13"                 hotfix
 *   "6.2.6-c857", "6.5.3-b15"    GlobalProtect / Prisma SD-WAN build numbers
 *   "6.2.7-1077"                 same, without the letter
 *   "6.3.3-h2 (6.3.3-c676)"      hotfix with its build number as an alias
 *   "8.7.101-CE"                 Cortex XDR release-channel label
 *   "135.16.8.96"                Prisma Browser, 4 numeric components
 *   "2.1"                        two components
 * Hotfix, build and a 4th numeric component all occupy the same slot: each
 * orders after the plain release it qualifies, and no single product mixes two
 * of them on one release line.
 */

export interface PanVersion {
  major: number;
  minor: number;
  patch: number;
  /** Hotfix / build number / 4th numeric component; 0 for a plain release. */
  sub: number;
}

const PAN_VERSION = /^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?(?:-(?:h|c|b)?(\d+))?(?:-CE)?$/;

// Same garbage threshold as normalizeVersion(): a component this large is a
// timestamp or build id, not a version.
const MAX_COMPONENT = 999999;

/**
 * Parse a PAN version string, or null when it is not one this module can order
 * ("All", "5.1*", "8.3.101-CE HF", ...). A trailing "(...)"/"[...]" alias and a
 * trailing "." are ignored.
 */
export function parsePanVersion(input: string): PanVersion | null {
  const s = input.trim()
    .replace(/\s*[([].*[)\]]$/, '')
    .replace(/\.$/, '')
    // Cortex XDR's "7.5-CE.0" is 7.5.0 on the CE channel.
    .replace(/^(\d+\.\d+)-CE\.(\d+)$/, '$1.$2-CE');
  const m = s.match(PAN_VERSION);
  if (!m) return null;
  // A 4th numeric component and a hotfix/build suffix would both need the
  // `sub` slot; no PAN version carries both.
  if (m[4] !== undefined && m[5] !== undefined) return null;

  const v: PanVersion = {
    major: parseInt(m[1], 10),
    minor: m[2] !== undefined ? parseInt(m[2], 10) : 0,
    patch: m[3] !== undefined ? parseInt(m[3], 10) : 0,
    sub: m[4] !== undefined ? parseInt(m[4], 10) : m[5] !== undefined ? parseInt(m[5], 10) : 0,
  };
  if (Object.values(v).some(n => n > MAX_COMPONENT)) return null;
  return v;
}

/** Negative / zero / positive, like Array.prototype.sort's comparator. */
export function comparePanVersions(a: PanVersion, b: PanVersion): number {
  return a.major - b.major || a.minor - b.minor || a.patch - b.patch || a.sub - b.sub;
}

/** "M.m" -- the branch PAN lists separately in every advisory's version table. */
export function panBranch(v: PanVersion): string {
  return `${v.major}.${v.minor}`;
}

/** First release of the next maintenance line: 10.2.9-h13 -> 10.2.10. */
export function nextPanMaintenanceLine(v: PanVersion): PanVersion {
  return { major: v.major, minor: v.minor, patch: v.patch + 1, sub: 0 };
}

/**
 * "M.m.p" for a plain release. Only used for range starts this module derives
 * itself (a branch's first release, the next maintenance line), which never
 * carry a sub component -- bounds taken from the advisory keep PAN's own string.
 */
export function formatPanRelease(v: PanVersion): string {
  return `${v.major}.${v.minor}.${v.patch}`;
}

/**
 * Versions just below a fix point, for boundary testing: the previous hotfix
 * and the unpatched base release for a hotfix fix (10.2.9-h13 -> 10.2.9-h12,
 * 10.2.9), one patch lower for a plain release (11.2.3 -> 11.2.2).
 */
export function panVersionsBelow(input: string): string[] {
  const v = parsePanVersion(input);
  if (!v) return [];
  const base = formatPanRelease(v);
  if (v.sub > 1) return [`${base}-h${v.sub - 1}`, base];
  if (v.sub === 1) return [base];
  return v.patch > 0 ? [formatPanRelease({ ...v, patch: v.patch - 1 })] : [];
}

/**
 * BigInt encoding for AdvisoryAffectedProduct's *Int columns, in the same
 * major*1e9 + minor*1e6 + patch*1e3 + sub layout as normalizeVersion() so the
 * existing range query works unchanged -- but with `sub` holding the hotfix,
 * which keeps the encoding monotonic in comparePanVersions() order.
 *
 * minor/patch/sub are clamped at 999 like normalizeVersion() does, so values at
 * or beyond that collapse together (only Prisma Browser's 4th component reaches
 * it in practice -- the same precision limit documented for normalizeVersion()).
 */
export function panVersionToInt(input: string): bigint | null {
  const v = parsePanVersion(input);
  if (!v) return null;
  const slot = (n: number) => BigInt(Math.min(n, 999));
  return BigInt(v.major) * 1_000_000_000n + slot(v.minor) * 1_000_000n + slot(v.patch) * 1_000n + slot(v.sub);
}
