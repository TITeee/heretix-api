/**
 * Pure search-time decision logic extracted from src/api/routes/vulnerabilities.ts
 * for unit testability. No DB dependency.
 */

export type VulnerabilityResult = {
  id: string;               // Vulnerability master ID
  externalId: string;       // cveId or osvId
  source: string;           // backward compat: primary source ("nvd" | "osv" | "advisory" etc.)
  sources: string[];        // list of sources that matched (["nvd", "osv"] etc.)
  severity: string | null;
  cvssScore: number | null;
  cvssVector: string | null;
  summary: string | null;
  publishedAt: Date | null;
  approximateMatch: boolean;
  isKev: boolean;
  epssScore: number | null;
  epssPercentile: number | null;
  fixedVersion: string | null;
};

/** Deduplicate by master ID (merge sources, keep first non-null fixedVersion) */
export function dedup(items: VulnerabilityResult[]): VulnerabilityResult[] {
  const seen = new Map<string, VulnerabilityResult>();
  for (const item of items) {
    const existing = seen.get(item.id);
    if (existing) {
      for (const s of item.sources) {
        if (!existing.sources.includes(s)) existing.sources.push(s);
      }
      if (!existing.fixedVersion && item.fixedVersion) {
        existing.fixedVersion = item.fixedVersion;
      }
    } else {
      seen.set(item.id, { ...item, sources: [...item.sources] });
    }
  }
  return [...seen.values()];
}

// ─── Version Range Filter Conditions ─────────────────────────

export function versionRangeWhere(versionInt: bigint) {
  return {
    AND: [
      {
        OR: [
          { introducedInt: { lte: versionInt } },
          { introducedInt: null },
        ],
      },
      {
        OR: [
          { fixedInt: { gt: versionInt } },
          {
            fixedInt: null,
            OR: [
              { lastAffectedInt: null },
              { lastAffectedInt: { gte: versionInt } },
            ],
          },
        ],
      },
    ],
  };
}

// ─── Ecosystem Classification ─────────────────────────────────

// Prefixes for distro-specific ecosystems.
// These use dpkg/apk version strings and require a different matching strategy
// (exact match against the versions list) instead of upstream semver range comparison.
// 'oracle-linux' has no colon-suffixed major version (unlike 'Red Hat:9') — it's
// matched as a bare, version-less ecosystem value per its documented usage.
export const DISTRO_ECOSYSTEM_PREFIXES = ['Ubuntu:', 'Debian:', 'Alpine:', 'AlmaLinux:', 'Rocky:', 'Red Hat:', 'CentOS:', 'oracle-linux'];

export function isDistroEcosystem(eco: string): boolean {
  return DISTRO_ECOSYSTEM_PREFIXES.some(p => eco.startsWith(p));
}

// Distro ecosystems whose OSV entries frequently publish only a continuous
// introduced/fixed range with no enumerated `versions` list at all (most
// Debian entries; a smaller fraction of Ubuntu/Alpine ones) — exact-match
// against affectedVersions alone silently matches nothing for those rows.
// These ecosystems' version format is close enough to dpkg's for
// compareDpkgVersions() to serve as a range-comparison fallback.
const DPKG_STYLE_DISTRO_PREFIXES = ['Ubuntu:', 'Debian:', 'Alpine:'];

export function isDpkgStyleDistro(eco: string): boolean {
  return DPKG_STYLE_DISTRO_PREFIXES.some(p => eco.startsWith(p));
}

// Language package ecosystems (npm, PyPI, Go, etc.) are fully covered by OSV.
// NVD and Advisory tables contain OS/C-library entries that share package names
// with language packages (e.g. C bzip2 vs npm bzip2), causing false positives.
const LANGUAGE_ECOSYSTEMS = new Set([
  'npm', 'PyPI', 'Go', 'Packagist', 'crates.io', 'RubyGems', 'NuGet', 'Maven',
]);

export function isLanguageEcosystem(eco: string): boolean {
  return LANGUAGE_ECOSYSTEMS.has(eco);
}

// Normalize ecosystem names from heretix-cli internal names to OSV ecosystem names
const ECOSYSTEM_ALIASES: Record<string, string> = {
  'composer': 'Packagist',
};

export function normalizeEcosystem(eco: string | undefined): string | undefined {
  if (!eco) return eco;
  return ECOSYSTEM_ALIASES[eco.toLowerCase()] ?? eco;
}

// RPM-based distro ecosystems that have vendor advisory data, routed to the
// exact rpmvercmp comparison (searchAdvisoryRpm) instead of the lossy BigInt
// approximation used elsewhere (see AdvisoryAffectedProduct.versionEnd — this
// reads that same string column directly, no precomputed/backfilled data needed).
// Maps ecosystem prefix (colon-suffixed major version, e.g. "Red Hat:9") →
// AdvisoryAffectedProduct.vendor value.
const RPM_ECOSYSTEM_VENDOR: Record<string, string> = {
  'Red Hat': 'red-hat',
};
// Ecosystems matched as an exact, version-less value instead of a colon-suffixed prefix.
const RPM_ECOSYSTEM_VENDOR_EXACT: Record<string, string> = {
  'oracle-linux': 'oracle-linux',
};

export function rpmAdvisoryVendor(ecosystem: string): string | null {
  const exact = RPM_ECOSYSTEM_VENDOR_EXACT[ecosystem];
  if (exact) return exact;
  for (const [prefix, vendor] of Object.entries(RPM_ECOSYSTEM_VENDOR)) {
    if (ecosystem.startsWith(prefix + ':')) return vendor;
  }
  return null;
}
