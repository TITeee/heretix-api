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
export const DISTRO_ECOSYSTEM_PREFIXES = ['Ubuntu:', 'Debian:', 'Alpine:', 'AlmaLinux:', 'Rocky:', 'Red Hat:', 'CentOS:'];

export function isDistroEcosystem(eco: string): boolean {
  return DISTRO_ECOSYSTEM_PREFIXES.some(p => eco.startsWith(p));
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

// RPM-based distro ecosystems that have vendor advisory data.
// Maps ecosystem prefix → AdvisoryAffectedProduct.vendor value.
const RPM_ECOSYSTEM_VENDOR: Record<string, string> = {
  'Red Hat': 'red-hat',
};

export function rpmAdvisoryVendor(ecosystem: string): string | null {
  for (const [prefix, vendor] of Object.entries(RPM_ECOSYSTEM_VENDOR)) {
    if (ecosystem.startsWith(prefix + ':')) return vendor;
  }
  return null;
}
