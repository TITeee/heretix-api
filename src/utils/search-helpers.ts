/**
 * Pure search-time decision logic extracted from src/api/routes/vulnerabilities.ts
 * for unit testability. No DB dependency.
 */
import { compareDpkgVersions } from './dpkg-version.js';
import { compareRpmVersions } from './rpm-version.js';

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
  /**
   * Every identifier this finding is reachable by, including externalId itself.
   *
   * externalId is not stable: it is the master's *preferred* id, recomputed on
   * every query as cveId ?? osvId ?? advisoryId. A vendor advisory or OSV record
   * assigned a CVE after it was first published keeps its own original id on its
   * source row but starts being reported here under the CVE, so a consumer keying
   * findings on externalId alone sees the old id vanish and an unrelated new one
   * appear. Carrying the source row's own id alongside lets it recognise the two
   * as one finding.
   */
  aliases: string[];
};

/** Collect the distinct, non-null identifiers a finding can be recognised by. */
export function buildAliases(
  master: { cveId?: string | null; osvId?: string | null; advisoryId?: string | null },
  sourceOwnId?: string | null,
): string[] {
  return [...new Set([master.cveId, master.osvId, master.advisoryId, sourceOwnId].filter((v): v is string => !!v))];
}

/** Deduplicate by master ID (merge sources and aliases, keep first non-null fixedVersion) */
export function dedup(items: VulnerabilityResult[]): VulnerabilityResult[] {
  const seen = new Map<string, VulnerabilityResult>();
  for (const item of items) {
    const existing = seen.get(item.id);
    if (existing) {
      for (const s of item.sources) {
        if (!existing.sources.includes(s)) existing.sources.push(s);
      }
      // Union rather than first-wins: each source contributes the id it knows this
      // finding by, and dropping the losers' would discard exactly the mapping a
      // consumer needs to follow a finding across a rename.
      for (const a of item.aliases) {
        if (!existing.aliases.includes(a)) existing.aliases.push(a);
      }
      if (!existing.fixedVersion && item.fixedVersion) {
        existing.fixedVersion = item.fixedVersion;
      }
    } else {
      seen.set(item.id, { ...item, sources: [...item.sources], aliases: [...item.aliases] });
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
// 'Oracle Linux:' is kept alongside it so this list stays consistent with
// RPM_ECOSYSTEM_VENDOR's alias — without it, that ecosystem form would route through
// searchAdvisoryRpm() (correct) but also searchNVD() (unlike every other RPM distro
// here, which skips NVD once isDistro is true), reintroducing name-collision noise.
// 'Rocky Linux:' (not 'Rocky:' -- OSV's own ecosystem string is "Rocky Linux:8",
// confirmed against a live OSV entry; the old 'Rocky:' value here never matched
// anything). No dedicated OVAL fetcher exists for it, so it's covered purely
// through OSV like AlmaLinux, not through a RPM_ECOSYSTEM_VENDOR entry.
// 'CentOS' has no entry here: OSV has no CentOS ecosystem at all (confirmed via
// its published ecosystem list and a live 404), and there's no dedicated fetcher
// either, so a 'CentOS:' prefix here would only ever suppress a genuine NVD
// centos-vendor CPE match for nothing in return.
export const DISTRO_ECOSYSTEM_PREFIXES = ['Ubuntu:', 'Debian:', 'Alpine:', 'AlmaLinux:', 'Rocky Linux:', 'Red Hat:', 'Oracle Linux:', 'oracle-linux'];

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

// RPM-based distros whose OSV entries have the same "range-only, no enumerated
// versions list" shape as the dpkg-style ones above (confirmed against live
// data: every AlmaLinux:9 row has affectedVersions=[] and only
// introducedVersion/fixedVersion) -- exact-match-only search-time filtering
// silently returns nothing for these ecosystems. 'Red Hat:' is included even
// though it currently has no OSV data at all (its vulnerabilities come from
// the dedicated OVAL fetcher via searchAdvisoryRpm instead) because
// searchOSV() runs unconditionally regardless of ecosystem, so this would
// resurface the instant OSV data for it exists.
const RPM_STYLE_DISTRO_PREFIXES = ['AlmaLinux:', 'Rocky Linux:', 'Red Hat:'];

export function isRpmStyleOsvDistro(eco: string): boolean {
  return RPM_STYLE_DISTRO_PREFIXES.some(p => eco.startsWith(p));
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
//
// 'Oracle Linux' is kept here too, as an alias of the canonical bare
// 'oracle-linux' value below. heretix-cli briefly emitted "Oracle Linux:N" for
// this ecosystem (2026-04-15 to 2026-08, under the mistaken assumption that all
// RPM distros shared one prefix+version convention) before being reverted to
// match this API's actual, documented format — any client or archived data
// still using that form falls through silently to the lossy BigInt path
// (searchAdvisory) without this entry, exactly the bug that alias exists to
// prevent from recurring.
const RPM_ECOSYSTEM_VENDOR: Record<string, string> = {
  'Red Hat': 'red-hat',
  'Oracle Linux': 'oracle-linux',
};
// Ecosystems matched as an exact, version-less value instead of a colon-suffixed prefix.
// This is the canonical form heretix-cli sends; see the alias above for the
// no-longer-emitted "Oracle Linux:N" form.
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

// ─── Version-range predicates ────────────────────────────────
// Applied in application code rather than SQL because both compare version
// strings with distro-specific ordering rules (dpkg / rpmvercmp) that the
// precomputed BigInt columns can't express.

/**
 * Most Debian OSV entries (and a smaller fraction of Ubuntu/Alpine ones)
 * publish only a continuous introduced/fixed range with no enumerated
 * `versions` list at all — exact-match against affectedVersions alone
 * silently matches nothing for those rows, regardless of what version is
 * queried. Fall back to dpkg-style range comparison using the raw
 * introduced/fixed/lastAffected strings when the enumerated list doesn't
 * contain (or doesn't exist for) the queried version.
 */
export function matchesDpkgStyleVersion(
  row: { affectedVersions: string[]; introducedVersion: string | null; fixedVersion: string | null; lastAffectedVersion: string | null },
  version: string,
): boolean {
  if (row.affectedVersions.includes(version)) return true;

  const hasRange = row.introducedVersion !== null || row.fixedVersion !== null || row.lastAffectedVersion !== null;
  if (!hasRange) return false;

  if (row.introducedVersion && compareDpkgVersions(version, row.introducedVersion) < 0) return false;
  if (row.fixedVersion && compareDpkgVersions(version, row.fixedVersion) >= 0) return false;
  if (row.lastAffectedVersion && compareDpkgVersions(version, row.lastAffectedVersion) > 0) return false;

  return true;
}

/**
 * Same shape as matchesDpkgStyleVersion() (enumerated `versions` list first,
 * then a continuous introduced/fixed/lastAffected range), but for RPM-based
 * OSV ecosystems (AlmaLinux, Rocky Linux, Red Hat) -- uses compareRpmVersions()
 * (rpmvercmp) rather than compareDpkgVersions() (dpkg's verrevcmp), since the
 * two algorithms disagree on things like tilde handling and can't be
 * substituted for each other. Distinct from matchesRpmVersionRange() below,
 * which compares against AdvisoryAffectedProduct's versionStart/versionEnd
 * shape (a single exclusive upper bound), not OSV's three-field range.
 */
export function matchesRpmStyleOsvVersion(
  row: { affectedVersions: string[]; introducedVersion: string | null; fixedVersion: string | null; lastAffectedVersion: string | null },
  version: string,
): boolean {
  if (row.affectedVersions.includes(version)) return true;

  const hasRange = row.introducedVersion !== null || row.fixedVersion !== null || row.lastAffectedVersion !== null;
  if (!hasRange) return false;

  if (row.introducedVersion && compareRpmVersions(version, row.introducedVersion) < 0) return false;
  if (row.fixedVersion && compareRpmVersions(version, row.fixedVersion) >= 0) return false;
  if (row.lastAffectedVersion && compareRpmVersions(version, row.lastAffectedVersion) > 0) return false;

  return true;
}

/**
 * Row predicate for RPM-based distro advisories (searchAdvisoryRpm).
 *
 * `versionEnd` comes from OVAL's "<package> is earlier than <version>" and is
 * therefore an *exclusive* upper bound — the named build is the patched one.
 * A row with no upper bound never matches, since there is nothing to compare.
 *
 * `versionStart`, when present, is an inclusive floor. OVAL's own upper-bound
 * criterion never carries one, but a sibling "Module <name>:N is enabled"
 * criterion does (see RedHatFetcher/OracleLinuxFetcher's collectCriteria) —
 * extracting that major version as the floor is what stops a newer DNF
 * module stream's fix from numerically swallowing a query against an older,
 * unrelated stream.
 */
export function matchesRpmVersionRange(
  row: { versionStart: string | null; versionEnd: string | null },
  version: string,
): boolean {
  if (!row.versionEnd) return false;
  if (compareRpmVersions(version, row.versionEnd) >= 0) return false;
  if (row.versionStart && compareRpmVersions(version, row.versionStart) < 0) return false;
  return true;
}
