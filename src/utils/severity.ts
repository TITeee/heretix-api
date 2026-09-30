/**
 * Severity handling shared by the importers, so every source lands on the
 * scale the API documents (CRITICAL / HIGH / MEDIUM / LOW). Two further
 * ratings are real and kept as-is rather than folded into LOW: NONE, the CVSS
 * qualitative rating for a 0.0 base score that NVD itself reports, and
 * INFORMATIONAL, which Splunk uses for advisories with no score.
 */

const CANONICAL = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'INFORMATIONAL']);

// Source-specific spellings of the same rating. GHSA (OSV's
// database_specific.severity) says MODERATE where CVSS and NVD say MEDIUM;
// heretix-management counts anything outside the canonical set as N/A.
const ALIASES: Record<string, string> = {
  MODERATE: 'MEDIUM',
};

/**
 * Canonical severity for a source-provided rating, or null when the value is
 * not a severity rating at all. The null case matters: an earlier OSV
 * importer stored severity[].type ("CVSS_V3", "Ubuntu") here, which no
 * consumer can interpret.
 */
export function normalizeSeverity(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const upper = raw.trim().toUpperCase();
  const canonical = ALIASES[upper] ?? upper;
  return CANONICAL.has(canonical) ? canonical : null;
}

/**
 * CVSS v3/v4 qualitative rating for a base score (FIRST's table, identical
 * for 3.x and 4.0): 0.0 None, 0.1-3.9 Low, 4.0-6.9 Medium, 7.0-8.9 High,
 * 9.0-10.0 Critical.
 */
export function severityFromCvssScore(score: number): string {
  if (score >= 9.0) return 'CRITICAL';
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MEDIUM';
  if (score > 0) return 'LOW';
  return 'NONE';
}
