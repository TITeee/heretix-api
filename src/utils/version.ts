/**
 * Convert a semantic version string to a numeric value
 * "1.2.3" -> 1002003
 * major * 1000000 + minor * 1000 + patch
 *
 * Returns null for abnormally large values or versions containing timestamps
 */
export function normalizeVersion(version: string): bigint | null {
  // Strip epoch prefix ("1:0.1.15-..." -> "0.1.15-...")
  const withoutEpoch = version.replace(/^\d+:/, '');

  // Detect pre-release (only when character after hyphen is a letter)
  // "1.0.0-beta" -> true, "0.1.15-2.git..." -> false (RPM revision excluded)
  const hasPrerelease = /\d-[a-zA-Z]/.test(withoutEpoch);

  // Strip everything after hyphen (release number / pre-release identifier) ("0.1.15-2.git..." -> "0.1.15")
  const versionOnly = withoutEpoch.split('-')[0];
  const cleaned = versionOnly.replace(/[^0-9.]/g, '').split('.').slice(0, 3);

  const major = parseInt(cleaned[0] || '0', 10);
  const minor = parseInt(cleaned[1] || '0', 10);
  const patch = parseInt(cleaned[2] || '0', 10);

  // Check for abnormally large values (timestamps, Git hashes, etc.)
  // Normal semantic versioning rarely exceeds 999 per component
  const MAX_COMPONENT = 999999; // maximum value per component

  if (major > MAX_COMPONENT || minor > MAX_COMPONENT || patch > MAX_COMPONENT) {
    // Return null for abnormal values
    return null;
  }

  // Verify the resulting BigInt is within a safe range
  let result = BigInt(major * 1000000 + minor * 1000 + patch);

  // Pre-release versions should sort lower than the release (e.g., "2.0.0-beta.1" < "2.0.0")
  if (hasPrerelease && result > 0n) {
    result -= 1n;
  }

  // PostgreSQL BIGINT max check (9,223,372,036,854,775,807)
  const MAX_BIGINT = BigInt('9223372036854775807');
  if (result > MAX_BIGINT) {
    return null;
  }

  return result;
}

/**
 * Validate a version string
 */
export function isValidVersion(version: string): boolean {
  const semverRegex = /^(\d+)\.(\d+)\.(\d+)(-[\w.-]+)?(\+[\w.-]+)?$/;
  return semverRegex.test(version);
}

/**
 * Check whether a version falls within a range
 * Returns false if version normalization fails
 */
export function isVersionInRange(
  version: string,
  introduced?: string | null,
  fixed?: string | null,
  lastAffected?: string | null
): boolean {
  const versionInt = normalizeVersion(version);

  // Treat failed normalization as out of range
  if (versionInt === null) return false;

  if (introduced) {
    const introducedInt = normalizeVersion(introduced);
    if (introducedInt === null) return false;
    if (versionInt < introducedInt) return false;
  }

  if (fixed) {
    const fixedInt = normalizeVersion(fixed);
    if (fixedInt === null) return false;
    if (versionInt >= fixedInt) return false;
  }

  if (lastAffected) {
    const lastAffectedInt = normalizeVersion(lastAffected);
    if (lastAffectedInt === null) return false;
    if (versionInt > lastAffectedInt) return false;
  }

  return true;
}
