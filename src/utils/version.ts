/**
 * Convert a semantic version string to a numeric value
 * "1.2.3"       -> 1002003000  (major * 1_000_000_000 + minor * 1_000_000 + patch * 1_000 + release)
 * "1.2.3-6.el9" -> 1002003006  (RPM release number included as 4th component)
 *
 * Returns null for abnormally large values or versions containing timestamps
 *
 * minor/patch/release each occupy a fixed-width digit slot (weight 1e6/1e3/1
 * respectively), so any of them reaching 1000+ overflows into the next slot up
 * instead of being rejected -- e.g. "67.9999.64" (a real NVD CPE convention for
 * "any 9999.x build of major 67") previously encoded to 76999064000, comparing
 * as *larger* than "68.0.15" (68000015000), a different major entirely. This
 * isn't just lossy, it's non-monotonic: an older version can normalize higher
 * than a newer one. Legitimately large-but-real values in this range (large
 * RPM release numbers, NVD's minor=9999 convention) are clamped to the slot's
 * max (999) instead -- confirmed this doesn't introduce new same-line
 * ambiguity beyond what already existed (RPM releases with a multi-part
 * suffix like "2136.344.4.3" already only capture the leading integer group;
 * see README.md's RPM sub-release precision note). Values beyond
 * MAX_COMPONENT (999999) are still rejected outright as garbage (timestamps,
 * git hashes) rather than clamped, since clamping those would treat obvious
 * garbage as a real, comparable version.
 */
export function normalizeVersion(version: string): bigint | null {
  // Strip epoch prefix ("1:0.1.15-..." -> "0.1.15-...")
  let withoutEpoch = version.replace(/^\d+:/, '');

  // Convert NVD "_update_?N" suffix to ".N" before stripping non-numerics.
  // Without this, "6_update_4" strips to "64" (major=64) instead of "6.4" (minor=4).
  // Examples: "6_update_4" → "6.4", "5.0_update13" → "5.0.13"
  withoutEpoch = withoutEpoch.replace(/_update_?(\d+)/gi, '.$1');

  // Broadcom/VMware: "8.0 U3d" → "8.0.3-4"  (major.minor.update-letter_index)
  // letter a=1, b=2, …, z=26; no letter means no 4th component.
  if (/^\d+\.\d+ U\d+[a-z]?$/.test(withoutEpoch)) {
    withoutEpoch = withoutEpoch.replace(/ U(\d+)([a-z]?)$/, (_, u, letter) => {
      const sub = letter ? `-${letter.charCodeAt(0) - 96}` : '';
      return `.${u}${sub}`;
    });
  }

  // Detect pre-release (only when character after hyphen is a letter)
  // "1.0.0-beta" -> true, "0.1.15-2.git..." -> false (RPM revision excluded)
  const hasPrerelease = /\d-[a-zA-Z]/.test(withoutEpoch);

  const parts = withoutEpoch.split('-');

  // Strip everything after hyphen (release number / pre-release identifier) ("0.1.15-2.git..." -> "0.1.15")
  const versionOnly = parts[0];
  const cleaned = versionOnly.replace(/[^0-9.]/g, '').split('.').slice(0, 3);

  const major = parseInt(cleaned[0] || '0', 10);
  const minor = parseInt(cleaned[1] || '0', 10);
  const patch = parseInt(cleaned[2] || '0', 10);

  // Extract RPM release number if hyphen is followed by a pure integer (e.g. "6" in "2.9.13-6.el9")
  // Pre-release identifiers starting with a letter are excluded by hasPrerelease check above
  const releaseMatch = !hasPrerelease ? parts[1]?.match(/^(\d+)/) : null;
  const release = releaseMatch ? parseInt(releaseMatch[1], 10) : 0;

  // Check for abnormally large values (timestamps, Git hashes, etc.) -- beyond
  // this, treat as garbage and reject rather than clamp.
  const MAX_COMPONENT = 999999;

  if (major > MAX_COMPONENT || minor > MAX_COMPONENT || patch > MAX_COMPONENT || release > MAX_COMPONENT) {
    return null;
  }

  // minor/patch/release must each stay below 1000 to not corrupt the next
  // slot up (see the function doc comment) -- clamp legitimately-large values
  // in [1000, MAX_COMPONENT] to the slot's max instead of letting them overflow.
  const SLOT_LIMIT = 999;
  const clampedMinor = Math.min(minor, SLOT_LIMIT);
  const clampedPatch = Math.min(patch, SLOT_LIMIT);
  const clampedRelease = Math.min(release, SLOT_LIMIT);

  // Verify the resulting BigInt is within a safe range
  let result = BigInt(major) * 1_000_000_000n
    + BigInt(clampedMinor) * 1_000_000n
    + BigInt(clampedPatch) * 1_000n
    + BigInt(clampedRelease);

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
