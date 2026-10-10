// Pre-release labels, lowest stage first. A pre-release sorts below its release,
// ordered by stage and then by its number: 1.2.3.dev1 < 1.2.3a1 < 1.2.3b2 <
// 1.2.3rc1 < 1.2.3rc2 < 1.2.3. Without the ordering, a range between two
// pre-releases ("3.15.0a1" to "3.15.0b3", as CPython's CNA records use) would
// collapse to nothing.
const PRE_RELEASE_STAGES: Record<string, number> = {
  dev: 0, devel: 0,
  a: 1, alpha: 1, ea: 1, test: 1,
  b: 2, beta: 2, m: 2, milestone: 2, pre: 2, preview: 2,
  c: 3, rc: 3, cr: 3,
};
const PRE_RELEASE_STAGE_WIDTH = 200;
// The top rank (rc199) lands on release - 1, where a hyphenated pre-release
// ("1.2.3-rc1") already sits; dev0 is the lowest, release - 800.
const PRE_RELEASE_MAX_RANK = 4 * PRE_RELEASE_STAGE_WIDTH - 1;

// Labels that come after, or qualify, a release: OpenSSH/sudo "p1", Checkmk
// "p49", Junos "R3"/"X53"/"F6", IOS XE "z2"/"y1"/"s1", squid "STABLE3",
// "u29"/"SR2"/"SU3" updates. Their number goes into the release slot, the way
// "-N" already does: 7.4 < 7.4p1 < 7.5, 17.3R3 < 17.3R10 < 17.4R1.
const POST_RELEASE_LABELS = new Set([
  'p', 'pl', 'patch', 'post', 'u', 'update', 'sr', 'su', 'stable', 'h', 'r', 'z', 'y', 's', 'x', 'f',
]);

/**
 * Split a version whose first hyphen-separated part is a dotted number with a
 * label and a 1-3 digit number attached ("6.0.18rc1", "2.1.0.dev2", "7.4p1").
 *
 * Deliberately narrow, so opaque identifiers keep the encoding they had
 * (usually null, and so exact-string matching): the base must be dotted with
 * at most 3 parts (not Windows "21h1" or "202308a1"), the number at most 3
 * digits (not a build stamp, "1.305b241111"), and nothing may follow the
 * number except, for a pre-release, a further dotted part ("0.5.0b3.dev13") --
 * not "1.0.2b05_20181207" or Huawei's "v200r007c00spcb00". Anything after the
 * first hyphen is ignored: "17.3R3-S2" encodes as "17.3R3".
 */
function labelledVersion(version: string):
  | { kind: 'pre'; base: string; label: string; num: number }
  | { kind: 'post'; base: string; num: number }
  | null {
  const first = version.split('-')[0];
  const m = first.match(/^[vV]?(\d+(?:\.\d+){1,2})\.?([A-Za-z]+)(\d{1,3})(.*)$/);
  if (!m) return null;
  const [, base, rawLabel, num, rest] = m;
  const label = rawLabel.toLowerCase();
  if (label in PRE_RELEASE_STAGES && (rest === '' || /^[.+]/.test(rest))) {
    return { kind: 'pre', base, label, num: Number(num) };
  }
  if (POST_RELEASE_LABELS.has(label) && rest === '') return { kind: 'post', base, num: Number(num) };
  return null;
}

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
 * see docs/known-issues.md's generic version encoding note). Values beyond
 * MAX_COMPONENT (999999) are still rejected outright as garbage (timestamps,
 * git hashes) rather than clamped, since clamping those would treat obvious
 * garbage as a real, comparable version.
 */
/**
 * The Junos version a CPE spells as a version and an update field:
 * `junos:21.2:r1-s1` is 21.2R1-S1 and `junos:12.3x48:d105` is 12.3X48-D105. NVD lists
 * every affected Junos release as its own CPE this way. Null when the pair is not one.
 */
export function qualifyJunosVersion(base: string, update: string): string | null {
  const b = base.trim();
  const u = update.trim();
  const release = u.match(/^r(\d{1,3})(?:-s(\d{1,3}))?$/i);
  if (release && /^\d{1,3}\.\d{1,3}$/.test(b)) {
    return `${b}R${release[1]}${release[2] ? `-S${release[2]}` : ''}`;
  }
  const build = u.match(/^d(\d{1,3})$/i);
  const train = b.match(/^(\d{1,3}\.\d{1,3})x(\d{1,3})$/i);
  if (build && train) return `${train[1]}X${train[2]}-D${build[1]}`;
  return null;
}

export function normalizeVersion(version: string): bigint | null {
  // Strip epoch prefix ("1:0.1.15-..." -> "0.1.15-...")
  let withoutEpoch = version.replace(/^\d+:/, '');

  // Go module pseudo-version (https://go.dev/ref/mod#pseudo-versions):
  // "vX.Y.Z-yyyymmddhhmmss-abcdefabcdef", possibly with a "-0"/"-pre.0"-style
  // infix (dot-joined per spec) directly before the timestamp. The generic
  // hyphen-suffix handling below misreads this: a hash starting with a digit
  // gets the 14-digit timestamp read as an RPM release number and rejected as
  // garbage (over MAX_COMPONENT below); one starting with a letter trips the
  // pre-release check and collapses the whole value to 0 -- either way the
  // actual base version is thrown away. Recognized here instead: normalize
  // the base and treat the pseudo-version as one step below it, same
  // convention as any other pre-release, since by construction it never
  // reaches the tag it's measured from. Must not fall through to the generic
  // logic below on a match (base==null) -- that would reintroduce the same
  // misparse this exists to avoid.
  const pseudoVersionSuffix = /[-.]\d{14}-[0-9a-fA-F]{7,40}$/;
  if (pseudoVersionSuffix.test(withoutEpoch)) {
    const base = withoutEpoch.replace(pseudoVersionSuffix, '').match(/^v?(\d+\.\d+\.\d+)/)?.[1];
    const baseInt = base ? normalizeVersion(base) : null;
    if (baseInt === null) return null;
    return baseInt > 0n ? baseInt - 1n : baseInt;
  }

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

  // Junos: "21.2R3-S9" is release 3 of 21.2 plus its ninth service release, and
  // "12.3X48-D105" is the X48 train's D105 build. The release (or train) number goes
  // into the patch slot and the service release (or D build) into the release slot:
  // 21.2R3 < 21.2R3-S1 < 21.2R3-S9 < 21.2R4. The generic label rule below would drop
  // the service release, and so read every S level of a release as the same version
  // (a fix in R3-S9 would never be told apart from R3-S8). A "-EVO" suffix (Junos
  // Evolved) takes no part in the order.
  const junos = withoutEpoch.match(/^(\d{1,3})\.(\d{1,3})([RrXx])(\d{1,3})(?:-([SsDd])(\d{1,3}))?(?:-EVO)?$/);
  if (junos) {
    const [, maj, min, , train, , service] = junos;
    return BigInt(maj) * 1_000_000_000n + BigInt(min) * 1_000_000n + BigInt(train) * 1_000n + BigInt(service ?? 0);
  }

  // A label attached straight to the number ("6.0.18rc1", "7.4p1", "17.3R3").
  // Must be handled before the generic logic below, which strips letters but
  // keeps their digits and so reads "6.0.18rc1" as patch 181 -- non-monotonic,
  // and far past the release the label belongs to. See labelledVersion().
  const labelled = labelledVersion(withoutEpoch);
  if (labelled) {
    const base = normalizeVersion(labelled.base);
    if (base === null) return null;
    if (labelled.kind === 'post') return normalizeVersion(`${labelled.base}-${labelled.num}`);
    const rank = PRE_RELEASE_STAGES[labelled.label] * PRE_RELEASE_STAGE_WIDTH
      + Math.min(labelled.num, PRE_RELEASE_STAGE_WIDTH - 1);
    const value = base - 1n - BigInt(PRE_RELEASE_MAX_RANK - rank);
    return value > 0n ? value : 0n;
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
  // A 4th dotted component ("15.1.10.8", "138.53.6.158") takes the release slot when no
  // RPM-style "-N" release is there. It is left out (as it always was) when the number
  // above 999 would be clamped in a slot before it -- Chrome's "120.0.6099.109" and
  // "120.0.6200.50" both clamp to 120.0.999, and ordering them by the 4th number
  // alone would be wrong -- and above 999 itself ("2.0.0.20230101", a date or build stamp).
  const dotted = versionOnly.match(/^[vV]?(\d+)\.(\d+)\.(\d+)\.(\d{1,3})$/);
  const fourth = dotted && Number(dotted[2]) <= 999 && Number(dotted[3]) <= 999 ? dotted[4] : undefined;
  const release = releaseMatch ? parseInt(releaseMatch[1], 10) : fourth ? parseInt(fourth, 10) : 0;

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
