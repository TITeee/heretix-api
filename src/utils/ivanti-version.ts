/**
 * Version ordering for Ivanti products.
 *
 * normalizeVersion() cannot order Ivanti's version strings: it keeps only three
 * dotted components, and the fix boundary of Ivanti's best-known product sits in
 * the fourth. EPMM is "12.7.0.0 and prior", fixed in "12.7.0.1" -- both encode
 * to 12.7.0, so a search for 12.7.0.0 (affected) read as already fixed.
 * Connect Secure's "22.7R2.5" only happened to sort because the release number
 * after the R was read as part of the minor ("22.72.5"), which stops being true
 * once that number reaches two digits ("9.1R18.9" outranks "9.2R1").
 *
 * This module is the Ivanti-specific replacement, used both when
 * AdvisoryAffectedProduct rows are written (advisory-fetcher.ts) and when a
 * search compares against them (routes/vulnerabilities.ts), so the two sides
 * always agree -- the same arrangement as pan-version.ts.
 *
 * Shapes seen in Ivanti's advisories (hub.ivanti.com, 2025-2026):
 *   "12.7.0.1"                    EPMM, 4 numeric components
 *   "6.4.8.8008"                  Avalanche, the 4th is a build number
 *   "22.7R2.5", "9.1R18.9"        Connect Secure / Policy Secure: <line>R<release>.<build>
 *   "22.8R1", "22.3R2"            same, without a build (also vTM)
 *   "R10.8.1"                     Sentry, an R in front of an ordinary version
 *   "5.0.5", "2026.2.1", "2026.2" CSA, Xtraction
 *   "2024 SU4 SR1", "2024"        Endpoint Manager: <year> [SU<n> [SR<n> | Security Update <n>]]
 * Anything else (the Neurons "2025.2 Sept 2026 Security Patch", cloud release
 * names such as "mo2026.2") cannot be placed in the order and encodes to null.
 */

export interface IvantiVersion {
  /** Always four numbers, most significant first. */
  parts: [number, number, number, number];
}

// "[R]12.7[R2][.5][.1]": the R-release number, when present, takes the third
// place and only one more number may follow it; without it, up to two may.
const RELEASE_TRAIN = /^[Rr]?(\d+)\.(\d+)(?:[Rr](\d+))?(?:\.(\d+))?(?:\.(\d+))?$/;
const ENDPOINT_MANAGER = /^(\d{4})(?:\s*SU\s*(\d+)(?:\s+(?:SR|Security\s+Update)\s*(\d+))?)?$/i;

// One slot is four digits: Avalanche's build number (8008) and year-based
// majors (2026) both fit, and 4 slots * 4 digits keep the value well inside a
// BigInt column. A component beyond it is a timestamp or build stamp, not a
// version.
const SLOT = 10_000;

/** Parse an Ivanti version, or null when it is not one this module can order. */
export function parseIvantiVersion(input: string): IvantiVersion | null {
  const s = input.trim().replace(/\.$/, '');

  const em = s.match(ENDPOINT_MANAGER);
  if (em) {
    // A bare year ("2024") is that year's first release, before SU1.
    return { parts: [Number(em[1]), em[2] === undefined ? 0 : Number(em[2]), em[3] === undefined ? 0 : Number(em[3]), 0] };
  }

  const m = s.match(RELEASE_TRAIN);
  if (!m) return null;
  const [, major, minor, release, a, b] = m;
  let parts: [number, number, number, number];
  if (release !== undefined) {
    // "22.7R2.5": the R-release is the third place, the build the fourth.
    if (b !== undefined) return null;
    parts = [Number(major), Number(minor), Number(release), a === undefined ? 0 : Number(a)];
  } else {
    parts = [Number(major), Number(minor), a === undefined ? 0 : Number(a), b === undefined ? 0 : Number(b)];
  }
  return parts.some(n => n >= SLOT) ? null : { parts };
}

/** Negative / zero / positive, like Array.prototype.sort's comparator. */
export function compareIvantiVersions(a: IvantiVersion, b: IvantiVersion): number {
  for (let i = 0; i < 4; i++) {
    const d = a.parts[i] - b.parts[i];
    if (d !== 0) return d;
  }
  return 0;
}

/** "22.7" -- the release line a fix is paired with within one product. */
export function ivantiLine(v: IvantiVersion): string {
  return `${v.parts[0]}.${v.parts[1]}`;
}

/**
 * BigInt encoding for AdvisoryAffectedProduct's *Int columns: four four-digit
 * slots, so the existing range query works unchanged while all four components
 * count. Monotonic in compareIvantiVersions() order.
 */
export function ivantiVersionToInt(input: string): bigint | null {
  const v = parseIvantiVersion(input);
  if (!v) return null;
  const [a, b, c, d] = v.parts.map(n => BigInt(n)) as [bigint, bigint, bigint, bigint];
  return a * 1_000_000_000_000n + b * 100_000_000n + c * 10_000n + d;
}
