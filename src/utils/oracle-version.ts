/**
 * Versions in Oracle's Critical Patch Update, Critical Security Patch Update and
 * Security Alert advisories (oracle-cpu-fetcher.ts): their order, and what an
 * affected-version text in those advisories stands for.
 *
 * normalizeVersion() cannot order them. It keeps four numbers and Oracle writes
 * five: WebLogic's 12.2.1.4.0 read as 12.2.1.0, and Java's CSPU build 21.0.13.0.3
 * as 21.0.13. Java 8's "8u511b33" was not a version at all, and the "21.0.13+11"
 * that `java -version` prints read as patch 1311. This module is used both when
 * the rows are written (advisory-fetcher.ts) and when a search compares against
 * them (routes/vulnerabilities.ts), the same arrangement as ivanti-version.ts.
 *
 * Shapes seen in the advisories (2020 to 2026):
 *   "19.3", "8.4.13", "12.2.1.4.0", "21.0.13.0.3"   1 to 5 numbers
 *   "8u511", "8u511b33", "8u511-b32", "8u503-perf"  Java 8 (also 7) updates
 *   ">=19.3|<=19.32"                                 a CSAF version range (2026)
 *   "19.3-19.32", "12.2.3 - 12.2.10"                 a range, both ends affected
 *   "8.0.28 and prior", "Prior to 21.4.3"            an upper bound
 *   "Oracle Java SE:11.0.17", "Java SE: 7u251"       the product, then the version
 *   "14; Java SE Embedded: 8u241"                    two products in one text
 * Anything else ("19c", "Cz8.2", "3.9m0p1", "prior to XCP3120") cannot be placed
 * in the order: it is kept as an exact version and matched as written.
 */

/** AdvisoryAffectedProduct.vendor for Oracle advisory rows (oracle-cpu-fetcher.ts). */
export const ORACLE_VENDOR = 'oracle';

// Java 8 and 7 updates: "8u511", "8u511b33", "8u511-b32", "8u503-perf", and the
// "1.8.0_511" a Java 8 runtime reports. The build and the performance pack take no
// part in the order.
const JAVA_UPDATE = /^(\d{1,2})u(\d{1,4})(?:-?b\d+)?(?:-perf)?$/i;
const JAVA_LEGACY = /^1\.(\d{1,2})\.0(?:_(\d{1,4}))?(?:-b\d+)?$/;
const DOTTED = /^\d{1,6}(?:\.\d{1,6}){0,4}$/;

// Slots: the major, the minor, the patch, and the 4th and 5th numbers together
// (4th * 1,000 + 5th). Oracle's 4th and 5th are small (12.2.1.4.0, 21.0.13.0.3,
// 18.1.4.48.0), so a value past a slot is not a version this order can hold.
const LIMITS = [92_232, 10_000, 100_000, 100, 1_000];
const WEIGHTS = [100_000_000_000_000n, 10_000_000_000n, 100_000n, 1_000n, 1n];

/** The numbers of an Oracle version, most significant first, or null when it is not one. */
export function oracleVersionParts(input: string): number[] | null {
  // `java -version` prints "21.0.13+11-LTS-250": what follows the + is the build.
  const s = input.trim().replace(/^v/i, '').split('+')[0];
  const update = s.match(JAVA_UPDATE);
  if (update) return [Number(update[1]), 0, Number(update[2])];
  const legacy = s.match(JAVA_LEGACY);
  if (legacy) return [Number(legacy[1]), 0, Number(legacy[2] ?? 0)];
  if (!DOTTED.test(s)) return null;
  const parts = s.split('.').map(Number);
  return parts.every((p, i) => p < LIMITS[i]) ? parts : null;
}

/** Encode an Oracle version for AdvisoryAffectedProduct's *Int columns, or null. */
export function oracleVersionToInt(input: string): bigint | null {
  const parts = oracleVersionParts(input);
  if (!parts) return null;
  return parts.reduce((sum, p, i) => sum + BigInt(p) * WEIGHTS[i], 0n);
}

/** What one affected-version text says, for one product. */
export interface OracleAffected {
  product: string;
  versionStart?: string; // first affected, inclusive
  versionEnd?: string; // first not affected
  lastAffected?: string; // last affected, inclusive
  affectedVersions: string[];
}

// The products whose advisories name only the newest affected version of each
// line, every earlier version of that line being affected too: Java lists the
// last update of each release (21.0.13, then its CSPU build 21.0.13.0.3), APEX the
// last patch of each release (24.1.22). Every other single version is a release
// Oracle names exactly (WebLogic's 12.2.1.4.0) and stays exact.
const LINE_BY_MAJOR = /^(Java SE|Java SE Embedded|JavaFX|GraalVM\b.*)$/i;
const LINE_BY_MINOR = /^(APEX|Application Express\b.*)$/i;

/**
 * The first version of the line `version` belongs to, where Oracle names only the
 * newest affected version of the line (Java, APEX) or the end of it ("8.0.28 and
 * prior", "Prior to 21.4.3"). Oracle names one per supported line, so without a
 * start the newest line's would take in every older line as well.
 *
 * Java's line is its major (21; 8u0 for Java 8) and APEX's its major and minor
 * (24.1). For a bound, the line is the major and minor of a version with three
 * numbers or more (8.0) and the major of one with two (21.5 is the 21 line), for
 * every product: "Prior to 19.1" says 19.0 is affected, so APEX's 19.1 line would
 * leave nothing.
 */
function lineStart(product: string, version: string, bound: boolean): string | undefined {
  const parts = oracleVersionParts(version);
  if (!parts) return undefined;
  if (JAVA_UPDATE.test(version.trim())) return `${parts[0]}u0`;
  if (!bound && LINE_BY_MAJOR.test(product)) return `${parts[0]}`;
  if (!bound && LINE_BY_MINOR.test(product)) return parts.length > 1 ? `${parts[0]}.${parts[1]}` : undefined;
  if (parts.length >= 3) return `${parts[0]}.${parts[1]}`;
  if (parts.length === 2) return `${parts[0]}`;
  return undefined;
}

/** "8u511b33" and "8u511-perf" are update 511 of Java 8, written "8u511"; other versions stay as written. */
function canonical(version: string): string {
  const update = version.trim().match(JAVA_UPDATE);
  return update ? `${update[1]}u${update[2]}` : version.trim();
}

const encodes = (v: string) => oracleVersionToInt(v) !== null;

function parseOne(text: string, product: string): OracleAffected | null {
  let s = text.trim();
  if (!s) return null;

  // "Oracle Java SE:11.0.17", "Java SE: 7u251", "IDIH: 8.0.0-8.2.2": a name before the
  // version. A Java or GraalVM name is the product (an advisory files GraalVM under
  // Java SE this way); any other is a part of the product and is dropped.
  const labelled = s.match(/^([A-Za-z][^:<>=|]*?)\s*:\s*(.+)$/);
  if (labelled) {
    if (/Java|GraalVM/i.test(labelled[1])) product = labelled[1].replace(/^Oracle\s+/i, '').trim();
    s = labelled[2].trim();
  }

  // ">=19.3|<=19.32", the CSAF version range.
  if (/^[<>=]/.test(s)) {
    const out: OracleAffected = { product, affectedVersions: [] };
    for (const c of s.split('|')) {
      const m = c.trim().match(/^(>=|>|<=|<|=)\s*(.+)$/);
      if (!m || !encodes(m[2])) return { product, affectedVersions: [text.trim()] };
      const v = canonical(m[2]);
      if (m[1] === '>=' || m[1] === '>') out.versionStart = v;
      else if (m[1] === '<=') out.lastAffected = v;
      else if (m[1] === '<') out.versionEnd = v;
      else out.versionStart = out.lastAffected = v;
    }
    return out;
  }

  const prior = s.match(/^(.+?)\s+and\s+prior$/i);
  if (prior && encodes(prior[1])) {
    const v = canonical(prior[1]);
    return { product, versionStart: lineStart(product, prior[1], true), lastAffected: v, affectedVersions: [] };
  }
  const priorTo = s.match(/^prior\s+to\s+(.+)$/i);
  if (priorTo && encodes(priorTo[1])) {
    const v = canonical(priorTo[1]);
    // "Prior to 8u0" or "Prior to 21" starts no line before it: no start then.
    const start = lineStart(product, priorTo[1], true);
    const below = start !== undefined && oracleVersionToInt(start)! < oracleVersionToInt(v)!;
    return { product, ...(below && { versionStart: start }), versionEnd: v, affectedVersions: [] };
  }
  const range = s.match(/^(.+?)\s*-\s*(.+)$/);
  if (range && encodes(range[1]) && encodes(range[2])) {
    return { product, versionStart: canonical(range[1]), lastAffected: canonical(range[2]), affectedVersions: [] };
  }

  if (!encodes(s)) return { product, affectedVersions: [s] };
  const v = canonical(s);
  if (LINE_BY_MAJOR.test(product) || LINE_BY_MINOR.test(product)) {
    return { product, versionStart: lineStart(product, s, false), lastAffected: v, affectedVersions: [] };
  }
  // One release, named exactly. Stored as a range of one as well as the text, so a
  // version written another way (12.2.1.4 for 12.2.1.4.0, 19.30.0.0.0 for 19.30)
  // still matches.
  return { product, versionStart: v, lastAffected: v, affectedVersions: [v] };
}

/**
 * What an advisory's affected-version text says for `product`: one entry, or one
 * per product when the text names several ("14; Java SE Embedded: 8u241"). An
 * empty text says nothing about the version and gives an entry without one.
 */
export function parseOracleAffected(text: string | null | undefined, product: string): OracleAffected[] {
  if (!text?.trim()) return [{ product, affectedVersions: [] }];
  return text.split(';').map(t => parseOne(t, product)).filter((e): e is OracleAffected => e !== null);
}
