import { compareRpmVersions } from '../../utils/rpm-version.js';
import { normalizeVersion } from '../../utils/version.js';

/**
 * Shared helpers for the validate-*.ts accuracy scripts' boundary-value sweep mode.
 *
 * Each validate-*.ts script scrapes a vendor's official advisory page as Ground
 * Truth, then (in sweep mode, i.e. no version argument given) automatically
 * derives boundary versions from every advisory's version range — exactly at
 * the range edges and one patch step past them — queries the local search API
 * for each, and aggregates Precision/Recall/F1 across all of them. This is
 * what actually stresses off-by-one bugs in range comparisons; a single
 * hand-picked version (the old CLI-arg mode) mostly doesn't.
 */

/**
 * Fetch every page of a limit/offset-paginated endpoint. The search API caps
 * `limit` at 500 per request (see the zod schema in vulnerabilities.ts); a
 * single page silently truncates results for heavily-patched packages
 * (kernel, glibc, systemd, ...) that have 500+ applicable CVEs at low
 * versions, which showed up as a massive false-negative count during the
 * RHEL/Oracle Linux sweeps — a bug in this test harness, not the product.
 */
export async function queryAllPages<T>(
  fetchPage: (offset: number) => Promise<T[]>,
  pageSize: number,
  stopEarly?: (allSoFar: T[]) => boolean,
): Promise<T[]> {
  const all: T[] = [];
  let offset = 0;
  for (;;) {
    const page = await fetchPage(offset);
    all.push(...page);
    if (stopEarly && stopEarly(all)) break;
    if (page.length < pageSize) break;
    offset += pageSize;
  }
  return all;
}

/**
 * Shift a "major.minor.patch..." version string's patch component by delta.
 * Returns null if patch would go negative (the caller should just skip that
 * boundary point rather than invent a nonsensical version).
 */
export function bumpPatch(version: string, delta: 1 | -1): string | null {
  const m = version.match(/^(\d+)\.(\d+)\.(\d+)/);
  if (!m) return null;
  const patch = parseInt(m[3], 10) + delta;
  if (patch < 0) return null;
  return `${m[1]}.${m[2]}.${patch}`;
}

/**
 * Shift an RPM-style version/release string (e.g. "3.2.5-3.el9_7.2") by ±1 on
 * its trailing digit run, for boundary-testing compareRpmVersions() (see
 * src/utils/rpm-version.ts) rather than the semver-shaped bumpPatch() above.
 * "3.el9" -1 -> "3.el8"; "7.2" +1 -> "7.3". Returns null if there's no
 * trailing digit run, or shifting would go negative.
 */
export function bumpRpmVersion(version: string, delta: 1 | -1): string | null {
  const m = version.match(/^(.*?)(\d+)(\D*)$/);
  if (!m) return null;
  const n = parseInt(m[2], 10) + delta;
  if (n < 0) return null;
  return `${m[1]}${n}${m[3]}`;
}

/**
 * Run `fn` over `items` with at most `concurrency` in flight at once.
 * RHEL/Oracle Linux sweeps can have tens of thousands of boundary points —
 * fully sequential HTTP round-trips to the local API make that impractically
 * slow, so this bounds parallelism instead of firing everything at once
 * (which would just overwhelm the DB connection pool) or running one-by-one.
 */
export async function mapWithConcurrency<T, R>(
  items: T[],
  concurrency: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;
  async function worker() {
    for (;;) {
      const i = next++;
      if (i >= items.length) return;
      results[i] = await fn(items[i], i);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, worker));
  return results;
}

export interface BoundaryPoint {
  product: string;
  version: string;
  reasons: string[];
}

/**
 * Cap the number of boundary points tested per product. Some packages (e.g.
 * Oracle Linux's kernel-uek family, ~19,700 AdvisoryAffectedProduct rows each)
 * have far more fixed-version entries than most; testing every single one
 * exercises the exact same comparison logic repeatedly while multiplying
 * cost, since searchAdvisoryRpm filters that many rows in JS per request —
 * during the Oracle Linux sweep this alone projected to 20+ hours. Sample
 * evenly across the product's own points instead of dropping its coverage
 * entirely or testing only its earliest/latest entries.
 */
export function capPointsPerProduct(points: Map<string, BoundaryPoint>, maxPerProduct: number): Map<string, BoundaryPoint> {
  const byProduct = new Map<string, BoundaryPoint[]>();
  for (const point of points.values()) {
    const list = byProduct.get(point.product);
    if (list) list.push(point);
    else byProduct.set(point.product, [point]);
  }

  const result = new Map<string, BoundaryPoint>();
  for (const list of byProduct.values()) {
    const step = Math.ceil(list.length / maxPerProduct);
    const sample = step <= 1 ? list : list.filter((_, i) => i % step === 0);
    for (const point of sample) {
      result.set(`${point.product} ${point.version}`, point);
    }
  }
  return result;
}

export interface RpmFixEntry {
  cveId: string;
  versionEnd: string;
  versionStart: string | null;
}

/**
 * Index RPM-vendor advisories (RHEL/Oracle Linux) by product name for O(1)
 * ground-truth lookups. The RHEL/Oracle Linux sweeps have tens of thousands of
 * boundary points; recomputing "which CVEs affect this product" by linearly
 * scanning every advisory on every single point (an O(points × advisories)
 * scan) is CPU-bound and blocks the event loop between awaits, which starves
 * the concurrent HTTP requests of any actual parallelism — building this
 * index once up front turns each lookup into O(1) instead.
 */
export function indexByProduct(
  advisories: { cveId?: string; affectedProducts: { product: string; versionStart?: string; versionEnd?: string }[] }[],
): Map<string, RpmFixEntry[]> {
  const index = new Map<string, RpmFixEntry[]>();
  for (const adv of advisories) {
    if (!adv.cveId) continue;
    for (const p of adv.affectedProducts) {
      if (!p.versionEnd) continue;
      const list = index.get(p.product);
      const entry = { cveId: adv.cveId, versionEnd: p.versionEnd, versionStart: p.versionStart ?? null };
      if (list) list.push(entry);
      else index.set(p.product, [entry]);
    }
  }
  return index;
}

/**
 * CVEs whose indexed RPM range for `product` covers `version`, replicating
 * matchesRpmVersionRange()'s (src/utils/search-helpers.ts) exact semantics:
 * version < versionEnd, AND (no versionStart OR version >= versionStart).
 *
 * The versionStart check matters as much as the versionEnd one: a DNF
 * module-stream entry (e.g. postgresql:18, versionStart="18.0") sets no
 * lower bound in the OVAL feed's own upper-bound-only criterion, but
 * RedHatFetcher/OracleLinuxFetcher derive one from the sibling "Module
 * <name>:<stream> is enabled" criterion (see collectCriteria() in both
 * fetchers) specifically so that querying an older, unrelated stream (e.g.
 * postgresql 13.7) doesn't numerically match a newer stream's fix. Ignoring
 * versionStart here would make ground truth share production's *old*
 * blind spot from before that fix existed -- and once production started
 * correctly excluding those older-stream queries, this function's old
 * unconditional-versionEnd-only check started flagging every one of those
 * correct exclusions as a false negative instead. Confirmed via a live
 * RHEL sweep: CVE-2026-6575's only affected-product entry is
 * postgresql:18 (versionStart="18.0"), yet the unguarded check expected it
 * to also match postgresql@13.7 -- a ground-truth bug, not a search bug.
 */
export function expectedCVEsRpm(product: string, version: string, index: Map<string, RpmFixEntry[]>): Set<string> {
  const result = new Set<string>();
  for (const e of index.get(product) ?? []) {
    if (compareRpmVersions(version, e.versionEnd) >= 0) continue;
    if (e.versionStart && compareRpmVersions(version, e.versionStart) < 0) continue;
    result.add(e.cveId.toUpperCase());
  }
  return result;
}

export interface GenericFixEntry {
  id: string;              // cveId, falling back to the advisory's own externalId
  introduced: string | null;
  exclusiveEnd: string | null; // versionEnd, falling back to versionFixed
  inclusiveEnd: string | null; // lastAffected — only meaningful when exclusiveEnd is absent
  exact: string[] | null;      // affectedVersions, when the advisory uses an exact list instead of a range
}

/**
 * Index generic advisory-table fetchers (Fortinet, PAN, ...) by product name,
 * replicating importAdvisoryData()'s own effective-range precedence exactly:
 * `versionEnd ?? versionFixed` wins as the exclusive upper bound, and
 * `lastAffected` (inclusive) is only consulted when neither is present. Some
 * fetchers (Fortinet, PAN) populate both an inclusive lastAffected AND a
 * supplementary versionFixed for the same product entry — getting this
 * precedence wrong silently produces a "ground truth" that disagrees with
 * what the search endpoint actually does, not a real bug.
 */
export function indexGenericByProduct(
  advisories: {
    cveId?: string;
    externalId: string;
    affectedProducts: {
      product: string;
      versionStart?: string;
      versionEnd?: string;
      versionFixed?: string;
      lastAffected?: string;
      affectedVersions?: string[];
    }[];
  }[],
): Map<string, GenericFixEntry[]> {
  const index = new Map<string, GenericFixEntry[]>();
  for (const adv of advisories) {
    const id = adv.cveId ?? adv.externalId;
    for (const p of adv.affectedProducts) {
      const exclusiveEnd = p.versionEnd ?? p.versionFixed ?? null;
      const entry: GenericFixEntry = {
        id,
        introduced: p.versionStart ?? null,
        exclusiveEnd,
        inclusiveEnd: exclusiveEnd ? null : (p.lastAffected ?? null),
        exact: p.affectedVersions && p.affectedVersions.length > 0 ? p.affectedVersions : null,
      };
      const list = index.get(p.product);
      if (list) list.push(entry);
      else index.set(p.product, [entry]);
    }
  }
  return index;
}

/** CVEs whose indexed range (or exact list) for `product` covers `version`, via normalizeVersion(). */
export function expectedIdsGeneric(product: string, version: string, index: Map<string, GenericFixEntry[]>): Set<string> {
  const result = new Set<string>();
  const versionInt = normalizeVersion(version);

  for (const e of index.get(product) ?? []) {
    if (e.exact && e.exact.includes(version)) {
      result.add(e.id.toUpperCase());
      continue;
    }
    // Guard: an exact-list-only entry (no range fields at all) that didn't
    // match above must not match anything else — without this, an entry with
    // introduced/exclusiveEnd/inclusiveEnd all absent falls through every
    // check below (none of them have anything to compare) straight to the
    // unconditional add, i.e. every OTHER version incorrectly "matches" too.
    if (!e.introduced && !e.exclusiveEnd && !e.inclusiveEnd) continue;
    if (versionInt === null) continue;

    if (e.introduced) {
      const iv = normalizeVersion(e.introduced);
      if (iv !== null && versionInt < iv) continue;
    }
    if (e.exclusiveEnd) {
      const ev = normalizeVersion(e.exclusiveEnd);
      if (ev !== null && versionInt >= ev) continue;
    } else if (e.inclusiveEnd) {
      const lv = normalizeVersion(e.inclusiveEnd);
      if (lv !== null && versionInt > lv) continue;
    }
    result.add(e.id.toUpperCase());
  }
  return result;
}

/** Derive boundary points (range edges ±1 patch, or each exact-list entry) from a generic advisory index. */
export function collectGenericBoundaryPoints(index: Map<string, GenericFixEntry[]>): Map<string, BoundaryPoint> {
  const points = new Map<string, BoundaryPoint>();
  const add = (product: string, version: string, reason: string) => {
    const key = `${product} ${version}`;
    const existing = points.get(key);
    if (existing) {
      existing.reasons.push(reason);
      return;
    }
    points.set(key, { product, version, reasons: [reason] });
  };

  for (const [product, entries] of index) {
    for (const e of entries) {
      if (e.exact) {
        for (const v of e.exact) add(product, v, `${e.id}: exact-list entry (expect affected)`);
        continue;
      }
      if (e.introduced) add(product, e.introduced, `${e.id}: introduced (expect affected)`);
      if (e.exclusiveEnd) {
        add(product, e.exclusiveEnd, `${e.id}: fixed exact (expect NOT affected)`);
        const before = bumpPatch(e.exclusiveEnd, -1);
        if (before) add(product, before, `${e.id}: fixed-1 (expect affected)`);
      } else if (e.inclusiveEnd) {
        add(product, e.inclusiveEnd, `${e.id}: lastAffected exact (expect affected)`);
        const after = bumpPatch(e.inclusiveEnd, 1);
        if (after) add(product, after, `${e.id}: lastAffected+1 (expect NOT affected)`);
      }
    }
  }

  return points;
}

/**
 * Restrict actual results to IDs ground truth has some opinion about at all.
 * Kept as a defensive safety net against data-freshness skew between a
 * one-off ground-truth fetch and the DB's last scheduled import (e.g.
 * Fortinet before it gained full-archive scraping, or any fetcher revising
 * an already-published advisory between imports) — without this, an entry
 * ground truth simply doesn't know about would be miscounted as a false
 * positive even though the DB entry is entirely correct. This just makes
 * them "unknown" (neither penalized nor credited) instead.
 */
export function restrictToKnownIds(actual: Set<string>, knownIds: Set<string>): Set<string> {
  return new Set([...actual].filter(id => knownIds.has(id)));
}

/** Split actual results against an expected set into true/false positive/negative CVE-ID lists. */
export function diffSets(expected: Set<string>, actual: Set<string>): { tp: string[]; fp: string[]; fn: string[] } {
  const tp: string[] = [];
  const fp: string[] = [];
  for (const c of actual) (expected.has(c) ? tp : fp).push(c);
  const fn = [...expected].filter(c => !actual.has(c));
  return { tp, fp, fn };
}

/**
 * Restrict API search results to CVEs actually surfaced by the vendor's own
 * AdvisoryFetcher (`sources` includes targetSource), rather than the raw
 * multi-source endpoint result. Without this, precision numbers get polluted
 * by unrelated products that happen to share the same name in another source
 * (e.g. RHEL/Oracle Linux package their own "nginx" RPM with an entirely
 * different, RPM-EVR version namespace that numerically collides with
 * upstream nginx.org semver at low version numbers) — that's a real,
 * separately-documented cross-source ambiguity, not a bug in this fetcher.
 */
export function filterBySource<T extends { externalId: string; sources: string[] }>(
  allResults: T[],
  targetSource: string,
): Set<string> {
  return new Set(
    allResults
      .filter(r => r.sources.includes(targetSource))
      .map(r => r.externalId.toUpperCase()),
  );
}

export interface SweepEntry {
  version: string;
  reasons: string[]; // e.g. "CVE-2024-1: fixed-1 (expect affected)"
  tp: number;
  fp: number;
  fn: number;
  fpDetail: string[]; // "CVE-..." over-detected at this version
  fnDetail: string[]; // "CVE-..." missed at this version
}

export interface SweepAggregate {
  totalVersions: number;
  totalTP: number;
  totalFP: number;
  totalFN: number;
  precision: number;
  recall: number;
  f1: number;
  passCount: number;
  failCount: number;
}

export function aggregateSweep(entries: SweepEntry[]): SweepAggregate {
  let totalTP = 0, totalFP = 0, totalFN = 0, passCount = 0;
  for (const e of entries) {
    totalTP += e.tp;
    totalFP += e.fp;
    totalFN += e.fn;
    if (e.fp === 0 && e.fn === 0) passCount++;
  }
  const precision = totalTP + totalFP > 0 ? totalTP / (totalTP + totalFP) : 1;
  const recall    = totalTP + totalFN > 0 ? totalTP / (totalTP + totalFN) : 1;
  const f1        = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;

  return {
    totalVersions: entries.length,
    totalTP,
    totalFP,
    totalFN,
    precision,
    recall,
    f1,
    passCount,
    failCount: entries.length - passCount,
  };
}

export function printSweepReport(
  productName: string,
  entries: SweepEntry[],
  agg: SweepAggregate,
  boundaryDescription = "derived from every advisory's range edges ±1 patch",
): void {
  const pct = (n: number) => `${(n * 100).toFixed(2)}%`;

  console.log('');
  console.log('====================================================');
  console.log(`  ${productName.toUpperCase()} BOUNDARY-VALUE ACCURACY SWEEP`);
  console.log('====================================================');
  console.log('');
  console.log(`Boundary versions tested: ${agg.totalVersions} (${boundaryDescription})`);
  console.log(`Per-version PASS (no FP/FN): ${agg.passCount}/${agg.totalVersions}`);
  console.log('');
  console.log(`  True  Positives (TP): ${agg.totalTP}`);
  console.log(`  False Positives (FP): ${agg.totalFP}`);
  console.log(`  False Negatives (FN): ${agg.totalFN}`);
  console.log('');
  console.log(`  Precision : ${pct(agg.precision)}  (TP / (TP+FP))`);
  console.log(`  Recall    : ${pct(agg.recall)}  (TP / (TP+FN))`);
  console.log(`  F1 Score  : ${pct(agg.f1)}`);

  const failures = entries.filter(e => e.fp > 0 || e.fn > 0);
  if (failures.length > 0) {
    console.log('');
    console.log('----------------------------------------------------');
    console.log(`FAILED BOUNDARY CASES (${failures.length}):`);
    for (const e of failures) {
      console.log(`  [FAIL] version=${e.version}`);
      for (const r of e.reasons) console.log(`         ${r}`);
      for (const c of e.fpDetail) console.log(`         over-detected: ${c}`);
      for (const c of e.fnDetail) console.log(`         missed:        ${c}`);
    }
  } else {
    console.log('');
    console.log('All boundary cases PASSED.');
  }

  console.log('====================================================');
  console.log('');
}
