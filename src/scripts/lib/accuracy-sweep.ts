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

export function printSweepReport(productName: string, entries: SweepEntry[], agg: SweepAggregate): void {
  const pct = (n: number) => `${(n * 100).toFixed(2)}%`;

  console.log('');
  console.log('====================================================');
  console.log(`  ${productName.toUpperCase()} BOUNDARY-VALUE ACCURACY SWEEP`);
  console.log('====================================================');
  console.log('');
  console.log(`Boundary versions tested: ${agg.totalVersions} (derived from every advisory's range edges ±1 patch)`);
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
