/**
 * Oracle Linux vulnerability search accuracy validation script
 *
 * Ground truth = the production OracleLinuxFetcher itself, fetched fresh from
 * linux.oracle.com's live OVAL feed -- not an independently reimplemented
 * parser (see validate-apache.ts's history: a second hand-rolled parser for
 * the same source silently drifts out of sync and produces a wrong "ground
 * truth" instead of testing anything useful).
 *
 * Production imports the combined all-OS-versions feed (`new
 * OracleLinuxFetcher()`, no variant -- com.oracle.elsa-all.xml.bz2), not a
 * single-OS-version one, so ground truth fetches that same combined feed;
 * using a narrower per-version feed here would miss entries that only exist
 * in a version not covered by it, which would look like false
 * positives/negatives that aren't actually bugs (same pitfall as RHEL 8 vs 9
 * in validate-redhat.ts).
 *
 * Oracle Linux OVAL entries only ever express an exclusive upper bound
 * (`versionEnd`, "<package> is earlier than <version>") and never a lower
 * bound, so there is no "introduced" boundary to test -- only "fixed exact"
 * (expect NOT affected) and "one RPM release step before fixed" (expect
 * affected).
 *
 * Indexed and queried per (product, OS major version), not by product name
 * alone: OracleLinuxFetcher writes `vendor: "oracle-linux-<major>"` (each
 * row's own release string determines its major, since this combined feed
 * covers every OL release at once), and the search API's `rpmAdvisoryVendor()`
 * only matches an `ecosystem=Oracle Linux:<major>` query to that same
 * version-qualified vendor -- a bare `ecosystem=oracle-linux` (this script's
 * value until 2026-09-02) instead matches only the near-empty legacy vendor
 * bucket rows predating that scheme, collapsing Recall to near-zero despite
 * production actually matching correctly (caught re-running this sweep for
 * the first time since the vendor-versioning change landed).
 *
 * Ground-truth lookups go through an index built once up front, not a linear
 * scan per boundary point -- with tens of thousands of boundary points, an
 * O(points x advisories) scan is CPU-bound and blocks the event loop between
 * awaits, which starves the concurrent HTTP requests of any actual
 * parallelism.
 *
 * Usage:
 *   pnpm validate:oracle-linux                  # sweep mode: every package
 *   pnpm validate:oracle-linux rsync 3.2.4 9     # single (package, version, OS major) check
 */
import 'dotenv/config';
import axios from 'axios';
import { compareRpmVersions } from '../utils/rpm-version.js';
import { OracleLinuxFetcher } from '../worker/oracle-linux-fetcher.js';
import {
  aggregateSweep, printSweepReport, filterBySource, diffSets,
  mapWithConcurrency, queryAllPages, bumpRpmVersion, dedupeSiblingProducts,
} from './lib/accuracy-sweep.js';

const MAX_POINTS_PER_PRODUCT = 50;

const TARGET_SOURCE = 'oracle-linux';
const PAGE_SIZE = 500; // API-enforced max (see zod schema in vulnerabilities.ts)

interface ApiVulnerability {
  externalId: string;
  sources: string[];
}

/** "oracle-linux-9" -> "Oracle Linux:9"; bare "oracle-linux" (no major parsed) stays bare. */
function vendorToEcosystem(vendor: string): string {
  const m = vendor.match(/^oracle-linux-(\d+)$/);
  return m ? `Oracle Linux:${m[1]}` : 'oracle-linux';
}

async function queryLocalAPI(baseUrl: string, product: string, version: string, ecosystem: string): Promise<ApiVulnerability[]> {
  const headers: Record<string, string> = {};
  if (process.env.API_KEY) headers['x-api-key'] = process.env.API_KEY;

  return queryAllPages(async (offset) => {
    const url = `${baseUrl}/api/v1/vulnerabilities/search?package=${encodeURIComponent(product)}&version=${encodeURIComponent(version)}&ecosystem=${encodeURIComponent(ecosystem)}&limit=${PAGE_SIZE}&offset=${offset}`;
    try {
      const res = await axios.get<{ results: ApiVulnerability[] }>(url, { timeout: 30000, headers });
      return res.data.results ?? [];
    } catch (err: unknown) {
      if (axios.isAxiosError(err) && err.code === 'ECONNREFUSED') {
        console.error(`ERROR: Could not reach local API at ${baseUrl}`);
        console.error('       Is the server running? (pnpm dev)');
        process.exit(1);
      }
      throw err;
    }
  }, PAGE_SIZE);
}

// ─── Ground truth (vendor-aware) ────────────────────────────────────────────

interface RpmFixEntry {
  cveId: string;
  versionEnd: string;
  versionStart: string | null;
}

interface BoundaryPoint {
  product: string;
  vendor: string;
  version: string;
  reasons: string[];
}

/** Keys ground truth by (product, vendor) -- not product alone -- since the
 * same product name can carry independent fix histories per OL major. */
function indexByProductAndVendor(
  advisories: { cveId?: string; affectedProducts: { vendor: string; product: string; versionStart?: string; versionEnd?: string }[] }[],
): Map<string, RpmFixEntry[]> {
  const index = new Map<string, RpmFixEntry[]>();
  for (const adv of advisories) {
    if (!adv.cveId) continue;
    for (const p of adv.affectedProducts) {
      if (!p.versionEnd) continue;
      const key = `${p.product} ${p.vendor}`;
      const entry = { cveId: adv.cveId, versionEnd: p.versionEnd, versionStart: p.versionStart ?? null };
      const list = index.get(key);
      if (list) list.push(entry);
      else index.set(key, [entry]);
    }
  }
  return index;
}

function expectedCVEsRpm(product: string, vendor: string, version: string, index: Map<string, RpmFixEntry[]>): Set<string> {
  const result = new Set<string>();
  for (const e of index.get(`${product} ${vendor}`) ?? []) {
    if (compareRpmVersions(version, e.versionEnd) >= 0) continue;
    if (e.versionStart && compareRpmVersions(version, e.versionStart) < 0) continue;
    result.add(e.cveId.toUpperCase());
  }
  return result;
}

function collectBoundaryPoints(index: Map<string, RpmFixEntry[]>): Map<string, BoundaryPoint> {
  const points = new Map<string, BoundaryPoint>();
  const add = (product: string, vendor: string, version: string, reason: string) => {
    const key = `${product} ${vendor} ${version}`;
    const existing = points.get(key);
    if (existing) {
      existing.reasons.push(reason);
      return;
    }
    points.set(key, { product, vendor, version, reasons: [reason] });
  };

  for (const [key, fixes] of index) {
    const [product, vendor] = key.split(' ');
    for (const { cveId, versionEnd } of fixes) {
      add(product, vendor, versionEnd, `${cveId}: fixed exact (expect NOT affected)`);
      const before = bumpRpmVersion(versionEnd, -1);
      if (before) add(product, vendor, before, `${cveId}: fixed-1 release (expect affected)`);
    }
  }

  return points;
}

/** Same policy as accuracy-sweep.ts's capPointsPerProduct, scoped per (product, vendor)
 * instead of product alone, so one OL major's kernel-uek-sized fix history
 * doesn't crowd out coverage of the same product on a different major. */
function capPoints(points: Map<string, BoundaryPoint>, maxPerGroup: number): BoundaryPoint[] {
  const byGroup = new Map<string, BoundaryPoint[]>();
  for (const point of points.values()) {
    const key = `${point.product} ${point.vendor}`;
    const list = byGroup.get(key);
    if (list) list.push(point);
    else byGroup.set(key, [point]);
  }

  const result: BoundaryPoint[] = [];
  for (const list of byGroup.values()) {
    const step = Math.ceil(list.length / maxPerGroup);
    const sample = step <= 1 ? list : list.filter((_, i) => i % step === 0);
    result.push(...sample);
  }
  return result;
}

const CONCURRENCY = 20; // matches the API's own pg pool size (see src/db/client.ts)

async function runSweep(baseUrl: string, index: Map<string, RpmFixEntry[]>, advisoryCount: number): Promise<void> {
  const rawPoints = collectBoundaryPoints(index);
  const points = capPoints(rawPoints, MAX_POINTS_PER_PRODUCT);
  console.log(`Sweeping ${points.length} (package, version) boundary points (capped at ${MAX_POINTS_PER_PRODUCT}/product-per-major from ${rawPoints.size} raw) derived from ${advisoryCount} advisories (concurrency=${CONCURRENCY})...`);

  let done = 0;
  const entries = await mapWithConcurrency(points, CONCURRENCY, async ({ product, vendor, version, reasons }) => {
    const expected = expectedCVEsRpm(product, vendor, version, index);
    const allResults = await queryLocalAPI(baseUrl, product, version, vendorToEcosystem(vendor));
    const actual = filterBySource(allResults, TARGET_SOURCE);
    const { tp, fp, fn } = diffSets(expected, actual);

    done++;
    if (done % 2000 === 0) console.log(`  ...${done}/${points.length}`);

    return {
      version: `${product}@${version} (${vendor})`,
      reasons,
      tp: tp.length,
      fp: fp.length,
      fn: fn.length,
      fpDetail: fp,
      fnDetail: fn,
    };
  });

  printSweepReport(
    'Oracle Linux',
    entries,
    aggregateSweep(entries),
    `derived from every package's fixed version across all OL versions, ±1 RPM release step, capped at ${MAX_POINTS_PER_PRODUCT}/product-per-major`,
  );
}

// ─── Entry Point ──────────────────────────────────────────────────────────────

function parseArgs(): { product: string; version: string; major: string } | null {
  const [, , product, version, major] = process.argv;
  if (!product && !version) return null; // sweep mode
  if (!product || !version || !major) {
    console.error('Usage: pnpm validate:oracle-linux [package version major]');
    console.error('Example: pnpm validate:oracle-linux rsync 3.2.4 9');
    console.error('(omit all three to run a boundary-value sweep across every Oracle Linux package)');
    process.exit(1);
  }
  return { product, version, major };
}

async function main() {
  const args = parseArgs();
  const baseUrl = process.env.API_BASE_URL ?? 'http://localhost:5000';

  console.log('Fetching live Oracle Linux OVAL feed (all versions, matching production)...');
  const advisories = await new OracleLinuxFetcher().fetch();
  console.log(`Parsed ${advisories.length} advisories from Oracle Linux OVAL`);

  const index = indexByProductAndVendor(advisories);

  if (args === null) {
    await runSweep(baseUrl, dedupeSiblingProducts(index), advisories.length);
    return;
  }

  const { product, version, major } = args;
  const vendor = `oracle-linux-${major}`;
  const expected = expectedCVEsRpm(product, vendor, version, index);
  console.log(`Ground truth for ${product} ${version} (OL${major}): ${expected.size} CVEs should match`);

  const allResults = await queryLocalAPI(baseUrl, product, version, vendorToEcosystem(vendor));
  const actual = filterBySource(allResults, TARGET_SOURCE);
  const { tp, fp, fn } = diffSets(expected, actual);

  const pct = (n: number) => `${(n * 100).toFixed(2)}%`;
  const precision = tp.length + fp.length > 0 ? tp.length / (tp.length + fp.length) : 1;
  const recall = tp.length + fn.length > 0 ? tp.length / (tp.length + fn.length) : 1;

  console.log('');
  console.log(`True Positives: ${tp.length}, False Positives: ${fp.length}, False Negatives: ${fn.length}`);
  console.log(`Precision: ${pct(precision)}  Recall: ${pct(recall)}`);
  if (fp.length > 0) console.log('False positives:', fp.join(', '));
  if (fn.length > 0) console.log('False negatives:', fn.join(', '));
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
