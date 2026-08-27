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
 * This exercises the `ecosystem=oracle-linux` routing added to
 * src/utils/search-helpers.ts (rpmAdvisoryVendor) -- previously absent, which
 * meant Oracle Linux searches silently fell back to the lossy BigInt
 * approximation regardless of what the README documented.
 *
 * Ground-truth lookups go through an index built once up front (indexByProduct
 * / expectedCVEsRpm), not a linear scan per boundary point -- with tens of
 * thousands of boundary points, an O(points x advisories) scan is CPU-bound
 * and blocks the event loop between awaits, which starves the concurrent HTTP
 * requests of any actual parallelism.
 *
 * Usage:
 *   pnpm validate:oracle-linux                  # sweep mode: every package
 *   pnpm validate:oracle-linux rsync 3.2.4       # single (package, version) check
 */
import 'dotenv/config';
import axios from 'axios';
import { OracleLinuxFetcher } from '../worker/oracle-linux-fetcher.js';
import {
  bumpRpmVersion, aggregateSweep, printSweepReport, filterBySource, diffSets,
  mapWithConcurrency, indexByProduct, expectedCVEsRpm, queryAllPages, capPointsPerProduct,
  type RpmFixEntry, type BoundaryPoint,
} from './lib/accuracy-sweep.js';

const MAX_POINTS_PER_PRODUCT = 50;

const TARGET_SOURCE = 'oracle-linux';
const ECOSYSTEM = 'oracle-linux';
const PAGE_SIZE = 500; // API-enforced max (see zod schema in vulnerabilities.ts)

interface ApiVulnerability {
  externalId: string;
  sources: string[];
}

async function queryLocalAPI(baseUrl: string, product: string, version: string): Promise<ApiVulnerability[]> {
  const headers: Record<string, string> = {};
  if (process.env.API_KEY) headers['x-api-key'] = process.env.API_KEY;

  return queryAllPages(async (offset) => {
    const url = `${baseUrl}/api/v1/vulnerabilities/search?package=${encodeURIComponent(product)}&version=${encodeURIComponent(version)}&ecosystem=${encodeURIComponent(ECOSYSTEM)}&limit=${PAGE_SIZE}&offset=${offset}`;
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

// ─── Boundary-Value Sweep ──────────────────────────────────────────────────────

function collectBoundaryPoints(index: Map<string, RpmFixEntry[]>): Map<string, BoundaryPoint> {
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

  for (const [product, fixes] of index) {
    for (const { cveId, versionEnd } of fixes) {
      add(product, versionEnd, `${cveId}: fixed exact (expect NOT affected)`);
      const before = bumpRpmVersion(versionEnd, -1);
      if (before) add(product, before, `${cveId}: fixed-1 release (expect affected)`);
    }
  }

  return points;
}

const CONCURRENCY = 20; // matches the API's own pg pool size (see src/db/client.ts)

async function runSweep(baseUrl: string, index: Map<string, RpmFixEntry[]>, advisoryCount: number): Promise<void> {
  const rawPoints = collectBoundaryPoints(index);
  const capped = capPointsPerProduct(rawPoints, MAX_POINTS_PER_PRODUCT);
  const points = [...capped.values()];
  console.log(`Sweeping ${points.length} (package, version) boundary points (capped at ${MAX_POINTS_PER_PRODUCT}/product from ${rawPoints.size} raw) derived from ${advisoryCount} advisories (concurrency=${CONCURRENCY})...`);

  let done = 0;
  const entries = await mapWithConcurrency(points, CONCURRENCY, async ({ product, version, reasons }) => {
    const expected = expectedCVEsRpm(product, version, index);
    const allResults = await queryLocalAPI(baseUrl, product, version);
    const actual = filterBySource(allResults, TARGET_SOURCE);
    const { tp, fp, fn } = diffSets(expected, actual);

    done++;
    if (done % 2000 === 0) console.log(`  ...${done}/${points.length}`);

    return {
      version: `${product}@${version}`,
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
    `derived from every package's fixed version across all OL versions, ±1 RPM release step, capped at ${MAX_POINTS_PER_PRODUCT}/product`,
  );
}

// ─── Entry Point ──────────────────────────────────────────────────────────────

function parseArgs(): { product: string; version: string } | null {
  const [, , product, version] = process.argv;
  if (!product && !version) return null; // sweep mode
  if (!product || !version) {
    console.error('Usage: pnpm validate:oracle-linux [package version]');
    console.error('Example: pnpm validate:oracle-linux rsync 3.2.4');
    console.error('(omit both to run a boundary-value sweep across every Oracle Linux package)');
    process.exit(1);
  }
  return { product, version };
}

async function main() {
  const args = parseArgs();
  const baseUrl = process.env.API_BASE_URL ?? 'http://localhost:5000';

  console.log('Fetching live Oracle Linux OVAL feed (all versions, matching production)...');
  const advisories = await new OracleLinuxFetcher().fetch();
  console.log(`Parsed ${advisories.length} advisories from Oracle Linux OVAL`);

  const index = indexByProduct(advisories);

  if (args === null) {
    await runSweep(baseUrl, index, advisories.length);
    return;
  }

  const { product, version } = args;
  const expected = expectedCVEsRpm(product, version, index);
  console.log(`Ground truth for ${product} ${version}: ${expected.size} CVEs should match`);

  const allResults = await queryLocalAPI(baseUrl, product, version);
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
