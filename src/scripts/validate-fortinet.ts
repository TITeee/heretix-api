/**
 * Fortinet PSIRT search accuracy validation script
 *
 * Ground truth = the production FortinetFetcher itself, fetched fresh from
 * FortiGuard's paginated PSIRT listing + per-advisory CSAF feed — not an
 * independently reimplemented parser (see validate-apache.ts's history: a
 * second hand-rolled parser for the same source silently drifts out of sync
 * and produces a wrong "ground truth" instead of testing anything useful).
 *
 * Fortinet advisories mix two range representations per affected-product
 * entry: an exact version list (`affectedVersions`), or a range
 * (`versionStart`/`versionEnd`/`versionFixed`/`lastAffected`). Crucially,
 * `versionFixed` and `lastAffected` can BOTH be set on the same entry —
 * importAdvisoryData() resolves this by preferring `versionEnd ?? versionFixed`
 * (exclusive) and only falling back to `lastAffected` (inclusive) when
 * neither is present. Ground truth replicates that exact precedence via
 * indexGenericByProduct()/expectedIdsGeneric() (see accuracy-sweep.ts) —
 * getting it backwards would silently disagree with what the search endpoint
 * actually does.
 *
 * Results are restricted to `sources` containing "fortinet" (see
 * src/scripts/lib/accuracy-sweep.ts's filterBySource) since the raw
 * package=X search also matches unrelated products/sources sharing the same
 * package name.
 *
 * FortinetFetcher.fetch() now scrapes the full paginated PSIRT archive
 * (same as production, matching PanFetcher's mode: 'all'), so this no
 * longer misses older advisories. Results are still restricted to IDs
 * ground truth has some opinion about at all (restrictToKnownIds) as a
 * defensive safety net against any remaining data-freshness skew between
 * a one-off ground-truth fetch and the DB's last scheduled import — see
 * accuracy-sweep.ts for why.
 *
 * Usage:
 *   pnpm validate:fortinet                    # sweep mode: every Fortinet product
 *   pnpm validate:fortinet FortiOS 7.4.3      # single (product, version) check
 */
import 'dotenv/config';
import axios from 'axios';
import { FortinetFetcher } from '../worker/fortinet-fetcher.js';
import {
  aggregateSweep, printSweepReport, filterBySource, diffSets, restrictToKnownIds,
  mapWithConcurrency, indexGenericByProduct, expectedIdsGeneric, collectGenericBoundaryPoints,
  queryAllPages, type SweepEntry,
} from './lib/accuracy-sweep.js';

const TARGET_SOURCE = 'fortinet';
const CONCURRENCY = 20;
const PAGE_SIZE = 500;

interface ApiVulnerability {
  externalId: string;
  sources: string[];
}

async function queryLocalAPI(baseUrl: string, product: string, version: string): Promise<ApiVulnerability[]> {
  const headers: Record<string, string> = {};
  if (process.env.API_KEY) headers['x-api-key'] = process.env.API_KEY;

  return queryAllPages(async (offset) => {
    const url = `${baseUrl}/api/v1/vulnerabilities/search?package=${encodeURIComponent(product)}&version=${encodeURIComponent(version)}&limit=${PAGE_SIZE}&offset=${offset}`;
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

async function runSweep(
  baseUrl: string,
  index: ReturnType<typeof indexGenericByProduct>,
  knownIds: Set<string>,
  advisoryCount: number,
): Promise<void> {
  const points = [...collectGenericBoundaryPoints(index).values()];
  console.log(`Sweeping ${points.length} (product, version) boundary points derived from ${advisoryCount} advisories (concurrency=${CONCURRENCY})...`);

  let done = 0;
  const entries: SweepEntry[] = await mapWithConcurrency(points, CONCURRENCY, async ({ product, version, reasons }) => {
    const expected = expectedIdsGeneric(product, version, index);
    const allResults = await queryLocalAPI(baseUrl, product, version);
    const actual = restrictToKnownIds(filterBySource(allResults, TARGET_SOURCE), knownIds);
    const { tp, fp, fn } = diffSets(expected, actual);

    done++;
    if (done % 200 === 0) console.log(`  ...${done}/${points.length}`);

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
    'Fortinet',
    entries,
    aggregateSweep(entries),
    "derived from every advisory's range edges (or exact-list entries) ±1 patch",
  );
}

function parseArgs(): { product: string; version: string } | null {
  const [, , product, version] = process.argv;
  if (!product && !version) return null;
  if (!product || !version) {
    console.error('Usage: pnpm validate:fortinet [product version]');
    console.error('Example: pnpm validate:fortinet FortiOS 7.4.3');
    console.error('(omit both to run a boundary-value sweep across every Fortinet product)');
    process.exit(1);
  }
  return { product, version };
}

async function main() {
  const args = parseArgs();
  const baseUrl = process.env.API_BASE_URL ?? 'http://localhost:5000';

  console.log('Fetching live Fortinet PSIRT feed (RSS + per-advisory CSAF)...');
  const advisories = await new FortinetFetcher({ delayMs: 100 }).fetch();
  console.log(`Parsed ${advisories.length} advisories from Fortinet PSIRT`);

  const index = indexGenericByProduct(advisories);
  const knownIds = new Set(advisories.map(a => (a.cveId ?? a.externalId).toUpperCase()));

  if (args === null) {
    await runSweep(baseUrl, index, knownIds, advisories.length);
    return;
  }

  const { product, version } = args;
  const expected = expectedIdsGeneric(product, version, index);
  console.log(`Ground truth for ${product} ${version}: ${expected.size} CVEs should match`);

  const allResults = await queryLocalAPI(baseUrl, product, version);
  const actual = restrictToKnownIds(filterBySource(allResults, TARGET_SOURCE), knownIds);
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
