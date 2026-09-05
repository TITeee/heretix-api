/**
 * Red Hat (RHEL) vulnerability search accuracy validation script
 *
 * Ground truth = the production RedHatFetcher itself, fetched fresh from
 * security.access.redhat.com's live OVAL feeds -- not an independently
 * reimplemented parser (see validate-apache.ts's history: a second hand-rolled
 * parser for the same source silently drifts out of sync and produces a wrong
 * "ground truth" instead of testing anything useful).
 *
 * RedHatFetcher.source() always returns 'red-hat' regardless of the RHEL major
 * version constructor arg, but AdvisoryAffectedProduct.vendor is keyed per OS
 * major ("red-hat-8"/"red-hat-9", see rpmAdvisoryVendor() in search-helpers.ts) --
 * ground truth fetches and merges both feeds, and queryLocalAPI() queries both
 * "Red Hat:8" and "Red Hat:9" and unions the results, or entries that only
 * exist in one major version (e.g. an RHEL8-only "elN_0" build) would look
 * like false positives/negatives that aren't actually bugs.
 *
 * RHEL OVAL entries only ever express an exclusive upper bound (`versionEnd`,
 * "<package> is earlier than <version>") and never a lower bound, so there is
 * no "introduced" boundary to test -- only "fixed exact" (expect NOT affected)
 * and "one RPM release step before fixed" (expect affected).
 *
 * Results are restricted to `sources` containing "red-hat" (see
 * src/scripts/lib/accuracy-sweep.ts's filterBySource) since the raw
 * package=X search also matches unrelated products/sources sharing the same
 * package name.
 *
 * Ground-truth lookups go through an index built once up front (indexByProduct
 * / expectedCVEsRpm), not a linear scan per boundary point -- with 100k+
 * boundary points, an O(points x advisories) scan is CPU-bound and blocks the
 * event loop between awaits, which starves the concurrent HTTP requests of
 * any actual parallelism.
 *
 * Usage:
 *   pnpm validate:redhat                      # sweep mode: every RHEL 8+9 package
 *   pnpm validate:redhat rsync 3.2.4           # single (package, version) check
 */
import 'dotenv/config';
import axios from 'axios';
import { RedHatFetcher } from '../worker/redhat-fetcher.js';
import {
  bumpRpmVersion, aggregateSweep, printSweepReport, filterBySource, diffSets,
  mapWithConcurrency, indexByProduct, expectedCVEsRpm, queryAllPages, dedupeSiblingProducts, type RpmFixEntry,
} from './lib/accuracy-sweep.js';

const PAGE_SIZE = 500; // API-enforced max (see zod schema in vulnerabilities.ts)

const TARGET_SOURCE = 'red-hat';
// AdvisoryAffectedProduct.vendor is keyed per OS major ("red-hat-8", "red-hat-9"),
// not one shared bucket -- a single hardcoded ecosystem only ever sees that one
// major's rows, so a fix recorded solely under RHEL8 (e.g. an "elN_0" build,
// like bpftool's CVE-2018-20784 fix) is invisible when only querying "Red Hat:9",
// even though ground truth below merges both RHEL8+RHEL9 OVAL feeds. Query both
// majors and union the results, matching how a real caller on either major
// would see it (same fix already applied to validate-nodejs.ts).
const ECOSYSTEMS = ['Red Hat:8', 'Red Hat:9'];

interface ApiVulnerability {
  externalId: string;
  sources: string[];
}

async function queryLocalAPI(baseUrl: string, product: string, version: string): Promise<ApiVulnerability[]> {
  const headers: Record<string, string> = {};
  if (process.env.API_KEY) headers['x-api-key'] = process.env.API_KEY;

  const perEcosystem = await Promise.all(ECOSYSTEMS.map(ecosystem =>
    queryAllPages(async (offset) => {
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
    }, PAGE_SIZE),
  ));
  return perEcosystem.flat();
}

// ─── Boundary-Value Sweep ──────────────────────────────────────────────────────

interface BoundaryPoint {
  product: string;
  version: string;
  reasons: string[];
}

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
  const points = [...collectBoundaryPoints(index).values()];
  console.log(`Sweeping ${points.length} (package, version) boundary points derived from ${advisoryCount} advisories (concurrency=${CONCURRENCY})...`);

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
    'Red Hat (RHEL 8+9)',
    entries,
    aggregateSweep(entries),
    "derived from every RHEL 8+9 package's fixed version, ±1 RPM release step",
  );
}

// ─── Entry Point ──────────────────────────────────────────────────────────────

function parseArgs(): { product: string; version: string } | null {
  const [, , product, version] = process.argv;
  if (!product && !version) return null; // sweep mode
  if (!product || !version) {
    console.error('Usage: pnpm validate:redhat [package version]');
    console.error('Example: pnpm validate:redhat rsync 3.2.4');
    console.error('(omit both to run a boundary-value sweep across every RHEL 8+9 package)');
    process.exit(1);
  }
  return { product, version };
}

async function main() {
  const args = parseArgs();
  const baseUrl = process.env.API_BASE_URL ?? 'http://localhost:5000';

  // Production imports RHEL 8 and RHEL 9 as separate jobs, but RedHatFetcher.source()
  // always returns 'red-hat' regardless of variant, so both land in the same
  // vendor bucket in the DB. Ground truth must merge both feeds too, or entries
  // that only exist in one RHEL major version look like false positives/negatives
  // that aren't actually bugs.
  console.log('Fetching live Red Hat OVAL feeds (RHEL 8 + RHEL 9)...');
  const [rhel9, rhel8] = await Promise.all([
    new RedHatFetcher('rhel9').fetch(),
    new RedHatFetcher('rhel8').fetch(),
  ]);
  const advisories = [...rhel9, ...rhel8];
  console.log(`Parsed ${advisories.length} advisories from Red Hat OVAL (${rhel9.length} RHEL9 + ${rhel8.length} RHEL8)`);

  const index = indexByProduct(advisories);

  if (args === null) {
    await runSweep(baseUrl, dedupeSiblingProducts(index), advisories.length);
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
