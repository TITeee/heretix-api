/**
 * Apache HTTP Server vulnerability search accuracy validation script
 *
 * Uses the official security advisories from httpd.apache.org as Ground Truth,
 * compares them against local API search results, and measures Precision/Recall.
 * Automatically selects the target page based on the version branch (2.4, etc.)
 *
 * Usage:
 *   pnpm validate:apache 2.4.62
 *   API_BASE_URL=http://localhost:5000 pnpm validate:apache 2.4.58
 */
import 'dotenv/config';
import axios from 'axios';
import { normalizeVersion } from '../utils/version.js';
import { bumpPatch, aggregateSweep, printSweepReport, filterBySource, type SweepEntry } from './lib/accuracy-sweep.js';
import { parseAffects, findAdvisoryBlocks, type AffectsSpec } from '../worker/apache-fetcher.js';

const TARGET_SOURCE = 'advisory-apache';
// apache-fetcher.ts only tracks the 2.4 branch page; sweep mode mirrors that.
const SWEEP_VERSION = '2.4.0';

// ─── Type Definitions ────────────────────────────────────────────────────────

interface VulnerableRange {
  introduced: string | null;  // null = all versions (no lower bound)
  fixed: string | null;       // exclusive upper bound ("before X")
  lastAffected: string | null; // inclusive upper bound ("through X" or "<=X")
  exact: string[] | null;      // exact version list (comma-separated notation), mutually exclusive with the above
}

interface ApacheAdvisory {
  cveId: string;
  severity: string;
  ranges: VulnerableRange[];
}

interface ApiVulnerability {
  externalId: string;
  sources: string[];
  severity: string | null;
  approximateMatch: boolean;
}

interface ComparisonResult {
  version: string;
  groundTruthCVEs: Set<string>;
  apiCVEs: Set<string>;
  truePositives: string[];
  falsePositives: string[];
  falseNegatives: string[];
  osvOnlyIds: string[];
  precision: number;
  recall: number;
  f1: number;
}

// ─── Argument Parsing ─────────────────────────────────────────────────────────

function parseArgs(): string | null {
  const [, , version] = process.argv;
  if (!version) return null; // sweep mode: derive boundary versions from every advisory
  if (!/^\d+\.\d+\.\d+/.test(version)) {
    console.error('Usage: pnpm validate:apache [version]');
    console.error('Example: pnpm validate:apache 2.4.62');
    console.error('(omit the version to run a boundary-value sweep across every advisory)');
    process.exit(1);
  }
  return version;
}

// ─── Ground Truth Fetch & Parse ───────────────────────────────────────────────

/** Derive branch number ("24", "22", etc.) from a version string and build the page URL */
function advisoryPageUrl(version: string): string {
  const [major, minor] = version.split('.');
  return `https://httpd.apache.org/security/vulnerabilities_${major}${minor}.html`;
}

async function fetchApacheAdvisoryPage(version: string): Promise<string> {
  const url = advisoryPageUrl(version);
  const res = await axios.get<string>(url, {
    responseType: 'text',
    timeout: 15000,
    headers: { 'User-Agent': 'heretix-api/1.0 accuracy-validator' },
  });
  return res.data;
}

/**
 * Convert apache-fetcher.ts's AffectsSpec into this script's VulnerableRange shape.
 * The parsing itself (parseAffects, findAdvisoryBlocks) is imported directly from
 * apache-fetcher.ts rather than reimplemented here — httpd.apache.org's notation is
 * varied enough (before/through/>=/<=/exact-list, HTML-entity-encoded comparisons)
 * that a second, independently maintained parser reliably drifts from the real one,
 * which silently corrupts the ground truth instead of testing anything useful.
 */
function toRange(spec: AffectsSpec): VulnerableRange {
  return {
    introduced: spec.versionStart ?? null,
    fixed: spec.versionEnd ?? null,
    lastAffected: spec.lastAffected ?? null,
    exact: spec.affectedVersions ?? null,
  };
}

/** Parse ApacheAdvisory[] from the HTML of httpd.apache.org using the production block/Affects parser. */
function parseApacheAdvisories(html: string): ApacheAdvisory[] {
  const advisories: ApacheAdvisory[] = [];

  for (const b of findAdvisoryBlocks(html)) {
    const affectsMatch = b.block.match(/<tr><td class="cve-header">Affects<\/td><td class="cve-value">([^<]*)<\/td><\/tr>/);
    if (!affectsMatch) continue;
    const spec = parseAffects(affectsMatch[1]);
    if (!spec) continue;

    advisories.push({ cveId: b.cveId, severity: b.severity.toLowerCase(), ranges: [toRange(spec)] });
  }

  return advisories;
}

/**
 * Return the set of CVE IDs that apply to the specified version.
 *
 * Apache uses three types of upper bound notation:
 *   - `fixed`        (exclusive):  versionInt < fixedInt
 *   - `lastAffected` (inclusive):  versionInt <= lastAffectedInt
 *   - both null: lower-bound check only
 */
function filterExpectedCVEs(version: string, advisories: ApacheAdvisory[]): Set<string> {
  const versionInt = normalizeVersion(version);
  if (versionInt === null) {
    console.error(`ERROR: Could not normalize version "${version}" to BigInt`);
    process.exit(1);
  }

  const result = new Set<string>();

  for (const adv of advisories) {
    for (const range of adv.ranges) {
      // Exact version list: matches the search endpoint's affectedVersions.has(version)
      // (exact string equality, no range comparison at all).
      if (range.exact !== null) {
        if (range.exact.includes(version)) {
          result.add(adv.cveId);
          break;
        }
        continue;
      }

      // Lower-bound check (introduced === null means no lower bound)
      if (range.introduced !== null) {
        const introducedInt = normalizeVersion(range.introduced);
        if (introducedInt !== null && versionInt < introducedInt) continue;
      }

      // Upper-bound check: fixed (exclusive)
      if (range.fixed !== null) {
        const fixedInt = normalizeVersion(range.fixed);
        if (fixedInt !== null && versionInt >= fixedInt) continue;
      }

      // Upper-bound check: lastAffected (inclusive)
      if (range.lastAffected !== null) {
        const lastInt = normalizeVersion(range.lastAffected);
        if (lastInt !== null && versionInt > lastInt) continue;
      }

      result.add(adv.cveId);
      break;
    }
  }

  return result;
}

// ─── Local API Query ──────────────────────────────────────────────────────────

async function querySearchEndpoint(baseUrl: string, version: string): Promise<ApiVulnerability[]> {
  const url = `${baseUrl}/api/v1/vulnerabilities/search?package=httpd&version=${encodeURIComponent(version)}&limit=500`;
  const headers: Record<string, string> = {};
  if (process.env.API_KEY) headers['x-api-key'] = process.env.API_KEY;
  const res = await axios.get<{ results: ApiVulnerability[] }>(url, { timeout: 30000, headers });
  return res.data.results ?? [];
}

async function queryLocalAPI(
  baseUrl: string,
  version: string,
): Promise<{ cveIds: Set<string>; osvOnlyIds: string[]; allResults: ApiVulnerability[] }> {
  let allResults: ApiVulnerability[] = [];

  try {
    allResults = await querySearchEndpoint(baseUrl, version);
  } catch (err: unknown) {
    if (axios.isAxiosError(err) && err.code === 'ECONNREFUSED') {
      console.error(`ERROR: Could not reach local API at ${baseUrl}`);
      console.error('       Is the server running? (pnpm dev)');
      process.exit(1);
    }
    throw err;
  }

  const cveIds = new Set<string>();
  const osvOnlyIds: string[] = [];

  for (const r of allResults) {
    if (/^CVE-\d{4}-\d+$/i.test(r.externalId)) {
      cveIds.add(r.externalId.toUpperCase());
    } else {
      osvOnlyIds.push(r.externalId);
    }
  }

  return { cveIds, osvOnlyIds, allResults };
}

// ─── Comparison & Report ──────────────────────────────────────────────────────

function compareResults(
  groundTruthCVEs: Set<string>,
  apiCVEs: Set<string>,
  version: string,
  osvOnlyIds: string[],
): ComparisonResult {
  const gt  = new Set([...groundTruthCVEs].map(c => c.toUpperCase()));
  const api = new Set([...apiCVEs].map(c => c.toUpperCase()));

  const truePositives  = [...gt].filter(c =>  api.has(c)).sort();
  const falsePositives = [...api].filter(c => !gt.has(c)).sort();
  const falseNegatives = [...gt].filter(c => !api.has(c)).sort();

  const tp = truePositives.length;
  const fp = falsePositives.length;
  const fn = falseNegatives.length;

  const precision = tp + fp > 0 ? tp / (tp + fp) : 1;
  const recall    = tp + fn > 0 ? tp / (tp + fn) : 1;
  const f1        = precision + recall > 0 ? 2 * (precision * recall) / (precision + recall) : 0;

  return { version, groundTruthCVEs: gt, apiCVEs: api, truePositives, falsePositives, falseNegatives, osvOnlyIds, precision, recall, f1 };
}

function printReport(
  result: ComparisonResult,
  allAdvisories: ApacheAdvisory[],
  allApiResults: ApiVulnerability[],
): void {
  const pct    = (n: number) => `${(n * 100).toFixed(2)}%`;
  const advMap = new Map(allAdvisories.map(a => [a.cveId.toUpperCase(), a]));
  const apiMap = new Map(allApiResults.map(r => [r.externalId.toUpperCase(), r]));

  const branch = result.version.split('.').slice(0, 2).join('.');
  console.log('');
  console.log('====================================================');
  console.log(`  APACHE HTTPD ${branch} ACCURACY VALIDATION — version ${result.version}`);
  console.log('====================================================');
  console.log('');
  console.log(`Ground truth (httpd.apache.org): ${result.groundTruthCVEs.size} CVEs affect ${result.version}`);
  console.log(`API results (CVE only):          ${result.apiCVEs.size} CVEs returned`);
  if (result.osvOnlyIds.length > 0) {
    console.log(`OSV-only IDs (excluded):         ${result.osvOnlyIds.length} (non-CVE, not compared)`);
  }
  console.log('');
  console.log(`  True  Positives (TP): ${result.truePositives.length}`);
  console.log(`  False Positives (FP): ${result.falsePositives.length}  ← returned by API but not in official advisories`);
  console.log(`  False Negatives (FN): ${result.falseNegatives.length}  ← in official advisories but missed by API`);
  console.log('');
  console.log(`  Precision : ${pct(result.precision)}  (TP / (TP+FP))`);
  console.log(`  Recall    : ${pct(result.recall)}  (TP / (TP+FN))`);
  console.log(`  F1 Score  : ${pct(result.f1)}`);

  if (result.falsePositives.length > 0) {
    console.log('');
    console.log('----------------------------------------------------');
    console.log('FALSE POSITIVES (over-detection — returned by API but not in official advisories):');
    for (const cve of result.falsePositives) {
      const api    = apiMap.get(cve);
      const srcStr = api ? `[sources: ${api.sources.join(', ')}]` : '';
      const approx = api?.approximateMatch ? ' [approximateMatch]' : '';
      console.log(`  ${cve}   ${srcStr}${approx}`);
    }
  }

  if (result.falseNegatives.length > 0) {
    console.log('');
    console.log('----------------------------------------------------');
    console.log('FALSE NEGATIVES (misses — in official advisories but not returned by API):');
    for (const cve of result.falseNegatives) {
      const adv = advMap.get(cve);
      const sevStr = adv ? `[severity: ${adv.severity}]` : '';
      const rangeStr = adv
        ? adv.ranges.map(r => {
            if (r.exact)        return `exact: [${r.exact.join(', ')}]`;
            if (r.fixed)        return `${r.introduced ?? '*'} before ${r.fixed}`;
            if (r.lastAffected) return `${r.introduced ?? '*'} through ${r.lastAffected}`;
            return r.introduced ?? '*';
          }).join(', ')
        : '';
      console.log(`  ${cve}   ${sevStr}  affects: ${rangeStr}`);
    }
  }

  if (result.truePositives.length > 0) {
    console.log('');
    console.log('----------------------------------------------------');
    const preview = result.truePositives.slice(0, 5).join(', ');
    const rest    = result.truePositives.length > 5 ? ` ... (+${result.truePositives.length - 5} more)` : '';
    console.log(`TRUE POSITIVES (${result.truePositives.length} CVEs correctly matched):`);
    console.log(`  ${preview}${rest}`);
  }

  console.log('====================================================');
  console.log('');
}

// ─── Boundary-Value Sweep ──────────────────────────────────────────────────────

/**
 * For every advisory range, derive the introduced/fixed/lastAffected edges.
 * `introduced === null` (no lower bound) and `fixed === null` with no `lastAffected`
 * (no upper bound at all) ranges contribute no boundary points on that side.
 */
function collectBoundaryVersions(advisories: ApacheAdvisory[]): Map<string, string[]> {
  const points = new Map<string, string[]>();
  const add = (version: string, reason: string) => {
    const list = points.get(version) ?? [];
    list.push(reason);
    points.set(version, list);
  };

  for (const adv of advisories) {
    for (const range of adv.ranges) {
      if (range.exact !== null) {
        for (const v of range.exact) {
          add(v, `${adv.cveId}: exact-list entry (expect affected)`);
        }
        continue;
      }
      if (range.introduced !== null) {
        add(range.introduced, `${adv.cveId}: introduced (expect affected)`);
      }
      if (range.fixed !== null) {
        add(range.fixed, `${adv.cveId}: fixed exact (expect NOT affected)`);
        const before = bumpPatch(range.fixed, -1);
        if (before) add(before, `${adv.cveId}: fixed-1 (expect affected)`);
      }
      if (range.lastAffected !== null) {
        add(range.lastAffected, `${adv.cveId}: lastAffected exact (expect affected)`);
        const after = bumpPatch(range.lastAffected, 1);
        if (after) add(after, `${adv.cveId}: lastAffected+1 (expect NOT affected)`);
      }
    }
  }

  return points;
}

async function runSweep(baseUrl: string, advisories: ApacheAdvisory[]): Promise<void> {
  const points = collectBoundaryVersions(advisories);
  console.log(`Sweeping ${points.size} boundary versions derived from ${advisories.length} advisory entries...`);

  const entries: SweepEntry[] = [];
  for (const [version, reasons] of points) {
    const expected = filterExpectedCVEs(version, advisories);
    const { allResults } = await queryLocalAPI(baseUrl, version);
    const actual = filterBySource(allResults, TARGET_SOURCE);
    const result = compareResults(expected, actual, version, []);
    entries.push({
      version,
      reasons,
      tp: result.truePositives.length,
      fp: result.falsePositives.length,
      fn: result.falseNegatives.length,
      fpDetail: result.falsePositives,
      fnDetail: result.falseNegatives,
    });
  }

  printSweepReport('apache httpd', entries, aggregateSweep(entries));
}

// ─── Entry Point ──────────────────────────────────────────────────────────────

async function main() {
  const version = parseArgs();
  const baseUrl = process.env.API_BASE_URL ?? 'http://localhost:5000';

  if (version === null) {
    console.log(`Fetching httpd.apache.org/security/vulnerabilities_24.html...`);
    const html = await fetchApacheAdvisoryPage(SWEEP_VERSION);
    const advisories = parseApacheAdvisories(html);
    console.log(`Parsed ${advisories.length} advisory entries from httpd.apache.org`);
    await runSweep(baseUrl, advisories);
    return;
  }

  const branch = version.split('.').slice(0, 2).join('.');

  console.log(`Fetching httpd.apache.org/security/vulnerabilities_${branch.replace('.', '')}.html...`);
  const html = await fetchApacheAdvisoryPage(version);
  const advisories = parseApacheAdvisories(html);
  console.log(`Parsed ${advisories.length} advisory entries from httpd.apache.org`);

  const groundTruthCVEs = filterExpectedCVEs(version, advisories);
  console.log(`Ground truth for Apache httpd ${version}: ${groundTruthCVEs.size} CVEs should match`);

  console.log(`Querying local API at ${baseUrl}...`);
  const { cveIds, osvOnlyIds, allResults } = await queryLocalAPI(baseUrl, version);

  const result = compareResults(groundTruthCVEs, cveIds, version, osvOnlyIds);
  printReport(result, advisories, allResults);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
