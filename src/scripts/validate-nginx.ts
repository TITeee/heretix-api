/**
 * nginx vulnerability search accuracy validation script
 *
 * Uses the official security advisories from nginx.org as Ground Truth,
 * compares them against local API search results, and measures Precision/Recall.
 *
 * Usage:
 *   pnpm validate:nginx 1.24.0
 *   API_BASE_URL=http://localhost:3001 pnpm validate:nginx 1.24.0
 */
import 'dotenv/config';
import axios from 'axios';
import { normalizeVersion } from '../utils/version.js';

// ─── Type Definitions ────────────────────────────────────────────────────────

interface VulnerableRange {
  introduced: string;
  lastAffected: string | null; // inclusive upper bound (nginx.org notation)
  fixed: string | null;        // exclusive upper bound (inferred from NVD notation)
}

interface NginxAdvisory {
  cveId: string;
  title: string;
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

function parseArgs(): string {
  const [, , version] = process.argv;
  if (!version || !/^\d+\.\d+\.\d+$/.test(version)) {
    console.error('Usage: pnpm validate:nginx <version>');
    console.error('Example: pnpm validate:nginx 1.24.0');
    process.exit(1);
  }
  return version;
}

// ─── Ground Truth Fetch & Parse ───────────────────────────────────────────────

async function fetchNginxAdvisoryPage(): Promise<string> {
  const res = await axios.get<string>('https://nginx.org/en/security_advisories.html', {
    responseType: 'text',
    timeout: 15000,
    headers: { 'User-Agent': 'heretix-api/1.0 accuracy-validator' },
  });
  return res.data;
}

/**
 * Parse the text of a "Vulnerable:" line into VulnerableRange[].
 *
 * nginx.org notation examples:
 *   "1.3.0-1.29.4"                  → { introduced:"1.3.0", lastAffected:"1.29.4" }
 *   "0.6.18-1.25.2, 1.21.0-1.25.1" → 2 entries
 *   "1.5.10"                        → { introduced:"1.5.10", lastAffected:"1.5.10" }
 *
 * The upper bound is inclusive (the last version listed on the nginx.org page is included).
 * Stored as lastAffected; fixed is not set.
 */
function parseVulnerableText(text: string): VulnerableRange[] {
  const ranges: VulnerableRange[] = [];

  // Handle multiple comma-separated ranges
  const parts = text.split(',').map(s => s.trim()).filter(Boolean);

  for (const part of parts) {
    // Either a hyphen-separated range "A-B" or a single version "A"
    const hyphen = part.indexOf('-');
    if (hyphen > 0) {
      // "1.3.0-1.29.4" format
      // Versions always start with a digit; account for possible multiple hyphens
      // by finding the break at the first "X.Y.Z-" pattern
      const introduced = part.slice(0, hyphen).trim();
      const lastAffected = part.slice(hyphen + 1).trim();
      if (/^\d+\.\d+/.test(introduced) && /^\d+\.\d+/.test(lastAffected)) {
        ranges.push({ introduced, lastAffected, fixed: null });
        continue;
      }
    }
    // Single version
    if (/^\d+\.\d+/.test(part)) {
      ranges.push({ introduced: part, lastAffected: part, fixed: null });
    }
  }

  return ranges;
}

/**
 * Parse NginxAdvisory[] from the HTML of nginx.org.
 * Old entries without a CVE ID are skipped.
 */
function parseNginxAdvisories(html: string): NginxAdvisory[] {
  const advisories: NginxAdvisory[] = [];

  // Split into <li> blocks (each block ends at </li>)
  const blocks = html.split(/<\/li>/i);

  for (const block of blocks) {
    // Extract all CVE IDs
    const cveMatches = [...block.matchAll(/CVE-\d{4}-\d+/g)];
    if (cveMatches.length === 0) continue;

    // Extract the "Vulnerable:" line (strip "Not vulnerable:" first to avoid false matches)
    const withoutNotVuln = block.replace(/Not vulnerable:[^\n<]*/gi, '');
    const vulnMatch = withoutNotVuln.match(/Vulnerable:\s*([^\n<]+)/i);
    if (!vulnMatch) continue;

    const vulnText = vulnMatch[1].trim();
    const ranges = parseVulnerableText(vulnText);
    if (ranges.length === 0) continue;

    // Title (text of the first <a> element)
    const titleMatch = block.match(/<a[^>]*>([^<]+)<\/a>/);
    const title = titleMatch ? titleMatch[1].trim() : '';

    // Severity
    const sevMatch = block.match(/Severity:\s*(\w+)/i);
    const severity = sevMatch ? sevMatch[1].toLowerCase() : 'unknown';

    // When multiple CVEs share the same block, generate one entry per CVE with the same ranges
    for (const cveMatch of cveMatches) {
      advisories.push({
        cveId: cveMatch[0],
        title,
        severity,
        ranges,
      });
    }
  }

  return advisories;
}

/**
 * Return the set of CVE IDs that apply to the specified version.
 * Applies the same BigInt comparison logic as versionRangeWhere() in the DB.
 */
function filterExpectedCVEs(version: string, advisories: NginxAdvisory[]): Set<string> {
  const versionInt = normalizeVersion(version);
  if (versionInt === null) {
    console.error(`ERROR: Could not normalize version "${version}" to BigInt`);
    process.exit(1);
  }

  const result = new Set<string>();

  for (const adv of advisories) {
    for (const range of adv.ranges) {
      const introducedInt = normalizeVersion(range.introduced);
      if (introducedInt === null) continue;
      if (versionInt < introducedInt) continue;

      if (range.lastAffected !== null) {
        const lastInt = normalizeVersion(range.lastAffected);
        if (lastInt !== null && versionInt > lastInt) continue;
      }

      // fixed (exclusive) upper bound check
      if (range.fixed !== null) {
        const fixedInt = normalizeVersion(range.fixed);
        if (fixedInt !== null && versionInt >= fixedInt) continue;
      }

      result.add(adv.cveId);
      break; // matched one range — move on to the next CVE
    }
  }

  return result;
}

// ─── Local API Query ──────────────────────────────────────────────────────────

async function querySearchEndpoint(baseUrl: string, version: string): Promise<ApiVulnerability[]> {
  const url = `${baseUrl}/api/v1/vulnerabilities/search?package=nginx&version=${encodeURIComponent(version)}&limit=500`;
  const res = await axios.get<{ results: ApiVulnerability[] }>(url, { timeout: 30000 });
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
    } else if (!r.externalId.startsWith('CVE-')) {
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
  // Normalize to uppercase
  const gt = new Set([...groundTruthCVEs].map(c => c.toUpperCase()));
  const api = new Set([...apiCVEs].map(c => c.toUpperCase()));

  const truePositives = [...gt].filter(c => api.has(c)).sort();
  const falsePositives = [...api].filter(c => !gt.has(c)).sort();
  const falseNegatives = [...gt].filter(c => !api.has(c)).sort();

  const tp = truePositives.length;
  const fp = falsePositives.length;
  const fn = falseNegatives.length;

  const precision = tp + fp > 0 ? tp / (tp + fp) : 1;
  const recall    = tp + fn > 0 ? tp / (tp + fn) : 1;
  const f1        = precision + recall > 0 ? 2 * (precision * recall) / (precision + recall) : 0;

  return {
    version,
    groundTruthCVEs: gt,
    apiCVEs: api,
    truePositives,
    falsePositives,
    falseNegatives,
    osvOnlyIds,
    precision,
    recall,
    f1,
  };
}

function printReport(
  result: ComparisonResult,
  allAdvisories: NginxAdvisory[],
  allApiResults: ApiVulnerability[],
): void {
  const pct = (n: number) => `${(n * 100).toFixed(2)}%`;
  const advMap = new Map(allAdvisories.map(a => [a.cveId.toUpperCase(), a]));
  const apiMap = new Map(allApiResults.map(r => [r.externalId.toUpperCase(), r]));

  console.log('');
  console.log('====================================================');
  console.log(`  NGINX ACCURACY VALIDATION — version ${result.version}`);
  console.log('====================================================');
  console.log('');
  console.log(`Ground truth (nginx.org):  ${result.groundTruthCVEs.size} CVEs affect ${result.version}`);
  console.log(`API results (CVE only):    ${result.apiCVEs.size} CVEs returned`);
  if (result.osvOnlyIds.length > 0) {
    console.log(`OSV-only IDs (excluded):   ${result.osvOnlyIds.length} (non-CVE, not compared)`);
  }
  console.log('');
  console.log(`  True  Positives (TP): ${result.truePositives.length}`);
  console.log(`  False Positives (FP): ${result.falsePositives.length}  ← returned by API but not in nginx.org advisories`);
  console.log(`  False Negatives (FN): ${result.falseNegatives.length}  ← in nginx.org advisories but missed by API`);
  console.log('');
  console.log(`  Precision : ${pct(result.precision)}  (TP / (TP+FP))`);
  console.log(`  Recall    : ${pct(result.recall)}  (TP / (TP+FN))`);
  console.log(`  F1 Score  : ${pct(result.f1)}`);

  if (result.falsePositives.length > 0) {
    console.log('');
    console.log('----------------------------------------------------');
    console.log('FALSE POSITIVES (over-detection — returned by API but not in nginx.org advisories):');
    for (const cve of result.falsePositives) {
      const api = apiMap.get(cve);
      const srcStr = api ? `[sources: ${api.sources.join(', ')}]` : '';
      const approx = api?.approximateMatch ? ' [approximateMatch]' : '';
      console.log(`  ${cve}   ${srcStr}${approx}`);
    }
  }

  if (result.falseNegatives.length > 0) {
    console.log('');
    console.log('----------------------------------------------------');
    console.log('FALSE NEGATIVES (misses — in nginx.org advisories but not returned by API):');
    for (const cve of result.falseNegatives) {
      const adv = advMap.get(cve);
      const sevStr = adv ? `[severity: ${adv.severity}]` : '';
      const rangeStr = adv ? adv.ranges.map(r => `${r.introduced}-${r.lastAffected ?? '?'}`).join(', ') : '';
      console.log(`  ${cve}   ${sevStr}  vulnerable: ${rangeStr}`);
    }
  }

  if (result.truePositives.length > 0) {
    console.log('');
    console.log('----------------------------------------------------');
    const preview = result.truePositives.slice(0, 5).join(', ');
    const rest = result.truePositives.length > 5 ? ` ... (+${result.truePositives.length - 5} more)` : '';
    console.log(`TRUE POSITIVES (${result.truePositives.length} CVEs correctly matched):`);
    console.log(`  ${preview}${rest}`);
  }

  console.log('====================================================');
  console.log('');
}

// ─── Entry Point ──────────────────────────────────────────────────────────────

async function main() {
  const version = parseArgs();
  const baseUrl = process.env.API_BASE_URL ?? 'http://localhost:5000';

  console.log(`Fetching nginx.org security advisories...`);
  const html = await fetchNginxAdvisoryPage();
  const advisories = parseNginxAdvisories(html);
  console.log(`Parsed ${advisories.length} advisory entries from nginx.org`);

  const groundTruthCVEs = filterExpectedCVEs(version, advisories);
  console.log(`Ground truth for nginx ${version}: ${groundTruthCVEs.size} CVEs should match`);

  console.log(`Querying local API at ${baseUrl}...`);
  const { cveIds, osvOnlyIds, allResults } = await queryLocalAPI(baseUrl, version);

  const result = compareResults(groundTruthCVEs, cveIds, version, osvOnlyIds);
  printReport(result, advisories, allResults);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
