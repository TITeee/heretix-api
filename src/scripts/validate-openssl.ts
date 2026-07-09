/**
 * OpenSSL vulnerability search accuracy validation script
 *
 * Uses the official security advisories from openssl.org as Ground Truth,
 * compares them against local API search results, and measures Precision/Recall.
 *
 * Usage:
 *   pnpm validate:openssl 3.0.12
 *   pnpm validate:openssl 1.1.1w
 */
import 'dotenv/config';
import axios from 'axios';
import { normalizeVersion } from '../utils/version.js';

// ─── Type Definitions ────────────────────────────────────────────────────────

interface VulnerableRange {
  introduced: string;
  fixed: string;
}

interface OpenSSLAdvisory {
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

function parseArgs(): string {
  const [, , version] = process.argv;
  if (!version || !/^\d+\.\d+\.\d+/.test(version)) {
    console.error('Usage: pnpm validate:openssl <version>');
    console.error('Example: pnpm validate:openssl 3.0.12');
    process.exit(1);
  }
  return version;
}

// ─── Ground Truth Fetch & Parse ───────────────────────────────────────────────

async function fetchOpenSSLAdvisoryPage(): Promise<string> {
  const res = await axios.get<string>('https://www.openssl.org/news/vulnerabilities.html', {
    responseType: 'text',
    timeout: 15000,
    headers: { 'User-Agent': 'heretix-api/1.0 accuracy-validator' },
    maxRedirects: 5,
  });
  return res.data;
}

/**
 * Parse OpenSSL advisory entries from the vulnerabilities HTML page.
 *
 * Each entry has structure:
 *   <h3 id="CVE-YYYY-NNNN">CVE-YYYY-NNNN</h3>
 *   Severity: Low/Moderate/High/Critical
 *   Affected:
 *     <li>from 3.0.0 before 3.0.21</li>
 *     <li>from 1.1.1 before 1.1.1zh</li>
 */
function parseOpenSSLAdvisories(html: string): OpenSSLAdvisory[] {
  const advisories: OpenSSLAdvisory[] = [];

  // Split by CVE headings
  const blocks = html.split(/<h3\s+id="(CVE-\d{4}-\d+)">/);

  for (let i = 1; i < blocks.length; i += 2) {
    const cveId = blocks[i];
    const body = blocks[i + 1] ?? '';

    // Severity
    const sevMatch = body.match(/>Severity<\/span><\/div>\s*<div[^>]*>(\w+)/);
    const severity = sevMatch ? sevMatch[1].toLowerCase() : 'unknown';

    // Affected ranges: "from X before Y"
    const affectedSection = body.split(/font-semibold">Affected/)[1] ?? '';
    const rangeRe = /from\s+([\d.]+[a-z]*)\s+before\s+([\d.]+[a-z]*)/g;
    const ranges: VulnerableRange[] = [];
    let m: RegExpExecArray | null;
    while ((m = rangeRe.exec(affectedSection)) !== null) {
      ranges.push({ introduced: m[1], fixed: m[2] });
    }

    if (ranges.length > 0) {
      advisories.push({ cveId, severity, ranges });
    }
  }

  return advisories;
}

/**
 * OpenSSL uses letter suffixes for patch versions (e.g., 1.1.1w, 1.0.2zq).
 * Convert to a comparable numeric form:
 *   3.0.12 → use normalizeVersion directly
 *   1.1.1w → append letter index as patch component
 */
function openSSLVersionToInt(version: string): bigint | null {
  // Try standard numeric form first
  const standard = normalizeVersion(version);
  if (standard !== null) return standard;

  // Handle letter-suffix versions: 1.1.1w, 1.0.2zq
  const m = version.match(/^(\d+\.\d+\.\d+)([a-z]+)$/);
  if (!m) return null;

  const base = normalizeVersion(m[1]);
  if (base === null) return null;

  // Convert letter suffix to numeric offset: a=1, z=26, za=27, zz=52, ...
  const letters = m[2];
  let offset = 0;
  for (const ch of letters) {
    offset = offset * 26 + (ch.charCodeAt(0) - 96); // a=1
  }

  return base + BigInt(offset);
}

function filterExpectedCVEs(version: string, advisories: OpenSSLAdvisory[]): Set<string> {
  const versionInt = openSSLVersionToInt(version);
  if (versionInt === null) {
    console.error(`ERROR: Could not normalize version "${version}"`);
    process.exit(1);
  }

  const result = new Set<string>();

  for (const adv of advisories) {
    for (const range of adv.ranges) {
      const introducedInt = openSSLVersionToInt(range.introduced);
      const fixedInt = openSSLVersionToInt(range.fixed);
      if (introducedInt === null || fixedInt === null) continue;

      if (versionInt >= introducedInt && versionInt < fixedInt) {
        result.add(adv.cveId);
        break;
      }
    }
  }

  return result;
}

// ─── Local API Query ──────────────────────────────────────────────────────────

async function queryLocalAPI(
  baseUrl: string,
  version: string,
): Promise<{ cveIds: Set<string>; osvOnlyIds: string[]; allResults: ApiVulnerability[] }> {
  const url = `${baseUrl}/api/v1/vulnerabilities/search?package=openssl&version=${encodeURIComponent(version)}&limit=500`;
  const headers: Record<string, string> = {};
  if (process.env.API_KEY) headers['x-api-key'] = process.env.API_KEY;

  let allResults: ApiVulnerability[] = [];
  try {
    const res = await axios.get<{ results: ApiVulnerability[] }>(url, { timeout: 30000, headers });
    allResults = res.data.results ?? [];
  } catch (err: unknown) {
    if (axios.isAxiosError(err) && err.code === 'ECONNREFUSED') {
      console.error(`ERROR: Could not reach local API at ${baseUrl}`);
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

  return { version, groundTruthCVEs: gt, apiCVEs: api, truePositives, falsePositives, falseNegatives, osvOnlyIds, precision, recall, f1 };
}

function printReport(
  result: ComparisonResult,
  allAdvisories: OpenSSLAdvisory[],
  allApiResults: ApiVulnerability[],
): void {
  const pct = (n: number) => `${(n * 100).toFixed(2)}%`;
  const advMap = new Map(allAdvisories.map(a => [a.cveId.toUpperCase(), a]));
  const apiMap = new Map(allApiResults.map(r => [r.externalId.toUpperCase(), r]));

  console.log('');
  console.log('====================================================');
  console.log(`  OPENSSL ACCURACY VALIDATION — version ${result.version}`);
  console.log('====================================================');
  console.log('');
  console.log(`Ground truth (openssl.org):  ${result.groundTruthCVEs.size} CVEs affect ${result.version}`);
  console.log(`API results (CVE only):      ${result.apiCVEs.size} CVEs returned`);
  if (result.osvOnlyIds.length > 0) {
    console.log(`OSV-only IDs (excluded):     ${result.osvOnlyIds.length} (non-CVE, not compared)`);
  }
  console.log('');
  console.log(`  True  Positives (TP): ${result.truePositives.length}`);
  console.log(`  False Positives (FP): ${result.falsePositives.length}  ← returned by API but not in openssl.org advisories`);
  console.log(`  False Negatives (FN): ${result.falseNegatives.length}  ← in openssl.org advisories but missed by API`);
  console.log('');
  console.log(`  Precision : ${pct(result.precision)}  (TP / (TP+FP))`);
  console.log(`  Recall    : ${pct(result.recall)}  (TP / (TP+FN))`);
  console.log(`  F1 Score  : ${pct(result.f1)}`);

  if (result.falsePositives.length > 0) {
    console.log('');
    console.log('----------------------------------------------------');
    console.log('FALSE POSITIVES (over-detection):');
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
    console.log('FALSE NEGATIVES (misses):');
    for (const cve of result.falseNegatives) {
      const adv = advMap.get(cve);
      const sevStr = adv ? `[severity: ${adv.severity}]` : '';
      const rangeStr = adv ? adv.ranges.map(r => `${r.introduced}–${r.fixed}`).join(', ') : '';
      console.log(`  ${cve}   ${sevStr}  affected: ${rangeStr}`);
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

  console.log(`Fetching openssl.org security advisories...`);
  const html = await fetchOpenSSLAdvisoryPage();
  const advisories = parseOpenSSLAdvisories(html);
  console.log(`Parsed ${advisories.length} advisory entries from openssl.org`);

  const groundTruthCVEs = filterExpectedCVEs(version, advisories);
  console.log(`Ground truth for OpenSSL ${version}: ${groundTruthCVEs.size} CVEs should match`);

  console.log(`Querying local API at ${baseUrl}...`);
  const { cveIds, osvOnlyIds, allResults } = await queryLocalAPI(baseUrl, version);

  const result = compareResults(groundTruthCVEs, cveIds, version, osvOnlyIds);
  printReport(result, advisories, allResults);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
