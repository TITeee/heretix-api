/**
 * Apache Tomcat vulnerability search accuracy validation script
 *
 * Uses the official security advisories from tomcat.apache.org as Ground Truth,
 * compares them against local API search results, and measures Precision/Recall.
 * Automatically selects the target page (security-9.html / security-10.html, etc.)
 * based on the major version number.
 *
 * Usage:
 *   pnpm validate:tomcat 9.0.100
 *   pnpm validate:tomcat 10.1.47
 *   API_BASE_URL=http://localhost:5000 pnpm validate:tomcat 9.0.50
 */
import 'dotenv/config';
import axios from 'axios';
import { normalizeVersion } from '../utils/version.js';

// ─── Type Definitions ────────────────────────────────────────────────────────

interface VulnerableRange {
  introduced: string;
  lastAffected: string; // inclusive upper bound (the Y in "Affects: X to Y")
}

interface TomcatAdvisory {
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
    console.error('Usage: pnpm validate:tomcat <version>');
    console.error('Example: pnpm validate:tomcat 9.0.100');
    process.exit(1);
  }
  return version;
}

// ─── Ground Truth Fetch & Parse ───────────────────────────────────────────────

async function fetchTomcatAdvisoryPage(majorVersion: number): Promise<string> {
  const url = `https://tomcat.apache.org/security-${majorVersion}.html`;
  const res = await axios.get<string>(url, {
    responseType: 'text',
    timeout: 15000,
    headers: { 'User-Agent': 'heretix-api/1.0 accuracy-validator' },
  });
  return res.data;
}

/**
 * Parse the text of an "Affects:" line into VulnerableRange[].
 *
 * Tomcat advisory notation examples:
 *   "9.0.0.M1 to 9.0.105"   → { introduced:"9.0.0.M1", lastAffected:"9.0.105" }
 *   "9.0.71 to 9.0.73"      → { introduced:"9.0.71",   lastAffected:"9.0.73"  }
 *   "9.0.0.M1"              → { introduced:"9.0.0.M1", lastAffected:"9.0.0.M1" }
 *
 * The upper bound is inclusive (the version on the right side of "to" is included).
 * Milestone versions (9.0.0.M1) are treated as 9.0.0 equivalent by normalizeVersion.
 */
function parseAffectsText(raw: string): VulnerableRange[] {
  // Strip "Apache Tomcat " prefix if present
  const text = raw.replace(/^Apache\s+Tomcat\s+/i, '').trim();

  // "X to Y" format (includes hyphens in milestone versions like "10.1.0-M1")
  const rangeMatch = text.match(/^([\d.A-Za-z-]+)\s+to\s+([\d.A-Za-z-]+)/i);
  if (rangeMatch) {
    const [, introduced, lastAffected] = rangeMatch;
    if (/^\d+\.\d+/.test(introduced) && /^\d+\.\d+/.test(lastAffected)) {
      return [{ introduced, lastAffected }];
    }
  }

  // Single version
  const singleMatch = text.match(/^([\d.A-Za-z-]+)/);
  if (singleMatch && /^\d+\.\d+/.test(singleMatch[1])) {
    return [{ introduced: singleMatch[1], lastAffected: singleMatch[1] }];
  }

  return [];
}

/**
 * Parse TomcatAdvisory[] from the HTML of tomcat.apache.org/security-9.html.
 *
 * Each advisory on the page has exactly one "Affects:" text.
 * The segment between consecutive "Affects:" occurrences is treated as one advisory block.
 *
 * CVE IDs are extracted only from the heading area (<strong>Severity: Title</strong> <a>CVE-XXXX</a>).
 * References to other CVEs in description paragraphs (e.g., "The fix for CVE-YYYY was incomplete")
 * appear in paragraphs after the heading, so restricting extraction to the heading prevents false matches.
 */
function parseTomcatAdvisories(html: string): TomcatAdvisory[] {
  // Collect all occurrences of "Affects:"
  const affectsRegex = /Affects:\s*([^\n<]+)/gi;
  const hits: Array<{ index: number; text: string }> = [];
  let m: RegExpExecArray | null;
  while ((m = affectsRegex.exec(html)) !== null) {
    hits.push({ index: m.index, text: m[1].trim() });
  }

  const advisories: TomcatAdvisory[] = [];

  for (let i = 0; i < hits.length; i++) {
    const { index, text } = hits[i];
    const ranges = parseAffectsText(text);
    if (ranges.length === 0) continue;

    // The segment from the previous Affects: to the current one is one advisory block
    const prevIndex = i > 0 ? hits[i - 1].index : 0;
    const segment = html.slice(prevIndex, index);

    // Extract CVEs from the heading area only (<strong>...</strong> through the next </p>).
    // Tomcat structure: <p><strong>Severity: Title</strong> <a href="...">CVE-XXXX</a></p>
    // CVE references in description <p> tags are not in this area, preventing false matches.
    const headingArea = segment.match(/<strong>[\s\S]*?<\/strong>[\s\S]*?(?=<\/p>|<p\b)/i)?.[0] ?? '';
    const titleCVEs = [...headingArea.matchAll(/CVE-\d{4}-\d+/g)].map(m => m[0]);
    if (titleCVEs.length === 0) continue;

    const sevMatch = headingArea.match(/\b(Critical|Important|Moderate|Low)\b/i);
    const severity = sevMatch ? sevMatch[1].toLowerCase() : 'unknown';

    for (const cveId of titleCVEs) {
      advisories.push({ cveId, severity, ranges });
    }
  }

  return advisories;
}

/**
 * Return the set of CVE IDs that apply to the specified version.
 * Applies the same BigInt comparison logic as versionRangeWhere() in the DB.
 */
function filterExpectedCVEs(version: string, advisories: TomcatAdvisory[]): Set<string> {
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

      const lastInt = normalizeVersion(range.lastAffected);
      if (lastInt !== null && versionInt > lastInt) continue;

      result.add(adv.cveId);
      break;
    }
  }

  return result;
}

// ─── Local API Query ──────────────────────────────────────────────────────────

async function querySearchEndpoint(baseUrl: string, version: string): Promise<ApiVulnerability[]> {
  const url = `${baseUrl}/api/v1/vulnerabilities/search?package=tomcat&version=${encodeURIComponent(version)}&limit=500`;
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
  allAdvisories: TomcatAdvisory[],
  allApiResults: ApiVulnerability[],
): void {
  const pct    = (n: number) => `${(n * 100).toFixed(2)}%`;
  const advMap = new Map(allAdvisories.map(a => [a.cveId.toUpperCase(), a]));
  const apiMap = new Map(allApiResults.map(r => [r.externalId.toUpperCase(), r]));

  console.log('');
  console.log('====================================================');
  const major = result.version.split('.')[0];
  console.log(`  TOMCAT ${major} ACCURACY VALIDATION — version ${result.version}`);
  console.log('====================================================');
  console.log('');
  console.log(`Ground truth (tomcat.apache.org): ${result.groundTruthCVEs.size} CVEs affect ${result.version}`);
  console.log(`API results (CVE only):           ${result.apiCVEs.size} CVEs returned`);
  if (result.osvOnlyIds.length > 0) {
    console.log(`OSV-only IDs (excluded):          ${result.osvOnlyIds.length} (non-CVE, not compared)`);
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
      const api   = apiMap.get(cve);
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
      const adv     = advMap.get(cve);
      const sevStr  = adv ? `[severity: ${adv.severity}]` : '';
      const rangeStr = adv ? adv.ranges.map(r => `${r.introduced}-${r.lastAffected}`).join(', ') : '';
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

// ─── Entry Point ──────────────────────────────────────────────────────────────

async function main() {
  const version = parseArgs();
  const baseUrl = process.env.API_BASE_URL ?? 'http://localhost:5000';
  const majorVersion = parseInt(version.split('.')[0], 10);

  console.log(`Fetching tomcat.apache.org/security-${majorVersion}.html...`);
  const html = await fetchTomcatAdvisoryPage(majorVersion);
  const advisories = parseTomcatAdvisories(html);
  console.log(`Parsed ${advisories.length} advisory entries from tomcat.apache.org`);

  const groundTruthCVEs = filterExpectedCVEs(version, advisories);
  console.log(`Ground truth for Tomcat ${majorVersion} ${version}: ${groundTruthCVEs.size} CVEs should match`);

  console.log(`Querying local API at ${baseUrl}...`);
  const { cveIds, osvOnlyIds, allResults } = await queryLocalAPI(baseUrl, version);

  const result = compareResults(groundTruthCVEs, cveIds, version, osvOnlyIds);
  printReport(result, advisories, allResults);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
