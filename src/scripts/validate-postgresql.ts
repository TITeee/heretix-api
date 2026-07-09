/**
 * PostgreSQL vulnerability search accuracy validation script
 *
 * Uses the official security page from postgresql.org as Ground Truth,
 * compares them against local API search results, and measures Precision/Recall.
 *
 * Usage:
 *   pnpm validate:postgresql 16.4
 *   pnpm validate:postgresql 15.8
 */
import 'dotenv/config';
import axios from 'axios';
import { normalizeVersion } from '../utils/version.js';

// ─── Type Definitions ────────────────────────────────────────────────────────

interface PostgreSQLAdvisory {
  cveId: string;
  affectedMajors: number[];
  fixedVersions: string[];
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
  if (!version || !/^\d+\.\d+/.test(version)) {
    console.error('Usage: pnpm validate:postgresql <version>');
    console.error('Example: pnpm validate:postgresql 16.4');
    process.exit(1);
  }
  return version;
}

// ─── Ground Truth Fetch & Parse ───────────────────────────────────────────────

async function fetchPostgreSQLSecurityPage(): Promise<string> {
  const res = await axios.get<string>('https://www.postgresql.org/support/security/', {
    responseType: 'text',
    timeout: 15000,
    headers: { 'User-Agent': 'heretix-api/1.0 accuracy-validator' },
  });
  return res.data;
}

/**
 * Parse PostgreSQL advisories from the security page HTML.
 *
 * Table structure:
 *   <tr>
 *     <td><a href="...">CVE-YYYY-NNNN</a></td>
 *     <td>18, 17, 16</td>           ← affected major versions
 *     <td>18.4, 17.10, 16.14</td>   ← fixed versions
 *     <td>component</td>
 *     <td>description</td>
 *   </tr>
 */
function parsePostgreSQLAdvisories(html: string): PostgreSQLAdvisory[] {
  const advisories: PostgreSQLAdvisory[] = [];

  const rowRe = /<tr>\s*<td>\s*<span[^>]*><a[^>]*>(CVE-\d{4}-\d+)<\/a><\/span>[\s\S]*?<\/tr>/g;
  let m: RegExpExecArray | null;

  while ((m = rowRe.exec(html)) !== null) {
    const cveId = m[1];
    const rowHtml = m[0];

    // Extract all <td> contents
    const tds: string[] = [];
    const tdRe = /<td[^>]*>([\s\S]*?)<\/td>/g;
    let tdMatch: RegExpExecArray | null;
    while ((tdMatch = tdRe.exec(rowHtml)) !== null) {
      tds.push(tdMatch[1].replace(/<[^>]+>/g, '').trim());
    }

    // tds[1] = affected majors: "18, 17, 16"
    // tds[2] = fixed versions: "18.4, 17.10, 16.14"
    if (tds.length < 3) continue;

    const affectedMajors = tds[1].split(',')
      .map(s => parseInt(s.trim(), 10))
      .filter(n => !isNaN(n));

    const fixedVersions = tds[2].split(',')
      .map(s => s.trim())
      .filter(s => /^\d+\.\d+/.test(s));

    if (affectedMajors.length > 0) {
      advisories.push({ cveId, affectedMajors, fixedVersions });
    }
  }

  return advisories;
}

/**
 * Return the set of CVE IDs that apply to the specified version.
 *
 * A CVE affects a version if:
 *   1. The version's major is in affectedMajors
 *   2. The version is less than the corresponding fixedVersion for that major
 */
function filterExpectedCVEs(version: string, advisories: PostgreSQLAdvisory[]): Set<string> {
  const versionInt = normalizeVersion(version);
  const major = parseInt(version.split('.')[0], 10);

  if (versionInt === null || isNaN(major)) {
    console.error(`ERROR: Could not normalize version "${version}"`);
    process.exit(1);
  }

  const result = new Set<string>();

  for (const adv of advisories) {
    if (!adv.affectedMajors.includes(major)) continue;

    // Find the fixed version for this major
    const fixedForMajor = adv.fixedVersions.find(fv => {
      const fvMajor = parseInt(fv.split('.')[0], 10);
      return fvMajor === major;
    });

    if (fixedForMajor) {
      const fixedInt = normalizeVersion(fixedForMajor);
      if (fixedInt !== null && versionInt < fixedInt) {
        result.add(adv.cveId);
      }
    } else {
      // Major is listed as affected but no fixed version → still affected
      result.add(adv.cveId);
    }
  }

  return result;
}

// ─── Local API Query ──────────────────────────────────────────────────────────

async function queryLocalAPI(
  baseUrl: string,
  version: string,
): Promise<{ cveIds: Set<string>; osvOnlyIds: string[]; allResults: ApiVulnerability[] }> {
  const url = `${baseUrl}/api/v1/vulnerabilities/search?package=postgresql&version=${encodeURIComponent(version)}&limit=500`;
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
  allAdvisories: PostgreSQLAdvisory[],
  allApiResults: ApiVulnerability[],
): void {
  const pct = (n: number) => `${(n * 100).toFixed(2)}%`;
  const advMap = new Map(allAdvisories.map(a => [a.cveId.toUpperCase(), a]));
  const apiMap = new Map(allApiResults.map(r => [r.externalId.toUpperCase(), r]));

  console.log('');
  console.log('====================================================');
  console.log(`  POSTGRESQL ACCURACY VALIDATION — version ${result.version}`);
  console.log('====================================================');
  console.log('');
  console.log(`Ground truth (postgresql.org):  ${result.groundTruthCVEs.size} CVEs affect ${result.version}`);
  console.log(`API results (CVE only):         ${result.apiCVEs.size} CVEs returned`);
  if (result.osvOnlyIds.length > 0) {
    console.log(`OSV-only IDs (excluded):        ${result.osvOnlyIds.length} (non-CVE, not compared)`);
  }
  console.log('');
  console.log(`  True  Positives (TP): ${result.truePositives.length}`);
  console.log(`  False Positives (FP): ${result.falsePositives.length}  ← returned by API but not in postgresql.org advisories`);
  console.log(`  False Negatives (FN): ${result.falseNegatives.length}  ← in postgresql.org advisories but missed by API`);
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
      const majors = adv ? `affected: ${adv.affectedMajors.join(', ')}` : '';
      const fixed = adv ? `fixed: ${adv.fixedVersions.join(', ')}` : '';
      console.log(`  ${cve}   ${majors}  ${fixed}`);
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

  console.log(`Fetching postgresql.org security advisories...`);
  const html = await fetchPostgreSQLSecurityPage();
  const advisories = parsePostgreSQLAdvisories(html);
  console.log(`Parsed ${advisories.length} advisory entries from postgresql.org`);

  const groundTruthCVEs = filterExpectedCVEs(version, advisories);
  console.log(`Ground truth for PostgreSQL ${version}: ${groundTruthCVEs.size} CVEs should match`);

  console.log(`Querying local API at ${baseUrl}...`);
  const { cveIds, osvOnlyIds, allResults } = await queryLocalAPI(baseUrl, version);

  const result = compareResults(groundTruthCVEs, cveIds, version, osvOnlyIds);
  printReport(result, advisories, allResults);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
