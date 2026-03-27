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

// ─── Type Definitions ────────────────────────────────────────────────────────

interface VulnerableRange {
  introduced: string | null;  // null = all versions (no lower bound)
  fixed: string | null;       // exclusive upper bound ("before X")
  lastAffected: string | null; // inclusive upper bound ("through X")
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

function parseArgs(): string {
  const [, , version] = process.argv;
  if (!version || !/^\d+\.\d+\.\d+/.test(version)) {
    console.error('Usage: pnpm validate:apache <version>');
    console.error('Example: pnpm validate:apache 2.4.62');
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
 * Parse the text of an "Affects" section into VulnerableRange[].
 *
 * Apache httpd advisory notation examples:
 *   "2.4.30 before 2.4.66"      → { introduced:"2.4.30", fixed:"2.4.66" }       ← exclusive
 *   "from 2.4.30 before 2.4.66" → same as above
 *   "2.4.0 through 2.4.63"      → { introduced:"2.4.0", lastAffected:"2.4.63" } ← inclusive
 *   "before 2.4.66"             → { introduced:null, fixed:"2.4.66" }           ← no lower bound
 */
function parseAffectsText(raw: string): VulnerableRange[] {
  const text = raw.trim();

  // "X.Y.Z before A.B.C" or "from X.Y.Z before A.B.C"
  const beforeMatch = text.match(/(?:from\s+)?([\d.]+)\s+before\s+([\d.]+)/i);
  if (beforeMatch) {
    return [{ introduced: beforeMatch[1], fixed: beforeMatch[2], lastAffected: null }];
  }

  // "X.Y.Z through A.B.C"
  const throughMatch = text.match(/([\d.]+)\s+through\s+([\d.]+)/i);
  if (throughMatch) {
    return [{ introduced: throughMatch[1], fixed: null, lastAffected: throughMatch[2] }];
  }

  // "before A.B.C" (no lower bound)
  const onlyBeforeMatch = text.match(/^before\s+([\d.]+)/i);
  if (onlyBeforeMatch) {
    return [{ introduced: null, fixed: onlyBeforeMatch[1], lastAffected: null }];
  }

  return [];
}

/**
 * Parse ApacheAdvisory[] from the HTML of httpd.apache.org.
 *
 * Each advisory contains exactly one "Affects" text.
 * The segment between consecutive "Affects" occurrences is treated as one advisory block.
 *
 * CVE IDs are extracted from <h3> heading lines only.
 * References to other CVEs in description text (e.g., "This was described as CVE-XXXX but...")
 * appear inside <p> tags and are excluded by restricting extraction to headings.
 */
function parseApacheAdvisories(html: string): ApacheAdvisory[] {
  // Collect all occurrences of "Affects" (including <dt>Affects</dt> etc.)
  const affectsRegex = /Affects(?:<[^>]+>|\s)+([\d.][^<\n]*)/gi;
  const hits: Array<{ index: number; text: string }> = [];
  let m: RegExpExecArray | null;
  while ((m = affectsRegex.exec(html)) !== null) {
    hits.push({ index: m.index, text: m[1].trim() });
  }

  const advisories: ApacheAdvisory[] = [];

  for (let i = 0; i < hits.length; i++) {
    const { index, text } = hits[i];
    const ranges = parseAffectsText(text);
    if (ranges.length === 0) continue;

    // The segment from the previous Affects to the current one is one advisory block
    const prevIndex = i > 0 ? hits[i - 1].index : 0;
    const segment = html.slice(prevIndex, index);

    // Extract CVE IDs from <h3> heading lines only
    // (prevents incorrectly associating references to other CVEs that appear in description text)
    const headingCVEs: string[] = [];
    for (const hm of segment.matchAll(/<h3[^>]*>[\s\S]*?<\/h3>/gi)) {
      for (const cm of hm[0].matchAll(/CVE-\d{4}-\d+/g)) {
        headingCVEs.push(cm[0]);
      }
    }
    if (headingCVEs.length === 0) continue;

    // Severity is embedded in the leading text of <h3> (critical / important / moderate / low)
    const headingText = segment.match(/<h3[^>]*>([\s\S]*?)<\/h3>/i)?.[1] ?? '';
    const sevMatch = headingText.match(/\b(critical|important|moderate|low)\b/i);
    const severity = sevMatch ? sevMatch[1].toLowerCase() : 'unknown';

    for (const cveId of headingCVEs) {
      advisories.push({ cveId, severity, ranges });
    }
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

// ─── Entry Point ──────────────────────────────────────────────────────────────

async function main() {
  const version = parseArgs();
  const baseUrl = process.env.API_BASE_URL ?? 'http://localhost:5000';
  const branch  = version.split('.').slice(0, 2).join('.');

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
