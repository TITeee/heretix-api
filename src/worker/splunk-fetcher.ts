import axios from 'axios';
import type { AdvisoryFetcher, NormalizedAdvisory } from './advisory-fetcher.js';
import { logger } from '../utils/logger.js';

// https://advisory.splunk.com/advisories lists the full historical archive (300+
// advisories) in one big table (id="advisory-table-all"), with every field already
// structured as columns (CVE, CVSS vector/score, per-branch affected/fixed versions,
// description, solution, mitigations). A single request here supersedes the
// homepage/RSS feed (which only expose the ~40-50 most recent advisories).
const ARCHIVE_URL = 'https://advisory.splunk.com/advisories';

// ─── HTML Parsing ───────────────────────────────────────────────

function decodeEntities(s: string): string {
  return s
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#8220;|&#8221;|&ldquo;|&rdquo;/g, '"')
    .trim();
}

function stripTags(html: string): string {
  return decodeEntities(html.replace(/<br\s*\/?>/gi, '\n').replace(/<[^>]+>/g, ' ').replace(/[ \t]+/g, ' ')).trim();
}

/** Splits a `<br/>`-joined cell (used for the per-branch Affected Product /
 * Fixed Versions / Affected Versions columns) into one string per branch. */
function splitBr(cellHtml: string): string[] {
  return cellHtml.split(/<br\s*\/?>/i).map(stripTags).filter(s => s.length > 0);
}

/** Cell lookup by `label="X"` attribute, tolerant of attribute order (some
 * columns render `label` before `class`, others after). */
function extractCells(rowHtml: string): Record<string, string> {
  const cells: Record<string, string> = {};
  for (const m of rowHtml.matchAll(/<td[^>]*label="([^"]*)"[^>]*>([\s\S]*?)<\/td>/g)) {
    cells[m[1]] = m[2];
  }
  return cells;
}

export function parseAffectedVersion(text: string): { versionStart?: string; versionEnd?: string; lastAffected?: string } | null {
  const below = text.match(/^Below\s+([\d.]+)/i);
  if (below) return { versionEnd: below[1] };

  const range = text.match(/^([\d.]+)\s+to\s+([\d.]+)$/i);
  if (range) return { versionStart: range[1], lastAffected: range[2] };

  const earlier = text.match(/^([\d.]+)\s+and\s+earlier$/i);
  if (earlier) return { lastAffected: earlier[1] };

  return null;
}

/** "Splunk AI Toolkit 5.7" → "Splunk AI Toolkit" (strip the trailing branch version). */
function extractProductName(productAndBranch: string): string {
  const m = productAndBranch.match(/^(.*?)\s+[\d][\w.]*$/);
  return m ? m[1] : productAndBranch;
}

export function buildAffectedProducts(cells: Record<string, string>): NormalizedAdvisory['affectedProducts'] {
  const products = splitBr(cells['Affected Product'] ?? '');
  const fixedVersions = splitBr(cells['Fixed Versions'] ?? '');
  const affectedVersions = splitBr(cells['Affected Versions'] ?? '');

  // A small number of legacy rows have mismatched column lengths (best-effort:
  // only walk as far as all three arrays agree).
  const n = Math.min(products.length, fixedVersions.length, affectedVersions.length);

  const affectedProducts: NormalizedAdvisory['affectedProducts'] = [];
  for (let i = 0; i < n; i++) {
    const affectedText = affectedVersions[i];
    if (/^not affected$/i.test(affectedText)) continue;

    const product = extractProductName(products[i]);
    const fixedRaw = fixedVersions[i];
    const cleanFixed = fixedRaw && /^[\d][\w.]*$/.test(fixedRaw) ? fixedRaw : undefined;
    const spec = parseAffectedVersion(affectedText);

    if (spec) {
      const isRange = spec.versionStart !== undefined || spec.versionEnd !== undefined || spec.lastAffected !== undefined;
      affectedProducts.push({
        vendor: 'splunk',
        product,
        versionStart: spec.versionStart,
        versionEnd: spec.versionEnd,
        lastAffected: spec.lastAffected,
        // versionFixed must only accompany an actual range: importAdvisoryData()
        // falls back to versionFixed as the exclusive upper bound when versionEnd
        // is absent, which would turn an exact-version-only entry into an
        // unbounded range (the bug fixed for the Apache/Zabbix fetchers).
        versionFixed: isRange ? cleanFixed : undefined,
        patchAvailable: !!cleanFixed,
      });
    } else {
      // Unrecognized format (best-effort): keep raw version tokens found in the text
      const tokens = affectedText.match(/\d+(?:\.\d+)+/g) ?? [];
      if (tokens.length === 0) continue;
      affectedProducts.push({
        vendor: 'splunk',
        product,
        affectedVersions: tokens,
        versionFixed: undefined,
        patchAvailable: !!cleanFixed,
      });
    }
  }
  return affectedProducts;
}

function parseRow(rowHtml: string): NormalizedAdvisory | null {
  const cells = extractCells(rowHtml);

  const svdMatch = (cells['SVD'] ?? '').match(/SVD-\d{4}-\d+/);
  if (!svdMatch) return null;
  const externalId = svdMatch[0];

  const title = stripTags(cells['Title'] ?? '');
  if (!title) return null;

  const cveMatch = (cells['CVE'] ?? '').match(/CVE-\d{4}-\d+/);
  const cveId = cveMatch?.[0];

  const severityText = stripTags(cells['Severity'] ?? '');
  const severity = severityText && severityText.toUpperCase() !== 'NA' ? severityText.toUpperCase() : undefined;

  const cvssScoreText = stripTags(cells['CVSS Score'] ?? '');
  const cvssScore = cvssScoreText && cvssScoreText.toUpperCase() !== 'NA' ? parseFloat(cvssScoreText) : undefined;

  const cvssVectorText = stripTags(cells['CVSS Vector'] ?? '');
  const cvssVector = cvssVectorText && cvssVectorText.toUpperCase() !== 'NA' ? cvssVectorText : undefined;

  const publishedText = stripTags(cells['Date'] ?? '');
  const publishedAt = publishedText ? new Date(publishedText) : undefined;

  const description = stripTags(cells['Description'] ?? '') || undefined;
  const solution = stripTags(cells['Solution'] ?? '') || undefined;
  const workaround = stripTags(cells['Mitigations'] ?? '') || undefined;

  return {
    externalId,
    cveId,
    summary: title,
    description,
    severity,
    cvssScore: cvssScore !== undefined && !isNaN(cvssScore) ? cvssScore : undefined,
    cvssVector,
    url: `${ARCHIVE_URL}/${externalId}`,
    workaround,
    solution,
    publishedAt,
    affectedProducts: buildAffectedProducts(cells),
    rawData: cells,
  };
}

// ─── AdvisoryFetcher Implementation ──────────────────────────

export class SplunkFetcher implements AdvisoryFetcher {
  source(): string { return 'advisory-splunk'; }

  async fetch(): Promise<NormalizedAdvisory[]> {
    logger.info('Fetching Splunk security advisories archive');
    const { data: html } = await axios.get<string>(ARCHIVE_URL, {
      timeout: 60000,
      headers: { 'User-Agent': 'heretix-api/1.0' },
      responseType: 'text',
    });

    const tableMatch = html.match(/<table class="advisory-table-all" id="advisory-table-all">([\s\S]*?)<\/table>/);
    if (!tableMatch) {
      logger.error('Could not locate advisory-table-all in Splunk archive page');
      return [];
    }

    const rows = [...tableMatch[1].matchAll(/<tr class="advisory-tr">([\s\S]*?)<\/tr>/g)].map(m => m[1]);

    // Dedup by SVD ID: the archive page occasionally repeats a row (e.g. paginated
    // DataTables markup), and importAdvisoryData()'s upsert would just overwrite
    // duplicates anyway, but deduping here keeps the succeeded/skipped counts accurate.
    const bySvd = new Map<string, NormalizedAdvisory>();
    let skipped = 0;
    for (const rowHtml of rows) {
      const advisory = parseRow(rowHtml);
      if (!advisory) { skipped++; continue; }
      if (!bySvd.has(advisory.externalId)) bySvd.set(advisory.externalId, advisory);
    }

    const results = [...bySvd.values()];
    logger.info(
      { totalRows: rows.length, succeeded: results.length, skipped },
      'Splunk advisory fetch complete',
    );
    return results;
  }
}
