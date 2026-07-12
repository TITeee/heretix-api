import axios from 'axios';
import { XMLParser } from 'fast-xml-parser';
import type { AdvisoryFetcher, NormalizedAdvisory } from './advisory-fetcher.js';
import { logger } from '../utils/logger.js';

const RSS_URL = 'https://advisory.splunk.com/feed.xml';
const CDX_URL = 'http://web.archive.org/cdx/search/cdx';
const DETAIL_BASE = 'https://advisory.splunk.com/advisories';

// ─── ID Discovery ───────────────────────────────────────────────

/**
 * Splunk's site only lists the most recent ~40-50 advisories (homepage table
 * and RSS feed); there is no archive/pagination for older ones. The Wayback
 * Machine CDX API is used to discover the full historical set of advisory
 * IDs that have ever been published, so this fetcher can backfill the
 * complete history (250+ advisories back to 2022) in addition to picking up
 * new/recently-updated ones via RSS.
 */
async function discoverIdsFromWayback(): Promise<string[]> {
  try {
    const { data } = await axios.get<string>(CDX_URL, {
      params: {
        url: 'advisory.splunk.com/advisories/*',
        output: 'json',
        fl: 'original',
        collapse: 'urlkey',
        limit: 100000,
      },
      timeout: 30000,
      headers: { 'User-Agent': 'heretix-api/1.0' },
      responseType: 'json',
    });
    const rows: string[][] = Array.isArray(data) ? (data as unknown as string[][]) : [];
    const ids = new Set<string>();
    for (const row of rows) {
      const url = row[0];
      if (!url) continue;
      const m = url.match(/SVD-\d{4}-\d+/);
      if (m) ids.add(m[0]);
    }
    return [...ids];
  } catch (err) {
    logger.warn({ err }, 'Wayback CDX lookup failed; continuing with RSS-only discovery');
    return [];
  }
}

async function discoverIdsFromRss(): Promise<string[]> {
  const { data } = await axios.get<string>(RSS_URL, {
    timeout: 30000,
    headers: { 'User-Agent': 'heretix-api/1.0' },
    responseType: 'text',
  });
  const parser = new XMLParser({ ignoreAttributes: false });
  const parsed = parser.parse(data);
  const items = parsed?.rss?.channel?.item ?? [];
  const list = Array.isArray(items) ? items : [items];

  const ids = new Set<string>();
  for (const item of list) {
    const m = String(item?.title ?? '').match(/SVD-\d{4}-\d+/);
    if (m) ids.add(m[0]);
  }
  return [...ids];
}

// ─── Detail Page Parsing ────────────────────────────────────────

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
  return decodeEntities(html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' '));
}

function extractSection(html: string, id: string): string | undefined {
  const re = new RegExp(`<h2 id="${id}">[^<]*</h2>([\\s\\S]*?)(?=<h2 |$)`);
  const m = html.match(re);
  if (!m) return undefined;
  const text = stripTags(m[1]);
  return text.length > 0 ? text : undefined;
}

interface AffectedRow {
  product?: string;
  affectedVersion?: string;
  fixVersion?: string;
}

function parseProductTable(html: string): AffectedRow[] | null {
  const tableMatch = html.match(/<table class="advisory-table"[^>]*>([\s\S]*?)<\/table>/);
  if (!tableMatch) return null;
  const table = tableMatch[1];

  const headers = [...table.matchAll(/<th>([^<]*)<\/th>/g)].map(m => decodeEntities(m[1]));
  const isVersionTable = headers.includes('Product') && headers.includes('Affected Version') && headers.includes('Fix Version');
  if (!isVersionTable) return null; // e.g. bulk "Package / Remediation / CVE / Severity" third-party advisories

  const rows: AffectedRow[] = [];
  for (const rowMatch of table.matchAll(/<tr class="advisory-tr">([\s\S]*?)<\/tr>/g)) {
    const cells = new Map<string, string>();
    for (const cellMatch of rowMatch[1].matchAll(/<td class="advisory-td" label="([^"]*)">([^<]*)<\/td>/g)) {
      cells.set(cellMatch[1], decodeEntities(cellMatch[2]));
    }
    rows.push({
      product: cells.get('Product'),
      affectedVersion: cells.get('Affected Version'),
      fixVersion: cells.get('Fix Version'),
    });
  }
  return rows;
}

function parseAffectedVersion(text: string): { versionStart?: string; versionEnd?: string; lastAffected?: string } | null {
  const below = text.match(/^Below\s+([\d.]+)/i);
  if (below) return { versionEnd: below[1] };

  const range = text.match(/^([\d.]+)\s+to\s+([\d.]+)$/i);
  if (range) return { versionStart: range[1], lastAffected: range[2] };

  const earlier = text.match(/^([\d.]+)\s+and\s+earlier$/i);
  if (earlier) return { lastAffected: earlier[1] };

  return null;
}

function buildAffectedProducts(rows: AffectedRow[] | null): NormalizedAdvisory['affectedProducts'] {
  if (!rows) return [];

  const affectedProducts: NormalizedAdvisory['affectedProducts'] = [];
  for (const row of rows) {
    if (!row.product || !row.affectedVersion) continue;
    if (/^not affected$/i.test(row.affectedVersion)) continue;

    const versionFixed = row.fixVersion && /^[\d.]+$/.test(row.fixVersion) ? row.fixVersion : undefined;
    const spec = parseAffectedVersion(row.affectedVersion);

    if (spec) {
      affectedProducts.push({
        vendor: 'splunk',
        product: row.product,
        versionStart: spec.versionStart,
        versionEnd: spec.versionEnd,
        lastAffected: spec.lastAffected,
        versionFixed,
        patchAvailable: !!versionFixed,
      });
    } else {
      // Unrecognized format (best-effort): keep raw version tokens found in the text
      const tokens = row.affectedVersion.match(/\d+(?:\.\d+)+/g) ?? [];
      affectedProducts.push({
        vendor: 'splunk',
        product: row.product,
        affectedVersions: tokens,
        versionFixed,
        patchAvailable: !!versionFixed,
      });
    }
  }
  return affectedProducts;
}

function parseAdvisoryHtml(html: string, advisoryId: string): NormalizedAdvisory | null {
  const titleMatch = html.match(/<div class="advisory-title">\s*<h1>([^<]*)<\/h1>/);
  const title = titleMatch ? decodeEntities(titleMatch[1]) : undefined;
  if (!title) return null;

  const cveMatch = html.match(/CVE&nbsp;ID:<\/b>&nbsp;<a[^>]*>([^<]+)<\/a>/);
  const cveId = cveMatch ? decodeEntities(cveMatch[1]) : undefined;

  const publishedMatch = html.match(/<b>Published:<\/b>&nbsp;([\d-]+)/);
  const publishedAt = publishedMatch ? new Date(publishedMatch[1]) : undefined;

  const scoreMatch = html.match(/CVSSv[\d.]*&nbsp;Score:<\/b>&nbsp;([\d.]+),&nbsp;(\w+)/);
  const cvssScore = scoreMatch ? parseFloat(scoreMatch[1]) : undefined;
  const severity = scoreMatch ? scoreMatch[2].toUpperCase() : undefined;

  const vectorMatch = html.match(/CVSSv[\d.]*&nbsp;Vector:<\/b>&nbsp;<a[^>]*>([^<]+)<\/a>/);
  const cvssVector = vectorMatch ? decodeEntities(vectorMatch[1]) : undefined;

  const description = extractSection(html, 'description');
  const solution = extractSection(html, 'solution');
  const mitigations = extractSection(html, 'mitigations-and-workarounds');

  const rows = parseProductTable(html);
  const affectedProducts = buildAffectedProducts(rows);

  return {
    externalId: advisoryId,
    cveId,
    summary: title,
    description,
    severity,
    cvssScore: isNaN(cvssScore ?? NaN) ? undefined : cvssScore,
    cvssVector,
    url: `${DETAIL_BASE}/${advisoryId}`,
    workaround: mitigations,
    solution,
    publishedAt,
    affectedProducts,
    rawData: { html },
  };
}

// ─── AdvisoryFetcher Implementation ──────────────────────────

export class SplunkFetcher implements AdvisoryFetcher {
  private readonly delayMs: number;

  constructor({ delayMs = 300 } = {}) {
    this.delayMs = delayMs;
  }

  source(): string { return 'advisory-splunk'; }

  async fetch(): Promise<NormalizedAdvisory[]> {
    logger.info('Discovering Splunk advisory IDs (RSS + Wayback CDX)');
    const [rssIds, waybackIds] = await Promise.all([
      discoverIdsFromRss().catch(err => {
        logger.warn({ err }, 'Splunk RSS discovery failed');
        return [] as string[];
      }),
      discoverIdsFromWayback(),
    ]);
    const ids = [...new Set([...rssIds, ...waybackIds])].sort();
    logger.info({ rss: rssIds.length, wayback: waybackIds.length, total: ids.length }, 'Discovered Splunk advisory IDs');

    const results: NormalizedAdvisory[] = [];
    let skipped = 0;
    let failed = 0;

    for (const advisoryId of ids) {
      try {
        const { data: html } = await axios.get<string>(`${DETAIL_BASE}/${advisoryId}`, {
          timeout: 15000,
          headers: { 'User-Agent': 'heretix-api/1.0' },
          responseType: 'text',
        });

        const advisory = parseAdvisoryHtml(html, advisoryId);
        if (advisory) {
          results.push(advisory);
        } else {
          logger.warn({ advisoryId }, 'Could not parse Splunk advisory page');
          skipped++;
        }
      } catch (err) {
        // 404s happen for IDs that were archived but later removed/renamed; skip quietly
        failed++;
        logger.debug({ err, advisoryId }, 'Failed to fetch/parse Splunk advisory');
      }

      await new Promise(r => setTimeout(r, this.delayMs));
    }

    logger.info(
      { total: ids.length, succeeded: results.length, skipped, failed },
      'Splunk advisory fetch complete',
    );
    return results;
  }
}
