import axios from 'axios';
import { XMLParser } from 'fast-xml-parser';
import type { AdvisoryFetcher, NormalizedAdvisory } from './advisory-fetcher.js';
import { logger } from '../utils/logger.js';
import { withPage, closeBrowser } from '../utils/browser.js';

const RSS_URL     = 'https://www.sophos.com/security-advisories/feed';
const SITEMAP_URL = 'https://www.sophos.com/sitemap.xml';
const BASE_URL    = 'https://www.sophos.com/en-us/security-advisories';

// ─── Types ────────────────────────────────────────────────────

interface RssItem {
  title: string;
  link: string;
  description: string;
  pubDate?: string;
  guid: string | { '#text': string; '@_isPermaLink': string };
}

export interface AdvisoryMeta {
  externalId: string;
  cveIds: string[];
  severity?: string;
  title?: string;
  pubDate?: Date;
  url: string;
}

// ─── Utilities ────────────────────────────────────────────────

function getGuid(item: RssItem): string {
  if (typeof item.guid === 'string') return item.guid;
  return item.guid?.['#text'] ?? '';
}

function extractCveIds(text: string): string[] {
  const matches = text.match(/CVE-\d{4}-\d+/g);
  return matches ? [...new Set(matches)] : [];
}

function extractSeverity(description: string): string | undefined {
  const m = description.match(/<strong>Severity:<\/strong>\s*([^<]+)/i);
  if (!m) return undefined;
  const raw = m[1].trim().toUpperCase();
  return ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(raw) ? raw : undefined;
}

function extractProduct(title: string): string {
  const m = title.match(/\bin\s+Sophos\s+(.+?)(?:\s+Firmware|\s+Software|\s*\(CVE|\s*\||\s*$)/i);
  if (m) return `Sophos ${m[1].trim()}`;
  return 'Sophos';
}

function normalizeUrl(link: string): string {
  return link.replace(/\/[a-z]{2}-[a-z]{2}\/security-advisories\//, '/en-us/security-advisories/');
}

// ─── Data Fetching ────────────────────────────────────────────

async function fetchRssItems(): Promise<Map<string, RssItem>> {
  const { data } = await axios.get<string>(RSS_URL, {
    timeout: 30000,
    headers: { 'User-Agent': 'heretix-api/1.0' },
    responseType: 'text',
  });
  const parser = new XMLParser({ ignoreAttributes: false, parseAttributeValue: false });
  const parsed = parser.parse(data);
  const rawItems = parsed?.rss?.channel?.item ?? [];
  const items: RssItem[] = Array.isArray(rawItems) ? rawItems : [rawItems];
  const map = new Map<string, RssItem>();
  for (const item of items) {
    const id = getGuid(item);
    if (id) map.set(id, item);
  }
  return map;
}

async function fetchSitemapIds(): Promise<string[]> {
  const { data } = await axios.get<string>(SITEMAP_URL, {
    timeout: 30000,
    headers: { 'User-Agent': 'heretix-api/1.0' },
    responseType: 'text',
  });
  const matches = data.match(/security-advisories\/(sophos-sa-[^<\s"]+)/g) ?? [];
  return [...new Set(matches.map(m => m.replace('security-advisories/', '')))];
}

/**
 * Fetch the advisory page HTML and extract CVE IDs from <title>.
 * `failed` distinguishes "the request itself failed" (network error, timeout,
 * non-2xx) from "the request succeeded but the page legitimately had no CVE
 * in its title" -- fetch()'s "no title or CVE" skip further down needs this
 * to avoid silently dropping an advisory that was never actually fetched.
 */
async function fetchTitleCveIds(id: string): Promise<{ cveIds: string[]; title: string | undefined; failed: boolean }> {
  try {
    const { data } = await axios.get<string>(`${BASE_URL}/${id}`, {
      timeout: 15000,
      headers: { 'User-Agent': 'heretix-api/1.0' },
      responseType: 'text',
    });
    const titleMatch = (data as string).match(/<title>([^<]+)<\/title>/);
    const title = titleMatch?.[1]?.replace(/\s*\|\s*Sophos\s*$/, '').trim();
    const cveIds = extractCveIds(title ?? '');
    return { cveIds, title, failed: false };
  } catch (err) {
    logger.warn({ id, err }, 'Failed to fetch Sophos advisory page title');
    return { cveIds: [], title: undefined, failed: true };
  }
}

/**
 * Render the advisory page with a headless browser and extract all CVE IDs
 * from the fully rendered body text. Used as fallback when the <title> has no CVE.
 */
async function fetchRenderedCveIds(id: string): Promise<string[]> {
  try {
    return await withPage(`${BASE_URL}/${id}`, async (page) => {
      // Wait until the main content area is visible
      await page.waitForSelector('main, article, [class*="advisory"], body', { timeout: 15000 });
      const bodyText = await page.locator('body').innerText();
      return extractCveIds(bodyText);
    });
  } catch (err) {
    logger.warn({ id, err }, 'Playwright fallback failed for Sophos advisory');
    return [];
  }
}

/**
 * Build one NormalizedAdvisory per CVE covered by a Sophos advisory. A single
 * sophos-sa-* page commonly covers several CVEs (e.g. a monthly firewall
 * roundup) — without the split, `externalId: meta.externalId` + a single
 * `cveId` field meant only the first CVE ever got linked to a Vulnerability
 * master row and became independently searchable. Follows the same
 * `${advisoryId}/${cveId}` composite-externalId pattern already used by
 * redhat-fetcher.ts / oracle-linux-fetcher.ts / broadcom-fetcher.ts for the
 * same one-advisory-many-CVEs shape. Entries with no CVE at all keep the
 * plain sophos-sa-* id as externalId, unchanged from before. Returns []
 * for the pre-existing skip case (no title and no CVE — advisory that was
 * never actually fetched, not just CVE-less).
 */
export function buildSophosAdvisories(meta: AdvisoryMeta): NormalizedAdvisory[] {
  if (!meta.title && meta.cveIds.length === 0) {
    return [];
  }

  const product = extractProduct(meta.title ?? meta.externalId);
  const base = {
    summary: meta.title,
    severity: meta.severity,
    url: meta.url,
    publishedAt: meta.pubDate,
    affectedProducts: [{
      vendor: 'sophos',
      product,
      patchAvailable: (meta.title ?? '').toLowerCase().startsWith('resolved'),
    }],
    rawData: meta,
  };

  if (meta.cveIds.length === 0) {
    return [{ externalId: meta.externalId, ...base }];
  }
  return meta.cveIds.map(cveId => ({ externalId: `${meta.externalId}/${cveId}`, cveId, ...base }));
}

// ─── AdvisoryFetcher Implementation ──────────────────────────

export class SophosFetcher implements AdvisoryFetcher {
  private readonly delayMs: number;
  private fetchFailed = 0;

  constructor({ delayMs = 500 } = {}) {
    this.delayMs = delayMs;
  }

  source(): string { return 'advisory-sophos'; }
  isCompleteSnapshot(): boolean { return true; }
  fetchFailedCount(): number { return this.fetchFailed; }

  async fetch(): Promise<NormalizedAdvisory[]> {
    this.fetchFailed = 0;
    logger.info('Fetching Sophos security advisories');

    const [rssMap, sitemapIds] = await Promise.all([
      fetchRssItems(),
      fetchSitemapIds(),
    ]);

    logger.info({ rss: rssMap.size, sitemap: sitemapIds.length }, 'Sophos sources fetched');

    const metas: AdvisoryMeta[] = [];

    for (const id of sitemapIds) {
      const rssItem = rssMap.get(id);

      // Try to get CVE from ID itself first (e.g., "cve-2020-9363" → "CVE-2020-9363")
      const cveFromId = extractCveIds(id.replace(/-/g, ' ').replace(/cve /gi, 'CVE-').replace(/CVE-(\d{4}) (\d+)/g, 'CVE-$1-$2'));

      if (rssItem) {
        // Full data from RSS
        const description = rssItem.description ?? '';
        const title = rssItem.title ?? '';
        const cveIds = extractCveIds(title + ' ' + description);
        metas.push({
          externalId: id,
          cveIds,
          severity: extractSeverity(description),
          title,
          pubDate: rssItem.pubDate ? new Date(rssItem.pubDate) : undefined,
          url: normalizeUrl(rssItem.link ?? `${BASE_URL}/${id}`),
        });
      } else {
        // Older advisory: fetch title via HTTP first (fast)
        await new Promise(r => setTimeout(r, this.delayMs));
        const { cveIds: titleCves, title, failed: titleFetchFailed } = await fetchTitleCveIds(id);
        if (titleFetchFailed) this.fetchFailed++;
        let cveIds = cveFromId.length > 0 ? cveFromId : titleCves;

        // If title exists but has no CVE, use Playwright to render the full page
        if (title && cveIds.length === 0) {
          logger.debug({ id }, 'No CVE in title, using Playwright to render full page');
          cveIds = await fetchRenderedCveIds(id);
        }

        metas.push({
          externalId: id,
          cveIds,
          title,
          url: `${BASE_URL}/${id}`,
        });
        logger.debug({ id, cveIds, title }, 'Sophos older advisory fetched');
      }
    }

    await closeBrowser();

    // Convert to NormalizedAdvisory, skip only entries where title could not be fetched
    // (cveId is optional — advisories without CVE link via advisoryId in the master table)
    const results: NormalizedAdvisory[] = [];
    for (const meta of metas) {
      const built = buildSophosAdvisories(meta);
      if (built.length === 0) {
        logger.debug({ externalId: meta.externalId }, 'Skipping Sophos advisory: no title or CVE');
        continue;
      }
      results.push(...built);
    }

    logger.info({ total: sitemapIds.length, imported: results.length, failed: this.fetchFailed }, 'Sophos advisory fetch complete');
    return results;
  }
}
