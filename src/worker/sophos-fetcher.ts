import axios from 'axios';
import { XMLParser } from 'fast-xml-parser';
import type { AdvisoryFetcher, NormalizedAdvisory } from './advisory-fetcher.js';
import { logger } from '../utils/logger.js';

const RSS_URL = 'https://www.sophos.com/security-advisories/feed';

// ─── RSS Parsing ──────────────────────────────────────────────

interface RssItem {
  title: string;
  link: string;
  description: string;
  pubDate?: string;
  guid: string | { '#text': string; '@_isPermaLink': string };
}

function getGuid(item: RssItem): string {
  if (typeof item.guid === 'string') return item.guid;
  return item.guid?.['#text'] ?? '';
}

/**
 * Extract all CVE IDs from a string
 * "CVE-2025-10159" or "CVE-2024-13972, CVE-2025-7433" → ["CVE-2025-10159"]
 */
function extractCveIds(text: string): string[] {
  const matches = text.match(/CVE-\d{4}-\d+/g);
  return matches ? [...new Set(matches)] : [];
}

/**
 * Extract severity from description HTML
 * "<div><strong>Severity:</strong> Critical</div>" → "CRITICAL"
 */
function extractSeverity(description: string): string | undefined {
  const m = description.match(/<strong>Severity:<\/strong>\s*([^<]+)/i);
  if (!m) return undefined;
  const raw = m[1].trim().toUpperCase();
  if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(raw)) return raw;
  return undefined;
}

/**
 * Extract product name from advisory title.
 * "Resolved Authentication Bypass Vulnerability in Sophos AP6 Series Wireless Access Points Firmware (CVE-...)"
 * → "AP6 Series Wireless Access Points"
 *
 * "Resolved Multiple Vulnerabilities in Sophos Firewall (CVE-...)"
 * → "Firewall"
 */
function extractProduct(title: string): string {
  // Match "in Sophos <product>" pattern
  const m = title.match(/\bin\s+Sophos\s+(.+?)(?:\s+Firmware|\s+Software|\s*\(CVE|\s*$)/i);
  if (m) return `Sophos ${m[1].trim()}`;
  // Fallback: use generic product from the advisory ID pattern
  return 'Sophos';
}

/**
 * Normalize advisory URL to English locale.
 * RSS links come in Japanese locale (ja-jp), normalize to en-us.
 */
function normalizeUrl(link: string): string {
  return link.replace(/\/[a-z]{2}-[a-z]{2}\/security-advisories\//, '/en-us/security-advisories/');
}

// ─── AdvisoryFetcher Implementation ──────────────────────────

export class SophosFetcher implements AdvisoryFetcher {
  source(): string { return 'advisory-sophos'; }

  async fetch(): Promise<NormalizedAdvisory[]> {
    logger.info('Fetching Sophos security advisories RSS feed');

    const { data } = await axios.get<string>(RSS_URL, {
      timeout: 30000,
      headers: { 'User-Agent': 'heretix-api/1.0' },
      responseType: 'text',
    });

    const parser = new XMLParser({ ignoreAttributes: false, parseAttributeValue: false });
    const parsed = parser.parse(data);
    const rawItems = parsed?.rss?.channel?.item ?? [];
    const items: RssItem[] = Array.isArray(rawItems) ? rawItems : [rawItems];

    logger.info({ count: items.length }, 'Fetched Sophos RSS items');

    const results: NormalizedAdvisory[] = [];

    for (const item of items) {
      const externalId = getGuid(item);
      if (!externalId) continue;

      const description = item.description ?? '';
      const title = item.title ?? '';
      const severity = extractSeverity(description);

      // Extract CVE IDs from title and description
      const cveIds = extractCveIds(title + ' ' + description);

      // Skip informational advisories without CVEs
      if (cveIds.length === 0 && (!severity || severity === 'INFORMATIONAL')) {
        logger.debug({ externalId }, 'Skipping Sophos informational advisory without CVE');
        continue;
      }

      const product = extractProduct(title);
      const publishedAt = item.pubDate ? new Date(item.pubDate) : undefined;
      const url = normalizeUrl(item.link ?? '');

      // NormalizedAdvisory supports one cveId; use the first CVE found
      const cveId = cveIds[0];

      results.push({
        externalId,
        cveId,
        summary: title,
        severity,
        url,
        publishedAt,
        affectedProducts: [{
          vendor: 'sophos',
          product,
          patchAvailable: title.toLowerCase().startsWith('resolved'),
        }],
        rawData: item,
      });
    }

    logger.info({ total: items.length, imported: results.length }, 'Sophos advisory fetch complete');
    return results;
  }
}
