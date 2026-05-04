import axios from 'axios';
import type { AdvisoryFetcher, NormalizedAdvisory } from './advisory-fetcher.js';
import { logger } from '../utils/logger.js';

const LIST_API = 'https://psirtapi.global.sonicwall.com/api/v1/vulnsummary/';

// ─── API Types ─────────────────────────────────────────────────

interface SonicWallAdvisory {
  advisory_id: string;
  title: string;
  published_when: string;
  last_updated_when: string;
  impact: string;
  cvss: string;
  cvss_vector: string;
  cvss_version: number;
  cwe: string;
  cve: string;
  is_workaround_available: boolean;
  summary: string;
  affected_products: string;
  vuln_status: string;
  patterns: unknown[];
  vulnerable_products: Array<{ id: number; name: string }>;
}

// ─── Utilities ─────────────────────────────────────────────────

function normalizeSeverity(impact: string): string | undefined {
  const upper = impact.toUpperCase();
  return ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(upper) ? upper : undefined;
}

function extractCveIds(cveField: string): string[] {
  if (!cveField) return [];
  return cveField.split(',').map(s => s.trim()).filter(s => /^CVE-\d{4}-\d+$/.test(s));
}

/**
 * Extract version strings from the HTML affected_products table.
 * Returns version-like strings found (e.g., "7.1.3.3", "6.5.5.1").
 * These are used as lastAffected versions (best-effort).
 */
function extractVersionsFromHtml(html: string): string[] {
  if (!html) return [];
  // Strip HTML tags
  const text = html.replace(/<[^>]+>/g, ' ').replace(/&[a-z]+;/g, ' ');
  // Match SonicOS version patterns: N.N.N.N or N.N.N
  const matches = text.match(/\b\d+\.\d+\.\d+(?:\.\d+)?(?:\.\d+)?\b/g) ?? [];
  return [...new Set(matches)].slice(0, 10);
}

// ─── AdvisoryFetcher Implementation ──────────────────────────

export class SonicWallFetcher implements AdvisoryFetcher {
  source(): string { return 'advisory-sonicwall'; }

  async fetch(): Promise<NormalizedAdvisory[]> {
    logger.info('Fetching SonicWall PSIRT advisories');

    const { data } = await axios.get<SonicWallAdvisory[]>(LIST_API, {
      params: { srch: '', vulnerable_products: '', ord: '-advisory_id' },
      timeout: 30000,
      headers: { 'User-Agent': 'heretix-api/1.0', 'Accept': 'application/json' },
    });

    logger.info({ count: data.length }, 'Fetched SonicWall advisories');

    const results: NormalizedAdvisory[] = [];

    for (const adv of data) {
      // Skip non-applicable entries
      if (adv.vuln_status === 'Not Applicable') continue;

      const cveIds = extractCveIds(adv.cve);
      const severity = normalizeSeverity(adv.impact);
      const cvssScore = adv.cvss ? parseFloat(adv.cvss) : undefined;
      const cvssScore_ = isNaN(cvssScore ?? NaN) ? undefined : cvssScore;

      // Build affected products list from structured vulnerable_products field
      const productNames = (adv.vulnerable_products ?? []).map(p => p.name);
      const primaryProduct = productNames[0] ?? 'SonicOS';

      // Try to extract version info from HTML table (best-effort)
      const versions = extractVersionsFromHtml(adv.affected_products);

      const affectedProducts: NormalizedAdvisory['affectedProducts'] = productNames.length > 0
        ? productNames.map(product => ({
            vendor: 'sonicwall',
            product,
            affectedVersions: versions,
            patchAvailable: true,
          }))
        : [{ vendor: 'sonicwall', product: 'SonicOS', affectedVersions: versions, patchAvailable: true }];

      results.push({
        externalId: adv.advisory_id,
        cveId: cveIds[0],
        summary: adv.title,
        severity,
        cvssScore: cvssScore_,
        cvssVector: adv.cvss_vector || undefined,
        url: `https://psirt.global.sonicwall.com/vuln-detail/${adv.advisory_id}`,
        publishedAt: adv.published_when ? new Date(adv.published_when) : undefined,
        affectedProducts,
        rawData: adv,
      });
    }

    logger.info({ total: data.length, imported: results.length }, 'SonicWall advisory fetch complete');
    return results;
  }
}
