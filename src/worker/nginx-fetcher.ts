import axios from 'axios';
import type { AdvisoryFetcher, NormalizedAdvisory } from './advisory-fetcher.js';
import { logger } from '../utils/logger.js';

const PAGE_URL = 'https://nginx.org/en/security_advisories.html';

export interface VulnerableRange {
  introduced: string;
  lastAffected: string; // inclusive upper bound (nginx.org notation)
}

interface RawEntry {
  cveId: string;
  severity: string;
  range: VulnerableRange;
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
 */
export function parseVulnerableText(text: string): VulnerableRange[] {
  const ranges: VulnerableRange[] = [];
  const parts = text.split(',').map(s => s.trim()).filter(Boolean);

  for (const part of parts) {
    const hyphen = part.indexOf('-');
    if (hyphen > 0) {
      const introduced = part.slice(0, hyphen).trim();
      const lastAffected = part.slice(hyphen + 1).trim();
      if (/^\d+\.\d+/.test(introduced) && /^\d+\.\d+/.test(lastAffected)) {
        ranges.push({ introduced, lastAffected });
        continue;
      }
    }
    if (/^\d+\.\d+/.test(part)) {
      ranges.push({ introduced: part, lastAffected: part });
    }
  }

  return ranges;
}

/**
 * Parse raw {cveId, severity, range} entries from the nginx.org security
 * advisories page. Old entries without a CVE ID are skipped.
 */
export function parseNginxPage(html: string): RawEntry[] {
  const entries: RawEntry[] = [];
  const blocks = html.split(/<\/li>/i);

  for (const block of blocks) {
    const cveMatches = [...block.matchAll(/CVE-\d{4}-\d+/g)];
    if (cveMatches.length === 0) continue;

    const withoutNotVuln = block.replace(/Not vulnerable:[^\n<]*/gi, '');
    const vulnMatch = withoutNotVuln.match(/Vulnerable:\s*([^\n<]+)/i);
    if (!vulnMatch) continue;

    const ranges = parseVulnerableText(vulnMatch[1].trim());
    if (ranges.length === 0) continue;

    const sevMatch = block.match(/Severity:\s*(\w+)/i);
    const severity = sevMatch ? sevMatch[1].toLowerCase() : 'unknown';

    for (const cveMatch of cveMatches) {
      for (const range of ranges) {
        entries.push({ cveId: cveMatch[0], severity, range });
      }
    }
  }

  return entries;
}

const SEVERITY_MAP: Record<string, string> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
};

/** Group raw entries by CVE ID into one NormalizedAdvisory each (multiple ranges become multiple affectedProducts). */
export function groupByAdvisory(entries: RawEntry[]): NormalizedAdvisory[] {
  const byCve = new Map<string, RawEntry[]>();
  for (const e of entries) {
    const list = byCve.get(e.cveId) ?? [];
    list.push(e);
    byCve.set(e.cveId, list);
  }

  const advisories: NormalizedAdvisory[] = [];
  for (const [cveId, group] of byCve) {
    const rawSeverity = group.find(g => g.severity !== 'unknown')?.severity;
    const severity = rawSeverity ? SEVERITY_MAP[rawSeverity] : undefined;

    const seen = new Set<string>();
    const affectedProducts: NormalizedAdvisory['affectedProducts'] = [];
    for (const g of group) {
      const key = `${g.range.introduced}-${g.range.lastAffected}`;
      if (seen.has(key)) continue;
      seen.add(key);
      affectedProducts.push({
        vendor: 'nginx',
        product: 'nginx',
        versionStart: g.range.introduced,
        lastAffected: g.range.lastAffected,
      });
    }

    advisories.push({
      externalId: cveId,
      cveId,
      severity,
      url: PAGE_URL,
      affectedProducts,
      rawData: {},
    });
  }

  return advisories;
}

// ─── AdvisoryFetcher Implementation ──────────────────────────

export class NginxFetcher implements AdvisoryFetcher {
  source(): string { return 'advisory-nginx'; }

  async fetch(): Promise<NormalizedAdvisory[]> {
    logger.info('Fetching nginx security advisories');
    const { data: html } = await axios.get<string>(PAGE_URL, {
      timeout: 30000,
      headers: { 'User-Agent': 'heretix-api/1.0' },
      responseType: 'text',
    });

    const entries = parseNginxPage(html);
    const results = groupByAdvisory(entries);
    logger.info({ total: results.length }, 'nginx advisory fetch complete');
    return results;
  }
}
