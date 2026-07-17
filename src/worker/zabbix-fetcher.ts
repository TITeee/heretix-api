import axios from 'axios';
import type { AdvisoryFetcher, NormalizedAdvisory } from './advisory-fetcher.js';
import { logger } from '../utils/logger.js';

const SEARCH_URL = 'https://www.zabbix.com/saas/search/collections/zabbix_web_security_advisories/documents/search';
const API_KEY = 'A6ZwNJS8IqnpeGqBZ3OSXcPPCjLfp6pu'; // public client-side search-only key, same as used by zabbix.com's own advisory page
const ADVISORY_PAGE_URL = 'https://www.zabbix.com/security_advisories';
const PER_PAGE = 250;

export interface ZabbixDocument {
  cve_id: string;            // Zabbix's own advisory ID (e.g. "ZBV-2026-05-06-3"), despite the field name
  cve_number?: string;       // actual CVE ID, or "-" when none assigned
  cvss_score?: number;
  severity?: string;         // "critical" | "high" | "medium" | "low" | "-"
  published?: string;
  synopsis_text?: string;
  synopsis_description?: string;
  synopsis_resolution?: string;
  workarounds?: string;
  version_affected?: string[];
  version_fixed?: string[];
}

interface SearchResponse {
  found: number;
  hits: { document: ZabbixDocument }[];
}

async function fetchAllDocuments(): Promise<ZabbixDocument[]> {
  const docs: ZabbixDocument[] = [];
  let page = 1;
  for (;;) {
    const { data } = await axios.get<SearchResponse>(SEARCH_URL, {
      params: {
        q: '*',
        query_by: 'cve_id',
        filter_by: 'inactive:=false',
        sort_by: 'published_int:desc',
        per_page: PER_PAGE,
        page,
      },
      headers: { 'X-TYPESENSE-API-KEY': API_KEY },
      timeout: 30000,
    });
    for (const hit of data.hits) docs.push(hit.document);
    if (docs.length >= data.found || data.hits.length === 0) break;
    page++;
  }
  return docs;
}

// ─── version_affected parsing ──────────────────────────────────

function normalizeDash(s: string): string {
  return s.replace(/[‒–—−]/g, '-').trim();
}

interface AffectsSpec {
  versionStart?: string;
  lastAffected?: string;
  version?: string; // single exact version (no range)
}

/**
 * Parses one entry of the version_affected array. Formats observed across the
 * full advisory history: clean ranges ("6.0.0-6.0.44"), spaced/en-dash ranges
 * ("5.0.0 – 5.0.18"), single exact versions ("5.0.18", no dash at all), branch
 * wildcards ("4.4.4-4.4.*"), and empty placeholders ("-"). A handful of very
 * old entries use free-text notation (e.g. "MSI pkg. (29.oct.22 - 2.dec.22)")
 * that isn't a parseable version range — those are skipped (best-effort,
 * matching the fallback approach used by other vendor fetchers in this repo).
 */
export function parseAffectsEntry(raw: string): AffectsSpec | null {
  const text = normalizeDash(raw);
  if (!text || text === '-') return null;

  const range = text.match(/^([\w.]+)\s*-\s*([\w.*]+)$/);
  if (range) {
    const [, start, end] = range;
    if (end.includes('*')) return { versionStart: start }; // wildcard upper bound: leave open-ended
    return { versionStart: start, lastAffected: end };
  }

  if (/^[\d][\w.]*$/.test(text)) return { version: text };

  return null;
}

export function buildAffectedProducts(doc: ZabbixDocument): NormalizedAdvisory['affectedProducts'] {
  const versionAffected = doc.version_affected ?? [];
  const versionFixed = doc.version_fixed ?? [];
  const affectedProducts: NormalizedAdvisory['affectedProducts'] = [];

  for (let i = 0; i < versionAffected.length; i++) {
    const spec = parseAffectsEntry(versionAffected[i]);
    if (!spec) continue;

    const fixed = versionFixed[i];
    const isRange = spec.versionStart !== undefined || spec.lastAffected !== undefined;
    // versionFixed must only be set alongside an actual range: importAdvisoryData()
    // falls back to versionFixed as the range's exclusive upper bound when versionEnd
    // is absent, which would incorrectly turn a single exact-version entry into an
    // unbounded range (see the same bug fixed for the Apache fetcher).
    const cleanFixed = fixed && /^[\d][\w.]*$/.test(normalizeDash(fixed)) ? fixed : undefined;

    affectedProducts.push({
      vendor: 'zabbix',
      product: 'zabbix',
      versionStart: spec.versionStart,
      lastAffected: spec.lastAffected,
      affectedVersions: spec.version ? [spec.version] : undefined,
      versionFixed: isRange ? cleanFixed : undefined,
      patchAvailable: !!cleanFixed,
    });
  }

  return affectedProducts;
}

function parseDocument(doc: ZabbixDocument): NormalizedAdvisory | null {
  if (!doc.synopsis_text) return null;

  const cveId = doc.cve_number && doc.cve_number !== '-' ? doc.cve_number : undefined;
  const severity = doc.severity && doc.severity !== '-' ? doc.severity.toUpperCase() : undefined;
  const cvssScore = doc.cvss_score && doc.cvss_score > 0 ? doc.cvss_score : undefined;

  return {
    externalId: doc.cve_id,
    cveId,
    summary: doc.synopsis_text,
    description: doc.synopsis_description,
    severity,
    cvssScore,
    url: ADVISORY_PAGE_URL,
    workaround: doc.workarounds,
    solution: doc.synopsis_resolution,
    publishedAt: doc.published ? new Date(doc.published) : undefined,
    affectedProducts: buildAffectedProducts(doc),
    rawData: doc,
  };
}

// ─── AdvisoryFetcher Implementation ──────────────────────────

export class ZabbixFetcher implements AdvisoryFetcher {
  source(): string { return 'advisory-zabbix'; }

  async fetch(): Promise<NormalizedAdvisory[]> {
    logger.info('Fetching Zabbix security advisories');
    const docs = await fetchAllDocuments();
    logger.info({ count: docs.length }, 'Fetched Zabbix advisory documents');

    const results: NormalizedAdvisory[] = [];
    let skipped = 0;

    for (const doc of docs) {
      const advisory = parseDocument(doc);
      if (advisory) {
        results.push(advisory);
      } else {
        skipped++;
      }
    }

    logger.info({ total: docs.length, succeeded: results.length, skipped }, 'Zabbix advisory fetch complete');
    return results;
  }
}
