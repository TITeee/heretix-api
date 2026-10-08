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

/**
 * A version as it should be stored: the leading comparison marker Zabbix puts
 * on fixed versions ("=>6.0.7rc1" = "6.0.7rc1 or later") and a trailing
 * alpha/beta/rc label are dropped. A label must go because normalizeVersion()
 * strips letters but keeps their digits, reading "6.0.7rc1" as patch 71. The
 * release the label belongs to ("6.0.7") is what the advisory means: the fix
 * is in 6.0.7rc1 and so in 6.0.7 too.
 */
function cleanVersion(raw: string): string | undefined {
  const text = normalizeDash(raw).replace(/^(?:=>|>=|≥|=)\s*/, '').replace(/(?:alpha|beta|rc)\d*$/i, '');
  return /^\d[\d.]*$/.test(text) && !text.endsWith('.') ? text : undefined;
}

/** Numeric comparison of dotted versions ("6.0.7" < "6.0.10"). */
function compareDotted(a: string, b: string): number {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

interface AffectsSpec {
  versionStart?: string;
  versionEnd?: string;    // exclusive upper bound, derived for wildcard branches only
  lastAffected?: string;
  version?: string; // single exact version (no range)
}

/**
 * Derive the next minor branch as an exclusive upper bound.
 * "4.4" → "4.5.0", "5.2" → "5.3.0"
 */
function nextMinorBranch(branch: string): string | undefined {
  const parts = branch.split('.');
  if (parts.length < 2) return undefined;
  const minor = parseInt(parts[1], 10);
  if (isNaN(minor)) return undefined;
  return `${parts[0]}.${minor + 1}.0`;
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
    const start = cleanVersion(range[1]);
    const end = range[2];
    if (!start) return null;
    if (end.includes('*')) {
      // "4.4.*" means "through the end of the 4.4 branch" -- bound it at the
      // next minor branch (exclusive) rather than leaving it fully open-ended,
      // which previously made these rows match every later zabbix version
      // forever (e.g. "4.4.4-4.4.*" incorrectly matched a 7.0.0 query).
      const branch = end.replace(/\.\*$/, '');
      return { versionStart: start, versionEnd: nextMinorBranch(branch) };
    }
    const lastAffected = cleanVersion(end);
    return lastAffected ? { versionStart: start, lastAffected } : null;
  }

  // "=>4.0.23rc1": affected from that version on, with the upper bound being
  // whatever the matching fixed version says. Only usable together with one.
  if (/^(?:=>|>=|≥)/.test(text)) {
    const start = cleanVersion(text);
    return start ? { versionStart: start } : null;
  }

  if (/^[\d][\w.]*$/.test(text)) {
    const version = cleanVersion(text);
    return version ? { version } : null;
  }

  return null;
}

export function buildAffectedProducts(doc: ZabbixDocument): NormalizedAdvisory['affectedProducts'] {
  const versionAffected = doc.version_affected ?? [];
  const versionFixed = doc.version_fixed ?? [];
  const affectedProducts: NormalizedAdvisory['affectedProducts'] = [];

  for (let i = 0; i < versionAffected.length; i++) {
    const spec = parseAffectsEntry(versionAffected[i]);
    if (!spec) continue;

    const cleanFixed = versionFixed[i] ? cleanVersion(versionFixed[i]) : undefined;
    const isRange = spec.versionStart !== undefined || spec.lastAffected !== undefined;
    const isOpenFrom = isRange && spec.lastAffected === undefined && spec.versionEnd === undefined;
    // "=>X" has no upper bound of its own: without a fixed version it would match
    // every later release, so it only counts together with one.
    if (isOpenFrom && !cleanFixed) continue;

    // versionFixed must only be set alongside an actual range: importAdvisoryData()
    // falls back to versionFixed as the range's exclusive upper bound when versionEnd
    // is absent, which would incorrectly turn a single exact-version entry into an
    // unbounded range (see the same bug fixed for the Apache fetcher). A single
    // exact version with a later fix is bounded on both sides instead.
    const boundedExact = spec.version !== undefined && cleanFixed !== undefined
      && compareDotted(spec.version, cleanFixed) < 0;

    affectedProducts.push({
      vendor: 'zabbix',
      product: 'zabbix',
      versionStart: boundedExact ? spec.version : spec.versionStart,
      versionEnd: spec.versionEnd,
      lastAffected: spec.lastAffected,
      affectedVersions: spec.version ? [spec.version] : undefined,
      versionFixed: isRange || boundedExact ? cleanFixed : undefined,
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
  isCompleteSnapshot(): boolean { return true; }

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
