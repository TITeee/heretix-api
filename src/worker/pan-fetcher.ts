import axios from 'axios';
import { XMLParser } from 'fast-xml-parser';
import type { AdvisoryFetcher, NormalizedAdvisory } from './advisory-fetcher.js';
import { logger } from '../utils/logger.js';

const RSS_URL  = 'https://security.paloaltonetworks.com/rss.xml';
const WEB_URL  = 'https://security.paloaltonetworks.com';
const CSAF_BASE = 'https://security.paloaltonetworks.com/csaf';

// ─── CSAF 2.0 Type Definitions ───────────────────────────────

interface CsafDocument {
  document: {
    title: string;
    tracking: {
      id: string;
      initial_release_date: string;
      current_release_date?: string;
    };
  };
  product_tree?: {
    branches?: CsafBranch[];
  };
  vulnerabilities: CsafVulnerability[];
}

interface CsafBranch {
  category: string;
  name: string;
  branches?: CsafBranch[];
  product?: { product_id: string; name: string };
}

interface CsafVulnerability {
  cve?: string;
  scores?: Array<{
    products: string[];
    cvss_v3?: { baseScore: number; baseSeverity: string; vectorString: string };
    cvss_v4?: { baseScore: number; baseSeverity: string; vectorString: string };
  }>;
  notes?: Array<{ category: string; title?: string; text: string }>;
  product_status?: {
    known_affected?: string[];
    known_not_affected?: string[];
    fixed?: string[];
  };
  remediations?: Array<{ category: string; details: string; product_ids?: string[] }>;
  references?: Array<{ url: string; summary: string }>;
}

// ─── Utilities ────────────────────────────────────────────────

interface ProductRangeInfo {
  productName: string;
  op: string;      // '<', '<=', '>=', '>'
  version: string;
}

/**
 * Build a map from product_id to version range info from product_tree
 * PAN CSAF format: product_version_range branch names contain "vers:generic/<12.1.4" etc.
 */
function buildProductMap(branches: CsafBranch[]): Map<string, ProductRangeInfo> {
  const map = new Map<string, ProductRangeInfo>();
  function walk(bs: CsafBranch[], parentProductName?: string) {
    for (const b of bs) {
      const productName = b.category === 'product_name' ? b.name : parentProductName;
      if (b.product?.product_id && productName) {
        // "vers:generic/<12.1.4", "vers:generic/>=11.2.10", "vers:generic/PAN-OS Firewall<12.1.4"
        const m = b.name.match(/([<>]=?)([\d][\d.]*)$/);
        if (m) {
          map.set(b.product.product_id, { productName, op: m[1], version: m[2] });
        }
      }
      if (b.branches) walk(b.branches, productName);
    }
  }
  walk(branches);
  return map;
}

/** Collect all product names from product_tree (used for legacy format fallback) */
function collectProductNames(branches: CsafBranch[]): Set<string> {
  const names = new Set<string>();
  function walk(bs: CsafBranch[]) {
    for (const b of bs) {
      if (b.category === 'product_name' || b.category === 'product') {
        names.add(b.name);
      }
      if (b.product) names.add(b.product.name);
      if (b.branches) walk(b.branches);
    }
  }
  walk(branches);
  return names;
}

/**
 * Infer product name from product_id (for legacy format fallback)
 * e.g. "PAN-OS 11.1" → "PAN-OS"
 */
function extractProductName(productId: string, knownProducts: Set<string>): string | null {
  const sorted = [...knownProducts].sort((a, b) => b.length - a.length);
  for (const name of sorted) {
    if (productId.startsWith(name)) return name;
  }
  const spaceIdx = productId.lastIndexOf(' ');
  if (spaceIdx > 0) return productId.slice(0, spaceIdx);
  return null;
}

/**
 * "< 11.1.4" → versionEnd: "11.1.4" (exclusive)
 * ">= 11.1.4" → versionFixed: "11.1.4"
 */
function parseVersionOperator(str: string): { versionEnd?: string; versionFixed?: string; lastAffected?: string } {
  const s = str.trim();
  const ltMatch = s.match(/^<\s*(\S+)$/);
  if (ltMatch) return { versionEnd: ltMatch[1] };
  const lteMatch = s.match(/^<=\s*(\S+)$/);
  if (lteMatch) return { lastAffected: lteMatch[1] };
  const gteMatch = s.match(/^>=\s*(\S+)$/);
  if (gteMatch) return { versionFixed: gteMatch[1] };
  return {};
}

// ─── CSAF → NormalizedAdvisory Conversion ────────────────────

function parseCsaf(csaf: CsafDocument, advisoryId: string, pubDate?: Date): NormalizedAdvisory | null {
  const vulns = csaf.vulnerabilities ?? [];
  if (vulns.length === 0) return null;

  const productMap   = buildProductMap(csaf.product_tree?.branches ?? []);
  const knownProducts = collectProductNames(csaf.product_tree?.branches ?? []);
  const firstVuln = vulns[0];
  const cveId = firstVuln.cve;

  // Select the highest CVSS score from all entries
  let cvssScore: number | undefined;
  let cvssVector: string | undefined;
  let severity: string | undefined;
  for (const v of vulns) {
    for (const s of v.scores ?? []) {
      const cv = s.cvss_v3 ?? s.cvss_v4;
      if (cv && (!cvssScore || cv.baseScore > cvssScore)) {
        cvssScore  = cv.baseScore;
        cvssVector = cv.vectorString;
        severity   = cv.baseSeverity;
      }
    }
  }

  const summaryNote    = firstVuln.notes?.find(n => n.category === 'summary' || n.category === 'description');
  const workaroundNote = firstVuln.notes?.find(n => n.category === 'workaround' || n.title?.toLowerCase().includes('workaround'));
  const fixRemediation = firstVuln.remediations?.find(r => r.category === 'vendor_fix' || r.category === 'mitigation');
  const refUrl         = firstVuln.references?.[0]?.url ?? `https://security.paloaltonetworks.com/${advisoryId}`;

  // Extract affected products
  const affectedProducts: NormalizedAdvisory['affectedProducts'] = [];
  const seenPids = new Set<string>();

  // Prefer vers:generic/ format (new); fall back to legacy format if absent
  const useNewFormat = vulns.some(v =>
    (v.product_status?.known_affected ?? []).some(pid => productMap.has(pid)),
  );

  if (useNewFormat) {
    for (const v of vulns) {
      // Collect fixed versions per product from >= or > product_ids
      const fixedByProduct = new Map<string, string>();
      for (const pid of [...(v.product_status?.known_not_affected ?? []), ...(v.product_status?.fixed ?? [])]) {
        const info = productMap.get(pid);
        if (info && (info.op === '>=' || info.op === '>')) {
          if (!fixedByProduct.has(info.productName)) {
            fixedByProduct.set(info.productName, info.version);
          }
        }
      }

      for (const pid of v.product_status?.known_affected ?? []) {
        if (seenPids.has(pid)) continue;
        seenPids.add(pid);

        const info = productMap.get(pid);
        if (!info) continue;

        const versionFixed = fixedByProduct.get(info.productName);
        affectedProducts.push({
          vendor:       'paloalto',
          product:      info.productName,
          versionEnd:   info.op === '<'  ? info.version : undefined,
          lastAffected: info.op === '<=' ? info.version : undefined,
          versionFixed,
          patchAvailable: !!versionFixed,
        });
      }
    }
  } else {
    // Legacy format: product_id contains a direct version like "PAN-OS 11.1.0"
    for (const v of vulns) {
      const fixedVersions: string[] = [];
      for (const pid of [...(v.product_status?.known_not_affected ?? []), ...(v.product_status?.fixed ?? [])]) {
        const name = extractProductName(pid, knownProducts);
        if (name) {
          const ver = pid.slice(name.length).trim();
          if (ver && /^\d/.test(ver)) fixedVersions.push(ver);
        }
      }

      for (const pid of v.product_status?.known_affected ?? []) {
        if (seenPids.has(pid)) continue;
        seenPids.add(pid);

        const name = extractProductName(pid, knownProducts);
        if (!name) continue;

        const versionPart = pid.slice(name.length).trim();
        if (!versionPart) {
          affectedProducts.push({ vendor: 'paloalto', product: name, patchAvailable: fixedVersions.length > 0 });
          continue;
        }

        if (/^\d[\d.]+$/.test(versionPart)) {
          const branch = versionPart.split('.').slice(0, 2).join('.');
          const versionFixed = fixedVersions.find(fv => fv.startsWith(branch + '.'));
          affectedProducts.push({
            vendor: 'paloalto',
            product: name,
            versionStart: versionPart,
            versionFixed,
            patchAvailable: !!versionFixed,
          });
        } else {
          const parsed = parseVersionOperator(versionPart);
          affectedProducts.push({
            vendor: 'paloalto',
            product: name,
            ...parsed,
            patchAvailable: fixedVersions.length > 0,
          });
        }
      }
    }
  }

  if (affectedProducts.length === 0) return null;

  const publishedAt = pubDate
    ?? (csaf.document.tracking.initial_release_date
      ? new Date(csaf.document.tracking.initial_release_date)
      : undefined);

  return {
    externalId:  advisoryId,
    cveId,
    summary:     summaryNote?.text?.trim(),
    severity,
    cvssScore,
    cvssVector,
    url:         refUrl,
    workaround:  workaroundNote?.text?.trim(),
    solution:    fixRemediation?.details,
    publishedAt,
    affectedProducts,
    rawData:     csaf,
  };
}

// ─── RSS Fetching ─────────────────────────────────────────────

interface RssItem {
  title: string;
  link: string;
  pubDate?: string;
}

async function fetchRssItems(): Promise<RssItem[]> {
  const { data } = await axios.get<string>(RSS_URL, {
    timeout: 30000,
    headers: { 'User-Agent': 'heretix-api/1.0' },
    responseType: 'text',
  });

  const parser = new XMLParser({ ignoreAttributes: false });
  const parsed = parser.parse(data);
  const items = parsed?.rss?.channel?.item ?? [];
  return Array.isArray(items) ? items : [items];
}

/** Extract advisory ID from the end of an RSS/Web link URL */
function extractAdvisoryId(link: string): string | null {
  // https://security.paloaltonetworks.com/CVE-2026-0229
  // https://security.paloaltonetworks.com/PAN-SA-2026-0003
  const m = link.match(/\/(CVE-\d{4}-\d+|PAN-SA-\d{4}-\d+)$/);
  return m ? m[1] : null;
}

/**
 * Scrape all pages of the website to retrieve the list of advisory IDs
 * https://security.paloaltonetworks.com/?page=N
 */
async function fetchAllAdvisoryIds(): Promise<string[]> {
  const ids = new Set<string>();
  const idPattern = /href="\/(CVE-\d{4}-\d+|PAN-SA-\d{4}-\d+)"/g;

  for (let page = 1; ; page++) {
    const { data } = await axios.get<string>(`${WEB_URL}/?page=${page}`, {
      timeout: 30000,
      headers: { 'User-Agent': 'heretix-api/1.0' },
      responseType: 'text',
    });

    const matches = [...data.matchAll(idPattern)].map(m => m[1]);
    if (matches.length === 0) break;

    matches.forEach(id => ids.add(id));
    logger.debug({ page, found: matches.length, total: ids.size }, 'Scraped PAN advisory page');
    await new Promise(r => setTimeout(r, 500));
  }

  return [...ids];
}

// ─── AdvisoryFetcher Implementation ──────────────────────────

export class PanFetcher implements AdvisoryFetcher {
  private readonly delayMs: number;
  private readonly mode: 'all' | 'latest';

  constructor({ delayMs = 1000, mode = 'all' as 'all' | 'latest' }: {
    delayMs?: number;
    mode?: 'all' | 'latest';
  } = {}) {
    this.delayMs = delayMs;
    this.mode    = mode;
  }

  source(): string { return 'paloalto'; }

  async fetch(): Promise<NormalizedAdvisory[]> {
    // Fetch the list of advisory IDs with their pubDate
    let advisoryEntries: Array<{ advisoryId: string; pubDate?: Date }>;

    if (this.mode === 'latest') {
      logger.info('Fetching Palo Alto Networks PSIRT RSS feed (latest)');
      const items = await fetchRssItems();
      logger.info({ count: items.length }, 'Fetched PAN RSS items');
      advisoryEntries = items.flatMap(item => {
        const advisoryId = extractAdvisoryId(item.link);
        if (!advisoryId) return [];
        return [{ advisoryId, pubDate: item.pubDate ? new Date(item.pubDate) : undefined }];
      });
    } else {
      logger.info('Fetching Palo Alto Networks PSIRT advisory list (all pages)');
      const ids = await fetchAllAdvisoryIds();
      logger.info({ count: ids.length }, 'Fetched PAN advisory IDs');
      advisoryEntries = ids.map(advisoryId => ({ advisoryId }));
    }

    const results: NormalizedAdvisory[] = [];
    let skipped = 0;
    let failed  = 0;

    for (const { advisoryId, pubDate } of advisoryEntries) {
      const url = `${CSAF_BASE}/${advisoryId}`;
      logger.debug({ advisoryId, url }, 'Fetching PAN CSAF JSON');

      const maxRetries = 3;
      let lastErr: unknown;
      let fetched = false;

      for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
          const { data } = await axios.get<CsafDocument>(url, {
            timeout: 15000,
            headers: { 'User-Agent': 'heretix-api/1.0' },
          });

          const advisory = parseCsaf(data, advisoryId, pubDate);

          if (advisory) {
            results.push(advisory);
          } else {
            logger.warn({ advisoryId }, 'No parseable vulnerability data in PAN CSAF');
            skipped++;
          }
          fetched = true;
          break;
        } catch (err) {
          lastErr = err;
          if (attempt < maxRetries) {
            const wait = 3000 * attempt;
            logger.warn({ advisoryId, attempt, wait }, 'PAN CSAF fetch failed, retrying');
            await new Promise(r => setTimeout(r, wait));
          }
        }
      }

      if (!fetched) {
        failed++;
        logger.error({ err: lastErr, advisoryId, url }, 'Failed to fetch/parse PAN CSAF after retries');
      }

      await new Promise(r => setTimeout(r, this.delayMs));
    }

    logger.info(
      { total: advisoryEntries.length, succeeded: results.length, skipped, failed },
      'PAN PSIRT fetch complete',
    );
    return results;
  }
}
