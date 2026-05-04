import axios from 'axios';
import { XMLParser } from 'fast-xml-parser';
import type { AdvisoryFetcher, NormalizedAdvisory } from './advisory-fetcher.js';
import { logger } from '../utils/logger.js';

const RSS_URL  = 'https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/rss-otn-sec.xml';
const CSAF_BASE = 'https://www.oracle.com/docs/tech/security-alerts';

// ─── CSAF Types (standard 2.0) ────────────────────────────────

interface CsafProduct {
  name: string;
  product_id: string;
  product_identification_helper?: { cpe?: string };
}

interface CsafBranch {
  category: string;
  name: string;
  branches?: CsafBranch[];
  product?: CsafProduct;
}

interface CsafVulnerability {
  cve?: string;
  notes?: Array<{ category: string; text: string }>;
  product_status?: { known_affected?: string[] };
  remediations?: Array<{ category: string; details: string }>;
  scores?: Array<{
    products: string[];
    cvss_v3?: { baseScore: number; baseSeverity: string; vectorString: string };
  }>;
}

interface CsafDocument {
  document: { title: string; tracking: { id: string; initial_release_date?: string } };
  product_tree: { branches: CsafBranch[] };
  vulnerabilities: CsafVulnerability[];
}

// ─── Utilities ─────────────────────────────────────────────────

/** Walk product_tree and build productId → product info map */
function buildProductMap(branches: CsafBranch[]): Map<string, { name: string; version: string | null }> {
  const map = new Map<string, { name: string; version: string | null }>();

  function walk(bs: CsafBranch[]) {
    for (const b of bs) {
      if (b.product?.product_id) {
        const fullName = b.product.name;
        // Extract version: look for semver-like or Oracle-version patterns at end of name
        const versionMatch = fullName.match(/[\s+](\d[\d.]+[a-z0-9]*)$/i)
          ?? fullName.match(/\s+v?(\d+\.\d[\d.]*\S*)$/i);
        const version = versionMatch ? versionMatch[1] : null;
        map.set(b.product.product_id, { name: fullName, version });
      }
      if (b.branches) walk(b.branches);
    }
  }

  walk(branches);
  return map;
}

/** Extract Oracle product family name by stripping "Oracle " prefix and version suffix */
function extractProductFamily(fullName: string): string {
  return fullName
    .replace(/^Oracle\s+/i, '')
    .replace(/\s+v?\d[\d.]*\S*$/i, '')
    .replace(/\s+Version\s*\S*$/i, '')
    .trim() || fullName;
}

// ─── RSS Parsing ───────────────────────────────────────────────

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

/** Convert advisory page URL to CSAF JSON URL */
function toCsafUrl(advisoryLink: string): string | null {
  // https://www.oracle.com/security-alerts/cpuapr2026.html
  // → https://www.oracle.com/docs/tech/security-alerts/cpuapr2026csaf.json
  const m = advisoryLink.match(/security-alerts\/(cpu\w+)\.html/);
  if (!m) return null;
  return `${CSAF_BASE}/${m[1]}csaf.json`;
}

// ─── CSAF Parsing ──────────────────────────────────────────────

function parseCsaf(csaf: CsafDocument, cpuId: string): NormalizedAdvisory[] {
  const productMap = buildProductMap(csaf.product_tree?.branches ?? []);
  const results: NormalizedAdvisory[] = [];

  for (const vuln of csaf.vulnerabilities ?? []) {
    const cveId = vuln.cve;
    if (!cveId) continue;

    // Extract CVSS
    let cvssScore: number | undefined;
    let cvssVector: string | undefined;
    let severity: string | undefined;
    for (const s of vuln.scores ?? []) {
      if (s.cvss_v3 && (!cvssScore || s.cvss_v3.baseScore > cvssScore)) {
        cvssScore  = s.cvss_v3.baseScore;
        cvssVector = s.cvss_v3.vectorString;
        severity   = s.cvss_v3.baseSeverity?.toUpperCase();
      }
    }

    const summaryNote = vuln.notes?.find(n => n.category === 'summary');

    // Build affectedProducts from known_affected product IDs
    const affectedProductIds = vuln.product_status?.known_affected ?? [];
    const seenProducts = new Set<string>();
    const affectedProducts: NormalizedAdvisory['affectedProducts'] = [];

    for (const pid of affectedProductIds) {
      const info = productMap.get(pid);
      if (!info) continue;
      const product = extractProductFamily(info.name);
      const key = `${product}:${info.version ?? ''}`;
      if (seenProducts.has(key)) continue;
      seenProducts.add(key);

      affectedProducts.push({
        vendor: 'oracle',
        product,
        affectedVersions: info.version ? [info.version] : [],
        patchAvailable: true,
      });
    }

    if (affectedProducts.length === 0) continue;

    results.push({
      externalId: `${cpuId}-${cveId}`,
      cveId,
      summary: summaryNote?.text?.trim() ?? `${cpuId.toUpperCase()}: ${cveId}`,
      severity,
      cvssScore,
      cvssVector,
      url: `https://www.oracle.com/security-alerts/${cpuId}.html`,
      publishedAt: csaf.document.tracking.initial_release_date
        ? new Date(csaf.document.tracking.initial_release_date)
        : undefined,
      affectedProducts,
      rawData: { cpuId, cve: cveId },
    });
  }

  return results;
}

// ─── AdvisoryFetcher Implementation ──────────────────────────

export class OracleCpuFetcher implements AdvisoryFetcher {
  private readonly delayMs: number;
  private readonly latestOnly: boolean;

  constructor({ delayMs = 1000, latestOnly = false } = {}) {
    this.delayMs = delayMs;
    this.latestOnly = latestOnly;
  }

  source(): string { return 'advisory-oracle-cpu'; }

  async fetch(): Promise<NormalizedAdvisory[]> {
    logger.info('Fetching Oracle CPU security advisories RSS');
    const rssItems = await fetchRssItems();
    // Filter to CPU advisories only (cpuXXXXYYYY pattern in link)
    let cpuItems = rssItems.filter(i => /\/cpu\w+\.html/.test(i.link ?? ''));
    if (this.latestOnly) cpuItems = cpuItems.slice(0, 1);
    logger.info({ total: rssItems.length, cpu: cpuItems.length }, 'Oracle RSS fetched');

    const results: NormalizedAdvisory[] = [];
    let failed = 0;

    for (const item of cpuItems) {
      const csafUrl = toCsafUrl(item.link);
      if (!csafUrl) continue;

      const cpuId = item.link.match(/security-alerts\/(cpu\w+)\.html/)?.[1] ?? 'unknown';

      try {
        logger.debug({ cpuId, csafUrl }, 'Fetching Oracle CPU CSAF');
        const { data: csaf } = await axios.get<CsafDocument>(csafUrl, {
          timeout: 60000,
          headers: { 'User-Agent': 'heretix-api/1.0', 'Accept': 'application/json' },
        });

        const advisories = parseCsaf(csaf, cpuId);
        results.push(...advisories);
        logger.info({ cpuId, count: advisories.length }, 'Oracle CPU CSAF parsed');
      } catch (err) {
        failed++;
        logger.warn({ cpuId, csafUrl, err }, 'Failed to fetch Oracle CPU CSAF, skipping');
      }

      await new Promise(r => setTimeout(r, this.delayMs));
    }

    logger.info({ total: results.length, csafFailed: failed }, 'Oracle CPU fetch complete');
    return results;
  }
}
