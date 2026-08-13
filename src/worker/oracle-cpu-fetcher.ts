import axios from 'axios';
import { XMLParser } from 'fast-xml-parser';
import type { AdvisoryFetcher, NormalizedAdvisory } from './advisory-fetcher.js';
import { logger } from '../utils/logger.js';

const RSS_URL  = 'https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/rss-otn-sec.xml';
const CSAF_BASE = 'https://www.oracle.com/docs/tech/security-alerts';
const CVRF_BASE = 'https://www.oracle.com/docs/tech/security-alerts';

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

/**
 * Convert advisory page URL to CVRF XML URL.
 * Oracle only started publishing CSAF JSON from CPUApr2022 onward; CPUs from
 * CPUJan2020 through CPUApr2022 only have the older CVRF 1.1 XML format
 * (confirmed by probing both endpoints across quarters — neither format
 * exists for anything before CPUJan2020, which would require scraping the
 * legacy HTML advisory pages instead).
 */
function toCvrfUrl(advisoryLink: string): string | null {
  const m = advisoryLink.match(/security-alerts\/(cpu\w+)\.html/);
  if (!m) return null;
  return `${CVRF_BASE}/${m[1]}cvrf.xml`;
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

// ─── CVRF 1.1 XML Parsing (CPUJan2020–CPUApr2022) ────────────

interface CvrfBranch {
  '@_Name'?: string;
  '@_Type'?: string;
  Branch?: CvrfBranch | CvrfBranch[];
  FullProductName?: { '#text'?: string; '@_ProductID'?: string } | { '#text'?: string; '@_ProductID'?: string }[];
}

interface CvrfVulnerability {
  CVE?: string;
  Notes?: { Note?: { '#text'?: string; '@_Type'?: string } | { '#text'?: string; '@_Type'?: string }[] };
  ProductStatuses?: { Status?: { '@_Type'?: string; ProductID?: string | string[] } | { '@_Type'?: string; ProductID?: string | string[] }[] };
  CVSSScoreSets?: { ScoreSet?: { BaseScore?: number; Vector?: string } | { BaseScore?: number; Vector?: string }[] };
}

interface CvrfDocument {
  DocumentTracking?: { InitialReleaseDate?: string };
  ProductTree?: CvrfBranch;
  Vulnerability?: CvrfVulnerability | CvrfVulnerability[];
}

function asArray<T>(v: T | T[] | undefined): T[] {
  if (v === undefined) return [];
  return Array.isArray(v) ? v : [v];
}

/** CVSS v3 base-score → severity band (CVRF has no severity label field, unlike CSAF) */
export function severityFromScore(score: number | undefined): string | undefined {
  if (score === undefined) return undefined;
  if (score >= 9.0) return 'CRITICAL';
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MEDIUM';
  if (score > 0)    return 'LOW';
  return undefined;
}

/**
 * Walk the CVRF ProductTree, tracking the nearest ancestor "Product Name"
 * branch (the product family, e.g. "Communications ASAP Cartridges") and
 * "Product Version" branch (e.g. "7.2") to build ProductID → {product,
 * version}. Unlike CSAF's buildProductMap, versions are explicit branch
 * attributes here, not regex-extracted from a combined display name.
 */
export function buildCvrfProductMap(root: CvrfBranch | undefined): Map<string, { product: string; version: string | null }> {
  const map = new Map<string, { product: string; version: string | null }>();
  if (!root) return map;

  function walk(branch: CvrfBranch, productName: string | null, version: string | null) {
    const nextProductName = branch['@_Type'] === 'Product Name' ? (branch['@_Name'] ?? productName) : productName;
    const nextVersion     = branch['@_Type'] === 'Product Version' ? (branch['@_Name'] ?? version) : version;

    for (const fp of asArray(branch.FullProductName)) {
      if (fp['@_ProductID'] && nextProductName) {
        map.set(fp['@_ProductID'], { product: nextProductName, version: nextVersion });
      }
    }
    for (const sub of asArray(branch.Branch)) {
      walk(sub, nextProductName, nextVersion);
    }
  }

  walk(root, null, null);
  return map;
}

export function parseCvrf(xml: string, cpuId: string): NormalizedAdvisory[] {
  const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '@_' });
  const parsed = parser.parse(xml);
  const doc: CvrfDocument | undefined = parsed['cvrf:cvrfdoc'] ?? parsed.cvrfdoc;
  if (!doc) return [];

  const productMap = buildCvrfProductMap(doc.ProductTree);
  const publishedAt = doc.DocumentTracking?.InitialReleaseDate
    ? new Date(doc.DocumentTracking.InitialReleaseDate)
    : undefined;

  // A single CVE can be split across multiple <Vulnerability> elements in the
  // same document — e.g. one CPU saw the same CVE appear 6 times, each
  // covering a different affected-product subset. Group by CVE first so
  // later occurrences add to the affected-product list instead of each
  // becoming its own NormalizedAdvisory with the same externalId, which
  // would otherwise silently drop earlier occurrences' products via
  // importAdvisoryData()'s delete-then-recreate upsert.
  const byCve = new Map<string, CvrfVulnerability[]>();
  for (const vuln of asArray(doc.Vulnerability)) {
    if (!vuln.CVE) continue;
    const group = byCve.get(vuln.CVE) ?? [];
    group.push(vuln);
    byCve.set(vuln.CVE, group);
  }

  const results: NormalizedAdvisory[] = [];

  for (const [cveId, group] of byCve) {
    let cvssScore: number | undefined;
    let cvssVector: string | undefined;
    let detailsText: string | undefined;

    const affectedProducts: NormalizedAdvisory['affectedProducts'] = [];
    const seen = new Set<string>();

    for (const vuln of group) {
      for (const s of asArray(vuln.CVSSScoreSets?.ScoreSet)) {
        const score = typeof s.BaseScore === 'number' ? s.BaseScore : parseFloat(String(s.BaseScore ?? ''));
        if (!isNaN(score) && (!cvssScore || score > cvssScore)) {
          cvssScore  = score;
          cvssVector = s.Vector;
        }
      }

      if (!detailsText) {
        const detailsNote = asArray(vuln.Notes?.Note).find(n => n['@_Type'] === 'Details');
        detailsText = detailsNote?.['#text']?.trim();
      }

      for (const status of asArray(vuln.ProductStatuses?.Status)) {
        if (status['@_Type'] !== 'Known Affected') continue;
        for (const pid of asArray(status.ProductID)) {
          const info = productMap.get(pid);
          if (!info) continue;
          const key = `${info.product}:${info.version ?? ''}`;
          if (seen.has(key)) continue;
          seen.add(key);

          affectedProducts.push({
            vendor: 'oracle',
            product: info.product,
            affectedVersions: info.version ? [info.version] : [],
            patchAvailable: true,
          });
        }
      }
    }

    if (affectedProducts.length === 0) continue;

    results.push({
      externalId: `${cpuId}-${cveId}`,
      cveId,
      summary: detailsText ?? `${cpuId.toUpperCase()}: ${cveId}`,
      severity: severityFromScore(cvssScore),
      cvssScore,
      cvssVector,
      url: `https://www.oracle.com/security-alerts/${cpuId}.html`,
      publishedAt,
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
  private fetchFailed = 0;

  constructor({ delayMs = 1000, latestOnly = false } = {}) {
    this.delayMs = delayMs;
    this.latestOnly = latestOnly;
  }

  source(): string { return 'advisory-oracle-cpu'; }
  isCompleteSnapshot(): boolean { return !this.latestOnly; }
  fetchFailedCount(): number { return this.fetchFailed; }

  async fetch(): Promise<NormalizedAdvisory[]> {
    this.fetchFailed = 0;
    logger.info('Fetching Oracle CPU security advisories RSS');
    const rssItems = await fetchRssItems();
    // Filter to CPU advisories only (cpuXXXXYYYY pattern in link)
    let cpuItems = rssItems.filter(i => /\/cpu\w+\.html/.test(i.link ?? ''));
    if (this.latestOnly) cpuItems = cpuItems.slice(0, 1);
    logger.info({ total: rssItems.length, cpu: cpuItems.length }, 'Oracle RSS fetched');

    const results: NormalizedAdvisory[] = [];

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
        await new Promise(r => setTimeout(r, this.delayMs));
        continue;
      } catch {
        // Fall through to CVRF below — CSAF isn't published for CPUs before
        // CPUApr2022 (confirmed by probing), not just a transient failure.
      }

      // CSAF unavailable: try the older CVRF 1.1 XML format (CPUJan2020–CPUApr2022).
      const cvrfUrl = toCvrfUrl(item.link);
      if (cvrfUrl) {
        try {
          logger.debug({ cpuId, cvrfUrl }, 'CSAF unavailable, fetching Oracle CPU CVRF');
          const { data: cvrfXml } = await axios.get<string>(cvrfUrl, {
            timeout: 60000,
            headers: { 'User-Agent': 'heretix-api/1.0' },
            responseType: 'text',
          });

          const advisories = parseCvrf(cvrfXml, cpuId);
          results.push(...advisories);
          logger.info({ cpuId, count: advisories.length }, 'Oracle CPU CVRF parsed');
        } catch (err) {
          this.fetchFailed++;
          logger.warn({ cpuId, cvrfUrl, err }, 'Failed to fetch Oracle CPU CSAF/CVRF, skipping (likely pre-2020, no structured data available)');
        }
      } else {
        this.fetchFailed++;
      }

      await new Promise(r => setTimeout(r, this.delayMs));
    }

    logger.info({ total: results.length, failed: this.fetchFailed }, 'Oracle CPU fetch complete');
    return results;
  }
}
