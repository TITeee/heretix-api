import axios from 'axios';
import { XMLParser } from 'fast-xml-parser';
import type { AdvisoryFetcher, NormalizedAdvisory } from './advisory-fetcher.js';
import { logger } from '../utils/logger.js';

const RSS_URL  = 'https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/rss-otn-sec.xml';
const CSAF_BASE = 'https://www.oracle.com/docs/tech/security-alerts';
const CVRF_BASE = 'https://www.oracle.com/docs/tech/security-alerts';
// Oracle's map of every CVE to the advisory that fixed it: it lists a new CPU, CSPU or
// Security Alert before the RSS feed does.
const MAPPING_URL = 'https://www.oracle.com/security-alerts/public-vuln-to-advisory-mapping.html';

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

/**
 * The advisories this fetcher reads, by the name of their page:
 * - the quarterly Critical Patch Update (cpuapr2026),
 * - the monthly Critical Security Patch Update between them (cspunov2026, 800 to
 *   1,000 CVEs a month in 2026),
 * - a Security Alert, out of cycle for one or two serious CVEs (alert-cve-2026-114820).
 * All three publish the same CSAF layout. A name is matched whole, so pages such as
 * cpuarchive or cpuapr2024verbose are not taken for advisories.
 */
const ADVISORY_ID = String.raw`(?:cpu|cspu)[a-z]{3}\d{4}|alert-cve-\d{4}-\d+`;

/** The advisory ids a feed or page links to, in the order they first appear, once each. */
export function advisoryIdsIn(text: string): string[] {
  const ids = new Set<string>();
  for (const m of text.matchAll(new RegExp(String.raw`security-alerts/(${ADVISORY_ID})\.html`, 'g'))) ids.add(m[1]);
  return [...ids];
}

/**
 * Where an advisory's CSAF is. A CPU's or CSPU's is named after it
 * (cpuoct2026csaf.json). A Security Alert's drops the "alert-": the page
 * alert-cve-2026-114820.html links cve-2026-114820csaf.json. Oracle has published
 * CSAF for CPUs since April 2022; recent alerts have one, older ones (Log4Shell's,
 * 2021) do not, and answer 404.
 */
export function csafUrlFor(id: string): string {
  return `${CSAF_BASE}/${id.replace(/^alert-/, '')}csaf.json`;
}

/**
 * Where a CPU's CVRF 1.1 XML is, for the quarters before CSAF: January 2020 through
 * April 2022 (confirmed by probing both formats across quarters; nothing structured
 * exists before January 2020). Null for every other advisory.
 */
export function cvrfUrlFor(id: string): string | null {
  const m = id.match(/^cpu[a-z]{3}(\d{4})$/);
  if (!m || Number(m[1]) < 2020 || Number(m[1]) > 2022) return null;
  return `${CVRF_BASE}/${id}cvrf.xml`;
}

async function fetchText(url: string): Promise<string> {
  const { data } = await axios.get<string>(url, {
    timeout: 60000,
    headers: { 'User-Agent': 'heretix-api/1.0' },
    responseType: 'text',
  });
  return data;
}

/** A document, or why there is none: missing (404) or an error that counts as a failure. */
type Fetched<T> = { data: T } | { data?: undefined; missing: boolean; error?: unknown };

async function fetchDocument<T>(url: string, kind: 'json' | 'text'): Promise<Fetched<T>> {
  try {
    const { data } = await axios.get<T>(url, {
      timeout: 60000,
      headers: kind === 'json'
        ? { 'User-Agent': 'heretix-api/1.0', 'Accept': 'application/json' }
        : { 'User-Agent': 'heretix-api/1.0' },
      ...(kind === 'text' ? { responseType: 'text' as const } : {}),
    });
    return { data };
  } catch (err) {
    return axios.isAxiosError(err) && err.response?.status === 404
      ? { missing: true }
      : { missing: false, error: err };
  }
}

// ─── CSAF Parsing ──────────────────────────────────────────────

export function parseCsaf(csaf: CsafDocument, cpuId: string): NormalizedAdvisory[] {
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

    // Oracle writes the text as one "description" note per affected product ("Vulnerability
    // in the Oracle APEX product ..."), never as "summary": reading "summary" alone left
    // every CSAF advisory with the placeholder below. The first description stands for all.
    const summaryNote = vuln.notes?.find(n => n.category === 'summary')
      ?? vuln.notes?.find(n => n.category === 'description' && n.text?.trim());

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

/**
 * The ids a CPU or CSPU of the last few months could have, newest first:
 * cspunov2026, cpunov2026... for each month, both kinds, since which months get which
 * is Oracle's to decide (2026 had a CPU in January, April, July and October and a
 * CSPU in May, June, August, September and November). The RSS feed lags: on
 * 18 November it still ended at 30 October, a day after cspunov2026 was published.
 * Asking for the ids directly closes that gap; a month with none answers 404.
 */
export function recentAdvisoryIds(now: Date, months = 3): string[] {
  const names = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];
  const ids: string[] = [];
  for (let back = 0; back < months; back++) {
    const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - back, 1));
    const suffix = `${names[d.getUTCMonth()]}${d.getUTCFullYear()}`;
    ids.push(`cspu${suffix}`, `cpu${suffix}`);
  }
  return ids;
}

// ─── AdvisoryFetcher Implementation ──────────────────────────

export class OracleCpuFetcher implements AdvisoryFetcher {
  private readonly delayMs: number;
  private readonly latestOnly: boolean;
  private readonly now: () => Date;
  private fetchFailed = 0;

  constructor({ delayMs = 1000, latestOnly = false, now = () => new Date() } = {}) {
    this.delayMs = delayMs;
    this.latestOnly = latestOnly;
    this.now = now;
  }

  source(): string { return 'advisory-oracle-cpu'; }
  isCompleteSnapshot(): boolean { return !this.latestOnly; }
  fetchFailedCount(): number { return this.fetchFailed; }

  async fetch(): Promise<NormalizedAdvisory[]> {
    this.fetchFailed = 0;

    // Which advisories exist, from two lists: the RSS feed lags (on 18 November it
    // still ended on 30 October, a day after cspunov2026 came out), Oracle's map of
    // CVEs to advisories had it already. Either may fail on its own; both failing
    // fails the run.
    let rssIds: string[] = [];
    let rssError: unknown;
    try {
      const items = await fetchRssItems();
      rssIds = advisoryIdsIn(items.map(i => i.link ?? '').join('\n'));
    } catch (err) {
      rssError = err;
    }

    // `latest`: the newest CPU or CSPU in the feed, nothing else.
    if (this.latestOnly) {
      if (rssError) throw rssError;
      const latest = rssIds.find(id => !id.startsWith('alert-'));
      return this.read(latest ? [latest] : []);
    }

    let mapIds: string[] = [];
    try {
      mapIds = advisoryIdsIn(await fetchText(MAPPING_URL));
    } catch (err) {
      if (rssError) throw rssError;
      this.fetchFailed++;
      logger.warn({ err }, "Failed to fetch Oracle's CVE to advisory map; listing advisories from the RSS feed alone");
    }
    if (rssError) {
      this.fetchFailed++;
      logger.warn({ err: rssError }, "Failed to fetch Oracle's security RSS feed; listing advisories from the CVE map alone");
    }

    // And the CPU and CSPU of the last months by name, in case neither list has them yet.
    const ids = [...new Set([...rssIds, ...mapIds, ...recentAdvisoryIds(this.now())])];
    logger.info({ rss: rssIds.length, map: mapIds.length, total: ids.length }, 'Oracle advisories listed');
    return this.read(ids);
  }

  /**
   * Each advisory's CSAF, or the CVRF of a CPU from 2020 to 2022. An id with neither
   * (404: a month with no advisory, an alert or a CPU from before Oracle published
   * structured data) is skipped; any other error counts as a failed fetch.
   */
  private async read(ids: string[]): Promise<NormalizedAdvisory[]> {
    const results: NormalizedAdvisory[] = [];
    for (const id of ids) {
      const csaf = await fetchDocument<CsafDocument>(csafUrlFor(id), 'json');
      if (csaf.data !== undefined) {
        const advisories = parseCsaf(csaf.data, id);
        results.push(...advisories);
        logger.info({ id, count: advisories.length }, 'Oracle advisory CSAF parsed');
      } else {
        const cvrfUrl = cvrfUrlFor(id);
        const cvrf: Fetched<string> = cvrfUrl ? await fetchDocument<string>(cvrfUrl, 'text') : { missing: true };
        if (cvrf.data !== undefined) {
          const advisories = parseCvrf(cvrf.data, id);
          results.push(...advisories);
          logger.info({ id, count: advisories.length }, 'Oracle advisory CVRF parsed');
        } else if (csaf.missing && cvrf.missing) {
          logger.debug({ id }, 'No structured Oracle advisory with this id');
        } else {
          this.fetchFailed++;
          logger.warn({ id, err: csaf.error ?? cvrf.error }, 'Failed to fetch an Oracle advisory');
        }
      }
      await new Promise(r => setTimeout(r, this.delayMs));
    }
    logger.info({ total: results.length, failed: this.fetchFailed }, 'Oracle advisories fetched');
    return results;
  }
}
