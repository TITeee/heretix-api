import axios from 'axios';
import { XMLParser } from 'fast-xml-parser';
import type { AdvisoryFetcher, NormalizedAdvisory } from './advisory-fetcher.js';
import { logger } from '../utils/logger.js';
import {
  type PanVersion,
  comparePanVersions,
  formatPanRelease,
  nextPanMaintenanceLine,
  panBranch,
  parsePanVersion,
} from '../utils/pan-version.js';

const RSS_URL  = 'https://security.paloaltonetworks.com/rss.xml';
const WEB_URL  = 'https://security.paloaltonetworks.com';
const CSAF_BASE = 'https://security.paloaltonetworks.com/csaf';

// ─── CSAF 2.0 Type Definitions ───────────────────────────────

export interface CsafDocument {
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
  name: string;           // the branch's own name, e.g. "PAN-OS 10.2 All"
  op: string | null;      // '<', '<=', '>=', '>', or null for a discrete/no-version entry
  version: string | null;
}

/**
 * Build a map from product_id to version range info from product_tree.
 * PAN CSAF documents mix two branch shapes under the same product_name:
 *   - `product_version_range`, name like "vers:generic/<12.1.4" or
 *     "vers:generic/PAN-OS Firewall>=11.2.10" -- a real range, captured as before.
 *   - `product_version` (discrete, no range), name like "Prisma Access Agent 0"
 *     or "Prisma Access Agent All" -- CSAF's placeholder for "affected, no
 *     specific version boundary" (paired with a separate `>=` "fixed" entry
 *     elsewhere in the tree that carries the real upper bound). These
 *     product_ids use an internal scheme ("PANW-Prisma-Access-Agent-3") that
 *     doesn't contain the product name or a version number at all, so unlike
 *     the range case there's nothing to parse out of the name -- record them
 *     with op/version null rather than skipping them, so the caller still
 *     recognizes the product_id (via productMap.has()) and routes the whole
 *     advisory through the range-aware path instead of falling through to
 *     legacy product-id string-matching, which can't resolve these IDs to a
 *     product name at all and silently drops the entire advisory as
 *     unparseable -- confirmed this affected ~46% of PAN's CVE advisories.
 *
 * One product_id can carry several branches: PAN reuses the same id for a
 * "<10.2.0-h3" and a ">=10.2.0-h3" branch (the two sides of one fix point),
 * so every branch is kept rather than the last one overwriting the others.
 */
function buildProductMap(branches: CsafBranch[]): Map<string, ProductRangeInfo[]> {
  const map = new Map<string, ProductRangeInfo[]>();
  const add = (id: string, info: ProductRangeInfo) => map.set(id, [...(map.get(id) ?? []), info]);
  function walk(bs: CsafBranch[], parentProductName?: string) {
    for (const b of bs) {
      const productName = b.category === 'product_name' ? b.name : parentProductName;
      if (b.product?.product_id && productName) {
        // "vers:generic/<12.1.4", "vers:generic/PAN-OS>=10.2.9-h1",
        // "vers:generic/GlobalProtect App<6.3.3-h2 (6.3.3-c676)". The version is
        // everything after the operator -- a digits-and-dots-only capture used to
        // drop every hotfix bound (829 of the feed's 2,090 range entries).
        const m = b.name.match(/([<>]=?)(\d[^<>]*)$/);
        if (m) {
          add(b.product.product_id, { productName, name: b.name, op: m[1], version: m[2].trim() });
        } else if (b.category === 'product_version' || b.category === 'product_version_range') {
          add(b.product.product_id, { productName, name: b.name, op: null, version: null });
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
 * Derive the next minor branch as an exclusive upper bound.
 * "11.1" → "11.2", "10.2" → "10.3"
 * Used when no versionFixed is found, to prevent unbounded range matching.
 */
function nextMinorBranch(branch: string): string | undefined {
  const parts = branch.split('.');
  if (parts.length < 2) return undefined;
  const minor = parseInt(parts[1], 10);
  if (isNaN(minor)) return undefined;
  return `${parts[0]}.${minor + 1}`;
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

// ─── Fix points → affected ranges ────────────────────────────

type AffectedRow = NormalizedAdvisory['affectedProducts'][number];

interface ProductStatusFacts {
  fixPoints: Array<{ raw: string; v: PanVersion }>;
  starts: Array<{ raw: string; v: PanVersion | null }>;
  wholeBranches: PanVersion[];
  lastAffected: string[];
  hasAffectedEntry: boolean;
  scoped: boolean;
}

// "PAN-OS 10.1 All" -- a whole branch listed by version, as opposed to the
// version-less "Cloud NGFW All" PAN uses for SaaS products.
const VERSIONED_BRANCH_NAME = /\s(\d+(?:\.\d+)*(?:-CE)?)\s+All$/;

// PAN copies its advisory table's "Affected" column into known_affected even
// when that column says "None" ("PAN-OS None", "Cortex XDR Agent 8.5 None"),
// with the "Unaffected: All" side in known_not_affected. Such an entry means
// *not* affected; read literally it used to become an unbounded "unfixed" row
// that matched every version of the product (CVE-2024-6387 on PAN-OS).
const NONE_ENTRY_NAME = /\sNone$/;

function collectFacts(v: CsafVulnerability, productMap: Map<string, ProductRangeInfo[]>): Map<string, ProductStatusFacts> {
  const facts = new Map<string, ProductStatusFacts>();
  const factsFor = (product: string) => {
    let f = facts.get(product);
    if (!f) {
      f = { fixPoints: [], starts: [], wholeBranches: [], lastAffected: [], hasAffectedEntry: false, scoped: false };
      facts.set(product, f);
    }
    return f;
  };
  const addFixPoint = (f: ProductStatusFacts, raw: string) => {
    const parsed = parsePanVersion(raw);
    // An unorderable bound ("<All", "<5.1*") is dropped rather than turned
    // into an unbounded row -- see affectedRangesFromStatus().
    if (parsed && !f.fixPoints.some(p => comparePanVersions(p.v, parsed) === 0)) f.fixPoints.push({ raw, v: parsed });
  };

  for (const pid of v.product_status?.known_affected ?? []) {
    const infos = productMap.get(pid) ?? [];
    const hasUpper = infos.some(i => i.op === '<');
    for (const info of infos) {
      if (info.op === null && NONE_ENTRY_NAME.test(info.name)) continue;
      const f = factsFor(info.productName);
      f.hasAffectedEntry = true;
      if (info.op === null) {
        const branch = info.name.match(VERSIONED_BRANCH_NAME)?.[1];
        const parsed = branch ? parsePanVersion(branch) : null;
        if (parsed) {
          f.wholeBranches.push(parsed);
          f.scoped = true;
        }
        continue;
      }
      if (!info.version) continue;
      if (info.op === '<') addFixPoint(f, info.version);
      else if (info.op === '<=') f.lastAffected.push(info.version);
      // A ">=" that is only the upper half of a "<X"/">=X" pair is that pair's
      // fix point, already recorded via "<"; on its own it is where the
      // affected range starts (CVE-2020-2035: ">=9.0.0", no fix at all).
      else if ((info.op === '>=' || info.op === '>') && !hasUpper) {
        f.starts.push({ raw: info.version, v: parsePanVersion(info.version) });
        f.scoped = true;
      }
    }
  }
  for (const pid of v.product_status?.fixed ?? []) {
    for (const info of productMap.get(pid) ?? []) {
      if ((info.op === '>=' || info.op === '>') && info.version) addFixPoint(factsFor(info.productName), info.version);
    }
  }
  for (const pid of v.product_status?.known_not_affected ?? []) {
    for (const info of productMap.get(pid) ?? []) {
      if (info.op !== null || VERSIONED_BRANCH_NAME.test(info.name)) factsFor(info.productName).scoped = true;
    }
  }
  return facts;
}

/**
 * Turn one CSAF vulnerability's product_status into affected ranges.
 *
 * PAN fixes each maintenance release separately with a hotfix, and lists every
 * one of them as its own fix point: CVE-2025-0126's PAN-OS 10.2 row is
 * "< 10.2.4-h25, < 10.2.9-h13, < 10.2.10-h6, >= 10.2.11". Within a branch
 * (M.m) the fix points f1 < f2 < ... therefore mean
 *   affected = [start, f1) ∪ [line after f1, f2) ∪ ...
 * where "line after 10.2.4-h25" is 10.2.5 -- 10.2.5 is *not* fixed even though
 * it orders above 10.2.4-h25; its own fix is 10.2.9-h13. A single
 * "< fixed" range per product (the previous reading) called every later
 * maintenance release fixed, and every earlier branch affected.
 *
 * A fix point is either side of how PAN spells it: a "<X" under known_affected
 * or a ">=X" under fixed -- the feed uses both, often for the same X under one
 * shared product_id.
 *
 * Where a branch's range starts:
 *  - an explicit ">=X" under known_affected, when there is one in the branch;
 *  - otherwise the branch's first release ("M.m.0") -- PAN's version table
 *    lists branches individually, so a fix in 10.2 says nothing about 10.1;
 *  - except for the lowest branch when nothing in the advisory says branches
 *    are listed individually (no explicit start, no versioned not-affected
 *    entry, e.g. Prisma Browser's "<135.16.8.96"): that one stays unbounded
 *    below, as before, rather than dropping everything older.
 */
function affectedRangesFromStatus(v: CsafVulnerability, productMap: Map<string, ProductRangeInfo[]>): AffectedRow[] {
  const rows: AffectedRow[] = [];

  for (const [product, f] of collectFacts(v, productMap)) {
    if (!f.hasAffectedEntry) continue;
    const productRows: AffectedRow[] = [];

    const byBranch = new Map<string, PanVersion[]>();
    const rawOf = new Map<string, string>();
    for (const p of [...f.fixPoints].sort((a, b) => comparePanVersions(a.v, b.v))) {
      const list = byBranch.get(panBranch(p.v)) ?? [];
      list.push(p.v);
      byBranch.set(panBranch(p.v), list);
      rawOf.set(JSON.stringify(p.v), p.raw);
    }
    const branchStarts = new Map<string, PanVersion>();
    for (const s of f.starts) {
      if (!s.v) continue;
      const existing = branchStarts.get(panBranch(s.v));
      if (!existing || comparePanVersions(s.v, existing) < 0) branchStarts.set(panBranch(s.v), s.v);
    }

    let lowest = true;
    for (const [branch, fixes] of byBranch) {
      let cur: PanVersion | undefined = branchStarts.get(branch)
        ?? (lowest && !f.scoped ? undefined : { ...fixes[0], patch: 0, sub: 0 });
      lowest = false;
      for (const fix of fixes) {
        if (!cur || comparePanVersions(cur, fix) < 0) {
          const raw = rawOf.get(JSON.stringify(fix))!;
          productRows.push({
            vendor: 'paloalto',
            product,
            versionStart: cur ? formatPanRelease(cur) : undefined,
            versionEnd: raw,
            versionFixed: raw,
            patchAvailable: true,
          });
        }
        cur = nextPanMaintenanceLine(fix);
      }
    }

    // A start with no fix point in its own branch: affected from there with no
    // fix. Capped at the next branch when other branches do have fixes (their
    // fixed releases are not affected); left open-ended when the advisory has
    // no fix at all (CVE-2020-2035, a design limitation with only a workaround).
    for (const s of f.starts) {
      // A start this module cannot order would be stored as a row with no
      // encodable bound at all -- i.e. unfixed and matching every version.
      if (!s.v || byBranch.has(panBranch(s.v))) continue;
      productRows.push({
        vendor: 'paloalto',
        product,
        versionStart: s.raw,
        versionEnd: byBranch.size > 0 ? `${s.v.major}.${s.v.minor + 1}.0` : undefined,
        lastAffected: undefined,
        versionFixed: undefined,
        patchAvailable: false,
      });
    }

    // "PAN-OS 10.1 All" under known_affected: the whole branch, no fix.
    for (const b of f.wholeBranches) {
      if (byBranch.has(panBranch(b))) continue;
      productRows.push({
        vendor: 'paloalto',
        product,
        versionStart: formatPanRelease({ ...b, patch: 0, sub: 0 }),
        versionEnd: `${b.major}.${b.minor + 1}.0`,
        patchAvailable: false,
      });
    }

    for (const la of f.lastAffected) {
      productRows.push({ vendor: 'paloalto', product, lastAffected: la, patchAvailable: f.fixPoints.length > 0 });
    }

    // Only discrete "affected" entries (or bounds too irregular to order) and
    // nothing usable: one row with no range, as before. patchAvailable false
    // makes it match every queried version (UNFIXED_NO_RANGE_WHERE) -- correct
    // for "Cloud NGFW All", and the only honest reading when there is truly
    // nothing to compare against.
    if (productRows.length === 0) {
      productRows.push({ vendor: 'paloalto', product, patchAvailable: f.fixPoints.length > 0 });
    }
    rows.push(...productRows);
  }
  return rows;
}

// ─── CSAF → NormalizedAdvisory Conversion ────────────────────

export function parseCsaf(csaf: CsafDocument, advisoryId: string, pubDate?: Date): NormalizedAdvisory | null {
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
    const seenRows = new Set<string>();
    for (const v of vulns) {
      for (const row of affectedRangesFromStatus(v, productMap)) {
        const key = JSON.stringify(row);
        if (seenRows.has(key)) continue;
        seenRows.add(key);
        affectedProducts.push(row);
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
          // Set exclusive upper bound: versionFixed if known, otherwise next minor branch.
          // Without this, the range is unbounded (+∞) and would incorrectly match future versions.
          const versionEnd = versionFixed ?? nextMinorBranch(branch);
          affectedProducts.push({
            vendor: 'paloalto',
            product: name,
            versionStart: versionPart,
            versionEnd,
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
  private fetchFailed = 0;

  constructor({ delayMs = 1000, mode = 'all' as 'all' | 'latest' }: {
    delayMs?: number;
    mode?: 'all' | 'latest';
  } = {}) {
    this.delayMs = delayMs;
    this.mode    = mode;
  }

  source(): string { return 'paloalto'; }
  isCompleteSnapshot(): boolean { return this.mode === 'all'; }
  fetchFailedCount(): number { return this.fetchFailed; }

  async fetch(): Promise<NormalizedAdvisory[]> {
    this.fetchFailed = 0;
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
        this.fetchFailed++;
        logger.error({ err: lastErr, advisoryId, url }, 'Failed to fetch/parse PAN CSAF after retries');
      }

      await new Promise(r => setTimeout(r, this.delayMs));
    }

    logger.info(
      { total: advisoryEntries.length, succeeded: results.length, skipped, failed: this.fetchFailed },
      'PAN PSIRT fetch complete',
    );
    return results;
  }
}
