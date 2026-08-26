import axios from 'axios';
import type { AdvisoryFetcher, NormalizedAdvisory } from './advisory-fetcher.js';
import { logger } from '../utils/logger.js';
import { withPage, closeBrowser } from '../utils/browser.js';

const LIST_API =
  'https://support.broadcom.com/web/ecx/security-advisory/-/securityadvisory/getSecurityAdvisoryList';

// Broadcom segments to query. "VC" covers VMware Cloud Foundation / VMware products (VMSA series).
const SEGMENTS = ['VC'];

const PAGE_SIZE = 50;
const DELAY_MS = 1000;

// ─── API Types (verified against live response) ────────────────

interface BroadcomApiItem {
  documentId: string;       // "VCDSA36947"
  notificationId: number;   // 36947
  published: string;        // "24 February 2026"
  status: string;           // "OPEN" | "CLOSED"
  title: string;            // "VMSA-2026-0001: VMware Aria Operations updates..."
  updated: string;
  notificationUrl: string;  // full URL to advisory detail
  alertType: string;
  severity: string;         // "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
  supportProducts: string;  // comma-separated, may be truncated: "VCF Operations,VCF Operat..."
  affectedCve: string;      // "CVE-2026-22719, CVE-2026-22720 and CVE-2026-22721"
  workAround: string;
}

interface BroadcomApiResponse {
  success: boolean;
  data: {
    list: BroadcomApiItem[];
    pageInfo: {
      totalCount: number;
      currentPage: number;
      lastPage: number;
      pageSize: number;
      nextPage: number;
    };
  };
}

// ─── Types ─────────────────────────────────────────────────────

// A wildcard/bare-prefix branch ("9.1.x.x", "8.0") becomes a range; a discrete
// non-numeric release token ("25H2") has no meaningful range and is kept as-is.
type AffectedRange = { versionStart: string; versionEnd: string } | { exact: string };

interface ProductVersion {
  product: string;
  fixed: string[];
  affected?: AffectedRange[];
}

// ─── Utilities ─────────────────────────────────────────────────

function normalizeSeverity(s: string | undefined): string | undefined {
  if (!s) return undefined;
  const upper = s.toUpperCase();
  return ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(upper) ? upper : undefined;
}

function extractCveIds(raw: string): string[] {
  const matches = raw.match(/CVE-\d{4}-\d+/g);
  return matches ? [...new Set(matches)] : [];
}

/** "24 February 2026" → Date */
function parsePublishedDate(s: string): Date | undefined {
  if (!s) return undefined;
  const m = s.match(/^(\d{1,2})\s+(\w+)\s+(\d{4})$/);
  if (!m) return undefined;
  const d = new Date(`${m[2]} ${m[1]}, ${m[3]}`);
  return isNaN(d.getTime()) ? undefined : d;
}

/** Extract VMSA ID from title: "VMSA-2024-0012: VMware vCenter Server..." → "VMSA-2024-0012" */
function extractVmsaId(title: string): string | undefined {
  const m = title.match(/VMSA-\d{4}-\d+/i);
  return m ? m[0].toUpperCase() : undefined;
}

/**
 * Parse product names from `supportProducts` (comma-separated, may be truncated).
 * Filters out truncated trailing entries ending with "...".
 */
function parseProductNames(raw: string): string[] {
  if (!raw) return [];
  return raw.split(',')
    .map(s => s.trim())
    .filter(s => s && !s.endsWith('...') && s.length > 2);
}

/**
 * True when a candidate fixed-version string actually looks like a version,
 * rather than prose ("Contact Broadcom Support if you have extended support
 * contract.") or a KB article reference ("KB449886", "Async Patching Guide:
 * KB88287") that happens to sit in the Fixed Version column. Broadcom uses
 * three shapes across the Response Matrix: a dotted decimal ("9.0.2.0100",
 * "8.0 U3k"), an ESXi build id ("ESXi80U3k-25595708"), or a Workstation/Fusion
 * year-half release ("26H1").
 */
function isVersionLike(v: string): boolean {
  if (!v || /n\/a|see\s+note/i.test(v)) return false;
  return /\d+\.\d+/.test(v) || /^ESXi[\w.-]*-\d+$/i.test(v) || /^\d{2}H\d$/i.test(v);
}

/**
 * Cleans and expands one Response Matrix row (raw product cell + raw fixed-version
 * cell, as scraped by fetchDetailVersions) into its product/version pairs, or null
 * when the row names no product at all.
 *
 * A single cell can list several products together — e.g. "VMware Cloud
 * Foundation, VMware vSphere Foundation" — which means each of those products is
 * fixed at that version, not that there's one combined product by that name.
 * The fixed-version cell can likewise list several versions ("ESXi80U3i-25205845
 * or ESXi80U3j-25429389"). Broadcom also marks some fixed versions with a
 * footnote reference ("[1] 9.1.0.0300") that isn't part of the version string.
 *
 * A product is kept even when fixedVersions comes back empty — e.g. VMware Telco
 * Cloud Platform/Infrastructure route their Fixed Version column through a KB
 * article reference ("KB449886") instead of a version number. The row still
 * names the product as affected; dropping it because the version text isn't
 * parseable would silently remove a real affected product rather than just
 * leaving its version unknown. The caller (fetchDetailVersions) is what turns an
 * empty fixedVersions into the existing "no known fixed version" fallback used
 * for products found via other means (buildBroadcomAdvisories' patchAvailable:
 * false branch).
 */
export function parseResponseMatrixRow(
  rawProduct: string,
  rawFixedVer: string,
): { products: string[]; fixedVersions: string[] } | null {
  const products = rawProduct.split(/[,+]/).map(s => s.trim()).filter(Boolean);
  if (products.length === 0 || !rawFixedVer.trim()) return null;

  const fixedVersions = rawFixedVer
    .split(/\s+or\s+/i)
    .map(v => v.replace(/^\[\d+\]\s*/, '').trim())
    .filter(isVersionLike);

  return { products, fixedVersions };
}

/**
 * Parses the Response Matrix "Version" column — the affected version, as
 * distinct from "Fixed Version" — into one range/token per comma-separated
 * candidate.
 *
 * Observed shapes: a wildcard branch ("9.1.x.x", "5.x"), a bare major.minor
 * understood the same way ("8.0" means "the whole 8.0.x branch", consistent
 * with how it pairs with patch-level Fixed Version entries like "8.0 U3k"), a
 * discrete non-numeric release token ("25H2"), or "Any" (no constraint —
 * omitted from the result entirely). A cell can list several of these
 * ("3.0, 4.x, 5.0.x, 5.1.x" for VMware Telco Cloud Platform); each describes
 * its own distinct affected range, not one combined range, so each becomes a
 * separate entry — the caller is expected to produce one AdvisoryAffectedProduct
 * row per entry, since versionStart/versionEnd can only hold one range each.
 */
export function parseAffectedVersionCell(raw: string): AffectedRange[] {
  return raw
    .split(',')
    .map(s => s.trim())
    .filter(Boolean)
    .filter(s => !/^any$/i.test(s))
    .filter(s => !/n\/a|see\s+note/i.test(s))
    .map((token): AffectedRange => {
      if (!/^\d+(\.(?:\d+|[xX]))*$/.test(token)) {
        return { exact: token };
      }
      // Strip trailing wildcard segments ("9.1.x.x" -> "9.1") to get the
      // concrete branch, then bump its last component for the exclusive
      // upper bound ("9.1" -> versionEnd "9.2").
      const parts = token.split('.');
      while (parts.length > 1 && /^[xX]$/.test(parts[parts.length - 1])) {
        parts.pop();
      }
      const versionStart = parts.join('.');
      const bumped = [...parts];
      bumped[bumped.length - 1] = String(Number(bumped[bumped.length - 1]) + 1);
      return { versionStart, versionEnd: bumped.join('.') };
    });
}

/**
 * Builds one affectedProducts entry for a (product, affected range, fixed
 * version) combination. Either range or fixedVer can be absent — a product
 * can be named as affected with no specific range, no specific fix, or both.
 *
 * versionFixed always wins over a wildcard-derived versionEnd when both are
 * available: versionFixed is a specific patch ("8.0 U3k"), while a range like
 * "8.0.x.x" only bounds the whole branch ("8.1") — a strictly wider, less
 * accurate upper bound. versionEnd is only set from the range when there's no
 * versionFixed to defer to, so it's the best available bound rather than none.
 */
function buildAffectedProductEntry(
  product: string,
  range: AffectedRange | undefined,
  fixedVer: string | undefined,
): NormalizedAdvisory['affectedProducts'][number] {
  const entry: NormalizedAdvisory['affectedProducts'][number] = {
    vendor: 'broadcom',
    product,
    patchAvailable: fixedVer !== undefined,
  };
  // normalizeVersion (called downstream in importAdvisoryData) handles "X.Y UZw".
  if (fixedVer !== undefined) entry.versionFixed = fixedVer;

  if (range && 'exact' in range) {
    entry.affectedVersions = [range.exact];
  } else if (range) {
    entry.versionStart = range.versionStart;
    if (fixedVer === undefined) {
      entry.versionEnd = range.versionEnd;
    }
  }
  return entry;
}

/**
 * Build one NormalizedAdvisory per CVE covered by a VMSA item. A single VMSA
 * commonly bundles several CVEs (e.g. "VMSA-2026-0006.1: ... address multiple
 * vulnerabilities (CVE-2026-59309, CVE-2026-59310, ...)") — without the split,
 * `externalId: vmsaId` + a single `cveId` field meant only the first CVE in
 * the list ever got linked to a Vulnerability master row and became
 * independently searchable; the rest were only visible inside rawData.
 * Follows the same `${advisoryId}/${cveId}` composite-externalId pattern
 * already used by redhat-fetcher.ts / oracle-linux-fetcher.ts for the same
 * one-advisory-many-CVEs shape. Items with no CVE at all keep the plain
 * VMSA/documentId as externalId, unchanged from before.
 */
export function buildBroadcomAdvisories(
  item: BroadcomApiItem,
  productVersions: ProductVersion[],
): NormalizedAdvisory[] {
  const vmsaId = extractVmsaId(item.title) ?? item.documentId;
  const cveIds = extractCveIds(item.affectedCve ?? '');
  const severity = normalizeSeverity(item.severity);
  const publishedAt = parsePublishedDate(item.published);

  let affectedProducts: NormalizedAdvisory['affectedProducts'];

  if (productVersions.length > 0) {
    affectedProducts = productVersions.flatMap((pv): NormalizedAdvisory['affectedProducts'] => {
      // A product can have several disjoint affected ranges (comma-separated
      // Version cell) and/or several fixed versions ("or"-separated Fixed
      // Version cell); every combination becomes its own row, since a single
      // AdvisoryAffectedProduct row can only hold one range and one fix.
      const ranges: (AffectedRange | undefined)[] = pv.affected && pv.affected.length > 0 ? pv.affected : [undefined];
      const fixedVers: (string | undefined)[] = pv.fixed.length > 0 ? pv.fixed : [undefined];
      return ranges.flatMap(range =>
        fixedVers.map(fixedVer => buildAffectedProductEntry(pv.product, range, fixedVer))
      );
    });
  } else {
    // Fallback: use product names from list API (may be truncated)
    const products = parseProductNames(item.supportProducts ?? '');
    affectedProducts = products.length > 0
      ? products.map(product => ({ vendor: 'broadcom', product, patchAvailable: true }))
      : [{ vendor: 'broadcom', product: 'VMware', patchAvailable: true }];
  }

  const base = {
    summary: item.title,
    severity,
    url: item.notificationUrl,
    publishedAt,
    affectedProducts,
    rawData: item,
  };

  if (cveIds.length === 0) {
    return [{ externalId: vmsaId, ...base }];
  }
  return cveIds.map(cveId => ({ externalId: `${vmsaId}/${cveId}`, cveId, ...base }));
}


// ─── Data Fetching ─────────────────────────────────────────────

async function fetchAdvisoryList(segment: string): Promise<{ items: BroadcomApiItem[]; truncated: boolean }> {
  const all: BroadcomApiItem[] = [];
  let pageNumber = 0;
  let truncated = false;

  while (true) {
    let response: BroadcomApiResponse;
    try {
      const { data } = await axios.post<BroadcomApiResponse>(LIST_API, {
        pageNumber,
        pageSize: PAGE_SIZE,
        searchVal: '',
        segment,
        sortInfo: { column: '', order: '' },
      }, {
        timeout: 30000,
        headers: {
          'User-Agent': 'heretix-api/1.0',
          Accept: 'application/json',
          'Content-Type': 'application/json',
        },
      });
      response = data;
    } catch (err) {
      logger.error({ err, segment, pageNumber }, 'Broadcom API request failed');
      // Any later pages beyond this one are silently missing from `all` —
      // the caller needs to know this page listing is incomplete, not just
      // that the segment happened to have fewer pages than usual.
      truncated = true;
      break;
    }

    const list = response.data?.list ?? [];
    if (list.length === 0) break;

    all.push(...list);
    logger.debug({ segment, pageNumber, count: list.length }, 'Broadcom advisory page fetched');

    const { lastPage } = response.data.pageInfo;
    if (pageNumber >= lastPage) break;

    pageNumber++;
    await new Promise(r => setTimeout(r, DELAY_MS));
  }

  return { items: all, truncated };
}

/**
 * Fetch detail page and extract product/fixed-version pairs from the Response Matrix table.
 * Runs in browser context via page.evaluate() to avoid innerText multiline cell issues.
 *
 * VMSA "Response Matrix" columns:
 *   0: VMware Product | 1: Version | ... | 6: Fixed Version | ...
 */
async function fetchDetailVersions(notificationUrl: string): Promise<{ versions: ProductVersion[]; failed: boolean }> {
  try {
    // page.evaluate() only extracts raw cell text — it runs serialized inside the
    // browser, so it can't call back into parseResponseMatrixRow() /
    // parseAffectedVersionCell(). Cleaning, splitting multi-value cells, and
    // dedup all happen below instead, in plain Node code that's actually
    // unit-testable.
    const rawRows = await withPage(notificationUrl, async (page) => {
      await page.waitForSelector('table', { timeout: 20000 });
      return page.evaluate(() => {
        const rows: Array<{ product: string; fixedVer: string; affectedVer: string }> = [];

        document.querySelectorAll('table').forEach((table) => {
          // Header may use <th> or <td> — check the first row for "Fixed Version" text
          const firstRow = table.querySelector('tr');
          if (!firstRow) return;
          const headerCells = Array.from(firstRow.querySelectorAll('th, td'));
          const fixedIdx = headerCells.findIndex(c => /fixed\s+version/i.test(c.textContent ?? ''));
          if (fixedIdx === -1) return;
          // Exact match, not a substring test — "Fixed Version" also contains
          // the word "Version" and would otherwise match here too.
          const versionIdx = headerCells.findIndex(c => (c.textContent ?? '').trim().toLowerCase() === 'version');

          // Process all rows except the header
          const tableRows = Array.from(table.querySelectorAll('tr')).slice(1);
          for (const row of tableRows) {
            const cells = Array.from(row.querySelectorAll('td'));
            if (cells.length <= fixedIdx) continue;

            const product = cells[0]?.textContent?.trim() ?? '';
            const fixedVer = cells[fixedIdx]?.textContent?.trim() ?? '';
            if (!product || !fixedVer) continue;

            const affectedVer = versionIdx !== -1 && cells.length > versionIdx
              ? (cells[versionIdx]?.textContent?.trim() ?? '')
              : '';
            rows.push({ product, fixedVer, affectedVer });
          }
        });

        return rows;
      });
    }, { timeout: 30000 });

    const results: ProductVersion[] = [];
    const seenFixed = new Set<string>();
    const seenAffected = new Set<string>();
    for (const raw of rawRows) {
      const parsed = parseResponseMatrixRow(raw.product, raw.fixedVer);
      if (!parsed) continue;
      const affectedRanges = parseAffectedVersionCell(raw.affectedVer);

      for (const product of parsed.products) {
        // Register the product even if this row contributes no parseable
        // fixed version or affected range — e.g. a KB-article-only Fixed
        // Version cell — so it isn't silently dropped. buildBroadcomAdvisories()
        // turns an empty fixed/affected into a "no known version" entry.
        let existing = results.find(r => r.product === product);
        if (!existing) {
          existing = { product, fixed: [], affected: [] };
          results.push(existing);
        }

        for (const fixedVersion of parsed.fixedVersions) {
          const key = `${product}|${fixedVersion}`;
          if (seenFixed.has(key)) continue;
          seenFixed.add(key);
          existing.fixed.push(fixedVersion);
        }

        for (const range of affectedRanges) {
          const key = `${product}|${JSON.stringify(range)}`;
          if (seenAffected.has(key)) continue;
          seenAffected.add(key);
          existing.affected!.push(range);
        }
      }
    }
    return { versions: results, failed: false };
  } catch (err) {
    logger.warn({ notificationUrl, err }, 'Playwright failed for Broadcom advisory detail');
    return { versions: [], failed: true };
  }
}

// ─── AdvisoryFetcher Implementation ──────────────────────────

export class BroadcomFetcher implements AdvisoryFetcher {
  private fetchFailed = 0;

  source(): string { return 'advisory-broadcom'; }
  isCompleteSnapshot(): boolean { return true; }
  fetchFailedCount(): number { return this.fetchFailed; }

  async fetch(): Promise<NormalizedAdvisory[]> {
    this.fetchFailed = 0;
    logger.info('Fetching Broadcom/VMware security advisories');

    // Collect advisories from all segments (deduplicate by documentId)
    const seen = new Map<string, BroadcomApiItem>();
    for (const segment of SEGMENTS) {
      const { items, truncated } = await fetchAdvisoryList(segment);
      if (truncated) this.fetchFailed++;
      for (const item of items) {
        if (item.documentId && !seen.has(item.documentId)) {
          seen.set(item.documentId, item);
        }
      }
      logger.info({ segment, count: items.length, truncated }, 'Broadcom segment fetched');
    }

    const items = [...seen.values()];
    logger.info({ total: items.length }, 'Broadcom unique advisories collected');

    const results: NormalizedAdvisory[] = [];

    for (const item of items) {
      // Fetch detail page for version table (uses the direct notificationUrl)
      await new Promise(r => setTimeout(r, DELAY_MS));
      const { versions: productVersions, failed: detailFailed } = await fetchDetailVersions(item.notificationUrl);
      if (detailFailed) this.fetchFailed++;

      const built = buildBroadcomAdvisories(item, productVersions);
      results.push(...built);

      logger.debug(
        { documentId: item.documentId, cves: built.length, products: built[0]?.affectedProducts.length ?? 0 },
        'Broadcom advisory processed',
      );
    }

    await closeBrowser();

    logger.info({ total: items.length, imported: results.length, failed: this.fetchFailed }, 'Broadcom advisory fetch complete');
    return results;
  }
}
