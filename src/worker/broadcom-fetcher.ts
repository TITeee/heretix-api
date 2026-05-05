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

interface ProductVersion {
  product: string;
  fixed: string[];
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


// ─── Data Fetching ─────────────────────────────────────────────

async function fetchAdvisoryList(segment: string): Promise<BroadcomApiItem[]> {
  const all: BroadcomApiItem[] = [];
  let pageNumber = 0;

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

  return all;
}

/**
 * Fetch detail page and extract product/fixed-version pairs from the Response Matrix table.
 * Runs in browser context via page.evaluate() to avoid innerText multiline cell issues.
 *
 * VMSA "Response Matrix" columns:
 *   0: VMware Product | 1: Version | ... | 6: Fixed Version | ...
 */
async function fetchDetailVersions(notificationUrl: string): Promise<ProductVersion[]> {
  try {
    return await withPage(notificationUrl, async (page) => {
      await page.waitForSelector('table', { timeout: 20000 });
      return page.evaluate(() => {
        const results: Array<{ product: string; fixed: string[] }> = [];
        const seen = new Set<string>();

        document.querySelectorAll('table').forEach((table) => {
          // Header may use <th> or <td> — check the first row for "Fixed Version" text
          const firstRow = table.querySelector('tr');
          if (!firstRow) return;
          const headerCells = Array.from(firstRow.querySelectorAll('th, td'));
          const fixedIdx = headerCells.findIndex(c => /fixed\s+version/i.test(c.textContent ?? ''));
          if (fixedIdx === -1) return;

          // Process all rows except the header
          const rows = Array.from(table.querySelectorAll('tr')).slice(1);
          for (const row of rows) {
            const cells = Array.from(row.querySelectorAll('td'));
            if (cells.length <= fixedIdx) continue;

            const product = cells[0]?.textContent?.trim() ?? '';
            const fixedVer = cells[fixedIdx]?.textContent?.trim() ?? '';

            if (!product || !fixedVer || !/\d+\.\d+/.test(fixedVer)) continue;
            if (/n\/a|see\s+note/i.test(fixedVer)) continue;

            const key = `${product}|${fixedVer}`;
            if (seen.has(key)) continue;
            seen.add(key);

            const existing = results.find(r => r.product === product);
            if (existing) {
              existing.fixed.push(fixedVer);
            } else {
              results.push({ product, fixed: [fixedVer] });
            }
          }
        });

        return results;
      });
    }, { timeout: 30000 });
  } catch (err) {
    logger.warn({ notificationUrl, err }, 'Playwright failed for Broadcom advisory detail');
    return [];
  }
}

// ─── AdvisoryFetcher Implementation ──────────────────────────

export class BroadcomFetcher implements AdvisoryFetcher {
  source(): string { return 'advisory-broadcom'; }

  async fetch(): Promise<NormalizedAdvisory[]> {
    logger.info('Fetching Broadcom/VMware security advisories');

    // Collect advisories from all segments (deduplicate by documentId)
    const seen = new Map<string, BroadcomApiItem>();
    for (const segment of SEGMENTS) {
      const items = await fetchAdvisoryList(segment);
      for (const item of items) {
        if (item.documentId && !seen.has(item.documentId)) {
          seen.set(item.documentId, item);
        }
      }
      logger.info({ segment, count: items.length }, 'Broadcom segment fetched');
    }

    const items = [...seen.values()];
    logger.info({ total: items.length }, 'Broadcom unique advisories collected');

    const results: NormalizedAdvisory[] = [];

    for (const item of items) {
      const vmsaId = extractVmsaId(item.title) ?? item.documentId;
      const cveIds = extractCveIds(item.affectedCve ?? '');
      const severity = normalizeSeverity(item.severity);
      const publishedAt = parsePublishedDate(item.published);

      // Fetch detail page for version table (uses the direct notificationUrl)
      await new Promise(r => setTimeout(r, DELAY_MS));
      const productVersions = await fetchDetailVersions(item.notificationUrl);

      let affectedProducts: NormalizedAdvisory['affectedProducts'];

      if (productVersions.length > 0) {
        affectedProducts = productVersions.flatMap((pv): NormalizedAdvisory['affectedProducts'] =>
          pv.fixed.length > 0
            ? pv.fixed.map(fixedVer => ({
                vendor: 'broadcom',
                product: pv.product,
                versionEnd: fixedVer,  // normalizeVersion handles "X.Y UZw"
                patchAvailable: true,
              }))
            : [{ vendor: 'broadcom', product: pv.product, patchAvailable: false }]
        );
      } else {
        // Fallback: use product names from list API (may be truncated)
        const products = parseProductNames(item.supportProducts ?? '');
        affectedProducts = products.length > 0
          ? products.map(product => ({ vendor: 'broadcom', product, patchAvailable: true }))
          : [{ vendor: 'broadcom', product: 'VMware', patchAvailable: true }];
      }

      results.push({
        externalId: vmsaId,
        cveId: cveIds[0],
        summary: item.title,
        severity,
        url: item.notificationUrl,
        publishedAt,
        affectedProducts,
        rawData: item,
      });

      logger.debug({ vmsaId, cveIds, products: affectedProducts.length }, 'Broadcom advisory processed');
    }

    await closeBrowser();

    logger.info({ total: items.length, imported: results.length }, 'Broadcom advisory fetch complete');
    return results;
  }
}
