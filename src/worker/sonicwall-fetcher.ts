import axios from 'axios';
import type { AdvisoryFetcher, NormalizedAdvisory } from './advisory-fetcher.js';
import { logger } from '../utils/logger.js';

const LIST_API = 'https://psirtapi.global.sonicwall.com/api/v1/vulnsummary/';
// Only the detail API carries fixed_software; the list API (above) does not.
const DETAIL_API = 'https://psirtapi.global.sonicwall.com/api/v1/vulndetail/';
const DETAIL_CONCURRENCY = 4;

// ─── API Types ─────────────────────────────────────────────────

interface SonicWallAdvisory {
  advisory_id: string;
  title: string;
  published_when: string;
  last_updated_when: string;
  impact: string;
  cvss: string;
  cvss_vector: string;
  cvss_version: number;
  cwe: string;
  cve: string;
  is_workaround_available: boolean;
  summary: string;
  affected_products: string;
  vuln_status: string;
  patterns: unknown[];
  vulnerable_products: Array<{ id: number; name: string }>;
}

// ─── Utilities ─────────────────────────────────────────────────

function normalizeSeverity(impact: string): string | undefined {
  const upper = impact.toUpperCase();
  return ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(upper) ? upper : undefined;
}

function extractCveIds(cveField: string): string[] {
  if (!cveField) return [];
  return cveField.split(',').map(s => s.trim()).filter(s => /^CVE-\d{4}-\d+$/.test(s));
}

/**
 * Extract version strings from the HTML affected_products table.
 * Returns version-like strings found (e.g., "7.1.3.3", "6.5.5.1").
 * These are used as lastAffected versions (best-effort).
 */
function extractVersionsFromHtml(html: string): string[] {
  if (!html) return [];
  // Strip HTML tags
  const text = html.replace(/<[^>]+>/g, ' ').replace(/&[a-z]+;/g, ' ');
  // Match SonicOS version patterns: N.N.N.N or N.N.N
  const matches = text.match(/\b\d+\.\d+\.\d+(?:\.\d+)?(?:\.\d+)?\b/g) ?? [];
  return [...new Set(matches)].slice(0, 10);
}

// ─── Fixed-version extraction ──────────────────────────────────
//
// The list API carries no fixed versions; they only exist in the detail API's
// `fixed_software` HTML ("7.0.1-5151, 7.1.1-7051 and later versions", "12.4.3-03670
// (platform-hotfix) and higher versions"). The layout is free-form per advisory
// (tables of varying shape, prose, "Pending Release"), so instead of parsing the
// table structure we pair version tokens: a fixed token F is matched with the
// highest affected token A of the same release line (major.minor.patch) below it.

/** The fields of the detail API this fetcher uses. */
export interface SonicWallDetail {
  fixed_software?: string | null;
}

// "7.0.1-5151", "12.4.3-03670", "6.5.4.9-92n", "10.2.2.3". The lookahead rejects
// letter-suffixed names such as OpenSSL's "1.1.1n", which are not product versions.
const VERSION_TOKEN = /\b\d+(?:\.\d+){2,3}(?:-[0-9A-Za-z]+)*(?![.\w])/g;
// Text right after a token that marks it as an upper bound of the affected range
// rather than a fixed version ("12.4.3-03526 (platform-hotfix) and older versions").
const AFFECTED_LIMIT_SUFFIX = /^(?:\s*\([^)]*\))?\s*(?:and\s+|or\s+)?(?:older|earlier|prior)/i;

function htmlToText(html: string): string {
  return html
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function extractVersionTokens(text: string, opts: { skipAffectedLimits: boolean }): string[] {
  const tokens: string[] = [];
  for (const m of text.matchAll(VERSION_TOKEN)) {
    const after = text.slice(m.index! + m[0].length, m.index! + m[0].length + 40);
    if (opts.skipAffectedLimits && AFFECTED_LIMIT_SUFFIX.test(after)) continue;
    tokens.push(m[0]);
  }
  return [...new Set(tokens)];
}

/** "7.0.1-5151" → nums [7,0,1] + build [5151]; the hyphen part is the SonicOS build number. */
function parseToken(token: string): { nums: number[]; build: number[] } {
  const [main, ...rest] = token.split('-');
  return {
    nums: main.split('.').map(Number),
    // Every number after the first hyphen, compared in order: "8v-37-481" → [8, 37, 481].
    build: (rest.join('-').match(/\d+/g) ?? []).map(Number),
  };
}

function compareNumbers(a: number[], b: number[]): number {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

function compareTokens(a: string, b: string): number {
  const pa = parseToken(a);
  const pb = parseToken(b);
  return compareNumbers(pa.nums, pb.nums) || compareNumbers(pa.build, pb.build);
}

/** Release line: the first three numeric components ("7.0.1-5151" → "7.0.1"). */
function releaseLine(token: string): string {
  return parseToken(token).nums.slice(0, 3).join('.');
}

/**
 * Whether a product's name pins down which version lines belong to it: Gen5-8
 * SonicOS platforms (5.x-8.x) and SMA 100 (10.x) / SMA 1000 (11.x, 12.x).
 * null = the name says nothing, so a version cannot be attributed to it.
 */
function productAcceptsVersion(product: string, token: string): boolean | null {
  const major = parseToken(token).nums[0];
  const gen = product.match(/\bGen\s*(\d)\b/i);
  if (gen) return major === Number(gen[1]);
  const sma = product.match(/\bSMA\)?\s*(100|1000)\s*Series/i);
  if (sma) return sma[1] === '100' ? major === 10 : major === 11 || major === 12;
  return null;
}

interface FixedPair { lastAffected: string; fixed: string }

/** "7.0.1-5151" → "7.0" (the minor line a patch-level jump such as 10.3.5 → 10.3.6 stays within). */
function minorLine(token: string): string {
  return parseToken(token).nums.slice(0, 2).join('.');
}

/**
 * Pairs each fixed version with the highest affected version below it, taking
 * one from the same release line (6.5.4.8 → 6.5.4.9) if there is one and else
 * from the same minor line (10.3.5 → 10.3.6). Fixes for one release line are
 * merged into the highest, so a line yields a single pair.
 */
export function pairAffectedAndFixed(affectedHtml: string, fixedHtml: string): FixedPair[] {
  const affected = extractVersionTokens(htmlToText(affectedHtml), { skipAffectedLimits: false });
  const fixed = extractVersionTokens(htmlToText(fixedHtml), { skipAffectedLimits: true });
  const highestBelow = (candidates: string[], f: string): string | undefined =>
    candidates.filter(a => compareTokens(a, f) < 0).sort(compareTokens).pop();

  const byLine = new Map<string, FixedPair>();
  for (const f of fixed) {
    const a =
      highestBelow(affected.filter(a => releaseLine(a) === releaseLine(f)), f) ??
      highestBelow(affected.filter(a => minorLine(a) === minorLine(f)), f);
    if (a === undefined) continue;
    const line = releaseLine(f);
    const kept = byLine.get(line);
    if (!kept || compareTokens(f, kept.fixed) > 0) byLine.set(line, { lastAffected: a, fixed: f });
  }
  return [...byLine.values()];
}

/**
 * Lower bound of the range a pair covers. A product's only pair in a minor line
 * starts at the line's x.y.0, so older builds of it are still reported; when a
 * minor line has several pairs (6.5.1.x and 6.5.4.x trains) each starts at its
 * own release line, otherwise a train's range would swallow another's fixed builds.
 */
function rangeStart(pair: FixedPair, all: FixedPair[]): string {
  const sharesMinor = all.filter(p => minorLine(p.fixed) === minorLine(pair.fixed)).length > 1;
  return sharesMinor ? releaseLine(pair.lastAffected) : `${minorLine(pair.fixed)}.0`;
}

/**
 * Build one NormalizedAdvisory per CVE covered by a SonicWall advisory. A
 * single advisory_id commonly covers several CVEs — without the split,
 * `externalId: adv.advisory_id` + a single `cveId` field meant only the
 * first CVE in the comma-separated `cve` field ever got linked to a
 * Vulnerability master row and became independently searchable. Follows the
 * same `${advisoryId}/${cveId}` composite-externalId pattern already used by
 * redhat-fetcher.ts / oracle-linux-fetcher.ts / broadcom-fetcher.ts /
 * sophos-fetcher.ts for the same one-advisory-many-CVEs shape. Advisories
 * with no CVE at all keep the plain advisory_id as externalId, unchanged
 * from before.
 */
export function buildSonicWallAdvisories(adv: SonicWallAdvisory, detail?: SonicWallDetail): NormalizedAdvisory[] {
  const cveIds = extractCveIds(adv.cve);
  const severity = normalizeSeverity(adv.impact);
  const cvssScore = adv.cvss ? parseFloat(adv.cvss) : undefined;
  const cvssScore_ = isNaN(cvssScore ?? NaN) ? undefined : cvssScore;

  // Build affected products list from structured vulnerable_products field
  const productNames = (adv.vulnerable_products ?? []).map(p => p.name);

  // Try to extract version info from HTML table (best-effort)
  const versions = extractVersionsFromHtml(adv.affected_products);

  const pairs = detail?.fixed_software
    ? pairAffectedAndFixed(adv.affected_products ?? '', detail.fixed_software)
    : [];

  const buildRows = (product: string, isOnlyProduct: boolean): NormalizedAdvisory['affectedProducts'] => {
    // With several products in one advisory, a version is only attributed to a
    // product whose name identifies its version line; the rest keep the
    // version-less legacy row rather than receiving another product's fix.
    const own = pairs.filter(p => isOnlyProduct || productAcceptsVersion(product, p.fixed) === true);
    if (own.length === 0) {
      return [{ vendor: 'sonicwall', product, affectedVersions: versions, patchAvailable: true }];
    }
    return own.map(p => ({
      vendor: 'sonicwall',
      product,
      versionStart: rangeStart(p, own),
      lastAffected: p.lastAffected,
      versionFixed: p.fixed,
      affectedVersions: versions,
      patchAvailable: true,
    }));
  };

  const affectedProducts: NormalizedAdvisory['affectedProducts'] = productNames.length > 0
    ? productNames.flatMap(product => buildRows(product, productNames.length === 1))
    : buildRows('SonicOS', true);

  const base = {
    summary: adv.title,
    severity,
    cvssScore: cvssScore_,
    cvssVector: adv.cvss_vector || undefined,
    url: `https://psirt.global.sonicwall.com/vuln-detail/${adv.advisory_id}`,
    publishedAt: adv.published_when ? new Date(adv.published_when) : undefined,
    affectedProducts,
    // fixed_software is kept so the pairing can be re-derived without the detail API.
    rawData: detail?.fixed_software ? { ...adv, fixed_software: detail.fixed_software } : adv,
  };

  if (cveIds.length === 0) {
    return [{ externalId: adv.advisory_id, ...base }];
  }
  return cveIds.map(cveId => ({ externalId: `${adv.advisory_id}/${cveId}`, cveId, ...base }));
}

// ─── AdvisoryFetcher Implementation ──────────────────────────

export class SonicWallFetcher implements AdvisoryFetcher {
  source(): string { return 'advisory-sonicwall'; }
  isCompleteSnapshot(): boolean { return true; }

  async fetch(): Promise<NormalizedAdvisory[]> {
    logger.info('Fetching SonicWall PSIRT advisories');

    // The whole advisory list comes from this one request -- unlike the
    // per-item loops other fetchers retry, a single transient failure here
    // (this endpoint has been observed to reset the connection outright, not
    // just time out) would otherwise fail the entire job with zero recovery.
    const maxRetries = 3;
    let data: SonicWallAdvisory[] | undefined;
    let lastErr: unknown;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        const res = await axios.get<SonicWallAdvisory[]>(LIST_API, {
          params: { srch: '', vulnerable_products: '', ord: '-advisory_id' },
          timeout: 30000,
          headers: { 'User-Agent': 'heretix-api/1.0', 'Accept': 'application/json' },
        });
        data = res.data;
        break;
      } catch (err) {
        lastErr = err;
        if (attempt < maxRetries) {
          const wait = 3000 * attempt;
          logger.warn({ attempt, wait, err }, 'SonicWall advisory list fetch failed, retrying');
          await new Promise(r => setTimeout(r, wait));
        }
      }
    }

    if (data === undefined) throw lastErr;

    logger.info({ count: data.length }, 'Fetched SonicWall advisories');

    const applicable = data.filter(adv => adv.vuln_status !== 'Not Applicable');
    const details = await this.fetchDetails(applicable.map(adv => adv.advisory_id));

    const results: NormalizedAdvisory[] = [];
    for (const adv of applicable) {
      results.push(...buildSonicWallAdvisories(adv, details.get(adv.advisory_id)));
    }

    logger.info(
      { total: data.length, imported: results.length, detailFailed: this.failedCount },
      'SonicWall advisory fetch complete',
    );
    return results;
  }

  private failedCount = 0;
  fetchFailedCount(): number { return this.failedCount; }

  /**
   * Fetch fixed_software from the detail API, which the list API lacks. A failed
   * advisory just goes without fix versions (it is still imported from the list).
   * Some pre-2021 advisories answer HTTP 500 every time -- that is the vendor's
   * data, not a transient fault, so it is not counted as a failure.
   */
  private async fetchDetails(ids: string[]): Promise<Map<string, SonicWallDetail>> {
    this.failedCount = 0;
    const details = new Map<string, SonicWallDetail>();
    let next = 0;

    const worker = async () => {
      while (next < ids.length) {
        const id = ids[next++];
        for (let attempt = 1; attempt <= 3; attempt++) {
          try {
            const res = await axios.get<SonicWallDetail>(DETAIL_API, {
              params: { advisory_id: id },
              timeout: 30000,
              headers: { 'User-Agent': 'heretix-api/1.0', 'Accept': 'application/json' },
            });
            details.set(id, res.data);
            break;
          } catch (err) {
            const status = axios.isAxiosError(err) ? err.response?.status : undefined;
            if (status === 500 || status === 404) break;
            if (attempt === 3) {
              this.failedCount++;
              logger.warn({ id, err }, 'SonicWall advisory detail fetch failed');
            } else {
              await new Promise(r => setTimeout(r, 2000 * attempt));
            }
          }
        }
      }
    };

    await Promise.all(Array.from({ length: DETAIL_CONCURRENCY }, worker));
    return details;
  }
}
