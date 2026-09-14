import axios from 'axios';
import type { AdvisoryFetcher, NormalizedAdvisory } from './advisory-fetcher.js';
import { logger } from '../utils/logger.js';

// The public page (https://support.checkpoint.com/security-advisories) is a
// client-rendered SPA with no server-side data; its "Export to CSV" button
// just serializes the same array this endpoint already returns. Found by
// inspecting the page's own JS bundle and confirming the real request host
// via a headless-browser network trace (support.checkpoint.com itself 404s
// the path -- the SPA calls a separate API host).
const ADVISORIES_URL = 'https://iapi-services-ucs.checkpoint.com/public/api/support-center-mms/api/securityAdvisories/getAllActive';

// ─── API response types (only the fields this fetcher reads) ─

interface CheckpointProduct {
  name?: unknown;
  version?: unknown;
  affected?: unknown;
}

interface CheckpointAdvisory {
  cvss?: unknown;
  cpSeverity?: unknown;
  summary?: unknown;
  url?: unknown;
  skId?: unknown;
  published?: unknown;
  updated?: unknown;
  cveId?: unknown;
  products?: unknown;
}

const SEVERITY_MAP: Record<string, string> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
};

function asString(v: unknown): string | undefined {
  return typeof v === 'string' && v.trim() !== '' ? v.trim() : undefined;
}

// ─── Version parsing ──────────────────────────────────────────

/**
 * A Check Point release line ("R81.20") as a normalizeVersion()-comparable
 * floor ("81.20"), or undefined when `version` isn't one at all.
 *
 * Real `version` values fall into three shapes this fetcher can act on --
 * "R81.20" (plain), "R81.10.X" / "R82.00.X" (a whole dot-line, "X" is a
 * literal placeholder not a digit), "R80 (EOS)" (end-of-support annotation
 * suffixed on) -- and several it can't: "Hardware" / "Other" / "Cloud"
 * (not a release at all) and "E86.x" .. "E89.x" (Harmony Endpoint's client
 * build numbering, a completely different scheme -- see extractTakeCeiling()'s
 * doc comment for why this fetcher doesn't attempt it). Requiring the "R"
 * prefix is what naturally excludes all of those without listing them.
 */
export function parseVersionLine(version: string): string | undefined {
  const m = version.match(/^R(\d+(?:\.\d+)?)/i);
  if (!m) return undefined;
  return m[1];
}

export type AffectedRange =
  | { kind: 'not-affected' }
  | { kind: 'unparseable' }
  | { kind: 'range'; versionEnd?: string; lastAffected?: string };

// Real "prior to"/"below" wording always pairs with a JHF (Jumbo Hotfix
// Accumulator) take number in this data; "or below" is the only inclusive
// phrasing observed.
const EXCLUSIVE_TAKE = /^(?:Prior to (?:JHF )?Take |Below [Tt]ake )(\d+)$/i;
const INCLUSIVE_TAKE = /^Take (\d+) or below$/i;

/**
 * Classifies one `products[].affected` string, given the release-line floor
 * already extracted from that same row's `version`.
 *
 * "None" and the "not this product's CVE" disclaimer are explicit negatives
 * confirmed against real data (e.g. one advisory lists Multi-Domain Security
 * Management R82 as "None" while R81.10/R81.20 carry real take numbers for
 * the same CVE) -- creating a row for these would turn an explicit
 * not-affected declaration into a false positive, so the caller must not
 * create an AdvisoryAffectedProduct for them at all.
 *
 * "All" and "Details in SK" both get the floor with no upper bound. For
 * "Details in SK" this was a deliberate call, not the conservative default:
 * every one of the 18 real advisories using it in 2026-09 has an otherwise
 * normal release-line `version`, and roughly half are current, mainstream
 * issues (e.g. an OpenSSH sshd race condition, a RADIUS MD5-collision
 * forgery) rather than the legacy Wi-Fi-driver advisories the phrase also
 * appears on -- dropping the row would make those undetectable for no
 * better reason than Check Point choosing prose over a take number.
 *
 * A bare number ("17", "166") is deliberately left unparseable: sk1000117's
 * own real data pairs a documented fix of "take 24" with `affected` values
 * of 10/17/44/126/166 for other release lines on the very same CVE, so a
 * bare number's relationship to the fix boundary isn't the simple "ceiling"
 * reading it would be tempting to assume.
 */
export function parseAffected(affected: string, versionFloor: string): AffectedRange {
  const value = affected.trim();

  if (value === 'None' || /^Not Check Point's product CVE/i.test(value)) {
    return { kind: 'not-affected' };
  }
  if (value === 'All' || value === 'Details in SK') {
    return { kind: 'range' };
  }

  const exclusive = value.match(EXCLUSIVE_TAKE);
  if (exclusive) return { kind: 'range', versionEnd: `${versionFloor}.${exclusive[1]}` };

  const inclusive = value.match(INCLUSIVE_TAKE);
  if (inclusive) return { kind: 'range', lastAffected: `${versionFloor}.${inclusive[1]}` };

  return { kind: 'unparseable' };
}

/** Builds the AdvisoryAffectedProduct rows for one advisory's products[] list. */
export function buildCheckpointAffectedProducts(
  products: CheckpointProduct[],
): NormalizedAdvisory['affectedProducts'] {
  const result: NormalizedAdvisory['affectedProducts'] = [];

  for (const p of products) {
    const name = asString(p.name);
    const version = asString(p.version);
    const affected = asString(p.affected);
    if (!name || !version || !affected) continue;

    const floor = parseVersionLine(version);
    if (!floor) continue; // Hardware / Other / Cloud / E-series -- see parseVersionLine()

    const range = parseAffected(affected, floor);
    if (range.kind === 'not-affected' || range.kind === 'unparseable') continue;

    result.push({
      vendor: 'checkpoint',
      product: name,
      versionStart: floor,
      versionEnd: range.versionEnd,
      lastAffected: range.lastAffected,
    });
  }

  return result;
}

// ─── Detail page (Solution / Mitigation) ─────────────────────

function stripTags(html: string): string {
  return html
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Extracts the plain-text content between one <h2>/<h3> heading and the next,
 * matching whichever level the page used for that heading. sk articles are
 * server-rendered static HTML (confirmed live), so this is a plain regex
 * slice -- no browser automation needed, unlike Broadcom/Sophos.
 */
function extractSection(html: string, heading: string): string | undefined {
  const re = new RegExp(`<h[23][^>]*>\\s*${heading}\\s*</h[23]>([\\s\\S]*?)(?=<h[23][^>]*>|$)`, 'i');
  const m = html.match(re);
  if (!m) return undefined;
  const text = stripTags(m[1]);
  return text.length > 0 ? text : undefined;
}

export interface CheckpointDetail {
  solution?: string;
  workaround?: string;
}

export async function fetchCheckpointDetail(url: string): Promise<CheckpointDetail> {
  const { data: html } = await axios.get<string>(url, {
    timeout: 30000,
    headers: { 'User-Agent': 'heretix-api/1.0' },
    responseType: 'text',
  });
  return {
    solution: extractSection(html, 'Solution'),
    workaround: extractSection(html, 'Mitigation'),
  };
}

// ─── AdvisoryFetcher implementation ───────────────────────────

export class CheckpointFetcher implements AdvisoryFetcher {
  private detailFailed = 0;

  source(): string { return 'advisory-checkpoint'; }
  isCompleteSnapshot(): boolean { return true; }
  fetchFailedCount(): number { return this.detailFailed; }

  async fetch(): Promise<NormalizedAdvisory[]> {
    this.detailFailed = 0;
    logger.info('Fetching Check Point security advisories');
    const { data } = await axios.get<CheckpointAdvisory[]>(ADVISORIES_URL, {
      timeout: 30000,
      headers: { 'User-Agent': 'heretix-api/1.0' },
    });

    const results: NormalizedAdvisory[] = [];

    for (const adv of data) {
      const skId = asString(adv.skId);
      const cveId = asString(adv.cveId);
      if (!skId) continue;

      const products = Array.isArray(adv.products) ? (adv.products as CheckpointProduct[]) : [];
      const affectedProducts = buildCheckpointAffectedProducts(products);
      if (affectedProducts.length === 0) continue;

      const url = asString(adv.url);
      let detail: CheckpointDetail = {};
      if (url) {
        try {
          detail = await fetchCheckpointDetail(url);
        } catch (err) {
          this.detailFailed++;
          logger.warn({ err, skId, url }, 'Failed to fetch Check Point advisory detail page');
        }
      }

      results.push({
        // A single sk article can document several distinct CVEs (confirmed
        // live: sk182899 alone covers 7 separate Apache HTTP Server CVEs, each
        // its own entry in this feed with its own cveId/summary/products).
        // Keying on the bare skId collapsed all but the last-processed one
        // into a single upserted row -- same composite-id fix already applied
        // to Sophos/Broadcom for the same "one bulletin, several CVEs" shape.
        externalId: cveId ? `${skId}/${cveId}` : skId,
        cveId,
        summary: asString(adv.summary),
        severity: SEVERITY_MAP[asString(adv.cpSeverity)?.toLowerCase() ?? ''],
        cvssScore: typeof adv.cvss === 'number' ? adv.cvss : undefined,
        url,
        solution: detail.solution,
        workaround: detail.workaround,
        publishedAt: typeof adv.published === 'number' ? new Date(adv.published) : undefined,
        affectedProducts,
        rawData: adv,
      });
    }

    logger.info({ total: data.length, succeeded: results.length, detailFailed: this.detailFailed }, 'Check Point advisory fetch complete');
    return results;
  }
}
