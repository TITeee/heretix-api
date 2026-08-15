import axios from 'axios';
import type { AdvisoryFetcher, NormalizedAdvisory } from './advisory-fetcher.js';
import { logger } from '../utils/logger.js';

// tomcat.apache.org publishes one security page per major version branch.
// Fetch every known branch page; skip ones that don't exist (future/retired
// branches) rather than hardcoding an exact set that will go stale.
const CANDIDATE_MAJORS = [8, 9, 10, 11, 12];

function pageUrl(major: number): string {
  return `https://tomcat.apache.org/security-${major}.html`;
}

export interface VulnerableRange {
  introduced: string;
  lastAffected: string; // inclusive upper bound (the Y in "Affects: X to Y")
}

interface RawEntry {
  cveId: string;
  severity: string;
  range: VulnerableRange;
  major: number;
  versionFixed?: string;
}

/**
 * Parse the text of an "Affects:" line into a VulnerableRange.
 *
 * Notation examples:
 *   "9.0.0.M1 to 9.0.105" → { introduced:"9.0.0.M1", lastAffected:"9.0.105" }
 *   "9.0.71 to 9.0.73"    → { introduced:"9.0.71",   lastAffected:"9.0.73"  }
 *   "9.0.0.M1"             → { introduced:"9.0.0.M1", lastAffected:"9.0.0.M1" }
 *
 * The upper bound is inclusive. Returns null when the text doesn't parse as
 * a version (e.g. free-text notes).
 */
export function parseAffectsText(raw: string): VulnerableRange | null {
  const text = raw.replace(/^Apache\s+Tomcat\s+/i, '').trim();

  const rangeMatch = text.match(/^([\d.A-Za-z-]+)\s+to\s+([\d.A-Za-z-]+)/i);
  if (rangeMatch) {
    const [, introduced, lastAffected] = rangeMatch;
    if (/^\d+\.\d+/.test(introduced) && /^\d+\.\d+/.test(lastAffected)) {
      return { introduced, lastAffected };
    }
  }

  const singleMatch = text.match(/^([\d.A-Za-z-]+)/);
  if (singleMatch && /^\d+\.\d+/.test(singleMatch[1])) {
    return { introduced: singleMatch[1], lastAffected: singleMatch[1] };
  }

  return null;
}

/**
 * Each branch page is organized into "Fixed in Apache Tomcat X.Y.Z" sections
 * (<h3 id="Fixed_in_Apache_Tomcat_X.Y.Z">), each covering one or more CVEs
 * that share that fix version. Locate every section heading's position and
 * version so entries can be matched to "the nearest preceding heading".
 */
function findFixedHeadings(html: string): Array<{ index: number; version: string }> {
  const headingRegex = /<h3 id="Fixed_in_Apache_Tomcat_([\d.A-Za-z]+)">/g;
  const headings: Array<{ index: number; version: string }> = [];
  let m: RegExpExecArray | null;
  while ((m = headingRegex.exec(html)) !== null) {
    headings.push({ index: m.index, version: m[1] });
  }
  return headings;
}

/** Version of the nearest heading at or before `index` (headings are in ascending index order). */
function fixedVersionAt(headings: Array<{ index: number; version: string }>, index: number): string | undefined {
  let result: string | undefined;
  for (const h of headings) {
    if (h.index > index) break;
    result = h.version;
  }
  return result;
}

/**
 * Parse raw {cveId, severity, range} entries out of one branch page.
 * CVE IDs are extracted only from the heading area (<strong>Severity: Title</strong> <a>CVE-XXXX</a>)
 * to avoid picking up CVE references mentioned in description paragraphs
 * (e.g. "The fix for CVE-YYYY was incomplete").
 */
export function parseTomcatPage(html: string, major: number): RawEntry[] {
  const affectsRegex = /Affects:\s*([^\n<]+)/gi;
  const hits: Array<{ index: number; text: string }> = [];
  let m: RegExpExecArray | null;
  while ((m = affectsRegex.exec(html)) !== null) {
    hits.push({ index: m.index, text: m[1].trim() });
  }

  const fixedHeadings = findFixedHeadings(html);
  const entries: RawEntry[] = [];

  for (let i = 0; i < hits.length; i++) {
    const { index, text } = hits[i];
    const range = parseAffectsText(text);
    if (!range) continue;

    const prevIndex = i > 0 ? hits[i - 1].index : 0;
    const segment = html.slice(prevIndex, index);

    const headingArea = segment.match(/<strong>[\s\S]*?<\/strong>[\s\S]*?(?=<\/p>|<p\b)/i)?.[0] ?? '';
    const titleCVEs = [...headingArea.matchAll(/CVE-\d{4}-\d+/g)].map(mm => mm[0]);
    if (titleCVEs.length === 0) continue;

    const sevMatch = headingArea.match(/\b(Critical|Important|Moderate|Low)\b/i);
    const severity = sevMatch ? sevMatch[1].toLowerCase() : 'unknown';
    const versionFixed = fixedVersionAt(fixedHeadings, index);

    for (const cveId of titleCVEs) {
      entries.push({ cveId, severity, range, major, versionFixed });
    }
  }

  return entries;
}

const SEVERITY_MAP: Record<string, string> = {
  critical: 'CRITICAL',
  important: 'HIGH',
  moderate: 'MEDIUM',
  low: 'LOW',
};

/**
 * Group raw per-branch entries by CVE ID into one NormalizedAdvisory each.
 * The same CVE can appear on multiple major-branch pages with different
 * ranges (e.g. 9.0.x and 10.1.x) — those become separate affectedProducts
 * entries under a single advisory rather than colliding on externalId.
 */
export function groupByAdvisory(entries: RawEntry[]): NormalizedAdvisory[] {
  const byCve = new Map<string, RawEntry[]>();
  for (const e of entries) {
    const list = byCve.get(e.cveId) ?? [];
    list.push(e);
    byCve.set(e.cveId, list);
  }

  const advisories: NormalizedAdvisory[] = [];
  for (const [cveId, group] of byCve) {
    const rawSeverity = group.find(g => g.severity !== 'unknown')?.severity;
    const severity = rawSeverity ? SEVERITY_MAP[rawSeverity] : undefined;
    const seen = new Set<string>();
    const affectedProducts: NormalizedAdvisory['affectedProducts'] = [];
    for (const g of group) {
      const key = `${g.range.introduced}-${g.range.lastAffected}`;
      if (seen.has(key)) continue;
      seen.add(key);
      affectedProducts.push({
        vendor: 'apache',
        product: 'tomcat',
        versionStart: g.range.introduced,
        lastAffected: g.range.lastAffected,
        versionFixed: g.versionFixed,
        patchAvailable: !!g.versionFixed,
      });
    }

    advisories.push({
      externalId: cveId,
      cveId,
      severity,
      url: pageUrl(group[0].major),
      affectedProducts,
      rawData: { majors: [...new Set(group.map(g => g.major))] },
    });
  }

  return advisories;
}

// ─── AdvisoryFetcher Implementation ──────────────────────────

export class TomcatFetcher implements AdvisoryFetcher {
  private fetchFailed = 0;

  source(): string { return 'advisory-tomcat'; }
  isCompleteSnapshot(): boolean { return true; }
  fetchFailedCount(): number { return this.fetchFailed; }

  async fetch(): Promise<NormalizedAdvisory[]> {
    this.fetchFailed = 0;
    logger.info('Fetching Apache Tomcat security advisories');

    const allEntries: RawEntry[] = [];
    for (const major of CANDIDATE_MAJORS) {
      try {
        const { data: html } = await axios.get<string>(pageUrl(major), {
          timeout: 30000,
          headers: { 'User-Agent': 'heretix-api/1.0' },
          responseType: 'text',
        });
        const entries = parseTomcatPage(html, major);
        allEntries.push(...entries);
        logger.info({ major, count: entries.length }, 'Parsed Tomcat branch page');
      } catch (err) {
        // A 404 means this candidate major has no page yet (or no longer) —
        // expected and harmless, CANDIDATE_MAJORS intentionally probes ahead
        // of the current release line. Anything else (timeout, 5xx, DNS) is
        // a genuine fetch failure for a branch that does exist.
        const notFound = axios.isAxiosError(err) && err.response?.status === 404;
        if (!notFound) this.fetchFailed++;
        logger.warn({ major, err, notFound }, 'Skipping Tomcat branch page (not found or fetch failed)');
      }
    }

    const results = groupByAdvisory(allEntries);
    logger.info({ total: results.length, failed: this.fetchFailed }, 'Apache Tomcat advisory fetch complete');
    return results;
  }
}
