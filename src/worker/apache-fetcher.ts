import axios from 'axios';
import type { AdvisoryFetcher, NormalizedAdvisory } from './advisory-fetcher.js';
import { logger } from '../utils/logger.js';

const PAGE_URL = 'https://httpd.apache.org/security/vulnerabilities_24.html';

// ─── HTML Parsing ───────────────────────────────────────────────

function decodeEntities(s: string): string {
  return s
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .trim();
}

function stripTags(html: string): string {
  return decodeEntities(html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' '));
}

const SEVERITY_MAP: Record<string, string> = {
  critical: 'CRITICAL',
  important: 'HIGH',
  moderate: 'MEDIUM',
  low: 'LOW',
};

export interface AffectsSpec {
  versionStart?: string;
  versionEnd?: string;
  lastAffected?: string;
  affectedVersions?: string[];
}

/**
 * Parse the "Affects" table cell value. httpd.apache.org uses several
 * notations across advisories:
 *   "2.4.0 before 2.4.66" / "before 2.4.66"        → exclusive upper bound
 *   "2.4.0 through 2.4.67" / "through 2.4.67"       → inclusive upper bound
 *   ">=2.4.7, <=2.4.51"                              → inclusive range
 *   "<=2.4.48" / "<=2.4.48, !<2.4.17"                → inclusive upper (+ optional inclusive lower)
 *   "2.4.10, 2.4.9, 2.2.31, ..." (comma list)         → exact version list, mixed with older
 *                                                        2.2.x/2.0.x/1.3.x entries that are out
 *                                                        of scope here (2.4.x tokens only)
 */
export function parseAffects(raw: string): AffectsSpec | null {
  const text = decodeEntities(raw);
  if (!text) return null;

  const before = text.match(/^(?:([\d.]+)\s+)?before\s+([\d.]+)$/i);
  if (before) return { versionStart: before[1] || undefined, versionEnd: before[2] };

  const through = text.match(/^(?:([\d.]+)\s+)?through\s+([\d.]+)$/i);
  if (through) return { versionStart: through[1] || undefined, lastAffected: through[2] };

  const gte = text.match(/>=\s*([\d.]+)/);
  const lte = text.match(/<=\s*([\d.]+)/);
  const notLt = text.match(/!<\s*([\d.]+)/);
  if (lte) return { versionStart: gte?.[1] ?? notLt?.[1], lastAffected: lte[1] };

  // Comma-separated exact version list; only 2.4.x is in scope (2.2/2.0/1.3 are EOL)
  const tokens = text.split(',').map(t => t.trim()).filter(Boolean);
  const v24 = tokens.filter(t => /^2\.4(\.|$)/.test(t));
  if (v24.length > 0) return { affectedVersions: v24 };

  return null;
}

export interface AdvisoryBlock {
  cveId: string;
  severity: string;
  title: string;
  block: string;
  index: number;
}

export function findAdvisoryBlocks(html: string): AdvisoryBlock[] {
  const headingRe = /<dt><h3 id="(CVE-\d{4}-\d+)">([a-z/]+): <name[^>]*>([^<]*)<\/name>/g;
  const hits: { index: number; cveId: string; severity: string; title: string }[] = [];
  let m: RegExpExecArray | null;
  while ((m = headingRe.exec(html)) !== null) {
    hits.push({ index: m.index, cveId: m[1], severity: m[2], title: decodeEntities(m[3]) });
  }

  return hits.map((hit, i) => {
    const end = i + 1 < hits.length ? hits[i + 1].index : html.length;
    return { ...hit, block: html.slice(hit.index, end) };
  });
}

export interface FixedHeading {
  index: number;
  version: string;
}

/**
 * The page is organized into "Fixed in Apache HTTP Server X.Y.Z" sections
 * (<h1 id="X.Y.Z">), each covering the CVEs first fixed in that release —
 * same "nearest preceding heading" shape as tomcat-fetcher.ts. This is a more
 * reliable versionFixed source than free-text prose: the "recommended to
 * upgrade to version X" phrase this file used to rely on is absent from many
 * blocks (their fix info lives only in structured table rows like "Update
 * X.Y.Z released" / "fixed by rNNNNNN in 2.4.x" instead), which was silently
 * leaving most rows' versionFixed null.
 */
export function findFixedHeadings(html: string): FixedHeading[] {
  const headingRegex = /<h1 id="([\d.]+)">Fixed in Apache HTTP Server [\d.]+<\/h1>/g;
  const headings: FixedHeading[] = [];
  let m: RegExpExecArray | null;
  while ((m = headingRegex.exec(html)) !== null) {
    headings.push({ index: m.index, version: m[1] });
  }
  return headings;
}

function fixedVersionAt(headings: FixedHeading[], index: number): string | undefined {
  let result: string | undefined;
  for (const h of headings) {
    if (h.index > index) break;
    result = h.version;
  }
  return result;
}

export function parseAdvisoryBlock(b: AdvisoryBlock, fixedHeadings: FixedHeading[]): NormalizedAdvisory | null {
  const descMatch = b.block.match(/<\/h3><\/dt>\s*<dd>\s*<p>([\s\S]*?)<\/p>/);
  const description = descMatch ? stripTags(descMatch[1]) : undefined;

  const solutionMatch = b.block.match(/recommended to upgrade to version ([\d.]+)/i);
  const proseFixed = solutionMatch?.[1];
  const headingFixed = fixedVersionAt(fixedHeadings, b.index);

  const affectsMatch = b.block.match(/<tr><td class="cve-header">Affects<\/td><td class="cve-value">([^<]*)<\/td><\/tr>/);
  const spec = affectsMatch ? parseAffects(affectsMatch[1]) : null;

  const affectedProducts: NormalizedAdvisory['affectedProducts'] = [];
  let solution: string | undefined;
  if (spec) {
    // versionFixed must only be set alongside a genuine range (versionStart..versionEnd,
    // whether that range came from "before/through X" text or was inferred below for a
    // single known-affected version). importAdvisoryData() falls back to versionFixed as
    // the range's exclusive upper bound when versionEnd is absent — applying that to a
    // multi-entry affectedVersions list (a non-contiguous set of tested releases, not
    // necessarily "every version below the highest one listed") would incorrectly widen
    // the affected range down to version zero.
    let versionStart = spec.versionStart;
    const isRange = spec.versionEnd !== undefined || spec.lastAffected !== undefined;
    const isSingleKnownVersion = !isRange && spec.affectedVersions?.length === 1;
    if (isSingleKnownVersion) versionStart = spec.affectedVersions![0];

    const versionFixed = (isRange || isSingleKnownVersion) ? (proseFixed ?? headingFixed) : undefined;
    solution = versionFixed ? `Upgrade to version ${versionFixed} or later.` : undefined;

    affectedProducts.push({
      vendor: 'apache',
      product: 'httpd',
      versionStart,
      versionEnd: spec.versionEnd,
      lastAffected: spec.lastAffected,
      affectedVersions: spec.affectedVersions,
      versionFixed,
      patchAvailable: !!versionFixed,
    });
  }

  return {
    externalId: b.cveId,
    cveId: b.cveId,
    summary: b.title,
    description,
    severity: SEVERITY_MAP[b.severity.toLowerCase()],
    url: `${PAGE_URL}#${b.cveId}`,
    solution,
    affectedProducts,
    rawData: { html: b.block },
  };
}

// ─── AdvisoryFetcher Implementation ──────────────────────────

export class ApacheFetcher implements AdvisoryFetcher {
  source(): string { return 'advisory-apache'; }
  isCompleteSnapshot(): boolean { return true; }

  async fetch(): Promise<NormalizedAdvisory[]> {
    logger.info('Fetching Apache httpd 2.4 security advisories');
    const { data: html } = await axios.get<string>(PAGE_URL, {
      timeout: 30000,
      headers: { 'User-Agent': 'heretix-api/1.0' },
      responseType: 'text',
    });

    const blocks = findAdvisoryBlocks(html);
    const fixedHeadings = findFixedHeadings(html);
    const results: NormalizedAdvisory[] = [];
    let skipped = 0;

    for (const b of blocks) {
      const advisory = parseAdvisoryBlock(b, fixedHeadings);
      if (advisory) {
        results.push(advisory);
      } else {
        skipped++;
      }
    }

    logger.info({ total: blocks.length, succeeded: results.length, skipped }, 'Apache httpd advisory fetch complete');
    return results;
  }
}
