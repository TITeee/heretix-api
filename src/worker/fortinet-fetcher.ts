import axios from 'axios';
import { XMLParser } from 'fast-xml-parser';
import type { AdvisoryFetcher, NormalizedAdvisory } from './advisory-fetcher.js';
import { logger } from '../utils/logger.js';

const RSS_URL = 'https://filestore.fortinet.com/fortiguard/rss/ir.xml';
const CSAF_BASE = 'https://filestore.fortinet.com/fortiguard/psirt';

// ─── CSAF 2.0 Type Definitions ────────────────────────────────

interface CsafDocument {
  document: {
    title: string;
    tracking: {
      id: string;
      initial_release_date: string;
    };
  };
  product_tree: { branches: CsafBranch[] };
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
  }>;
  notes?: Array<{ category: string; title?: string; text: string }>;
  product_status?: {
    known_affected?: string[];
    known_not_affected?: string[];
  };
  remediations?: Array<{ category: string; details: string; product_ids?: string[] }>;
  references?: Array<{ url: string; summary: string }>;
}

// ─── Utilities ────────────────────────────────────────────────

/** Convert RSS title → CSAF URL slug */
function titleToSlug(title: string): string {
  return title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');
}

/** Build CSAF JSON URL */
function buildCsafUrl(title: string, advisoryId: string): string {
  return `${CSAF_BASE}/csaf_${titleToSlug(title)}_${advisoryId.toLowerCase()}.json`;
}

/** Collect all product names from product_tree */
function collectProductNames(branches: CsafBranch[]): Set<string> {
  const names = new Set<string>();
  function walk(bs: CsafBranch[]) {
    for (const b of bs) {
      if (b.category === 'product') names.add(b.name);
      if (b.branches) walk(b.branches);
    }
  }
  walk(branches);
  return names;
}

/**
 * Extract product name from CSAF product_id
 * "FortiOS >=7.6.0|<=7.6.1" → "FortiOS"
 * "FortiAnalyzer Cloud 7.4 all versions" → "FortiAnalyzer Cloud"
 */
function extractProductName(productId: string, knownProducts: Set<string>): string | null {
  // Try longer names first ("FortiAnalyzer Cloud" before "FortiAnalyzer")
  const sorted = [...knownProducts].sort((a, b) => b.length - a.length);
  for (const name of sorted) {
    if (productId.startsWith(name)) return name;
  }
  // "ProductName-X.Y.Z" format (appears in known_not_affected)
  for (const name of sorted) {
    if (productId.startsWith(name + '-')) return name;
  }
  return null;
}

/**
 * Parse a version specification string
 * ">=7.6.0|<=7.6.1" → range
 * "7.2 all versions" → heuristic range
 * "6.2.0"           → exact version
 */
function parseVersionSpec(productId: string, productName: string): {
  versionStart?: string;
  versionEnd?: string;
  lastAffected?: string;
  exactVersions?: string[];
} | null {
  // "ProductName-X.Y.Z" format (fixed version)
  if (productId.startsWith(productName + '-')) {
    const v = productId.slice(productName.length + 1);
    return { exactVersions: [v] };
  }

  // Get the spec portion after the product name
  let spec = productId.slice(productName.length).replace(/^[\s/]+/, '').trim();
  if (!spec) return null;

  // ">=X.Y.Z|<=A.B.C"
  const rangeMatch = spec.match(/^>=?(\d[\d.]+[^\s|]*)\|<=?(\d[\d.]+\S*)$/);
  if (rangeMatch) {
    return { versionStart: rangeMatch[1], lastAffected: rangeMatch[2] };
  }

  // "X.Y all versions"
  const allMatch = spec.match(/^(\d+)\.(\d+)\s+all\s+versions$/i);
  if (allMatch) {
    const major = Number(allMatch[1]);
    const minor = Number(allMatch[2]);
    return {
      versionStart: `${major}.${minor}.0`,
      versionEnd:   `${major}.${minor + 1}.0`,
    };
  }

  // "X.Y.Z" exact match
  if (/^\d+\.\d+\.\d+$/.test(spec)) {
    return { exactVersions: [spec] };
  }

  // Other (non-semver, etc.): retain as string
  return { exactVersions: [spec] };
}

/**
 * Match a fixed version by branch
 * For branch "7.6" derived from "7.6.0", find a fixed version like "7.6.2"
 */
function findFixVersion(
  versionStart: string | undefined,
  notAffectedVersions: string[],
): string | undefined {
  if (!versionStart) return undefined;
  const branch = versionStart.split('.').slice(0, 2).join('.');
  const matching = notAffectedVersions.filter(v => v.startsWith(branch + '.'));
  return matching.sort()[0];
}

// ─── CSAF → NormalizedAdvisory Conversion ────────────────────

function parseCsaf(csaf: CsafDocument, advisoryId: string, pubDate?: Date): NormalizedAdvisory | null {
  const vulns = csaf.vulnerabilities ?? [];
  if (vulns.length === 0) return null;

  const knownProducts = collectProductNames(csaf.product_tree?.branches ?? []);

  // Get CVE, CVSS, and summary from the first vulnerability entry
  const firstVuln = vulns[0];
  const cveId = firstVuln.cve;

  // Select the highest CVSS score from all entries
  let cvssScore: number | undefined;
  let cvssVector: string | undefined;
  let severity: string | undefined;
  for (const v of vulns) {
    for (const s of v.scores ?? []) {
      if (s.cvss_v3 && (!cvssScore || s.cvss_v3.baseScore > cvssScore)) {
        cvssScore  = s.cvss_v3.baseScore;
        cvssVector = s.cvss_v3.vectorString;
        severity   = s.cvss_v3.baseSeverity;
      }
    }
  }

  const summaryNote    = firstVuln.notes?.find(n => n.category === 'summary');
  const workaroundNote = firstVuln.notes?.find(n => n.title === 'Workarounds');
  const fixRemediation = firstVuln.remediations?.find(r => r.category === 'vendor_fix');
  const refUrl         = firstVuln.references?.[0]?.url;

  // Create one record per known_affected entry
  // (handles products with multiple non-contiguous version branches)
  const affectedProducts: NormalizedAdvisory['affectedProducts'] = [];
  const seenRanges = new Set<string>();

  for (const v of vulns) {
    // Fixed version list for this vulnerability entry (semver-like only)
    const notAffectedVersions = (v.product_status?.known_not_affected ?? [])
      .map(pid => {
        const name = extractProductName(pid, knownProducts);
        if (!name) return null;
        const spec = parseVersionSpec(pid, name);
        return spec?.exactVersions?.filter(ev => /^\d+\.\d+\.\d+/.test(ev)) ?? [];
      })
      .flat()
      .filter(Boolean) as string[];

    for (const pid of v.product_status?.known_affected ?? []) {
      // Deduplicate
      if (seenRanges.has(pid)) continue;
      seenRanges.add(pid);

      const name = extractProductName(pid, knownProducts);
      if (!name) continue;

      const spec = parseVersionSpec(pid, name);
      if (!spec) continue;

      if (spec.exactVersions?.length) {
        // Single version specification
        affectedProducts.push({
          vendor:          'fortinet',
          product:         name,
          affectedVersions: spec.exactVersions,
          patchAvailable:  notAffectedVersions.length > 0,
        });
      } else {
        // Version range specification (one record per branch)
        const versionFixed = findFixVersion(spec.versionStart, notAffectedVersions);
        affectedProducts.push({
          vendor:        'fortinet',
          product:       name,
          versionStart:  spec.versionStart,
          versionEnd:    spec.versionEnd,      // "all versions" → exclusive end (heuristic)
          lastAffected:  spec.lastAffected,    // inclusive end of ">=X|<=Y" range
          versionFixed,
          patchAvailable: !!versionFixed,
        });
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
    url:         refUrl ?? `https://fortiguard.fortinet.com/psirt/${advisoryId}`,
    workaround:  workaroundNote?.text === 'N/A' ? undefined : workaroundNote?.text?.trim(),
    solution:    fixRemediation?.details,
    publishedAt,
    affectedProducts,
    rawData:     csaf,
  };
}

// ─── RSS Fetching ─────────────────────────────────────────────

interface RssItem {
  title: string;
  link:  string;
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

function extractAdvisoryId(link: string): string | null {
  const m = link.match(/FG-IR-\d{2}-\d+/);
  return m ? m[0] : null;
}

// ─── AdvisoryFetcher Implementation ──────────────────────────

export class FortinetFetcher implements AdvisoryFetcher {
  private readonly delayMs: number;

  constructor({ delayMs = 300 } = {}) {
    this.delayMs = delayMs;
  }

  source(): string { return 'fortinet'; }

  async fetch(): Promise<NormalizedAdvisory[]> {
    logger.info('Fetching Fortinet PSIRT RSS feed');
    const items = await fetchRssItems();
    logger.info({ count: items.length }, 'Fetched Fortinet RSS items');

    const results: NormalizedAdvisory[] = [];
    let skipped = 0;
    let failed  = 0;

    for (const item of items) {
      const advisoryId = extractAdvisoryId(item.link);
      if (!advisoryId) {
        logger.warn({ link: item.link }, 'Could not extract advisory ID from link');
        skipped++;
        continue;
      }

      const url = buildCsafUrl(item.title, advisoryId);
      logger.debug({ advisoryId, url }, 'Fetching CSAF JSON');

      try {
        const { data } = await axios.get<CsafDocument>(url, {
          timeout: 15000,
          headers: { 'User-Agent': 'heretix-api/1.0' },
        });

        const pubDate  = item.pubDate ? new Date(item.pubDate) : undefined;
        const advisory = parseCsaf(data, advisoryId, pubDate);

        if (advisory) {
          results.push(advisory);
        } else {
          logger.warn({ advisoryId }, 'No parseable vulnerability data in CSAF');
          skipped++;
        }
      } catch (err) {
        failed++;
        logger.error({ err, advisoryId, url }, 'Failed to fetch/parse CSAF for advisory');
      }

      // Wait to reduce server load
      await new Promise(r => setTimeout(r, this.delayMs));
    }

    logger.info(
      { total: items.length, succeeded: results.length, skipped, failed },
      'Fortinet PSIRT fetch complete',
    );
    return results;
  }
}
