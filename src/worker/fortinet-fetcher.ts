import axios from 'axios';
import type { AdvisoryFetcher, NormalizedAdvisory } from './advisory-fetcher.js';
import { logger } from '../utils/logger.js';

const CSAF_BASE = 'https://filestore.fortinet.com/fortiguard/psirt';
const PSIRT_LIST_URL = 'https://fortiguard.fortinet.com/psirt';

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

export interface CsafVulnerability {
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
  const spec = productId.slice(productName.length).replace(/^[\s/]+/, '').trim();
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

/** Numeric comparison of dotted versions ("7.4.2" < "7.4.10"). */
function compareDotted(a: string, b: string): number {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

/**
 * Fixed version for the last affected version of a branch: the exactly-listed
 * one ("FortiOS 7.4.1"), or a range's last ("FortiOS >=7.4.0|<=7.4.5" -> 7.4.5,
 * "7.4 all versions" -> 7.4.0).
 *
 * known_not_affected usually names it ("FortiOS-7.4.2"), but not always: a
 * cloud service's fix can appear only in the remediation text ("FortiSandbox
 * Cloud 5.0: Fortinet remediated this issue in 5.0.5 ..."). Either way it must
 * be a later release of the same product and branch, past the last affected
 * version. known_not_affected lists every product's fixed versions together,
 * and one product can have two ranges on a branch: FG-IR-24-463 labels its
 * FortiManager Cloud ranges FortiManager too, so FortiManager 7.4 has fixes
 * 7.4.5 and 7.4.6, and taking the branch's lowest gave the range up to 7.4.5 the
 * fix 7.4.5. A fix on another branch says nothing about this version.
 */
function findFixAfter(
  affected: string,
  productName: string,
  notAffectedVersions: string[],
  remediation: string | undefined,
): string | undefined {
  if (!/^\d+\.\d+\.\d+$/.test(affected)) return undefined;
  const branch = affected.split('.').slice(0, 2).join('.');
  const isLaterOnBranch = (v: string) => /^\d+\.\d+\.\d+$/.test(v) && v.startsWith(branch + '.') && compareDotted(v, affected) > 0;

  const fromStatus = notAffectedVersions.filter(isLaterOnBranch).sort(compareDotted)[0];
  if (fromStatus) return fromStatus;

  // "<product> <branch>: Upgrade to 7.4.2 or above" / "...remediated this issue in 5.0.5 ..."
  for (const line of (remediation ?? '').split('\n')) {
    const m = line.trim().match(/^(.+?)\s+(\d+(?:\.\d+)*):\s.*?(?:Upgrade to|remediated (?:this issue )?in)\s+(\d+(?:\.\d+)+)/i);
    if (m && m[1] === productName && m[2] === branch && isLaterOnBranch(m[3])) return m[3];
  }
  return undefined;
}

// ─── CSAF → NormalizedAdvisory Conversion ────────────────────

export function parseCsaf(csaf: CsafDocument, advisoryId: string): NormalizedAdvisory | null {
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
  const fixRemediation = firstVuln.remediations?.find(r => r.category === 'vendor_fix');
  const refUrl         = firstVuln.references?.[0]?.url;

  // Create one record per known_affected entry
  // (handles products with multiple non-contiguous version branches)
  const affectedProducts: NormalizedAdvisory['affectedProducts'] = [];
  const seenRanges = new Set<string>();

  for (const v of vulns) {
    // Fixed versions of this vulnerability entry, by product (semver-like only)
    const notAffectedByProduct = new Map<string, string[]>();
    for (const pid of v.product_status?.known_not_affected ?? []) {
      const name = extractProductName(pid, knownProducts);
      if (!name) continue;
      const spec = parseVersionSpec(pid, name);
      const versions = spec?.exactVersions?.filter(ev => /^\d+\.\d+\.\d+/.test(ev)) ?? [];
      notAffectedByProduct.set(name, [...(notAffectedByProduct.get(name) ?? []), ...versions]);
    }
    const anyNotAffected = [...notAffectedByProduct.values()].some(vs => vs.length > 0);

    for (const pid of v.product_status?.known_affected ?? []) {
      // Deduplicate
      if (seenRanges.has(pid)) continue;
      seenRanges.add(pid);

      const name = extractProductName(pid, knownProducts);
      if (!name) continue;

      const spec = parseVersionSpec(pid, name);
      if (!spec) continue;
      const notAffectedVersions = notAffectedByProduct.get(name) ?? [];

      if (spec.exactVersions?.length) {
        // Single version specification
        const exact = spec.exactVersions[0];
        const exactFixed = spec.exactVersions.length === 1
          ? findFixAfter(exact, name, notAffectedVersions, fixRemediation?.details)
          : undefined;
        affectedProducts.push({
          vendor:          'fortinet',
          product:         name,
          // Bounded on both sides: versionFixed alone would turn the exact
          // version into an open range from zero.
          versionStart:    exactFixed ? exact : undefined,
          versionFixed:    exactFixed,
          affectedVersions: spec.exactVersions,
          patchAvailable:  anyNotAffected || !!exactFixed,
        });
      } else {
        // Version range specification (one record per branch). Past the range's
        // last version; for "all versions", past its first.
        const last = spec.lastAffected ?? spec.versionStart;
        const versionFixed = last ? findFixAfter(last, name, notAffectedVersions, fixRemediation?.details) : undefined;
        affectedProducts.push({
          vendor:        'fortinet',
          product:       name,
          versionStart:  spec.versionStart,
          // "all versions" → exclusive end at the next branch (heuristic), unless
          // the branch has a fix: "7.4 all versions" with "Upgrade to 7.4.11" is
          // affected up to 7.4.11, not through 7.4.11 and later.
          versionEnd:    versionFixed ? undefined : spec.versionEnd,
          lastAffected:  spec.lastAffected,    // inclusive end of ">=X|<=Y" range
          versionFixed,
          patchAvailable: !!versionFixed,
        });
      }
    }
  }

  if (affectedProducts.length === 0) return null;

  const publishedAt = csaf.document.tracking.initial_release_date
    ? new Date(csaf.document.tracking.initial_release_date)
    : undefined;

  return {
    externalId:  advisoryId,
    cveId,
    summary:     summaryNote?.text?.trim(),
    severity,
    cvssScore,
    cvssVector,
    url:         refUrl ?? `https://fortiguard.fortinet.com/psirt/${advisoryId}`,
    workaround:  extractWorkaround(vulns),
    solution:    fixRemediation?.details,
    publishedAt,
    affectedProducts,
    rawData:     csaf,
  };
}

/**
 * The advisory's workarounds, verbatim. Fortinet writes them in three places:
 * a "mitigation" remediation (virtual patches: "A virtual patch is available.
 * FortiGuard IPS signature package: ..."), the "Additional info" note
 * ("Workaround: Disable SNMP entirely ..."), and rarely a "Workarounds" note,
 * which in practice only ever says "N/A". An "Additional info" note that does
 * not mention a workaround or mitigation is something else ("Fortinet PSIRT is
 * currently investigating ...", "FortiAnalyzer Cloud is not affected") and is
 * left out. Each text is kept once, however many CVE entries repeat it.
 */
export function extractWorkaround(vulns: CsafVulnerability[]): string | undefined {
  const texts: string[] = [];
  const add = (text: string | undefined) => {
    const t = text?.trim();
    if (t && t !== 'N/A' && !texts.includes(t)) texts.push(t);
  };
  for (const v of vulns) {
    for (const r of v.remediations ?? []) if (r.category === 'mitigation') add(r.details);
    for (const n of v.notes ?? []) {
      if (n.title === 'Workarounds' || (n.title === 'Additional info' && /workaround|mitigat/i.test(n.text))) add(n.text);
    }
  }
  return texts.length > 0 ? texts.join('\n\n') : undefined;
}

// ─── Full PSIRT Listing (paginated) ──────────────────────────

export interface AdvisoryListEntry {
  advisoryId: string;
  title: string;
}

/**
 * Advisory id + title of every row on one PSIRT listing page.
 *
 * Reads the row's own "<b>FG-IR-23-165 Title</b>" rather than the link: the
 * row's link has already moved once -- from an inline
 * `onclick="location.href = '/psirt/FG-IR-..'"` attribute to an
 * `addEventListener` script at the end of the page (2026-08) -- and matching
 * on it made every page look empty, so the fetcher silently returned nothing
 * for six weeks. The CVE ids in the same cell are `<b class="cve">`, so a bare
 * `<b>` holding an FG-IR id is the row heading and nothing else.
 */
export function parseListingPage(html: string): AdvisoryListEntry[] {
  const seen = new Set<string>();
  const entries: AdvisoryListEntry[] = [];
  for (const m of html.matchAll(/<b>\s*(FG-IR-\d{2}-\d+)\s+([^<]+?)\s*<\/b>/g)) {
    if (seen.has(m[1])) continue;
    seen.add(m[1]);
    entries.push({ advisoryId: m[1], title: decodeHtmlEntities(m[2]) });
  }
  return entries;
}

// The title feeds the CSAF file name (buildCsafUrl()), so an undecoded
// "Products&#39; FortiCloud" turned into a "...-products-39-forticloud-..."
// URL that does not exist (FG-IR-25-647).
function decodeHtmlEntities(s: string): string {
  return s
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(Number(n)))
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/&quot;/g, '"')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&');
}

/**
 * Scrape every page of the PSIRT advisory listing (not just the RSS feed's
 * rolling window of recent items). RSS is a "what's new" feed and only ever
 * exposes ~50 recent advisories — it has no way to discover older ones. This
 * listing page paginates through the full historical archive instead
 * (id + title embedded directly in each row, e.g.
 * `<b>FG-IR-23-165 Use of uninitialized resource in SSLVPN websocket</b>`),
 * mirroring PanFetcher's fetchAllAdvisoryIds().
 */
async function fetchAllAdvisoryEntries(): Promise<AdvisoryListEntry[]> {
  const entries: AdvisoryListEntry[] = [];

  for (let page = 1; ; page++) {
    const { data } = await axios.get<string>(`${PSIRT_LIST_URL}?page=${page}`, {
      timeout: 30000,
      headers: { 'User-Agent': 'heretix-api/1.0' },
      responseType: 'text',
    });

    const pageEntries = parseListingPage(data);
    if (pageEntries.length === 0) break;

    entries.push(...pageEntries);
    logger.debug({ page, found: pageEntries.length, total: entries.length }, 'Scraped Fortinet PSIRT listing page');
    await new Promise(r => setTimeout(r, 500));
  }

  return entries;
}

// ─── AdvisoryFetcher Implementation ──────────────────────────

export class FortinetFetcher implements AdvisoryFetcher {
  private readonly delayMs: number;
  private fetchFailed = 0;

  constructor({ delayMs = 300 }: { delayMs?: number } = {}) {
    this.delayMs = delayMs;
  }

  source(): string { return 'fortinet'; }
  isCompleteSnapshot(): boolean { return true; }
  fetchFailedCount(): number { return this.fetchFailed; }

  async fetch(): Promise<NormalizedAdvisory[]> {
    this.fetchFailed = 0;
    logger.info('Fetching Fortinet PSIRT advisory list (all pages)');
    const entries = await fetchAllAdvisoryEntries();
    logger.info({ count: entries.length }, 'Fetched Fortinet advisory list entries');

    const results: NormalizedAdvisory[] = [];
    let skipped = 0;

    for (const { advisoryId, title } of entries) {
      const url = buildCsafUrl(title, advisoryId);
      logger.debug({ advisoryId, url }, 'Fetching CSAF JSON');

      try {
        const { data } = await axios.get<CsafDocument>(url, {
          timeout: 15000,
          headers: { 'User-Agent': 'heretix-api/1.0' },
        });

        const advisory = parseCsaf(data, advisoryId);

        if (advisory) {
          results.push(advisory);
        } else {
          logger.warn({ advisoryId }, 'No parseable vulnerability data in CSAF');
          skipped++;
        }
      } catch (err) {
        this.fetchFailed++;
        logger.error({ err, advisoryId, url }, 'Failed to fetch/parse CSAF for advisory');
      }

      // Wait to reduce server load
      await new Promise(r => setTimeout(r, this.delayMs));
    }

    logger.info(
      { total: entries.length, succeeded: results.length, skipped, failed: this.fetchFailed },
      'Fortinet PSIRT fetch complete',
    );
    return results;
  }
}
