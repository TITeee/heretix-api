import axios from 'axios';
import type { AdvisoryFetcher, NormalizedAdvisory } from './advisory-fetcher.js';
import { logger } from '../utils/logger.js';
import { MICROSOFT_VENDOR } from '../utils/advisory-version.js';
import { parseMicrosoftVersion } from '../utils/microsoft-version.js';
import { severityFromCvssScore } from '../utils/severity.js';
import { WINDOWS_SERVER_BUILDS } from '../config/support-policy.js';

// Windows Server security updates from the MSRC Security Update Guide, read
// from its CVRF API: one document per month, listing every CVE released or
// revised in it, the products it affects, and for each product the update
// (KB) that fixes it and the OS build that update brings ("FixedBuild").
//
// Windows is serviced by monthly cumulative updates that raise only the last
// number of the build (the UBR), so whether a server has a fix is a question
// of its build number: Windows Server 2022 at 10.0.20348.5761 has every fix
// whose FixedBuild is 10.0.20348.5761 or lower. That is what this stores, as
// the exclusive end of the affected range of each product.
//
// MSRC also publishes CSAF documents. The CVRF documents were chosen because
// they cover every Windows Server CVE of a month (CSAF advisories miss one or
// two a month, and CSAF VEX only goes back to September 2026), and they
// carry Microsoft's per-product severity, which CSAF VEX does not.
const UPDATES_URL = 'https://api.msrc.microsoft.com/cvrf/v3.0/updates';
const documentUrl = (id: string) => `https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/${id}`;

// The CVRF documents give a FixedBuild only from March 2021; before that they
// name the KB but not the build it brings, which cannot be compared with a
// server's build number.
const FIRST_DOCUMENT_WITH_FIXED_BUILD = { year: 2021, month: 3 };

// A daily run re-reads the documents revised in this window. MSRC revises
// older months as well as the current one (four documents on 2026-10-15).
const RECENT_WINDOW_DAYS = 7;

const HTTP = {
  // A month's document reaches 25MB.
  timeout: 300_000,
  headers: { Accept: 'application/json', 'User-Agent': 'heretix-api/1.0' },
};

// CVRF Threat types and Remediation types used below.
const THREAT_IMPACT = 0;
const THREAT_EXPLOIT_STATUS = 1;
const THREAT_SEVERITY = 3;
const REMEDIATION_VENDOR_FIX = 2;
// A regular cumulative update. Hotpatch updates ("SecurityHotpatchUpdate") are
// a separate servicing track with lower build numbers (10.0.20348.3745 against
// the regular 10.0.20348.3807 in June 2025); using one as the bound would
// leave every regular build between the two marked as fixed.
const REGULAR_UPDATE = 'Security Update';

const MONTHS = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];
const CVE_ID = /^CVE-\d{4}-\d{4,}$/;

// Microsoft's own rating, in rank order (Security Update Severity Rating System).
const MSRC_SEVERITY_RANK: Record<string, number> = { low: 1, moderate: 2, important: 3, critical: 4 };

// ─── CVRF types (the parts read here) ──────────────────────────

interface CvrfText { Value?: string }

interface CvrfVulnerability {
  CVE?: string;
  Title?: CvrfText;
  RevisionHistory?: Array<{ Date?: string }>;
  Threats?: Array<{ Type?: number; Description?: CvrfText; ProductID?: string[] }>;
  CVSSScoreSets?: Array<{ BaseScore?: number; Vector?: string; ProductID?: string[] }>;
  Remediations?: Array<{
    Type?: number;
    SubType?: string;
    Description?: CvrfText;
    URL?: string;
    FixedBuild?: string;
    Supercedence?: string;
    ProductID?: string[];
  }>;
}

export interface CvrfDocument {
  DocumentTracking?: { InitialReleaseDate?: string; CurrentReleaseDate?: string };
  ProductTree?: { FullProductName?: Array<{ ProductID?: string; Value?: string }> };
  Vulnerability?: CvrfVulnerability[];
}

interface CvrfUpdate {
  ID?: string;
  CurrentReleaseDate?: string;
}

// ─── Products ──────────────────────────────────────────────────

/**
 * The Windows Server products imported, by the name MSRC gives them, with the
 * build their updates carry. A Server Core installation is a product of its own
 * in MSRC, so each release appears twice.
 */
export function windowsServerProducts(): Map<string, number> {
  const products = new Map<string, number>();
  for (const [release, build] of Object.entries(WINDOWS_SERVER_BUILDS)) {
    products.set(`Windows Server ${release}`, build);
    products.set(`Windows Server ${release} (Server Core installation)`, build);
  }
  return products;
}

// ─── Documents ─────────────────────────────────────────────────

/** "2026-Oct" to year and month (1-12), or null for an id of another shape. */
export function parseDocumentId(id: string): { year: number; month: number } | null {
  const m = id.match(/^(\d{4})-([A-Za-z]{3})$/);
  if (!m) return null;
  const month = MONTHS.indexOf(m[2].toLowerCase()) + 1;
  return month > 0 ? { year: Number(m[1]), month } : null;
}

function hasFixedBuilds(id: string): boolean {
  const d = parseDocumentId(id);
  if (!d) return false;
  const first = FIRST_DOCUMENT_WITH_FIXED_BUILD;
  return d.year > first.year || (d.year === first.year && d.month >= first.month);
}

/**
 * The documents to read: every one from March 2021 for a full run. A daily run
 * reads those revised within the last RECENT_WINDOW_DAYS, and always the latest
 * month's: a week with no revision would otherwise read nothing, and a run that
 * returns no advisories is recorded as failed (runAdvisoryFetcher).
 */
export function selectDocuments(updates: CvrfUpdate[], full: boolean, now = new Date()): string[] {
  const candidates = updates.filter((u): u is CvrfUpdate & { ID: string } => !!u.ID && hasFixedBuilds(u.ID));
  if (full) return candidates.map(u => u.ID);

  const order = (id: string) => { const d = parseDocumentId(id)!; return d.year * 12 + d.month; };
  const latest = candidates.reduce<string | undefined>((best, u) => (!best || order(u.ID) > order(best) ? u.ID : best), undefined);
  const since = now.getTime() - RECENT_WINDOW_DAYS * 24 * 60 * 60 * 1000;
  return candidates
    .filter(u => u.ID === latest || (u.CurrentReleaseDate !== undefined && Date.parse(u.CurrentReleaseDate) >= since))
    .map(u => u.ID);
}

// ─── Advisories ────────────────────────────────────────────────

interface ProductFix {
  product: string;
  kb: string;
  fixedBuild: string;
  url?: string;
  supersedes?: string;
}

/**
 * A CVRF date. They are UTC but written without a zone ("2026-10-13T07:00:00"),
 * which Date would read as local time.
 */
export function parseMsrcDate(value: string | undefined): Date | undefined {
  if (!value) return undefined;
  const date = new Date(/(?:Z|[+-]\d\d:?\d\d)$/i.test(value) ? value : `${value}Z`);
  return Number.isNaN(date.getTime()) ? undefined : date;
}

/**
 * First and latest revision dates of a CVE entry: when it was published, and
 * which of two documents describes it more recently. The entry's own
 * ReleaseDate is never filled in (ReleaseDateSpecified is false, the value
 * 0001-01-01), so the revision history is the only source of either.
 */
function revisionDates(v: CvrfVulnerability): { first?: Date; latest?: Date } {
  const dates = (v.RevisionHistory ?? [])
    .map(r => parseMsrcDate(r.Date))
    .filter((d): d is Date => d !== undefined)
    .sort((a, b) => a.getTime() - b.getTime());
  return { first: dates[0], latest: dates.at(-1) };
}

/**
 * One advisory per CVE of the document that a regular cumulative update fixes
 * on at least one imported Windows Server product. Each such product becomes an
 * affected product whose range ends (exclusive) at the update's build.
 *
 * Left out, so a server's build never decides them:
 *  - ADV advisories, whose updates (e.g. servicing stack) are not the fix of a CVE;
 *  - products affected without a fixed build, such as CVE-2013-3900, whose fix is
 *    an opt-in registry setting no update applies.
 *
 * When two regular updates fix a CVE on one product (an out-of-band update next to
 * the monthly one), the lower build is the bound: a server at either has the fix.
 */
export function buildMsrcAdvisories(doc: CvrfDocument, documentId: string): NormalizedAdvisory[] {
  const products = windowsServerProducts();
  const productById = new Map<string, string>();
  for (const p of doc.ProductTree?.FullProductName ?? []) {
    if (p.ProductID && p.Value && products.has(p.Value)) productById.set(p.ProductID, p.Value);
  }
  if (productById.size === 0) return [];

  const results: NormalizedAdvisory[] = [];
  for (const v of doc.Vulnerability ?? []) {
    const cve = v.CVE?.trim();
    if (!cve || !CVE_ID.test(cve)) continue;

    const fixes = new Map<string, ProductFix>();
    const hotpatches: ProductFix[] = [];
    for (const r of v.Remediations ?? []) {
      if (r.Type !== REMEDIATION_VENDOR_FIX) continue;
      for (const id of r.ProductID ?? []) {
        const product = productById.get(id);
        if (!product) continue;
        const build = r.FixedBuild?.trim() ?? '';
        const parsed = parseMicrosoftVersion(build);
        // A build of another release would make the bound meaningless for this product.
        if (!parsed || parsed[2] !== products.get(product)) continue;
        const fix: ProductFix = {
          product,
          kb: r.Description?.Value?.trim() ?? '',
          fixedBuild: build,
          url: r.URL,
          supersedes: r.Supercedence,
        };
        if (r.SubType !== REGULAR_UPDATE) {
          hotpatches.push(fix);
          continue;
        }
        const current = fixes.get(product);
        if (!current || parseMicrosoftVersion(current.fixedBuild)![3] > parsed[3]) fixes.set(product, fix);
      }
    }
    if (fixes.size === 0) continue;

    const fixedIds = new Set([...productById].filter(([, name]) => fixes.has(name)).map(([id]) => id));
    const onFixedProduct = (ids: string[] | undefined) => (ids ?? []).some(id => fixedIds.has(id));

    // Microsoft's rating, the highest any fixed product gets.
    let msrcSeverity: string | undefined;
    for (const t of v.Threats ?? []) {
      if (t.Type !== THREAT_SEVERITY || !onFixedProduct(t.ProductID)) continue;
      const rating = t.Description?.Value?.trim();
      if (rating && (MSRC_SEVERITY_RANK[rating.toLowerCase()] ?? 0) > (MSRC_SEVERITY_RANK[msrcSeverity?.toLowerCase() ?? ''] ?? 0)) {
        msrcSeverity = rating;
      }
    }

    // The highest CVSS score among the fixed products.
    let cvss: { score: number; vector?: string } | undefined;
    for (const s of v.CVSSScoreSets ?? []) {
      if (typeof s.BaseScore !== 'number' || !onFixedProduct(s.ProductID)) continue;
      if (!cvss || s.BaseScore > cvss.score) cvss = { score: s.BaseScore, vector: s.Vector };
    }

    const threatText = (type: number) =>
      (v.Threats ?? []).find(t => t.Type === type && (!t.ProductID?.length || onFixedProduct(t.ProductID)))?.Description?.Value;

    const fixList = [...fixes.values()].sort((a, b) => a.product.localeCompare(b.product));
    const revisions = revisionDates(v);

    results.push({
      externalId: cve,
      cveId: cve,
      summary: v.Title?.Value?.trim() || undefined,
      severity: cvss && cvss.score > 0 ? severityFromCvssScore(cvss.score) : undefined,
      cvssScore: cvss?.score,
      cvssVector: cvss?.vector,
      distroPriority: msrcSeverity,
      url: `https://msrc.microsoft.com/update-guide/vulnerability/${cve}`,
      solution: fixList.map(f => `${f.product}: ${f.kb ? `KB${f.kb}` : 'update'} (OS build ${f.fixedBuild})`).join('; ') +
        ', or any later cumulative update',
      publishedAt: revisions.first,
      affectedProducts: fixList.map(f => ({
        vendor: MICROSOFT_VENDOR,
        product: f.product,
        versionEnd: f.fixedBuild,
        versionFixed: f.fixedBuild,
        patchAvailable: true,
      })),
      rawData: {
        document: documentId,
        revisedAt: revisions.latest?.toISOString(),
        impact: threatText(THREAT_IMPACT),
        exploitStatus: threatText(THREAT_EXPLOIT_STATUS),
        fixes: fixList,
        hotpatchFixes: hotpatches,
      },
    });
  }
  return results;
}

/**
 * Keep one advisory per CVE when it appears in several documents (a CVE revised
 * in a later month is listed there again): the one revised most recently.
 */
export function latestRevisions(advisories: NormalizedAdvisory[]): NormalizedAdvisory[] {
  const byCve = new Map<string, NormalizedAdvisory>();
  const revised = (a: NormalizedAdvisory) => (a.rawData as { revisedAt?: string }).revisedAt ?? '';
  for (const adv of advisories) {
    const kept = byCve.get(adv.externalId);
    if (!kept || revised(adv) >= revised(kept)) byCve.set(adv.externalId, adv);
  }
  return [...byCve.values()];
}

// ─── Fetcher ───────────────────────────────────────────────────

export class MsrcFetcher implements AdvisoryFetcher {
  private failedCount = 0;

  /** full: read every document from March 2021 instead of only the recently revised ones. */
  constructor(private readonly options: { full?: boolean } = {}) {}

  source(): string { return 'advisory-microsoft'; }
  // Only a full run that read every document is complete: a document that
  // failed would leave its CVEs out and get them pruned as retracted.
  isCompleteSnapshot(): boolean { return this.options.full === true && this.failedCount === 0; }
  fetchFailedCount(): number { return this.failedCount; }

  async fetch(): Promise<NormalizedAdvisory[]> {
    this.failedCount = 0;
    const full = this.options.full === true;
    const { data } = await axios.get<{ value?: CvrfUpdate[] }>(UPDATES_URL, HTTP);
    const ids = selectDocuments(data.value ?? [], full);
    logger.info({ documents: ids.length, full }, 'Fetching MSRC CVRF documents');

    const advisories: NormalizedAdvisory[] = [];
    for (const id of ids) {
      try {
        const { data: doc } = await axios.get<CvrfDocument>(documentUrl(id), HTTP);
        const fromDoc = buildMsrcAdvisories(doc, id);
        logger.info({ document: id, advisories: fromDoc.length }, 'Read MSRC CVRF document');
        advisories.push(...fromDoc);
      } catch (err) {
        this.failedCount++;
        logger.warn({ document: id, err }, 'Failed to fetch MSRC CVRF document');
      }
    }
    const results = latestRevisions(advisories);
    logger.info({ documents: ids.length, advisories: results.length, failed: this.failedCount }, 'MSRC advisory fetch complete');
    return results;
  }
}
