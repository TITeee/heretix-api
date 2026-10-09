import axios from 'axios';
import type { AdvisoryFetcher, NormalizedAdvisory } from './advisory-fetcher.js';
import { logger } from '../utils/logger.js';
import { closeBrowser, withPage } from '../utils/browser.js';
import { IVANTI_VENDOR } from '../utils/advisory-version.js';
import { compareIvantiVersions, ivantiLine, parseIvantiVersion } from '../utils/ivanti-version.js';
import { buildLegacyIvantiAdvisories } from './ivanti-legacy-advisories.js';

// Ivanti publishes its security advisories as knowledge articles on the
// Innovators Hub (a Salesforce community, formerly forums.ivanti.com). The
// pages are rendered client-side, so a plain HTTP GET returns only an empty
// shell; a headless browser renders the article, whose body carries a CVE table
// and an "Affected Versions" table (affected and resolved versions per product).
// The sitemap lists every article; the advisories are the ones whose name
// contains "Security-Advisory". Ivanti offers no feed or API of its own for
// them -- the RSS on ivanti.com only announces each month's advisories.
const HUB = 'https://hub.ivanti.com';
const SITEMAP_INDEX_URL = `${HUB}/s/sitemap.xml`;
const ARTICLE_SITEMAP = /<loc>(https:\/\/hub\.ivanti\.com\/s\/sitemap-topicarticle-\d+\.xml)<\/loc>/g;
const ARTICLE_URL = /<loc>(https:\/\/hub\.ivanti\.com\/s\/article\/([^<?]*Security-Advisory[^<?]*))(?:\?[^<]*)?<\/loc>/gi;
const CVE_ID = /CVE-\d{4}-\d{4,}/g;

// ─── Types ─────────────────────────────────────────────────────

/** What the browser hands back for one rendered article: text, and tables as rows of cell text. */
export interface RenderedArticle {
  url: string;
  urlName: string;
  bodyText: string;
  tables: string[][][];
}

interface CveRow {
  cve: string;
  description?: string;
  score?: number;
  severity?: string;
  vector?: string;
}

export interface AffectedSpec {
  start?: string;
  last?: string;
  end?: string;
  exact?: string;
}

export interface ProductVersions {
  versionStart?: string;
  versionEnd?: string;
  lastAffected?: string;
  versionFixed?: string;
  affectedVersions?: string[];
}

// ─── Article text ──────────────────────────────────────────────

/**
 * The editor Ivanti writes articles in puts non-breaking spaces into some
 * headers and cells ("Affected&nbsp;Version(s)"), which no pattern for a plain
 * space matches -- the EPMM advisory for CVE-2026-1281 read as having no
 * version table at all. Any whitespace but a newline is folded to a plain space
 * here, once, at the boundary.
 */
export function normalizeArticle(article: RenderedArticle): RenderedArticle {
  const fold = (s: string) => s.replace(/[^\S\n]/g, ' ');
  return {
    ...article,
    bodyText: fold(article.bodyText),
    tables: article.tables.map(t => t.map(r => r.map(fold))),
  };
}

function lines(text: string): string[] {
  return text.split('\n').map(l => l.trim()).filter(Boolean);
}

/** The value printed on the line after a label ("Created Date" -> "Jan 29, 2026 ..."). */
function valueAfter(body: string, label: string): string | undefined {
  const ls = lines(body);
  const i = ls.indexOf(label);
  return i >= 0 ? ls[i + 1] : undefined;
}

/** The article title is the line just above the "Primary Product" label. */
export function articleTitle(body: string, urlName: string): string {
  const ls = lines(body);
  const i = ls.indexOf('Primary Product');
  if (i > 0) return ls[i - 1];
  return decodeURIComponent(urlName).replace(/-+/g, ' ').trim();
}

const SECTION_HEADINGS = [
  'Summary', 'Vulnerability Details', 'Affected Versions', 'Solution', 'Mitigation', 'Mitigations',
  'Mitigation or Workaround', 'Workaround', 'Workarounds', 'Acknowledgements', 'FAQ', 'Note', 'Revision History',
];

/** Text from a heading line up to the next known heading ("Solution" -> its body). */
export function sectionText(body: string, names: string[]): string | undefined {
  const ls = lines(body);
  const heading = (l: string) => SECTION_HEADINGS.includes(l.replace(/[:：]\s*$/, ''));
  const start = ls.findIndex(l => names.includes(l.replace(/[:：]\s*$/, '')));
  if (start < 0) return undefined;
  const out: string[] = [];
  for (let i = start + 1; i < ls.length && !heading(ls[i]); i++) out.push(ls[i]);
  const text = out.join('\n').trim();
  return text || undefined;
}

// ─── Tables ────────────────────────────────────────────────────

function findTable(tables: string[][][], header: RegExp): string[][] | undefined {
  return tables.find(t => t.length > 0 && t[0].some(c => header.test(c)));
}

function columnIndex(header: string[], re: RegExp): number {
  return header.findIndex(c => re.test(c.trim()));
}

function severityOf(label: string | undefined): string | undefined {
  const m = label?.match(/\((critical|high|medium|low)\)/i);
  return m ? m[1].toUpperCase() : undefined;
}

/** The "CVE Number | Description | CVSS Score (Severity) | CVSS Vector | CWE" table. */
export function parseCveTable(tables: string[][][]): CveRow[] {
  const table = findTable(tables, /^CVE( Number)?$/i);
  if (!table) return [];
  const header = table[0];
  const iCve = columnIndex(header, /^CVE/i);
  const iDesc = columnIndex(header, /^Description/i);
  const iScore = columnIndex(header, /^CVSS Score/i);
  const iVector = columnIndex(header, /^CVSS Vector/i);

  const rows: CveRow[] = [];
  for (const row of table.slice(1)) {
    for (const cve of row[iCve]?.match(CVE_ID) ?? []) {
      const scoreText = iScore >= 0 ? row[iScore] : undefined;
      const score = scoreText ? parseFloat(scoreText) : NaN;
      rows.push({
        cve,
        description: iDesc >= 0 ? row[iDesc]?.replace(/\s+/g, ' ').trim() || undefined : undefined,
        score: Number.isNaN(score) ? undefined : score,
        severity: severityOf(scoreText),
        vector: iVector >= 0 ? row[iVector]?.trim() || undefined : undefined,
      });
    }
  }
  return rows;
}

// ─── Versions ──────────────────────────────────────────────────

/** A cell's entries, one per line or comma; a note in brackets ("22.7R2.6 (released February 2025)") is dropped. */
function cellParts(cell: string): string[] {
  return cell.replace(/\s*\([^)]*\)/g, '').split(/[\n;,]+/).map(s => s.trim()).filter(Boolean);
}

/** A version as written in a cell, minus a product name in front of it ("DSM 2026.1", "EPM 2024 SU1"). */
const bare = (v: string): string => v.trim().replace(/^[A-Za-z]{3,}\s+(?=\d)/, '');

const VALID = (v: string | undefined): v is string => v !== undefined && parseIvantiVersion(bare(v)) !== null;

/**
 * One line of an "Affected Version(s)" cell:
 *   "22.7R2.4 and prior" / "and below" / "and earlier"   -> inclusive upper bound
 *   "22.7R2 through 22.7R2.4"                            -> inclusive range
 *   "Prior to 12.6.1.1" / "Before ..."                   -> exclusive upper bound
 *   "2025.2"                                             -> one affected release
 * A line whose version Ivanti's order cannot place is dropped.
 */
export function parseAffectedCell(cell: string): AffectedSpec[] {
  const specs: AffectedSpec[] = [];
  for (const part of cellParts(cell)) {
    // "Prior to X" first: the range pattern below would read its "to" as a separator.
    // "All versions before X" says the same.
    let m = part.match(/^(?:all\s+versions?\s+)?(?:prior\s+to|before|below|earlier\s+than)\s+(.+)$/i);
    if (m) { if (VALID(m[1])) specs.push({ end: bare(m[1]) }); continue; }
    // "5.1 versions prior to 5.1.2": the 5.1 line, below its fix.
    m = part.match(/^(.+?)\s+versions?\s+(?:prior\s+to|before|below)\s+(.+)$/i);
    if (m) { if (VALID(m[1]) && VALID(m[2])) specs.push({ start: bare(m[1]), end: bare(m[2]) }); continue; }
    m = part.match(/^(.+?)\s+(?:and|or)\s+(?:prior|previous|below|earlier|lower|before|older)\b/i);
    if (m) { if (VALID(m[1])) specs.push({ last: bare(m[1]) }); continue; }
    m = part.match(/^(.+?)\s+(?:through|thru|to)\s+(.+)$/i);
    if (m) { if (VALID(m[1]) && VALID(m[2])) specs.push({ start: bare(m[1]), last: bare(m[2]) }); continue; }
    if (VALID(part)) specs.push({ exact: bare(part) });
  }
  return specs;
}

/** The "Resolved Version(s)" cell: the versions in it, without "Download Portal" and similar. */
export function parseResolvedCell(cell: string): string[] {
  const out: string[] = [];
  for (const part of cell.replace(/\s*\([^)]*\)/g, '').split(/[\n;,]+|\s+and\s+/i).map(s => s.trim())) {
    if (VALID(part) && !out.includes(bare(part))) out.push(bare(part));
  }
  return out;
}

function referenceOf(spec: AffectedSpec): string {
  return (spec.last ?? spec.end ?? spec.exact ?? spec.start)!;
}

const cmp = (a: string, b: string) => compareIvantiVersions(parseIvantiVersion(a)!, parseIvantiVersion(b)!);
const highest = (vs: string[]) => [...vs].sort(cmp).pop();
const lowest = (vs: string[]) => [...vs].sort(cmp)[0];

/**
 * Pair each resolved version with the affected versions of its release line
 * (major.minor) that lie below it -- Sentry's "R10.8.1 and prior / R10.7.2 and
 * prior" with "R10.8.2 / R10.7.3" gives one range per line. A product with a
 * single affected entry and a single resolved version pairs across lines.
 *
 * A line's range starts at its own line start whenever the product has several
 * lines, except the lowest: otherwise one line's "and prior" range would cover
 * the next line's fixed releases (R10.7.3 below R10.8.2). The lowest line stays
 * open below, as "and prior" says.
 */
export function pairIvantiVersions(specs: AffectedSpec[], resolved: string[]): ProductVersions[] {
  const refLine = (spec: AffectedSpec) => ivantiLine(parseIvantiVersion(referenceOf(spec))!);
  const fixes = [...resolved].sort(cmp);
  const used = new Set<AffectedSpec>();
  const rows: ProductVersions[] = [];

  for (const fix of fixes) {
    const line = ivantiLine(parseIvantiVersion(fix)!);
    let group = specs.filter(s => refLine(s) === line && cmp(referenceOf(s), fix) <= 0);
    // A product with one fix and affected versions on other lines ("2025.2,
    // 2025.3" fixed in 2025.4; "2024 SU4" in "2024 SU4 SR1"): the fix is the
    // upgrade target for all of them.
    if (fixes.length === 1) {
      const rest = specs.filter(s => !group.includes(s) && cmp(referenceOf(s), fix) <= 0);
      group = [...group, ...rest];
    }
    if (group.length === 0) continue;
    group.forEach(s => used.add(s));

    const exacts = group.map(s => s.exact).filter(VALID);
    const lasts = group.map(s => s.last).filter(VALID);
    const starts = group.map(s => s.start).filter(VALID);
    const ends = group.map(s => s.end).filter(VALID);
    const spanned = [...exacts, ...lasts];
    const row: ProductVersions = { versionFixed: fix };
    if (starts.length || exacts.length) row.versionStart = lowest([...starts, ...exacts]);
    if (ends.length) row.versionEnd = highest(ends);
    if (spanned.length) row.lastAffected = highest(spanned);
    if (exacts.length) row.affectedVersions = exacts;
    rows.push(row);
  }

  // Affected entries no resolved version covers (an end-of-support line, a fix
  // not yet released) stay as ranges without a fix.
  for (const spec of specs) {
    if (used.has(spec)) continue;
    const row: ProductVersions = {};
    if (spec.start) row.versionStart = spec.start;
    if (spec.end) row.versionEnd = spec.end;
    if (spec.last) row.lastAffected = spec.last;
    if (spec.exact) { row.versionStart = spec.exact; row.lastAffected = spec.exact; row.affectedVersions = [spec.exact]; }
    rows.push(row);
  }

  if (rows.length > 1) {
    const lineOf = (r: ProductVersions) => parseIvantiVersion((r.versionFixed ?? r.lastAffected ?? r.versionEnd ?? r.versionStart)!)!;
    const lowestLine = [...rows].sort((a, b) => compareIvantiVersions(lineOf(a), lineOf(b)))[0];
    for (const r of rows) {
      if (r.versionStart === undefined && r !== lowestLine) r.versionStart = `${ivantiLine(lineOf(r))}.0`;
    }
  }
  return rows;
}

// ─── Products ──────────────────────────────────────────────────

/**
 * "Ivanti Connect Secure (ICS)" -> "Connect Secure": the vendor prefix and a
 * trailing acronym are dropped, so one product reads the same across advisories.
 */
export function productName(raw: string): string {
  const name = raw
    .replace(/\s+/g, ' ')
    // Some tables put the CVE in front of the product ("CVE-2026-18851 Ivanti Endpoint Manager Mobile").
    .replace(/^(?:CVE-\d{4}-\d{4,}[\s,/&]+)+/i, '')
    .replace(/^Ivanti\s+/i, '')
    // A trailing acronym or status in brackets: "(ICS)", "(EPMM)", "(EoS)", "(Core)".
    .replace(/\s*\([A-Za-z0-9]{2,6}\)\s*$/, '')
    .trim();
  const canonical = CANONICAL_PRODUCTS.find(([pattern]) => pattern.test(name));
  return canonical ? canonical[1] : name;
}

// One product, several spellings across advisories: the acronym alone, a
// deployment note ("on-premises only"), a platform ("(Windows)"), or a typo.
const CANONICAL_PRODUCTS: [RegExp, string][] = [
  [/^EPMM\b/, 'Endpoint Manager Mobile'],
  [/^Neurons for ITSM/i, 'Neurons for ITSM'],
  [/^(CSA\b|Cloud Services (Application|Appliance))/i, 'Cloud Services Appliance'],
  [/^Secure Access Client/i, 'Secure Access Client'],
  [/^(Neurons for )?ZTA gateways?$/i, 'Neurons for ZTA gateways'],
  [/^Application Control/i, 'Application Control'],
];

/** A product row for Ivanti's own cloud service: its fix is applied by Ivanti, and no customer runs a version of it. */
function isCloudService(raw: string): boolean {
  return /\(\s*cloud(\s*\/\s*saas)?\s*\)|\bsaas\b/i.test(raw);
}

// ─── Article -> advisories ─────────────────────────────────────

function isoDate(text: string | undefined): Date | undefined {
  const d = text ? new Date(text) : undefined;
  return d && !Number.isNaN(d.getTime()) ? d : undefined;
}

/**
 * One advisory per CVE the article covers (externalId "<article>/<CVE>"), like
 * the other multi-CVE sources, so each CVE is searchable on its own. Articles
 * with no CVE table (installation notes, announcements) yield nothing.
 */
export function buildIvantiAdvisories(article: RenderedArticle): NormalizedAdvisory[] {
  const cves = parseCveTable(article.tables);
  const table = findTable(article.tables, /Affected Version/i);
  if (cves.length === 0 || !table) return [];

  const header = table[0];
  const iProduct = columnIndex(header, /^Product/i);
  const iCve = columnIndex(header, /^CVE/i);
  const iAffected = columnIndex(header, /^Affected Version/i);
  const iResolved = columnIndex(header, /^(Resolved|Fixed) Version/i);
  if (iProduct < 0 || iAffected < 0) return [];

  const title = articleTitle(article.bodyText, article.urlName);
  const summary = sectionText(article.bodyText, ['Summary']);
  const solution = sectionText(article.bodyText, ['Solution']);
  const workaround = sectionText(article.bodyText, ['Mitigation', 'Mitigations', 'Mitigation or Workaround', 'Workaround', 'Workarounds']);
  const publishedAt = isoDate(valueAfter(article.bodyText, 'Created Date'));

  return cves.map(row => {
    const affectedProducts: NormalizedAdvisory['affectedProducts'] = [];
    for (const r of table.slice(1)) {
      const rawProduct = r[iProduct]?.trim();
      if (!rawProduct || isCloudService(rawProduct)) continue;
      // A table that has a CVE column lists one row per CVE and product.
      if (iCve >= 0 && r[iCve] && !r[iCve].includes(row.cve)) continue;

      const specs = parseAffectedCell(r[iAffected] ?? '');
      const resolved = iResolved >= 0 ? parseResolvedCell(r[iResolved] ?? '') : [];
      for (const v of pairIvantiVersions(specs, resolved)) {
        affectedProducts.push({
          vendor: IVANTI_VENDOR,
          product: productName(rawProduct),
          ...v,
          patchAvailable: v.versionFixed ? true : undefined,
        });
      }
    }

    return {
      externalId: `${article.urlName}/${row.cve}`,
      cveId: row.cve,
      summary: title,
      description: row.description ?? summary,
      severity: row.severity,
      cvssScore: row.score,
      cvssVector: row.vector,
      url: article.url,
      solution,
      workaround,
      publishedAt,
      affectedProducts,
      rawData: { url: article.url, title, tables: article.tables },
    };
  });
}

// ─── Data fetching ─────────────────────────────────────────────

const HTTP = { timeout: 60000, headers: { 'User-Agent': 'heretix-api/1.0' }, responseType: 'text' as const };

/** Advisory article URLs from the community's sitemaps, with the article name (the URL's last segment). */
async function listAdvisoryArticles(): Promise<{ url: string; urlName: string }[]> {
  const { data: index } = await axios.get<string>(SITEMAP_INDEX_URL, HTTP);
  const sitemaps = [...index.matchAll(ARTICLE_SITEMAP)].map(m => m[1]);
  if (sitemaps.length === 0) throw new Error('Ivanti sitemap index lists no article sitemaps -- the site layout may have changed');

  const found = new Map<string, string>();
  for (const sitemap of sitemaps) {
    const { data } = await axios.get<string>(sitemap, HTTP);
    for (const m of data.matchAll(ARTICLE_URL)) found.set(m[2], m[1]);
  }
  return [...found].map(([urlName, url]) => ({ urlName, url }));
}

export async function renderArticle(url: string, urlName: string): Promise<RenderedArticle> {
  return withPage(url, async (page) => {
    // The article body appears once the community's data call returns.
    await page.waitForFunction(() => document.body.innerText.includes('Created Date'), null, { timeout: 40000 });
    // The tables can lag the body.
    await page.waitForFunction(() => /Affected\s+Version/i.test(document.body.innerText), null, { timeout: 25000 }).catch(() => {});
    const { bodyText, tables } = await page.evaluate(() => ({
      bodyText: document.body.innerText,
      tables: Array.from(document.querySelectorAll('table')).map(t =>
        Array.from(t.rows).map(r => Array.from(r.cells).map(c => c.innerText.trim())),
      ),
    }));
    const article = normalizeArticle({ url, urlName, bodyText, tables });
    // A standard CVE table without the version table beside it is a render that
    // did not finish: fail it, so it is counted rather than silently dropped.
    // Older "KB-Security-Advisory-..." articles have a different layout (a
    // "CVE | Description | CVSS | Vector" table and prose) and no version table
    // at all; they are not failures.
    if (findTable(article.tables, /^CVE Number$/i) && !findTable(article.tables, /Affected Version/i)) {
      throw new Error('article rendered a CVE table but no version table');
    }
    return article;
  }, { timeout: 60000 });
}

// ─── AdvisoryFetcher Implementation ──────────────────────────

export class IvantiFetcher implements AdvisoryFetcher {
  private failedCount = 0;

  source(): string { return 'advisory-ivanti'; }
  isCompleteSnapshot(): boolean { return true; }
  fetchFailedCount(): number { return this.failedCount; }

  async fetch(): Promise<NormalizedAdvisory[]> {
    this.failedCount = 0;
    logger.info('Fetching Ivanti security advisories');
    const articles = await listAdvisoryArticles();
    logger.info({ count: articles.length }, 'Listed Ivanti advisory articles');

    const results: NormalizedAdvisory[] = [];
    let noCve = 0;
    try {
      for (const { url, urlName } of articles) {
        try {
          const advisories = buildIvantiAdvisories(await renderArticle(url, urlName));
          if (advisories.length === 0) noCve++;
          results.push(...advisories);
        } catch (err) {
          this.failedCount++;
          logger.warn({ url, err }, 'Failed to render Ivanti advisory article');
        }
      }
    } finally {
      await closeBrowser();
    }

    // The curated entries are always there, so they must not be allowed to make a
    // fetch that read nothing from the site look successful: that would hide a
    // layout change and let pruning delete everything the site did give us.
    if (results.length === 0) {
      throw new Error('Ivanti: no advisory could be read from the hub -- the site layout may have changed');
    }
    const legacy = buildLegacyIvantiAdvisories();

    logger.info(
      { articles: articles.length, advisories: results.length, legacy: legacy.length, withoutCveTable: noCve, failed: this.failedCount },
      'Ivanti advisory fetch complete',
    );
    return [...results, ...legacy];
  }
}
