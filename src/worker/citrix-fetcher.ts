import axios from 'axios';
import type { AdvisoryFetcher, NormalizedAdvisory } from './advisory-fetcher.js';
import { logger } from '../utils/logger.js';
import { CITRIX_VENDOR } from '../utils/advisory-version.js';
import { nextCitrixBranch, parseCitrixVersion } from '../utils/citrix-version.js';

// NetScaler (formerly Citrix ADC / Gateway) security bulletins are knowledge articles
// on support.citrix.com. The site has a sitemap and serves the article text in the
// page, so plain HTTP is enough (robots.txt allows /external/article/). The bulletins
// of the ADC / Gateway line share a template from 2022 on:
//
//   NetScaler ADC and NetScaler Gateway 14.1 BEFORE 14.1-73.32
//   NetScaler ADC 13.1-FIPS before 13.1-37.277
//
// i.e. the first fixed build of each release branch, written out per product. That is
// what this reads. Other Citrix bulletins (Workspace app, StoreFront, XenServer, ...)
// word their versions differently and are not read.
const SITEMAP_INDEX_URL = 'https://support.citrix.com/sitemap.xml';
const ARTICLE_URL = /<loc>(https:\/\/support\.citrix\.com\/external\/article\/(CTX\d+)\/([^<]+?)\.html)<\/loc>/g;
// The slug is cut at about 40 characters, so the family is recognized by its prefix.
const BULLETIN_SLUG = /^(?:(?:netscaler|citrix)-(?:adc|gateway)-and-(?:netscaler|citrix)-(?:gateway|adc)-secu|netscaler-console-agent-and-sdx-svm-secu)/;
const CVE_ID = /CVE-\d{4}-\d{4,}/g;

// ─── Text ──────────────────────────────────────────────────────

function decodeEntities(s: string): string {
  return s
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&rsquo;|&lsquo;/g, "'");
}

/** Article HTML to lines of text; a table cell ends with " | " so rows stay readable. */
export function htmlToLines(html: string): string[] {
  const text = decodeEntities(
    html
      // The head holds the title, which is read on its own; left in, its text runs into the first
      // line of the body, and a CVE in the title would be taken for one in the first sentence.
      .replace(/<head[\s\S]*?<\/head>/gi, ' ')
      .replace(/<script[\s\S]*?<\/script>/gi, ' ')
      .replace(/<style[\s\S]*?<\/style>/gi, ' ')
      .replace(/<br\s*\/?>|<\/(?:p|tr|li|div|h\d)>/gi, '\n')
      .replace(/<\/t[dh]>/gi, ' | ')
      .replace(/<[^>]+>/g, ' '),
  );
  // Any whitespace but a newline, non-breaking spaces included, becomes one plain space.
  return text.split('\n').map(l => l.replace(/[^\S\n]+/g, ' ').trim()).filter(Boolean);
}

export function articleTitle(html: string, lines: string[]): string {
  const t = decodeEntities((html.match(/<title>([\s\S]*?)<\/title>/i)?.[1] ?? '').replace(/<[^>]+>/g, ' '))
    .replace(/\s+/g, ' ').trim();
  if (t && /security/i.test(t)) return t;
  return lines.find(l => /Security (Bulletin|Update)/i.test(l)) ?? t;
}

// ─── CVE table ─────────────────────────────────────────────────

export interface CveRow {
  cve: string;
  description?: string;
  score?: number;
  vector?: string;
}

function tableRows(html: string): string[][] {
  const rows: string[][] = [];
  for (const t of html.matchAll(/<table[\s\S]*?<\/table>/gi)) {
    for (const tr of t[0].matchAll(/<tr[\s\S]*?<\/tr>/gi)) {
      const cells = [...tr[0].matchAll(/<t[dh][\s\S]*?<\/t[dh]>/gi)]
        .map(c => decodeEntities(c[0].replace(/<br\s*\/?>/gi, ' ').replace(/<[^>]+>/g, ' ')).replace(/\s+/g, ' ').trim());
      if (cells.length > 1) rows.push(cells);
    }
  }
  return rows;
}

/** The CVE-ID | Description | Pre-conditions | CWE | CVSS table (the CVSS column is absent from older bulletins). */
export function parseCveTable(html: string): CveRow[] {
  const rows = tableRows(html);
  const header = rows.find(r => /^CVE[- ]ID$/i.test(r[0]));
  if (!header) return [];
  const iDesc = header.findIndex(c => /^Description/i.test(c));
  const iScore = header.findIndex(c => /^CVSS/i.test(c));
  const out: CveRow[] = [];
  for (const r of rows.slice(rows.indexOf(header) + 1)) {
    const cves = r[0].match(CVE_ID);
    if (!cves) continue;
    const scoreCell = iScore >= 0 ? r[iScore] ?? '' : '';
    const score = scoreCell.match(/Base Score:\s*(\d+(?:\.\d+)?)/i)?.[1];
    const vector = scoreCell.match(/\((CVSS:[^)]+)\)/)?.[1]?.replace(/\s+/g, '');
    for (const cve of cves) {
      out.push({
        cve,
        description: iDesc >= 0 ? r[iDesc] || undefined : undefined,
        score: score === undefined ? undefined : Number(score),
        vector,
      });
    }
  }
  return out;
}

// ─── Affected versions ─────────────────────────────────────────

export interface AffectedLine {
  product: string;
  /** Branch the line is about ("14.1"); the start of its builds. */
  branch: string;
  /** First fixed build, exclusive end of the affected range. */
  fixed: string;
  /** CVEs the line is limited to; undefined = all CVEs of the bulletin. */
  cves?: string[];
  /** The one build the line names, when the bulletin lists a single affected build instead of "before X". */
  onlyBuild?: string;
}

export interface EndOfLifeLine {
  product: string;
  branch: string;
  cves?: string[];
}

// One bulletin writes the fixed build with a dot ("12.1.65.21"); toBuild() puts the hyphen back.
const BEFORE_LINE = /^(?<left>.+?)\s+before\s+(?<fixed>\d+\.\d+[-.]\d+\.\d+)(?<tail>.*)$/i;
// "NetScaler ADC and NetScaler Gateway 14.1-66.54": a single affected build, under a "CVE-x:" heading.
const SINGLE_BUILD_LINE = /^(?<left>(?:NetScaler|Citrix)\b.*?)\s+(?<build>\d+\.\d+-\d+\.\d+)$/i;
// "CVE-2026-3055:" or "CVE-2026-3055 and CVE-2026-4368:" on a line of its own.
const CVE_HEADING = /^(?:CVE-\d{4}-\d{4,}(?:\s*(?:,|and|&)\s*)?)+:$/i;

function toBuild(v: string): string {
  return v.replace(/^(\d+\.\d+)\.(\d+\.\d+)$/, '$1-$2');
}
const BRANCH = /(\d+\.\d+)(?:-(?:FIPS|NDcPP))?\s*$/i;

/**
 * The product(s) a line names, in the one name each is stored under. Citrix ADC and
 * Citrix Gateway are the old names of NetScaler ADC and Gateway; the FIPS / NDcPP
 * builds have a numbering of their own, so they are a product of their own.
 */
export function productNames(text: string, flavored: boolean): string[] {
  const names: string[] = [];
  for (const part of text.split(/\s+and\s+(?=(?:NetScaler|Citrix)\b)/i)) {
    // Not anchored: a sentence can start with a lead-in ("Note: NetScaler ADC and NetScaler Gateway version ...").
    // No trailing \b: "SDX (SVM)" ends in a bracket, where there is no word boundary.
    const m = part.match(/\b(?:NetScaler|Citrix)\s+(SDX\s*\(SVM\)|ADC|Gateway|Console|Agent|ADM)(?![A-Za-z])/i);
    if (!m) continue;
    const kind = m[1].replace(/\s+/g, ' ');
    let name =
      /^adc$/i.test(kind) ? 'NetScaler ADC' :
      /^gateway$/i.test(kind) ? 'NetScaler Gateway' :
      /^adm$|^console$/i.test(kind) ? 'NetScaler Console' :
      /^agent$/i.test(kind) ? 'NetScaler Agent' : 'NetScaler SDX (SVM)';
    if (name === 'NetScaler ADC' && flavored) name = 'NetScaler ADC FIPS and NDcPP';
    if (!names.includes(name)) names.push(name);
  }
  return names;
}

/**
 * The CVEs a sentence names when it introduces the version lines that follow it:
 * "... NetScaler Console, Agent and SDX (SVM) are affected by CVE-2024-6236 :".
 */
function scopeOf(line: string): string[] | undefined {
  if (!/affected by/i.test(line)) return undefined;
  const cves = line.match(CVE_ID);
  return cves ? [...new Set(cves)] : undefined;
}

export function parseAffectedLines(lines: string[]): { affected: AffectedLine[]; endOfLife: EndOfLifeLine[] } {
  const affected: AffectedLine[] = [];
  const endOfLife: EndOfLifeLine[] = [];
  let scope: string[] | undefined;

  for (const line of lines) {
    const intro = scopeOf(line);
    if (intro) { scope = intro; continue; }
    if (CVE_HEADING.test(line)) { scope = line.match(CVE_ID) ?? undefined; continue; }
    if (/^What Customers Should Do/i.test(line)) scope = undefined;

    const eol = line.match(/^(?<who>.+?)\s+versions?\s+(?<branches>\d+\.\d+(?:\s*(?:,|and)\s*\d+\.\d+)*)\s+(?:is|are)\s+now\s+End[- ]Of[- ]Life\b.*\bvulnerable/i);
    if (eol?.groups) {
      const flavored = /FIPS|NDcPP/i.test(eol.groups.who);
      for (const product of productNames(eol.groups.who, flavored)) {
        for (const branch of eol.groups.branches.match(/\d+\.\d+/g) ?? []) endOfLife.push({ product, branch, cves: scope });
      }
      continue;
    }

    const single = scope && !/\bbefore\b/i.test(line) ? line.match(SINGLE_BUILD_LINE) : null;
    if (single?.groups) {
      const build = single.groups.build;
      for (const product of productNames(single.groups.left, /FIPS|NDcPP/i.test(single.groups.left))) {
        affected.push({ product, branch: build.match(/^\d+\.\d+/)![0], fixed: build, cves: scope, onlyBuild: build });
      }
      continue;
    }

    const m = line.match(BEFORE_LINE);
    if (!m?.groups) continue;
    const { left, tail } = m.groups;
    const fixed = toBuild(m.groups.fixed);
    if (!/^(?:NetScaler|Citrix)\b/i.test(left)) continue;
    if (parseCitrixVersion(fixed) === null) continue;

    const flavored = /FIPS|NDcPP/i.test(left) || /FIPS|NDcPP/i.test(tail);
    const branch = left.match(BRANCH)?.[1] ?? fixed.match(/^\d+\.\d+/)![0];
    const who = left.replace(BRANCH, '').trim();
    for (const product of productNames(who, flavored)) affected.push({ product, branch, fixed, cves: scope });
  }
  return { affected, endOfLife };
}

// ─── Bulletin -> advisories ────────────────────────────────────

export interface Bulletin {
  id: string;
  url: string;
  html: string;
}

function severityOf(score: number | undefined, bulletin: string | undefined): string | undefined {
  if (score !== undefined) return score >= 9 ? 'CRITICAL' : score >= 7 ? 'HIGH' : score >= 4 ? 'MEDIUM' : 'LOW';
  const b = bulletin?.toUpperCase();
  return b && ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(b) ? b : undefined;
}

function sectionAfter(lines: string[], heading: RegExp, stop: RegExp, max = 1500): string | undefined {
  const start = lines.findIndex(l => heading.test(l));
  if (start < 0) return undefined;
  const out: string[] = [];
  for (let i = start + 1; i < lines.length && !stop.test(lines[i]); i++) out.push(lines[i]);
  const text = out.join('\n').trim();
  return text ? text.slice(0, max) : undefined;
}

/**
 * One advisory per CVE (externalId "<CTX id>/<CVE>"), like the other multi-CVE
 * sources. A line limited to some CVEs ("... affected by CVE-2024-6236 :") applies
 * to those only; every other line applies to all of the bulletin's CVEs.
 */
export function buildCitrixAdvisories(b: Bulletin): NormalizedAdvisory[] {
  const lines = htmlToLines(b.html);
  const title = articleTitle(b.html, lines);
  const table = parseCveTable(b.html);
  const cves = table.length > 0 ? table : [...new Set(title.match(CVE_ID) ?? [])].map(cve => ({ cve } as CveRow));
  if (cves.length === 0) return [];

  const { affected, endOfLife } = parseAffectedLines(lines);
  const bulletinSeverity = lines.join(' ').match(/Severity of Bulletin:\s*(\w+)/i)?.[1];
  const solution = sectionAfter(lines, /^What Customers Should Do/i, /^(Steps to|Additionally|Note|For CVE-)/i);

  return cves.map(row => {
    const applies = (scope: string[] | undefined) => scope === undefined || scope.includes(row.cve);
    const affectedProducts: NormalizedAdvisory['affectedProducts'] = [];

    const seen = new Set<string>();
    for (const a of affected.filter(x => applies(x.cves))) {
      const key = `${a.product}|${a.branch}|${a.fixed}|${a.onlyBuild ?? ''}`;
      if (seen.has(key)) continue;
      seen.add(key);
      if (a.onlyBuild) {
        affectedProducts.push({ vendor: CITRIX_VENDOR, product: a.product, versionStart: a.onlyBuild, lastAffected: a.onlyBuild });
        continue;
      }
      affectedProducts.push({
        vendor: CITRIX_VENDOR,
        product: a.product,
        versionStart: a.branch,
        versionFixed: a.fixed,
        patchAvailable: true,
      });
    }
    // A branch the bulletin calls end of life and vulnerable has no fix: every build of it is affected.
    for (const e of endOfLife.filter(x => applies(x.cves))) {
      const branch = parseCitrixVersion(e.branch);
      if (!branch || affected.some(a => a.product === e.product && a.branch === e.branch)) continue;
      affectedProducts.push({
        vendor: CITRIX_VENDOR,
        product: e.product,
        versionStart: e.branch,
        versionEnd: nextCitrixBranch(branch),
        fixStatus: 'out_of_support',
        fixStatusDetail: `${e.branch} is end of life and vulnerable`,
      });
    }

    return {
      externalId: `${b.id}/${row.cve}`,
      cveId: row.cve,
      summary: title,
      description: row.description,
      severity: severityOf(row.score, bulletinSeverity),
      cvssScore: row.score,
      cvssVector: row.vector,
      url: b.url,
      solution,
      affectedProducts,
      rawData: { id: b.id, url: b.url, title },
    };
  });
}

// ─── Data fetching ─────────────────────────────────────────────

const HTTP = {
  timeout: 60000,
  // The site answers a plain client with the same pages; a browser-like agent avoids its bot rules.
  headers: { 'User-Agent': 'Mozilla/5.0 (compatible; heretix-api/1.0)' },
  responseType: 'text' as const,
};

async function listBulletins(): Promise<{ id: string; url: string }[]> {
  const { data: index } = await axios.get<string>(SITEMAP_INDEX_URL, HTTP);
  const sitemaps = [...index.matchAll(/<loc>([^<]+)<\/loc>/g)].map(m => m[1]);
  if (sitemaps.length === 0) throw new Error('Citrix sitemap index lists no sitemaps -- the site layout may have changed');

  const found = new Map<string, string>();
  for (const sitemap of sitemaps) {
    const { data } = await axios.get<string>(sitemap, HTTP);
    for (const m of data.matchAll(ARTICLE_URL)) if (BULLETIN_SLUG.test(m[3])) found.set(m[2], m[1]);
  }
  return [...found].map(([id, url]) => ({ id, url }));
}

// ─── AdvisoryFetcher Implementation ──────────────────────────

export class CitrixFetcher implements AdvisoryFetcher {
  private failedCount = 0;

  source(): string { return 'advisory-citrix'; }
  isCompleteSnapshot(): boolean { return true; }
  fetchFailedCount(): number { return this.failedCount; }

  async fetch(): Promise<NormalizedAdvisory[]> {
    this.failedCount = 0;
    logger.info('Fetching NetScaler security bulletins');
    const bulletins = await listBulletins();
    logger.info({ count: bulletins.length }, 'Listed NetScaler security bulletins');

    const results: NormalizedAdvisory[] = [];
    let noCve = 0;
    for (const { id, url } of bulletins) {
      try {
        const { data: html } = await axios.get<string>(url, HTTP);
        const advisories = buildCitrixAdvisories({ id, url, html });
        if (advisories.length === 0) noCve++;
        results.push(...advisories);
      } catch (err) {
        this.failedCount++;
        logger.warn({ id, err }, 'Failed to fetch NetScaler security bulletin');
      }
    }

    logger.info(
      { bulletins: bulletins.length, advisories: results.length, withoutCve: noCve, failed: this.failedCount },
      'NetScaler advisory fetch complete',
    );
    return results;
  }
}
