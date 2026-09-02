import axios from 'axios';
import { createRequire } from 'module';
import { XMLParser } from 'fast-xml-parser';
import type { AdvisoryFetcher, NormalizedAdvisory } from './advisory-fetcher.js';
import { logger } from '../utils/logger.js';
import { inferBareVersionStart, moduleStreamVersionStart } from './advisory-helpers.js';

const require = createRequire(import.meta.url);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const bz2 = require('bzip2') as any;

// ─── Constants ────────────────────────────────────────────────

const BASE_URL = 'https://security.access.redhat.com/data/oval/v2';

const SEVERITY_MAP: Record<string, string> = {
  critical:  'CRITICAL',
  important: 'HIGH',
  moderate:  'MEDIUM',
  low:       'LOW',
};

// ─── Helpers ──────────────────────────────────────────────────

export function mapSeverity(s?: unknown): string | undefined {
  if (s === undefined || s === null || s === '') return undefined;
  const str = String(s);
  return SEVERITY_MAP[str.toLowerCase()] ?? str.toUpperCase();
}

/**
 * Derive advisory ID from definition id.
 * "oval:com.redhat.rhsa:def:20260425" → "RHSA-2026:0425"
 * "oval:com.redhat.rhba:def:20223893" → "RHBA-2022:3893"
 */
function advisoryIdFromDefId(defId: string): string | null {
  const prefixMatch = defId.match(/com\.redhat\.(rh[a-z]+):/);
  const numMatch = defId.match(/:def:(\d{4})(\d+)$/);
  if (!prefixMatch || !numMatch) return null;
  const prefix = prefixMatch[1].toUpperCase();
  return `${prefix}-${numMatch[1]}:${numMatch[2]}`;
}

function toArray<T>(val: T | T[] | undefined | null): T[] {
  if (val == null) return [];
  return Array.isArray(val) ? val : [val];
}

export interface CveInfo {
  cveId: string;
  cvssScore?: number;
  cvssVector?: string;
}

export function parseCveElement(cve: unknown): CveInfo | null {
  if (typeof cve === 'string') {
    if (!cve.startsWith('CVE-')) return null;
    return { cveId: cve };
  }
  if (typeof cve === 'object' && cve !== null) {
    const obj = cve as Record<string, unknown>;
    const cveId = obj['#text'] as string | undefined;
    if (!cveId?.startsWith('CVE-')) return null;

    const cvss3 = obj['@_cvss3'] as string | undefined;
    let cvssScore: number | undefined;
    let cvssVector: string | undefined;

    if (cvss3) {
      const slash = cvss3.indexOf('/');
      if (slash !== -1) {
        const score = parseFloat(cvss3.slice(0, slash));
        if (!isNaN(score)) {
          cvssScore = score;
          cvssVector = cvss3.slice(slash + 1);
        }
      }
    }

    return { cveId, cvssScore, cvssVector };
  }
  return null;
}

// versionEnd is kept as the full "epoch:version-release" string the OVAL feed
// writes ("0:3.2.5-3.el9_7.2" when a package has no real epoch, RPM's own
// convention for "none" is a literal number here, never a placeholder like the
// "(none)" rpm(8) itself prints -- see redhat-fetcher.test.ts). Stripping it
// (as this used to) drops the single highest-precedence field
// compareRpmVersions() compares: an installed package with a real epoch (e.g.
// openssl-libs at "1:3.5.5-6.el9_8") then reads as newer than *any*
// epoch-omitted (implicitly epoch-0) row regardless of its actual
// version/release, so every fix for it silently stops matching.
export function parseCriterionComment(comment: string): { packageName: string; versionEnd: string } | null {
  const m = comment.match(/^(.+?)\s+is earlier than\s+(.+)$/i);
  if (!m) return null;
  return {
    packageName: m[1].trim(),
    versionEnd:  m[2].trim(),
  };
}

/**
 * Extracts the stream label from a "Module <name>:<stream> is enabled"
 * criterion comment (DNF module-stream gate). The stream label is whatever
 * the vendor uses to identify the stream verbatim -- a plain integer for
 * most products (nodejs's "20", postgresql's "16"), but a dotted
 * major.minor for others (mysql's "8.4", mariadb's "10.11") wherever that's
 * the product's real, mutually-incompatible release-line boundary. Returning
 * it as-is (not parsed as an integer) is what lets the caller use it
 * directly as a versionStart floor without needing to know which shape a
 * given product uses.
 */
export function extractModuleMajor(comment: string): string | null {
  const m = comment.match(/^Module\s+\S+:(\S+)\s+is enabled$/i);
  return m ? m[1] : null;
}

export interface CollectedCriterion {
  node: Record<string, unknown>;
  /**
   * Stream label from an ancestor "Module <name>:<stream> is enabled"
   * criterion, if any. RHEL/Oracle Linux OVAL always pairs that check and
   * the OR-of-packages it guards as sibling children of the same
   * <criteria operator="AND"> parent, so finding one at a level scopes
   * every criterion at that level and everything nested beneath it.
   */
  moduleMajor: string | null;
}

export function collectCriteria(node: unknown, moduleMajor: string | null = null): CollectedCriterion[] {
  if (!node || typeof node !== 'object') return [];
  const n = node as Record<string, unknown>;
  const results: CollectedCriterion[] = [];

  const ownCriteria = toArray(n['criterion'] as unknown) as Record<string, unknown>[];

  let scopedModuleMajor = moduleMajor;
  for (const c of ownCriteria) {
    // fast-xml-parser auto-coerces purely numeric attribute text (e.g.
    // comment="0") to a number -- guard against that the same way
    // mapSeverity() does, rather than assuming the `as string` cast holds
    // (a live Oracle Linux feed hit exactly this and crashed the fetcher,
    // 2026-09-02; RedHatFetcher shares this same parsing code).
    const comment = c['@_comment'];
    const major = typeof comment === 'string' ? extractModuleMajor(comment) : null;
    if (major !== null) scopedModuleMajor = major;
  }

  for (const c of ownCriteria) {
    results.push({ node: c, moduleMajor: scopedModuleMajor });
  }

  for (const nested of toArray(n['criteria'] as unknown)) {
    results.push(...collectCriteria(nested, scopedModuleMajor));
  }

  return results;
}

// ─── Fetcher ──────────────────────────────────────────────────

export class RedHatFetcher implements AdvisoryFetcher {
  private readonly feedUrl: string;
  // Written into every affectedProducts[].vendor below as "red-hat-<major>" —
  // AdvisoryAffectedProduct is looked up by (product, vendor) with no other
  // version column, so a vendor value that drops this major version (the bare
  // "red-hat" this used until 2026-09-01) makes the lookup compare an
  // installed package against every RHEL release's fix versions at once. An
  // RHEL10 fix numerically higher than an installed RHEL9 version then reads
  // as "not yet fixed" even when the correct RHEL9 advisory is long satisfied.
  private readonly majorVersion: string;

  /**
   * @param variant - RHEL version: 'rhel9', 'rhel8'.
   *                  Maps to RHEL9/rhel-9.oval.xml.bz2, etc.
   */
  constructor(variant?: string) {
    this.majorVersion = variant ? variant.replace('rhel', '') : '9';
    this.feedUrl = `${BASE_URL}/RHEL${this.majorVersion}/rhel-${this.majorVersion}.oval.xml.bz2`;
  }

  source(): string {
    return 'red-hat';
  }

  isCompleteSnapshot(): boolean {
    return true;
  }

  async fetch(): Promise<NormalizedAdvisory[]> {
    logger.info({ url: this.feedUrl }, 'Downloading Red Hat OVAL feed');

    const response = await axios.get<ArrayBuffer>(this.feedUrl, {
      responseType: 'arraybuffer',
      timeout: 300000,
    });

    logger.info({ bytes: response.data.byteLength }, 'Downloaded OVAL bzip2 file, decompressing...');

    const bits = bz2.array(new Uint8Array(response.data));
    const decompressed: Uint8Array = bz2.simple(bits);
    const xmlString = Buffer.from(decompressed).toString('utf8');

    logger.info({ xmlLength: xmlString.length }, 'Decompressed, parsing OVAL XML...');

    const fixedXml = xmlString.replace(/\bcomment="([^"\n]*)\n/g, 'comment="$1"/>\n');

    return this._parseOVAL(fixedXml);
  }

  private _parseOVAL(xmlString: string): NormalizedAdvisory[] {
    const parser = new XMLParser({
      ignoreAttributes: false,
      attributeNamePrefix: '@_',
      processEntities: false,
      allowBooleanAttributes: true,
      isArray: (name) =>
        ['criterion', 'criteria', 'reference', 'cve'].includes(name),
    });

    const defRe = /<definition\b[^>]*>[\s\S]*?<\/definition>/g;
    const definitions: Record<string, unknown>[] = [];
    let m: RegExpExecArray | null;
    while ((m = defRe.exec(xmlString)) !== null) {
      if (!m[0].includes('class="patch"')) continue;
      try {
        const doc = parser.parse(`<r>${m[0]}</r>`);
        const rNode = (doc as Record<string, unknown>)['r'] as Record<string, unknown> | undefined;
        const def = rNode?.['definition'];
        if (def && typeof def === 'object') {
          definitions.push(def as Record<string, unknown>);
        }
      } catch {
        // skip malformed definitions
      }
    }

    const advisories: NormalizedAdvisory[] = [];

    for (const def of definitions) {
      const d = def;

      const meta = d['metadata'] as Record<string, unknown> | undefined;
      if (!meta) continue;

      // ── RHSA/RHBA ID ────────────────────────────────────────
      const refs = toArray(meta['reference'] as unknown);
      const rhsaRef = refs.find(
        (r) => (r as Record<string, unknown>)['@_source'] === 'RHSA'
      ) as Record<string, unknown> | undefined;

      const advisoryId =
        (rhsaRef?.['@_ref_id'] as string | undefined) ??
        advisoryIdFromDefId((d['@_id'] as string) ?? '');

      if (!advisoryId) continue;

      // ── Severity + CVEs ──────────────────────────────────────
      const advisory = meta['advisory'] as Record<string, unknown> | undefined;
      const severity = mapSeverity(advisory?.['severity']);

      const cveElements = toArray(advisory?.['cve'] as unknown);
      const cves = cveElements
        .map(parseCveElement)
        .filter((c): c is CveInfo => c !== null);

      // ── Affected packages ─────────────────────────────────────
      const criteriaNode = d['criteria'] as unknown;
      const topCriteria = Array.isArray(criteriaNode) ? criteriaNode[0] : criteriaNode;
      const criterionList = collectCriteria(topCriteria);

      const affectedProducts: NormalizedAdvisory['affectedProducts'] = [];
      const seen = new Set<string>();

      for (const crit of criterionList) {
        const comment = crit.node['@_comment'];
        if (typeof comment !== 'string') continue;

        const parsed = parseCriterionComment(comment);
        if (!parsed) continue;

        const key = `${parsed.packageName}@${parsed.versionEnd}`;
        if (seen.has(key)) continue;
        seen.add(key);

        const moduleVersionStart = crit.moduleMajor !== null
          ? moduleStreamVersionStart(crit.moduleMajor, parsed.versionEnd)
          : undefined;
        const versionStart = moduleVersionStart ?? inferBareVersionStart(parsed.packageName, parsed.versionEnd);

        affectedProducts.push({
          vendor: `red-hat-${this.majorVersion}`,
          product: parsed.packageName,
          versionStart,
          versionEnd: parsed.versionEnd,
          affectedVersions: [],
        });
      }

      if (affectedProducts.length === 0) continue;

      const baseFields = {
        summary: meta['title'] as string | undefined,
        severity,
        url: rhsaRef?.['@_ref_url'] as string | undefined,
        affectedProducts,
        rawData: def,
      };

      if (cves.length === 0) {
        advisories.push({ externalId: advisoryId, ...baseFields });
      } else {
        for (const cve of cves) {
          advisories.push({
            externalId: `${advisoryId}/${cve.cveId}`,
            cveId: cve.cveId,
            cvssScore: cve.cvssScore,
            cvssVector: cve.cvssVector,
            ...baseFields,
          });
        }
      }
    }

    logger.info({ count: advisories.length }, 'Parsed Red Hat OVAL advisories');
    return advisories;
  }
}
