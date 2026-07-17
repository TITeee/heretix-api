import axios from 'axios';
import { createRequire } from 'module';
import { XMLParser } from 'fast-xml-parser';
import type { AdvisoryFetcher, NormalizedAdvisory } from './advisory-fetcher.js';
import { logger } from '../utils/logger.js';

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

export function stripEpoch(version: string): string {
  return version.replace(/^\d+:/, '');
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

export function parseCriterionComment(comment: string): { packageName: string; versionEnd: string } | null {
  const m = comment.match(/^(.+?)\s+is earlier than\s+(.+)$/i);
  if (!m) return null;
  return {
    packageName: m[1].trim(),
    versionEnd:  stripEpoch(m[2].trim()),
  };
}

export function collectCriteria(node: unknown): Record<string, unknown>[] {
  if (!node || typeof node !== 'object') return [];
  const n = node as Record<string, unknown>;
  const results: Record<string, unknown>[] = [];

  for (const c of toArray(n['criterion'] as unknown)) {
    results.push(c as Record<string, unknown>);
  }

  for (const nested of toArray(n['criteria'] as unknown)) {
    results.push(...collectCriteria(nested));
  }

  return results;
}

// ─── Fetcher ──────────────────────────────────────────────────

export class RedHatFetcher implements AdvisoryFetcher {
  private readonly feedUrl: string;

  /**
   * @param variant - RHEL version: 'rhel9', 'rhel8'.
   *                  Maps to RHEL9/rhel-9.oval.xml.bz2, etc.
   */
  constructor(variant?: string) {
    if (variant) {
      const ver = variant.replace('rhel', '');
      this.feedUrl = `${BASE_URL}/RHEL${ver}/rhel-${ver}.oval.xml.bz2`;
    } else {
      this.feedUrl = `${BASE_URL}/RHEL9/rhel-9.oval.xml.bz2`;
    }
  }

  source(): string {
    return 'red-hat';
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
        const comment = crit['@_comment'] as string | undefined;
        if (!comment) continue;

        const parsed = parseCriterionComment(comment);
        if (!parsed) continue;

        const key = `${parsed.packageName}@${parsed.versionEnd}`;
        if (seen.has(key)) continue;
        seen.add(key);

        affectedProducts.push({
          vendor: 'red-hat',
          product: parsed.packageName,
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
