import axios from 'axios';
import { createRequire } from 'module';
import { XMLParser } from 'fast-xml-parser';
import type { AdvisoryFetcher, NormalizedAdvisory } from './advisory-fetcher.js';
import { logger } from '../utils/logger.js';

// bzip2 is a CommonJS module — use createRequire in ESM context
const require = createRequire(import.meta.url);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const bz2 = require('bzip2') as any;

// ─── Constants ────────────────────────────────────────────────

const BASE_URL = 'https://linux.oracle.com/security/oval';

const SEVERITY_MAP: Record<string, string> = {
  critical:  'CRITICAL',
  important: 'HIGH',
  moderate:  'MEDIUM',
  low:       'LOW',
};

// ─── Helpers ──────────────────────────────────────────────────

function mapSeverity(s?: string): string | undefined {
  if (!s) return undefined;
  return SEVERITY_MAP[s.toLowerCase()] ?? s.toUpperCase();
}

/** Strip RPM epoch prefix: "0:2.9.13-9.el9" → "2.9.13-9.el9" */
function stripEpoch(version: string): string {
  return version.replace(/^\d+:/, '');
}

/**
 * Derive ELSA ID from definition id.
 * "oval:com.oracle.elsa:def:20266390" → "ELSA-2026-6390"
 */
function elsaIdFromDefId(defId: string): string | null {
  const m = defId.match(/:def:(\d{4})(\d+)$/);
  if (!m) return null;
  return `ELSA-${m[1]}-${m[2]}`;
}

/** Normalize a value that may be a single item or an array into an array. */
function toArray<T>(val: T | T[] | undefined | null): T[] {
  if (val == null) return [];
  return Array.isArray(val) ? val : [val];
}

interface CveInfo {
  cveId: string;
  cvssScore?: number;
  cvssVector?: string;
}

/**
 * Parse a <cve> element which may be a plain string ("CVE-XXXX")
 * or an object with @_cvss3="score/vector" and #text="CVE-XXXX".
 */
function parseCveElement(cve: unknown): CveInfo | null {
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
      // Format: "7.5/CVSS:3.1/AV:N/..."
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

/**
 * Parse criterion comment text.
 * "rsync is earlier than 0:3.2.5-3.el9_7.2" → { packageName: "rsync", versionEnd: "3.2.5-3.el9_7.2" }
 * Returns null for non-version criteria ("is signed with", "is installed", etc.)
 */
function parseCriterionComment(comment: string): { packageName: string; versionEnd: string } | null {
  const m = comment.match(/^(.+?)\s+is earlier than\s+(.+)$/i);
  if (!m) return null;
  return {
    packageName: m[1].trim(),
    versionEnd:  stripEpoch(m[2].trim()),
  };
}

/**
 * Recursively collect all <criterion> elements from a criteria tree.
 * OVAL criteria can be nested: <criteria><criteria><criterion/></criteria></criteria>
 */
function collectCriteria(node: unknown): Record<string, unknown>[] {
  if (!node || typeof node !== 'object') return [];
  const n = node as Record<string, unknown>;
  const results: Record<string, unknown>[] = [];

  // Direct criterion children
  for (const c of toArray(n['criterion'] as unknown)) {
    results.push(c as Record<string, unknown>);
  }

  // Recurse into nested criteria
  for (const nested of toArray(n['criteria'] as unknown)) {
    results.push(...collectCriteria(nested));
  }

  return results;
}

// ─── Fetcher ──────────────────────────────────────────────────

export class OracleLinuxFetcher implements AdvisoryFetcher {
  private readonly feedUrl: string;

  /**
   * @param variant - Optional OS variant: 'ol9', 'ol8', 'ol7', etc.
   *                  Omit to download the full feed (all.xml.bz2).
   */
  constructor(variant?: string) {
    const filename = variant
      ? `com.oracle.elsa-${variant}.xml.bz2`
      : 'com.oracle.elsa-all.xml.bz2';
    this.feedUrl = `${BASE_URL}/${filename}`;
  }

  source(): string {
    return 'oracle-linux';
  }

  async fetch(): Promise<NormalizedAdvisory[]> {
    logger.info({ url: this.feedUrl }, 'Downloading Oracle Linux OVAL feed');

    const response = await axios.get<ArrayBuffer>(this.feedUrl, {
      responseType: 'arraybuffer',
      timeout: 300000, // 5 minutes
    });

    logger.info({ bytes: response.data.byteLength }, 'Downloaded OVAL bzip2 file, decompressing...');

    const bits = bz2.array(new Uint8Array(response.data));
    const decompressed: Uint8Array = bz2.simple(bits);
    const xmlString = Buffer.from(decompressed).toString('utf8');

    logger.info({ xmlLength: xmlString.length }, 'Decompressed, parsing OVAL XML...');

    // Oracle OVAL XML sometimes has malformed <criterion> elements where the
    // comment attribute value is not terminated before a newline.
    // Fix by closing the attribute and self-closing the element at the newline.
    // e.g.  comment="curl is\n</criteria>  →  comment="curl is"/>\n</criteria>
    const fixedXml = xmlString.replace(/\bcomment="([^"\n]*)\n/g, 'comment="$1"/>\n');

    return this._parseOVAL(fixedXml);
  }

  private _parseOVAL(xmlString: string): NormalizedAdvisory[] {
    // Parse each <definition> block individually to avoid fast-xml-parser
    // limitations on very large files (47 MB+ for the full OL9 feed).
    const parser = new XMLParser({
      ignoreAttributes: false,
      attributeNamePrefix: '@_',
      processEntities: false,
      allowBooleanAttributes: true,
      isArray: (name) =>
        ['criterion', 'criteria', 'reference', 'cve'].includes(name),
    });

    // Extract all <definition …>…</definition> blocks with regex.
    // OVAL definitions are flat (never nested), so this is safe.
    const defRe = /<definition\b[^>]*>[\s\S]*?<\/definition>/g;
    const definitions: Record<string, unknown>[] = [];
    let m: RegExpExecArray | null;
    while ((m = defRe.exec(xmlString)) !== null) {
      // Skip non-patch definitions early without parsing
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

      // ── ELSA ID ──────────────────────────────────────────────
      const refs = toArray(meta['reference'] as unknown);
      const elsaRef = refs.find(
        (r) => (r as Record<string, unknown>)['@_source'] === 'elsa'
      ) as Record<string, unknown> | undefined;

      const elsaId =
        (elsaRef?.['@_ref_id'] as string | undefined) ??
        elsaIdFromDefId((d['@_id'] as string) ?? '');

      if (!elsaId) continue;

      // ── Severity + CVEs ──────────────────────────────────────
      const advisory = meta['advisory'] as Record<string, unknown> | undefined;
      const severity = mapSeverity(advisory?.['severity'] as string | undefined);

      const cveElements = toArray(advisory?.['cve'] as unknown);
      const cves = cveElements
        .map(parseCveElement)
        .filter((c): c is CveInfo => c !== null);

      // Primary CVE: highest CVSS score, or first in list
      const primaryCve = cves.sort((a, b) => (b.cvssScore ?? 0) - (a.cvssScore ?? 0))[0];

      // ── Affected packages ─────────────────────────────────────
      const criteriaNode = d['criteria'] as unknown;
      // criteria parsed as array due to isArray; use first top-level node
      const topCriteria = Array.isArray(criteriaNode) ? criteriaNode[0] : criteriaNode;
      const criterionList = collectCriteria(topCriteria);

      const affectedProducts: NormalizedAdvisory['affectedProducts'] = [];
      const seen = new Set<string>();

      for (const crit of criterionList) {
        const comment = crit['@_comment'] as string | undefined;
        if (!comment) continue;

        const parsed = parseCriterionComment(comment);
        if (!parsed) continue;

        // Deduplicate same package+version pairs within one advisory
        const key = `${parsed.packageName}@${parsed.versionEnd}`;
        if (seen.has(key)) continue;
        seen.add(key);

        affectedProducts.push({
          vendor: 'oracle-linux',
          product: parsed.packageName,
          versionEnd: parsed.versionEnd,
          affectedVersions: [],
        });
      }

      if (affectedProducts.length === 0) continue;

      advisories.push({
        externalId:  elsaId,
        cveId:       primaryCve?.cveId,
        summary:     meta['title'] as string | undefined,
        severity,
        cvssScore:   primaryCve?.cvssScore,
        cvssVector:  primaryCve?.cvssVector,
        url:         elsaRef?.['@_ref_url'] as string | undefined,
        affectedProducts,
        rawData: def,
      });
    }

    logger.info({ count: advisories.length }, 'Parsed Oracle Linux OVAL advisories');
    return advisories;
  }
}
