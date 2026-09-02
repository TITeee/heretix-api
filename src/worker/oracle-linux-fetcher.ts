import axios from 'axios';
import { createRequire } from 'module';
import { XMLParser } from 'fast-xml-parser';
import type { AdvisoryFetcher, NormalizedAdvisory } from './advisory-fetcher.js';
import { logger } from '../utils/logger.js';
import { extractOsMajorVersion, inferBareVersionStart, moduleStreamVersionStart } from './advisory-helpers.js';

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

export function mapSeverity(s?: unknown): string | undefined {
  if (s === undefined || s === null || s === '') return undefined;
  // fast-xml-parser auto-coerces purely numeric tag text (e.g. "<severity>0</severity>") to a number
  const str = String(s);
  return SEVERITY_MAP[str.toLowerCase()] ?? str.toUpperCase();
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

export interface CveInfo {
  cveId: string;
  cvssScore?: number;
  cvssVector?: string;
}

/**
 * Parse a <cve> element which may be a plain string ("CVE-XXXX")
 * or an object with @_cvss3="score/vector" and #text="CVE-XXXX".
 */
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
// versionEnd is kept as the full "epoch:version-release" string the OVAL feed
// writes ("0:3.2.5-3.el9_7.2" when a package has no real epoch, RPM's own
// convention for "none" is a literal number here, never a placeholder like the
// "(none)" rpm(8) itself prints -- see oracle-linux-fetcher.test.ts). Stripping
// it (as this used to) drops the single highest-precedence field
// compareRpmVersions() compares: an installed package with a real epoch reads
// as newer than *any* epoch-omitted (implicitly epoch-0) row regardless of its
// actual version/release, so every fix for it silently stops matching.
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

// Oracle ships parallel, differently-epoched fix tracks for the same product
// name alongside the regular build: ksplice live-patch errata ("<pkg> is
// ksplice-based", epoch bumped by roughly 1) and FIPS-validated module
// builds ("<pkg> is fips patched", epoch pinned to 10 specifically to keep
// it sorting above every ordinary release). Both markers sit as a sibling
// <criterion> alongside the package's own "is earlier than" criterion, under
// the same AND block -- confirmed live on Oracle Linux 9's openssl/openssl-libs
// and gnutls definitions. Merging one of these rows into the regular
// (product, vendor) bucket makes a fully-patched regular-track install read
// as vulnerable against a fix version on a track it was never running,
// because that track's own epoch has nothing to do with the regular
// package's version history (confirmed: 79 "fips patched" + 200
// "ksplice-based" definitions inflated one image's false-positive count from
// ~0 to 47 across just openssl/openssl-libs/gnutls, 2026-09-02).
const BUILD_VARIANT_RE = /\bis (fips patched|ksplice-based)$/i;

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
  /**
   * True when a sibling criterion in the same AND block marks this as a
   * ksplice or FIPS build-variant track rather than the regular package
   * (see BUILD_VARIANT_RE). Scoped to the immediate criterion array only,
   * not inherited by nested <criteria> the way moduleMajor is -- each
   * package's own AND block carries its own variant marker independently.
   */
  isBuildVariant: boolean;
}

/**
 * Recursively collect all <criterion> elements from a criteria tree.
 * OVAL criteria can be nested: <criteria><criteria><criterion/></criteria></criteria>
 */
export function collectCriteria(node: unknown, moduleMajor: string | null = null): CollectedCriterion[] {
  if (!node || typeof node !== 'object') return [];
  const n = node as Record<string, unknown>;
  const results: CollectedCriterion[] = [];

  const ownCriteria = toArray(n['criterion'] as unknown) as Record<string, unknown>[];

  let scopedModuleMajor = moduleMajor;
  let isBuildVariant = false;
  for (const c of ownCriteria) {
    // fast-xml-parser auto-coerces purely numeric attribute text (e.g.
    // comment="0") to a number -- guard against that the same way
    // mapSeverity() does, rather than assuming the `as string` cast holds.
    const comment = c['@_comment'];
    if (typeof comment !== 'string') continue;
    const major = extractModuleMajor(comment);
    if (major !== null) scopedModuleMajor = major;
    if (BUILD_VARIANT_RE.test(comment)) isBuildVariant = true;
  }

  // Direct criterion children
  for (const c of ownCriteria) {
    results.push({ node: c, moduleMajor: scopedModuleMajor, isBuildVariant });
  }

  // Recurse into nested criteria
  for (const nested of toArray(n['criteria'] as unknown)) {
    results.push(...collectCriteria(nested, scopedModuleMajor));
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

  isCompleteSnapshot(): boolean {
    return true;
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
      const severity = mapSeverity(advisory?.['severity']);

      const cveElements = toArray(advisory?.['cve'] as unknown);
      const cves = cveElements
        .map(parseCveElement)
        .filter((c): c is CveInfo => c !== null);

      // ── Affected packages ─────────────────────────────────────
      const criteriaNode = d['criteria'] as unknown;
      // criteria parsed as array due to isArray; use first top-level node
      const topCriteria = Array.isArray(criteriaNode) ? criteriaNode[0] : criteriaNode;
      const criterionList = collectCriteria(topCriteria);

      const affectedProducts: NormalizedAdvisory['affectedProducts'] = [];
      const seen = new Set<string>();

      for (const crit of criterionList) {
        if (crit.isBuildVariant) continue;

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

        // This feed covers every Oracle Linux release in one download (see the
        // constructor), so — unlike RedHatFetcher, which knows its release from
        // which file it requested — the release has to come from each row's own
        // release string. A row search-helpers.ts's per-release lookup can't
        // reach falls back to the bare, unqualified vendor rather than being
        // dropped, same as the pre-2026-09-01 behavior for every row.
        const major = extractOsMajorVersion(parsed.versionEnd);
        affectedProducts.push({
          vendor: major ? `oracle-linux-${major}` : 'oracle-linux',
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
        url: elsaRef?.['@_ref_url'] as string | undefined,
        affectedProducts,
        rawData: def,
      };

      if (cves.length === 0) {
        advisories.push({ externalId: elsaId, ...baseFields });
      } else {
        for (const cve of cves) {
          advisories.push({
            externalId: `${elsaId}/${cve.cveId}`,
            cveId: cve.cveId,
            cvssScore: cve.cvssScore,
            cvssVector: cve.cvssVector,
            ...baseFields,
          });
        }
      }
    }

    logger.info({ count: advisories.length }, 'Parsed Oracle Linux OVAL advisories');
    return advisories;
  }
}
