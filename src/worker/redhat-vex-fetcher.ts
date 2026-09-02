import zlib from 'node:zlib';
import axios from 'axios';
import tarStream from 'tar-stream';
import type { AdvisoryFetcher, NormalizedAdvisory } from './advisory-fetcher.js';
import { logger } from '../utils/logger.js';

// ─── Constants ────────────────────────────────────────────────

const LATEST_URL = 'https://security.access.redhat.com/data/csaf/v2/vex/archive_latest.txt';

const SEVERITY_MAP: Record<string, string> = {
  critical: 'CRITICAL',
  important: 'HIGH',
  moderate: 'MEDIUM',
  low: 'LOW',
};

// ─── Helpers ──────────────────────────────────────────────────

export function mapSeverity(s?: unknown): string | undefined {
  if (s === undefined || s === null || s === '') return undefined;
  const str = String(s);
  return SEVERITY_MAP[str.toLowerCase()] ?? str.toUpperCase();
}

export interface RhelComponent {
  major: string;
  pkg: string;
}

const RHEL_PRODUCT_RE = /^red_hat_enterprise_linux_(\d+)$/;

// Matches RedHatFetcher's own supported variants (redhat-fetcher.ts). The VEX
// archive tracks every RHEL major back to 5, and the vast majority of that
// history is long-EOL and irrelevant here; accepting all of it multiplied the
// qualifying-CVE set several times over for no benefit and was a direct
// contributor to an OOM crash processing the full archive (see git history).
const SUPPORTED_MAJORS = new Set(['8', '9']);

/**
 * Maps a VEX document's compound product IDs ("red_hat_enterprise_linux_9:bzip2-libs")
 * back to (RHEL major, package name), using product_tree.relationships rather
 * than parsing the ID string directly -- the compound ID's shape is an
 * implementation detail of "default_component_of" relationships onto a bare
 * "red_hat_enterprise_linux_N" product; other relationship categories (container
 * images, product families) use unrelated ID schemes that happen to also
 * contain colons, so matching on the relationship structure itself, not a
 * regex over the ID, is what keeps this from misparsing those.
 */
export function buildRhelComponentMap(relationships: unknown): Map<string, RhelComponent> {
  const map = new Map<string, RhelComponent>();
  if (!Array.isArray(relationships)) return map;

  for (const rel of relationships) {
    if (!rel || typeof rel !== 'object') continue;
    const r = rel as Record<string, unknown>;
    if (r['category'] !== 'default_component_of') continue;

    const relatesTo = r['relates_to_product_reference'];
    const majorMatch = typeof relatesTo === 'string' ? relatesTo.match(RHEL_PRODUCT_RE) : null;
    if (!majorMatch || !SUPPORTED_MAJORS.has(majorMatch[1])) continue;

    const fpn = r['full_product_name'] as Record<string, unknown> | undefined;
    const productId = fpn?.['product_id'];
    const pkg = r['product_reference'];
    if (typeof productId !== 'string' || typeof pkg !== 'string') continue;

    map.set(productId, { major: majorMatch[1], pkg });
  }

  return map;
}

/**
 * Components a CVE affects on some RHEL major version with no fix recorded
 * anywhere in this document. "known_affected" is Red Hat's own explicit "yes
 * this applies, no it's not resolved" signal -- unlike the OVAL patch feed
 * (redhat-fetcher.ts), which only ever publishes definitions for CVEs that
 * *have* a fix and has no representation for the unfixed case at all.
 */
export function extractUnfixedComponents(
  productStatus: unknown,
  componentMap: Map<string, RhelComponent>,
): RhelComponent[] {
  if (!productStatus || typeof productStatus !== 'object') return [];
  const ps = productStatus as Record<string, unknown>;

  const knownAffected = Array.isArray(ps['known_affected']) ? (ps['known_affected'] as unknown[]) : [];
  const fixed = new Set(Array.isArray(ps['fixed']) ? (ps['fixed'] as unknown[]) : []);

  const seen = new Set<string>();
  const results: RhelComponent[] = [];
  for (const productId of knownAffected) {
    if (typeof productId !== 'string' || fixed.has(productId)) continue;
    const component = componentMap.get(productId);
    if (!component) continue;
    const key = `${component.major}:${component.pkg}`;
    if (seen.has(key)) continue;
    seen.add(key);
    results.push(component);
  }
  return results;
}

export interface VexCveInfo {
  cve: string;
  title?: string;
  severity?: string;
  cvssScore?: number;
  cvssVector?: string;
}

export function parseVexVulnerability(vuln: unknown): VexCveInfo | null {
  if (!vuln || typeof vuln !== 'object') return null;
  const v = vuln as Record<string, unknown>;
  const cve = v['cve'];
  if (typeof cve !== 'string' || !cve.startsWith('CVE-')) return null;

  const scores = Array.isArray(v['scores']) ? (v['scores'] as Record<string, unknown>[]) : [];
  const cvss3 = scores.map(s => s['cvss_v3']).find((c): c is Record<string, unknown> => !!c && typeof c === 'object');

  return {
    cve,
    title: typeof v['title'] === 'string' ? (v['title'] as string) : undefined,
    severity: mapSeverity(cvss3?.['baseSeverity']),
    cvssScore: typeof cvss3?.['baseScore'] === 'number' ? (cvss3['baseScore'] as number) : undefined,
    cvssVector: typeof cvss3?.['vectorString'] === 'string' ? (cvss3['vectorString'] as string) : undefined,
  };
}

/**
 * Builds one NormalizedAdvisory for a single decoded VEX document's CVE, with
 * one affectedProduct entry per (RHEL major, package) pair that CVE affects
 * with no recorded fix. Returns null for the common case -- most CVEs in the
 * archive are for other Red Hat products entirely, or are fully fixed on
 * every RHEL major they touch (already covered by RedHatFetcher's OVAL feed).
 *
 * affectedProducts carry no versionStart/versionEnd: there is no upper bound
 * to record, only the fact of being unfixed. patchAvailable: false is the
 * explicit signal matchesRpmVersionRange() and searchAdvisory() key off of to
 * match unconditionally rather than the version-range default of never
 * matching a row with no bound (see search-helpers.ts).
 */
export function normalizeVexDoc(doc: unknown): NormalizedAdvisory | null {
  if (!doc || typeof doc !== 'object') return null;
  const d = doc as Record<string, unknown>;

  const productTree = d['product_tree'] as Record<string, unknown> | undefined;
  const vulnerabilities = Array.isArray(d['vulnerabilities']) ? (d['vulnerabilities'] as unknown[]) : [];
  if (!productTree || vulnerabilities.length === 0) return null;

  const componentMap = buildRhelComponentMap(productTree['relationships']);
  if (componentMap.size === 0) return null;

  // Red Hat's archive is one CVE per file, but the CSAF schema allows several
  // `vulnerabilities` entries per document -- fold every entry's unfixed
  // components together under the first one that parses as a real CVE
  // (defensive; not observed in practice).
  let info: VexCveInfo | null = null;
  const components: RhelComponent[] = [];
  const seen = new Set<string>();
  for (const vuln of vulnerabilities) {
    const parsed = parseVexVulnerability(vuln);
    if (!parsed) continue;
    info ??= parsed;

    const v = vuln as Record<string, unknown>;
    for (const c of extractUnfixedComponents(v['product_status'], componentMap)) {
      const key = `${c.major}:${c.pkg}`;
      if (seen.has(key)) continue;
      seen.add(key);
      components.push(c);
    }
  }
  if (!info || components.length === 0) return null;

  return {
    externalId: info.cve,
    cveId: info.cve,
    summary: info.title,
    severity: info.severity,
    cvssScore: info.cvssScore,
    cvssVector: info.cvssVector,
    affectedProducts: components.map(c => ({
      vendor: `red-hat-${c.major}`,
      product: c.pkg,
      patchAvailable: false,
    })),
    // Not the full parsed document: a VEX doc's product_tree can carry
    // hundreds of container-image/product-family relationships entirely
    // unrelated to the handful of RHEL components extracted above, and
    // keeping every qualifying CVE's full doc alive in memory for the whole
    // run (tens of thousands of them, across the entire archive) is what
    // pushed a prior version of this fetcher into an OOM crash. Everything
    // meaningful for this advisory is already on the fields above and in
    // affectedProducts; this exists only so rawData isn't empty.
    rawData: { source: 'redhat-vex', cve: info.cve },
  };
}

// ─── Fetcher ──────────────────────────────────────────────────

/**
 * Fetches Red Hat's bulk CSAF VEX archive (one JSON document per CVE, across
 * every Red Hat product) and extracts the RHEL-specific "affected, no fix
 * available" facts it carries -- data the OVAL patch feed (RedHatFetcher)
 * structurally cannot represent, since that feed only ever publishes
 * definitions for CVEs that already have a released fix.
 *
 * The archive is large (a few hundred MB compressed, an order of magnitude
 * more decompressed) and covers every Red Hat product, not just RHEL, so it
 * is streamed end-to-end (HTTP -> zstd decompress -> tar extract -> per-entry
 * JSON parse) rather than buffered in memory.
 */
export class RedHatVexFetcher implements AdvisoryFetcher {
  private failedCount = 0;

  source(): string {
    return 'red-hat-vex';
  }

  isCompleteSnapshot(): boolean {
    return true;
  }

  fetchFailedCount(): number {
    return this.failedCount;
  }

  async fetch(): Promise<NormalizedAdvisory[]> {
    this.failedCount = 0;

    const latestResp = await axios.get<string>(LATEST_URL, { responseType: 'text', timeout: 30000 });
    const archiveName = latestResp.data.trim();
    const archiveUrl = LATEST_URL.replace('archive_latest.txt', archiveName);

    logger.info({ url: archiveUrl }, 'Downloading Red Hat VEX archive');

    const response = await axios.get<NodeJS.ReadableStream>(archiveUrl, {
      responseType: 'stream',
      timeout: 20 * 60 * 1000,
    });

    // Keyed by CVE id: within one archive a CVE could in principle recur
    // (it doesn't, in practice -- Red Hat publishes one file per CVE), and a
    // Map naturally dedupes to the last-seen entry rather than needing an
    // explicit check.
    const advisoriesByCve = new Map<string, NormalizedAdvisory>();

    await new Promise<void>((resolve, reject) => {
      const extract = tarStream.extract();

      extract.on('entry', (header, entryStream, next) => {
        if (header.type !== 'file' || !header.name.endsWith('.json')) {
          entryStream.resume();
          next();
          return;
        }

        const chunks: Buffer[] = [];
        entryStream.on('data', (chunk: unknown) => chunks.push(chunk as Buffer));
        entryStream.on('error', next);
        entryStream.on('end', () => {
          try {
            const doc = JSON.parse(Buffer.concat(chunks).toString('utf8'));
            const normalized = normalizeVexDoc(doc);
            if (normalized) advisoriesByCve.set(normalized.externalId, normalized);
          } catch (err) {
            this.failedCount++;
            logger.warn({ err, entry: header.name }, 'Failed to parse Red Hat VEX document');
          }
          next();
        });
      });

      extract.on('finish', resolve);
      extract.on('error', reject);

      response.data.on('error', reject);
      response.data.pipe(zlib.createZstdDecompress()).pipe(extract);
    });

    logger.info({ count: advisoriesByCve.size, failed: this.failedCount }, 'Parsed Red Hat VEX advisories');
    return [...advisoriesByCve.values()];
  }
}
