import zlib from 'node:zlib';
import axios from 'axios';
import tarStream from 'tar-stream';
import type { AdvisoryFetcher, NormalizedAdvisory } from './advisory-fetcher.js';
import { logger } from '../utils/logger.js';
import { parseRedHatImpact } from './redhat-fetcher.js';
import { type FixStatusInfo, redHatRemediationStatus } from '../utils/fix-status.js';
import { compareRpmVersions } from '../utils/rpm-version.js';

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

/** An unfixed component, with Red Hat's stated reason for the missing fix. */
export interface UnfixedRhelComponent extends RhelComponent, FixStatusInfo {}

const RHEL_PRODUCT_RE = /^red_hat_enterprise_linux_(\d+)$/;

// Matches RedHatFetcher's own supported variants (redhat-fetcher.ts). The VEX
// archive tracks every RHEL major back to 5, and the vast majority of that
// history is long-EOL and irrelevant here; accepting all of it multiplied the
// qualifying-CVE set several times over for no benefit and was a direct
// contributor to an OOM crash processing the full archive (see git history).
const SUPPORTED_MAJORS = new Set(['8', '9', '10']);

// Majors Red Hat publishes no OVAL patch feed for: OVAL stops at RHEL 9, and
// RHEL 10 security data is CSAF/VEX only. RedHatFetcher therefore has nothing
// to import for these, so the fixed builds recorded here are the only source
// of their fixed rows, not just of their unfixed ones.
const VEX_ONLY_MAJORS = new Set(['10']);

const DEBUG_PACKAGE_RE = /-debug(?:info|source)$/;

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
    const rawPkg = r['product_reference'];
    if (typeof productId !== 'string' || typeof rawPkg !== 'string') continue;

    // A source RPM ("sed.src") can be the *only* relationship Red Hat records
    // for a component, with no separate entry for its own same-named binary
    // package ("sed") -- observed live on CVE-2026-5958. Nothing installed on
    // a running system is ever named "foo.src", so left as-is this component
    // could never match an SBOM's installed package list. Stripping the
    // suffix recovers the real, installable name for the common case (a
    // single-binary-output source RPM); it isn't a full source->binary
    // mapping and won't help a multi-output source RPM whose extra binaries
    // aren't independently listed, but that's the same "no data recorded"
    // gap this whole fetcher exists to narrow, not one it can close alone.
    const pkg = rawPkg.endsWith('.src') ? rawPkg.slice(0, -'.src'.length) : rawPkg;

    map.set(productId, { major: majorMatch[1], pkg });
  }

  return map;
}

/**
 * Components a CVE affects on some RHEL major version with no fix recorded
 * anywhere in this document. Pulled from two of `product_status`'s buckets,
 * both treated as an unconditional "affected, no fix" signal despite their
 * different confidence levels:
 *   - "known_affected": Red Hat's explicit "yes this applies, not resolved".
 *   - "under_investigation": Red Hat hasn't yet confirmed impact one way or
 *     the other (observed live on CVE-2026-56403/expat) -- narrower than
 *     known_affected, but still not "ruled out", so it's surfaced the same
 *     way rather than silently dropped pending a triage that may take a
 *     while to land.
 * Either way this is unlike the OVAL patch feed (redhat-fetcher.ts), which
 * only ever publishes definitions for CVEs that *have* a fix and has no
 * representation for an unresolved case at all.
 *
 * Each component carries Red Hat's reason for the missing fix, from the
 * vulnerability's `remediations` (redHatRemediationStatus()): "Will not fix",
 * "Out of support scope", "Fix deferred" or "Affected" -- the distinction
 * between "accept it, no fix is coming" and "wait for the fix". A
 * known_affected component with no such remediation is plain `affected`;
 * an under_investigation one is `under_investigation` unless a remediation
 * says more.
 */
export function extractUnfixedComponents(
  productStatus: unknown,
  componentMap: Map<string, RhelComponent>,
  remediations: unknown = [],
): UnfixedRhelComponent[] {
  if (!productStatus || typeof productStatus !== 'object') return [];
  const ps = productStatus as Record<string, unknown>;

  const toArray = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
  const fixed = new Set(toArray(ps['fixed']));
  const knownAffected = toArray(ps['known_affected']);
  // A product in both buckets is known_affected: the confirmed statement wins.
  const investigating = new Set(toArray(ps['under_investigation']).filter(id => !knownAffected.includes(id)));
  const candidates = [...knownAffected, ...investigating];

  // product_id -> reason. A product listed under more than one no-fix
  // remediation keeps the first, which is how Red Hat orders them.
  const reasons = new Map<string, FixStatusInfo>();
  for (const rem of toArray(remediations)) {
    if (!rem || typeof rem !== 'object') continue;
    const r = rem as Record<string, unknown>;
    const status = redHatRemediationStatus(r['category'], r['details']);
    if (!status) continue;
    for (const id of toArray(r['product_ids'])) {
      if (typeof id === 'string' && !reasons.has(id)) reasons.set(id, status);
    }
  }

  const seen = new Set<string>();
  const results: UnfixedRhelComponent[] = [];
  for (const productId of candidates) {
    if (typeof productId !== 'string' || fixed.has(productId)) continue;
    const component = componentMap.get(productId);
    if (!component) continue;
    const key = `${component.major}:${component.pkg}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const reason = reasons.get(productId)
      ?? { fixStatus: investigating.has(productId) ? 'under_investigation' : 'affected', fixStatusDetail: null };
    results.push({ ...component, ...reason });
  }
  return results;
}

// A release stream a fixed build ships in: "BaseOS-9.3.0.GA",
// "AppStream-9.2.0.Z.EUS", "RT-9.3.GA", ... -- "<repo>-<major>.<minor>...".
const RHEL_STREAM_RE = /^[A-Za-z0-9_]+-(\d+)\.\d+(?:\.|$)/;
// A binary or source RPM NEVRA: "bpftool-0:7.2.0-362.8.1.el9_3.x86_64".
const NEVRA_RE = /^(.+)-(\d+):([^-]+)-([^-]+)\.([A-Za-z0-9_]+)$/;

/**
 * The newest fixed build, per (RHEL major, package), that this document's
 * `fixed` product status records in any release stream of that major.
 *
 * Red Hat's VEX states "unfixed" per major only
 * ("red_hat_enterprise_linux_9:kernel" known_affected) but "fixed" per
 * release stream and exact build ("BaseOS-9.3.0.GA:kernel-0:5.14.0-362.8.1.el9_3.x86_64",
 * "...-9.2.0.Z.EUS:..."). Measured on 2,609 OVAL/VEX overlapping pairs, 54%
 * had such a fix for the very major they called affected -- read on its own,
 * the major-level statement matched every version, including builds at or
 * past those fixes.
 *
 * The newest fix across all streams is used as the row's exclusive upper
 * bound: anything at or above it is newer than every recorded fix, so it can
 * be called fixed without risking a miss. Builds between an older stream's
 * fix (an EUS one, say) and that bound still match -- a remaining false
 * positive, deliberately preferred over introducing misses by guessing which
 * stream an installed build belongs to.
 */
export function newestFixedVersions(relationships: unknown, productStatus: unknown): Map<string, string> {
  const result = new Map<string, string>();
  if (!Array.isArray(relationships) || !productStatus || typeof productStatus !== 'object') return result;
  const fixedIds = (productStatus as Record<string, unknown>)['fixed'];
  const fixed = new Set(Array.isArray(fixedIds) ? fixedIds : []);
  if (fixed.size === 0) return result;

  for (const rel of relationships) {
    if (!rel || typeof rel !== 'object') continue;
    const r = rel as Record<string, unknown>;
    if (r['category'] !== 'default_component_of') continue;
    const productId = (r['full_product_name'] as Record<string, unknown> | undefined)?.['product_id'];
    if (typeof productId !== 'string' || !fixed.has(productId)) continue;

    const stream = r['relates_to_product_reference'];
    const majorMatch = typeof stream === 'string' ? stream.match(RHEL_STREAM_RE) : null;
    if (!majorMatch || !SUPPORTED_MAJORS.has(majorMatch[1])) continue;
    const nevra = typeof r['product_reference'] === 'string' ? r['product_reference'].match(NEVRA_RE) : null;
    if (!nevra) continue;

    const [, name, epoch, version, release] = nevra;
    const evr = `${epoch}:${version}-${release}`;
    const key = `${majorMatch[1]}:${name}`;
    const current = result.get(key);
    if (!current || compareRpmVersions(evr, current) > 0) result.set(key, evr);
  }
  return result;
}

/** Splits a "<major>:<package>" key built by newestFixedVersions(). */
function splitComponentKey(key: string): [string, string] {
  const sep = key.indexOf(':');
  return [key.slice(0, sep), key.slice(sep + 1)];
}

export interface VexCveInfo {
  cve: string;
  title?: string;
  severity?: string;
  cvssScore?: number;
  cvssVector?: string;
  /** Red Hat's own impact rating for the CVE, from threats[category=impact]. */
  impact?: string;
}

export function parseVexVulnerability(vuln: unknown): VexCveInfo | null {
  if (!vuln || typeof vuln !== 'object') return null;
  const v = vuln as Record<string, unknown>;
  const cve = v['cve'];
  if (typeof cve !== 'string' || !cve.startsWith('CVE-')) return null;

  const scores = Array.isArray(v['scores']) ? (v['scores'] as Record<string, unknown>[]) : [];
  const threats = Array.isArray(v['threats']) ? (v['threats'] as Record<string, unknown>[]) : [];
  const cvss3 = scores.map(s => s['cvss_v3']).find((c): c is Record<string, unknown> => !!c && typeof c === 'object');

  return {
    cve,
    title: typeof v['title'] === 'string' ? (v['title'] as string) : undefined,
    severity: mapSeverity(cvss3?.['baseSeverity']),
    cvssScore: typeof cvss3?.['baseScore'] === 'number' ? (cvss3['baseScore'] as number) : undefined,
    cvssVector: typeof cvss3?.['vectorString'] === 'string' ? (cvss3['vectorString'] as string) : undefined,
    // `severity` above is the CVSS rating; Red Hat's own judgement of the CVE
    // (which can differ -- a CVSS 7.5 Red Hat rates "moderate") is the
    // impact threat. Kept verbatim as the distro priority.
    impact: threats
      .filter(t => t['category'] === 'impact')
      .map(t => parseRedHatImpact(t['details']))
      .find((i): i is string => i !== undefined),
  };
}

/**
 * Builds one NormalizedAdvisory for a single decoded VEX document's CVE, with
 * one affectedProduct entry per (RHEL major, package) pair that CVE affects
 * with no recorded fix, plus -- for majors with no OVAL feed (VEX_ONLY_MAJORS,
 * i.e. RHEL 10) -- one patchAvailable: true row per fixed package, bounded by
 * its newest recorded fix. Returns null for the common case -- most CVEs in
 * the archive are for other Red Hat products entirely, or are fully fixed on
 * every OVAL-covered major they touch (already covered by RedHatFetcher).
 *
 * affectedProducts carry no versionStart, and a versionEnd only when the same
 * document records a fixed build for that major in some release stream
 * (newestFixedVersions()). Without one there is no upper bound to record, only
 * the fact of being unfixed: patchAvailable: false is the explicit signal
 * matchesRpmVersionRange() and searchAdvisory() key off of to match
 * unconditionally rather than the version-range default of never matching a
 * row with no bound (see search-helpers.ts).
 */
export function normalizeVexDoc(doc: unknown): NormalizedAdvisory | null {
  if (!doc || typeof doc !== 'object') return null;
  const d = doc as Record<string, unknown>;

  const productTree = d['product_tree'] as Record<string, unknown> | undefined;
  const vulnerabilities = Array.isArray(d['vulnerabilities']) ? (d['vulnerabilities'] as unknown[]) : [];
  if (!productTree || vulnerabilities.length === 0) return null;

  // No early return on an empty map: a CVE fully fixed on a VEX-only major
  // records its builds per release stream ("AppStream-10.0.Z:...") and has no
  // major-level relationship at all.
  const componentMap = buildRhelComponentMap(productTree['relationships']);

  // Red Hat's archive is one CVE per file, but the CSAF schema allows several
  // `vulnerabilities` entries per document -- fold every entry's unfixed
  // components together under the first one that parses as a real CVE
  // (defensive; not observed in practice).
  let info: VexCveInfo | null = null;
  const components: UnfixedRhelComponent[] = [];
  const newestFix = new Map<string, string>();
  const seen = new Set<string>();
  for (const vuln of vulnerabilities) {
    const parsed = parseVexVulnerability(vuln);
    if (!parsed) continue;
    info ??= parsed;

    const v = vuln as Record<string, unknown>;
    for (const c of extractUnfixedComponents(v['product_status'], componentMap, v['remediations'])) {
      const key = `${c.major}:${c.pkg}`;
      if (seen.has(key)) continue;
      seen.add(key);
      components.push(c);
    }
    for (const [key, evr] of newestFixedVersions(productTree['relationships'], v['product_status'])) {
      const current = newestFix.get(key);
      if (!current || compareRpmVersions(evr, current) > 0) newestFix.set(key, evr);
    }
  }
  // Fixed rows for VEX-only majors, bounded by the newest fix the same way
  // the unfixed rows above are. A component that is also unfixed on that
  // major already has its row. Debug packages are skipped, as the OVAL feed
  // never lists them either.
  const fixedRows: NormalizedAdvisory['affectedProducts'] = [];
  for (const [key, evr] of newestFix) {
    const [major, pkg] = splitComponentKey(key);
    if (!VEX_ONLY_MAJORS.has(major) || seen.has(key) || DEBUG_PACKAGE_RE.test(pkg)) continue;
    fixedRows.push({ vendor: `red-hat-${major}`, product: pkg, versionEnd: evr, patchAvailable: true });
  }
  if (!info || (components.length === 0 && fixedRows.length === 0)) return null;

  const unfixedRows: NormalizedAdvisory['affectedProducts'] = components.map(c => {
    // Bounded by the newest fix the same document records for this major
    // (newestFixedVersions()); unbounded -- every version -- when it records none.
    const versionEnd = newestFix.get(`${c.major}:${c.pkg}`);
    return {
      vendor: `red-hat-${c.major}`,
      product: c.pkg,
      ...(versionEnd ? { versionEnd } : {}),
      patchAvailable: false,
      fixStatus: c.fixStatus,
      fixStatusDetail: c.fixStatusDetail,
    };
  });

  return {
    externalId: info.cve,
    cveId: info.cve,
    summary: info.title,
    severity: info.severity,
    cvssScore: info.cvssScore,
    cvssVector: info.cvssVector,
    distroPriority: info.impact,
    affectedProducts: [...unfixedRows, ...fixedRows],
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
 * definitions for CVEs that already have a released fix. For RHEL 10, which
 * has no OVAL feed, it also supplies the fixed rows.
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
