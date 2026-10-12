import axios from 'axios';
import AdmZip from 'adm-zip';
import { logger } from '../utils/logger.js';
import { normalizeVersion } from '../utils/version.js';

// ─── cvelistV5 release bundles ───────────────────────────────
//
// The CVE Program publishes every CVE Record as JSON 5.x to the cvelistV5 repo
// and attaches two kinds of bundle to its hourly GitHub releases:
//   <date>_all_CVEs_at_midnight.zip.zip   full snapshot, ~600MB, daily
//   <date>_delta_CVEs_at_<HHMM>Z.zip      only records changed that hour, a few MB/day
// No API key and no rate limit to work around, unlike the NVD API.
//
// This module stays free of DB imports so its parsing rules can be unit tested
// without a database, the same split apache-fetcher.ts and the other advisory
// fetchers use. Persistence lives in cna-importer.ts.

const RELEASES_URL = 'https://api.github.com/repos/CVEProject/cvelistV5/releases';

export interface GitHubRelease {
  tag_name: string;
  published_at: string;
  assets: Array<{ name: string; browser_download_url: string; size: number }>;
}

// ─── CVE Record types (only the fields this fetcher reads) ───

export interface CveRecordVersion {
  version?: unknown;
  status?: unknown;
  lessThan?: unknown;
  lessThanOrEqual?: unknown;
  versionType?: unknown;
}

export interface CveRecordAffected {
  vendor?: unknown;
  product?: unknown;
  packageName?: unknown;
  defaultStatus?: unknown;
  versions?: unknown;
}

export interface CveRecord {
  cveMetadata?: { cveId?: unknown; datePublished?: unknown; dateUpdated?: unknown; state?: unknown };
  containers?: {
    cna?: { providerMetadata?: { shortName?: unknown }; affected?: unknown };
    // Authorized Data Publisher containers -- CISA's Vulnrichment (SSVC) data
    // is one of these, alongside the CVE Program's own transferred-reference
    // container and others. Array shape confirmed live (CVE-2024-3400).
    adp?: unknown[];
  };
}

// ─── Extraction ──────────────────────────────────────────────

export interface CnaAffectedRow {
  vendor: string;
  product: string;
  packageName?: string;
  versionType?: string;
  versionStart?: string;
  versionEnd?: string;
  lastAffected?: string;
  affectedVersions?: string[];
}

export type DropReason =
  | 'defaultAffectedNoVersions'
  | 'noVendorOrProduct'
  | 'gitVersionType'
  | 'unusableVersionString'
  | 'exactVersionUnusable'
  | 'unencodableRangeBound'
  | 'netscalerBuildBound';

export interface ExtractResult {
  rows: CnaAffectedRow[];
  dropped: Partial<Record<DropReason, number>>;
}

/**
 * A version string this fetcher is willing to hand to normalizeVersion().
 *
 * normalizeVersion() cannot be used as the validity check here: it strips every
 * non-digit character rather than rejecting the string, so free text comes back
 * as a confident but wrong number instead of null. Measured against real CNA
 * data: "unspecified" / "n/a" / "?" / "*" / "All versions" all return 0 (not
 * null), "Apache HTTP Server 2.4 2.4.49" (the real CVE-2021-41773 declaration)
 * returns 2.42.4, and "before 2.0" returns 2.0 -- inverting "below 2.0" into
 * the version itself. Any of those stored as a bound is a false positive
 * waiting to happen, so the string has to look like a dotted numeric version
 * before it is trusted.
 */
const STRICT_VERSION = /^[0-9]+(\.[0-9]+)*([.\-_+][0-9A-Za-z.\-_+]*)?$/;

// Values CNAs use to mean "not a real version". These have to be listed
// explicitly: "0" and "-" would otherwise pass STRICT_VERSION, and the rest
// normalize to 0 rather than failing.
const PLACEHOLDER_VERSIONS = new Set([
  '', '0', '*', '-', '?', 'n/a', 'na', 'none', 'unspecified', 'unknown',
  'all', 'all versions', 'various', 'tbd',
]);

const PLACEHOLDER_NAMES = new Set(['', '-', '?', 'n/a', 'na', 'none', 'unspecified', 'unknown', 'various', 'tbd']);

function asString(v: unknown): string | undefined {
  return typeof v === 'string' && v.trim() !== '' ? v.trim() : undefined;
}

function isPlaceholderVersion(v: string | undefined): boolean {
  return v === undefined || PLACEHOLDER_VERSIONS.has(v.toLowerCase());
}

/** A bound usable for range comparison: real version syntax, not a placeholder. */
export function isUsableVersion(v: unknown): v is string {
  const s = asString(v);
  if (s === undefined || PLACEHOLDER_VERSIONS.has(s.toLowerCase())) return false;
  return STRICT_VERSION.test(s);
}

/**
 * A range bound trustworthy enough to store as a range at all: passes
 * isUsableVersion() *and* normalizeVersion() can actually encode it.
 *
 * A bound like a YYYYMMDD date-as-version ("20210218") or a Jenkins plugin
 * version ("4.618.v441a_27fa_46d2") passes the dotted-numeric syntax check but
 * normalizeVersion() rejects it as out of range or garbage, returning null.
 * Storing the row anyway with a null *Int column would make it read as
 * unbounded on that side once any range query runs against it -- for a
 * one-sided bound (the common "0, lessThan: X" shape) with no other bound at
 * all, that is "matches every version queried". Range bounds have to clear
 * this bar; a single exact-match version does not, since it is never combined
 * into a range in the first place.
 */
function isEncodableBound(v: string): boolean {
  return isUsableVersion(v) && normalizeVersion(v) !== null;
}

function isUsableName(v: unknown): v is string {
  const s = asString(v);
  // Single-character product names ("i" appears in real data) carry no signal
  // and would collide with anything.
  return s !== undefined && s.length >= 2 && !PLACEHOLDER_NAMES.has(s.toLowerCase());
}

/**
 * A NetScaler range: the CNA (NetScaler / Cloud Software Group) writes the
 * release branch as the version and the build as the bound --
 * { version: "14.1", lessThan: "56.73", versionType: "patch" } -- or, in another
 * spelling, the whole thing as the bound ("14.1-73.37"). Neither is a version
 * that normalizeVersion() can order:
 *   - "14.1" .. "56.73" reads as 14.1.0 up to 56.73.0, so every build of 14.1 and
 *     later, the fixed ones included, comes back as affected (the fix 14.1-56.73
 *     and the later 14.1-60.52 among them);
 *   - "14.1-73.37" keeps only the 73 of its build, so 73.37 and 73.99 compare equal.
 * The builds are in the NetScaler security bulletins, which need an order of
 * their own, so these ranges are not stored here rather than stored wrong.
 *
 * Other vendors use versionType "patch" for ordinary ranges (Concrete CMS
 * "5.6" to "9.4.3"), and Citrix's own client apps use it for client versions;
 * only the NetScaler products are matched.
 */
function isNetScalerBuildRange(vendor: string, versionType: string | undefined, hasUpperBound: boolean): boolean {
  return hasUpperBound && versionType?.toLowerCase() === 'patch' && /netscaler/i.test(vendor);
}

/**
 * `lessThan: "*"` with a real starting version: "this release and every later one in
 * its branch, no fix yet". F5 writes the branches it has not fixed (end-of-life ones
 * above all) this way, one entry per branch, e.g. BIG-IP "16.1.0" to "*" next to
 * "17.1.0" to "17.1.3.1" in the same record. A bound is not a version, so the row is
 * stored with a start and no end, which the search reads as "from this version on".
 *
 * Read alone that would run on into later branches that ARE fixed (16.1.0 and up
 * takes in 17.1.3.1), so it ends where the next branch of the same record begins: the
 * smallest starting version above it that is in a different major.minor, looking
 * at every entry the record has for the same product (WatchGuard puts a branch in
 * an entry of its own, so one entry alone would not see its neighbours). With no
 * later branch it has no end. Measured on real data this is F5 (118 ranges), EEF (36),
 * WatchGuard (6), hackerone (3) and Juniper (1); a placeholder start ("0", "*") with a
 * "*" end still means every version and is still dropped.
 */
function branchOf(version: string): string {
  const parts = version.split(/[^0-9]+/).filter(Boolean);
  return `${parts[0] ?? ''}.${parts[1] ?? '0'}`;
}

function compareVersions(a: string, b: string): number {
  const x = a.split(/[^0-9]+/).filter(Boolean).map(Number);
  const y = b.split(/[^0-9]+/).filter(Boolean).map(Number);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const d = (x[i] ?? 0) - (y[i] ?? 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  return 0;
}

function nextBranchStart(start: string, versions: CveRecordVersion[]): string | undefined {
  return versions
    .map(v => asString(v?.version))
    .filter((s): s is string => s !== undefined && isUsableVersion(s) && !isPlaceholderVersion(s))
    .filter(s => branchOf(s) !== branchOf(start) && compareVersions(s, start) > 0)
    .sort(compareVersions)[0];
}

/**
 * Juniper writes a train that was fixed in several releases as a list:
 * "version: 23.4, lessThan: 23.4R1-S2, 23.4R2". Each release line has its own fix, so
 * the affected releases are those below the fix of their own line: here 23.4 up to
 * 23.4R1-S2 (R1 is fixed at S2) and nothing in R2 (R2 itself is fixed). In general:
 *   - from the start up to the first fix;
 *   - from the release after one fix's line up to the next fix, which is empty when the
 *     next fix is a plain release ("23.4R3" starts at 23.4R3) and is dropped then.
 * Returns the [start, end) pairs, or null when the list is not the shape this reads
 * (a version that is not a Junos release, or fixes in more than one train), so the
 * caller drops it as it always did. Palo Alto and Microsoft also write lists with
 * commas and mean something else by them, so the caller only asks for Juniper.
 */
function junosFixListRanges(start: string | undefined, list: string): { start?: string; end: string }[] | null {
  const fixes = list.split(',').map(s => s.trim());
  const parsed = fixes.map(f => f.match(/^(\d+)\.(\d+)R(\d+)(?:-S(\d+))?$/));
  if (parsed.some(m => m === null) || fixes.length < 2) return null;
  const sorted = fixes.map((f, i) => ({ f, m: parsed[i]! })).sort((a, b) => compareVersions(a.f, b.f));
  const train = `${sorted[0].m[1]}.${sorted[0].m[2]}`;
  if (sorted.some(x => `${x.m[1]}.${x.m[2]}` !== train)) return null;

  const ranges: { start?: string; end: string }[] = [{ start, end: sorted[0].f }];
  for (let i = 1; i < sorted.length; i++) {
    const prev = sorted[i - 1].m;
    const from = `${prev[1]}.${prev[2]}R${Number(prev[3]) + 1}`;
    if (compareVersions(from, sorted[i].f) < 0) ranges.push({ start: from, end: sorted[i].f });
  }
  return ranges;
}

function bump(dropped: Partial<Record<DropReason, number>>, reason: DropReason): void {
  dropped[reason] = (dropped[reason] ?? 0) + 1;
}

/**
 * Turn one CVE Record's containers.cna.affected into the rows worth storing.
 *
 * Everything here exists to keep unusable declarations out of the database
 * rather than to maximise coverage -- see each rule's comment for the shape of
 * real data that motivates it.
 */
export function extractCnaRows(affected: unknown): ExtractResult {
  const rows: CnaAffectedRow[] = [];
  const dropped: Partial<Record<DropReason, number>> = {};
  if (!Array.isArray(affected)) return { rows, dropped };

  // Every version a record lists per product, whatever entry it sits in: what a
  // "lessThan: *" branch is cut off by (nextBranchStart).
  const versionsByProduct = new Map<string, CveRecordVersion[]>();
  const productKey = (r: CveRecordAffected) =>
    `${asString(r.vendor)?.toLowerCase()}\u0000${(asString(r.product) ?? asString(r.packageName))?.toLowerCase()}`;
  for (const raw of affected as CveRecordAffected[]) {
    if (typeof raw !== 'object' || raw === null || !Array.isArray(raw.versions)) continue;
    const key = productKey(raw);
    versionsByProduct.set(key, [...(versionsByProduct.get(key) ?? []), ...(raw.versions as CveRecordVersion[])]);
  }

  for (const raw of affected as CveRecordAffected[]) {
    if (typeof raw !== 'object' || raw === null) continue;

    const versions = Array.isArray(raw.versions) ? (raw.versions as CveRecordVersion[]) : [];
    // Only "affected" entries. A CNA also lists what it has ruled out --
    // CVE-2024-3094 (xz) enumerates RHEL 6/7/8/9/10 with defaultStatus
    // "unaffected" -- and taking those as affected would invert the finding.
    const affectedVersions = versions.filter(v => v && typeof v === 'object' && v.status === 'affected');

    // defaultStatus "affected" with nothing to bound it means "every version",
    // which as a stored row matches every version queried. 883 of 19,676
    // entries in a single day's data look like this.
    if (raw.defaultStatus === 'affected' && affectedVersions.length === 0) {
      bump(dropped, 'defaultAffectedNoVersions');
      continue;
    }

    const vendor = asString(raw.vendor);
    const product = asString(raw.product) ?? asString(raw.packageName);
    if (!isUsableName(vendor) || !isUsableName(product)) {
      if (affectedVersions.length > 0) bump(dropped, 'noVendorOrProduct');
      continue;
    }

    const packageName = asString(raw.packageName);

    for (const v of affectedVersions) {
      const versionType = asString(v.versionType);

      // versionType "git" carries commit hashes on both bounds (the Linux CNA
      // publishes these), which are not orderable as versions at all.
      if (versionType === 'git') {
        bump(dropped, 'gitVersionType');
        continue;
      }

      const lower = asString(v.version);
      const lessThanRaw = asString(v.lessThan);
      const lessThanOrEqualRaw = asString(v.lessThanOrEqual);
      // A bound with a wildcard names a whole line: "22.2*" (Juniper), "11.2.*" (Drupal, whose
      // unsupported 11.0 to 11.2 lines are \"0.0.0 to 11.2.*\"), "8.1.*" as an inclusive bound
      // (MongoDB). Whichever of lessThan or lessThanOrEqual carries it, the line is covered up
      // to the start of the next one: below "22.3", "11.3", "8.2". The "*" would otherwise make
      // the bound unusable and the whole range be dropped.
      const wildLine = (s: string | undefined) => {
        const m = s?.match(/^(\d+(?:\.\d+)*)\.?\*$/);
        if (!m) return undefined;
        const parts = m[1].split('.');
        parts[parts.length - 1] = String(Number(parts[parts.length - 1]) + 1);
        return parts.join('.');
      };
      const wildLessThan = wildLine(lessThanRaw);
      const wildLessThanOrEqual = wildLine(lessThanOrEqualRaw);
      const lessThan = wildLessThan ?? wildLessThanOrEqual ?? lessThanRaw;
      const lessThanOrEqual = wildLessThanOrEqual !== undefined ? undefined : lessThanOrEqualRaw;
      const upperRaw = lessThan ?? lessThanOrEqual;

      if (isNetScalerBuildRange(vendor, versionType, upperRaw !== undefined)) {
        bump(dropped, 'netscalerBuildBound');
        continue;
      }

      if (lessThan !== undefined && lessThan.includes(',') && /^juniper/i.test(vendor)) {
        const startOk = isPlaceholderVersion(lower) || (isUsableVersion(lower) && isEncodableBound(lower));
        const ranges = startOk ? junosFixListRanges(isPlaceholderVersion(lower) ? undefined : lower, lessThan) : null;
        if (ranges && ranges.every(r => isEncodableBound(r.end) && (r.start === undefined || isEncodableBound(r.start)))) {
          for (const r of ranges) {
            rows.push({ vendor, product, packageName, versionType, versionStart: r.start, versionEnd: r.end });
          }
          continue;
        }
      }

      if (lessThanRaw === '*' && lower !== undefined && !isPlaceholderVersion(lower)
          && isUsableVersion(lower) && isEncodableBound(lower)) {
        const cap = nextBranchStart(lower, versionsByProduct.get(productKey(raw)) ?? versions);
        rows.push({
          vendor,
          product,
          packageName,
          versionType,
          versionStart: lower,
          versionEnd: cap !== undefined && isEncodableBound(cap) ? cap : undefined,
        });
        continue;
      }

      if (upperRaw !== undefined) {
        if (!isUsableVersion(upperRaw)) {
          bump(dropped, 'unusableVersionString');
          continue;
        }
        if (!isEncodableBound(upperRaw)) {
          bump(dropped, 'unencodableRangeBound');
          continue;
        }
        // "version": "0" with a lessThan bound is the dominant idiom (91.9% of
        // real entries carry lessThan) and means "everything below the bound".
        // Keep the row with no lower bound rather than discarding it, but a
        // lower bound that is present and unusable -- free text like "Prior to
        // 1.2.3" -- makes the whole row untrustworthy.
        let versionStart: string | undefined;
        if (!isPlaceholderVersion(lower)) {
          if (!isUsableVersion(lower)) {
            bump(dropped, 'unusableVersionString');
            continue;
          }
          if (!isEncodableBound(lower)) {
            bump(dropped, 'unencodableRangeBound');
            continue;
          }
          versionStart = lower;
        }

        rows.push({
          vendor,
          product,
          packageName,
          versionType,
          versionStart,
          versionEnd: lessThan !== undefined ? upperRaw : undefined,
          lastAffected: lessThan === undefined ? upperRaw : undefined,
        });
        continue;
      }

      // No range operator: a single declared version. Stored for equality
      // matching only -- widening it into a range would claim every version
      // below it is affected too.
      if (!isUsableVersion(lower)) {
        bump(dropped, 'exactVersionUnusable');
        continue;
      }
      rows.push({ vendor, product, packageName, versionType, affectedVersions: [lower] });
    }
  }

  return { rows, dropped };
}

export interface ParsedCveRecord {
  cveId: string;
  cnaShortName: string;
  datePublished: Date | null;
  dateUpdated: Date | null;
  affected: unknown;
  rows: CnaAffectedRow[];
  dropped: Partial<Record<DropReason, number>>;
}

function toDate(v: unknown): Date | null {
  const s = asString(v);
  if (!s) return null;
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? null : d;
}

/**
 * The CVE id a record identifies, independent of whether it has any usable
 * affected data. parseCveRecord() returns null both for "no id at all" and
 * "id present but nothing worth storing" -- the importer needs to tell those
 * apart, since the second case can mean a CVE that used to have usable rows
 * (from an earlier, looser import, or a CNA correction) no longer does, and
 * whatever was previously stored for it needs to be removed rather than left
 * stale.
 */
export function cveIdOf(record: CveRecord): string | null {
  return asString(record?.cveMetadata?.cveId) ?? null;
}

/** Parse one CVE Record. Returns null when there is nothing worth storing. */
export function parseCveRecord(record: CveRecord): ParsedCveRecord | null {
  const cveId = cveIdOf(record);
  if (!cveId) return null;
  // REJECTED records describe a CVE ID that was withdrawn; its affected list
  // (if any) no longer describes a real vulnerability.
  if (record.cveMetadata?.state === 'REJECTED') return null;

  const cna = record.containers?.cna;
  const { rows, dropped } = extractCnaRows(cna?.affected);
  if (rows.length === 0) return null;

  return {
    cveId,
    cnaShortName: asString(cna?.providerMetadata?.shortName) ?? 'unknown',
    datePublished: toDate(record.cveMetadata?.datePublished),
    dateUpdated: toDate(record.cveMetadata?.dateUpdated),
    affected: cna?.affected,
    rows,
    dropped,
  };
}

// ─── CISA Vulnrichment (SSVC) ──────────────────────────────────

interface AdpEntry {
  metrics?: unknown;
  providerMetadata?: { shortName?: unknown };
}

interface SsvcMetricEntry {
  other?: { type?: unknown; content?: unknown };
}

interface SsvcContent {
  options?: unknown;
  timestamp?: unknown;
}

export interface SsvcAssessment {
  exploitation: string;
  automatable: string;
  technicalImpact: string;
  timestamp: Date | null;
}

const SSVC_EXPLOITATION = new Set(['none', 'poc', 'active']);
const SSVC_AUTOMATABLE = new Set(['yes', 'no']);
const SSVC_TECHNICAL_IMPACT = new Set(['partial', 'total']);

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null;
}

/**
 * CISA's SSVC assessment (Exploitation / Automatable / Technical Impact) from
 * a CVE Record's `containers.adp`, or undefined when this record has none.
 *
 * Every field checked here is required: CISA always publishes exactly these
 * three decision points together (confirmed live, e.g. CVE-2024-3400), never
 * a subset, so a partial match means the shape changed and the whole
 * assessment should be treated as absent rather than guessed at. Deliberately
 * does NOT attempt to derive a final decision (Track, Track-star, Attend, or
 * Act) -- that needs a fourth axis (Mission & Well-being impact) that is
 * stakeholder-specific and CISA does not publish per CVE. Turning these three
 * raw axes into a priority is left to the consumer (heretix-management).
 */
export function parseSsvc(record: CveRecord): SsvcAssessment | undefined {
  const adp = record.containers?.adp;
  if (!Array.isArray(adp)) return undefined;

  const cisaAdp = adp.find(
    (c): c is AdpEntry => isObject(c) && asString((c as AdpEntry).providerMetadata?.shortName) === 'CISA-ADP',
  );
  if (!cisaAdp || !Array.isArray(cisaAdp.metrics)) return undefined;

  const ssvcMetric = (cisaAdp.metrics as unknown[]).find(
    (m): m is SsvcMetricEntry => isObject(m) && isObject((m as SsvcMetricEntry).other) && (m as SsvcMetricEntry).other?.type === 'ssvc',
  );
  const content = ssvcMetric?.other?.content;
  if (!isObject(content) || !Array.isArray((content as SsvcContent).options)) return undefined;

  let exploitation: string | undefined;
  let automatable: string | undefined;
  let technicalImpact: string | undefined;
  for (const opt of (content as SsvcContent).options as unknown[]) {
    if (!isObject(opt)) continue;
    if ('Exploitation' in opt) exploitation = asString(opt.Exploitation)?.toLowerCase();
    if ('Automatable' in opt) automatable = asString(opt.Automatable)?.toLowerCase();
    if ('Technical Impact' in opt) technicalImpact = asString(opt['Technical Impact'])?.toLowerCase();
  }

  if (!exploitation || !SSVC_EXPLOITATION.has(exploitation)) return undefined;
  if (!automatable || !SSVC_AUTOMATABLE.has(automatable)) return undefined;
  if (!technicalImpact || !SSVC_TECHNICAL_IMPACT.has(technicalImpact)) return undefined;

  return { exploitation, automatable, technicalImpact, timestamp: toDate((content as SsvcContent).timestamp) };
}

// ─── Bundle download ─────────────────────────────────────────

export async function listReleases(perPage = 100): Promise<GitHubRelease[]> {
  const { data } = await axios.get<GitHubRelease[]>(RELEASES_URL, {
    params: { per_page: perPage },
    timeout: 30000,
    headers: { 'User-Agent': 'heretix-api/1.0', Accept: 'application/vnd.github+json' },
  });
  return data;
}

export async function downloadZip(url: string, timeoutMs: number): Promise<AdmZip> {
  const { data } = await axios.get<ArrayBuffer>(url, {
    timeout: timeoutMs,
    responseType: 'arraybuffer',
    maxContentLength: Infinity,
    maxBodyLength: Infinity,
    headers: { 'User-Agent': 'heretix-api/1.0' },
  });
  return new AdmZip(Buffer.from(data));
}

/**
 * Records inside a bundle, restricted to the CVE ID years in `years` when given.
 *
 * Three things about the bundle layouts this has to absorb:
 *  - The full snapshot is a zip wrapping a single inner cves.zip (hence its
 *    "....zip.zip" asset name), so a nested archive is unwrapped rather than
 *    skipped. Deltas are a single flat archive.
 *  - The paths inside differ too: "cves/2026/59xxx/CVE-2026-59346.json" in the
 *    full snapshot against "deltaCves/CVE-2026-59346.json" in a delta. The year
 *    therefore comes from the CVE ID in the filename, not from the path --
 *    cvelistV5 buckets records by that same id year anyway.
 *  - Bundles also ship delta.json / deltaLog.json manifests, which the CVE-id
 *    filename check skips.
 */
export function* recordsFromZip(zip: AdmZip, years: Set<string> | null): Generator<CveRecord> {
  for (const entry of zip.getEntries()) {
    if (entry.isDirectory) continue;

    if (entry.entryName.endsWith('.zip')) {
      yield* recordsFromZip(new AdmZip(entry.getData()), years);
      continue;
    }

    const match = entry.entryName.match(/(?:^|\/)CVE-(\d{4})-\d+\.json$/);
    if (!match) continue;
    if (years && !years.has(match[1])) continue;
    try {
      yield JSON.parse(entry.getData().toString('utf8')) as CveRecord;
    } catch {
      // A single malformed record must not abort the whole bundle.
      logger.warn({ entry: entry.entryName }, 'Skipping unparseable CVE record');
      continue;
    }
  }
}

/** The full-snapshot asset from the most recent release that carries one. */
export function findFullBundle(releases: GitHubRelease[]): GitHubRelease['assets'][number] | undefined {
  return releases.flatMap(r => r.assets).find(a => /_all_CVEs_at_midnight\.zip(\.zip)?$/.test(a.name));
}

/** Delta assets published after `since`, oldest first. */
export function findDeltaBundles(releases: GitHubRelease[], since: Date): GitHubRelease['assets'][number][] {
  return releases
    .filter(r => new Date(r.published_at) > since)
    .sort((a, b) => new Date(a.published_at).getTime() - new Date(b.published_at).getTime())
    .map(r => r.assets.find(a => /_delta_CVEs_at_.*\.zip$/.test(a.name)))
    .filter((a): a is GitHubRelease['assets'][number] => a !== undefined);
}
