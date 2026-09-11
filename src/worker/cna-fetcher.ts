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
  containers?: { cna?: { providerMetadata?: { shortName?: unknown }; affected?: unknown } };
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
  | 'unencodableRangeBound';

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
      const lessThan = asString(v.lessThan);
      const lessThanOrEqual = asString(v.lessThanOrEqual);
      const upperRaw = lessThan ?? lessThanOrEqual;

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
