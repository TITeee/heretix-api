/**
 * Node.js (RHEL/Oracle Linux module-stream) vulnerability search accuracy validation script
 *
 * Ground truth = the Node.js Security Working Group's own vulnerability index
 * (nodejs/security-wg), NOT RedHatFetcher/OracleLinuxFetcher's parsed OVAL data.
 * That distinction matters here: RHEL/Oracle Linux ship nodejs as parallel DNF
 * module streams (nodejs:18/:20/:22/... coexisting on one OS), but their OVAL
 * feeds only ever express an exclusive upper bound ("nodejs is earlier than
 * X") with no lower bound. A "ground truth" built from that same feed
 * (as validate-redhat.ts's indexByProduct/expectedCVEsRpm does) shares the
 * exact same missing-lower-bound blind spot as production, so it can never
 * catch a fix from one stream silently matching a query against an older,
 * unrelated stream. Using nodejs/security-wg's independent, per-major-line
 * `vulnerable`/`patched` semver ranges as ground truth (same approach
 * validate-postgresql.ts takes with postgresql.org) is what actually
 * surfaces that class of bug.
 *
 * `vulnerable`/`patched` interpretation follows the same convention as the
 * `is-my-node-vulnerable` npm package: a version is affected if its major
 * appears in `vulnerable` (as an "N.x" clause) AND it is below that major's
 * corresponding `patched` version (a "^N.M.P" clause) -- or there is no
 * patched clause for that major at all (never fixed on that line).
 *
 * Scoped to the module-stream majors RHEL 8/9 and Oracle Linux 8/9/10 actually
 * package (10/12/14/16/18/20/22/24); older majors are irrelevant to this
 * search path and would only add noise.
 *
 * AdvisoryAffectedProduct.vendor is keyed per OS major version ("red-hat-8",
 * "oracle-linux-9", ...), not one shared bucket across majors -- queryLocalAPI
 * queries every OS major's ecosystem string and unions the results (see
 * VENDORS below), since ground truth here has no concept of which OS major a
 * given nodejs module stream shipped on.
 *
 * Version comparisons use compareRpmVersions (rpmvercmp), matching
 * matchesRpmVersionRange() (search-helpers.ts), the actual comparison the
 * search endpoint performs for RPM-vendor ecosystems.
 *
 * Usage:
 *   pnpm validate:nodejs                        # sweep mode, vendor=red-hat
 *   pnpm validate:nodejs --vendor=oracle-linux   # sweep mode, vendor=oracle-linux
 *   pnpm validate:nodejs 20.11.1                 # single version check (red-hat)
 */
import 'dotenv/config';
import axios from 'axios';
import { compareRpmVersions } from '../utils/rpm-version.js';
import {
  bumpRpmVersion, aggregateSweep, printSweepReport, filterBySource, diffSets,
  mapWithConcurrency, queryAllPages,
} from './lib/accuracy-sweep.js';

const PAGE_SIZE = 500; // API-enforced max (see zod schema in vulnerabilities.ts)
const CONCURRENCY = 20; // matches the API's own pg pool size (see src/db/client.ts)
const PRODUCT = 'nodejs';
const SECURITY_WG_INDEX_URL = 'https://raw.githubusercontent.com/nodejs/security-wg/main/vuln/core/index.json';

// Module-stream majors RHEL 8/9 and Oracle Linux 8/9 actually package.
const ACTIVE_MAJORS = new Set([10, 12, 14, 16, 18, 20, 22, 24]);

interface VendorConfig {
  label: string;
  ecosystems: string[];
  targetSource: string;
}

// AdvisoryAffectedProduct.vendor is now keyed per OS major version
// ("red-hat-8"/"red-hat-9", "oracle-linux-8"/"oracle-linux-9"/"oracle-linux-10")
// rather than one shared bucket across majors (see rpmAdvisoryVendor() /
// search-helpers.ts) -- querying a single ecosystem string only ever sees
// that one major's rows, so a nodejs module stream packaged solely on
// another major (e.g. nodejs:10/:12/:14 on RHEL 8 only) would never be
// found against "Red Hat:9" alone. Query every major this data actually
// exists under and union the results, matching how a real caller running
// either OS major would see it. The legacy bare "oracle-linux" ecosystem
// string (pre-2026-09-01) now resolves to a vendor bucket with zero rows --
// see rpmAdvisoryVendor()'s comment -- so it must not be used here.
const VENDORS: Record<string, VendorConfig> = {
  'red-hat': { label: 'RHEL 8+9', ecosystems: ['Red Hat:8', 'Red Hat:9'], targetSource: 'red-hat' },
  'oracle-linux': { label: 'Oracle Linux 8+9+10', ecosystems: ['Oracle Linux:8', 'Oracle Linux:9', 'Oracle Linux:10'], targetSource: 'oracle-linux' },
};

// ─── Type Definitions ────────────────────────────────────────────────────────

interface RawSecurityWgEntry {
  cve?: string[];
  vulnerable?: string;
  patched?: string;
}

interface NodejsFixEntry {
  cveId: string;
  major: number;
  patchedVersion: string | null; // null = vulnerable on this major, never patched (per this snapshot)
}

interface ApiVulnerability {
  externalId: string;
  sources: string[];
}

interface BoundaryPoint {
  version: string;
  reasons: string[];
}

// ─── Ground Truth Fetch & Parse ───────────────────────────────────────────────

async function fetchNodejsSecurityIndex(): Promise<Record<string, RawSecurityWgEntry>> {
  const res = await axios.get<Record<string, RawSecurityWgEntry>>(SECURITY_WG_INDEX_URL, {
    timeout: 30000,
    headers: { 'User-Agent': 'heretix-api/1.0 accuracy-validator' },
  });
  return res.data;
}

/** Extract active-major numbers from a "20.x || 18.x" style OR-clause list. */
function parseMajorsFromVulnerable(vulnerable: string): number[] {
  const majors: number[] = [];
  for (const clause of vulnerable.split('||')) {
    const m = clause.trim().match(/^(\d+)\.x$/);
    if (m) majors.push(parseInt(m[1], 10));
  }
  return majors;
}

/** Extract per-major patched versions from a "^20.11.1 || ^18.20.1" style OR-clause list. */
function parsePatchedByMajor(patched: string): Map<number, string> {
  const map = new Map<number, string>();
  for (const clause of patched.split('||')) {
    const m = clause.trim().match(/^\^(\d+)\.(\d+)\.(\d+)/);
    if (m) map.set(parseInt(m[1], 10), `${m[1]}.${m[2]}.${m[3]}`);
  }
  return map;
}

/**
 * Flatten the security-wg index into one (cveId, major, patchedVersion) entry
 * per active major a CVE applies to. Entries with no CVE ID (advisory
 * predates CVE assignment) can't be matched against the API's externalId, so
 * they're dropped -- same reasoning as validate-postgresql.ts's osvOnlyIds
 * exclusion.
 */
function parseNodejsAdvisories(json: Record<string, RawSecurityWgEntry>): NodejsFixEntry[] {
  const entries: NodejsFixEntry[] = [];
  let skippedNoCve = 0;
  let skippedNoVulnerable = 0;

  for (const raw of Object.values(json)) {
    if (!raw.cve || raw.cve.length === 0) { skippedNoCve++; continue; }
    if (!raw.vulnerable) { skippedNoVulnerable++; continue; }

    const activeMajors = parseMajorsFromVulnerable(raw.vulnerable).filter(m => ACTIVE_MAJORS.has(m));
    if (activeMajors.length === 0) continue; // no overlap with RHEL/Oracle Linux packaged streams

    const patchedByMajor = raw.patched ? parsePatchedByMajor(raw.patched) : new Map<number, string>();
    for (const cveId of raw.cve) {
      for (const major of activeMajors) {
        entries.push({ cveId, major, patchedVersion: patchedByMajor.get(major) ?? null });
      }
    }
  }

  console.log(
    `Parsed ${entries.length} (CVE, major) fix entries for active majors [${[...ACTIVE_MAJORS].join(', ')}] ` +
    `(skipped ${skippedNoCve} entries with no CVE ID, ${skippedNoVulnerable} with no "vulnerable" field)`,
  );
  return entries;
}

/** CVEs whose (major, patchedVersion) entry places `version` before the patch, on the matching major line. */
function expectedCVEsNodejs(version: string, entries: NodejsFixEntry[]): Set<string> {
  const result = new Set<string>();
  const major = parseInt(version.split('.')[0], 10);
  if (isNaN(major)) return result;

  for (const e of entries) {
    if (e.major !== major) continue;
    if (e.patchedVersion === null || compareRpmVersions(version, e.patchedVersion) < 0) {
      result.add(e.cveId.toUpperCase());
    }
  }
  return result;
}

// ─── Local API Query ──────────────────────────────────────────────────────────

async function queryLocalAPI(baseUrl: string, version: string, vendor: VendorConfig): Promise<ApiVulnerability[]> {
  const headers: Record<string, string> = {};
  if (process.env.API_KEY) headers['x-api-key'] = process.env.API_KEY;

  const perEcosystem = await Promise.all(vendor.ecosystems.map(ecosystem =>
    queryAllPages(async (offset) => {
      const url = `${baseUrl}/api/v1/vulnerabilities/search?package=${encodeURIComponent(PRODUCT)}&version=${encodeURIComponent(version)}&ecosystem=${encodeURIComponent(ecosystem)}&limit=${PAGE_SIZE}&offset=${offset}`;
      try {
        const res = await axios.get<{ results: ApiVulnerability[] }>(url, { timeout: 30000, headers });
        return res.data.results ?? [];
      } catch (err: unknown) {
        if (axios.isAxiosError(err) && err.code === 'ECONNREFUSED') {
          console.error(`ERROR: Could not reach local API at ${baseUrl}`);
          console.error('       Is the server running? (pnpm dev)');
          process.exit(1);
        }
        throw err;
      }
    }, PAGE_SIZE),
  ));

  return perEcosystem.flat();
}

// ─── Boundary-Value Sweep ──────────────────────────────────────────────────────

/**
 * Derive boundary versions from every fix entry (patched version, and one RPM
 * release step before it), plus each active major's stream-start version
 * (`{major}.0.0`). That last point is what actually probes the bug this
 * script exists to catch: if some other, higher major's patched version is
 * numerically above `{major}.0.0`, a versionStart-less production row for
 * that other major would incorrectly match here, while ground truth (which
 * knows about the major-line boundary) correctly expects nothing.
 */
function collectBoundaryPoints(entries: NodejsFixEntry[]): Map<string, BoundaryPoint> {
  const points = new Map<string, BoundaryPoint>();
  const add = (version: string, reason: string) => {
    const existing = points.get(version);
    if (existing) { existing.reasons.push(reason); return; }
    points.set(version, { version, reasons: [reason] });
  };

  const seenMajors = new Set<number>();
  for (const e of entries) {
    if (e.patchedVersion) {
      add(e.patchedVersion, `${e.cveId}: fixed exact for ${e.major}.x (expect NOT affected)`);
      const before = bumpRpmVersion(e.patchedVersion, -1);
      if (before) add(before, `${e.cveId}: fixed-1 release for ${e.major}.x (expect affected)`);
    }
    if (!seenMajors.has(e.major)) {
      seenMajors.add(e.major);
      add(`${e.major}.0.0`, `${e.major}.x stream start (cross-stream false-positive probe)`);
    }
  }

  return points;
}

async function runSweep(baseUrl: string, entries: NodejsFixEntry[], vendor: VendorConfig): Promise<void> {
  const points = [...collectBoundaryPoints(entries).values()];
  console.log(`Sweeping ${points.length} nodejs version boundary points against ${vendor.label} (concurrency=${CONCURRENCY})...`);

  let done = 0;
  const sweepEntries = await mapWithConcurrency(points, CONCURRENCY, async ({ version, reasons }) => {
    const expected = expectedCVEsNodejs(version, entries);
    const allResults = await queryLocalAPI(baseUrl, version, vendor);
    const actual = filterBySource(allResults, vendor.targetSource);
    const { tp, fp, fn } = diffSets(expected, actual);

    done++;
    if (done % 200 === 0) console.log(`  ...${done}/${points.length}`);

    return {
      version: `nodejs@${version}`,
      reasons,
      tp: tp.length,
      fp: fp.length,
      fn: fn.length,
      fpDetail: fp,
      fnDetail: fn,
    };
  });

  printSweepReport(
    `Node.js (${vendor.label})`,
    sweepEntries,
    aggregateSweep(sweepEntries),
    "derived from nodejs/security-wg patched versions ±1 RPM release step, plus each module stream's X.0.0 start (cross-stream FP probe)",
  );
}

// ─── Entry Point ──────────────────────────────────────────────────────────────

function parseArgs(): { version: string | null; vendor: VendorConfig } {
  const args = process.argv.slice(2);
  let vendorKey = 'red-hat';
  let version: string | null = null;

  for (const arg of args) {
    if (arg.startsWith('--vendor=')) {
      vendorKey = arg.slice('--vendor='.length);
    } else {
      version = arg;
    }
  }

  const vendor = VENDORS[vendorKey];
  if (!vendor) {
    console.error(`Unknown vendor "${vendorKey}". Supported: ${Object.keys(VENDORS).join(', ')}`);
    process.exit(1);
  }

  return { version, vendor };
}

async function main() {
  const { version, vendor } = parseArgs();
  const baseUrl = process.env.API_BASE_URL ?? 'http://localhost:5000';

  console.log('Fetching nodejs/security-wg vulnerability index...');
  const json = await fetchNodejsSecurityIndex();
  const entries = parseNodejsAdvisories(json);

  if (version === null) {
    await runSweep(baseUrl, entries, vendor);
    return;
  }

  const expected = expectedCVEsNodejs(version, entries);
  console.log(`Ground truth for nodejs ${version}: ${expected.size} CVEs should match`);

  const allResults = await queryLocalAPI(baseUrl, version, vendor);
  const actual = filterBySource(allResults, vendor.targetSource);
  const { tp, fp, fn } = diffSets(expected, actual);

  const pct = (n: number) => `${(n * 100).toFixed(2)}%`;
  const precision = tp.length + fp.length > 0 ? tp.length / (tp.length + fp.length) : 1;
  const recall = tp.length + fn.length > 0 ? tp.length / (tp.length + fn.length) : 1;

  console.log('');
  console.log(`True Positives: ${tp.length}, False Positives: ${fp.length}, False Negatives: ${fn.length}`);
  console.log(`Precision: ${pct(precision)}  Recall: ${pct(recall)}`);
  if (fp.length > 0) console.log('False positives:', fp.join(', '));
  if (fn.length > 0) console.log('False negatives:', fn.join(', '));
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
