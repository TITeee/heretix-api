/**
 * Shared sweep logic for the OSV distro-ecosystem (Ubuntu/Debian/Alpine)
 * accuracy validators.
 *
 * Unlike the vendor OVAL/HTML sources (RHEL, Oracle Linux, Apache, ...),
 * OSV data arrives as already-structured JSON with no scrape/parse step of
 * our own — the imported `OSVAffectedPackage` rows (affectedVersions /
 * introducedVersion / fixedVersion / lastAffectedVersion) already ARE the
 * ground truth, so this reads the DB directly instead of re-fetching
 * anything live.
 *
 * These ecosystems have millions of rows (Ubuntu alone: ~1.9M), several
 * orders of magnitude past what an exhaustive sweep (as used for RHEL/Oracle
 * Linux) can cover — this is a bounded SAMPLE-based spot check instead: N
 * rows with an enumerated `affectedVersions` list (exercises the pre-existing
 * exact-match path) and N rows with only a continuous range and an empty list
 * (exercises the dpkg-range fallback added to fix the ~68% Debian search gap
 * — see search-helpers.ts's isDpkgStyleDistro).
 *
 * Each check is scoped to one specific vulnerability ID rather than a full
 * per-package expected-set comparison (as RHEL/Oracle Linux do) — at this
 * row count, indexing every CVE for every sampled package to build a
 * complete local expected-set is disproportionate to what a spot check needs.
 */
import 'dotenv/config';
import axios from 'axios';
import { prisma } from '../../db/client.js';
import { bumpRpmVersion as bumpTrailingDigit, mapWithConcurrency, aggregateSweep, printSweepReport, queryAllPages, type SweepEntry } from './accuracy-sweep.js';

const SAMPLE_SIZE = 500;
const CONCURRENCY = 20;
const PAGE_SIZE = 500;

interface Point {
  ecosystem: string;
  packageName: string;
  version: string;
  id: string;
  expectAffected: boolean;
  reason: string;
}

interface ApiVulnerability {
  externalId: string;
}

const MAX_PAGES = 20; // absolute ceiling (10,000 rows) for pathological packages like "linux"

/**
 * Checks whether `targetId` appears anywhere in the search results for
 * (product, version, ecosystem), stopping as soon as it's found rather than
 * paginating through everything — this is a membership check, not a full-set
 * comparison, and some Debian/Ubuntu packages (e.g. "linux") return many
 * thousands of results that would otherwise make every point pay for full
 * pagination regardless of where (or whether) the target actually appears.
 */
async function checkIdPresent(baseUrl: string, product: string, version: string, ecosystem: string, targetId: string): Promise<boolean> {
  const headers: Record<string, string> = {};
  if (process.env.API_KEY) headers['x-api-key'] = process.env.API_KEY;
  const target = targetId.toUpperCase();
  let pages = 0;

  const results = await queryAllPages(async (offset) => {
    if (++pages > MAX_PAGES) return []; // stop paginating; treat as exhausted
    const url = `${baseUrl}/api/v1/vulnerabilities/search?package=${encodeURIComponent(product)}&version=${encodeURIComponent(version)}&ecosystem=${encodeURIComponent(ecosystem)}&limit=${PAGE_SIZE}&offset=${offset}`;
    const res = await axios.get<{ results: ApiVulnerability[] }>(url, { timeout: 30000, headers });
    return res.data.results ?? [];
  }, PAGE_SIZE, (allSoFar) => allSoFar.some(r => r.externalId.toUpperCase() === target));

  return results.some(r => r.externalId.toUpperCase() === target);
}

async function sampleExactMatchPoints(ecosystemPrefix: string): Promise<Point[]> {
  const rows = await prisma.oSVAffectedPackage.findMany({
    where: { ecosystem: { startsWith: ecosystemPrefix }, NOT: { affectedVersions: { equals: [] } } },
    include: { vulnerability: { select: { osvId: true, cveId: true } } },
    take: SAMPLE_SIZE,
  });

  const points: Point[] = [];
  for (const row of rows) {
    const id = row.vulnerability.cveId ?? row.vulnerability.osvId;
    const version = row.affectedVersions[0];
    if (!id || !version) continue;
    points.push({
      ecosystem: row.ecosystem,
      packageName: row.packageName,
      version,
      id,
      expectAffected: true,
      reason: `${id}: enumerated affectedVersions entry (expect affected)`,
    });
  }
  return points;
}

async function sampleRangeOnlyPoints(ecosystemPrefix: string): Promise<Point[]> {
  const rows = await prisma.oSVAffectedPackage.findMany({
    where: {
      ecosystem: { startsWith: ecosystemPrefix },
      affectedVersions: { equals: [] },
      OR: [
        { introducedVersion: { not: null } },
        { fixedVersion: { not: null } },
        { lastAffectedVersion: { not: null } },
      ],
    },
    include: { vulnerability: { select: { osvId: true, cveId: true } } },
    take: SAMPLE_SIZE,
  });

  const points: Point[] = [];
  for (const row of rows) {
    const id = row.vulnerability.cveId ?? row.vulnerability.osvId;
    if (!id) continue;
    const { ecosystem, packageName, fixedVersion, lastAffectedVersion } = row;

    if (fixedVersion) {
      points.push({ ecosystem, packageName, version: fixedVersion, id, expectAffected: false, reason: `${id}: fixed exact (expect NOT affected)` });
      const before = bumpTrailingDigit(fixedVersion, -1);
      if (before) points.push({ ecosystem, packageName, version: before, id, expectAffected: true, reason: `${id}: fixed-1 (expect affected)` });
    } else if (lastAffectedVersion) {
      points.push({ ecosystem, packageName, version: lastAffectedVersion, id, expectAffected: true, reason: `${id}: lastAffected exact (expect affected)` });
      const after = bumpTrailingDigit(lastAffectedVersion, 1);
      if (after) points.push({ ecosystem, packageName, version: after, id, expectAffected: false, reason: `${id}: lastAffected+1 (expect NOT affected)` });
    }
  }
  return points;
}

export async function runOsvDistroSweep(ecosystemPrefix: string, label: string): Promise<void> {
  const baseUrl = process.env.API_BASE_URL ?? 'http://localhost:5000';

  console.log(`Sampling ${label} rows from the DB (ground truth = our own imported OSV data, no live re-fetch)...`);
  const [exactPoints, rangePoints] = await Promise.all([
    sampleExactMatchPoints(ecosystemPrefix),
    sampleRangeOnlyPoints(ecosystemPrefix),
  ]);
  const points = [...exactPoints, ...rangePoints];
  console.log(`Sampled ${exactPoints.length} exact-match points and ${rangePoints.length} dpkg-range-fallback points (${points.length} total, concurrency=${CONCURRENCY})...`);

  let done = 0;
  let errors = 0;
  const entries: SweepEntry[] = await mapWithConcurrency(points, CONCURRENCY, async (pt) => {
    done++;
    if (done % 200 === 0) console.log(`  ...${done}/${points.length}`);

    let found: boolean;
    try {
      found = await checkIdPresent(baseUrl, pt.packageName, pt.version, pt.ecosystem, pt.id);
    } catch (err: unknown) {
      // One point's network hiccup shouldn't sink the whole sample — count and move on.
      errors++;
      const msg = axios.isAxiosError(err) ? (err.code ?? err.message) : String(err);
      return {
        version: `${pt.packageName}@${pt.version} (${pt.ecosystem})`,
        reasons: [pt.reason, `SKIPPED due to request error: ${msg}`],
        tp: 0, fp: 0, fn: 0, fpDetail: [], fnDetail: [],
      };
    }

    const tp = pt.expectAffected && found;
    const fn = pt.expectAffected && !found;
    const fp = !pt.expectAffected && found;

    return {
      version: `${pt.packageName}@${pt.version} (${pt.ecosystem})`,
      reasons: [pt.reason],
      tp: tp ? 1 : 0,
      fp: fp ? 1 : 0,
      fn: fn ? 1 : 0,
      fpDetail: fp ? [pt.id] : [],
      fnDetail: fn ? [pt.id] : [],
    };
  });

  if (errors > 0) console.log(`(${errors} point(s) skipped due to request errors)`);

  printSweepReport(
    label,
    entries,
    aggregateSweep(entries),
    `${SAMPLE_SIZE} exact-match + ${SAMPLE_SIZE} range-fallback rows sampled from the DB, not exhaustive`,
  );

  await prisma.$disconnect();
}
