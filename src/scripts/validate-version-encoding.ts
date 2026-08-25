/**
 * Version-encoding self-consistency check
 *
 * normalizeVersion() (src/utils/version.ts) packs major/minor/patch/release
 * into one BigInt ("major*1e9 + minor*1e6 + patch*1e3 + release") so range
 * queries can run in SQL. AdvisoryAffectedProduct / OSVAffectedPackage /
 * NVDAffectedPackage each store a lower and upper bound encoded this way.
 *
 * This script does NOT need to know any ecosystem's real version semantics
 * (SemVer, PEP 440, Maven, dpkg, ...) to find bugs in that encoding -- three
 * things are wrong no matter what a "correct" comparator would say:
 *
 *  1. Collapsed/inverted ranges: lowerInt >= upperInt (exclusive) or
 *     lowerInt > upperInt (inclusive) means no version can ever satisfy the
 *     range -- a silent false negative. The exact shape of bug already fixed
 *     once for RHEL/Oracle Linux module streams (versionStart > versionEnd,
 *     see README.md's Known Issues) turns out not to be unique to that case.
 *  2. Encoding contract violations: the release slot's place value is 1000,
 *     but normalizeVersion()'s own upper-bound check only rejects
 *     release > 999999 -- a release in [1000, 999999] silently overflows
 *     into the patch digit instead of being rejected, producing a
 *     *non-monotonic* result (an older version can normalize higher than a
 *     newer one), not just a lossy one.
 *  3. Same-package collisions: two distinct raw version strings for the same
 *     package normalizing to the identical int. This is direct proof the
 *     encoding lost information needed to tell them apart, regardless of
 *     which one "should" sort higher -- no ecosystem knowledge required.
 *
 * This is a detection-only report: it does not modify any data or change
 * normalizeVersion()'s behavior. Counts here are a lower bound on affected
 * rows, not a total -- a range like "1.0.0 <= v < 1.0.5" that's internally
 * consistent but still ecosystem-semantically wrong (e.g. a PEP 440-specific
 * ordering) isn't something this script can catch.
 *
 * Usage:
 *   pnpm validate:version-encoding
 */
import 'dotenv/config';
import { prisma } from '../db/client.js';

// ─── Shared: mirrors normalizeVersion()'s release extraction ───────────────
// (src/utils/version.ts) without its silent 1000+ overflow, so it can be used
// to *detect* the contract violation without duplicating the bug.

function hasPrereleaseMarker(withoutEpoch: string): boolean {
  return /\d-[a-zA-Z]/.test(withoutEpoch);
}

/** Returns the parsed release component, or null if this version has no hyphen-integer release. */
function extractReleaseComponent(raw: string): number | null {
  const withoutEpoch = raw.replace(/^\d+:/, '');
  if (hasPrereleaseMarker(withoutEpoch)) return null;
  const parts = withoutEpoch.split('-');
  const m = parts[1]?.match(/^(\d+)/);
  return m ? parseInt(m[1], 10) : null;
}

const RELEASE_OVERFLOW_THRESHOLD = 1000; // normalizeVersion()'s release*1 place value

function findReleaseOverflows(values: string[]): { raw: string; release: number }[] {
  const seen = new Map<string, number>();
  for (const v of values) {
    const release = extractReleaseComponent(v);
    if (release !== null && release >= RELEASE_OVERFLOW_THRESHOLD && !seen.has(v)) {
      seen.set(v, release);
    }
  }
  return [...seen].map(([raw, release]) => ({ raw, release }));
}

// ─── Report plumbing ────────────────────────────────────────────────────────

function section(title: string): void {
  console.log('\n' + '='.repeat(70));
  console.log(title);
  console.log('='.repeat(70));
}

function printGroupCounts(rows: { group: string; n: bigint }[], total: number): void {
  for (const r of rows) {
    console.log(`  ${r.group.padEnd(20)} ${String(Number(r.n)).padStart(8)}`);
  }
  console.log(`  ${'TOTAL'.padEnd(20)} ${String(total).padStart(8)}`);
}

// ─── 1. Collapsed / inverted ranges ─────────────────────────────────────────

async function checkCollapsedRanges() {
  section('1. COLLAPSED / INVERTED RANGES (lowerInt >= upperInt -- matches nothing)');

  const osv = await prisma.$queryRaw<{ group: string; n: bigint }[]>`
    SELECT ecosystem AS group, COUNT(*) AS n FROM "OSVAffectedPackage"
    WHERE "introducedInt" IS NOT NULL AND (
      ("fixedInt" IS NOT NULL AND "introducedInt" >= "fixedInt") OR
      ("fixedInt" IS NULL AND "lastAffectedInt" IS NOT NULL AND "introducedInt" > "lastAffectedInt")
    )
    GROUP BY ecosystem ORDER BY n DESC
  `;
  const osvTotal = osv.reduce((s, r) => s + Number(r.n), 0);
  console.log('\nOSVAffectedPackage, by ecosystem:');
  printGroupCounts(osv, osvTotal);

  const nvd = await prisma.$queryRaw<{ group: string; n: bigint }[]>`
    SELECT COALESCE(ecosystem, '(none)') AS group, COUNT(*) AS n FROM "NVDAffectedPackage"
    WHERE "introducedInt" IS NOT NULL AND (
      ("fixedInt" IS NOT NULL AND "introducedInt" >= "fixedInt") OR
      ("fixedInt" IS NULL AND "lastAffectedInt" IS NOT NULL AND "introducedInt" > "lastAffectedInt")
    )
    GROUP BY ecosystem ORDER BY n DESC
  `;
  const nvdTotal = nvd.reduce((s, r) => s + Number(r.n), 0);
  console.log('\nNVDAffectedPackage, by ecosystem:');
  printGroupCounts(nvd, nvdTotal);

  const adv = await prisma.$queryRaw<{ group: string; n: bigint }[]>`
    SELECT vendor AS group, COUNT(*) AS n FROM "AdvisoryAffectedProduct"
    WHERE "versionStartInt" IS NOT NULL AND (
      ("versionEndInt" IS NOT NULL AND "versionStartInt" >= "versionEndInt") OR
      ("versionEndInt" IS NULL AND "lastAffectedInt" IS NOT NULL AND "versionStartInt" > "lastAffectedInt")
    )
    GROUP BY vendor ORDER BY n DESC
  `;
  const advTotal = adv.reduce((s, r) => s + Number(r.n), 0);
  console.log('\nAdvisoryAffectedProduct, by vendor:');
  printGroupCounts(adv, advTotal);

  return { osvTotal, nvdTotal, advTotal };
}

// ─── 2. Release-slot overflow ────────────────────────────────────────────────

async function checkReleaseOverflow() {
  section(`2. RELEASE-SLOT OVERFLOW (release >= ${RELEASE_OVERFLOW_THRESHOLD} silently overflows into patch)`);

  const osvRows = await prisma.$queryRaw<{ v: string }[]>`
    SELECT DISTINCT v FROM (
      SELECT "introducedVersion" AS v FROM "OSVAffectedPackage" WHERE "introducedVersion" IS NOT NULL
      UNION ALL SELECT "fixedVersion" FROM "OSVAffectedPackage" WHERE "fixedVersion" IS NOT NULL
      UNION ALL SELECT "lastAffectedVersion" FROM "OSVAffectedPackage" WHERE "lastAffectedVersion" IS NOT NULL
    ) t
  `;
  const osvOverflows = findReleaseOverflows(osvRows.map(r => r.v));
  console.log(`\nOSVAffectedPackage: ${osvOverflows.length} distinct raw version string(s) with release >= ${RELEASE_OVERFLOW_THRESHOLD}`);
  if (osvOverflows.length) console.log('  samples:', osvOverflows.slice(0, 5).map(o => o.raw).join(', '));

  const advRows = await prisma.$queryRaw<{ v: string }[]>`
    SELECT DISTINCT v FROM (
      SELECT "versionStart" AS v FROM "AdvisoryAffectedProduct" WHERE "versionStart" IS NOT NULL
      UNION ALL SELECT "versionEnd" FROM "AdvisoryAffectedProduct" WHERE "versionEnd" IS NOT NULL
      UNION ALL SELECT "versionFixed" FROM "AdvisoryAffectedProduct" WHERE "versionFixed" IS NOT NULL
      UNION ALL SELECT "lastAffected" FROM "AdvisoryAffectedProduct" WHERE "lastAffected" IS NOT NULL
    ) t
  `;
  const advOverflows = findReleaseOverflows(advRows.map(r => r.v));
  console.log(`\nAdvisoryAffectedProduct: ${advOverflows.length} distinct raw version string(s) with release >= ${RELEASE_OVERFLOW_THRESHOLD}`);
  if (advOverflows.length) console.log('  samples:', advOverflows.slice(0, 5).map(o => o.raw).join(', '));

  // How many *rows* (not just distinct strings) does this actually reach through
  // the default, ecosystem-less search path? Non-module rows use the BigInt
  // columns directly (see searchAdvisory() in vulnerabilities.ts); RPM-module
  // rows are excluded there and go through compareRpmVersions() instead when
  // ecosystem= is given, so they're informational here, not part of the count.
  const [{ n: reachableAdv }] = await prisma.$queryRaw<{ n: bigint }[]>`
    SELECT COUNT(*) AS n FROM "AdvisoryAffectedProduct"
    WHERE "versionEnd" IS NOT NULL
      AND "versionEnd" NOT LIKE '%.module+%'
      AND "versionEnd" ~ '-[0-9]{4,}'
  `;
  console.log(`  of which, rows reachable via the default (no ecosystem=) search path: ${Number(reachableAdv)}`);

  return { osvOverflowCount: osvOverflows.length, advOverflowCount: advOverflows.length, reachableAdv: Number(reachableAdv) };
}

// ─── 3. Same-package collisions ─────────────────────────────────────────────

async function checkCollisions() {
  section('3. SAME-PACKAGE COLLISIONS (distinct raw versions -> identical int)');

  const osv = await prisma.$queryRaw<{ ecosystem: string; packageName: string; n: bigint }[]>`
    SELECT ecosystem, "packageName", COUNT(DISTINCT "introducedVersion") AS n
    FROM "OSVAffectedPackage"
    WHERE "introducedInt" IS NOT NULL
    GROUP BY ecosystem, "packageName", "introducedInt"
    HAVING COUNT(DISTINCT "introducedVersion") > 1
  `;
  console.log(`\nOSVAffectedPackage: ${osv.length} (ecosystem, package, int) group(s) with colliding introducedVersion strings`);
  for (const r of osv.slice(0, 5)) console.log(`  ${r.ecosystem}/${r.packageName}: ${Number(r.n)} distinct strings collapse together`);

  const adv = await prisma.$queryRaw<{ vendor: string; product: string; n: bigint }[]>`
    SELECT vendor, product, COUNT(DISTINCT "versionStart") AS n
    FROM "AdvisoryAffectedProduct"
    WHERE "versionStartInt" IS NOT NULL
    GROUP BY vendor, product, "versionStartInt"
    HAVING COUNT(DISTINCT "versionStart") > 1
  `;
  console.log(`\nAdvisoryAffectedProduct: ${adv.length} (vendor, product, int) group(s) with colliding versionStart strings`);
  for (const r of adv.slice(0, 5)) console.log(`  ${r.vendor}/${r.product}: ${Number(r.n)} distinct strings collapse together`);

  return { osvCollisionGroups: osv.length, advCollisionGroups: adv.length };
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main() {
  console.log('Scanning AdvisoryAffectedProduct / OSVAffectedPackage / NVDAffectedPackage for');
  console.log('version-encoding self-contradictions (see file header for what each check means)...');

  const collapsed = await checkCollapsedRanges();
  const overflow = await checkReleaseOverflow();
  const collisions = await checkCollisions();

  section('SUMMARY');
  console.log(`Collapsed/inverted ranges:  OSV=${collapsed.osvTotal}  NVD=${collapsed.nvdTotal}  Advisory=${collapsed.advTotal}`);
  console.log(`Release-slot overflows:     OSV=${overflow.osvOverflowCount} distinct strings  Advisory=${overflow.advOverflowCount} distinct strings (${overflow.reachableAdv} rows reachable via default search)`);
  console.log(`Same-package collisions:    OSV=${collisions.osvCollisionGroups} groups  Advisory=${collisions.advCollisionGroups} groups`);
  console.log('\nThis is a report only -- no data was modified. See ACCURACY.md / README.md for how to interpret and prioritize these.');

  await prisma.$disconnect();
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
