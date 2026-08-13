/**
 * Pure advisory-import decision logic extracted from the RHEL/Oracle Linux
 * OVAL fetchers for unit testability. No DB dependency.
 */

/**
 * Products confirmed (via live query, not just inspection) to still leak
 * cross-major false positives from "bare" rows -- rows whose OVAL
 * `<definition>` carries no "Module <name>:N is enabled" criterion at all,
 * so the fetchers' primary versionStart extraction (collectCriteria() in
 * redhat-fetcher.ts / oracle-linux-fetcher.ts) has nothing to read.
 *
 * - nodejs: RHSA-2022:6595 on RHEL9 ("nodejs and nodejs-nodemon security and
 *   bug fix update", versionEnd "16.16.0-1.el9_0") predates nodejs's move to
 *   DNF modules on that release. Confirmed: package=nodejs&version=10.4.1 on
 *   RHEL9 matched CVEs whose own description states they only affect
 *   Node.js 14.21.3/16.19.1/18.14.1/19.6.1 and later.
 * - postgresql: bare rows come from three distinct origins -- RHEL7 (predates
 *   DNF modularity entirely, e.g. "9.2.24-9.0.7.el7_9"), RHEL9/OL9's
 *   pre-modularization baseline (e.g. "13.23-5.el9_8", no module marker),
 *   and RHEL10/OL10 (postgresql isn't modularized there at all -- single
 *   distribution). Confirmed: package=postgresql&version=9.2.10 on
 *   oracle-linux matched CVE-2026-2004/2005/2006, fixed only in the
 *   unrelated "13.23-2.el9_7" (RHEL9) build.
 *
 * NOT generalized to the ~917 other (product, vendor) pairs found to mix
 * modular and bare rows (qemu-kvm, mysql, httpd, php, mariadb, golang,
 * podman, libvirt, ...), since for those it's unverified whether a bare row
 * is a genuine pre-modularization/pre-DNF remnant of the same major-version
 * lineage (safe to floor) or a legitimately continuous version history that
 * happens to span major-version bumps (where flooring would introduce new
 * false negatives) -- confirm with a live query like the two above before
 * adding a product here.
 */
const BARE_ROW_FALLBACK_PRODUCTS = new Set(['nodejs', 'postgresql']);

export function inferBareVersionStart(product: string, versionEnd: string): string | undefined {
  if (!BARE_ROW_FALLBACK_PRODUCTS.has(product)) return undefined;

  // PostgreSQL used two-component majors before version 10 (9.0 through
  // 9.6 -- each a distinct, incompatible major in PostgreSQL's own
  // versioning, unlike every later release which uses a single integer).
  // A single-component floor ("9.0") collapses all of them together, which
  // is wrong: confirmed CVE-2019-10130 is postgresql:9.6-specific (its own
  // RHSA is literally titled "postgresql:9.6 security update") yet a "9.0"
  // floor let it match a 9.2.10 query. This also covers module rows whose
  // "Module postgresql:9.6 is enabled" criterion the primary extraction
  // (extractModuleMajor() in both fetchers) can't parse, since its `\d+`
  // capture doesn't allow the dotted "9.6" stream label -- those rows fall
  // through to this same function.
  if (product === 'postgresql') {
    const pre10 = versionEnd.match(/^9\.(\d+)\./);
    if (pre10) return `9.${pre10[1]}`;
  }

  const major = versionEnd.match(/^(\d+)\./)?.[1];
  return major ? `${major}.0` : undefined;
}
