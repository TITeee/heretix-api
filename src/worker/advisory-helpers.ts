/**
 * Pure advisory-import decision logic extracted from the RHEL/Oracle Linux
 * OVAL fetchers for unit testability. No DB dependency.
 */
import { normalizeVersion } from '../utils/version.js';

/**
 * Converts a DNF module stream label (from extractModuleMajor() in either
 * fetcher) into a versionStart floor, unless the label turns out to be
 * numerically incompatible with the row's own versionEnd.
 *
 * Most products use a plain integer stream label (nodejs's "20",
 * postgresql's "16") which just needs ".0" appended; others use a dotted
 * major.minor label (mysql's "8.4", mariadb's "10.11") that's already a
 * complete floor as-is. Some legitimately use a full calendar-date-style
 * label (python-pytz's "2017", relaxngDatatype's "2011", perl-Text-Tabs+Wrap's
 * "2013") because the package's own version scheme genuinely IS date-based --
 * confirmed via live data that these always satisfy floor <= versionEnd, so
 * "looks like a date" alone isn't a safe signal to distrust a label.
 *
 * The actual exception found: RHEL8's javapackages-tools module bundles
 * several independently-versioned Java build tools (ant, xmvn, an older
 * maven line, ...) under one stream labeled by build generation ("201801"),
 * unrelated to any of the bundled packages' own versions (xmvn's real
 * version is "3.0.0..."). Using "201801.0" as a floor made those rows
 * permanently unmatchable (floor numerically far above the row's own
 * ceiling) -- confirmed to affect 510 product names, a ~230k false-negative
 * regression caught by re-running the RHEL/Oracle Linux boundary-value
 * sweep after this function shipped. Detected generically (not by module
 * name, since other modules could have the same shape) by checking floor <=
 * versionEnd: every legitimate label observed in real data, date-shaped or
 * not, satisfies this; only javapackages-tools's build-generation label
 * violates it. Returns undefined when it does, so the caller falls back to
 * inferBareVersionStart() exactly as if there had been no Module criterion
 * at all.
 */
export function moduleStreamVersionStart(moduleMajor: string, versionEnd: string): string | undefined {
  const candidate = moduleMajor.includes('.') ? moduleMajor : `${moduleMajor}.0`;
  const startInt = normalizeVersion(candidate);
  const endInt = normalizeVersion(versionEnd);
  if (startInt !== null && endInt !== null && startInt > endInt) return undefined;
  return candidate;
}

/**
 * mysql/mariadb/php RPM subpackages confirmed to ship from the same source
 * RPM as their base package -- i.e. they always carry the exact same
 * version-release string, so the base package's bare-row floor logic
 * applies to them unchanged. Verified per-package by inspecting real
 * versionEnd samples, not assumed from the name alone: excludes packages
 * confirmed to carry their own, unrelated version scheme bundled alongside
 * the parent (e.g. `mysql-selinux` versions its SELinux policy, not MySQL
 * itself, "1.0.14-1.el10_0"; `mariadb-connector-c*` versions the Connector/C
 * client library independently of the server, "3.4.4-2.el10_2"; PHP's
 * `php-pecl-*` extensions and `php-pear`/`php-libguestfs` each version
 * independently of PHP core). Also excludes the RHEL6/7-era Software
 * Collections naming scheme (`php54-php-cli`, `mysql55-mysql-server`,
 * `mariadb11.8-server`, ...), which bakes the version into the product name
 * itself -- those are already distinct `product` strings with no
 * cross-line collision risk in the first place, nothing to fix here.
 */
const MYSQL_FAMILY = new Set([
  'mysql', 'mysql-server', 'mysql-libs', 'mysql-common', 'mysql-errmsg',
  'mysql-devel', 'mysql-test', 'mysql-test-data', 'mysql-bench',
  'mysql-embedded', 'mysql-embedded-devel',
]);
const MARIADB_FAMILY = new Set([
  'mariadb', 'mariadb-server', 'mariadb-devel', 'mariadb-embedded',
  'mariadb-embedded-devel', 'mariadb-test', 'mariadb-common', 'mariadb-errmsg',
  'mariadb-libs', 'mariadb-backup', 'mariadb-bench', 'mariadb-client-utils',
  'mariadb-gssapi-server', 'mariadb-oqgraph-engine', 'mariadb-pam',
  'mariadb-server-galera', 'mariadb-server-utils',
]);
const PHP_FAMILY = new Set([
  'php', 'php-cli', 'php-common', 'php-fpm', 'php-mysqlnd', 'php-mysql',
  'php-bcmath', 'php-dba', 'php-dbg', 'php-devel', 'php-embedded',
  'php-enchant', 'php-ffi', 'php-gd', 'php-gmp', 'php-imap', 'php-intl',
  'php-json', 'php-ldap', 'php-mbstring', 'php-ncurses', 'php-odbc',
  'php-opcache', 'php-pdo', 'php-pgsql', 'php-process', 'php-pspell',
  'php-recode', 'php-snmp', 'php-soap', 'php-tidy', 'php-xml', 'php-xmlrpc',
  'php-zts',
]);

/**
 * Products confirmed (via live query, not just inspection) to still leak
 * cross-generation false positives from "bare" rows -- rows whose OVAL
 * `<definition>` carries no "Module <name>:<stream> is enabled" criterion at
 * all, so the fetchers' primary versionStart extraction (collectCriteria()
 * in redhat-fetcher.ts / oracle-linux-fetcher.ts) has nothing to read.
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
 * - httpd: Oracle Linux carries both the 2.2 line (RHEL5/6-era, e.g.
 *   "2.2.15-15.0.1.el6_2.1") and the 2.4 line (RHEL7+, e.g.
 *   "2.4.62-13.el9_8.1") with no Module criterion on either -- Apache never
 *   used a single-integer major here, "2.2" and "2.4" are the real,
 *   independently-maintained release lines (2.2 has been EOL upstream since
 *   2018). Confirmed: package=httpd&version=2.2.3&ecosystem=oracle-linux
 *   matched 154 CVEs, 104 of them (68%) fixed only in the unrelated 2.4.x
 *   line.
 * - mysql (MYSQL_FAMILY): RHEL5/6-era 5.0/5.1 lines (e.g. "5.1.66-2.el6_3")
 *   predate DNF modularity entirely -- unlike mysql's later 8.0/8.4 module
 *   streams (handled by extractModuleMajor() now that it reads dotted stream
 *   labels; see that function's doc comment), these have no Module criterion
 *   to have ever existed.
 * - mariadb (MARIADB_FAMILY): RHEL7-era 5.5 line (e.g. "5.5.68-1.0.1.el7")
 *   predates DNF modularity the same way, alongside mariadb's later
 *   10.3/10.5/10.11/11.8 module streams (also now handled by
 *   extractModuleMajor()).
 * - php (PHP_FAMILY): RHEL5/6-era 5.1/5.3 lines (e.g. "5.1.6-27.el5_7.4",
 *   "5.3.3-26.el6") predate DNF modularity, alongside RHEL10 bare rows for
 *   some subpackages even at the current 8.3.x line (e.g. php-fpm/php-mysqlnd
 *   "8.3.32-1.el10_2" -- php isn't modularized on RHEL10 either). Confirmed:
 *   package=php&version=5.1.6&ecosystem=oracle-linux matched 180 CVEs, 134
 *   of them (74%) fixed only in the unrelated 5.3.x line.
 *
 * NOT generalized to the other (product, vendor) pairs found to mix modular
 * and bare rows (qemu-kvm, golang, podman, libvirt, ...), since for those
 * it's unverified whether a bare row is a genuine pre-modularization remnant
 * of the same release-line lineage (safe to floor, and at what granularity)
 * or a legitimately continuous version history that happens to span
 * release-line bumps (where flooring would introduce new false negatives)
 * -- confirm with a live query like the ones above before adding a product
 * here.
 */
export const BARE_ROW_FALLBACK_PRODUCTS = new Set([
  'nodejs', 'postgresql', 'httpd', ...MYSQL_FAMILY, ...MARIADB_FAMILY, ...PHP_FAMILY,
]);

// Products whose real "major" is the first two dot-separated components, not
// the first alone -- see the doc comment above. postgresql only needs this
// for its pre-10 releases (10+ uses a single integer, handled by the generic
// branch below); httpd/mysql/mariadb/php need it unconditionally, since none
// of them has ever used a single-integer major across the versions
// RHEL/Oracle Linux track.
function twoComponentMajor(versionEnd: string, prefix?: string): string | undefined {
  const re = prefix ? new RegExp(`^${prefix}\\.(\\d+)\\.`) : /^(\d+\.\d+)\./;
  const m = versionEnd.match(re);
  if (!m) return undefined;
  return prefix ? `${prefix}.${m[1]}` : m[1];
}

/**
 * Extracts the OS major version (e.g. "9") from an RPM release string, using
 * the ".elN" marker every RHEL/Oracle Linux build carries in its release field
 * (Oracle Linux's own ksplice-tagged releases included, e.g.
 * "2.34-274.0.1.ksplice1.el9_8" -- the marker sits after "ksplice1", not
 * necessarily right after the version, so this scans for it anywhere rather
 * than anchoring right after the last "-").
 *
 * "el" isn't required to sit right after a ".": DNF module-stream builds
 * write it after a "+" instead, e.g. "8.0.0-10.0.1.module+el8.7.0+20875+...".
 * The lookbehind below accepts either (or start-of-string) by rejecting only
 * an alphanumeric character immediately before "el", so it doesn't also match
 * "el" as part of an unrelated word. The digits must not be followed by
 * another digit (so "el10" doesn't get read as "1"), but otherwise anything
 * can follow them -- not just "." or "_" or end-of-string. Oracle Linux's UEK
 * (Unbreakable Enterprise Kernel) packages append a bare "uek" suffix with no
 * separator at all, e.g. "5.15.0-323.211.3.3.el9uek".
 *
 * Both shapes were confirmed live to each be a large share of Oracle Linux's
 * OVAL data (UEK kernel-uek* packages over half of it, DNF module-stream
 * builds a large part of the rest) -- a stricter boundary or "." requirement
 * here left the vast majority of real rows unqualified, defeating the fix for
 * most of what it was meant to cover.
 *
 * Needed because OracleLinuxFetcher pulls one feed covering every OS release
 * at once (unlike RedHatFetcher, one feed request per release) -- there is no
 * single "which major version is this fetch for" to stamp on every row, so
 * each criterion's own release string is the only per-row signal available.
 * Every AdvisoryAffectedProduct row needs a version-qualified vendor
 * ("oracle-linux-9") for search-helpers.ts's per-release lookup to work at
 * all; a row this can't extract a version from falls back to the bare,
 * unqualified vendor in the caller, same as the pre-2026-09-01 behavior for
 * every row.
 */
export function extractOsMajorVersion(versionEnd: string): string | undefined {
  return versionEnd.match(/(?<![a-zA-Z0-9])el(\d+)(?!\d)/)?.[1];
}

export function inferBareVersionStart(product: string, versionEnd: string): string | undefined {
  if (!BARE_ROW_FALLBACK_PRODUCTS.has(product)) return undefined;

  if (product === 'httpd' || MYSQL_FAMILY.has(product) || MARIADB_FAMILY.has(product) || PHP_FAMILY.has(product)) {
    return twoComponentMajor(versionEnd);
  }

  // PostgreSQL used two-component majors before version 10 (9.0 through
  // 9.6 -- each a distinct, incompatible major in PostgreSQL's own
  // versioning, unlike every later release which uses a single integer).
  // A single-component floor ("9.0") collapses all of them together, which
  // is wrong: confirmed CVE-2019-10130 is postgresql:9.6-specific (its own
  // RHSA is literally titled "postgresql:9.6 security update") yet a "9.0"
  // floor let it match a 9.2.10 query.
  if (product === 'postgresql') {
    const pre10 = twoComponentMajor(versionEnd, '9');
    if (pre10) return pre10;
  }

  const major = versionEnd.match(/^(\d+)\./)?.[1];
  return major ? `${major}.0` : undefined;
}
