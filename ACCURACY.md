# Accuracy Validation

[日本語版](ACCURACY.ja.md)

Scripts to measure Precision / Recall against official security advisories. This file grows as more products get boundary-value coverage — see [README.md](README.md) for everything else.

```bash
pnpm validate:tomcat 9.0.100      # vs tomcat.apache.org
pnpm validate:apache 2.4.62       # vs httpd.apache.org
pnpm validate:nginx 1.24.0        # vs nginx.org
pnpm validate:openssl 3.0.12      # vs openssl.org
pnpm validate:postgresql 16.4     # vs postgresql.org
```

## Boundary-value sweep (nginx / tomcat / apache)

For products with a dedicated `AdvisoryFetcher` (`advisory-nginx`, `advisory-tomcat`, `advisory-apache`), running the same commands **without a version argument** switches to sweep mode: it automatically derives every advisory's range edges (`introduced`, `lastAffected`/`fixed`, and one patch step past each) from the official page, queries the search endpoint at every one of those boundary versions, and aggregates Precision/Recall/F1 — this is what actually catches off-by-one bugs, since a single hand-picked version mostly doesn't.

Results are restricted to `sources` containing that product's own fetcher (e.g. `advisory-nginx`), not the raw multi-source endpoint — see [Known limitations](#known-limitations) below for why.

```bash
pnpm validate:nginx     # sweep mode (no version arg)
pnpm validate:tomcat
pnpm validate:apache
```

| Product | Boundary versions tested | TP | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|
| nginx | 91 | 1,873 | 100.00% | 100.00% | 100.00% |
| Apache Tomcat | 336 | 12,374 | 100.00% | 100.00% | 100.00% |
| Apache HTTP Server | 56 | 4,112 | 100.00% | 100.00% | 100.00% |

*Reproduced 2026-07-21. All 483 boundary cases passed with zero false positives/negatives against each fetcher's own data.*

## Boundary-value sweep (Fortinet / Palo Alto Networks)

Fortinet and PAN advisories mix two range representations per affected-product entry: an exact version list, or a range (`versionStart`/`versionEnd`/`versionFixed`/`lastAffected`). Both fetchers can set an inclusive `lastAffected` **and** a supplementary `versionFixed` on the same entry — `importAdvisoryData()` resolves this by preferring `versionEnd ?? versionFixed` (exclusive) and only falling back to `lastAffected` (inclusive) when neither is present. Ground truth (`indexGenericByProduct`/`expectedIdsGeneric` in `src/scripts/lib/accuracy-sweep.ts`) replicates that exact precedence rather than checking both independently, which would silently disagree with what the search endpoint actually does.

```bash
pnpm validate:fortinet   # sweep mode: every Fortinet product
pnpm validate:pan        # sweep mode: every PAN product (mode: 'all', matching the production job)
```

| Product | Boundary versions tested | TP | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|
| Fortinet | 1,019 | 14,612 | 100.00% | 100.00% | 100.00% |
| Palo Alto Networks | 235 | 5,881 | 99.56% | 99.98% | 99.77% |

*Reproduced 2026-07-26. Three real bugs surfaced during this work — two in the validation harness, one in production:

1. **Harness bug**: `expectedIdsGeneric` had a real logic gap — an exact-list-only entry (no range fields at all) that didn't match the queried version fell through every subsequent check (none of them had anything to compare against) straight to an unconditional match, so it incorrectly matched *every other version too*. Fixed in `accuracy-sweep.ts`.
2. **Production gap**: `FortinetFetcher` discovered advisories via RSS only, which is a "what's new" feed exposing a rolling window of ~50 recent items — not a full archive (unlike PAN's `mode: 'all'`, which already paginates PAN's full advisory list). Older advisories the DB had from past scheduled runs were being flagged as false positives simply because a one-off ground-truth fetch couldn't see them. The real fix was adding a `mode: 'all'` to `FortinetFetcher` itself (defaulting to it, matching PAN's precedent) that paginates the full PSIRT advisory listing (`fortiguard.fortinet.com/psirt?page=N`, 21 pages / ~300 advisories back to 2018) instead of relying on RSS — this is a genuine data-completeness improvement to production, not just a validation-script workaround.
3. PAN's single remaining mismatch (CVE-2025-9132) is a real, accepted limitation: Chromium-style 4-component versions (Prisma Browser, e.g. `138.53.6.158`) get truncated to 3 components by `normalizeVersion()`, the same class of precision loss as the already-documented RPM sub-release issue (`el9` vs `el9_7.2`) — not fixed here for the same reason (see git history).

The Fortinet numbers above are from the corrected `mode: 'all'` fetcher (254 advisories, vs. ~47 from RSS alone).*

## Boundary-value sweep (RHEL / Oracle Linux)

RHEL and Oracle Linux advisories only ever express an exclusive upper bound (`<package> is earlier than <version>`, no lower bound in the plain "is earlier than" criterion) — only "fixed exact" (expect NOT affected) and "one RPM release step before fixed" (expect affected) boundary points are tested. Ground truth is the production `RedHatFetcher`/`OracleLinuxFetcher` themselves, fetched fresh from the live OVAL feeds rather than a second hand-rolled parser (seesawing between two independently-maintained parsers of the same page is exactly what went wrong with `validate:apache` during development — see git history). Results are restricted to the fetcher's own `sources` entry, same as nginx/tomcat/apache.

```bash
pnpm validate:redhat          # sweep mode: every RHEL 8+9 package
pnpm validate:oracle-linux    # sweep mode: every Oracle Linux package (capped at 50 boundary points/product — some packages, e.g. the kernel-uek family, have 19,000+ fixed-version entries; sampling avoids multi-hour runs without losing coverage)
```

| Product | Boundary points tested | TP | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|
| Red Hat (RHEL 8+9) | 107,118 | 42,290,911 | 99.99% | 99.98% | 99.99% |
| Oracle Linux | 148,699 | 11,013,762 | 98.71% | 99.70% | 99.21% |

*Reproduced 2026-08-18, after fixing two bugs this re-sweep surfaced (both described in detail in [README.md's Known Issues](README.md#rheloracle-linux-module-stream-false-positives-fixed-at-the-source-one-residual-gap-remains-for-products-other-than-nodejspostgresqlhttpdmysqlmariadbphp)):*

1. *`moduleStreamVersionStart()` (`advisory-helpers.ts`) now rejects a Module criterion's stream label as a floor when it's numerically incompatible with the row's own `versionEnd` (falling back to `inferBareVersionStart()`, same as if there had been no Module criterion at all). RHEL8's `javapackages-tools:201801` module bundles several independently-versioned Java build tools (ant, xmvn, an older maven line, ...) under one stream labeled by build generation, unrelated to any of the bundled packages' own versions — using it as a floor made 510 product names permanently unmatchable. Caught this by re-running this sweep after the original module-criterion fix shipped and seeing Recall drop to 99.43%; confirmed the guard doesn't reject legitimate calendar-versioned packages (`python-pytz`'s "2017" stream genuinely matches its own "2017.2..." version) by checking against real data before landing the fix.*
2. *The sweep's own ground truth (`expectedCVEsRpm`/`indexByProduct`, `src/scripts/lib/accuracy-sweep.ts`) never checked `versionStart` at all — only `versionEnd`. Before any module-criterion fix existed, production also had no `versionStart` anywhere, so ground truth and production shared the same blind spot and happened to agree (this is exactly why `validate-nodejs.ts` deliberately uses an independent, non-fetcher-derived ground truth — see below). Once production started correctly excluding older-stream queries via `versionStart`, this function kept expecting them anyway, misreporting every one of those correct exclusions as a false negative. Fixed to replicate `matchesRpmVersionRange()`'s (`search-helpers.ts`) exact semantics. This is what took RHEL's Recall from a misleading 99.64% back to 99.98%, and Oracle Linux's from 97.81%/99.87% to a clean 100%.*

*Reproduced again 2026-09-02, after two more fixes to Oracle Linux specifically:*

3. *`OracleLinuxFetcher` was merging Oracle's parallel FIPS-validated and ksplice live-patch build tracks into the same `(product, vendor)` bucket as the regular build, under a sibling `"<pkg> is fips patched"`/`"<pkg> is ksplice-based"` criterion this fetcher previously ignored. Those tracks carry their own, unrelated epoch (FIPS builds are pinned to epoch 10 specifically to sort above every ordinary release) — merged in, a fully-patched regular-track install compared as vulnerable against a fix version on a track it was never running. `collectCriteria()` now tags a criterion `isBuildVariant` when a sibling in the same AND block carries either marker, and those rows are excluded entirely rather than imported. Found live: one RHEL9-equivalent image's false-positive count for just `openssl`/`openssl-libs`/`gnutls` dropped from 47 to 0 once this landed. RHEL's OVAL feed carries neither marker (confirmed: 0 occurrences across the whole feed), so this is Oracle-Linux-only.*
4. *This sweep script itself (`validate-oracle-linux.ts`) had silently gone stale: it queried the bare `ecosystem=oracle-linux`, the pre-2026-09-01 form, while production had since moved to version-qualified vendors (`oracle-linux-<major>`, see item 2's history and [`rpmAdvisoryVendor()`](src/utils/search-helpers.ts)) — the bare form still matches, but only the near-empty legacy bucket predating that change. Re-running this sweep for the first time since that vendor-versioning change landed collapsed Recall to 0.02%, which looked like a catastrophic regression from fix ③ above but was entirely this script querying the wrong bucket. Fixed to index and query per `(product, OS major)`, deriving `ecosystem=Oracle Linux:<major>` from each row's own vendor instead of a single hardcoded value — mirroring how `validate-redhat.ts` already scopes to a single, hardcoded `Red Hat:9` (itself now worth re-checking against `RedHatFetcher`'s equivalent 2026-09-01 vendor-versioning change, since RHEL8-only entries could be silently invisible to that sweep for the same reason; not yet done).*

**A note on Oracle Linux's Precision column**: earlier measurements here (86.88%–87.01%, prior to fix ③ above) were attributed to Oracle's combined `com.oracle.elsa-all.xml.bz2` feed being revised in near-real-time between fetches — a real, still-present effect (see [Known limitations](#known-limitations) below), but fix ③ shows it was not the dominant cause: removing the FIPS/ksplice cross-track contamination alone took Precision to 98.71% in a single re-run, an 11+ point jump for one bug. The residual gap to 100% is consistent with the sweep's own note on feed volatility (Oracle's feed changing between the ground-truth fetch and the query), now a plausible sole explanation at this much smaller magnitude rather than an unverified one covering an 11-point gap.

## Boundary-value sweep (Node.js module streams / RHEL & Oracle Linux)

Ground truth here is deliberately **not** `RedHatFetcher`/`OracleLinuxFetcher`'s own parsed data — a "ground truth" built from the same feed the fetchers read would share production's exact blind spot and could never catch a fix from one DNF module stream (e.g. `nodejs:22`) leaking into a query against another, unrelated stream (e.g. `nodejs:10`). Ground truth is instead the independent [nodejs/security-wg vulnerability index](https://github.com/nodejs/security-wg/blob/main/vuln/core/index.json), whose `vulnerable`/`patched` fields express per-major-line semver ranges — scoped to the module-stream majors RHEL/Oracle Linux actually package (10/12/14/16/18/20/22/24). See [README.md's Known Issues](README.md#rheloracle-linux-module-stream-false-positives-fixed-at-the-source-one-residual-gap-remains-for-products-other-than-nodejspostgresql) for background on both the fix and the residual gap.

```bash
pnpm validate:nodejs                        # sweep mode, vendor=red-hat
pnpm validate:nodejs --vendor=oracle-linux  # sweep mode, vendor=oracle-linux
```

| Vendor | Stage | Boundary points | TP | FP | FN | Precision | Recall | F1 |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| Red Hat (RHEL 8+9) | before any fix | 154 | 2,507 | 13,199 | 802 | 15.96% | 75.76% | 26.37% |
| Red Hat (RHEL 8+9) | + Module-criterion `versionStart` | 154 | 2,309 | 4,265 | 1,000 | 35.12% | 69.78% | 46.73% |
| Red Hat (RHEL 8+9) | + bare-row fallback | 154 | 2,257 | 2,157 | 1,052 | **51.13%** | 68.21% | **58.45%** |
| Oracle Linux | before any fix | 154 | 2,459 | 13,015 | 850 | 15.89% | 74.31% | 26.18% |
| Oracle Linux | + Module-criterion `versionStart` | 154 | 2,112 | 8,346 | 1,197 | 20.20% | 63.83% | 30.68% |
| Oracle Linux | + bare-row fallback | 153 | 2,042 | 2,059 | 1,267 | **49.79%** | 61.71% | **55.11%** |

*Reproduced 2026-08-11, in the order fixed:*

1. *Baseline: both fetchers parsed only the `"<package> is earlier than <version>"` criterion, discarding the sibling `"Module <name>:N is enabled"` criterion in the same OVAL AND-block — no `versionStart` for module rows, so any older stream's query matched a newer stream's fix.*
2. *Extracting `versionStart` from that Module criterion at parse time (`collectCriteria()` in both fetchers) roughly doubled Precision. Self-gating verified first: across every nodejs `<definition>` in RHEL9's live feed, "has a Module criterion" and "`versionEnd` contains `.module+`" matched 1:1 (0 discrepancies), so the fix can't touch the ~9,364 non-modular product names. Applied to every DNF-module product, not just nodejs.*
3. *Residual FPs traced to advisories that predate a package's modularization entirely, with no Module criterion to extract from at all (e.g. RHSA-2022:6595 on RHEL9, `nodejs 16.16.0-1.el9_0`, issued before nodejs was modularized on that release). `inferBareVersionStart()` (`src/worker/advisory-helpers.ts`) falls back to the row's own `versionEnd` — scoped to exactly `nodejs`, `postgresql`, and `httpd` (see below for both), since a follow-up query found 917 other (product, vendor) pairs mixing modular and bare rows where it's unverified whether the same floor is safe.*

*Recall settled in the 62–70% range, unaffected by the fixes above (they only remove over-broad matches). Root cause, found by cross-referencing the 79 unique missed CVEs against the DB: 39 (49%) have **no** `nodejs` row at all under `red-hat`/`oracle-linux`, for any major — not missing data, but a mismatch between ground truth (upstream `nodejs/security-wg`, which has no concept of a distro's packaging window) and each RHEL/Oracle Linux module stream's bounded lifespan. Two patterns account for nearly all of it: fixed before the stream existed (CVE-2018-7161/7162/7164 patched upstream at `10.4.1`, but RHEL8's `nodejs:10` stream's first shipped build was already `10.14.1` — nothing to fix), and fixed after the stream was retired (CVE-2021-3449 patched upstream at `10.24.1`, but `nodejs:10`'s last build was `10.24.0`, retired around upstream Node 10's own April-2021 EOL). This is a limitation of `validate-nodejs.ts`'s ground-truth model, not a search or fetcher defect — fixing it would mean bounding ground-truth expectations to each stream's observed `versionEnd` range, not touching production code. Not yet implemented.*

## Sampled spot check (Ubuntu / Debian / Alpine)

Unlike the vendor OVAL/HTML sources above, OSV data arrives as already-structured JSON with no scrape/parse step of our own — the imported `OSVAffectedPackage` rows already *are* the ground truth, so these scripts read the DB directly instead of re-fetching anything live. These ecosystems have millions of rows (Ubuntu alone: ~1.9M) — several orders of magnitude past what an exhaustive sweep can cover — so this is a bounded **sample**, not exhaustive: 500 rows with an enumerated `affectedVersions` list (exercises the pre-existing exact-match path) plus 500 rows with only a continuous range and no enumerated list (exercises the dpkg-range fallback described below).

Investigating what "ground truth" should mean here surfaced a real, previously-undiscovered bug before any sweep script was even written: most Debian OSV entries (and a smaller fraction of Ubuntu/Alpine ones) publish *only* a continuous `introduced`/`fixed` range with no enumerated `versions` list at all. Since distro-ecosystem search used exact-match against `affectedVersions` exclusively, **version-specific search silently returned nothing for ~68% of Debian's OSV data**, regardless of what version was queried. Fixed by implementing `compareDpkgVersions()` ([`src/utils/dpkg-version.ts`](src/utils/dpkg-version.ts), the dpkg version-comparison algorithm) as a range-comparison fallback — exact-match is tried first, falling back to range comparison only when the enumerated list doesn't contain (or doesn't exist for) the queried version. See [`README.md`'s Known Issues](README.md#known-issues) for more detail.

```bash
pnpm validate:debian
pnpm validate:ubuntu
pnpm validate:alpine
```

| Ecosystem | Points tested | TP | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|
| Debian | 1,500 | 999 | 100.00% | 99.90% | 99.95% |
| Ubuntu | 1,500 | 1,000 | 100.00% | 100.00% | 100.00% |
| Alpine | 1,039 | 539 | 100.00% | 100.00% | 100.00% |

*Reproduced 2026-07-26 (post-fix). Debian's single miss involves a Bazaar-revision-style version string (`0~bzrNNN`) where the synthetic "fixed-1" boundary point doesn't land exactly one real dpkg-ordering step below the actual fixed version — a quirk of deriving a boundary point automatically for an unusual version scheme, not a reproduced search miss on real advisory data.*

## Single-version spot check (openssl / PostgreSQL)

OpenSSL and PostgreSQL have no dedicated `AdvisoryFetcher` — their vulnerabilities come from NVD/OSV only, so `pnpm validate:openssl`/`pnpm validate:postgresql` always require an explicit version (no sweep mode; see [Known limitations](#known-limitations)).

```bash
pnpm validate:openssl 3.5.0
pnpm validate:postgresql 16.4
```

| Product | Version | TP | FP | FN | Precision | Recall | F1 |
|---|---|---:|---:|---:|---:|---:|---:|
| OpenSSL | 3.5.0 | 36 | 0 | 2 | 100.00% | 94.74% | 97.30% |
| PostgreSQL | 16.4 | 20 | 1 | 4 | 95.24% | 83.33% | 88.89% |

*Reproduced 2026-07-26. OpenSSL's FPs are unrelated CVEs from other sources tracking their own "openssl" package under a different version scheme (see below) — not misses in the official-advisory data itself. OpenSSL's 2 FNs (CVE-2025-9231/9232) are real gaps worth investigating separately.*

*PostgreSQL's numbers reflect a production fix made during this investigation — see [RHEL/Oracle Linux module-stream false positives](README.md#rheloracle-linux-module-stream-false-positives-fixed-at-the-source-one-residual-gap-remains-for-products-other-than-nodejspostgresql) in README.md's Known Issues for the full history. Originally 5 FPs/0 FN (82.76%/100.00%/90.57%): 4 of the 5 FPs were RHEL/Oracle Linux OVAL's missing version lower bound (a newer module stream's fix numerically swallowed this 16.x query), fixed first by excluding module-stream rows from the default search (costing 4 legitimate TPs with no other searchable source, hence the FNs above) and then properly, by inferring each row's own floor. The remaining 1 FP (CVE-2017-8806) is an unrelated NVD product-identity mix-up (Debian's `postgresql-common` wrapper package mapped to "postgresql"). None of this table reflects `ecosystem=`-scoped queries, since `validate:postgresql` only exercises the default (no-`ecosystem`) path.*

*The RHEL/Oracle Linux `versionStart` root-cause fix (extracting it from the OVAL Module criterion, see the [Node.js section](#boundary-value-sweep-nodejs-module-streams--rhel--oracle-linux) above) applies to postgresql automatically, superseding the earlier product-specific floor heuristic. Investigating nodejs's bare-row gap surfaced the same class of bug in postgresql, confirmed live rather than through a sweep (no `ecosystem=`-scoped sweep mode exists for `validate-postgresql.ts` yet): `package=postgresql&version=9.2.10&ecosystem=oracle-linux` matched 56 results, including CVE-2026-2004/2005/2006, fixed only in the unrelated `13.23-2.el9_7` (RHEL9) build — bare rows with no Module criterion at all (RHEL7 predates DNF modularity, e.g. `9.2.24-9.0.7.el7_9`; RHEL9/OL9's pre-modularization baseline, e.g. `13.23-5.el9_8`; RHEL10/OL10, which doesn't modularize postgresql at all, e.g. `16.14-1.0.1.el10_2`) still had no lower bound. `inferBareVersionStart()` (`src/worker/advisory-helpers.ts`) now covers `postgresql` too, cutting the same query to 34 results.*

*One refinement was needed beyond a single leading digit: PostgreSQL used a two-component major before version 10 (`9.0`–`9.6`, each mutually incompatible), so `9.2.24-...` and `9.6.20-...` initially collapsed onto the same `9.0` floor — CVE-2019-10130 (its own RHSA titled "postgresql:9.6 security update") wrongly matched the `9.2.10` query as a result. `inferBareVersionStart()` now floors `9.x` rows at the full `9.{minor}`. After both fixes, the same query returns 29 results, all genuinely within the `9.2.x` line; a sanity check at `9.6.19` still correctly matches CVE-2019-10130 (fixed at `9.6.20`), confirming no same-line recall was lost.*

*`httpd` needed the two-component treatment unconditionally, with no single-digit-safe range at all: Apache has never used a plain integer major across the versions RHEL/Oracle Linux track, only `2.2` (RHEL5/6, EOL upstream since 2018) and `2.4` (RHEL7+), both bare on Oracle Linux (no Module criterion either way). `package=httpd&version=2.2.3&ecosystem=oracle-linux` matched 154 CVEs before the fix, 104 of them (68%) fixed only in the unrelated `2.4.x` line; `inferBareVersionStart()` now floors at the full `2.2`/`2.4`, and the same query returns 57, all genuinely `2.2.x`. A sanity check at `2.4.36` still matches CVE-2020-11984 (fixed at `2.4.37`). No dedicated `validate-httpd`-for-RHEL sweep exists yet (unrelated to `validate:apache`, which checks httpd.apache.org's own advisories, not this RHEL/Oracle Linux OVAL path) — both this and the PostgreSQL numbers above are live-query spot checks, not swept the same rigorous way as `validate-nodejs.ts`.*

*`mysql`/`mariadb` turned out not to be a bare-row problem at all, but a gap in the root-cause fix itself: their live OVAL feeds use dotted Module stream labels (`"Module mysql:8.4 is enabled"`, `"Module mariadb:10.11 is enabled"`), which `extractModuleMajor()`'s original digit-only regex silently failed to parse — those rows fell through to the generic `.module+` backfill's single-digit extraction and collapsed mysql's `8.0`/`8.4` and mariadb's `10.3`/`10.5`/`10.11`/`11.8` lines onto the same floor. Fixed by having `extractModuleMajor()` capture the stream label verbatim (any non-whitespace token, not just digits) instead of parsing it as an integer. Confirmed live: `package=mysql&version=8.0.30&ecosystem=oracle-linux` and `package=mariadb&version=10.3.30&ecosystem=oracle-linux` each now return only same-line matches (362 and 50 results respectively, 0 from another line), and `mysql@8.4.0` still matches its own line. Each product also has an ancient, genuinely bare pre-DNF line needing the same two-component `inferBareVersionStart()` fallback as postgresql/httpd — mysql's RHEL5/6-era `5.0`/`5.1` and mariadb's RHEL7-era `5.5` — confirmed via `package=mysql&version=5.1.60&ecosystem=oracle-linux` (70 results, all `5.1.x`). No dedicated sweep for either; same live-query-only caveat as above.*

*`php` uses the same dotted Module stream label (`"Module php:8.1 is enabled"`), already covered for free by the `extractModuleMajor()` fix above, plus an ancient bare `5.1`/`5.3` line (RHEL5/6, predating DNF modularity) confirmed via `package=php&version=5.1.6&ecosystem=oracle-linux`: 180 matches before the fix, 134 of them (74%) fixed only in the unrelated `5.3.x` line, down to 59 (0 cross-line) after. `mysql`/`mariadb`/`php` all ship many same-source-RPM subpackages (`mysql-server`, `mariadb-bench`, `php-cli`, ...) sharing the exact same version-release string as their base package — `inferBareVersionStart()` now covers those too, confirmed via `package=php-cli&version=5.3.3&ecosystem=oracle-linux` (76 results, 0 cross-line) and `package=mysql-server&version=5.1.60&ecosystem=oracle-linux` (70 results, 0 cross-line). A handful of subpackages carry their own independent version instead (`mysql-selinux`'s SELinux policy version, `mariadb-connector-c`'s client-library version, PHP's `php-pecl-*`/`php-pear`/`php-libguestfs`) and are deliberately excluded — see `inferBareVersionStart()`'s doc comment for the full verified membership list. RHEL6/7-era Software Collections packages (`php54-php-cli`, `mysql55-mysql-server`, ...) need no fix at all: the version is baked into the product name itself, so they're already isolated from this collision by construction.*

## Known limitations

### Cross-source version-namespace collisions (package=openssl etc.)

Some product names are tracked by multiple independent sources under different version schemes — e.g. `openssl`/`nginx` are packaged separately by RHEL/Oracle Linux (RPM Epoch:Version-Release) in addition to the upstream project's own semver-like releases. Querying `package=X&version=Y` returns matches from *every* source tracking that product name, so a raw comparison against just one source's official advisories can show inflated false positives from another source's numerically-colliding, unrelated version range — this is not a bug in either source's fetcher.

For products with a dedicated `AdvisoryFetcher` (nginx, Tomcat, Apache HTTP Server), the [boundary-value sweep](#boundary-value-sweep-nginx--tomcat--apache) scripts filter results to that fetcher's own `sources` entry to measure the fetcher in isolation, which is why they show 100% Precision despite this endpoint-wide characteristic.

OpenSSL has no dedicated fetcher (NVD/OSV coverage only), so there's no single source to filter to, and a further limitation compounds it: NVD's CPE version-range representation cannot express "affects branches A, C, D but not the already-EOL'd branch B" — it can only express a single contiguous range — so a recent CVE affecting several actively-maintained branches simultaneously ends up numerically covering an old, already-retired branch's version numbers too. Because of this, `validate:openssl` intentionally has no automatic sweep mode; use the single-version check and expect some Precision noise from this endpoint-wide, upstream-data characteristic rather than a defect in this product's own advisory ingestion.

PostgreSQL also has no dedicated fetcher and shares this same NVD-side limitation in principle, but its FPs in practice turned out to have a different, more specific root cause — see [RHEL/Oracle Linux module-stream false positives](README.md#rheloracle-linux-module-stream-false-positives-mitigated-for-the-default-search-fixed-for-postgresql-specifically) above.

### RHEL/Oracle Linux OVAL feeds get revised after the fact

Red Hat and Oracle occasionally revise an already-published advisory's affected-package list (e.g. adding or dropping a sub-package) without a corresponding CVE or errata number change. The [boundary-value sweep](#boundary-value-sweep-rhel--oracle-linux) fetches ground truth live at report time, while the DB reflects whatever the daily scheduled import last saw — so a handful of mismatches between the two are expected and self-correct on the next import, not a search or fetcher defect. Confirmed by re-fetching the live feed for several of the mismatching CVEs and finding the affected-package list had genuinely changed from what's in the DB.

### Oracle Linux has no confirmed-unfixed CVE ingestion (unlike Red Hat)

Oracle Linux's OVAL feed has the identical structural gap as Red Hat's (it only ever publishes definitions for CVEs with a released fix — see [Red Hat CSAF VEX](README.md#red-hat-csaf-vex-srcworkerredhat-vex-fetcherts)), but this project doesn't ingest a fix for it. Oracle does publish a CSAF VEX tree in the same schema at `linux.oracle.com/csaf/beta/vex/`, confirmed live, but unlike Red Hat's there is no bulk archive — only a per-CVE JSON file browsable one year-directory at a time (roughly 2,000–6,600 files/year sampled, back to 1999, no `changes.csv`-style incremental path), and its product IDs (`P-1309V-10:dovecot`) use a different, undocumented scheme with no `relationships` array to resolve them from. Checked whether other tools solve this: they don't — [Trivy's own coverage docs](https://trivy.dev/docs/latest/coverage/os/oracle/) list unfixed-vulnerability support as unsupported for Oracle Linux, and Grype's data source ([vunnel](https://github.com/anchore/vunnel/tree/main/src/vunnel/providers/oracle)) is confirmed OVAL-only for it (no CSAF/VEX client in its fetcher source, unlike its RHEL provider).

### Debian issues without a CVE number (`TEMP-*`) are not tracked

Debian's own Security Tracker assigns temporary `TEMP-000000-XXXXXX` / `TEMP-<bug>-XXXXXX` names to issues that haven't been assigned a CVE yet, and explicitly documents these as unstable — they can change when the tracker's database is updated, so [Debian itself recommends against using them in external references](https://security-tracker.debian.org/tracker/data/fake-names). Since Debian/Ubuntu coverage here comes via OSV (which imports Debian Security Tracker data keyed to CVE entries), issues that only have a `TEMP-*` name and no CVE are not searchable. This is a deliberate scope boundary rather than a fetcher defect — resolving it would mean ingesting Debian's tracker data directly instead of through OSV.
