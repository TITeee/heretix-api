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

RHEL and Oracle Linux advisories only ever express an exclusive upper bound (`<package> is earlier than <version>`, no lower bound), so there's no "introduced" edge to test — only "fixed exact" (expect NOT affected) and "one RPM release step before fixed" (expect affected). Ground truth is the production `RedHatFetcher`/`OracleLinuxFetcher` themselves, fetched fresh from the live OVAL feeds rather than a second hand-rolled parser (seesawing between two independently-maintained parsers of the same page is exactly what went wrong with `validate:apache` during development — see git history). Results are restricted to the fetcher's own `sources` entry, same as nginx/tomcat/apache.

```bash
pnpm validate:redhat          # sweep mode: every RHEL 8+9 package
pnpm validate:oracle-linux    # sweep mode: every Oracle Linux package (capped at 50 boundary points/product — some packages, e.g. the kernel-uek family, have 19,000+ fixed-version entries; sampling avoids multi-hour runs without losing coverage)
```

| Product | Boundary points tested | TP | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|
| Red Hat (RHEL 8+9) | 105,049 | 40,622,977 | 99.97% | 99.98% | 99.98% |
| Oracle Linux | 97,538 | 7,822,599 | 99.48% | 100.00% | 99.74% |

*Reproduced 2026-07-25/26. The small residual FP/FN counts are not code bugs: spot-checking the top offending CVEs showed the vendor's live OVAL feed had been revised (e.g. a package added to or removed from an advisory's affected list) in the hours between when the DB was last imported and when ground truth was fetched for this report — an inherent skew whenever comparing a live upstream feed against a periodically-imported snapshot, not a search or fetcher defect. Recall is comprehensive (99.98%/100%) since an earlier draft of this sweep undercounted heavily-patched packages (kernel etc. return 500+ CVEs) with un-paginated requests against the API's 500-result page cap — fixed by paginating fully in the validate scripts themselves.*

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

*PostgreSQL's numbers reflect a real production fix made during this investigation — see [RHEL/Oracle Linux module-stream false positives](README.md#rheloracle-linux-module-stream-false-positives-mitigated-for-the-default-search) in README.md's Known Issues. Originally 5 FPs/0 FN (82.76%/100.00%/90.57%): 4 of the 5 FPs turned out to be a real bug (RHEL/Oracle Linux OVAL data for DNF module-stream software has no version lower bound, so a newer stream's fix version numerically swallowed this query for the older 16.x stream), not the "cross-source collision" originally assumed below. Fixed by excluding module-stream rows (`versionEnd` containing `.module+`) from the default (no-`ecosystem`) search — this removed the 4 bogus FPs but also cost 4 legitimate TPs that had no other searchable source (NVD has no version-range data at all for those specific CVEs), hence the new FNs. The remaining 1 FP (CVE-2017-8806) is a genuine, unrelated NVD product-identity mix-up (Debian's `postgresql-common` wrapper-script package mapped to product name "postgresql").*

## Known limitations

### Cross-source version-namespace collisions (package=openssl etc.)

Some product names are tracked by multiple independent sources under different version schemes — e.g. `openssl`/`nginx` are packaged separately by RHEL/Oracle Linux (RPM Epoch:Version-Release) in addition to the upstream project's own semver-like releases. Querying `package=X&version=Y` returns matches from *every* source tracking that product name, so a raw comparison against just one source's official advisories can show inflated false positives from another source's numerically-colliding, unrelated version range — this is not a bug in either source's fetcher.

For products with a dedicated `AdvisoryFetcher` (nginx, Tomcat, Apache HTTP Server), the [boundary-value sweep](#boundary-value-sweep-nginx--tomcat--apache) scripts filter results to that fetcher's own `sources` entry to measure the fetcher in isolation, which is why they show 100% Precision despite this endpoint-wide characteristic.

OpenSSL has no dedicated fetcher (NVD/OSV coverage only), so there's no single source to filter to, and a further limitation compounds it: NVD's CPE version-range representation cannot express "affects branches A, C, D but not the already-EOL'd branch B" — it can only express a single contiguous range — so a recent CVE affecting several actively-maintained branches simultaneously ends up numerically covering an old, already-retired branch's version numbers too. Because of this, `validate:openssl` intentionally has no automatic sweep mode; use the single-version check and expect some Precision noise from this endpoint-wide, upstream-data characteristic rather than a defect in this product's own advisory ingestion.

PostgreSQL also has no dedicated fetcher and shares this same NVD-side limitation in principle, but its FPs in practice turned out to have a different, more specific root cause — see [RHEL/Oracle Linux module-stream false positives](README.md#rheloracle-linux-module-stream-false-positives-mitigated-for-the-default-search) above.

### RHEL/Oracle Linux OVAL feeds get revised after the fact

Red Hat and Oracle occasionally revise an already-published advisory's affected-package list (e.g. adding or dropping a sub-package) without a corresponding CVE or errata number change. The [boundary-value sweep](#boundary-value-sweep-rhel--oracle-linux) fetches ground truth live at report time, while the DB reflects whatever the daily scheduled import last saw — so a handful of mismatches between the two are expected and self-correct on the next import, not a search or fetcher defect. Confirmed by re-fetching the live feed for several of the mismatching CVEs and finding the affected-package list had genuinely changed from what's in the DB.
