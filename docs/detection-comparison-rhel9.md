# RHEL 9 detection comparison: heretix-api and Trivy

One RHEL 9.8 host scanned with both heretix-api and [Trivy](https://trivy.dev/). The two tools were given the same installed packages, and every difference between their findings was checked against Red Hat's own VEX data.

**Measured on 2026-10-18.** Both tools depend on data that changes daily, so a later run can give different numbers. This is one host and one distribution, so read it as a worked example of how the two sources differ, not as a general detection rate. [ACCURACY.md](../ACCURACY.md) has the per-product precision and recall sweeps.

- [Summary](#summary)
- [Setup](#setup)
- [Results](#results)
- [Where the tools differ](#where-the-tools-differ)
- [How the differences were checked](#how-the-differences-were-checked)
- [Limits](#limits)
- [Reproducing it](#reproducing-it)

## Summary

- On the 517 RPM packages of the host, the two tools report the same finding for 63,452 of Trivy's 63,465 package-version-CVE rows (100.0%).
- heretix-api reports 5,471 further rows that Trivy does not. Checked against Red Hat's VEX data, 5,470 are confirmed as unfixed on this host; the other one is not confirmed (see below).
- The 1,712 findings that have a fixed version agree on that version in every case.
- The first run found 1,103 rows that only Trivy reported (98.3% agreement). They were a defect in how heretix-api bounded Red Hat's unfixed findings, fixed in [#117](https://github.com/TITeee/heretix-api/pull/117). The numbers below show the run before and after the fix.
- About 98% of all rows belong to the kernel family. On the other packages the tools report 1,550 and 1,563 rows and differ in a handful.

## Setup

| | |
|---|---|
| Host | RHEL 9.8 on AWS EC2, fully updated with `dnf update` on 2026-10-18 |
| Kernels installed | `5.14.0-687.10.1.el9_8` and `5.14.0-687.58.1.el9_8` (the second is running) |
| Packages | 520 `rpm -qa` entries: 517 packages and 3 `gpg-pubkey` entries |
| Trivy | 0.74.0, `rootfs` scan run on the host on 2026-10-18 with its defaults, so unfixed findings are included (no `--ignore-unfixed`). Vulnerability database (schema version 2) built 2026-10-18 00:43 UTC, downloaded 06:05 UTC, just before the scan |
| heretix-api | Before: `00835cc` (#116). After: `62ce731` (#117). Red Hat VEX archive of 2026-10-11 |
| heretix-cli | 0.5.1, which produced the CycloneDX SBOM that supplied the package list |

The unit of comparison is the row (installed package name, installed version, CVE). Both tools list each binary package separately, so one kernel CVE yields a row for every installed kernel package and version.

Trivy also scanned Go binaries on the host (106 rows). heretix-api does not scan binaries on a host, so those rows are left out and the comparison covers RPM packages only. The 6 PyPI components in the SBOM are likewise outside the Red Hat comparison.

## Results

| | Before #117 | After #117 |
|---|---:|---:|
| Trivy rows (RPM) | 63,465 | 63,465 |
| heretix-api rows | 67,550 | 68,923 |
| Rows in both | 62,362 | 63,452 |
| Only Trivy | 1,103 | 13 |
| Only heretix-api | 5,188 | 5,471 |
| Agreement, as a share of Trivy's rows | 98.3% | 100.0% |
| Distinct CVEs, Trivy / heretix-api | 6,615 / 7,012 | 6,615 / 7,120 |
| Distinct CVEs in both | 6,525 | 6,613 |

By package family, after the fix:

| | Trivy | heretix-api |
|---|---:|---:|
| Kernel family (`kernel*`, `python3-perf`) | 61,915 | 67,360 |
| Everything else | 1,550 | 1,563 |

Other comparisons on the rows both tools report:

- **Fix version.** Of the rows with a fixed version, all 1,712 agree.
- **Severity.** Trivy's rating is Red Hat's own. heretix-api returns it as `distroPriority`. They match on 63,440 of 63,452 shared rows; the 12 others differ by one step (Trivy `MEDIUM` where heretix-api has `important`, and one `LOW` against `moderate`).
- **Status.** heretix-api labels each unfixed finding with a `fixStatus`. After the fix its unfixed rows are: `deferred` 46,668, `affected` 15,710, `will_not_fix` 3,979, `out_of_support` 799, `under_investigation` 55.

## Where the tools differ

### Only Trivy: 1,103 rows, now 13

**The defect (fixed).** Red Hat's VEX states "unfixed" once per major version, but "fixed" per release stream (9.2 EUS, 9.4 E4S, ...). heretix-api bounded each unfixed row by the newest fix across all streams. For 103 kernel CVEs the fixes exist only in older sustaining streams, so a 9.8 build (`el9_8`) was newer than every recorded fix and was called fixed, although its own stream has no fix.

After #117 a build that carries a stream tag is judged against that stream's fix alone, and is affected when its stream has none. That change added 1,373 rows and removed none; all 1,373 are confirmed by the VEX data.

**What remains: 13 rows, 3 CVEs.**

| CVE | Rows | What Red Hat's data says |
|---|---:|---|
| CVE-2021-47430 | 11 | Kernel family. Red Hat publishes no VEX document for it. |
| CVE-2026-0438 | 1 | `microcode_ctl`. No VEX document either. |
| CVE-2026-39834 | 1 | `conmon`. The VEX document lists `conmon` as known not affected. |

heretix-api takes Red Hat's unfixed findings from the VEX data, so a CVE with no VEX document cannot be reported from that source. For CVE-2026-39834, heretix-api follows the VEX document.

### Only heretix-api: 5,471 rows, 507 CVEs

None of these 507 CVEs appears anywhere in Trivy's output, on any package.

| heretix-api `fixStatus` | Rows | Checked against VEX |
|---|---:|---|
| `deferred` ("Fix deferred") | 4,358 | 4,357 confirmed, 1 not |
| `affected` | 924 | all confirmed |
| `will_not_fix` | 145 | all confirmed |
| `under_investigation` | 22 | all confirmed |
| `out_of_support` | 22 | all confirmed |

Most are kernel CVEs from 2022 and 2023 (5,024 of the 5,471 rows), which Red Hat records as known affected for RHEL 9 with no fix, a deferred fix, or a decision not to fix.

The one row not confirmed is `polkit` 0.117-14.el9 for CVE-2025-8263, reported as `deferred`. It comes from the VEX archive of 2026-10-11. Red Hat revised that document on 2026-10-15, and the revision lists `polkit-libs`, `polkit-devel`, `polkit-docs` and the source package as known affected but no longer lists `polkit` itself. That is a difference in data freshness, not in matching.

Trivy's output does contain `affected`, `will_not_fix`, `end_of_life` and `fixed` findings, so it does not leave out unfixed findings as a class. Why it has none of these 507 CVEs was not investigated here; it may depend on the vulnerability database in use on the scan date (see [Setup](#setup)).

## How the differences were checked

Every row that only one tool reported was compared with the CVE's Red Hat VEX (CSAF) document, `https://security.access.redhat.com/data/csaf/v2/vex/<year>/<cve>.json`. A row is **confirmed** when:

1. the document lists the package (or its source package) for RHEL 9 as `known_affected` or `under_investigation`, and not as `known_not_affected`; and
2. no fixed build in the installed build's own minor-release stream (`el9_8`) is at or below the installed version.

The check covers all 5,471 heretix-api-only rows, all 13 Trivy-only rows and the 1,373 rows added by the fix. It is a check against Red Hat's published data, not against the running system, so it shows agreement with Red Hat's statements and does not by itself prove exploitability.

## Limits

- One host, one release (RHEL 9.8), and a result that is about 98% kernel family. Results for other distributions or for hosts without several kernels will differ.
- The package list came from the heretix-cli SBOM (517 packages), and Trivy read the RPM database directly (520 entries). The three extra entries are `gpg-pubkey` records, which are not packages.
- A scan is a snapshot. Red Hat revises its VEX documents continually and the heretix-api archive used here is dated 2026-10-11, so a small number of differences can come from data freshness alone.
- Trivy was run once, with the database current on the scan date. A later database may report more.

## Reproducing it

On the host:

```bash
trivy rootfs --scanners vuln --list-all-pkgs --format json -o trivy-all.json /   # the run compared, unfixed findings included
heretix-cli collect --output sbom.json                                          # CycloneDX SBOM of the host
```

Every comparison above uses `trivy-all.json`. A second run with `--ignore-unfixed` was made only to check the fixed versions: it reports the same 1,712 fixed rows as the first run, so it adds nothing to the other comparisons.

```bash
trivy rootfs --scanners vuln --ignore-unfixed --format json -o trivy-fixed.json /
```

For each RPM component of the SBOM (ecosystem `Red Hat:9`), ask heretix-api for its findings, paging at 500 per request:

```
GET /api/v1/vulnerabilities/search?package=<name>&version=<version>&ecosystem=Red%20Hat:9&limit=500&offset=<n>
```

Then key both result sets by (package, version with a leading `0:` removed, CVE) and take the set differences. For each row in a difference, fetch the CVE's VEX document and apply the two conditions above.
