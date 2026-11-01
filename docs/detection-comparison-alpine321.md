# Alpine 3.21 detection comparison: heretix-api and Trivy

One Alpine 3.21 container image scanned with both heretix-api and [Trivy](https://trivy.dev/). The two tools were given the same image, and every difference between their findings was checked against the OSV records that heretix-api holds, the Alpine security database and NVD.

**Measured on 2026-11-01.** Both tools depend on data that changes daily, so a later run can give different numbers. This is one image and one release, so read it as a worked example of how the two sources differ, not as a general detection rate. The [Ubuntu 24.04 comparison](detection-comparison-ubuntu2404.md), the [Debian 13 comparison](detection-comparison-debian13.md) and the [RHEL 9 comparison](detection-comparison-rhel9.md) do the same for those distributions, and [ACCURACY.md](../ACCURACY.md) has the per-product precision and recall sweeps.

- [Summary](#summary)
- [Setup](#setup)
- [Results](#results)
- [Where the tools differed, and what was fixed](#where-the-tools-differed-and-what-was-fixed)
- [What remains](#what-remains)
- [How the differences were checked](#how-the-differences-were-checked)
- [Limits](#limits)
- [Reproducing it](#reproducing-it)

## Summary

- On the 68 apk packages of the image, heretix-api reports 198 of Trivy's 212 package-CVE rows (93.4%). Every row heretix-api reports, Trivy reports too, and the fixed version agrees on all 198.
- The first run reported 182 of the 212 (85.8%). The 16 rows it missed came from one defect in heretix-api, now fixed ([#146](https://github.com/TITeee/heretix-api/pull/146)): Alpine OSV records whose range starts above its own fixed version matched no installed version.
- 14 rows are reported only by Trivy:
  - 7 where the OSV record has a range that starts after the installed version (curl and libpng), so heretix-api does not report them;
  - 7 for which heretix-api holds no OSV record for Alpine 3.21 at all (curl, libpng and musl).
- No row is reported only by heretix-api.

## Setup

| | |
|---|---|
| Image | `nginx:1.27-alpine3.21`, Alpine 3.21.3, digest `sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10`. Pulled from the registry on 2026-11-01 (no Docker daemon was involved). The tag is a pinned, older build, so it has fixes waiting; the newest `python:3.13-alpine` (Alpine 3.24.3) had no OS package findings in Trivy and was not used |
| Packages | 68 apk packages collected by heretix-cli |
| Trivy | 0.74.0, `image --image-src remote --scanners vuln`, with its defaults (unfixed findings included) and again with `--ignore-unfixed`. Vulnerability database (schema version 2) updated 2026-11-01 07:08 UTC |
| heretix-api | first run on `3610ded`, final run on `02463ca` (the content of #146). The Alpine records in the database were last fetched on 2026-10-28; the `osv-Alpine` job was started again on 2026-11-01 before the first run and its completion was not observed |
| heretix-cli | `421d7d2` (main after 0.5.3), run as `heretix-cli collect --image`, then `check` against heretix-api |

The unit of comparison is the row (installed package name, CVE). Both tools list each binary package separately, so a CVE in a source package yields a row for every installed package built from it (`libssl3` and `libcrypto3` for `openssl`, `curl` and `libcurl` for `curl`). Trivy lists two CVE-2026-1965 entries on curl (`CVE-2026-1965_1` and `CVE-2026-1965_2`); they are counted as two rows. Alpine's security database lists only vulnerabilities that have a fix, so every finding of either tool has a fixed version, and the `--ignore-unfixed` run is the same as the default one.

## Results

| | First run | Final run |
|---|---:|---:|
| Trivy rows | 212 | 212 |
| heretix-api rows | 182 | 198 |
| Rows in both | 182 | 198 |
| Only Trivy | 30 | 14 |
| Only heretix-api | 0 | 0 |
| Agreement, as a share of Trivy's rows | 85.8% | 93.4% |

In the final run the tools cover 131 distinct CVEs in common; Trivy reports 139 in all. Both report findings on the same 20 packages. The rerun after the fix added exactly the 16 rows described below and removed none.

Other comparisons on the 198 shared rows:

- **Fix version.** The tools agree on the fixed version on all 198 rows.
- **Severity.** The two tools give the same severity on 110 of the 198 rows (Trivy: `CRITICAL` 3, `HIGH` 54, `MEDIUM` 93, `LOW` 46 on the shared rows). On the other 88 the labels differ: heretix-api's is higher on 64 and lower on 24. heretix-api's severity comes from its merged CVE data (NVD taking precedence over OSV); where Trivy's comes from was not examined.
- **Status.** heretix-api reports no `fixStatus` for Alpine, whose data has fixed vulnerabilities only.

## Where the tools differed, and what was fixed

### 16 rows on `openssl` and `libxml2`: ranges that start above their fix (#146)

Some Alpine OSV records give a range whose `introduced` version is above its `fixed` version, and no installed version is in such a range. These are the records for Alpine 3.21, checked on api.osv.dev as well as in the local database:

| Package | CVEs | Rows | OSV range in Alpine 3.21 |
|---|---|---:|---|
| `openssl` (as `libssl3`, `libcrypto3`) | CVE-2026-34183, 42768, 54875, 63073, 72897, 75804, 84784 | 14 | introduced `3.4.0`, fixed `3.3.7-r1` or `3.3.7-r2` |
| `libxml2` | CVE-2025-32414, CVE-2025-32415 | 2 | introduced `2.14.0`, fixed `2.13.4-r6` |

The same records give a valid range for Alpine 3.22 to 3.24 (for CVE-2026-34183: introduced `3.4.0`, fixed `3.5.7-r0`). The image has `openssl` 3.3.3-r0 and `libxml2` 2.13.4-r5, below the fixed versions that Alpine's security database lists for 3.21, and Trivy reports them. NVD lists CVE-2025-32414 and CVE-2025-32415 as affecting libxml2 before 2.13.8, and from 2.14.0 before 2.14.2, so 2.13.4 is in the first range.

heretix-api now treats the start of such a range as unknown, so the fixed version alone bounds it. A range that starts below its fixed version is unchanged. Across the Alpine records held by heretix-api, 411 of the 11,241 ranges with both bounds start at or above their fixed version (65 of them in Alpine 3.21 to 3.24); Debian and Ubuntu have no such range. The rerun on the same SBOM added the 16 rows and changed nothing else.

## What remains

### Only Trivy: 14 rows

| What | Rows | Notes |
|---|---:|---|
| OSV range starts after the installed version | 7 | `curl` and `libcurl` 8.12.1-r1 on CVE-2025-5399, CVE-2025-9086 and CVE-2026-3805 (6 rows); `libpng` 1.6.47-r0 on CVE-2026-22695 (1 row). The Alpine 3.21 records give `introduced` 8.13.0 (curl) and 1.6.51 (libpng), above the installed versions, with fixes at 8.14.1-r0, 8.14.1-r2, 8.14.1-r3 and 1.6.54-r0. heretix-api follows the range. Trivy reports them |
| No OSV record for Alpine 3.21 | 7 | CVE-2026-1965 on `curl` and `libcurl` (4 rows, both Trivy entries): OSV has the record for Alpine 3.23 and 3.24 only. CVE-2026-46675 on `libpng` (1 row) and CVE-2026-107891 on `musl` and `musl-utils` (2 rows): api.osv.dev returned no Alpine record for either. All three are in Alpine's security database for 3.21 (fixed in curl 8.14.1-r3, libpng 1.6.59-r0 and musl 1.2.5-r12) |

The first group is a difference in what each source says about the affected versions. Whether curl 8.12.1 and libpng 1.6.47 are affected by those CVEs was not established here, and the rows are not counted as matches or as false positives. The second group is a gap in the OSV data that heretix-api reads. Nothing in heretix-api's matching changes it.

### Only heretix-api: none

## How the differences were checked

Every row that only one tool reported was looked up in the OSV records held by heretix-api (`OSVVulnerability` and `OSVAffectedPackage`, for the ecosystem `Alpine:v3.21`), on api.osv.dev, and in Alpine's security database for 3.21 (`secdb.alpinelinux.org`). The binary package of each row was mapped to the source package that Alpine's records name (`libssl3` and `libcrypto3` to `openssl`, `libcurl` to `curl`, `musl-utils` to `musl`). The libxml2 ranges were compared with NVD's.

It is a check against Alpine's, OSV's and NVD's published data, not against the running image, so it shows agreement with their statements and does not by itself prove exploitability.

## Limits

- One image, one release (Alpine 3.21), and a small image (68 packages). Results for other releases and for images with more packages will differ.
- Packages installed outside apk were not part of this comparison. Trivy's run found no findings of that kind on this image.
- The 14 rows only Trivy reports were not checked against the upstream projects' advisories one by one; the 7 with a range that starts after the installed version in particular are unresolved.
- The `osv-Alpine` job was started on 2026-11-01 but its completion was not observed. The nine records checked on api.osv.dev were last modified between 2026-08-27 and 2026-10-08.
- A scan is a snapshot. OSV, NVD and Alpine's security database are revised continually and do not always agree.
- Trivy was run once, with the database current on the scan date.

## Reproducing it

Collect the package list from the image and check it, and scan the same image with Trivy:

```bash
heretix-cli collect --image nginx:1.27-alpine3.21 --name nginx-alpine --output sbom.json
heretix-cli check sbom.json --api-url <heretix-api> --api-key <key> --format json > heretix.json
trivy image --image-src remote --scanners vuln --format json -o trivy-all.json nginx:1.27-alpine3.21
trivy image --image-src remote --scanners vuln --ignore-unfixed --format json -o trivy-fixed.json nginx:1.27-alpine3.21
```

The tag `nginx:1.27-alpine3.21` moves when the image is rebuilt; use the digest in the setup table to scan the same one. Key both result sets by (package, CVE) and take the set differences. For heretix-api, a result's `externalId` is the CVE, or its `aliases` contain it; a Trivy row's `VulnerabilityID` is the CVE, with a `_1` or `_2` suffix where Alpine's database lists a CVE twice. For each row in a difference, look up the source package, then the record for `Alpine:v3.21` in OSV and in Alpine's security database.
