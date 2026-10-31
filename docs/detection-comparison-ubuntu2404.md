# Ubuntu 24.04 detection comparison: heretix-api and Trivy

One Ubuntu 24.04 host scanned with both heretix-api and [Trivy](https://trivy.dev/). The two tools were given the same installed packages, and every difference between their findings was checked against the Ubuntu CVE Tracker statuses that heretix-api holds, OSV, and the host's own `apt list --upgradable`.

**Measured on 2026-10-31.** Both tools depend on data that changes daily, so a later run can give different numbers. This is one host and one distribution, so read it as a worked example of how the two sources differ, not as a general detection rate. The [Debian 13 comparison](detection-comparison-debian13.md) and the [RHEL 9 comparison](detection-comparison-rhel9.md) do the same for those distributions, and [ACCURACY.md](../ACCURACY.md) has the per-product precision and recall sweeps.

- [Summary](#summary)
- [Setup](#setup)
- [Results](#results)
- [Where the tools differed, and what was fixed](#where-the-tools-differed-and-what-was-fixed)
- [What remains](#what-remains)
- [How the differences were checked](#how-the-differences-were-checked)
- [Limits](#limits)
- [Reproducing it](#reproducing-it)

## Summary

- On the 651 dpkg packages of the host, heretix-api reports every one of Trivy's 20,604 package-CVE rows (100%). Trivy reports 6 rows that have a fixed version; heretix-api reports all 6, with the same fixed version on each.
- The first run found one defect in heretix-api, now fixed ([#144](https://github.com/TITeee/heretix-api/pull/144)): the meta package `linux-aws`, which ships no code, was matched against the records of an unrelated source of the same name, the 6.8-series kernel. That gave it 3,209 findings, 519 of them CVEs that exist only for the older series.
- No row is reported only by Trivy.
- heretix-api reports 4,213 rows Trivy does not:
  - 3,459 on the signed kernel image `linux-image-7.0.0-1014-aws`, which Trivy reports nothing for. Every one is a CVE Trivy reports on `linux-modules-7.0.0-1014-aws`, built from the same source;
  - 706 that the Ubuntu CVE Tracker has not triaged (`needs-triage`, 625) or marked `ignored` (81). heretix-api reports them with a `fixStatus`, and Trivy leaves them out;
  - 4 security updates that carry no CVE number (USNs), all four on the host's list of upgradable packages;
  - 43 from OSV records that the tracker data held by heretix-api has no entry for, and 1 `deferred` finding Trivy's database does not have. These 44 are not verified against Ubuntu.

## Setup

| | |
|---|---|
| Host | Ubuntu 24.04.5 LTS (noble) on AWS EC2, not upgraded after launch. Kernel `7.0.0-1014-aws`. Ubuntu Pro not attached |
| Packages | 651 installed dpkg packages, from the host's `/var/lib/dpkg/status` (copied on 2026-10-31). `apt list --upgradable` lists 18 |
| Trivy | 0.74.0, `rootfs --scanners vuln`, with its defaults (unfixed findings included) and again with `--ignore-unfixed`. Vulnerability database (schema version 2) updated 2026-10-31 07:07 UTC, downloaded just before the scan |
| heretix-api | `4dab304` (#144). The `osv-Ubuntu` job was run again on 2026-10-31 at 09:50 UTC, before the final run |
| heretix-cli | `421d7d2` (main after 0.5.3), run on the host as `heretix-cli collect --only dpkg`, then `check` against heretix-api. The SBOM carries the source package and its version for each package |

Trivy did not recognise the distribution from `/etc/os-release` alone: on a root filesystem laid out from copied files it reported `Unsupported os` and found nothing until `/etc/lsb-release` was there too; one was written from the host's `os-release` values (`DISTRIB_ID=Ubuntu`, `DISTRIB_RELEASE=24.04`).

The unit of comparison is the row (installed package name, CVE). Both tools list each binary package separately, so a CVE in a source package yields a row for every installed package built from it. Packages installed outside dpkg were not part of this comparison.

## Results

| | First run | Final run |
|---|---:|---:|
| Trivy rows | 20,604 | 20,604 |
| heretix-api rows | 28,021 | 24,817 |
| Rows in both | 20,604 | 20,604 |
| Only Trivy | 0 | 0 |
| Only heretix-api | 7,417 | 4,213 |
| Agreement, as a share of Trivy's rows | 100% | 100% |

The final run differs from the first by two things: #144 removed 3,209 rows, and the refreshed OSV import added 5. In the final run the tools cover 4,051 distinct CVEs in common, and heretix-api reports 4,356 in all.

Rows with a fixed version (`--ignore-unfixed` for Trivy, rows with a `fixedVersion` for heretix-api):

| | Trivy | heretix-api |
|---|---:|---:|
| Rows | 6 | 10 |
| In both | 6 | 6 |
| Only this tool | 0 | 4 |

Other comparisons on the rows both tools report:

- **Fix version.** The 6 rows that both tools report with a fixed version agree on it (`libbrotli1`, `zlib1g` and four on `python3-jwt`).
- **Severity.** Trivy rates an Ubuntu finding with Ubuntu's priority. heretix-api returns it as `distroPriority`, and the two agree on every one of the 20,604 rows: 106 rows that Ubuntu calls `negligible` are `LOW` for Trivy.
- **Status.** heretix-api labels an unfixed finding with the tracker's handling as `fixStatus`: `affected` 18,593 and `deferred` 170 on the shared rows, and none on 1,841 (the OSV record says unfixed, and the tracker data held by heretix-api has no entry). Trivy reports 20,598 of the shared rows as `affected` and 6 as `fixed`, so the two tools label the 170 deferred rows differently even where they agree on the rows.

## Where the tools differed, and what was fixed

### 3,209 rows on the meta package `linux-aws` (#144)

The host's kernel meta package `linux-aws` depends on the current kernel; it is built from the source `linux-meta-aws-7.0` and ships no code. A source of the same name, `linux-aws`, also exists: Ubuntu's 6.8-series kernel for 24.04.

heretix-api searched an Ubuntu package under its own name as well as under the source package the client sent. The meta package was therefore matched against the records of the 6.8-series source:

| | |
|---|---:|
| Findings on `linux-aws` | 3,209 |
| Labelled `affected`, from the tracker entries of source `linux-aws` | 2,915 |
| CVEs not on the 7.0 kernel (`linux-modules-7.0.0-1014-aws`) at all | 519 |

When the client names the source, heretix-api now searches that source only (and, for Debian, the source its binary-to-source mapping gives). A client that sends no source is searched under the binary name, as before. A rerun on the same package list removed the 3,209 rows and changed nothing else.

## What remains

### Only Trivy: none

### Only heretix-api: 4,213 rows

| What | Rows | Notes |
|---|---:|---|
| Signed kernel image `linux-image-7.0.0-1014-aws` | 3,459 | Ubuntu builds the image from a template source that carries no code (`linux-signed-aws-7.0`) and files the advisories under the source it signs (`linux-aws-7.0`, named in `Built-Using`). heretix-cli sends that source and version, as it does for Debian's signed kernels, so the image is checked like the other kernel packages. Trivy reports no finding on the image. All 3,459 CVEs are ones Trivy reports on `linux-modules-7.0.0-1014-aws`, which comes from the same source and version |
| Tracker status `needs-triage` | 625 | Ubuntu has not yet decided whether the release is affected. heretix-api reports it with `fixStatus: under_investigation`; Trivy does not report them |
| Tracker status `ignored` | 81 | Ubuntu will not fix it. heretix-api reports it with `fixStatus: will_not_fix` |
| Security updates without a CVE number | 4 | USN-8945-1 on `liblzma5` and `xz-utils`, USN-8947-1 on `libnss3`, USN-8944-1 on `ca-certificates`. Trivy reports none of them; the USNs carry no CVE number |
| OSV record, no entry in the tracker data held by heretix-api | 43 | See below |
| `deferred` in the tracker, not in Trivy's database | 1 | `CVE-2026-9375` on `python3-urllib3` (`HIGH`) |

The first two rows are a difference of policy, not of matching. The security updates are real: all four are on the host's `apt list --upgradable` with the same newer version (for example `5.6.1+really5.4.5-1ubuntu0.4` for `liblzma5` and `xz-utils`).

The 43 OSV-only rows are on `python3.12` and its libraries, `open-iscsi`, `python3-twisted`, `python3-oauthlib`, `python3-pyasn1`, `libexpat1`, `gpgconf` and `patch`. Their OSV records list the affected versions of the source explicitly, with no fixed version, and the tracker data held by heretix-api has no entry for them. Whether Ubuntu has since added one, or the records are ahead of or behind the tracker, was not established, so these are not counted as matches or as false positives.

Of the 18 packages `apt list --upgradable` lists, 7 are in a finding with a fixed version in heretix-api (`libbrotli1`, `zlib1g`, `python3-jwt`, `liblzma5`, `xz-utils`, `libnss3`, `ca-certificates`) and 3 in Trivy's. The other 11 (among them `git`, `libglib2.0-0t64`, `tmux` and `cloud-init`) have no finding with a fixed version in either tool.

## How the differences were checked

Every row that only heretix-api reported was classified by the Ubuntu CVE Tracker status that heretix-api holds for its source package and CVE (`needed`, `pending`, `deferred`, `needs-triage`, `ignored`, or no entry), and by the CVE's OSV record. The source package of each binary was taken from the host's dpkg status file. The security updates were compared with the host's `apt list --upgradable`, and the signed kernel image with the CVEs Trivy reports on the other binary built from the same source.

It is a check against Ubuntu's and OSV's published data, not against the running system, so it shows agreement with their statements and does not by itself prove exploitability.

## Limits

- One host, one release (Ubuntu 24.04.5), and a small cloud image (651 packages). Results for other releases, for LTS releases with Ubuntu Pro (ESM) or for hosts with more packages will differ.
- Ubuntu Pro was not attached. heretix-api searched the `Ubuntu:24.04:LTS` records, and the Pro (ESM) records are separate; this run does not show how either tool treats them.
- Neither tool's rows were checked against Ubuntu's own security pages one by one; the 43 OSV-only rows in particular are unverified.
- The 11 upgradable packages with no finding were not examined. Their updates may carry fixes the tracker does not list, or none.
- A scan is a snapshot. OSV and the tracker are revised continually and do not always agree.
- Trivy was run once, with the database current on the scan date.

## Reproducing it

On the host, copy `/var/lib/dpkg/status`, `/etc/os-release` and the output of `apt list --upgradable`, then run heretix-cli:

```bash
heretix-cli collect --only dpkg --output sbom.json                                               # 0.5.3 or later
```

Lay the copied files out as a root filesystem (`etc/os-release`, `etc/lsb-release`, `var/lib/dpkg/status`) and scan it:

```bash
trivy rootfs --scanners vuln --format json -o trivy-all.json rootfs                              # unfixed findings included
trivy rootfs --scanners vuln --ignore-unfixed --format json -o trivy-fixed.json rootfs
heretix-cli check sbom.json --api-url <heretix-api> --api-key <key> --severity 0 --format json > heretix.json
```

Then key both result sets by (package, CVE) and take the set differences. For heretix-api, a result's `externalId` is the CVE, or its `aliases` contain it; a Trivy row's `VulnerabilityID` is the CVE. For each row in a difference, look up the source package in `/var/lib/dpkg/status` and check the tracker status and the OSV record.
