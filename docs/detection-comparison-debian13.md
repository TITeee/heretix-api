# Debian 13 detection comparison: heretix-api and Trivy

One Debian 13 host scanned with both heretix-api and [Trivy](https://trivy.dev/). The two tools were given the same installed packages, and every difference between their findings was checked against the Debian security tracker and OSV.

**Measured on 2026-10-23, with the heretix-cli 0.5.3 run added on 2026-10-24.** Both tools depend on data that changes daily, so a later run can give different numbers. This is one host and one distribution, so read it as a worked example of how the two sources differ, not as a general detection rate. The [RHEL 9 comparison](detection-comparison-rhel9.md) does the same for Red Hat, and [ACCURACY.md](../ACCURACY.md) has the per-product precision and recall sweeps.

- [Summary](#summary)
- [Setup](#setup)
- [Results](#results)
- [Where the tools differed, and what was fixed](#where-the-tools-differed-and-what-was-fixed)
- [What remains](#what-remains)
- [How the differences were checked](#how-the-differences-were-checked)
- [Limits](#limits)
- [Reproducing it](#reproducing-it)

## Summary

- On the 337 dpkg packages of the host, the two tools report the same finding for 1,673 of Trivy's 1,684 package-CVE rows (99.3%). Of the 739 rows that have a fixed version, 734 agree, and on every one of them the fixed version is the same.
- The first run agreed on 67.7% of Trivy's rows. Comparing them found two defects in heretix-api, both fixed:
  - its daily OSV import for Debian read a file OSV had stopped updating in October 2024, so no Debian record had been updated since the first import ([#129](https://github.com/TITeee/heretix-api/pull/129); Ubuntu and Alpine had the same problem, [#130](https://github.com/TITeee/heretix-api/pull/130));
  - it compared a binary package's own version with advisories that give source package versions, so `bsdutils` and `login`, built from `util-linux`, were taken as fixed before their fix ([#131](https://github.com/TITeee/heretix-api/pull/131), with heretix-cli 0.5.2).
- The 11 rows only Trivy reports are Debian issues without a CVE number (`TEMP-*` and two CVE-less DSAs), which OSV does not publish.
- The 10 rows only heretix-api reports are 6 that the Debian tracker has not yet decided on, which heretix-api reports and Trivy leaves out, and 4 where OSV still lists Debian 13 as affected after the tracker changed it to not affected.
- With heretix-cli 0.5.3, heretix-api also reports the host's kernel and boot loaders, which Trivy does not: 6,196 kernel rows and 11 more on `grub-efi-amd64-signed`, `shim-signed` and `shim-helpers-amd64-signed`. All but one of the kernel rows match the Debian security tracker or OSV (see [The signed kernel and boot loaders](#the-kernel-and-the-boot-loaders-heretix-cli-053)).

## Setup

| | |
|---|---|
| Host | Debian 13.4 (trixie) on AWS EC2, from Debian's official AMI. Kernel `6.12.74+deb13+1-cloud-amd64` |
| Packages | 337 installed dpkg packages, from the host's `/var/lib/dpkg/status` (copied on 2026-10-23 08:38 UTC) |
| Trivy | 0.74.0, `rootfs --scanners vuln --pkg-types os`, with its defaults (unfixed findings included) and again with `--ignore-unfixed`. Vulnerability database (schema version 2) updated 2026-10-23 07:12 UTC, downloaded just before the scan |
| heretix-api | `618c709` (#131). OSV `Debian` bucket imported up to 2026-10-23; Debian security tracker imported 2026-10-23 08:41 UTC. The 0.5.3 run used the same instance on 2026-10-24, after its daily OSV imports |
| heretix-cli | 0.5.2 for the first three runs, 0.5.3 for the last. Its dpkg collector read the same status file to produce the CycloneDX SBOM, and `check` sent it to heretix-api |

Both tools read the same status file, laid out as a root filesystem. The host's `apt list --upgradable` listed nothing, but both tools report 739 findings that have a fixed version newer than the installed one, so the package lists on the host were evidently not current: the host was behind on updates.

The unit of comparison is the row (installed package name, CVE). Both tools list each binary package separately, so a CVE in `util-linux` yields a row for every installed package built from it. The 31 PyPI packages on the host are all installed by `python3-*` Debian packages, which carry their findings, so the comparison covers dpkg packages only.

## Results

| | First run | After #129/#130 | After #131 | With cli 0.5.3 |
|---|---:|---:|---:|---:|
| Trivy rows | 1,684 | 1,684 | 1,684 | 1,684 |
| heretix-api rows | 1,152 | 1,669 | 1,683 | 7,896 |
| Rows in both | 1,140 | 1,659 | 1,673 | 1,673 |
| Only Trivy | 544 | 25 | 11 | 11 |
| Only heretix-api | 12 | 10 | 10 | 6,223 |
| Agreement, as a share of Trivy's rows | 67.7% | 98.5% | 99.3% | 99.3% |
| Distinct CVEs, Trivy / heretix-api | 700 / 456 | 700 / 697 | 700 / 697 | 700 / 6,896 |
| Distinct CVEs in both | 452 | 692 | 692 | 692 |

The last column adds the kernel and the boot loaders: of its 6,223 rows only heretix-api reports, 6,196 are on the kernel package and 11 on the signed boot loaders. The packages Trivy also covers are unchanged (700 distinct CVEs on both sides, 692 shared).

Rows with a fixed version (`--ignore-unfixed` for Trivy, rows with a `fixedVersion` for heretix-api):

| | First run | After #129/#130 | After #131 | With cli 0.5.3 |
|---|---:|---:|---:|---:|
| Trivy rows | 739 | 739 | 739 | 739 |
| heretix-api rows | 408 | 720 | 734 | 6,079 |
| Only Trivy | 331 | 19 | 5 | 5 |
| Agreement | 55.2% | 97.4% | 99.3% | 99.3% |

Other comparisons on the rows both tools report, after #131:

- **Fix version.** All 734 rows that both tools report with a fixed version agree on it. In the first run, 177 further rows were reported by both tools, but by heretix-api without the fix it had not imported.
- **Severity.** Trivy rates a Debian finding with Debian's urgency where the tracker gives one (263 shared rows), otherwise with NVD's (409) or not at all (1,001). heretix-api returns Debian's urgency as `distroPriority`. Where Trivy's rating is Debian's, the two match on 261 of 263 rows; on the other 2, Trivy has `LOW` where heretix-api has `not yet assigned`.
- **Status.** heretix-api labels an unfixed finding with the tracker's handling as `fixStatus`: `deferred` 509, `affected` 417, `will_not_fix` 13, `under_investigation` 6, none 4. heretix-api counts the tracker's `no-dsa` as `deferred` (Debian has decided to fix it in a later point release, if at all), while Trivy reports most of those as `affected` (its `fix_deferred` has 17 rows), so the two tools label the same rows differently even where they agree on the rows.

## Where the tools differed, and what was fixed

### 544 rows only Trivy reported, and 177 without their fix (#129, #130)

OSV publishes its records in one file per ecosystem. Until October 2024 Debian, Ubuntu and Alpine had one file per release (`Debian:13/all.zip`). OSV then moved every release into one file per distribution (`Debian/all.zip`) and stopped writing the old ones, which still answer. heretix-api's daily import kept reading `Debian:13/all.zip`, found nothing new each day and reported success, so after its first import no Debian record was updated. For example, OSV has recorded the fix `2.41.5-0+deb13u1` for `DEBIAN-CVE-2026-53612` (`util-linux`) since 2026-10-15; heretix-api still had the record without a fix.

#129 reads Debian and Alpine from the shared files, and #130 does the same for Ubuntu. A job now fails, instead of reporting success, when its file is missing, empty or no longer updated, and `pnpm validate:osv-buckets` checks every file the jobs would read. After a backfill of the missed records, the difference fell to 25 rows only Trivy reported.

### 14 rows on `bsdutils` and `login` (#131)

Debian's advisories give **source** package versions; an installed package is a **binary** package, and its version can differ from its source's:

| Binary | Binary version | Source | Source version |
|---|---|---|---|
| `bsdutils` | `1:2.41-5` | `util-linux` | `2.41-5` |
| `login` | `1:4.16.0-2+really2.41-5` | `util-linux` | `2.41-5` |
| `dmsetup` | `2:1.02.205-2` | `lvm2` | `2.03.31-2` |

heretix-api compared the binary's version with the fixed source version `2.41.5-0+deb13u1`. Both `bsdutils` and `login` sort above it, so 7 CVEs fixed in that version were taken as fixed on each. Trivy compares the source version that dpkg records (`Source: util-linux (2.41-5)`).

With #131, heretix-cli 0.5.2 sends the source package and its version, and heretix-api compares the source version for Debian, Ubuntu and Alpine. Dropping the binary's epoch instead was tried and rejected: it fixes `bsdutils`, not `login`, and makes `dmsetup` match `lvm2` advisories that do not apply to it. In Debian 13 (main, amd64), about 5.5% of binary packages (3,796 of 68,825) have a version that differs from their source's by more than a binary rebuild suffix (`+b1`).

The same change lets an Ubuntu or Alpine binary named unlike its source (`libssl3` from `openssl`) be found at all; before it, only Debian's binary names were resolved to source names. That does not show here, since the host runs Debian.

### The kernel and the boot loaders (heretix-cli 0.5.3)

The host's kernel `linux-image-6.12.74+deb13+1-cloud-amd64` and its boot loaders are signed binaries. Debian builds them from a template source that carries no code (`linux-signed-amd64`, `grub-efi-amd64-signed`, `shim-signed`, `fwupd-amd64-signed`, ...): the template signs a binary an unsigned source already built and names that source in `Built-Using` (`linux (= 6.12.74-2)`). Debian and OSV file the advisories under the unsigned source, so a package sent as `linux-signed-amd64` matched none of them, and neither tool reported a kernel CVE in the first runs.

heretix-cli 0.5.3 sends, for a package whose source name contains `-signed` and whose `Built-Using` names exactly one source, that source and version (`linux` `6.12.74-2`). Other packages use `Built-Using` for what they link in statically, which advisories do not name them by, and are left alone. Trivy still reports none of these.

The 6,196 kernel rows, checked against the Debian security tracker (fetched 2026-10-23) and OSV:

| What the data says for trixie | Rows |
|---|---:|
| Resolved in a version newer than the installed 6.12.74-2 (tracker) | 5,212 |
| Not fixed yet: `open` or `undetermined` (tracker) | 802 |
| Records newer than the tracker snapshot: OSV lists Debian 13 as fixed in a later version (`6.12.111-1`) | 133 |
| Records newer than the tracker snapshot: OSV lists Debian 13 as affected, no fix | 48 |
| Resolved with fixed version `0`, which means not affected | 1 |

The host is behind on updates, so most kernel CVEs are ones a newer `linux` package already fixes; the last row is a false positive of the same kind as the four below. The 11 boot loader rows are `grub-efi-amd64-signed` (9 CVEs, the tracker has them `open` for trixie) and `shim-signed` and `shim-helpers-amd64-signed` (CVE-2026-19411, `open`).

The comparison the rest of this page makes cannot check these rows against Trivy, because Trivy reports none. They show what the signed-template fix adds, not an agreement between tools.

## What remains

### Only Trivy: 11 rows

| ID | Packages | Rows | Why heretix-api does not report it |
|---|---|---:|---|
| `TEMP-*` (open) | `bash`, `groff-base`, `login.defs`, `passwd`, `sysvinit-utils`, `tar` | 6 | The tracker's temporary ID for an issue with no CVE number yet. Five rows are `unimportant`; the sixth (`groff-base`) is a minor issue Debian will not issue an advisory for. OSV publishes no `TEMP-*` record. |
| `TEMP-1147318-639065` (fixed in `5.8.1-1+deb13u2`) | `xz-utils`, `liblzma5` | 2 | Same. |
| `DSA-6549-1` | `xz-utils`, `liblzma5` | 2 | A security advisory with no CVE. OSV has no record of it (`api.osv.dev` answers 404). |
| `DSA-6572-1` | `ca-certificates` | 1 | Same. |

heretix-api takes Debian findings from OSV and uses the tracker only to label them, so an issue that exists only in the tracker cannot be reported from that source.

### Only heretix-api, other than the kernel and boot loaders: 10 rows from the earlier runs, and 6 more in the 0.5.3 run

| CVE | Packages | Rows | What the tracker says for trixie |
|---|---|---:|---|
| CVE-2025-8941 | `libpam0g`, `libpam-modules`, `libpam-modules-bin`, `libpam-runtime` | 4 | `undetermined`: Debian has not yet decided whether the release is affected |
| CVE-2026-112060, CVE-2026-112061 | `librtmp1` | 2 | `undetermined` |
| CVE-2026-106589 | `openssh-client`, `openssh-server`, `openssh-sftp-server` | 3 | Resolved with fixed version `0`, which means not affected |
| CVE-2026-39113 | `libsqlite3-0` | 1 | Resolved with fixed version `0` |

For the first 6, heretix-api reports the finding with `fixStatus: under_investigation`, while Trivy leaves out what the tracker has not decided on. That is a difference of policy, not of matching.

The 6 rows added in the 0.5.3 run are `CVE-2026-114583` on four `python3.13` packages and `CVE-2026-113351` and `CVE-2026-115506` on `libexpat1`. OSV records for them (modified 2026-10-23, after the earlier runs) list Debian 13 as affected with no fix, and the tracker snapshot has no entry for them yet. Trivy's database, downloaded earlier on 2026-10-23, did not have them.

The last 4 of the first 10 are false positives in heretix-api's data: OSV's records (last modified on 2026-10-07 and 2026-09-14) still list Debian 13 as affected with no fix, and the tracker has since marked the release not affected. heretix-api follows OSV, and keeps only the tracker's unresolved entries.

## How the differences were checked

Every row that only one tool reported was compared with the Debian security tracker's data (`https://security-tracker.debian.org/tracker/data/json`, fetched on 2026-10-23) for the source package and `trixie`, and with the CVE's OSV record (`https://api.osv.dev/v1/vulns/DEBIAN-<cve>`). The source package of each binary was taken from the host's dpkg status file.

For the defects above, the check went one step further: the fix in the first came from comparing heretix-api's stored records with OSV's current ones, and the fix in the second from the dpkg status file's source versions.

It is a check against Debian's and OSV's published data, not against the running system, so it shows agreement with their statements and does not by itself prove exploitability.

## Limits

- One host, one release (Debian 13.4), and a small cloud image (337 packages). Results for other releases, or for hosts with more packages, will differ.
- **Trivy reports no kernel or boot loader CVE for this host.** It takes the installed kernel as built from `linux-signed-amd64`, while Debian and OSV record kernel CVEs under `linux`. heretix-cli 0.5.3 maps the signed template to its source; the 6,196 + 11 rows it adds are checked against the tracker and OSV above, and not against Trivy.
- The 0.5.3 run happened a day after the others, on the same host data and the same Trivy and tracker snapshots but a heretix-api whose OSV data had moved on, which is why 6 non-kernel rows differ from the 10 before.
- Both tools take the same packages from the status file. Language packages installed outside dpkg (pip, npm) were not part of this comparison.
- A scan is a snapshot. OSV and the tracker are revised continually and do not always agree; the 4 false positives above come from that alone.
- Trivy was run once, with the database current on the scan date.

## Reproducing it

On the host:

```bash
trivy rootfs --scanners vuln --pkg-types os --format json -o trivy-all.json /                    # unfixed findings included
trivy rootfs --scanners vuln --pkg-types os --ignore-unfixed --format json -o trivy-fixed.json /
heretix-cli collect --only dpkg --output sbom.json                                               # 0.5.3 or later
heretix-cli check sbom.json --api-url <heretix-api> --api-key <key> --severity 0 --format json > heretix.json
```

Then key both result sets by (package, CVE) and take the set differences. For heretix-api, a result's `externalId` is the CVE, or its `aliases` contain it; a Trivy row's `VulnerabilityID` is the CVE, a `TEMP-*` ID or a DSA. For each row in a difference, look up the source package in `/var/lib/dpkg/status` and check the tracker's entry for it and `trixie`, and the OSV record.
