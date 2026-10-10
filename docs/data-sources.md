# Data sources

Each source has an import job that the [scheduler](operations.md#scheduler) runs, and most also have a `pnpm import:*` command for manual runs.

`pnpm import:*` runs the compiled `dist/` output, so run `pnpm build` first. Without a build, use `pnpm exec tsx src/scripts/<script>.ts ...` instead.

- [Choosing what to import](#choosing-what-to-import)
- [NVD](#nvd)
- [OSV](#osv)
- [CISA KEV](#cisa-kev) · [EPSS](#epss) · [CVE Records (CNA) and CISA Vulnrichment](#cve-records-cna-and-cisa-vulnrichment)
- Linux distributions: [Red Hat](#red-hat) · [Oracle Linux](#oracle-linux) · [Debian security tracker](#debian-security-tracker)
- Vendor advisories ([common behavior](architecture.md#vendor-advisories)): [Fortinet](#fortinet) · [Palo Alto Networks](#palo-alto-networks) · [Cisco](#cisco) · [Sophos](#sophos) · [SonicWall](#sonicwall) · [Broadcom / VMware](#broadcom--vmware) · [Oracle Critical Patch Update](#oracle-critical-patch-update) · [Splunk](#splunk) · [Apache HTTP Server](#apache-http-server) · [Apache Tomcat](#apache-tomcat) · [nginx](#nginx) · [Zabbix](#zabbix) · [Check Point](#check-point) · [Ivanti](#ivanti) · [NetScaler](#netscaler)

## Choosing what to import

Import only what you scan. Each source adds import time, disk space and requests to its upstream.

| You scan | Import |
|---|---|
| Anything | NVD, CISA KEV and EPSS. They are the baseline, and the only jobs enabled by default |
| Application dependencies | The OSV ecosystem of each language you use (`npm`, `PyPI`, `Go`, `Maven`, ...), plus `osv-mal` for malicious packages |
| Debian, Ubuntu, Alpine, AlmaLinux or Rocky Linux hosts and images | The OSV ecosystem of each release you run (e.g. `Ubuntu:22.04:LTS`). For Debian, also `debian-tracker` for fix status |
| RHEL hosts and images | Red Hat OVAL for each major you run (`advisory-redhat-rhel9`, `-rhel8`) and Red Hat VEX (`advisory-redhat-vex`; the only source for RHEL 10) |
| Oracle Linux | `advisory-oracle-linux` |
| Network appliances and commercial products | The vendor advisory jobs of the products you run (Fortinet, Palo Alto Networks, Cisco, ...) |
| Products with no dedicated source | CVE Records (`cna`), which carry the affected products declared by each CVE's issuer |

Measured import times: the full NVD mirror takes several hours, and Red Hat VEX about 12 minutes. Other sources depend on their size and upstream response times; the dashboard shows each run's duration.

## NVD

Fetcher: [src/worker/nvd-fetcher.ts](../src/worker/nvd-fetcher.ts). Source: NVD REST API v2.0.

```bash
pnpm import:nvd full                         # Full mirror (~400k CVEs); starts a new job
pnpm import:nvd full <job-id>                # Resume a failed job from its checkpoint
pnpm import:nvd update                       # Changes since the last run
pnpm import:nvd cve CVE-2021-44228           # Single CVE
pnpm import:nvd range 2024-01-01 2024-03-31  # Date range (auto-chunked at NVD's 120-day limit)
```

- The full mirror takes **several hours** (about 6 hours in one measured run). Most of that is downloading pages and writing rows, not the rate limit. `NVD_API_KEY` (50 instead of 10 requests/min) still helps; get a free key at [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key).
- A full import is not resumed automatically. If a page still fails after retries, the job is marked `failed`, the command exits non-zero, and the error message ends with the resume command (`pnpm import:nvd full <job-id>`). A failed job is never used as the starting point of `update`.
- The scheduled job runs `update` every 2 hours.

### CPE mapping

NVD describes affected products as CPE 2.3. The `<product>` field of `cpe:2.3:a:` (application) and `cpe:2.3:o:` (OS) entries becomes the package name, and the ecosystem is inferred from `<vendor>` (`python`/`pypi` → `PyPI`, `nodejs`/`npm` → `npm`, `golang` → `Go`, `rubygems` → `RubyGems`, `redhat`/`almalinux` → `AlmaLinux`). Hardware CPEs (`cpe:2.3:h:`) are skipped. A version written into the CPE itself (`...:product:3.0:*...`) is stored as an exact version.

Old-style CPEs put version detail in the `<update>` field. Two patterns are recovered: `update21` → `1.5.0_21`, and `rc3` → `4.19.0-rc3`. Others are not; see [known-issues.md](known-issues.md#nvd-cpe-update-qualifiers).

### Product name aliases

NVD sometimes uses several CPE product names for one product, e.g. after an acquisition. [src/config/product-aliases.ts](../src/config/product-aliases.ts) maps a search term to all of them:

| Search term | CPE product names searched |
|---|---|
| `nginx` | `nginx`, `nginx_open_source`, `nginx_open_source_subscription` |
| `java` / `jre` / `jdk` | `jre`, `jdk` (`openjdk` is kept separate) |
| `acrobat` / `acrobat_reader` | `acrobat`, `acrobat_dc`, `acrobat_reader`, `acrobat_reader_dc` |
| `httpd` / `http_server` | `httpd`, `http_server` |
| `macos` / `mac_os_x` | `macos`, `mac_os_x` |
| `curl` | `curl`, `libcurl` |
| `postgres` | `postgresql` |
| `k8s` | `kubernetes` |

The file has the full list. Add an alias only after confirming that the target names exist in `NVDAffectedPackage`.

### Product catalog

[src/config/product-catalog.ts](../src/config/product-catalog.ts) lists the products people register by hand (network devices, middleware, tools), each with the vendor and product the data files it under. A client such as heretix-management can offer it as a picker, so a user does not have to know that BIG-IP is `f5` and some ninety `big-ip_…` names in NVD, or that `automation` is both ivanti's and nintex's product.

An entry names its pairs exactly:

| Field | Meaning |
|---|---|
| `name` | Shown, and stored as the package name. Matched case-sensitively; unique; never a `PRODUCT_ALIASES` key |
| `nvd` | NVD CPE `vendor` with exact `products`, or `productPrefixes` (with `excludePrefixes`) for a family NVD splits into many names |
| `cna` | The CVE records' `vendors` (they spell one vendor several ways) and `products` |
| `aliases`, `versionHint` | Other names to find it by; a version as the vendor writes it |

The catalog covers products NVD and the CVE records cover. A product with its own vendor-advisory fetcher is picked from the Advisory list, which searches those advisories only; the two are not merged so that where a result comes from stays visible.

After changing the catalog, run `pnpm build && pnpm validate:catalog`. It checks the catalog's structure and that every listed NVD product, product prefix and CNA vendor or product has rows in the database, and warns about NVD products of a listed vendor that look like a listed one but are not covered (plugins, components and sibling products usually; add one if it is the same product).

## OSV

Fetcher: [src/worker/osv-fetcher.ts](../src/worker/osv-fetcher.ts). Source: the OSV API and its per-ecosystem bulk exports.

```bash
pnpm import:osv ecosystem npm            # Full import of one ecosystem
pnpm import:osv update npm               # Changes since the last run
pnpm import:osv package npm lodash       # One package
pnpm import:osv id GHSA-67hx-6x53-jw92   # One record (OSV or CVE ID)
pnpm import:osv malware                  # All malicious-package entries (ossf/malicious-packages)
pnpm import:osv update malware           # Malware changes since the last run
```

- Ecosystem names are case-sensitive: `npm`, `PyPI`, `Go`, `RubyGems`, `crates.io`, `Packagist`, `Maven`, `NuGet`, `Hex`, `Pub`, `ConanCenter`, `SwiftURL`, `CRAN`, `Linux`, `Android`, `OSS-Fuzz`, `Bitnami`, and distributions (`Debian`, `Ubuntu`, `Alpine`, `AlmaLinux`, `Rocky Linux`, with or without a release suffix).
- Each ecosystem has its own daily job (`osv-<ecosystem>`, 08:00 UTC) that imports records modified since its last completed run. Malware is `osv-mal` (08:30 UTC); it makes one GitHub API call, so set `GITHUB_TOKEN` only if you run it more than 60 times an hour.
- **Adding an ecosystem**: run the full `pnpm import:osv ecosystem <name>` once *before* enabling its daily job. The daily job only picks up records modified after its cursor, so it never backfills older ones. The full import is recorded as an `osv-full-<ecosystem>` job. Check completeness against OSV's live export at any time:
  ```bash
  pnpm validate:osv-coverage            # every tracked ecosystem
  pnpm validate:osv-coverage Go PyPI    # selected ecosystems
  ```
- Only the distro releases in the [support policy](../README.md#supported-os-releases) are maintained. Others are imported and searchable on a best-effort basis.
- Severity: GHSA's `MODERATE` is stored as `MEDIUM`. A CVSS score is computed from OSV's vector when the record has none. Ubuntu priority and Debian urgency are kept per package as `distroPriority`.
- AlmaLinux, Rocky Linux and Alpine data only lists fixed vulnerabilities, so unfixed vulnerabilities on those distributions are not reported.

## CISA KEV

```bash
pnpm import:kev full    # Fetch the catalog and sync the master table
pnpm import:kev stats   # KEV statistics from the DB
```

Sets `isKev` and the `kev*` fields on master rows. The catalog is fully replaced on each run, so entries CISA removes are removed here too. Daily at 09:00 UTC.

## EPSS

```bash
pnpm import:epss full                  # Today's dataset
pnpm import:epss full 2024-03-01       # A specific date
pnpm import:epss cve CVE-2021-44228    # One CVE
```

FIRST.org EPSS (~320,000 CVEs). Sets `epssScore` / `epssPercentile`. Daily at 10:00 UTC.

## CVE Records (CNA) and CISA Vulnrichment

Fetcher: [src/worker/cna-fetcher.ts](../src/worker/cna-fetcher.ts), [src/worker/cna-importer.ts](../src/worker/cna-importer.ts). Source: [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) release bundles.

```bash
pnpm import:cna              # Delta if already bootstrapped, otherwise a full bootstrap
pnpm import:cna --bootstrap  # Force the full bundle (~600 MB)
```

- **CNA-declared affected products** (`containers.cna.affected`) go into their own `CnaVulnerability` / `CnaAffectedProduct` tables. They cover vendors that have no dedicated advisory fetcher. The bootstrap only imports recent years (`BOOTSTRAP_YEARS` in `src/scripts/import-cna.ts`); deltas apply to any year. Ranges that cannot be ordered are not stored: git commit hashes, free text, and NetScaler's branch-plus-build bounds (`14.1` up to `56.73`, which read as 14.1.0 up to 56.73.0 and flagged the fixed builds).
- **CISA Vulnrichment SSVC** (`containers.adp`, the CISA-ADP entry): exploitation (none/poc/active), automatable (yes/no) and technical impact (partial/total). Stored on the master row and returned by `GET /vulnerabilities/:id`. No final SSVC decision is computed, since that needs the consumer's own mission impact. SSVC is backfilled from every year in the bundle.
- The daily delta runs at 15:30 UTC. No API key or rate limit.

## Red Hat

| Data | Fetcher | Job | Covers |
|---|---|---|---|
| OVAL patch definitions | [redhat-fetcher.ts](../src/worker/redhat-fetcher.ts) | `advisory-redhat-rhel9` / `-rhel8` (13:15 / 13:30 UTC) | Fixed CVEs on RHEL 8 and 9 |
| CSAF VEX archive | [redhat-vex-fetcher.ts](../src/worker/redhat-vex-fetcher.ts) | `advisory-redhat-vex` (15:00 UTC) | Unfixed CVEs on RHEL 8, 9 and 10, plus fixed CVEs on RHEL 10 |

```bash
pnpm import:redhat          # OVAL, RHEL 9 and 8
pnpm import:redhat rhel9    # OVAL, RHEL 9 only
pnpm import:redhat-vex      # VEX archive (~12 minutes)
```

Search with `ecosystem=Red Hat:<major>` (`Red Hat:9`, `Red Hat:10`); versions are compared with `rpmvercmp`, epoch included.

**OVAL** only describes CVEs that have a released fix. Each `"<package> is earlier than <version>"` criterion becomes a row with that fixed version as its upper bound. Rows are keyed per major release (`red-hat-9`), so one release's fixes are never compared against another release's packages.

**DNF module streams** (e.g. `postgresql:15` and `postgresql:16` side by side) are handled by reading the OVAL `Module <name>:<stream> is enabled` criterion and using the stream as a lower bound. A fix for one stream then cannot match another stream's packages. A stream label that cannot be a version floor (e.g. `javapackages-tools:201801`) is ignored. For advisories with no module criterion, `nodejs`, `postgresql`, `httpd` and the `mysql`/`mariadb`/`php` families fall back to a per-product floor ([advisory-helpers.ts](../src/worker/advisory-helpers.ts)). Other products are not covered; see [known-issues.md](known-issues.md#rhel--oracle-linux-module-streams).

**VEX** fills in what OVAL cannot express:
- Packages that are `known_affected` or `under_investigation` with no fix become rows with `patchAvailable: false`, which match every version. Red Hat's reason for the missing fix is returned as `fixStatus`.
- VEX says "unfixed" per major release but "fixed" per release stream. An unfixed row is therefore bounded by the newest fix the same document records for that major.
- **RHEL 10 has no OVAL feed at all** (Red Hat's OVAL v2 tree stops at RHEL 9). For RHEL 10 only, every fixed package also gets a `patchAvailable: true` row bounded by its newest fixed build across release streams. Debug packages are skipped.
- A source RPM name (`sed.src`) is mapped to its installable name (`sed`).
- Only RHEL 8, 9 and 10 are read from the archive, which covers every Red Hat product back to RHEL 5.

## Oracle Linux

Fetcher: [src/worker/oracle-linux-fetcher.ts](../src/worker/oracle-linux-fetcher.ts). Source: Oracle's ELSA OVAL feed.

```bash
pnpm import:oracle-linux       # All releases
pnpm import:oracle-linux ol9   # One release
```

Parsed like Red Hat's OVAL, with the same epoch-preserving fixed versions and module-stream handling. Search with `ecosystem=Oracle Linux:<major>`. There is no unfixed-CVE data for Oracle Linux; see [known-issues.md](known-issues.md#oracle-linux-has-no-unfixed-cve-data). Daily at 11:45 UTC.

## Debian security tracker

Fetcher: [src/worker/debian-tracker-fetcher.ts](../src/worker/debian-tracker-fetcher.ts). Source: the tracker's JSON export (~80 MB). Job `debian-tracker`, daily at 07:15 UTC.

Matching stays on OSV's Debian data. The tracker only adds `fixStatus` to unfixed Debian matches: `no-dsa`, `postponed`, `ignored`, `end-of-life` and `undetermined`, with the tag and note in `fixStatusDetail`. Only unresolved entries are stored, and they are fully replaced on each run. Debian 11 is not in the export.

A separate weekly job (`debian-source-packages`, Sunday 07:00 UTC) maps Debian binary package names to source package names for matching.

## Fortinet

[fortinet-fetcher.ts](../src/worker/fortinet-fetcher.ts) · `pnpm import:fortinet` · daily 11:00 UTC

Pages through the full PSIRT advisory listing and reads each advisory's CSAF 2.0 document. No authentication. Covers FortiOS, FortiProxy, FortiManager, FortiAnalyzer and more, with one row per version branch (7.6.x, 7.4.x, ...).

## Palo Alto Networks

[pan-fetcher.ts](../src/worker/pan-fetcher.ts) · `pnpm import:pan` · daily 11:15 UTC

RSS plus CSAF JSON. No authentication. Covers PAN-OS, Prisma Access, Cortex XDR and more.
- Every `vers:generic/` bound is read as a fix point and expanded into one range per branch and maintenance release. PAN fixes each maintenance release with its own hotfix. For CVE-2025-0126, PAN-OS 10.2 becomes `[10.2.0, 10.2.4-h25)`, `[10.2.5, 10.2.9-h13)` and `[10.2.10, 10.2.10-h6)`.
- Versions are compared with a PAN-specific ordering ([pan-version.ts](../src/utils/pan-version.ts)), in which `10.2.9-h1` is the hotfix *after* 10.2.9.
- `known_affected` entries such as `PAN-OS None` mean "not affected" and are skipped.

## Cisco

[cisco-fetcher.ts](../src/worker/cisco-fetcher.ts) · `pnpm import:cisco` (all) / `pnpm import:cisco latest` (latest 100) · daily 11:30 UTC

openVuln API with OAuth 2.0 (`CISCO_CLIENT_ID` / `CISCO_CLIENT_SECRET`) plus CSAF JSON. Covers IOS XE, NX-OS, ASA, FTD and more.

## Sophos

[sophos-fetcher.ts](../src/worker/sophos-fetcher.ts) · `pnpm import:sophos` · daily 12:00 UTC

Advisory IDs from the sitemap, enriched from RSS, with a headless browser for pages whose title has no CVE. Only CVE IDs and severity are available, with no version ranges; see [known-issues.md](known-issues.md#sophos-advisories-have-no-version-ranges).

## SonicWall

[sonicwall-fetcher.ts](../src/worker/sonicwall-fetcher.ts) · `pnpm import:sonicwall` · daily 12:15 UTC

The public JSON API behind SonicWall's PSIRT site (~200 advisories): CVE, severity, CVSS and product families, with versions taken best-effort from the product tables. Covers SonicOS Gen5–8 and SMA.

## Broadcom / VMware

[broadcom-fetcher.ts](../src/worker/broadcom-fetcher.ts) · `pnpm import:broadcom` · daily 13:00 UTC

The advisory list comes from the support portal's JSON API, and each detail page is rendered with Playwright to read its Response Matrix (affected/fixed versions, one row per product and CVE). VMware update levels are normalized (`8.0 U3d` → `8.0.3-4`), so `version=8.0+U3d` works. Covers vCenter, ESXi, NSX, Aria, Horizon and more. Older advisories use a different table format that is not parsed.

## Oracle Critical Patch Update

[oracle-cpu-fetcher.ts](../src/worker/oracle-cpu-fetcher.ts) · `pnpm import:oracle-cpu` (all) / `latest` · daily 12:30 UTC

Quarterly CPUs back to January 2020, discovered from Oracle's RSS. CSAF 2.0 is read from April 2022 onward, and CVRF 1.1 for earlier quarters. Each CPU is split into one advisory per CVE (`cpuapr2026-CVE-...`). This covers Oracle software (MySQL, Java SE, WebLogic, ...), not Oracle Linux packages.

## Splunk

[splunk-fetcher.ts](../src/worker/splunk-fetcher.ts) · `pnpm import:splunk` · daily 13:45 UTC

The full advisory archive table (300+ advisories): CVE, CVSS, per-branch affected/fixed versions, solution and mitigations. Each product branch is a separate row.

## Apache HTTP Server

[apache-fetcher.ts](../src/worker/apache-fetcher.ts) · `pnpm import:apache` · daily 14:00 UTC

The official 2.4 vulnerabilities page. "Affects" notations (`before X`, `through X`, `>=X, <=Y`, version lists) become ranges. 2.4.x only.

## Apache Tomcat

[tomcat-fetcher.ts](../src/worker/tomcat-fetcher.ts) · `pnpm import:tomcat` · daily 14:30 UTC

One security page per major branch. A CVE affecting several branches becomes one advisory with one row per branch. CVE IDs are read from advisory headings only.

## nginx

[nginx-fetcher.ts](../src/worker/nginx-fetcher.ts) · `pnpm import:nginx` · daily 14:45 UTC

The official security advisories page. Multi-range notation (`0.6.18-1.25.2, 1.21.0-1.25.1`) becomes one row per range.

## Zabbix

[zabbix-fetcher.ts](../src/worker/zabbix-fetcher.ts) · `pnpm import:zabbix` · daily 14:15 UTC

The search API behind zabbix.com's advisory page. Reads the CVE, Zabbix's own ZBV ID, severity, CVSS and affected/fixed versions. Ranges (`6.0.0-6.0.44`), exact versions and wildcards (`4.4.4-4.4.*`) are handled; free-text entries are skipped.

## Check Point

[checkpoint-fetcher.ts](../src/worker/checkpoint-fetcher.ts) · `pnpm import:checkpoint` · daily 16:00 UTC

The JSON API used by Check Point's advisory page, plus each sk article for its solution and mitigation. Each product row pairs a release line (`R81.20`) with a range of Jumbo Hotfix takes. An sk article covering several CVEs becomes one advisory per CVE (`<skId>/<cveId>`).

| `affected` | Stored as |
|---|---|
| `Prior to JHF Take N`, `Below take N` | Fixed in take N (`fixedVersion`) |
| `Take N or below`, `Take N or lower` | Affected up to take N; no fixed take stated |
| `All`, `Details in SK` | The whole release line is affected; no fixed take in the feed |
| `None`, "Not Check Point's product CVE" | Not affected: no row |

On an end-of-support line (`R80.40 (EOS)`) with no fixed take, the row carries `fixStatus: out_of_support`, since Check Point does not fix those lines. Harmony Endpoint `E8x.x` builds, SmartConsole and Quantum Spark build numbers, hardware/cloud rows and bare-number ranges are skipped rather than guessed.

## Ivanti

[ivanti-fetcher.ts](../src/worker/ivanti-fetcher.ts) · `pnpm import:ivanti` · daily 16:30 UTC

Ivanti publishes its advisories as knowledge articles on the Innovators Hub (hub.ivanti.com, a Salesforce community). The pages are rendered in the browser, so a headless browser renders each one. The sitemap lists the articles, and those whose name contains `Security-Advisory` are fetched. Each has a CVE table (score, vector) and an "Affected Versions" table with the affected and resolved versions per product. An article covering several CVEs becomes one advisory per CVE (`<article>/<cveId>`).

| Affected version | Stored as |
|---|---|
| `22.7R2.5 and prior`, `and below`, `and previous` | Affected up to that version |
| `22.7R2 through 22.7R2.4` | Affected range |
| `Prior to X`, `All versions before X`, `5.1 versions prior to 5.1.2` | Affected below X |
| `2025.2, 2025.3` | The listed releases, spanned up to the fix |

A resolved version is paired with the affected versions of its own release line (major.minor), so Sentry's `R10.8.1 and prior` / `R10.7.2 and prior` with `R10.8.2` / `R10.7.3` gives one range per line. Versions use Ivanti's own ordering (`22.7R2.5`, `R10.8.1`, 4-component `12.7.0.1`, Endpoint Manager `2024 SU4 SR1`), because the generic encoding drops the 4th component, which is where EPMM's fix boundary is.

Older advisories are not in this template and are kept as data in [ivanti-legacy-advisories.ts](../src/worker/ivanti-legacy-advisories.ts), each read once from its article: the Pulse Secure bulletins from 2019 on that name a version (SA44019 to SA45520, 14 of them), the January 2024 Connect Secure articles (CVE-2023-46805, CVE-2024-21887, CVE-2024-21888, CVE-2024-21893) and the Sentry article for CVE-2023-38035. Their versions sit in prose, in lists inside a sentence, or in tables of a different shape, and they no longer change. Bulletins from 2018 and earlier are left out (end-of-support products), as are those that name no version (products "Not Vulnerable" or "Vulnerable" with no release). A January 2024 patch is a rebuild of an R-train: `9.1R18.4` fixes train 9.1R18, and the first build of a train (`22.2R3`) fixes the line before it.

Rows for Ivanti's own cloud services are skipped, since no customer runs a version of them. Versions Ivanti's order cannot place (Endpoint Manager's monthly "November security update", Neurons "Sept 2026 Security Patch") are left out, so those advisories carry a CVE and severity but no version range.

## NetScaler

[citrix-fetcher.ts](../src/worker/citrix-fetcher.ts) · `pnpm import:citrix` · daily 16:45 UTC

The security bulletins of NetScaler ADC and Gateway (formerly Citrix ADC and Gateway), read from the knowledge articles on support.citrix.com. The sitemap lists them; plain HTTP is enough, no browser. A bulletin becomes one advisory per CVE (`<CTX id>/<cveId>`), with the CVSS v4 score from its CVE table.

The bulletins of 2022 and later share a template, one line per product and release branch:

```
NetScaler ADC and NetScaler Gateway 14.1 BEFORE 14.1-73.32
NetScaler ADC 13.1-FIPS before 13.1-37.277
```

Each line becomes a range from the branch (`14.1`) to the first fixed build, for each product it names. A line under "affected by CVE-x :" applies to that CVE only (the NetScaler Console bulletin). A branch the bulletin calls end of life and vulnerable (`12.1`) is affected with no fix (`fixStatus: out_of_support`). The FIPS / NDcPP builds run on their own numbering (`13.1-37.x` against `13.1-6x.x`), so they are a separate product, `NetScaler ADC FIPS and NDcPP`.

A NetScaler version is a branch and a build (`14.1-73.32`); it is ordered with its own order ([citrix-version.ts](../src/utils/citrix-version.ts)), because the generic encoding keeps only the 73 of 73.32, and a bound written as a branch plus a bare build (`14.1` up to `56.73`, how the CVE record gives it) reads as 14.1.0 up to 56.73.0 and flags every later build. The CVE-record (CNA) ranges of NetScaler are therefore not stored.

Other Citrix bulletins (Workspace app, StoreFront, XenServer, SD-WAN, Session Recording) word their versions differently and are not read.
