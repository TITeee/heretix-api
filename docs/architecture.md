# Architecture

## Data flow

```
OSV ──────────┐
NVD ──────────┤                                   ┌─ KEV / EPSS / SSVC (per CVE)
CVE Records ──┼─► per-source tables ─► Vulnerability (master) ─► REST API
Vendor feeds ─┘                                   └─ deduplicated by CVE ID
```

Each source has a fetcher in `src/worker/` that downloads and normalizes its data. Jobs are defined in [src/jobs/registry.ts](../src/jobs/registry.ts), scheduled by [src/scheduler.ts](../src/scheduler.ts) and run through [src/jobs/executor.ts](../src/jobs/executor.ts). Search lives in [src/api/routes/vulnerabilities.ts](../src/api/routes/vulnerabilities.ts) with its matching predicates in [src/utils/search-helpers.ts](../src/utils/search-helpers.ts).

## Data model

Defined in [prisma/schema.prisma](../prisma/schema.prisma).

```
Vulnerability (master)
  ├── cveId      @unique  # CVE ID: the shared dedup key
  ├── osvId      @unique  # OSV ID (GHSA-..., PYSEC-...), only when there is no CVE
  ├── advisoryId @unique  # vendor advisory ID (FG-IR-...), only when there is no CVE or OSV ID
  ├── severity / cvssScore / cvssVector / summary
  ├── isKev / kev*, epssScore / epssPercentile, ssvc*
  ├── nvdVulnerability        # NVDVulnerability → NVDAffectedPackage[]
  ├── osvVulnerabilities      # OSVVulnerability[] → OSVAffectedPackage[]
  ├── advisoryVulnerabilities # AdvisoryVulnerability[] → AdvisoryAffectedProduct[]
  └── cnaVulnerability        # CnaVulnerability → CnaAffectedProduct[]
```

Supporting tables:
- `CollectionJob`: one row per job run, used for status, resume checkpoints and delta cursors.
- `JobConfig`: per-job enabled flag.
- `DataMigration`: ledger of applied one-time backfills.
- `DebianSourcePackage`, `DebianTrackerStatus`: Debian name mapping and fix status.

## Deduplication

When the same CVE appears in several sources, they share one master row:

```
CVE-2021-44228 (Log4Shell)
  ├── NVDVulnerability            ─┐
  ├── OSVVulnerability (GHSA-...) ─┼→ Vulnerability (cveId: "CVE-2021-44228", isKev: true)
  └── AdvisoryVulnerability       ─┘
```

The master row is keyed by `cveId` when there is a CVE, otherwise by `osvId`, otherwise by `advisoryId`. Search results from all sources are merged by master row, which is why one finding can list several `sources`.

## Source priority

| Field | Authoritative source |
|---|---|
| `severity` / `cvssScore` / `cvssVector` | NVD when it has a rating; otherwise OSV (GHSA rating, with CVSS computed from OSV's vector). An NVD record with no rating yet leaves the existing value in place |
| `summary` / `publishedAt` | NVD; OSV or the advisory only when NVD has none |
| `isKev` / `kev*` | CISA KEV |
| `epssScore` / `epssPercentile` | FIRST.org EPSS |
| `ssvc*` | CISA Vulnrichment |
| `workaround` / `solution` / `url` | The vendor advisory |
| `distroPriority`, `fixStatus` | Per matched row, from the distro's own data (never written to the master row) |

## Version matching

Generic versions are encoded as integers so that range queries can use an index ([src/utils/version.ts](../src/utils/version.ts)):

```
major × 1,000,000,000 + minor × 1,000,000 + patch × 1,000 + release
1.2.3        → 1_002_003_000
2.9.13-6.el9 → 2_009_013_006
```

```sql
WHERE ecosystem = 'npm' AND packageName = 'lodash'
  AND introducedInt <= 4017020000
  AND (fixedInt IS NULL OR fixedInt > 4017020000)
```

| Case | Behavior |
|---|---|
| Pre-release (`1.0.0-beta.1`) | Slightly below the release |
| Build metadata (`1.0.0+build.123`) | Ignored |
| minor / patch / release ≥ 1,000 | Clamped to 999, so it cannot overflow into the next component |
| Any component > 999,999, or non-numeric (dates, git hashes) | Cannot be encoded: the search falls back to package-name matching with `approximateMatch: true` |

Where this encoding is not precise enough, exact comparators are used instead:

| Data | Comparator |
|---|---|
| Red Hat / Oracle Linux (`ecosystem=Red Hat:*`, `Oracle Linux:*`) | `rpmvercmp` ([rpm-version.ts](../src/utils/rpm-version.ts)), full epoch:version-release |
| Ubuntu / Debian / Alpine OSV ranges | dpkg ordering ([dpkg-version.ts](../src/utils/dpkg-version.ts)), when the enumerated version list has no match |
| Palo Alto Networks | PAN hotfix ordering ([pan-version.ts](../src/utils/pan-version.ts)) |

A row with no range data at all never matches, except when `patchAvailable` is explicitly `false` (an unfixed package from Red Hat VEX): that row matches every version. `patchAvailable: null`, meaning unknown, does not.

For speed, RPM advisory rows are cached per (package, release) for 5 minutes and split into "matches every version" and "needs a comparison".

## Vendor advisories

Every vendor fetcher implements `AdvisoryFetcher` ([src/worker/advisory-fetcher.ts](../src/worker/advisory-fetcher.ts)) and returns `NormalizedAdvisory[]`. `runAdvisoryFetcher()` then handles everything common to them:

- **Master row linkage**: an advisory with a CVE attaches to that CVE's master row; one without gets its own row keyed by `advisoryId`.
- **Zero results fail the run**: a fetch that returns no advisories at all is treated as a scraper failure, not as "everything was retracted".
- **Stale advisory pruning**: fetchers that return the complete current set (`isCompleteSnapshot() === true`) prune advisories missing from the source. One must be missing for 3 consecutive runs before it is deleted, so a single bad run cannot wipe data. Partial-window runs (PAN or Cisco in `latest` mode, Oracle CPU `latest`) never prune.
- **Per-release vendor keys**: RPM distributions write a vendor per major release (`red-hat-9`, `oracle-linux-8`). These rows are reachable only through an explicit `Red Hat:*` / `Oracle Linux:*` search, so generic package names (`php`, `sed`) cannot leak into unrelated searches.
