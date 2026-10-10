# API reference

Base URL: `http://localhost:5000`.

## Authentication

Every endpoint requires the `x-api-key` header to match the `API_KEY` environment variable, except these public routes: `/health`, `/dashboard` and `/icon.png`. `/dashboard` serves only the HTML page. The data it loads (`/api/v1/import-status`) is authenticated like everything else.

Browser cross-origin access is limited to `ALLOWED_ORIGINS` (see [operations.md](operations.md#environment-variables)).

## Health check

```
GET /health
```

```json
{ "status": "ok", "timestamp": "2025-01-18T12:00:00.000Z" }
```

## Search vulnerabilities

Returns vulnerabilities affecting a package and version. OSV, NVD and vendor advisories are queried in parallel, and results are deduplicated through the master table.

```
GET /api/v1/vulnerabilities/search
```

| Parameter | Required | Description |
|---|---|---|
| `package` | ✅ | Package or product name (e.g. `lodash`, `FortiOS`) |
| `version` | | Version string (e.g. `4.17.20`, `7.4.3`). Omit to match the package/ecosystem alone: every result then has `approximateMatch: true` |
| `ecosystem` | | Ecosystem or vendor (e.g. `npm`, `PyPI`, `Go`, `Ubuntu:22.04:LTS`, `Red Hat:9`). Case-sensitive. `composer` is accepted as an alias of `Packagist` |
| `severity` | | Filter by one or more severities (`severity=CRITICAL&severity=HIGH`). Exact match against the `severity` a result carries: `CRITICAL` / `HIGH` / `MEDIUM` / `LOW`, plus `NONE` (CVSS 0.0) and `INFORMATIONAL` (Splunk). GHSA's `MODERATE` is stored as `MEDIUM`. A result with no severity never matches |
| `limit` | | Max results (default 500, max 500) |
| `offset` | | Pagination offset (default 0) |

```bash
# OSV/NVD package
curl -H "x-api-key: $API_KEY" \
  "http://localhost:5000/api/v1/vulnerabilities/search?package=lodash&version=4.17.20&ecosystem=npm"

# Vendor advisory (no ecosystem required)
curl -H "x-api-key: $API_KEY" \
  "http://localhost:5000/api/v1/vulnerabilities/search?package=FortiOS&version=7.4.3"
```

### Search behavior by ecosystem

`ecosystem` changes *which sources are queried* and *how versions are compared*. It is not just a display filter.

| `ecosystem` | Sources queried | Version comparison | Why |
|---|---|---|---|
| Language ecosystem (`npm`, `PyPI`, `Go`, `Packagist`, `crates.io`, `RubyGems`, `NuGet`, `Maven`, ...) | **OSV only** | semver range | NVD and advisories carry C-library/OS entries that share names with language packages (C `bzip2` vs npm `bzip2`) |
| `Red Hat:<major>` / `Oracle Linux:<major>` | **Vendor advisory only** (OVAL / VEX) | RPM (`rpmvercmp`) against the advisory's `versionEnd` | OSV has no Red Hat or Oracle Linux ecosystem |
| Other distros (`Ubuntu:*`, `Debian:*`, `Alpine:*`, `AlmaLinux:*`, `Rocky Linux:*`) | **OSV only** | Exact match against the enumerated affected versions, then a dpkg range comparison for Ubuntu/Debian/Alpine when no list matches | Distro data means "needs a patched build", not an upstream version range |
| `advisory` | **Vendor advisories only** | Each advisory's own version fields | Excludes NVD/OSV noise when searching appliances and vendor products |
| Not specified | OSV (distro ecosystems excluded) + NVD + vendor advisories (RPM module-stream rows excluded) | semver range | Best for names not tied to one ecosystem (`openssl`, `FortiOS`) |

The distro version suffix is optional: `ecosystem=Ubuntu` matches every Ubuntu release by prefix, and `ecosystem=Ubuntu:22.04:LTS` narrows it to one. Distro ecosystems compare distro-format versions (`5.2.4-1ubuntu1`, `1.0.8-8.el9`), so an upstream version such as `5.2.4` will not match.

The legacy value `oracle-linux` (no major) is still accepted for older clients, but it only matches the few rows whose release could not be determined. Use `Oracle Linux:<major>`.

```bash
# Red Hat: RPM comparison against OVAL/VEX advisories
curl -H "x-api-key: $API_KEY" "http://localhost:5000/api/v1/vulnerabilities/search?package=rsync&version=3.2.4-1.el9&ecosystem=Red%20Hat:9"

# Distro ecosystem
curl -H "x-api-key: $API_KEY" "http://localhost:5000/api/v1/vulnerabilities/search?package=xz-utils&version=5.2.4-1ubuntu1&ecosystem=Ubuntu:20.04:LTS"

# Vendor advisories only
curl -H "x-api-key: $API_KEY" "http://localhost:5000/api/v1/vulnerabilities/search?package=httpd&version=2.4.60&ecosystem=advisory"
```

Go vulnerabilities are recorded per sub-module, so search with the exact module path (see [known-issues.md](known-issues.md#go-sub-modules-need-the-exact-module-path)).

### Response

```json
{
  "results": [
    {
      "id": "clxxx...",
      "externalId": "CVE-2019-10744",
      "source": "nvd",
      "sources": ["nvd"],
      "severity": "CRITICAL",
      "cvssScore": 9.8,
      "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "summary": "Prototype pollution in lodash",
      "publishedAt": "2019-07-26T00:00:00.000Z",
      "approximateMatch": false,
      "isKev": true,
      "epssScore": 0.97,
      "epssPercentile": 0.998,
      "fixedVersion": "4.17.21",
      "distroPriority": null,
      "fixStatus": null,
      "fixStatusDetail": null,
      "aliases": ["CVE-2019-10744"]
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `source` | The preferred source: `nvd`, `osv` or `advisory` |
| `sources` | Every source that matched (`["nvd", "osv"]`). Use it to see where a match came from: a match from Red Hat VEX lists `red-hat-vex` here even when `source` is `nvd` |
| `severity`, `cvssScore`, `cvssVector` | CVE-wide rating: NVD first, otherwise OSV (see [architecture.md](architecture.md#source-priority)) |
| `approximateMatch` | `true` when the version could not be compared, so the match is by package name and ecosystem only |
| `isKev` | Listed in the CISA Known Exploited Vulnerabilities catalog |
| `epssScore`, `epssPercentile` | Probability of exploitation within 30 days (0–1), and its rank among all CVEs |
| `fixedVersion` | The version that resolves this finding, when the source states one |
| `distroPriority` | The distribution's own rating (below) |
| `fixStatus`, `fixStatusDetail` | Whether a fix will come (below) |
| `aliases` | Every identifier this finding is known by, including `externalId`. A record that later received a CVE keeps its original ID here |

#### `distroPriority`

The distribution's own rating of this CVE for the matched package, verbatim. Unlike `severity`, it can differ per distro: NVD may say `HIGH` while Ubuntu says `negligible`. Use it when triaging that distro's packages. `null` when the matching source carries no rating.

| Distro | Values | Source |
|---|---|---|
| Ubuntu | `negligible` / `low` / `medium` / `high` / `critical` | Ubuntu priority (OSV) |
| Debian | `unimportant` / `low` / `medium` / `high` / `end-of-life` / `not yet assigned`, per release | Debian security tracker urgency (OSV) |
| RHEL | `low` / `moderate` / `important` / `critical` | Red Hat's per-CVE impact (OVAL / VEX) |

Alpine, AlmaLinux, Rocky Linux and Oracle Linux return `null`: their sources have no rating, or only one per advisory rather than per CVE.

#### `fixStatus`

Whether a fix will come for an unfixed package. It answers a different question from `distroPriority`: Red Hat can rate a CVE `moderate` and still not fix it. `fixStatusDetail` carries the source's own wording (e.g. `Will not fix`, or the Debian tracker's tag and note).

| `fixStatus` | Meaning | Red Hat | Debian security tracker |
|---|---|---|---|
| `affected` | Not fixed yet; a fix may still come | `Affected` | open, no tag |
| `deferred` | Postponed, or will not come as a security update | `Fix deferred` | `postponed`; plain `no-dsa` |
| `will_not_fix` | The vendor has decided not to fix it | `Will not fix` | `ignored` |
| `out_of_support` | Outside the vendor's support scope | `Out of support scope` | `end-of-life` |
| `under_investigation` | Not yet confirmed whether it applies | (product status) | `undetermined` |

Sources today: Red Hat CSAF VEX (RHEL 8/9/10), the Debian security tracker (Debian 12 and later; Debian 11 is not in the tracker's export), and Check Point, which marks end-of-support release lines with no fix as `out_of_support` (`fixStatusDetail` is the release line, e.g. `R80.40 (EOS)`). Other results return `null`, including every match that only has a `fixedVersion`. **The set of values may grow**: treat an unknown value like `affected`.

A RHEL result can carry both `fixedVersion` and `fixStatus`:
- Red Hat's VEX says "unfixed" per major version but "fixed" per release stream (9.3 GA, 9.2 EUS, ...). Such an entry is bounded by the newest fix for that major, returned as `fixedVersion`. A build that is fixed only in an older stream (e.g. EUS) is still reported. This false positive is preferred over guessing which stream a build belongs to.
- Red Hat's OVAL and VEX data sometimes disagree, with VEX recording no fix at all. Both are returned as Red Hat publishes them.

## Search vulnerabilities (batch)

Up to 1,000 packages in one request. Each entry takes the same fields as the single search.

```
POST /api/v1/vulnerabilities/search/batch
```

```bash
curl -X POST -H "x-api-key: $API_KEY" -H "Content-Type: application/json" \
  "http://localhost:5000/api/v1/vulnerabilities/search/batch" \
  -d '{
    "packages": [
      { "package": "lodash",   "version": "4.17.20", "ecosystem": "npm" },
      { "package": "requests", "version": "2.31.0",  "ecosystem": "PyPI" }
    ]
  }'
```

## CPE search

Search NVD with a CPE 2.3 string. When the version component is `*` or omitted, results have `approximateMatch: true`.

```
GET /api/v1/vulnerabilities/search/cpe
```

```bash
curl -H "x-api-key: $API_KEY" \
  "http://localhost:5000/api/v1/vulnerabilities/search/cpe?cpe=cpe:2.3:a:vercel:next.js:15.1.0:*:*:*:*:*:*:*"
```

## CPE lookup by CVE and product

Returns the CPE 2.3 string NVD recorded for a product in a CVE, for building a CPE search. Returns 404 in any of these cases: the CVE is not in NVD, the product matches none of its affected packages, or the product name matches more than one vendor.

```
GET /api/v1/vulnerabilities/:id/cpe?product=<name>
```

```bash
curl -H "x-api-key: $API_KEY" "http://localhost:5000/api/v1/vulnerabilities/CVE-2021-44228/cpe?product=log4j"
# → { "cpe": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", "vendor": "apache", "product": "log4j" }
```

## Package name autocomplete

Suggests real package names for a prefix. NVD names are CPE product identifiers (`http_server`, not "Apache HTTP Server"), which are hard to guess. Searches NVD, OSV and CNA-declared products.

```
GET /api/v1/vulnerabilities/suggest
```

| Parameter | Required | Description |
|---|---|---|
| `q` | ✅ | Name prefix |
| `ecosystem` | | Restrict to an ecosystem/vendor prefix |
| `limit` | | Max suggestions (default 10, max 50) |

How `q` is matched:

- The prefix is tried as typed, in lowercase, in uppercase and in Title Case, so `HTTP_S`, `Connect Secure` and `br-6208` find `http_server`, `Connect Secure` and `BR-6208AC`.
- A space also matches `_` and `-` (`connect secure` finds `connect_secure`, `big ip` finds `big-ip_…`). A typed `%` or `_` matches itself.
- A prefix that is a CPE vendor (`ivanti`, `palo alto`) also lists that vendor's NVD products, after the names that match what was typed. Without an `ecosystem` only; the CPE vendor belongs to NVD.
- Order: the name typed exactly, then names starting with it, then a vendor's products; alphabetical within each.

`details` says where each suggestion was found; `suggestions` is the same names as plain strings.

```bash
curl -H "x-api-key: $API_KEY" "http://localhost:5000/api/v1/vulnerabilities/suggest?q=ivanti&limit=3"
# → { "suggestions": ["connect_secure", "endpoint_manager", ...],
#     "details": [{ "name": "connect_secure", "sources": ["nvd"], "vendors": ["ivanti"], "ecosystems": [], "matchedBy": "vendor" }, ...] }
```

| `details` field | Meaning |
|---|---|
| `name` | The suggested name |
| `sources` | Where the name was found: `nvd`, `osv` or `cna` |
| `vendors` | CPE (NVD) and CNA vendors the name is found under, all of them; a vendor the prefix matched comes first |
| `ecosystems` | Ecosystem families of the OSV packages with this name (`Debian`, `npm`), without the version |
| `matchedBy` | `name` (the prefix matched the name) or `vendor` (the prefix matched the vendor) |

## Vulnerability detail

By CVE ID, OSV ID or vendor advisory ID.

```
GET /api/v1/vulnerabilities/:id
```

```bash
curl -H "x-api-key: $API_KEY" "http://localhost:5000/api/v1/vulnerabilities/CVE-2021-44228"
curl -H "x-api-key: $API_KEY" "http://localhost:5000/api/v1/vulnerabilities/GHSA-67hx-6x53-jw92"
curl -H "x-api-key: $API_KEY" "http://localhost:5000/api/v1/vulnerabilities/FG-IR-25-934"
```

The detail response also includes CISA Vulnrichment's SSVC assessment when available (`ssvcExploitation`, `ssvcAutomatable`, `ssvcTechnicalImpact`, `ssvcTimestamp`). Search results do not include it.

## Statistics

```
GET /api/v1/vulnerabilities/stats
```

```json
{
  "total": 280283,
  "bySeverity": [{ "severity": "CRITICAL", "_count": 8234 }, { "severity": "HIGH", "_count": 71234 }],
  "kevCount": 1238,
  "withEpss": 223107,
  "bySource": { "osv": 269380, "nvd": 11311, "advisory": 47, "advisoryByVendor": { "fortinet": 47 } }
}
```

## Import status

The JSON behind the dashboard: the latest job per source, record counts, and per-OSV-ecosystem status. `osvEcosystems[].maintained` is `false` for distro releases outside the [support policy](../README.md#supported-os-releases). Per-ecosystem record counts are cached for 5 minutes.

```
GET /api/v1/import-status
```

## Jobs

`:source` is the job's source key (`nvd`, `kev`, `advisory-fortinet`, `osv-npm`, ...).

```
POST  /api/v1/jobs/:source/run    # Run now (fire-and-forget), regardless of the enabled state
PATCH /api/v1/jobs/:source        # Enable/disable the scheduled run. Body: { "enabled": boolean }
```

| Case | Response |
|---|---|
| Run started | `202 { "status": "started", "source": "..." }` |
| Already running | `409` |
| Unknown source | `404` |

```bash
curl -X POST -H "x-api-key: $API_KEY" "http://localhost:5000/api/v1/jobs/nvd/run"
curl -X PATCH -H "x-api-key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"enabled": false}' "http://localhost:5000/api/v1/jobs/osv-npm"
```
