# Heretix API

A simple, high-performance vulnerability management API backed by PostgreSQL. It collects and normalizes data from **OSV**, **NIST NVD**, **CISA KEV**, **EPSS**, and **vendor security advisories**, then provides fast, deduplicated search through a unified master table.

[日本語版 README](README.ja.md)

## Features

- **Multi-source**: OSV (Open Source Vulnerabilities), NIST NVD (CVE), and vendor advisories (Fortinet, Palo Alto Networks, Cisco PSIRT, Sophos, SonicWall, Oracle CPU, Oracle Linux, Red Hat, Broadcom/VMware, Splunk, Apache HTTP Server, Apache Tomcat, nginx, Zabbix, and more)
- **Malware detection**: OSV `MAL-YYYY-NNNN` entries (malicious packages) are imported from [ossf/malicious-packages](https://github.com/ossf/malicious-packages) and searchable via the same vulnerability search endpoint
- **Deduplication**: A `Vulnerability` master table uses CVE ID as the primary key to merge duplicate entries across sources
- **CPE alias support**: `src/config/product-aliases.ts` tracks CPE product name changes (e.g., post-acquisition renames) so search accuracy stays high
- **Risk scoring**: CISA KEV (known-exploited flag) and EPSS (exploitation probability score) are attached to each vulnerability
- **Simple**: Runs on PostgreSQL only — no Redis required. Docker Compose support included for easy deployment
- **Fast search**: Version numbers are normalized to integers for high-speed range queries
- **Scalable**: Raw data stored as JSONB, search fields kept normalized
- **RESTful API**: Lightweight, high-throughput Fastify server
- **Full NVD mirror**: Local mirror of all ~240,000 NVD CVEs with incremental update support
- **Incremental updates**: OSV ecosystems and MAL entries support delta updates via `CollectionJob`-tracked timestamps

## Setup

### Option A: Docker (recommended)

```bash
cp .env.example .env   # edit values, especially API_KEY

# Foreground (recommended for first run — shows logs)
docker compose up --build

# Or background (detached mode)
docker compose up --build -d
```

The API is available at `http://localhost:5000`. `docker compose down` to stop (add `-v` to also remove the database volume). This runs the full stack — Postgres and the API — with a single command.

### Option B: Manual (native PostgreSQL)

1. **Install dependencies**
   ```bash
   pnpm install
   ```

2. **Prepare PostgreSQL** — use an existing instance or install one locally:
   ```bash
   psql --version   # verify PostgreSQL 15+ is installed
   createdb vulndb
   ```
   Remote PostgreSQL (Supabase, Neon, Railway, AWS RDS, etc.) also works — just point `DATABASE_URL` at it.

3. **Configure environment variables** — copy `.env.example` to `.env` and fill in the values. See [Environment variables](#environment-variables) below.

4. **Run database migrations**
   ```bash
   pnpm db:migrate
   ```
   The Docker image also runs `pnpm migrate:all` on every container start, right
   after schema migrations — see [One-time data backfills](#one-time-data-backfills)
   below. Running it locally after `pnpm db:migrate` keeps a dev database caught up
   the same way.

5. **Start the server**
   ```bash
   pnpm dev      # development, with auto-reload
   # or, for production:
   pnpm build && pnpm start
   ```
   The server starts at http://localhost:5000.

> **Import scripts in dev mode**: `pnpm import:*` commands run against the compiled `dist/` output. When running `pnpm dev` without a prior build, use `pnpm exec tsx src/scripts/<script>.ts` instead:
> ```bash
> pnpm exec tsx src/scripts/import-osv.ts update npm
> pnpm exec tsx src/scripts/import-nvd.ts update
> ```

### Environment variables

```env
DATABASE_URL="postgresql://postgres:password@localhost:5432/vulndb?schema=public"
PORT=5000
NODE_ENV=development                # use "production" for a production deployment
API_KEY=your-api-key-here           # Required. Requests without x-api-key header return 401
NVD_API_KEY=                        # Optional. Relaxes NVD rate limit from 10 → 50 req/min
CISCO_CLIENT_ID=                    # Required for Cisco PSIRT import (openVuln API client ID)
CISCO_CLIENT_SECRET=                # Required for Cisco PSIRT import (openVuln API client secret)
GITHUB_TOKEN=                       # Optional. Authenticates the single GitHub tree API call used by MAL import/update. Only needed if running MAL commands more than 60 times/hr from the same IP.
```

## Database Management

### One-time data backfills

Some fixes need to correct rows already written before the fix existed, not just
change how future rows are written — a `pnpm migrate:*` script under
[`src/scripts/`](src/scripts/), one per fix. Each is idempotent: it finds rows still
needing the correction and does nothing once none remain, safe to run any number of
times.

They're run together, in one pass, via:
```bash
pnpm migrate:all
```
which scans `dist/scripts/` for every `migrate-*.js` file and runs them in sequence —
a new one just has to exist there, nothing has to add it to a list. `entrypoint.sh`
calls this automatically on every container start, right after `prisma migrate
deploy`, so a newly added backfill reaches production on the next deploy without a
manual step to remember. Run it locally too after pulling changes that add one.

Individual scripts remain runnable on their own (`pnpm migrate:job-config-defaults`,
etc.) for testing a specific one or re-running after investigating a partial
failure.

### Prisma Studio

Browse and edit the database in a GUI:
```bash
pnpm db:studio
```
Opens http://localhost:5555 in your browser.

## Import Status Dashboard

A lightweight web dashboard is available at `/dashboard` (viewing requires no authentication).

![Import Status Dashboard](docs/dashboard.png)

```
GET /dashboard
```

Displays:
- **Record counts** — total rows in NVD, OSV, KEV, and Advisory tables
- **Import status table** — latest `CollectionJob` per source with status badge, last completed time, inserted/updated counts, and any error message
- **OSV ecosystems** — per-ecosystem import status and record counts

Auto-refreshes every 60 seconds. Also available as JSON:

```
GET /api/v1/import-status
```

### Job control (enable/disable & manual run)

Each row has an **On/Off toggle** to enable/disable the scheduled run, and a **Run** button to trigger it on demand. OSV is controllable per ecosystem.

These actions mutate state, so they require `x-api-key` authentication. Enter your API key in the field at the top-right of the dashboard — it is saved in the browser's `localStorage` and sent with subsequent actions (not needed for viewing).

Corresponding endpoints (inside the `/api/v1` auth scope):

```
POST  /api/v1/jobs/:source/run     # Manual run (fire-and-forget, 202; runs regardless of enabled state)
PATCH /api/v1/jobs/:source          # Toggle enabled. Body: { "enabled": boolean }
```

`:source` is the `CollectionJob.source` (`nvd`, `kev`, `advisory-fortinet`, `osv-npm`, etc.). Re-running while in progress returns `409`; an unknown source returns `404`. The enabled state is persisted in the `JobConfig` table and defaults to enabled when no row exists.

Example: `http://localhost:5000/dashboard`

---

## API Endpoints

Endpoints require the `x-api-key` header to match the `API_KEY` environment variable, except the following public routes: `/health`, `/dashboard`, `/icon.png`, `/api/v1/import-status`.

### Health check

```
GET /health
```

```json
{ "status": "ok", "timestamp": "2025-01-18T12:00:00.000Z" }
```

### Search vulnerabilities (single)

Search for vulnerabilities affecting a specific package and version. Queries OSV, NVD, and vendor advisory tables in parallel, then deduplicates results via the master table.

```
GET /api/v1/vulnerabilities/search
```

**Query parameters:**
| Parameter | Required | Description |
|---|---|---|
| `package` | ✅ | Package or product name (e.g. `lodash`, `FortiOS`) |
| `version` | ✅ | Version string (e.g. `4.17.20`, `7.4.3`) |
| `ecosystem` | | Ecosystem or vendor (e.g. `npm`, `PyPI`, `Go`, `composer`, `fortinet`) |
| `severity` | | Filter by severity (array) |
| `limit` | | Max results (default: 500, max: 500) |
| `offset` | | Pagination offset (default: 0) |

**Examples:**
```bash
# OSV/NVD package
curl -H "x-api-key: $API_KEY" \
  "http://localhost:5000/api/v1/vulnerabilities/search?package=lodash&version=4.17.20&ecosystem=npm"

# Vendor advisory (no ecosystem required)
curl -H "x-api-key: $API_KEY" \
  "http://localhost:5000/api/v1/vulnerabilities/search?package=FortiOS&version=7.4.3"
```

**Search behavior by ecosystem:**

The `ecosystem` parameter changes *which sources are queried* and *how versions are compared* — not just a display filter. This trips people up, so read this table before assuming a search returned "everything":

| `ecosystem` | Sources queried | Version comparison | Why |
|---|---|---|---|
| Language ecosystem (`npm`, `PyPI`, `Go`, `Packagist`, `crates.io`, `RubyGems`, `NuGet`, `Maven`) | **OSV only** | semver range | NVD/Advisory carry C-library/OS entries that share names with language packages (e.g. C `bzip2` vs. npm `bzip2`) — querying them here would produce false positives |
| `Red Hat:*` (e.g. `Red Hat:9`) / `oracle-linux` | **Vendor advisory (OVAL) only** | RPM (`rpmvercmp`), against the advisory's `versionEnd` | OSV has no Red Hat/Oracle Linux ecosystem — the vendor OVAL feed is the only source of RHEL/Oracle Linux vulnerability data |
| Other distro ecosystems (`Ubuntu:*`, `Debian:*`, `Alpine:*`, `AlmaLinux:*`, `Rocky:*`, `CentOS:*`) | **OSV only** | Exact match against `affectedVersions` (dpkg/rpm version strings) | Distro advisories express "needs a patched build," not an upstream version range (see [Known Issues](#known-issues)); vendor advisory product names also overlap with distro package names |
| `advisory` | **Vendor advisory only** (Fortinet, PAN, Apache, Tomcat, nginx, etc.) | semver range, against the advisory's own version fields | Not a real NVD/OSV ecosystem name, so both return nothing for it — searchAdvisory() itself doesn't filter by ecosystem at all, so it's unaffected and returns its full result set. Use this to search vendor advisories only, with NVD/OSV noise excluded |
| Not specified | OSV (distro ecosystems excluded) + NVD + Advisory (RPM module-stream rows excluded — see [Known Issues](#known-issues)) | semver range | Default — best for names not tied to a single ecosystem (e.g. `openssl`, `FortiOS`) |

```bash
# Language ecosystem — OSV only
curl -H "x-api-key: $API_KEY" "http://localhost:5000/api/v1/vulnerabilities/search?package=lodash&version=4.17.20&ecosystem=npm"

# Red Hat — RPM version comparison against OVAL advisories
curl -H "x-api-key: $API_KEY" "http://localhost:5000/api/v1/vulnerabilities/search?package=rsync&version=3.2.4-1.el9&ecosystem=Red%20Hat:9"

# Distro ecosystem — exact version-string match
curl -H "x-api-key: $API_KEY" "http://localhost:5000/api/v1/vulnerabilities/search?package=xz-utils&version=5.2.4-1ubuntu1&ecosystem=Ubuntu:20.04:LTS"

# advisory — vendor advisories only, NVD/OSV excluded
curl -H "x-api-key: $API_KEY" "http://localhost:5000/api/v1/vulnerabilities/search?package=httpd&version=2.4.60&ecosystem=advisory"
```

**Response:**
```json
{
  "results": [
    {
      "id": "clxxx...",
      "externalId": "CVE-2019-10744",
      "source": "nvd",
      "severity": "CRITICAL",
      "cvssScore": 9.8,
      "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "summary": "Prototype pollution in lodash",
      "publishedAt": "2019-07-26T00:00:00.000Z",
      "approximateMatch": false,
      "isKev": true,
      "epssScore": 0.97,
      "epssPercentile": 0.998
    }
  ]
}
```

`source` values: `"nvd"` · `"osv"` · `"advisory"`

> `approximateMatch: true` — version normalization failed; results matched by package name and ecosystem only.

> `isKev: true` — listed in the CISA Known Exploited Vulnerabilities catalog.

> `epssScore` — probability of exploitation within 30 days (0–1); `epssPercentile` — rank among all CVEs.

### Search vulnerabilities (batch)

Search up to 1,000 packages in a single request.

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

### CPE search (NVD only)

Search using a CPE 2.3 string. NVD table only.

```
GET /api/v1/vulnerabilities/search/cpe
```

```bash
# With version (range filter applied)
curl -H "x-api-key: $API_KEY" \
  "http://localhost:5000/api/v1/vulnerabilities/search/cpe?cpe=cpe:2.3:a:vercel:next.js:15.1.0:*:*:*:*:*:*:*"

# Wildcard version (returns all matching vulnerabilities)
curl -H "x-api-key: $API_KEY" \
  "http://localhost:5000/api/v1/vulnerabilities/search/cpe?cpe=cpe:2.3:a:vercel:next.js:*"
```

When the `<version>` component is `*` or omitted, results are returned with `approximateMatch: true`.

### Vulnerability detail

Retrieve details by CVE ID, OSV ID, or vendor advisory ID.

```
GET /api/v1/vulnerabilities/:id
```

```bash
curl -H "x-api-key: $API_KEY" "http://localhost:5000/api/v1/vulnerabilities/CVE-2021-44228"
curl -H "x-api-key: $API_KEY" "http://localhost:5000/api/v1/vulnerabilities/GHSA-67hx-6x53-jw92"
curl -H "x-api-key: $API_KEY" "http://localhost:5000/api/v1/vulnerabilities/FG-IR-25-934"
```

### Statistics

```
GET /api/v1/vulnerabilities/stats
```

```json
{
  "total": 280283,
  "bySeverity": [
    { "severity": "CRITICAL", "_count": 8234 },
    { "severity": "HIGH",     "_count": 71234 }
  ],
  "kevCount": 1238,
  "withEpss": 223107,
  "bySource": {
    "osv": 269380,
    "nvd": 11311,
    "advisory": 47,
    "advisoryByVendor": { "fortinet": 47, "paloalto": 21, "cisco": 21 }
  }
}
```

### Run a job (manual trigger)

```
POST /api/v1/jobs/:source/run
```

Triggers the given source on demand (fire-and-forget). Runs regardless of enabled state.

| Case | Response |
|---|---|
| Started | `202 { "status": "started", "source": "..." }` |
| Already running | `409` |
| Unknown source | `404` |

```bash
curl -X POST -H "x-api-key: $API_KEY" "http://localhost:5000/api/v1/jobs/nvd/run"
```

### Enable/disable a job

```
PATCH /api/v1/jobs/:source
```

Toggles whether the scheduler runs the job (does not affect manual runs). State is persisted in `JobConfig`.

```bash
curl -X PATCH -H "x-api-key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"enabled": false}' "http://localhost:5000/api/v1/jobs/osv-npm"
# → { "source": "osv-npm", "enabled": false }
```

`:source` is the `CollectionJob.source` (`nvd`, `kev`, `advisory-fortinet`, `osv-npm`, etc.).

## Project Structure

```
heretix-api/
├── src/
│   ├── api/
│   │   ├── routes/
│   │   │   ├── vulnerabilities.ts   # Vulnerability API endpoints
│   │   │   ├── vulnerabilities.integration.test.ts  # search route integration test (fastify.inject, Vitest)
│   │   │   ├── dashboard.ts         # Dashboard UI & import-status API
│   │   │   └── jobs.ts              # Job manual-run & enable/disable API
│   │   └── server.ts                # Fastify server configuration
│   ├── jobs/
│   │   ├── types.ts                 # JobDefinition / JobResult types
│   │   ├── registry.ts              # All job definitions (STATIC_JOBS) + dynamic resolver
│   │   ├── executor.ts              # Shared job lifecycle + concurrency lock
│   │   ├── executor.integration.test.ts  # executeJob / getDeltaCursor integration test (Vitest)
│   │   └── config.ts                # Job enable/disable (JobConfig) accessors
│   ├── db/
│   │   └── client.ts                # Prisma client
│   ├── test-utils/
│   │   └── db.ts                    # resetDb() — truncates all tables, used by integration test beforeEach()
│   ├── scripts/
│   │   ├── import-osv.ts            # OSV import CLI
│   │   ├── import-nvd.ts            # NVD import CLI
│   │   ├── import-kev.ts            # CISA KEV import CLI
│   │   ├── import-epss.ts           # EPSS score import CLI
│   │   ├── import-fortinet.ts       # Fortinet PSIRT import CLI
│   │   ├── import-pan.ts            # Palo Alto Networks PSIRT import CLI
│   │   ├── import-cisco.ts          # Cisco PSIRT import CLI
│   │   ├── import-oracle-linux.ts   # Oracle Linux ELSA import CLI
│   │   ├── import-sophos.ts         # Sophos advisory import CLI
│   │   ├── import-sonicwall.ts      # SonicWall PSIRT import CLI
│   │   ├── import-redhat.ts         # Red Hat RHSA/RHBA import CLI
│   │   ├── import-oracle-cpu.ts     # Oracle CPU (quarterly patch) import CLI
│   │   ├── import-broadcom.ts       # Broadcom/VMware VMSA import CLI
│   │   ├── import-splunk.ts         # Splunk security advisory import CLI
│   │   ├── import-apache.ts         # Apache HTTP Server advisory import CLI
│   │   ├── import-zabbix.ts         # Zabbix security advisory import CLI
│   │   ├── import-tomcat.ts         # Apache Tomcat advisory import CLI
│   │   ├── import-nginx.ts          # nginx advisory import CLI
│   │   ├── validate-tomcat.ts       # Tomcat search accuracy validator
│   │   ├── validate-apache.ts       # Apache HTTPD search accuracy validator
│   │   ├── validate-nginx.ts        # nginx search accuracy validator
│   │   ├── validate-openssl.ts      # OpenSSL search accuracy validator
│   │   ├── validate-postgresql.ts   # PostgreSQL search accuracy validator
│   │   └── clear-db.ts              # Drop all tables including Vulnerability
│   ├── worker/
│   │   ├── osv-fetcher.ts           # OSV API integration
│   │   ├── nvd-fetcher.ts           # NVD REST API v2.0 integration
│   │   ├── kev-fetcher.ts           # CISA KEV catalog fetch & import
│   │   ├── epss-fetcher.ts          # FIRST.org EPSS daily dataset fetch & import
│   │   ├── advisory-fetcher.ts      # Vendor advisory common interface & import logic
│   │   ├── fortinet-fetcher.ts      # Fortinet PSIRT CSAF fetch & parse
│   │   ├── pan-fetcher.ts           # Palo Alto Networks PSIRT CSAF fetch & parse
│   │   ├── cisco-fetcher.ts         # Cisco PSIRT openVuln API fetch & parse
│   │   ├── oracle-linux-fetcher.ts  # Oracle Linux OVAL XML fetch, decompress & parse
│   │   ├── redhat-fetcher.ts        # Red Hat OVAL v2 XML fetch, decompress & parse
│   │   ├── sophos-fetcher.ts        # Sophos sitemap + RSS + headless browser fetch
│   │   ├── sonicwall-fetcher.ts     # SonicWall PSIRT JSON API fetch & parse
│   │   ├── oracle-cpu-fetcher.ts    # Oracle CPU CSAF 2.0 fetch & per-CVE split
│   │   ├── broadcom-fetcher.ts      # Broadcom/VMware VMSA JSON API + Playwright fetch
│   │   ├── splunk-fetcher.ts        # Splunk advisory archive HTML fetch & parse
│   │   ├── apache-fetcher.ts        # Apache HTTP Server (httpd) security page HTML fetch & parse
│   │   ├── zabbix-fetcher.ts        # Zabbix security advisory search API fetch & parse
│   │   ├── tomcat-fetcher.ts        # Apache Tomcat multi-branch security page fetch & parse
│   │   ├── nginx-fetcher.ts         # nginx security advisories page fetch & parse
│   │   ├── *.test.ts                # Version-range parser unit tests (redhat/oracle-linux/splunk/apache/zabbix/tomcat/nginx, Vitest)
│   │   ├── advisory-fetcher.integration.test.ts  # importAdvisoryData integration test (Vitest, requires TEST_DATABASE_URL)
│   │   └── osv-fetcher.integration.test.ts       # importOSVData integration test — orphaned-master-row regression
│   ├── config/
│   │   ├── product-aliases.ts       # NVD CPE product name alias mappings
│   │   └── product-aliases.test.ts  # Unit tests (Vitest)
│   ├── utils/
│   │   ├── logger.ts                # Pino logger configuration
│   │   ├── version.ts               # Version normalization utility
│   │   ├── rpm-version.ts           # RPM version comparison (rpmvercmp algorithm)
│   │   ├── cpe.ts                   # CPE 2.3 parse utility
│   │   ├── search-helpers.ts        # Search-time decision logic (dedup, ecosystem classification, etc.), extracted from vulnerabilities.ts
│   │   ├── browser.ts               # Shared Playwright stealth browser singleton
│   │   └── *.test.ts                # Unit tests for each utility (Vitest)
│   ├── scheduler.ts                 # Iterates the job registry to register cron jobs (node-cron)
│   └── index.ts                     # Entry point
├── prisma/
│   ├── schema.prisma                # Database schema
│   └── migrations/                  # Migration files
├── vitest.config.ts                 # Unit test configuration (Vitest, no DB)
├── vitest.integration.config.ts     # Integration test configuration (Vitest, requires TEST_DATABASE_URL)
├── .env.example                     # Environment variable template
├── package.json
└── tsconfig.json
```

## Key Components

### Data model ([prisma/schema.prisma](prisma/schema.prisma))

```
Vulnerability (master)
  ├── cveId      @unique  — CVE ID (shared dedup key across NVD/OSV/Advisory)
  ├── osvId      @unique  — OSV ID (GHSA-xxx, PYSEC-xxx, etc. — only when no CVE)
  ├── advisoryId @unique  — Vendor advisory ID (FG-IR-xx-xxx, etc. — only when no CVE/OSV)
  ├── severity / cvssScore / cvssVector / summary
  ├── isKev / kevDateAdded / kevDueDate / ...    — CISA KEV fields
  ├── epssScore / epssPercentile / epssUpdatedAt — EPSS fields
  ├── nvdVulnerability        — NVDVulnerability (1:1)
  ├── osvVulnerabilities      — OSVVulnerability[] (1:N)
  └── advisoryVulnerabilities — AdvisoryVulnerability[] (1:N)
```

**Dedup key priority:**

| Field | When used |
|---|---|
| `cveId` | CVE ID exists (highest priority) — NVD, OSV, and advisories share one row |
| `osvId` | No CVE ID but an OSV ID exists (GHSA-xxx, PYSEC-xxx, etc.) |
| `advisoryId` | No CVE/OSV ID — vendor advisory-specific ID only (FG-IR-xx-xxx, etc.) |

### Version normalization ([src/utils/version.ts](src/utils/version.ts))

Semantic versions are converted to integers for fast range queries:
- `1.2.3` → `1_002_003_000` (major × 1,000,000,000 + minor × 1,000,000 + patch × 1,000 + release)
- RPM release numbers are included as the 4th component: `2.9.13-6.el9` → `2_009_013_006`
- Stored as PostgreSQL BigInt with index-backed range scans

### OSV data ([src/worker/osv-fetcher.ts](src/worker/osv-fetcher.ts))

- Integrates with the OSV API (`https://api.osv.dev/v1/`) and the GCS ecosystem bucket
- Single lookup, package query, bulk import, and delta update modes
- **Malware detection**: imports `MAL-YYYY-NNNN` entries from [ossf/malicious-packages](https://github.com/ossf/malicious-packages) — malicious packages are searchable via `/api/v1/vulnerabilities/search` with exact version matching
- Automatically upserts to the `Vulnerability` master table on import
- Delta updates track the last run via `CollectionJob` and skip entries not modified since then

### NVD data ([src/worker/nvd-fetcher.ts](src/worker/nvd-fetcher.ts))

- Integrates with NVD REST API v2.0 (`https://services.nvd.nist.gov/rest/json/cves/2.0`)
- Full mirror with resumable pagination via `CollectionJob`
- Incremental update via `lastModStartDate`
- Authoritative source for CVSS scores

### KEV data ([src/worker/kev-fetcher.ts](src/worker/kev-fetcher.ts))

- Fetches the CISA KEV catalog (~1,200 entries)
- Updates `Vulnerability.isKev` and related fields
- Full-replace strategy (handles CISA-side removals)

### EPSS data ([src/worker/epss-fetcher.ts](src/worker/epss-fetcher.ts))

- Paginates the FIRST.org EPSS API (10,000 entries/page, ~320,000 total)
- Updates `epssScore` / `epssPercentile` in chunks of 1,000

### Vendor advisory framework ([src/worker/advisory-fetcher.ts](src/worker/advisory-fetcher.ts))

- Implement the `AdvisoryFetcher` interface to add new vendors
- `importAdvisoryData()` handles master table linkage automatically
- Import priority: CVE present → link to existing NVD record / no CVE → manage via `advisoryId`
- **Stale-advisory pruning**: `runAdvisoryFetcher()` deletes advisories that have vanished from the source (retracted, corrected) rather than keeping them forever. Each `AdvisoryFetcher` implements `isCompleteSnapshot(): boolean` — `true` for fetchers whose `fetch()` always returns the *complete* current set (a full re-scrape/archive fetch, the vast majority — Apache, Nginx, Tomcat, Fortinet, Broadcom, Splunk, Sophos, SonicWall, Zabbix, Red Hat, Oracle Linux, Oracle CPU), `false` when configured for a partial recent window (PAN/Cisco's `mode: 'latest'`, Oracle CPU's `latestOnly`) — pruning against a partial window would delete perfectly valid advisories that just fall outside it. Only complete-snapshot runs are eligible for pruning, and even then an advisory must be missing for 3 consecutive runs (`AdvisoryVulnerability.missingRunCount`, resets to 0 whenever it's seen again) before being hard-deleted, to tolerate a transient scrape hiccup rather than treating one bad run as a mass retraction. A run that returns zero advisories at all skips pruning entirely (indistinguishable from a parser/fetch bug returning an empty array without throwing — never treated as "everything was retracted"). Deleting an advisory also deletes its master `Vulnerability` row if that row was solely `advisoryId`-managed (no CVE/OSV data) and no other advisory still references it.

### Fortinet PSIRT ([src/worker/fortinet-fetcher.ts](src/worker/fortinet-fetcher.ts))

- Advisory discovery + CSAF 2.0 JSON per advisory (no authentication required). Paginates the full PSIRT advisory listing (`fortiguard.fortinet.com/psirt?page=N`) for complete historical coverage — previously discovered advisories via RSS only, which is a "what's new" feed exposing just a rolling window of recent items, not a full archive (found while building [boundary-value accuracy coverage](ACCURACY.md#boundary-value-sweep-fortinet--palo-alto-networks))
- Covers FortiOS, FortiProxy, FortiManager, FortiAnalyzer, and more
- Creates separate records per version branch (e.g., 7.6.x / 7.4.x / 7.2.x)

### Palo Alto Networks PSIRT ([src/worker/pan-fetcher.ts](src/worker/pan-fetcher.ts))

- RSS feed + CSAF JSON (no authentication required)
- Covers PAN-OS, Prisma Access, Cortex XDR, and more
- Parses `vers:generic/` version ranges into `versionEnd` (exclusive) and `versionFixed`

### Cisco PSIRT ([src/worker/cisco-fetcher.ts](src/worker/cisco-fetcher.ts))

- OAuth 2.0 via `CISCO_CLIENT_ID` / `CISCO_CLIENT_SECRET` + openVuln API + CSAF JSON
- Covers Cisco IOS XE, NX-OS, ASA, FTD, and more
- `pnpm import:cisco latest` fetches the latest 100 advisories only

### Oracle Linux ELSA ([src/worker/oracle-linux-fetcher.ts](src/worker/oracle-linux-fetcher.ts))

- Downloads Oracle's public OVAL XML feed (bzip2-compressed, no authentication required)
- Parses ELSA advisories: severity, CVE list with CVSS scores, affected package/version pairs
- Uses `criterion` comment text ("X is earlier than Y") to extract `versionEnd` (exclusive) per package
- Per-variant feeds supported: `ol9`, `ol8`, `ol7`, etc.
- RPM release numbers (e.g. `2.9.13-6.el9`) are handled by `normalizeVersion()` for accurate range queries

### CPE mapping notes

NVD describes affected products in CPE 2.3 format. This API uses the `<product>` field of `cpe:2.3:a:` (application) and `cpe:2.3:o:` (OS) entries as the package name, and infers the ecosystem from `<vendor>`. Hardware CPEs (`cpe:2.3:h:`) are excluded because their version is always `-`.

CPEs come in two forms: version range fields (`versionStartIncluding`, etc.) and versions embedded directly in the URI. The latter (e.g., `cpe:2.3:a:vendor:product:3.0:*:*:*:*:*:*:*`) is stored as `introduced = lastAffected = 3.0`.

Old-style CPEs encode version detail in the `<update>` field (parts[6]) rather than the version field. NVD range fields only reflect the base version, losing the qualifier. Two patterns are recovered automatically at import time:

| Pattern | Example CPE update field | Stored as | Query format |
|---|---|---|---|
| `update_N` | `update21` | `1.5.0_21` | `version=1.5.0_21` |
| `rcN` | `rc3` | `4.19.0-rc3` | `version=4.19.0-rc3` |

The following patterns are **not** recovered (version range ordering breaks due to how `normalizeVersion` strips non-numeric characters):

| Pattern | Affected products | Impact |
|---|---|---|
| `rN` / `rN-sN` | Juniper Junos (~63k entries) | Version ordering incorrect |
| `spN` | Windows Server Service Pack (~23k entries) | Version ordering incorrect |
| `pN` | FreeBSD/OpenBSD patches (~25k entries) | Treated as equivalent to `.N` patch release |

| vendor | Inferred ecosystem |
|---|---|
| `python` / `pypi` | `PyPI` |
| `nodejs` / `npm` | `npm` |
| `redhat` / `almalinux` | `AlmaLinux` |
| `golang` | `Go` |
| `rubygems` | `RubyGems` |

### NVD product name aliases

NVD sometimes uses multiple CPE product names for the same software (e.g., after vendor acquisitions). `src/config/product-aliases.ts` maps search terms to all known CPE product names. Aliases are verified against actual `NVDAffectedPackage` counts in the database.

| Search term | CPE product names searched | Reason |
|---|---|---|
| `nginx` | `nginx`, `nginx_open_source`, `nginx_open_source_subscription` | F5 acquisition renamed the product |
| `java` / `jre` / `jdk` | `jre`, `jdk` | Sun/Oracle uses both names interchangeably |
| `openjdk` | `openjdk` | Kept separate — old entries have unbounded wildcard ranges |
| `acrobat` / `acrobat_reader` | `acrobat`, `acrobat_dc`, `acrobat_reader`, `acrobat_reader_dc` | Four product names across generations |
| `opera` | `opera`, `opera_browser` | Two distinct product names in NVD |
| `macos` / `mac_os_x` | `macos`, `mac_os_x` | Apple renamed macOS |
| `joomla` | `joomla`, `joomla!` | Exclamation mark variant in older NVD entries |
| `curl` | `curl`, `libcurl` | Both names used in NVD |
| `tomcat` | `tomcat` | Version-specific names (tomcat7/8/9/10) absent from DB |
| `postgres` | `postgresql` | Common abbreviation |
| `spring` / `spring_framework` | `spring_framework` | NVD uses full name only |
| `k8s` | `kubernetes` | Common abbreviation |

## Data Collection

### NVD

```bash
pnpm import:nvd full              # Full mirror (~240k CVEs); resumes from CollectionJob if interrupted
pnpm import:nvd full <job-id>     # Resume a specific job
pnpm import:nvd update            # Incremental update (recent changes only)
pnpm import:nvd cve CVE-2021-44228  # Single CVE
pnpm import:nvd range 2024-01-01 2024-03-31  # Date range (auto-chunks at 120-day NVD limit)
```

| Condition | Estimated time |
|---|---|
| Without `NVD_API_KEY` (10 req/min) | ~12 min |
| With `NVD_API_KEY` (50 req/min) | ~2.5 min |

Get a free API key at [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key).

### OSV

```bash
pnpm import:osv sample                    # Import sample data
pnpm import:osv package npm lodash        # All vulnerabilities for a package
pnpm import:osv ecosystem npm             # Entire ecosystem bulk download (full)
pnpm import:osv ecosystem Go              # Go modules
pnpm import:osv ecosystem Packagist       # PHP Composer packages
pnpm import:osv update npm               # Delta update since last run
pnpm import:osv update PyPI              # Delta update for PyPI
pnpm import:osv update malware           # Delta update for MAL entries
pnpm import:osv malware                  # Full import of all MAL entries (ossf/malicious-packages)
pnpm import:osv id GHSA-67hx-6x53-jw92   # By OSV ID
pnpm import:osv id CVE-2021-44228         # By CVE ID
```

Delta updates (`update <ecosystem>`) download the full ecosystem ZIP but skip entries whose `modified` timestamp is not newer than the last completed `CollectionJob`. `update malware` makes one GitHub tree API call (60 req/hr unauthenticated); set `GITHUB_TOKEN` only if running it more than 60 times per hour.

**Onboarding a new ecosystem**: always run the full `ecosystem <name>` import *before* the daily delta job (`osv-<ecosystem>`) starts running against it — the delta path only ever catches entries modified after its cursor, so if the initial backfill is skipped or interrupted partway, the missing older entries are never picked up by any later delta run. `pnpm import:osv ecosystem <name>` now records its own `osv-full-<ecosystem>` `CollectionJob` (separate from the delta job's `osv-<ecosystem>`, so it doesn't clobber that dashboard row) so a completed run is auditable — this used to leave no trace at all, which is exactly how most tracked ecosystems ended up permanently stuck well below 100% coverage (as low as 3.7% for GitHub Actions) despite their delta jobs reporting "completed" every day. Verify actual completeness against the live OSV bulk export at any time with:
```bash
pnpm validate:osv-coverage              # check every tracked ecosystem
pnpm validate:osv-coverage Go PyPI      # check only the named ecosystem(s)
```

**Supported ecosystems for `ecosystem` / `update` commands:**

| Ecosystem value | Language / Platform |
|---|---|
| `npm` | Node.js |
| `PyPI` | Python |
| `Go` | Go modules |
| `RubyGems` | Ruby |
| `crates.io` | Rust |
| `Packagist` | PHP (Composer) |
| `Maven` | Java / Kotlin |
| `NuGet` | .NET |
| `Hex` | Elixir / Erlang |
| `Pub` | Dart / Flutter |
| `ConanCenter` | C / C++ |
| `SwiftURL` | Swift |
| `CRAN` | R |
| `Linux` | Linux kernel |
| `Android` | Android |
| `OSS-Fuzz` | OSS-Fuzz projects |
| `Bitnami` | Bitnami application stack |

> Ecosystem names are **case-sensitive** — use exactly the values shown above.
> Linux distribution ecosystems (Alpine, Debian, Ubuntu, AlmaLinux, Rocky Linux, etc.) can be imported without a version suffix (e.g. `pnpm import:osv ecosystem Ubuntu`). When **searching**, the version suffix is optional — `?ecosystem=Ubuntu` matches all Ubuntu versions via prefix match; `?ecosystem=Ubuntu:22.04:LTS` narrows to that specific version. Note that distro ecosystems store distro-format version strings, so upstream semver versions will not match.

### CISA KEV

```bash
pnpm import:kev full    # Fetch catalog and sync to master table (full-replace)
pnpm import:kev stats   # Show KEV statistics from DB
```

### EPSS

```bash
pnpm import:epss full                    # Today's daily dataset
pnpm import:epss full 2024-03-01         # Dataset for a specific date
pnpm import:epss cve CVE-2021-44228      # Update a single CVE
```

### Vendor advisories

```bash
pnpm import:fortinet                  # Fortinet PSIRT (all)
pnpm import:pan                       # Palo Alto Networks PSIRT (all)
pnpm import:cisco                     # Cisco PSIRT (all, requires credentials)
pnpm import:cisco latest              # Cisco PSIRT (latest 100 only)
pnpm import:sophos                    # Sophos security advisories (63 advisories via sitemap + browser)
pnpm import:sonicwall                 # SonicWall PSIRT (all, ~200 advisories via JSON API)
pnpm import:oracle-cpu                # Oracle Critical Patch Updates (all historical CPUs via CSAF)
pnpm import:oracle-cpu latest         # Oracle CPU (most recent CPU only)
pnpm import:broadcom                  # Broadcom/VMware security advisories (VMSA series, JSON API)
```

### Oracle Linux

```bash
pnpm import:oracle-linux              # Full feed (all OL versions)
pnpm import:oracle-linux ol9          # Oracle Linux 9 only
pnpm import:oracle-linux ol8          # Oracle Linux 8 only
```

```bash
# Search Oracle Linux packages
curl -H "x-api-key: $API_KEY" \
  "http://localhost:5000/api/v1/vulnerabilities/search?package=rsync&ecosystem=oracle-linux&version=3.2.4"
```

> **ecosystem value**: `oracle-linux` (no version suffix). Range queries use RPM version strings.
> Specify versions as `MAJOR.MINOR.PATCH-RELEASE.dist` (e.g. `3.2.5-3.el9`) or upstream `MAJOR.MINOR.PATCH` (e.g. `3.2.4`).
> Routed to the same exact `rpmvercmp` comparison as Red Hat (see [`rpmAdvisoryVendor`](src/utils/search-helpers.ts)) — previously this ecosystem value wasn't wired up and silently fell back to the lossy BigInt approximation regardless of what this doc said; see the [boundary-value sweep](ACCURACY.md#boundary-value-sweep-rhel--oracle-linux) in ACCURACY.md.

### Sophos

Sophos security advisories. No authentication required.

```bash
pnpm import:sophos                    # All 63 advisories (sitemap + RSS + headless browser)
```

- Fetches advisory IDs from sitemap → enriches with RSS → falls back to Playwright stealth for pages where CVE is not in the title
- CVE IDs and severity extracted; no version ranges available (use CVE ID lookup instead)
- Products: XG/XGS Firewall, Sophos AP series, etc.

### SonicWall

SonicWall PSIRT advisories via public JSON API. No authentication required.

```bash
pnpm import:sonicwall                 # All advisories (~200)
```

- Fetches directly from the JSON API (`psirtapi.global.sonicwall.com/api/v1/vulnsummary/`) that the React SPA calls internally
- Extracts CVE IDs, severity, CVSS score/vector, and product family names
- Version numbers extracted best-effort from HTML product tables
- Products: SonicOS Gen5/6/7/8 firewalls, SMA series, etc.

### Broadcom / VMware

Broadcom/VMware VMSA advisories via public JSON API + Playwright for version detail. No authentication required.

```bash
pnpm import:broadcom                  # All VMSA advisories (JSON API + Playwright)
```

- Fetches the advisory list from the Broadcom support portal JSON API (unauthenticated POST endpoint)
- Renders each advisory detail page with Playwright to extract the affected/fixed version table
- VMware update-level version strings (`8.0 U3d`) are automatically normalized (`8.0.3-4`) for range queries
- Products: vCenter Server, ESXi, NSX, VMware Aria, Horizon, Carbon Black, and more

> **Version query format**: Use VMware update-level strings — `version=8.0+U3d` is automatically normalized.

### Oracle Critical Patch Update

Oracle quarterly CPU advisories. No authentication required.

```bash
pnpm import:oracle-cpu                # All historical CPUs (via RSS)
pnpm exec tsx src/scripts/import-oracle-cpu.ts latest   # Most recent CPU only
```

- Discovers CPUs from Oracle RSS (28 quarters back to CPUJan2020 — Oracle's own feed doesn't go back further)
- Fetches CSAF 2.0 JSON per CPU (CPUApr2022 onward), falling back to the older CVRF 1.1 XML format for CPUJan2020–CPUApr2022, where CSAF isn't published. CPUs before CPUJan2020 have neither format and aren't covered (would require scraping the legacy HTML advisory pages)
- Each CPU is split into per-CVE advisory entries (`externalId: cpuapr2026-CVE-XXXX-NNNN`), merging affected products from every `<Vulnerability>` element sharing that CVE (a single CVE can be split across several CVRF entries, one per affected-product subset — naively taking one entry per CVE would silently drop the rest)
- ~450 CVEs per CPU covering MySQL, Java SE, WebLogic, E-Business Suite, Fusion Middleware, etc.
- Separate from `advisory-oracle-linux` (ELSA) — this covers Oracle software products, not OS packages

### Splunk

Splunk security advisory archive. No authentication required.

```bash
pnpm import:splunk                    # All advisories (300+, single archive page)
```

- Fetches the full historical table from `advisory.splunk.com/advisories` (one page covers the entire archive)
- Extracts CVE ID, CVSS score/vector, per-branch affected/fixed versions, description, solution, and mitigations
- Deduplicates rows sharing the same SVD ID
- Products: Splunk Enterprise, Splunk Cloud Platform, Splunk AI Toolkit, etc. (each branch recorded as a separate affected product)

### Apache HTTP Server

Apache httpd 2.4 security advisories. No authentication required.

```bash
pnpm import:apache                    # All advisories (httpd.apache.org/security/vulnerabilities_24.html)
```

- Parses the official vulnerabilities page HTML into per-CVE blocks
- Handles multiple "Affects" notations: `before X`, `through X`, `>=X, <=Y`, and comma-separated version lists
- Covers 2.4.x only (2.2/2.0/1.3 are EOL and out of scope)
- Same source used by `pnpm validate:apache` for accuracy validation

### Zabbix

Zabbix security advisories. No authentication required (public client-side search-only key).

```bash
pnpm import:zabbix                    # All advisories (paginated via Typesense search API)
```

- Fetches directly from the Typesense search API that zabbix.com's own advisory page uses internally
- Extracts CVE ID (alongside Zabbix's own ZBV-YYYY-MM-DD-N identifier), severity, CVSS score, and affected/fixed versions
- Handles range notation (`6.0.0-6.0.44`), single exact versions, and wildcard upper bounds (`4.4.4-4.4.*`); free-text legacy entries are skipped best-effort

### Apache Tomcat

Apache Tomcat security advisories. No authentication required.

```bash
pnpm import:tomcat                    # All advisories across all major branch pages
```

- tomcat.apache.org publishes one security page per major version branch (`security-8.html`, `security-9.html`, ...); fetches all known branch pages and skips ones that don't exist (future/retired branches)
- The same CVE often affects multiple branches with different version ranges — these are merged into a single advisory with one `affectedProducts` entry per branch, rather than being split across duplicate rows
- CVE IDs are extracted from the advisory heading only, to avoid false matches from CVE mentions in description text (e.g. "the fix for CVE-YYYY was incomplete")
- Same source used by `pnpm validate:tomcat` for accuracy validation

### nginx

nginx security advisories. No authentication required.

```bash
pnpm import:nginx                     # All advisories (nginx.org/en/security_advisories.html)
```

- Parses the official security advisories page; handles comma-separated multi-range notation (e.g. `"0.6.18-1.25.2, 1.21.0-1.25.1"`) as separate `affectedProducts` entries under one advisory
- Same source used by `pnpm validate:nginx` for accuracy validation

### Adding a new vendor

Implement the `AdvisoryFetcher` interface:

```typescript
// src/worker/my-vendor-fetcher.ts
import type { AdvisoryFetcher, NormalizedAdvisory } from './advisory-fetcher.js';

export class MyVendorFetcher implements AdvisoryFetcher {
  source() { return 'myvendor'; }

  async fetch(): Promise<NormalizedAdvisory[]> {
    // Fetch from vendor API and return NormalizedAdvisory[]
  }
}
```

Then call `runAdvisoryFetcher(new MyVendorFetcher())` — master table linkage is handled automatically.

## Architecture

### Master table deduplication

When the same CVE appears in multiple sources, the `Vulnerability` master table consolidates them into one row keyed by CVE ID:

```
CVE-2021-44228 (Log4Shell)
  ├── NVDVulnerability            ─┐
  ├── OSVVulnerability (GHSA-...) ─┤→ Vulnerability (cveId: "CVE-2021-44228", isKev: true)
  └── AdvisoryVulnerability       ─┘   ↑ all sources share this single master row
```

Advisories without a CVE ID are managed as independent master rows via `advisoryId`.

### Fast version search

1. **Normalize versions**: `1.2.3` → `1_002_003_000` (PostgreSQL BigInt); RPM `2.9.13-6.el9` → `2_009_013_006`
2. **Index-backed range scan**: `(ecosystem, packageName)` + `(packageName, introducedInt, fixedInt)`

```sql
WHERE ecosystem = 'npm'
  AND packageName = 'lodash'
  AND introducedInt <= 4017020000
  AND (fixedInt IS NULL OR fixedInt > 4017020000)
```

Vendor advisory search also uses `versionStartInt` / `lastAffectedInt` (inclusive) or `versionEndInt` (exclusive), plus an exact match against `affectedVersions[]` for distro ecosystems.

### Source priority

| Field | Authoritative source |
|---|---|
| `cvssScore` / `cvssVector` / `severity` | NVD (always overwrites) |
| `summary` / `publishedAt` | NVD preferred; OSV/Advisory used only when NVD is null |
| `isKev` / `kev*` | CISA KEV (updated independently) |
| `epssScore` / `epssPercentile` | FIRST.org EPSS (updated independently) |
| `workaround` / `solution` / `url` | Advisory (vendor-specific fields) |

## Testing

```bash
pnpm test               # unit tests (no DB required)
pnpm test:integration   # integration tests (requires TEST_DATABASE_URL — use a disposable DB, separate from your dev DB)
```

One-time setup for `TEST_DATABASE_URL`:
```bash
createdb heretix_test
# add TEST_DATABASE_URL="postgresql://user:password@localhost:5432/heretix_test" to .env
TEST_DATABASE_URL="postgresql://...heretix_test" pnpm exec prisma migrate deploy
```

Both run on every `push`/`pull_request` via CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)). See [SPEC.md](SPEC.md) for test coverage details and design rationale.

### Automatic scheduler

Job definitions (source key, label, cron, run logic) are centralized in `src/jobs/registry.ts` (`STATIC_JOBS`). On startup `src/scheduler.ts` iterates the registry to register cron jobs, checks each job's `JobConfig` enabled flag at fire time, then calls `executeJob()` from `src/jobs/executor.ts` — which handles the shared `CollectionJob` lifecycle (`running` → `completed`/`failed` + counts) and concurrency locking for every job.

| Job | Schedule |
|---|---|
| NVD delta update | Every 2 hours |
| KEV full replace | Daily at 09:00 UTC |
| EPSS bulk update | Daily at 10:00 UTC |
| Fortinet advisory | Daily at 11:00 UTC |
| PAN advisory | Daily at 11:15 UTC |
| Cisco advisory | Daily at 11:30 UTC |
| Oracle Linux advisory | Daily at 11:45 UTC |
| Sophos advisory | Daily at 12:00 UTC |
| SonicWall advisory | Daily at 12:15 UTC |
| Oracle CPU advisory | Daily at 12:30 UTC |
| Broadcom/VMware advisory | Daily at 13:00 UTC |
| Red Hat RHEL 9 advisory | Daily at 13:15 UTC |
| Red Hat RHEL 8 advisory | Daily at 13:30 UTC |
| Splunk advisory | Daily at 13:45 UTC |
| Apache HTTP Server advisory | Daily at 14:00 UTC |
| Zabbix advisory | Daily at 14:15 UTC |
| Apache Tomcat advisory | Daily at 14:30 UTC |
| nginx advisory | Daily at 14:45 UTC |
| OSV delta (per ecosystem, all in DB) | Daily at 08:00 UTC |
| MAL delta (ossf/malicious-packages) | Daily at 08:30 UTC |

Each OSV ecosystem runs as an independent job (`osv-{ecosystem}`) so its status, enable/disable toggle, and manual run appear separately in the dashboard. Jobs disabled via `JobConfig` are skipped at fire time (toggling takes effect immediately, without re-registering cron). Manual runs are also available via `POST /api/v1/jobs/:source/run` regardless of the enabled state.

## Accuracy Validation

Scripts measure Precision / Recall against official security advisories, including automatic boundary-value sweeps for products with a dedicated `AdvisoryFetcher`. Moved to a dedicated file since coverage keeps growing: **[ACCURACY.md](ACCURACY.md)**.

## Known Issues

### Ubuntu/Debian OSV false positives (mitigated)

Ubuntu/Debian OSV advisories use `introduced: "0"` + `fixed: "<ubuntu_patched_version>"` to indicate that a package update is required — not to express an upstream version range. Comparing upstream semver versions against this range would cause false positives, so distro ecosystems primarily use exact-match against `affectedVersions` instead. See [Search behavior by ecosystem](#search-vulnerabilities-single) for current behavior and examples.

Most Debian entries (and a smaller fraction of Ubuntu/Alpine ones) publish only that `introduced`/`fixed` range with no enumerated `affectedVersions` list at all — exact-match alone silently matched nothing for those rows regardless of the version queried (confirmed to affect ~68% of Debian's OSV data). Fixed by adding a `compareDpkgVersions()` ([`src/utils/dpkg-version.ts`](src/utils/dpkg-version.ts), the dpkg version-comparison algorithm) range-comparison fallback for `Ubuntu:*`/`Debian:*`/`Alpine:*` ecosystems: exact-match is tried first, and only falls back to range comparison when the enumerated list doesn't contain (or doesn't exist for) the queried version — so already-correct exact-match results are unaffected.

Ecosystem alias: `composer` is automatically mapped to `Packagist` (OSV's ecosystem name for PHP Composer packages).

### RHEL/Oracle Linux module-stream false positives (fixed at the source; one residual gap remains for products other than nodejs/postgresql/httpd/mysql/mariadb/php)

RHEL/Oracle Linux distribute some software as DNF module streams — several parallel, coexisting version lineages under one package name (e.g. `postgresql:12`/`:13`/`:15`/`:16`/`:17`/`:18`, similarly for `nodejs`, `mysql`, `mariadb`, `php`, `ruby`, `redis`, `podman`, `qemu-kvm`, `libvirt`, and others). The human-readable `"<package> is earlier than <version>"` OVAL criterion RedHatFetcher/OracleLinuxFetcher parse only expresses an exclusive upper bound, so a fix-version row for a *newer* stream (e.g. postgresql:18 fixed at `18.4-2.module+el9.8.0...`) had no way to exclude an unrelated, older stream's query (e.g. postgresql 16.4) from numerically matching too — confirmed to affect 155 product names across the packages above.

**Root-cause fix**: the OVAL feed does carry the missing lower-bound information — it's just in a sibling criterion the fetchers previously discarded. RHEL/Oracle Linux OVAL always pairs a `"Module <name>:<stream> is enabled"` check and the OR-of-packages it guards as two children of the same `<criteria operator="AND">` parent (verified directly against both vendors' live feeds). `collectCriteria()` in both [`redhat-fetcher.ts`](src/worker/redhat-fetcher.ts) and [`oracle-linux-fetcher.ts`](src/worker/oracle-linux-fetcher.ts) now walks that tree propagating the stream label down to every criterion it scopes, and sets `versionStart` from it directly at import time via `moduleStreamVersionStart()` — no per-product heuristic or allowlist, and self-gating by construction (a product with no module criterion in its OVAL entry is untouched; confirmed 1:1 correlation with the `.module+` build marker across live samples from both feeds). The stream label is read verbatim, not parsed as an integer: most products use a plain number (`nodejs:20`), but `mysql:8.4` and `mariadb:10.11` don't — an early version of this fix only captured digits and silently failed to extract those, so their rows fell through to a cruder blanket backfill that collapsed e.g. mysql's 8.0 and 8.4 lines onto the same floor (confirmed and fixed: see below). `searchAdvisoryRpm()` ([`vulnerabilities.ts`](src/api/routes/vulnerabilities.ts) / `matchesRpmVersionRange()` in [`search-helpers.ts`](src/utils/search-helpers.ts)) then honors `versionStart` like any other row. A one-time backfill (`pnpm migrate:module-version-start`) applied this to rows already imported before the fix; the fetchers apply it automatically to all future imports, across every DNF-module product.

`moduleStreamVersionStart()` also guards against one further failure mode found by re-running [ACCURACY.md's RHEL/Oracle Linux sweep](ACCURACY.md#boundary-value-sweep-rhel--oracle-linux) after the fix above shipped: the stream label isn't always the packaged software's own version. RHEL8's `javapackages-tools:201801` module bundles several independently-versioned Java build tools (`ant`, `xmvn`, an older `maven` line, ...) under one stream labeled by build generation ("201801") rather than any of their real versions — using it as a floor made 510 product names permanently unmatchable (a floor far above their own ceiling). Detected generically, not by module name (since other modules could share this shape): the label is only used as a floor when it's numerically `<=` the row's own `versionEnd`; otherwise it falls back to `inferBareVersionStart()` exactly as if there had been no Module criterion at all. This isn't a "looks date-shaped" heuristic — some products genuinely use calendar-based versions that legitimately satisfy the check (`python-pytz`'s "2017" stream matches its own "2017.2..." version) — only a label truly incompatible with the row's own version gets rejected. A one-time backfill (`pnpm migrate:fix-implausible-module-floor`) corrects rows already written with an implausible floor before this guard existed.

**Residual gap**: some advisories carry no Module criterion to extract from at all — either they predate a package's move to DNF modules (e.g. RHSA-2022:6595 on RHEL9, `nodejs 16.16.0-1.el9_0`), or, for `postgresql`/`httpd`/`php` on some RHEL major versions, the product simply isn't (or wasn't) modularized there. `inferBareVersionStart()` ([`advisory-helpers.ts`](src/worker/advisory-helpers.ts)) falls back to the row's own `versionEnd` for `nodejs`, `postgresql`, `httpd`, and the `mysql`/`mariadb`/`php` families (including same-source-RPM subpackages like `mysql-server`, but excluding independently-versioned bundled tools like `mysql-selinux`, `mariadb-connector-c`, and PHP's `php-pecl-*`/`php-pear` — each confirmed individually), each confirmed by a live before/after query — not a blanket per-`.module+`-row rule like the primary fix above. The floor granularity is per-product, matching each product's real, mutually-incompatible release-line boundary: `nodejs` and `postgresql` (10+) need only a single major digit; `postgresql` before 10 (`9.0`–`9.6`), `httpd` (`2.2`/`2.4`), and the ancient pre-DNF `mysql` (`5.0`/`5.1`), `mariadb` (`5.5`), and `php` (`5.1`/`5.3`) lines all need the full two-component version. See [ACCURACY.md](ACCURACY.md#boundary-value-sweep-nodejs-module-streams--rhel--oracle-linux) for detailed numbers per product. This fallback is **not** generalized to the other (product, vendor) pairs found to mix modular and bare rows (`golang`, `podman`, `libvirt`, `qemu-kvm`, ...) — for those it's unverified whether a bare row is a genuine pre-modularization remnant of the same lineage (safe to floor, and at what granularity) or a legitimately continuous version history spanning release-line bumps (where flooring would introduce new false negatives).

### Go sub-module search requires exact module path

OSV records Go vulnerabilities at the sub-module level (e.g., `go.opentelemetry.io/otel/baggage`), not at the parent module level (`go.opentelemetry.io/otel`). Searching with the parent module returns no results even if a sub-module is affected.

Workaround: search with the exact sub-module path:
```
GET /api/v1/vulnerabilities/search?package=go.opentelemetry.io/otel/baggage&version=1.36.0&ecosystem=Go
```

Dependabot and similar tools resolve the full dependency graph to find affected sub-modules. Prefix-based matching (searching `go.opentelemetry.io/otel` to also match `/baggage`) is not yet implemented.

### Sophos advisory source has no version ranges

Sophos advisories are collected via sitemap + RSS + headless browser rendering (63 advisories total). CVE IDs and severity are extracted; however, affected version ranges are not available because the advisory detail pages do not expose structured version data. Advisories are linked to CVEs where present, but version-specific matching (`?version=18.0.1`) will not return Sophos results. Use CVE ID lookup (`/api/v1/vulnerabilities/CVE-YYYY-NNNNN`) to find associated Sophos advisories.

### PAN CSAF documents with an empty product_tree (pre-2013 CVEs only)

Investigating a dashboard count that looked low (211 imported vs. 563 known advisory IDs) found two distinct gaps in [`pan-fetcher.ts`](src/worker/pan-fetcher.ts)'s CSAF parsing. One was a real, now-fixed bug: `buildProductMap()` only recognized range-shaped `product_tree` branches (`vers:generic/<12.1.4`), so a discrete/placeholder branch paired with a separate range branch under the same product (e.g. Prisma Access Agent's CSAF, which pairs a versionless "Prisma Access Agent 0" affected-marker branch with a `vers:generic/...>=26.2.2` fixed branch) resolved to no usable product data at all, and the whole advisory — despite carrying real vulnerability data — was silently dropped as unparseable. Fixed by having `buildProductMap()` record discrete branches too (with no version bound, matched with whatever `versionFixed` a sibling range branch supplies), rather than requiring every branch name to be range-shaped.

The other gap is a genuine upstream data-quality issue, left unfixed: a Palo Alto CSAF document's `product_status` can reference product ids (e.g. `PANW-PAN-OS-496`) that don't appear anywhere in that same document's `product_tree` at all — confirmed live on several pre-2013 CVEs (e.g. `CVE-2012-6593`), where `product_tree.branches` is a bare `[]`. There is no version data to recover from an empty tree no matter how it's parsed; a product name could be *guessed* from the id string itself, but doing so reliably is not possible (some real PAN product names contain a hyphen, e.g. "PAN-OS", others a space, e.g. "Prisma Access Agent", and the id string alone doesn't distinguish which) and was judged not worth the resulting product-name inconsistency for a handful of advisories over a decade old. These stay unimported; CVE ID lookup on nvd.nist.gov will still show PAN's exposure, just not through this API.

### NVD vs OSV package name discrepancies

NVD uses CPE `product` as the package name, which may differ from the OSV package name (e.g., NVD=`xz`, OSV=`xz-utils`). Searching both sources simultaneously requires name normalization. (not yet implemented)

### In-memory pagination for large result sets

The current search implementation fetches all `NVDAffectedPackage` / `OSVAffectedPackage` rows without a limit, deduplicates in memory, then applies `limit`/`offset`. This is fine for most packages (~900 entries), but packages with thousands of CPE entries (e.g., `openssl`, `linux_kernel`) may see increased response time and memory usage.

Two more limitations specific to the accuracy-validation scripts (cross-source version-namespace collisions, RHEL/Oracle Linux OVAL feed revisions) are documented in [ACCURACY.md](ACCURACY.md#known-limitations).

## Troubleshooting

### Database connection error

```
Error: P1001: Can't reach database server
```
- Check `DATABASE_URL` in `.env`
- Confirm PostgreSQL is running
- Check firewall / security group settings

### Migration error

```bash
pnpm prisma migrate reset   # Reset migration state
pnpm db:migrate             # Re-run migrations
```

### Version normalization edge cases

Versions are converted as `major × 1,000,000,000 + minor × 1,000,000 + patch × 1,000 + release`.

| Case | Behavior | Impact |
|---|---|---|
| Pre-release (`1.0.0-beta.1`) | Treated as slightly less than the release (`1.0.0 - 1`) | Minor inaccuracy possible |
| Build metadata (`1.0.0+build.123`) | Stripped and ignored | No impact |
| RPM release (`2.9.13-6.el9`) | Release number (6) included as 4th component → `2_009_013_006` | Accurate sub-release range queries |
| minor/patch/release ≥ 1,000 | Clamped to 999 (each occupies a fixed-width slot; letting it through unclamped would overflow into the next component up and silently corrupt it) | Bounded imprecision among values in this range for the same package, rather than colliding with an unrelated version |
| Any component > 999,999 | Normalization fails (null) — treated as garbage (timestamp, git hash), not a real version | Falls back to approximate match |
| Non-semver (date-based, etc.) | Normalization fails (null) | Falls back to approximate match |

**Approximate match fallback**: when normalization fails, all vulnerabilities matching the package name and ecosystem are returned with `approximateMatch: true`.

**RPM release strings with multiple dot-separated segments** (e.g. `2136.344.4.3` in Oracle Linux UEK kernel builds like `5.4.17-2136.344.4.3.el8uek`) only have their *leading* integer group (`2136`) captured — everything after the first dot is ignored, same as it always has been. Different builds sharing that leading group (`2136.344...` vs `2136.331...`) normalize identically. This is orthogonal to the ≥1,000 clamping above (already true for release values under 1,000 too) and not fixed here for the same reason as the RPM sub-release / 4-component precision limits already accepted elsewhere in this section — `ecosystem=oracle-linux`/`ecosystem=red-hat` queries are unaffected, since those route through `compareRpmVersions()` (full RPM release-string comparison) instead of this generic encoding.

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.
