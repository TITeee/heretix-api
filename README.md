# Heretix API

A simple, high-performance vulnerability management API backed by PostgreSQL. It collects and normalizes data from **OSV**, **NIST NVD**, **CISA KEV**, **EPSS**, **Oracle Linux ELSA**, and **vendor security advisories**, then provides fast, deduplicated search through a unified master table.

[日本語版 README](README.ja.md)

## Features

- **Multi-source**: OSV (Open Source Vulnerabilities), NIST NVD (CVE), Oracle Linux ELSA (OVAL XML), and vendor advisories (Fortinet, Palo Alto Networks, Cisco PSIRT, and more)
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

## Tech Stack

| | |
|---|---|
| **Runtime** | Node.js |
| **Framework** | Fastify |
| **ORM** | Prisma |
| **Database** | PostgreSQL 15+ |
| **Language** | TypeScript |
| **Logging** | Pino |
| **Validation** | Zod |

## Setup

### 1. Install dependencies

```bash
pnpm install
```

### 2. Prepare PostgreSQL

Use an existing PostgreSQL instance or install a new one.

**Local PostgreSQL:**
```bash
# Verify PostgreSQL 15+ is installed
psql --version

# Create the database
createdb vulndb
```

**Remote PostgreSQL:** Supabase, Neon, Railway, AWS RDS, etc. are all supported.

### 3. Configure environment variables

Copy `.env.example` to `.env` and fill in the values:

```env
DATABASE_URL="postgresql://postgres:password@localhost:5432/vulndb?schema=public"
PORT=5000
NODE_ENV=development
API_KEY=your-api-key-here   # Required. Requests without x-api-key header return 401
NVD_API_KEY=                # Optional. Relaxes NVD rate limit from 10 → 50 req/min
```

### 4. Run database migrations

```bash
pnpm db:migrate
```

### 5. Start the development server

```bash
pnpm dev
```

The server starts at http://localhost:5000.

> **Import scripts in dev mode**: `pnpm import:*` commands run against the compiled `dist/` output. When running `pnpm dev` without a prior build, use `pnpm exec tsx src/scripts/<script>.ts` instead:
> ```bash
> pnpm exec tsx src/scripts/import-osv.ts update npm
> pnpm exec tsx src/scripts/import-nvd.ts update
> ```

## Database Management

### Prisma Studio

Browse and edit the database in a GUI:
```bash
pnpm db:studio
```
Opens http://localhost:5555 in your browser.

### Generate ER diagram

Generate a Mermaid ER diagram of the schema:
```bash
pnpm db:erd
```
Output is saved to `docs/erd.md`.

## Import Status Dashboard

A lightweight web dashboard is available at `/dashboard` (no authentication required).

```
GET /dashboard
```

Displays:
- **Record counts** — total rows in NVD, OSV, KEV, and Advisory tables
- **Import status table** — latest `CollectionJob` per source with status badge, last completed time, inserted/updated counts, and any error message
- **OSV ecosystems** — list of all ecosystems currently imported in the database

Auto-refreshes every 60 seconds. Also available as JSON:

```
GET /api/v1/import-status
```

Example: `http://localhost:5000/dashboard`

---

## API Endpoints

All endpoints require the `x-api-key` header to match the `API_KEY` environment variable.

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

## Project Structure

```
heretix-api/
├── src/
│   ├── api/
│   │   ├── routes/
│   │   │   └── vulnerabilities.ts   # Vulnerability API endpoints
│   │   └── server.ts                # Fastify server configuration
│   ├── db/
│   │   └── client.ts                # Prisma client
│   ├── scripts/
│   │   ├── import-osv.ts            # OSV import CLI
│   │   ├── import-nvd.ts            # NVD import CLI
│   │   ├── import-kev.ts            # CISA KEV import CLI
│   │   ├── import-epss.ts           # EPSS score import CLI
│   │   ├── import-fortinet.ts       # Fortinet PSIRT import CLI
│   │   ├── import-pan.ts            # Palo Alto Networks PSIRT import CLI
│   │   ├── import-cisco.ts          # Cisco PSIRT import CLI
│   │   ├── import-oracle-linux.ts   # Oracle Linux ELSA import CLI
│   │   ├── validate-tomcat.ts       # Tomcat search accuracy validator
│   │   ├── validate-apache.ts       # Apache HTTPD search accuracy validator
│   │   ├── validate-nginx.ts        # nginx search accuracy validator
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
│   │   └── sophos-fetcher.ts        # Sophos sitemap + RSS + headless browser fetch
│   ├── config/
│   │   └── product-aliases.ts       # NVD CPE product name alias mappings
│   ├── utils/
│   │   ├── logger.ts                # Pino logger configuration
│   │   ├── version.ts               # Version normalization utility
│   │   ├── cpe.ts                   # CPE 2.3 parse utility
│   │   └── browser.ts               # Shared Playwright stealth browser singleton
│   ├── scheduler.ts                 # node-cron based automatic update scheduler
│   └── index.ts                     # Entry point
├── prisma/
│   ├── schema.prisma                # Database schema
│   └── migrations/                  # Migration files
├── docs/
│   └── erd.md                       # ER diagram (Mermaid)
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

### Fortinet PSIRT ([src/worker/fortinet-fetcher.ts](src/worker/fortinet-fetcher.ts))

- RSS feed + CSAF 2.0 JSON (no authentication required)
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

### Automatic scheduler

When the server starts, `src/scheduler.ts` registers cron jobs:

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
| OSV delta (per ecosystem, all in DB) | Daily at 08:00 UTC |
| MAL delta (ossf/malicious-packages) | Daily at 08:30 UTC |

Each OSV ecosystem runs as an independent job (`osv-{ecosystem}`) so its status appears separately in the dashboard.

## Development & Deployment

### Docker (recommended)

```bash
# Copy and edit environment variables
cp .env.example .env

# Start in foreground (recommended for first run — shows logs)
API_KEY=your-api-key docker compose up --build

# Start in background (detached mode)
API_KEY=your-api-key docker compose up --build -d
```

The API will be available at `http://localhost:5000`.

`docker compose down` to stop. Add `-v` to also remove the database volume.

### Manual

#### Build

```bash
pnpm build
```

#### Start production server

```bash
pnpm start
```

### Production environment variables

```env
DATABASE_URL="postgresql://user:password@host:5432/dbname?schema=public"
PORT=5000
NODE_ENV=production
API_KEY=your-api-key-here   # Required. Requests without x-api-key header return 401
NVD_API_KEY=                # Optional. Relaxes NVD rate limit from 10 → 50 req/min
CISCO_CLIENT_ID=            # Required for Cisco PSIRT import (openVuln API client ID)
CISCO_CLIENT_SECRET=        # Required for Cisco PSIRT import (openVuln API client secret)
GITHUB_TOKEN=               # Optional. Authenticates the single GitHub tree API call used by MAL import/update. Only needed if running MAL commands more than 60 times/hr from the same IP.
```

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

## Accuracy Validation

Scripts to measure Precision / Recall against official security advisories:

```bash
pnpm validate:tomcat 9.0.100      # vs tomcat.apache.org
pnpm validate:apache 2.4.62       # vs httpd.apache.org
pnpm validate:nginx 1.24.0        # vs nginx.org
```

## Known Issues

### Ubuntu/Debian OSV false positives (mitigated)

Ubuntu/Debian OSV advisories use `introduced: "0"` + `fixed: "<ubuntu_patched_version>"` to indicate that a package update is required — not to express an upstream version range. Comparing upstream semver versions against this range causes false positives.

**Current behavior:**
- **No `ecosystem` specified**: distro-specific ecosystems (`Ubuntu:*`, `Debian:*`, `Alpine:*`, `AlmaLinux:*`, `Rocky:*`, `Red Hat:*`, `CentOS:*`) are excluded from results
- **`ecosystem` explicitly specified** (e.g., `ecosystem=Ubuntu:20.04:LTS`): uses `affectedVersions` exact match with dpkg/rpm-format versions; upstream versions (e.g., `5.1.1`) do not match distro-format strings, so no false positives occur
- **Ecosystem aliases**: `composer` is automatically mapped to `Packagist` (OSV ecosystem name for PHP Composer packages)

```
# Correct (Ubuntu 20.04 package version)
GET /api/v1/vulnerabilities/search?package=xz-utils&version=5.2.4-1ubuntu1&ecosystem=Ubuntu:20.04:LTS

# Upstream version → no match in distro ecosystem (intentional)
GET /api/v1/vulnerabilities/search?package=xz-utils&version=5.1.1&ecosystem=Ubuntu:20.04:LTS
→ {"results": []}
```

### Go sub-module search requires exact module path

OSV records Go vulnerabilities at the sub-module level (e.g., `go.opentelemetry.io/otel/baggage`), not at the parent module level (`go.opentelemetry.io/otel`). Searching with the parent module returns no results even if a sub-module is affected.

Workaround: search with the exact sub-module path:
```
GET /api/v1/vulnerabilities/search?package=go.opentelemetry.io/otel/baggage&version=1.36.0&ecosystem=Go
```

Dependabot and similar tools resolve the full dependency graph to find affected sub-modules. Prefix-based matching (searching `go.opentelemetry.io/otel` to also match `/baggage`) is not yet implemented.

### Vendor advisory search is skipped for distro ecosystems

When `ecosystem` is a distribution ecosystem (`Ubuntu:*`, `Debian:*`, `Alpine:*`, etc.), vendor advisory results (Fortinet, Cisco, Oracle Linux ELSA, Sophos, etc.) are excluded. Distro-specific package names (e.g., `curl`) overlap with vendor product names, which would cause false positives.

### Sophos advisory source has no version ranges

Sophos advisories are collected via sitemap + RSS + headless browser rendering (63 advisories total). CVE IDs and severity are extracted; however, affected version ranges are not available because the advisory detail pages do not expose structured version data. Advisories are linked to CVEs where present, but version-specific matching (`?version=18.0.1`) will not return Sophos results. Use CVE ID lookup (`/api/v1/vulnerabilities/CVE-YYYY-NNNNN`) to find associated Sophos advisories.

### NVD vs OSV package name discrepancies

NVD uses CPE `product` as the package name, which may differ from the OSV package name (e.g., NVD=`xz`, OSV=`xz-utils`). Searching both sources simultaneously requires name normalization. (not yet implemented)

### In-memory pagination for large result sets

The current search implementation fetches all `NVDAffectedPackage` / `OSVAffectedPackage` rows without a limit, deduplicates in memory, then applies `limit`/`offset`. This is fine for most packages (~900 entries), but packages with thousands of CPE entries (e.g., `openssl`, `linux_kernel`) may see increased response time and memory usage.

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
| Component ≥ 1,000,000 | Normalization fails (null) | Falls back to approximate match |
| Non-semver (date-based, etc.) | Normalization fails (null) | Falls back to approximate match |

**Approximate match fallback**: when normalization fails, all vulnerabilities matching the package name and ecosystem are returned with `approximateMatch: true`.

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.
