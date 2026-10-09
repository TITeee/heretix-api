# Operations

## Setup

### Docker (recommended)

Follow the [quick start in the README](../README.md#quick-start). On every start the container applies schema migrations and pending [backfills](#one-time-backfills) before starting the server.

Run import and backfill scripts inside the `app` container:

```bash
docker compose exec app pnpm import:osv update npm
docker compose exec app pnpm migrate:all
```

### Native

Requires Node.js 22, pnpm and PostgreSQL 15 or later.

1. Get the code and install dependencies:
   ```bash
   git clone https://github.com/TITeee/heretix-api.git
   cd heretix-api
   pnpm install
   ```
2. Prepare PostgreSQL 15 or later (`createdb vulndb`). A managed instance such as RDS, Supabase or Neon works too.
3. Copy `.env.example` to `.env` and fill it in (see [below](#environment-variables)).
4. Apply migrations: `pnpm db:migrate`, then `pnpm build && pnpm migrate:all`.
5. Start the server: `pnpm dev` (auto-reload) or `pnpm build && pnpm start`.
6. Load data as in [the README's step 3](../README.md#3-load-data), using `pnpm import:nvd full`, `pnpm import:osv ecosystem <name>` and so on, in place of the `docker compose exec` commands.

`pnpm import:*` and `pnpm migrate:*` run the compiled `dist/` output. Rebuild after changing code, or run the TypeScript directly with `pnpm exec tsx src/scripts/<script>.ts ...`.

## Environment variables

```env
DATABASE_URL="postgresql://postgres:password@localhost:5432/vulndb?schema=public"
PORT=5000
NODE_ENV=development        # "production" in production
API_KEY=your-api-key-here   # Required. Requests without a matching x-api-key get 401
ALLOWED_ORIGINS=            # Optional, comma-separated browser origins allowed to read responses (default: none)
DATABASE_POOL_MAX=20        # Optional. Postgres connection pool size
NVD_API_KEY=                # Optional. NVD rate limit 10 → 50 requests/min
CISCO_CLIENT_ID=            # Required for the Cisco import (openVuln API)
CISCO_CLIENT_SECRET=
GITHUB_TOKEN=               # Optional. Only needed to run the malware import more than 60 times/hour
```

`ALLOWED_ORIGINS` only affects browsers. Server-to-server callers such as heretix-cli are unaffected.

## Scheduler

Jobs are defined in [src/jobs/registry.ts](../src/jobs/registry.ts) and registered on startup. Times are UTC.

| Job (`source`) | Schedule | Enabled by default |
|---|---|---|
| `nvd` (changes since last run) | Every 2 hours | ✅ |
| `kev` | Daily 09:00 | ✅ |
| `epss` | Daily 10:00 | ✅ |
| `osv-<ecosystem>` (one per imported ecosystem) | Daily 08:00 | |
| `osv-mal` (malicious packages) | Daily 08:30 | |
| `debian-source-packages` | Weekly, Sunday 07:00 | |
| `debian-tracker` | Daily 07:15 | |
| `advisory-fortinet` / `-pan` / `-cisco` / `-oracle-linux` | Daily 11:00 / 11:15 / 11:30 / 11:45 | |
| `advisory-sophos` / `-sonicwall` / `-oracle-cpu` | Daily 12:00 / 12:15 / 12:30 | |
| `advisory-broadcom` / `-redhat-rhel9` / `-redhat-rhel8` / `-splunk` | Daily 13:00 / 13:15 / 13:30 / 13:45 | |
| `advisory-apache` / `-zabbix` / `-tomcat` / `-nginx` | Daily 14:00 / 14:15 / 14:30 / 14:45 | |
| `advisory-redhat-vex` | Daily 15:00 | |
| `cna` (CVE Records and CISA SSVC) | Daily 15:30 | |
| `advisory-checkpoint` / `-ivanti` | Daily 16:00 / 16:30 | `advisory-ivanti` renders about 90 pages in a headless browser and takes 10 to 15 minutes |

Switch jobs on and off with the dashboard's On/Off toggle or `PATCH /api/v1/jobs/:source` (see [api.md](api.md#jobs)). On a fresh install only NVD, KEV and EPSS are enabled. The other jobs are high-volume scrapers, so switch on just the ones you need. Each OSV ecosystem job appears once that ecosystem has been imported.

An existing install may have more jobs enabled; check the dashboard and switch off the ones you do not need.

The setting is stored in `JobConfig` and checked when the job fires, so a change takes effect without a restart. A job can be run manually whether or not it is enabled.

Each job run is recorded in `CollectionJob`: status, counts, error message, and the cursor for the next delta run. A job left `running` by a restart is marked as failed on the next start.

## One-time backfills

When a fix needs to correct rows that were written before it existed, it ships as a `src/scripts/migrate-*.ts` script. Each script is idempotent.

```bash
pnpm migrate:all        # run every pending backfill
pnpm migrate:<name>     # run one, e.g. after investigating a failure
```

`migrate:all` runs every `dist/scripts/migrate-*.js` that is not yet recorded in `DataMigration`. The Docker entrypoint runs it on every start, after `prisma migrate deploy` and before the server starts. The API therefore does not answer until pending backfills finish. Most take seconds, but some scan every OSV record and take several minutes on a full database (e.g. `migrate-backfill-distro-priority` ~8.5 minutes on ~430k records). Allow for this in orchestrator start-up timeouts and health checks.

## Database

```bash
pnpm db:migrate    # apply Prisma migrations
pnpm db:studio     # browse the database at http://localhost:5555
```

## Troubleshooting

**`P1001: Can't reach database server`**: check `DATABASE_URL`, check that PostgreSQL is running, and check firewall / security group rules.

**Migration errors on a development database**: `pnpm prisma migrate reset` drops and recreates it; then re-run `pnpm db:migrate`. Never run this against production.

**A source shows no data**: check that its job is enabled on the dashboard and has completed at least once. OSV ecosystems need one full `pnpm import:osv ecosystem <name>` before their daily job (see [data-sources.md](data-sources.md#osv)).

**An import command seems to ignore a code change**: `pnpm import:*` runs `dist/`. Run `pnpm build` first.
