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
RATE_LIMIT_MAX=1200         # Optional. Requests per client address per minute, over 429 (0 = off). /health is never limited
RATE_LIMIT_BATCH_MAX=30     # Optional. Batch searches per client address per minute (0 = only the limit above)
BATCH_SEARCH_MAX_CONCURRENT=2  # Optional. Batch searches running at once; more get 429 (0 = no cap)
BATCH_SEARCH_TIMEOUT_MS=300000  # Optional. A batch search still running after this is answered 503 and its slot freed (0 = no limit)
JOB_MAX_CONCURRENT=2        # Optional. Collection jobs running at once; the rest wait as "queued"
JOB_MAX_HEAVY=1             # Optional. Of those, memory-heavy jobs (EPSS, CNA, Red Hat OVAL and VEX) running at once
JOB_MAX_OLD_SPACE_MB=3072   # Optional. Heap limit of each job process
JOB_DATABASE_POOL_MAX=5     # Optional. Postgres connection pool of each job process
NVD_API_KEY=                # Optional. NVD rate limit 10 → 50 requests/min
CISCO_CLIENT_ID=            # Required for the Cisco import (openVuln API)
CISCO_CLIENT_SECRET=
```

`ALLOWED_ORIGINS` only affects browsers. Server-to-server callers such as heretix-cli are unaffected.

The limits are a backstop, not a way to tell callers apart: heretix-management reaches the API from one address with one shared key. A batch search keeps the server's one JS thread busy for seconds (about 12 s for 1,000 packages with many findings each), and a single search issued meanwhile waited 1.4 s instead of 2 ms, so the number of batches running at once is capped rather than queued. A batch whose caller has gone away is dropped at the next chunk of 20 packages.

## Scheduler

Jobs are defined in [src/jobs/registry.ts](../src/jobs/registry.ts) and registered on startup. Times are UTC.

| Job (`source`) | Schedule | Enabled by default | First load |
|---|---|---|---|
| `nvd` (changes since last run) | Every 2 hours | ✅ | `pnpm import:nvd full`. Run alone reads only the last 2 hours |
| `kev` | Daily 09:00 | ✅ | Run is enough |
| `epss` | Daily 10:00 | ✅ | Run is enough |
| `osv-<ecosystem>` (one per imported ecosystem) | Daily 08:00 | | `pnpm import:osv ecosystem <name>`. The job does not exist until then; Run reads the changes since the last run, or the last 30 days |
| `debian-source-packages` | Weekly, Sunday 07:00 | | Run is enough |
| `debian-tracker` | Daily 07:15 | | Run is enough |
| `ubuntu-tracker` | Daily 07:45 | | Run is enough. Needs `git` (in the Docker image) and a few minutes: it clones a 220 MB repository |
| `advisory-fortinet` / `-pan` / `-cisco` / `-oracle-linux` | Daily 11:00 / 11:15 / 11:30 / 11:45 | | Run is enough. `advisory-cisco` needs `CISCO_CLIENT_ID` and `CISCO_CLIENT_SECRET` |
| `advisory-sophos` / `-sonicwall` / `-oracle-cpu` | Daily 12:00 / 12:15 / 12:30 | | Run is enough |
| `advisory-broadcom` / `-redhat-rhel9` / `-redhat-rhel8` / `-splunk` | Daily 13:00 / 13:15 / 13:30 / 13:45 | | Run is enough |
| `advisory-apache` / `-zabbix` / `-tomcat` / `-nginx` | Daily 14:00 / 14:15 / 14:30 / 14:45 | | Run is enough |
| `advisory-redhat-vex` | Daily 15:00 | | Run is enough |
| `cna` (CVE Records and CISA SSVC) | Daily 15:30 | | `pnpm import:cna`. The first run downloads a bundle of about 600MB; Run alone reads only the last 25 hours |
| `advisory-checkpoint` / `-ivanti` / `-citrix` | Daily 16:00 / 16:30 / 16:45 | | Run is enough. `advisory-ivanti` renders about 90 pages in a headless browser and takes 10 to 15 minutes; `advisory-citrix` reads about 20 pages over plain HTTP in under a minute |
| `advisory-microsoft` | Daily 18:30 | | `pnpm import:msrc` once: it reads all the MSRC documents since March 2021 (about 68) in about 3 minutes. Run alone reads only the documents revised in the last 7 days and the latest month |

**First load.** A dashboard Run does what the scheduled job does. Most sources are fetched in full every time, so for them a Run is the first load. The sources marked with a command fetch only what changed since the last run, so a Run on an empty database loads next to nothing: run the command first (`docker compose exec app pnpm import:...`, after `pnpm build` when running from source), then switch the job on. Switching a job on is separate from running it: a new job is Off until switched on, and Run works either way.

Switch jobs on and off with the dashboard's On/Off toggle or `PATCH /api/v1/jobs/:source` (see [api.md](api.md#jobs)). On a fresh install only NVD, KEV and EPSS are enabled. The other jobs are high-volume scrapers, so switch on just the ones you need. Each OSV ecosystem job appears once that ecosystem has been imported.

An existing install may have more jobs enabled; check the dashboard and switch off the ones you do not need.

The setting is stored in `JobConfig` and checked when the job fires, so a change takes effect without a restart. A job can be run manually whether or not it is enabled.

Each job run is recorded in `CollectionJob`: status, counts, error message, peak memory (`metadata.peakMemoryMb`), and the cursor for the next delta run.

### Job processes

Every job runs in a process of its own, started by the API process ([src/jobs/runner.ts](../src/jobs/runner.ts)). A job that blocks for seconds, fails in an unexpected way or runs out of memory therefore stops only its own process: searches keep answering, and the job's row says what happened (`Job process crashed, most likely out of memory (heap limit 3072 MB ...)`). Before, jobs ran inside the API process, and a search could wait up to 14 seconds during the EPSS import.

At most `JOB_MAX_CONCURRENT` jobs run at once (2), and of those at most `JOB_MAX_HEAVY` (1) of the jobs that hold a large dataset in memory (EPSS, CNA, and the Red Hat OVAL and VEX imports). A job waiting for a slot shows as **queued** on the dashboard; a Run while it is queued or running is refused. With the defaults, jobs use at most about one 3GB heap plus a light job beside it; raise the limits only with the memory to match, since two heavy jobs together approach 6GB.

Each job process opens its own connections to PostgreSQL (`JOB_DATABASE_POOL_MAX`, 5), so the most in use is the API's `DATABASE_POOL_MAX` plus `JOB_MAX_CONCURRENT` times that.

On shutdown, waiting jobs are dropped and running ones stopped, each recorded on its row (`Not started: the API was shutting down`, `Interrupted: ...`). A row left `queued` or `running` by a process that was killed outright is marked as failed on the next start. An interrupted job did not record its delta cursor, so its next run picks up the same changes again.

## One-time backfills

When a fix needs to correct rows that were written before it existed, it ships as a `src/scripts/migrate-*.ts` script. Each script is idempotent.

```bash
pnpm migrate:all        # run every pending backfill the server waits for
pnpm migrate:all --background  # run the pending migrate-background-* ones
pnpm migrate:<name>     # run one, e.g. after investigating a failure
```

`migrate:all` runs every `dist/scripts/migrate-*.js` (except `migrate-background-*`) that is not yet recorded in `DataMigration`. The Docker entrypoint runs it on every start, after `prisma migrate deploy` and before the server starts. The API therefore does not answer until pending backfills finish. Most take seconds, but some scan every OSV record and take several minutes on a full database (e.g. `migrate-backfill-distro-priority` ~8.5 minutes on ~430k records). Allow for this in orchestrator start-up timeouts and health checks.

A backfill that takes longer than that is named `migrate-background-*`. The entrypoint starts the server first and runs those beside it (`migrate-all --background`), so the API is up while they run. Until one finishes, rows it has not reached still carry the old values and the matching searches give the old answers; a failure is logged and the script runs again on the next start. Add such a script by naming it `migrate-background-<name>.ts`.

## Database

```bash
pnpm db:migrate    # apply Prisma migrations
pnpm db:studio     # browse the database at http://localhost:5555
```

### Memory

PostgreSQL keeps recently read data in `shared_buffers`, 128MB unless configured. That is small next to what one search can read: a batch search for an RHEL 9 host with two kernels installed (523 packages) reads about 1.1GB, mostly the kernel's 10,000 Red Hat rows per package. What `shared_buffers` cannot hold is read again through the operating system's file cache, which is fast while the files are still cached (8 s for that batch) and slow once other programs have pushed them out: the same batch then took 171 s, most of it waiting for the disk.

The Compose file sets `shared_buffers` to 1GB. Change it with `POSTGRES_SHARED_BUFFERS` in `.env` (for example `2GB`), up to about a quarter of the server's memory, and restart the database (`docker compose up -d db`). For a PostgreSQL you run yourself, set it in `postgresql.conf` or with `ALTER SYSTEM SET shared_buffers = '1GB';`, then restart PostgreSQL; `SHOW shared_buffers;` shows the value in use.

### Indexes Prisma does not manage

The name suggestions (`/vulnerabilities/suggest`) match a prefix on `lower(name)`. Unless the database uses the `C` collation, a plain index cannot serve `LIKE 'x%'`, so migration `20261010150000_add_lowercase_prefix_indexes` adds `lower(...) text_pattern_ops` indexes on `NVDAffectedPackage` (`packageName`, `vendor`), `OSVAffectedPackage` (`packageName`) and `CnaAffectedProduct` (`product`). Prisma's schema cannot express an expression index and ignores one when it compares the database with `schema.prisma`, so they do not appear there and `prisma migrate dev` leaves them alone. They take a few seconds per million rows to build and hold a write lock on their table meanwhile, so the first start after the upgrade builds them before any import runs. A second migration, `20261010150100_analyze_prefix_search_tables`, analyzes the three tables: until a table is analyzed the planner ignores the new indexes. Without the indexes the suggestions still work, only slowly (two to five seconds on a database with millions of rows).

## Troubleshooting

**`P1001: Can't reach database server`**: check `DATABASE_URL`, check that PostgreSQL is running, and check firewall / security group rules.

**The first search after a quiet period is slow, or a client times out on a large batch** (heretix-management: `heretix-api batch search did not answer within ...`): the database is reading from disk. Raise `shared_buffers` (see [Memory](#memory)); a second run of the same search is fast because the data is then cached.

**Migration errors on a development database**: `pnpm prisma migrate reset` drops and recreates it; then re-run `pnpm db:migrate`. Never run this against production.

**A source shows no data**: check that its job is enabled on the dashboard and has completed at least once. OSV ecosystems need one full `pnpm import:osv ecosystem <name>` before their daily job (see [data-sources.md](data-sources.md#osv)).

**An import command seems to ignore a code change**: `pnpm import:*` runs `dist/`. Run `pnpm build` first.
