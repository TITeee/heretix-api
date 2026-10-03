# Contributing

## Development setup

Follow the [native setup](docs/operations.md#native), then:

```bash
pnpm dev        # API with auto-reload
pnpm lint
pnpm build      # needed before running pnpm import:* / migrate:* against your changes
```

## Tests

```bash
pnpm test               # unit tests, no database needed
pnpm test:integration   # integration tests, needs TEST_DATABASE_URL
```

Integration tests need a separate, disposable database. They reset tables, so never point them at your dev database:

```bash
createdb heretix_test
# add to .env: TEST_DATABASE_URL="postgresql://user:password@localhost:5432/heretix_test"
TEST_DATABASE_URL="postgresql://...heretix_test" pnpm exec prisma migrate deploy
```

CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs both on every push and pull request.

Accuracy against official advisories is measured with the `pnpm validate:*` scripts described in [ACCURACY.md](ACCURACY.md). Run the relevant one when changing a fetcher or a version comparator.

## Changing the schema or stored data

- Schema changes go through Prisma migrations (`prisma/migrations/`).
- To correct rows that are already stored, add an idempotent `src/scripts/migrate-<name>.ts` and a `migrate:<name>` script in `package.json`. `migrate:all` picks it up automatically on the next deploy (see [operations.md](docs/operations.md#one-time-backfills)). If it scans a large table, give a measured run time in the PR.

## Adding a vendor advisory source

1. Implement `AdvisoryFetcher` in `src/worker/<vendor>-fetcher.ts`:

   ```typescript
   import type { AdvisoryFetcher, NormalizedAdvisory } from './advisory-fetcher.js';

   export class MyVendorFetcher implements AdvisoryFetcher {
     source() { return 'myvendor'; }         // stored as AdvisoryVulnerability.source
     isCompleteSnapshot() { return true; }   // true if fetch() returns every current advisory

     async fetch(): Promise<NormalizedAdvisory[]> {
       // Download and normalize. One NormalizedAdvisory per advisory (or per CVE),
       // with affectedProducts carrying the version range.
     }
   }
   ```

   Master-row linkage, pruning and zero-result detection are handled by `runAdvisoryFetcher()` (see [architecture.md](docs/architecture.md#vendor-advisories)).
2. Add a job to `STATIC_JOBS` in [src/jobs/registry.ts](src/jobs/registry.ts). The job's source key is `advisory-<vendor>` (e.g. `advisory-myvendor`), which is what the dashboard and the jobs API use. New jobs are disabled by default.
3. Map the job's source key to the fetcher's `source()` value in `ADVISORY_SOURCE_MAP` ([src/api/routes/dashboard.ts](src/api/routes/dashboard.ts)), e.g. `'advisory-myvendor': 'myvendor'`, so the dashboard shows the record count.
4. Add an `import:<vendor>` script (`src/scripts/import-<vendor>.ts` and `package.json`).
5. Add unit tests built from real advisory samples. Add an accuracy check if the vendor publishes a usable ground truth.
6. Document it in [docs/data-sources.md](docs/data-sources.md), and in [docs/known-issues.md](docs/known-issues.md) if it has limitations.

## Documentation

- [README.md](README.md) is the entry point. Keep it short and keep [README.ja.md](README.ja.md) in sync with it.
- Detailed documentation lives in [docs/](docs/) and [ACCURACY.md](ACCURACY.md), in English only.
- Document current behavior. How a problem was found and investigated belongs in the pull request and commit history, not in the docs.
