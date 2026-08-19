/**
 * Runs every one-time migrate-*.ts script in this directory, in one pass.
 *
 * Each script here is a self-contained backfill: idempotent (it finds rows still
 * needing the fix and does nothing once none remain) and independent of the others
 * (they touch disjoint tables/columns, so run order between them doesn't matter).
 *
 * This scans the compiled directory for migrate-*.js files rather than importing a
 * hardcoded list, so a new script just has to exist here — nothing has to be told
 * its name. That property is the actual point: migrate:job-config-defaults went
 * unrun in production after PR #14 shipped because running a newly-added migrate:*
 * script was a step someone had to remember, discoverable only by reading the PR
 * body or scanning package.json's script list by hand. Invoked from entrypoint.sh
 * on every container start, right after `prisma migrate deploy`, so from here on
 * that step doesn't need remembering.
 *
 * Usage:
 *   pnpm migrate:all
 */
import { execFileSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const SELF = 'migrate-all.js';

async function main() {
  const here = dirname(fileURLToPath(import.meta.url));
  const scripts = readdirSync(here)
    .filter((f) => f.startsWith('migrate-') && f.endsWith('.js') && f !== SELF)
    .sort();

  console.log(`Found ${scripts.length} migration script(s) to run: ${scripts.join(', ')}`);

  for (const script of scripts) {
    console.log(`\n--- ${script} ---`);
    execFileSync(process.execPath, [join(here, script)], { stdio: 'inherit', env: process.env });
  }

  console.log(`\nAll ${scripts.length} migration script(s) completed.`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
