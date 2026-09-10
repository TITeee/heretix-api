/**
 * Runs every migrate-*.ts script in this directory that hasn't already been
 * applied, recording each success in the DataMigration table so it is never
 * re-run.
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
 * The DataMigration ledger exists because this list only grows (a completed
 * backfill's script stays here indefinitely rather than being deleted, in case
 * a fresh/restored DB needs to run it again) -- running every script's own
 * idempotent DB query on every single boot forever, even long after it has
 * converged to zero candidate rows, adds startup latency (each one is a
 * separate child process) that scales with the count of scripts ever written,
 * not with how much work is actually pending. A script that fails is not
 * recorded, so the next boot retries it (safe: each script's own
 * candidate-row query is idempotent, per its own file).
 *
 * Usage:
 *   pnpm migrate:all
 */
import 'dotenv/config';
import { execFileSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { prisma } from '../db/client.js';

const SELF = 'migrate-all.js';

async function main() {
  const here = dirname(fileURLToPath(import.meta.url));
  const scripts = readdirSync(here)
    .filter((f) => f.startsWith('migrate-') && f.endsWith('.js') && f !== SELF)
    .sort();

  const applied = new Set((await prisma.dataMigration.findMany({ select: { name: true } })).map(r => r.name));
  const pending = scripts.filter(f => !applied.has(f.replace(/\.js$/, '')));

  console.log(`Found ${scripts.length} migration script(s), ${pending.length} not yet applied: ${pending.join(', ') || '(none)'}`);

  for (const script of pending) {
    console.log(`\n--- ${script} ---`);
    execFileSync(process.execPath, [join(here, script)], { stdio: 'inherit', env: process.env });
    await prisma.dataMigration.create({ data: { name: script.replace(/\.js$/, '') } });
  }

  console.log(`\n${pending.length} migration script(s) applied, ${scripts.length - pending.length} already up to date.`);
}

main()
  .catch((err) => {
    console.error(err);
    process.exitCode = 1;
  })
  .finally(() => prisma.$disconnect());
