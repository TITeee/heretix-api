/**
 * One-time migration: one master for each group of aliased OSV records that
 * names no CVE, and no masters left keyed by an OSV id nothing points at.
 *
 * Background:
 *   One vulnerability is often published under several ids with no CVE
 *   (GHSA-6q48-6c7w-9gw2 and PYSEC-2026-4320 for one certifi issue, or a
 *   malicious package as MAL-… and PYSEC-…). importOSVData() gave each its own
 *   master, and a search reports one finding per master, so a package got the
 *   same finding twice. It now shares one master per group, keyed by GHSA, then
 *   the source's own id, then MAL; this merges the groups imported before. See
 *   mergeOsvAliasGroups() and pruneOrphanOsvMasters().
 *
 *   Runs after migrate-osv-own-cve-ids (the scripts run in name order), so the
 *   records named by their CVE already have it.
 *
 * Usage:
 *   pnpm migrate:osv-shared-alias-masters
 */
import 'dotenv/config';
import { closeDb } from '../db/client.js';
import { mergeOsvAliasGroups, pruneOrphanOsvMasters } from '../worker/osv-alias-groups.js';

async function main() {
  const { records } = await mergeOsvAliasGroups();
  console.log(`Merged the masters of ${records} aliased OSV record(s).`);
  const { deleted } = await pruneOrphanOsvMasters();
  console.log(`Deleted ${deleted} master(s) keyed by an OSV id no record points at.`);
}

main()
  .catch((err) => {
    console.error(err);
    process.exit(1);
  })
  .finally(async () => {
    await closeDb();
    process.exit(0);
  });
