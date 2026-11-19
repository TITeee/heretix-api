/**
 * One-time migration: give CVE masters with no published date the date of their NVD
 * record, or failing that their CVE Record's. See fillMissingPublishedAt().
 *
 * Usage:
 *   pnpm migrate:fill-master-published-at
 */
import 'dotenv/config';
import { closeDb } from '../db/client.js';
import { fillMissingPublishedAt } from '../worker/master-published-at.js';

async function main() {
  const { fromNvd, fromCna } = await fillMissingPublishedAt();
  console.log(`Done: published date set on ${fromNvd} master(s) from NVD and ${fromCna} from the CVE Records.`);
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
