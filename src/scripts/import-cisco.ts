/**
 * Cisco PSIRT advisory import
 *
 * Usage:
 *   pnpm import:cisco          # Fetch all advisories
 *   pnpm import:cisco latest   # Fetch latest 100 only
 *
 * Required environment variables:
 *   CISCO_CLIENT_ID
 *   CISCO_CLIENT_SECRET
 */
import 'dotenv/config';
import { CiscoFetcher } from '../worker/cisco-fetcher.js';
import { runAdvisoryFetcher } from '../worker/advisory-fetcher.js';

const [, , mode] = process.argv;

async function main() {
  const isLatest = mode === 'latest';
  console.log(`Fetching Cisco PSIRT advisories (${isLatest ? 'latest 100' : 'all'})...`);

  const fetcher = new CiscoFetcher({ mode: isLatest ? 'latest' : 'all' });
  const result  = await runAdvisoryFetcher(fetcher);
  console.log(`Done: ${result.succeeded} imported, ${result.failed} failed (total: ${result.total})`);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
