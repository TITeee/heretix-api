/**
 * Palo Alto Networks PSIRT advisory import
 *
 * Usage:
 *   pnpm import:pan          # Fetch all advisories (scrape all web pages)
 *   pnpm import:pan latest   # Fetch latest 25 only (RSS)
 */
import 'dotenv/config';
import { PanFetcher } from '../worker/pan-fetcher.js';
import { runAdvisoryFetcher } from '../worker/advisory-fetcher.js';

const [, , mode] = process.argv;

async function main() {
  const isLatest = mode === 'latest';
  console.log(`Fetching Palo Alto Networks PSIRT advisories (${isLatest ? 'latest RSS' : 'all pages'})...`);
  const fetcher = new PanFetcher({ mode: isLatest ? 'latest' : 'all' });
  const result  = await runAdvisoryFetcher(fetcher);
  console.log(`Done: ${result.succeeded} imported, ${result.failed} failed (total: ${result.total})`);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
