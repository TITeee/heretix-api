import 'dotenv/config';
import { FortinetFetcher } from '../worker/fortinet-fetcher.js';
import { runAdvisoryFetcher } from '../worker/advisory-fetcher.js';

async function main() {
  console.log('Fetching Fortinet PSIRT advisories...');
  const fetcher = new FortinetFetcher();
  const result  = await runAdvisoryFetcher(fetcher);
  console.log(`Done: ${result.succeeded} imported, ${result.failed} failed (total: ${result.total})`);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
