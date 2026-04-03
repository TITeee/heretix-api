import 'dotenv/config';
import { OracleLinuxFetcher } from '../worker/oracle-linux-fetcher.js';
import { runAdvisoryFetcher } from '../worker/advisory-fetcher.js';

async function main() {
  // Optional variant argument: ol9, ol8, ol7, ...
  // e.g.  node dist/scripts/import-oracle-linux.js ol9
  const variant = process.argv[2];

  if (variant) {
    console.log(`Fetching Oracle Linux OVAL advisories for variant: ${variant}`);
  } else {
    console.log('Fetching Oracle Linux OVAL advisories (full feed)...');
  }

  const fetcher = new OracleLinuxFetcher(variant);
  const result  = await runAdvisoryFetcher(fetcher);
  console.log(`Done: ${result.succeeded} imported, ${result.failed} failed (total: ${result.total})`);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
