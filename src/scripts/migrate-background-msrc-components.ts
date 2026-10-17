/**
 * One-time migration: fill AdvisoryVulnerability.component for the Windows
 * Server advisories imported before it existed.
 *
 * The component is MSRC's per-CVE tag ("Role: DNS Server"), which search
 * results turn into requiresFeatures. It is read from the CVRF documents, which
 * the stored rawData does not keep, so the documents are read again: this runs
 * the full MSRC import (every document since March 2021, a few minutes). The
 * daily job only re-reads recent documents, so without this the older CVEs
 * would keep no component and be reported as applying to every server.
 *
 * Skipped when nothing from MSRC has been imported: a first `pnpm import:msrc`
 * writes the component itself.
 *
 * Usage:
 *   pnpm migrate:background-msrc-components
 */
import 'dotenv/config';
import { closeDb, prisma } from '../db/client.js';
import { MsrcFetcher } from '../worker/msrc-fetcher.js';
import { runAdvisoryFetcher } from '../worker/advisory-fetcher.js';

async function main() {
  const imported = await prisma.advisoryVulnerability.count({ where: { source: 'advisory-microsoft' } });
  if (imported === 0) {
    console.log('No MSRC advisories imported; nothing to fill.');
    return;
  }
  const result = await runAdvisoryFetcher(new MsrcFetcher({ full: true }));
  const filled = await prisma.advisoryVulnerability.count({ where: { source: 'advisory-microsoft', component: { not: null } } });
  console.log(`MSRC: ${result.succeeded} advisories re-imported, ${result.failed} failed, ${result.fetchFailed} documents failed to fetch; ${filled} now carry a component`);
  if (result.fetchFailed > 0) throw new Error(`${result.fetchFailed} MSRC documents could not be fetched; run again`);
}

main()
  .catch(err => {
    console.error(err);
    process.exit(1);
  })
  .finally(async () => {
    await closeDb();
    process.exit(0);
  });
