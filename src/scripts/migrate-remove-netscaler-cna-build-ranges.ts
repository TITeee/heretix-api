/**
 * One-time migration: delete the NetScaler range rows that CnaAffectedProduct
 * kept before extractCnaRows() learned to leave them out (cna-fetcher.ts,
 * isNetScalerBuildRange()).
 *
 * The CNA writes a NetScaler range as the release branch plus the build --
 * { version: "14.1", lessThan: "56.73", versionType: "patch" } -- which reads as
 * 14.1.0 up to 56.73.0. A search for NetScaler 14.1-56.73, the build that fixes
 * CVE-2025-12101, or the later 14.1-60.52 came back as affected. The other
 * spelling ("14.1-73.37") keeps only the 73 of its build.
 *
 * Only rows with an upper bound are removed, which is what the extractor now
 * drops; a NetScaler version stored for equality matching alone is kept. The
 * CnaVulnerability rows stay (their rawAffected keeps the declaration).
 *
 * Usage:
 *   pnpm migrate:remove-netscaler-cna-build-ranges
 */
import 'dotenv/config';
import { closeDb, prisma } from '../db/client.js';

async function main() {
  const removed = await prisma.$executeRaw`
    DELETE FROM "CnaAffectedProduct"
    WHERE vendor ~* 'netscaler'
      AND lower("versionType") = 'patch'
      AND ("versionEnd" IS NOT NULL OR "lastAffected" IS NOT NULL)
  `;
  console.log(`Done: ${removed} NetScaler build-range row(s) removed from CnaAffectedProduct.`);
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
