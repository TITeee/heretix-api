import { prisma } from '../db/client.js';

/**
 * Truncate all app tables and reset identity sequences. Call in beforeEach()
 * for every integration test — tests run against a disposable database
 * (TEST_DATABASE_URL), never the dev database.
 */
export async function resetDb(): Promise<void> {
  await prisma.$executeRawUnsafe(`
    TRUNCATE TABLE "Vulnerability", "OSVVulnerability", "OSVAffectedPackage",
      "NVDVulnerability", "NVDAffectedPackage", "AdvisoryVulnerability",
      "AdvisoryAffectedProduct", "CollectionJob", "JobConfig"
    RESTART IDENTITY CASCADE
  `);
}
