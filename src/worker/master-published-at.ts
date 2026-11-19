import { prisma } from '../db/client.js';

/**
 * Give each CVE master with no published date the date of its NVD record, or failing
 * that its CVE Record's. Such masters were made by an importer that had no date (the
 * CVE Records' SSVC or texts, stored before the record itself), and neither NVD's
 * import nor the CVE Record's filled the date into a master that already existed. A
 * search shown newest first put them last. Only empty dates are written: idempotent.
 */
export async function fillMissingPublishedAt(): Promise<{ fromNvd: number; fromCna: number }> {
  const fromNvd = await prisma.$executeRaw`
    UPDATE "Vulnerability" v
       SET "publishedAt" = n."publishedAt"
      FROM "NVDVulnerability" n
     WHERE n."masterVulnId" = v.id
       AND v."publishedAt" IS NULL
       AND n."publishedAt" IS NOT NULL`;
  const fromCna = await prisma.$executeRaw`
    UPDATE "Vulnerability" v
       SET "publishedAt" = c."datePublished"
      FROM "CnaVulnerability" c
     WHERE c."masterVulnId" = v.id
       AND v."publishedAt" IS NULL
       AND c."datePublished" IS NOT NULL`;
  return { fromNvd, fromCna };
}
