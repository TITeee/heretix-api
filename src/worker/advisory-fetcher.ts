import { prisma } from '../db/client.js';
import { normalizeVersion } from '../utils/version.js';
import { logger } from '../utils/logger.js';
import type { Prisma } from '@prisma/client';

// ─── Common Interfaces ────────────────────────────────────────

export interface NormalizedAdvisory {
  externalId: string;              // "FG-IR-24-001", "K000138242", "cisco-sa-xxxx"
  cveId?: string;                  // Associated CVE ID (if any)
  summary?: string;
  description?: string;
  severity?: string;
  cvssScore?: number;
  cvssVector?: string;
  url?: string;                    // Original advisory URL
  workaround?: string;             // Mitigation
  solution?: string;               // Fix details
  publishedAt?: Date;
  affectedProducts: Array<{
    vendor: string;                // "fortinet", "f5", "cisco", etc.
    product: string;               // "FortiOS", "BIG-IP", etc.
    versionStart?: string;         // First affected version (inclusive)
    versionEnd?: string;           // Last affected version (exclusive)
    lastAffected?: string;         // Last affected version (inclusive)
    versionFixed?: string;         // Fixed version (first non-affected)
    affectedVersions?: string[];   // Non-semver: list of individual versions
    patchAvailable?: boolean;
  }>;
  rawData: unknown;
}

export interface AdvisoryFetcher {
  /** Data source identifier ("fortinet", "f5", "cisco", etc.) */
  source(): string;
  /** Fetch advisories and return them in normalized form */
  fetch(): Promise<NormalizedAdvisory[]>;
}

// ─── Import Functions ─────────────────────────────────────────

/**
 * Save advisory data to the AdvisoryVulnerability table
 * Vendor is identified by the source field
 */
export async function importAdvisoryData(adv: NormalizedAdvisory, source: string): Promise<void> {
  logger.info({ externalId: adv.externalId, source }, 'Importing advisory');

  await prisma.$transaction(async (tx) => {
    // ─── Step 1: Link to Vulnerability master table ───────────
    //
    // Priority rules:
    //   cveId present  → prefer NVD data; if record exists, link only;
    //                    otherwise create a placeholder from advisory data (overwritten at NVD import time)
    //   cveId absent   → manage master by advisoryId (advisory is the sole source)

    const masterFields = {
      severity:    adv.severity    ?? null,
      cvssScore:   adv.cvssScore   ?? null,
      cvssVector:  adv.cvssVector  ?? null,
      summary:     adv.summary     ?? null,
      publishedAt: adv.publishedAt ?? null,
    };

    let masterVulnId: string;

    if (adv.cveId) {
      // CVE present: find and link existing record; create placeholder from advisory data if absent
      const existing = await tx.vulnerability.findUnique({
        where: { cveId: adv.cveId },
        select: { id: true },
      });
      if (existing) {
        masterVulnId = existing.id;
      } else {
        const created = await tx.vulnerability.create({
          data: { cveId: adv.cveId, ...masterFields },
          select: { id: true },
        });
        masterVulnId = created.id;
      }
    } else {
      // No CVE: upsert by advisoryId (advisory is the sole source)
      const master = await tx.vulnerability.upsert({
        where:  { advisoryId: adv.externalId },
        create: { advisoryId: adv.externalId, ...masterFields },
        update: masterFields,
        select: { id: true },
      });
      masterVulnId = master.id;
    }

    // ─── Step 2: Upsert AdvisoryVulnerability ────────────────────
    const advisory = await tx.advisoryVulnerability.upsert({
      where: { source_externalId: { source, externalId: adv.externalId } },
      create: {
        source,
        externalId: adv.externalId,
        cveId: adv.cveId ?? null,
        rawData: adv.rawData as Prisma.InputJsonValue,
        severity: adv.severity ?? null,
        cvssScore: adv.cvssScore ?? null,
        cvssVector: adv.cvssVector ?? null,
        summary: adv.summary ?? null,
        description: adv.description ?? null,
        url: adv.url ?? null,
        workaround: adv.workaround ?? null,
        solution: adv.solution ?? null,
        publishedAt: adv.publishedAt ?? null,
        masterVulnId,
      },
      update: {
        cveId: adv.cveId ?? null,
        rawData: adv.rawData as Prisma.InputJsonValue,
        severity: adv.severity ?? null,
        cvssScore: adv.cvssScore ?? null,
        cvssVector: adv.cvssVector ?? null,
        summary: adv.summary ?? null,
        description: adv.description ?? null,
        url: adv.url ?? null,
        workaround: adv.workaround ?? null,
        solution: adv.solution ?? null,
        masterVulnId,
      },
    });

    // Delete existing affected products
    await tx.advisoryAffectedProduct.deleteMany({ where: { advisoryId: advisory.id } });

    for (const prod of adv.affectedProducts) {
      const versionStartInt = prod.versionStart
        ? (normalizeVersion(prod.versionStart) ?? null)
        : null;
      const versionEndInt = prod.versionEnd
        ? (normalizeVersion(prod.versionEnd) ?? null)
        : null;
      const lastAffectedInt = prod.lastAffected
        ? (normalizeVersion(prod.lastAffected) ?? null)
        : null;

      await tx.advisoryAffectedProduct.create({
        data: {
          advisoryId: advisory.id,
          vendor: prod.vendor.trim(),
          product: prod.product.trim(),
          versionStart: prod.versionStart ?? null,
          versionEnd: prod.versionEnd ?? null,
          versionFixed: prod.versionFixed ?? null,
          versionStartInt,
          versionEndInt,
          lastAffectedInt,
          affectedVersions: prod.affectedVersions ?? [],
          patchAvailable: prod.patchAvailable ?? null,
        },
      });
    }
  });

  logger.debug({ externalId: adv.externalId, source }, 'Advisory imported');
}

/**
 * Run fetch and import in one step using an AdvisoryFetcher
 */
export async function runAdvisoryFetcher(fetcher: AdvisoryFetcher): Promise<{
  total: number;
  succeeded: number;
  failed: number;
}> {
  const source = fetcher.source();
  logger.info({ source }, 'Running advisory fetcher');

  const advisories = await fetcher.fetch();
  let succeeded = 0;
  let failed = 0;

  for (const adv of advisories) {
    try {
      await importAdvisoryData(adv, source);
      succeeded++;
    } catch (err) {
      failed++;
      logger.error({ err, externalId: adv.externalId, source }, 'Failed to import advisory');
    }
  }

  logger.info({ source, total: advisories.length, succeeded, failed }, 'Advisory fetcher completed');
  return { total: advisories.length, succeeded, failed };
}
