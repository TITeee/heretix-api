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
  /**
   * Whether this configured instance's fetch() returns the *complete* current
   * set of advisories for this source (a full re-scrape/full-archive fetch),
   * as opposed to a partial recent window (e.g. an RSS "latest" mode). Only
   * complete snapshots are safe input for stale-advisory pruning in
   * runAdvisoryFetcher() — pruning against a partial window would delete
   * perfectly valid advisories that just fall outside it.
   */
  isCompleteSnapshot(): boolean;
}

// ─── Import Functions ─────────────────────────────────────────

/**
 * Save advisory data to the AdvisoryVulnerability table
 * Vendor is identified by the source field
 */
export async function importAdvisoryData(adv: NormalizedAdvisory, source: string): Promise<'inserted' | 'updated'> {
  logger.info({ externalId: adv.externalId, source }, 'Importing advisory');

  return prisma.$transaction(async (tx) => {
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
    const existing = await tx.advisoryVulnerability.findUnique({
      where: { source_externalId: { source, externalId: adv.externalId } },
      select: { id: true },
    });

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
        missingRunCount: 0,
      },
    });

    // Delete existing affected products
    await tx.advisoryAffectedProduct.deleteMany({ where: { advisoryId: advisory.id } });

    for (const prod of adv.affectedProducts) {
      const versionStartInt = prod.versionStart
        ? (normalizeVersion(prod.versionStart) ?? null)
        : null;
      // versionFixed has the same exclusive-upper-bound semantics as versionEnd:
      // "fixed in X.Y.Z" means versions < X.Y.Z are affected → use as fallback for range queries.
      const effectiveVersionEnd = prod.versionEnd ?? prod.versionFixed;
      const versionEndInt = effectiveVersionEnd
        ? (normalizeVersion(effectiveVersionEnd) ?? null)
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
          lastAffected: prod.lastAffected ?? null,
          versionStartInt,
          versionEndInt,
          lastAffectedInt,
          affectedVersions: prod.affectedVersions ?? [],
          patchAvailable: prod.patchAvailable ?? null,
        },
      });
    }

    return existing ? 'updated' : 'inserted';
  });
}

// Number of consecutive full-snapshot runs an advisory may be absent from
// the source before it's treated as genuinely retracted rather than a
// transient scrape hiccup.
const PRUNE_THRESHOLD = 3;

/**
 * For full-snapshot fetchers, find advisories present in the DB for this
 * source but absent from the latest fetch (retracted/corrected upstream, or
 * missed by a transient scrape issue). Missing entries get PRUNE_THRESHOLD
 * consecutive chances to reappear before being hard-deleted.
 * AdvisoryAffectedProduct rows cascade automatically; the linked master
 * Vulnerability row is also removed if it was solely managed by this
 * advisory (advisoryId-keyed, no cveId/osvId — see importAdvisoryData) and
 * no other AdvisoryVulnerability still references it.
 */
async function pruneStaleAdvisories(source: string, seenExternalIds: Set<string>): Promise<{ deleted: number; warned: number }> {
  // Diff in application code rather than a SQL `externalId NOT IN (...)` —
  // large full-snapshot sources (Red Hat, Oracle Linux) can have tens of
  // thousands of seen externalIds in one run, and binding that many
  // parameters into a single query exceeds the driver's parameter limit
  // (Prisma P2029). A plain per-source SELECT has exactly one parameter
  // regardless of table size.
  const existing = await prisma.advisoryVulnerability.findMany({
    where: { source },
    select: {
      id: true,
      externalId: true,
      missingRunCount: true,
      masterVulnId: true,
      masterVuln: { select: { id: true, cveId: true, osvId: true } },
    },
  });
  const missing = existing.filter(row => !seenExternalIds.has(row.externalId));

  let deleted = 0;
  let warned = 0;

  for (const row of missing) {
    if (row.missingRunCount + 1 < PRUNE_THRESHOLD) {
      await prisma.advisoryVulnerability.update({
        where: { id: row.id },
        data: { missingRunCount: { increment: 1 } },
      });
      warned++;
      continue;
    }

    await prisma.$transaction(async (tx) => {
      await tx.advisoryVulnerability.delete({ where: { id: row.id } });

      // Clean up the master row only if this advisory was its sole owner
      // (no cveId/osvId means it was created purely via advisoryId upsert).
      if (row.masterVuln && !row.masterVuln.cveId && !row.masterVuln.osvId) {
        const stillReferenced = await tx.advisoryVulnerability.count({
          where: { masterVulnId: row.masterVuln.id },
        });
        if (stillReferenced === 0) {
          await tx.vulnerability.delete({ where: { id: row.masterVuln.id } });
        }
      }
    });
    logger.warn({ source, externalId: row.externalId }, 'Pruned stale advisory (missing from source for consecutive runs)');
    deleted++;
  }

  return { deleted, warned };
}

/**
 * Run fetch and import in one step using an AdvisoryFetcher
 */
export async function runAdvisoryFetcher(fetcher: AdvisoryFetcher): Promise<{
  total: number;
  succeeded: number;
  inserted: number;
  updated: number;
  failed: number;
  pruned: number;
}> {
  const source = fetcher.source();
  logger.info({ source }, 'Running advisory fetcher');

  const advisories = await fetcher.fetch();
  let inserted = 0;
  let updated = 0;
  let failed = 0;

  for (const adv of advisories) {
    try {
      const result = await importAdvisoryData(adv, source);
      if (result === 'inserted') inserted++; else updated++;
    } catch (err) {
      failed++;
      logger.error({ err, externalId: adv.externalId, source }, 'Failed to import advisory');
    }
  }

  const succeeded = inserted + updated;

  let pruned = 0;
  if (advisories.length === 0) {
    // A genuine zero-result fetch is indistinguishable here from a scrape/parse
    // bug returning an empty array without throwing — never treat that as
    // "everything was retracted". Skip pruning entirely in that case.
    logger.warn({ source }, 'Fetch returned zero advisories — skipping stale-advisory pruning');
  } else if (fetcher.isCompleteSnapshot()) {
    const seenIds = new Set(advisories.map(a => a.externalId));
    ({ deleted: pruned } = await pruneStaleAdvisories(source, seenIds));
  }

  logger.info({ source, total: advisories.length, succeeded, failed, pruned }, 'Advisory fetcher completed');
  return { total: advisories.length, succeeded, inserted, updated, failed, pruned };
}
