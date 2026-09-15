import { logger } from '../utils/logger.js';
import { prisma } from '../db/client.js';
import { normalizeVersion } from '../utils/version.js';
import {
  type CveRecord,
  type DropReason,
  type ParsedCveRecord,
  type SsvcAssessment,
  cveIdOf,
  downloadZip,
  findDeltaBundles,
  findFullBundle,
  listReleases,
  parseCveRecord,
  parseSsvc,
  recordsFromZip,
} from './cna-fetcher.js';
import type { Prisma } from '@prisma/client';

/**
 * Store one parsed CVE Record's CNA-declared affected products.
 *
 * Master linking follows importAdvisoryData()'s conservative rule: link to the
 * CVE-keyed master when it exists, create a bare placeholder when it does not,
 * and never overwrite an existing master's severity/CVSS/summary -- NVD stays
 * the authoritative source for those.
 */
export async function importCnaRecord(parsed: ParsedCveRecord): Promise<'inserted' | 'updated'> {
  return prisma.$transaction(async (tx) => {
    const existingMaster = await tx.vulnerability.findUnique({
      where: { cveId: parsed.cveId },
      select: { id: true },
    });
    const masterVulnId = existingMaster
      ? existingMaster.id
      : (await tx.vulnerability.create({
          data: { cveId: parsed.cveId, publishedAt: parsed.datePublished },
          select: { id: true },
        })).id;

    const existing = await tx.cnaVulnerability.findUnique({
      where: { cveId: parsed.cveId },
      select: { id: true },
    });

    const fields = {
      cnaShortName: parsed.cnaShortName,
      datePublished: parsed.datePublished,
      dateUpdated: parsed.dateUpdated,
      rawAffected: (parsed.affected ?? []) as Prisma.InputJsonValue,
      masterVulnId,
    };

    const record = await tx.cnaVulnerability.upsert({
      where: { cveId: parsed.cveId },
      create: { cveId: parsed.cveId, ...fields },
      update: fields,
      select: { id: true },
    });

    await tx.cnaAffectedProduct.deleteMany({ where: { vulnerabilityId: record.id } });

    for (const row of parsed.rows) {
      await tx.cnaAffectedProduct.create({
        data: {
          vulnerabilityId: record.id,
          vendor: row.vendor,
          product: row.product,
          packageName: row.packageName ?? null,
          versionType: row.versionType ?? null,
          versionStart: row.versionStart ?? null,
          versionEnd: row.versionEnd ?? null,
          lastAffected: row.lastAffected ?? null,
          versionStartInt: row.versionStart ? (normalizeVersion(row.versionStart) ?? null) : null,
          versionEndInt: row.versionEnd ? (normalizeVersion(row.versionEnd) ?? null) : null,
          lastAffectedInt: row.lastAffected ? (normalizeVersion(row.lastAffected) ?? null) : null,
          affectedVersions: row.affectedVersions ?? [],
        },
      });
    }

    return existing ? 'updated' : 'inserted';
  });
}

/**
 * Store one CVE's SSVC assessment directly on the Vulnerability master row,
 * the same "flat, 1:1-per-CVE" shape as the existing KEV/EPSS fields --
 * unlike CNA-affected-products, this has no separate table.
 *
 * Runs independently of parseCveRecord()/importCnaRecord(): a record can have
 * a perfectly good CISA-ADP SSVC container while having nothing CNA-affected-
 * products can use (or vice versa), so this must not be gated on that
 * function's success.
 */
export async function importSsvcAssessment(cveId: string, ssvc: SsvcAssessment): Promise<void> {
  await prisma.vulnerability.upsert({
    where: { cveId },
    create: {
      cveId,
      ssvcExploitation: ssvc.exploitation,
      ssvcAutomatable: ssvc.automatable,
      ssvcTechnicalImpact: ssvc.technicalImpact,
      ssvcTimestamp: ssvc.timestamp,
    },
    update: {
      ssvcExploitation: ssvc.exploitation,
      ssvcAutomatable: ssvc.automatable,
      ssvcTechnicalImpact: ssvc.technicalImpact,
      ssvcTimestamp: ssvc.timestamp,
    },
  });
}

function cveYear(cveId: string): string | undefined {
  return cveId.match(/^CVE-(\d{4})-/)?.[1];
}

export interface CnaImportResult {
  scanned: number;
  usable: number;
  inserted: number;
  updated: number;
  pruned: number;
  failed: number;
  rows: number;
  ssvcUpdated: number;
  dropped: Partial<Record<DropReason, number>>;
}

function emptyResult(): CnaImportResult {
  return { scanned: 0, usable: 0, inserted: 0, updated: 0, pruned: 0, failed: 0, rows: 0, ssvcUpdated: 0, dropped: {} };
}

/**
 * Remove a previously-stored CNA record that no longer has any usable
 * affected data -- a CNA correction, a since-fixed filtering gap being
 * reprocessed, or (via parseCveRecord's REJECTED check) a withdrawn CVE.
 * Deleting CnaVulnerability cascades to its CnaAffectedProduct rows.
 * A no-op (and reported as such) when nothing was stored for this id.
 */
async function pruneCnaRecord(cveId: string): Promise<boolean> {
  const { count } = await prisma.cnaVulnerability.deleteMany({ where: { cveId } });
  return count > 0;
}

function mergeDropped(into: CnaImportResult, from: Partial<Record<DropReason, number>>): void {
  for (const [reason, count] of Object.entries(from)) {
    const key = reason as DropReason;
    into.dropped[key] = (into.dropped[key] ?? 0) + count;
  }
}

/**
 * Parse, filter and store a stream of CVE Records.
 *
 * `cnaYears`, when given, restricts CNA-affected-products storage to CVE ids
 * in those years (bootstrapCna()'s existing scope decision -- older records
 * predate the structured `versions` conventions that feature relies on).
 * SSVC has no such dependency and is always attempted for every record,
 * regardless of this filter, so passing `cnaYears` costs nothing beyond what
 * decompressing/parsing the full bundle already costs.
 */
export async function importCveRecords(records: Iterable<CveRecord>, cnaYears: Set<string> | null = null): Promise<CnaImportResult> {
  const result = emptyResult();

  for (const record of records) {
    result.scanned++;
    const cveId = cveIdOf(record);

    const ssvc = parseSsvc(record);
    if (ssvc && cveId) {
      try {
        await importSsvcAssessment(cveId, ssvc);
        result.ssvcUpdated++;
      } catch (err) {
        result.failed++;
        logger.error({ err, cveId }, 'Failed to import SSVC assessment');
      }
    }

    if (cnaYears) {
      const year = cveId ? cveYear(cveId) : undefined;
      if (!year || !cnaYears.has(year)) continue;
    }

    const parsed = parseCveRecord(record);

    if (!parsed) {
      // Not just "no id at all": also the case where a CVE that previously had
      // usable rows (an earlier, looser import; a CNA correction) has none now.
      // Leaving its old rows in place would make the DB richer than the data
      // actually justifies -- see pruneCnaRecord()'s doc comment.
      if (cveId) {
        try {
          if (await pruneCnaRecord(cveId)) result.pruned++;
        } catch (err) {
          result.failed++;
          logger.error({ err, cveId }, 'Failed to prune stale CNA record');
        }
      }
      continue;
    }

    mergeDropped(result, parsed.dropped);
    result.usable++;
    result.rows += parsed.rows.length;
    try {
      const outcome = await importCnaRecord(parsed);
      if (outcome === 'inserted') result.inserted++;
      else result.updated++;
    } catch (err) {
      result.failed++;
      logger.error({ err, cveId: parsed.cveId }, 'Failed to import CNA record');
    }
    if (result.scanned % 5000 === 0) {
      logger.info({ scanned: result.scanned, usable: result.usable, rows: result.rows }, 'CNA import progress');
    }
  }

  return result;
}

/**
 * One-time bootstrap from the full bundle. CNA-affected-products storage is
 * restricted to `years`, but SSVC has no such restriction and is backfilled
 * for every record in the bundle -- see importCveRecords()'s doc comment.
 *
 * Deliberately scans every record (no year filter at the zip level) rather
 * than filtering to `years` there and only that: the ~600MB download is paid
 * either way, so restricting the zip-level scan would silently drop SSVC
 * backfill for the years it excludes instead of just skipping CNA-affected-
 * products for them.
 *
 * The full bundle is ~600MB, so this is deliberately not the routine path --
 * importCnaDelta() handles everything after the first run.
 */
export async function bootstrapCna(years: string[]): Promise<CnaImportResult> {
  const asset = findFullBundle(await listReleases(10));
  if (!asset) throw new Error('No full CVE bundle found in recent cvelistV5 releases');

  logger.info({ asset: asset.name, sizeMB: Math.round(asset.size / 1e6), years }, 'Downloading full CVE bundle');
  const zip = await downloadZip(asset.browser_download_url, 30 * 60 * 1000);
  logger.info('Full CVE bundle downloaded, importing');

  return importCveRecords(recordsFromZip(zip, null), new Set(years));
}

/**
 * Incremental import: every delta bundle published since `since`.
 *
 * Deltas cover one hour each, so every release newer than the cursor is
 * applied. Overlap is harmless -- importCnaRecord() upserts. Years are not
 * filtered here: a delta only contains recently changed records, and an older
 * CVE being revised now is exactly as worth storing.
 */
export async function importCnaDelta(since: Date): Promise<CnaImportResult> {
  const assets = findDeltaBundles(await listReleases(100), since);
  logger.info({ since: since.toISOString(), bundles: assets.length }, 'Importing CNA delta bundles');

  const total = emptyResult();
  for (const asset of assets) {
    const zip = await downloadZip(asset.browser_download_url, 5 * 60 * 1000);
    const result = await importCveRecords(recordsFromZip(zip, null));
    total.scanned += result.scanned;
    total.usable += result.usable;
    total.inserted += result.inserted;
    total.updated += result.updated;
    total.pruned += result.pruned;
    total.failed += result.failed;
    total.rows += result.rows;
    total.ssvcUpdated += result.ssvcUpdated;
    mergeDropped(total, result.dropped);
  }

  return total;
}
