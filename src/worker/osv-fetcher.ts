import axios from 'axios';
import { logger } from '../utils/logger.js';
import { prisma } from '../db/client.js';
import { normalizeVersion } from '../utils/version.js';
import AdmZip from 'adm-zip';
import type { Prisma } from '@prisma/client';

/**
 * OSV Schema Types
 */
interface OSVVulnerability {
  id: string;
  modified: string;
  published?: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: Array<{
    type: string;
    score: string;
  }>;
  affected?: Array<{
    package?: {
      ecosystem: string;
      name: string;
      purl?: string;
    };
    ranges?: Array<{
      type: string;
      events: Array<{
        introduced?: string;
        fixed?: string;
        last_affected?: string;
      }>;
    }>;
    versions?: string[];
  }>;
  references?: Array<{
    type: string;
    url: string;
  }>;
  upstream?: string[];
  database_specific?: Record<string, unknown>;
  schema_version?: string;
}

/**
 * Download OSV vulnerability data
 * Download and extract the ZIP file for the entire ecosystem
 */
export async function fetchOSVEcosystem(ecosystem: string): Promise<OSVVulnerability[]> {
  const url = `https://storage.googleapis.com/osv-vulnerabilities/${ecosystem}/all.zip`;

  logger.info({ ecosystem, url }, 'Fetching OSV data for ecosystem');

  try {
    const response = await axios.get(url, {
      responseType: 'arraybuffer',
      timeout: 300000, // 5 minutes
    });

    logger.info({ ecosystem, size: response.data.byteLength }, 'Downloaded ZIP file, extracting...');

    // Extract ZIP file
    const zip = new AdmZip(Buffer.from(response.data));
    const zipEntries = zip.getEntries();

    const vulnerabilities: OSVVulnerability[] = [];

    for (const entry of zipEntries) {
      // Process only JSON files
      if (!entry.entryName.endsWith('.json')) {
        continue;
      }

      try {
        const content = entry.getData().toString('utf8');
        const vuln = JSON.parse(content) as OSVVulnerability;
        vulnerabilities.push(vuln);
      } catch (parseError) {
        logger.warn({ entryName: entry.entryName, error: parseError }, 'Failed to parse JSON entry');
      }
    }

    logger.info({ ecosystem, count: vulnerabilities.length }, 'Successfully extracted vulnerabilities');

    return vulnerabilities;
  } catch (error) {
    logger.error({ error, ecosystem }, 'Failed to fetch OSV ecosystem data');
    throw error;
  }
}

/**
 * Fetch a single vulnerability by ID using the OSV API
 */
export async function fetchOSVById(osvId: string): Promise<OSVVulnerability> {
  const url = `https://api.osv.dev/v1/vulns/${osvId}`;

  logger.info({ osvId, url }, 'Fetching OSV vulnerability by ID');

  try {
    const response = await axios.get<OSVVulnerability>(url, {
      timeout: 30000,
    });

    return response.data;
  } catch (error) {
    logger.error({ error, osvId }, 'Failed to fetch OSV vulnerability');
    throw error;
  }
}

/**
 * Query vulnerabilities by package name and version
 * If packageName is not specified, fetch data for the entire ecosystem
 */
export async function queryOSVByPackage(
  ecosystem: string,
  packageName?: string,
  version?: string
): Promise<OSVVulnerability[]> {
  // If packageName is not specified, fetch the entire ecosystem
  if (!packageName) {
    logger.info({ ecosystem }, 'Fetching all vulnerabilities for ecosystem');
    return await fetchOSVEcosystem(ecosystem);
  }

  const url = 'https://api.osv.dev/v1/query';

  const payload: {
    package: { ecosystem: string; name: string };
    version?: string;
  } = {
    package: {
      ecosystem,
      name: packageName,
    },
  };

  if (version) {
    payload.version = version;
  }

  logger.info({ ecosystem, packageName, version }, 'Querying OSV by package');

  try {
    const response = await axios.post<{ vulns: OSVVulnerability[] }>(url, payload, {
      timeout: 30000,
    });

    return response.data.vulns || [];
  } catch (error) {
    logger.error({ error, ecosystem, packageName }, 'Failed to query OSV');
    throw error;
  }
}

/**
 * Extract CVSS score from severity array
 * Note: CVSS v4 vectors do not embed the base score; returns null for v4 entries.
 * Callers should supplement from database_specific.cvss_score if available.
 */
function extractCVSSScore(severity?: Array<{ type: string; score: string }>): number | null {
  if (!severity || severity.length === 0) return null;

  for (const s of severity) {
    if (s.type === 'CVSS_V3' || s.type === 'CVSS_V2') {
      // Extract numeric score from e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
      const match = s.score.match(/(\d+\.\d+)/);
      if (match) {
        return parseFloat(match[1]);
      }
    }
  }

  return null;
}

/**
 * Extract human-readable severity level (CRITICAL/HIGH/MEDIUM/LOW) from OSV data.
 * Prefers database_specific.severity, then derives from CVSS vector type as last resort.
 */
function extractOSVSeverity(osvData: OSVVulnerability): string | null {
  const dbSeverity = (osvData.database_specific as Record<string, unknown> | undefined)?.severity;
  if (typeof dbSeverity === 'string' && dbSeverity) return dbSeverity;
  return null;
}

/**
 * Download the ecosystem-wide ZIP and import entries one by one
 * Memory-efficient: does not accumulate all entries into an array
 */
export async function importOSVEcosystemStreaming(ecosystem: string): Promise<{
  total: number;
  succeeded: number;
  failed: number;
}> {
  const url = `https://storage.googleapis.com/osv-vulnerabilities/${ecosystem}/all.zip`;

  logger.info({ ecosystem, url }, 'Fetching OSV data for ecosystem');

  const response = await axios.get(url, {
    responseType: 'arraybuffer',
    timeout: 300000,
  });

  logger.info({ ecosystem, size: response.data.byteLength }, 'Downloaded ZIP file, importing entry by entry...');

  const zip = new AdmZip(Buffer.from(response.data));
  const zipEntries = zip.getEntries();

  let total = 0;
  let succeeded = 0;
  let failed = 0;

  for (const entry of zipEntries) {
    if (!entry.entryName.endsWith('.json')) continue;

    total++;
    try {
      const content = entry.getData().toString('utf8');
      const vuln = JSON.parse(content) as OSVVulnerability;
      await importOSVData(vuln);
      succeeded++;
    } catch (err) {
      failed++;
      logger.error({ err, entry: entry.entryName }, 'Failed to import OSV entry');
    }

    if (total % 1000 === 0) {
      logger.info({ total, succeeded, failed }, 'OSV ecosystem import progress');
    }
  }

  logger.info({ ecosystem, total, succeeded, failed }, 'OSV ecosystem import completed');
  return { total, succeeded, failed };
}

/**
 * Upsert into master table and update OSVVulnerability.masterVulnId
 * If NVD already has a master row, do not overwrite CVSS/severity values
 */
async function upsertMasterFromOSV(
  tx: Parameters<Parameters<typeof prisma.$transaction>[0]>[0],
  osvRecord: { id: string; cveId: string | null; osvId: string },
  osvData: OSVVulnerability,
): Promise<void> {
  const cvssScore = extractCVSSScore(osvData.severity);
  const severity = extractOSVSeverity(osvData);
  const publishedAt = osvData.published ? new Date(osvData.published) : null;
  const modifiedAt = osvData.modified ? new Date(osvData.modified) : null;

  let masterId: string;

  if (osvRecord.cveId) {
    // CVE alias present → upsert keyed by cveId
    // NVD may already have a row; preserve NVD CVSS values and fill only null fields with OSV values
    const existing = await tx.vulnerability.findUnique({ where: { cveId: osvRecord.cveId } });
    if (existing) {
      await tx.vulnerability.update({
        where: { cveId: osvRecord.cveId },
        data: {
          // Use OSV value only when NVD value is absent
          severity: existing.severity ?? severity,
          cvssScore: existing.cvssScore ?? cvssScore,
          summary: existing.summary ?? osvData.summary ?? null,
          publishedAt: existing.publishedAt ?? publishedAt,
          modifiedAt: modifiedAt && (!existing.modifiedAt || modifiedAt > existing.modifiedAt)
            ? modifiedAt : existing.modifiedAt,
        },
      });
      masterId = existing.id;
    } else {
      const master = await tx.vulnerability.create({
        data: {
          cveId: osvRecord.cveId,
          severity,
          cvssScore,
          summary: osvData.summary ?? null,
          publishedAt,
          modifiedAt,
        },
      });
      masterId = master.id;
    }
  } else {
    // No CVE → upsert keyed by osvId
    const master = await tx.vulnerability.upsert({
      where: { osvId: osvRecord.osvId },
      create: {
        osvId: osvRecord.osvId,
        severity,
        cvssScore,
        summary: osvData.summary ?? null,
        publishedAt,
        modifiedAt,
      },
      update: {
        severity,
        cvssScore,
        summary: osvData.summary ?? null,
        modifiedAt,
      },
    });
    masterId = master.id;
  }

  await tx.oSVVulnerability.update({
    where: { id: osvRecord.id },
    data: { masterVulnId: masterId },
  });
}

/**
 * Convert OSV data to Prisma model and save
 */
export async function importOSVData(osvData: OSVVulnerability): Promise<void> {
  logger.info({ osvId: osvData.id }, 'Importing OSV vulnerability');

  // Extract CVE ID from aliases, then upstream
  const cveId =
    (osvData.aliases ?? []).find((a: string) => a.startsWith('CVE-')) ??
    (osvData.upstream ?? []).find((u: string) => u.startsWith('CVE-')) ??
    null;

  try {
    // Save in a transaction
    await prisma.$transaction(async (tx) => {
      // Save basic vulnerability info
      const vulnerability = await tx.oSVVulnerability.upsert({
        where: { osvId: osvData.id },
        create: {
          osvId: osvData.id,
          cveId,
          aliases: osvData.aliases ?? [],
          source: 'osv',
          ecosystem: osvData.affected?.[0]?.package?.ecosystem,
          rawData: osvData as unknown as Prisma.InputJsonValue,
          packageName: osvData.affected?.[0]?.package?.name,
          severity: extractOSVSeverity(osvData),
          cvssScore: extractCVSSScore(osvData.severity),
          summary: osvData.summary,
          publishedAt: osvData.published ? new Date(osvData.published) : null,
          modifiedAt: osvData.modified ? new Date(osvData.modified) : null,
        },
        update: {
          cveId,
          aliases: osvData.aliases ?? [],
          rawData: osvData as unknown as Prisma.InputJsonValue,
          packageName: osvData.affected?.[0]?.package?.name,
          severity: extractOSVSeverity(osvData),
          cvssScore: extractCVSSScore(osvData.severity),
          summary: osvData.summary,
          modifiedAt: osvData.modified ? new Date(osvData.modified) : null,
        },
      });

      // Upsert into master table
      await upsertMasterFromOSV(tx, { id: vulnerability.id, cveId, osvId: osvData.id }, osvData);

      // Delete existing affected packages
      await tx.oSVAffectedPackage.deleteMany({
        where: { vulnerabilityId: vulnerability.id },
      });

      // Save affected packages and version ranges
      if (osvData.affected) {
        for (const affected of osvData.affected) {
          if (!affected.package) continue;

          const ecosystem = affected.package.ecosystem;
          const packageName = affected.package.name;

          // affected.versions: used for exact-match lookups in distro ecosystems
          const affectedVersions: string[] = affected.versions ?? [];

          // Extract version ranges
          if (affected.ranges) {
            for (const range of affected.ranges) {
              if (range.type !== 'SEMVER' && range.type !== 'ECOSYSTEM') continue;

              // OSV events are a state machine: {introduced} → {fixed|last_affected} pairs produce one row
              // Pair events rather than processing each independently to create range rows
              let currentIntroducedVersion: string | undefined = undefined;

              const emitRange = async (
                introducedVersion: string | undefined,
                fixedVersion: string | undefined,
                lastAffectedVersion: string | undefined,
              ) => {
                let introducedInt: bigint | null = null;
                let fixedInt: bigint | null = null;
                let lastAffectedInt: bigint | null = null;

                try {
                  if (introducedVersion) {
                    if (introducedVersion === '0') {
                      introducedInt = 0n;
                    } else {
                      introducedInt = normalizeVersion(introducedVersion);
                      if (introducedInt === null) {
                        logger.debug({ introducedVersion, osvId: osvData.id },
                          'Skipped version normalization (abnormal value detected)');
                      }
                    }
                  }
                  if (fixedVersion) {
                    fixedInt = normalizeVersion(fixedVersion);
                    if (fixedInt === null) {
                      logger.debug({ fixedVersion, osvId: osvData.id },
                        'Skipped version normalization (abnormal value detected)');
                    }
                  }
                  if (lastAffectedVersion) {
                    lastAffectedInt = normalizeVersion(lastAffectedVersion);
                    if (lastAffectedInt === null) {
                      logger.debug({ lastAffectedVersion, osvId: osvData.id },
                        'Skipped version normalization (abnormal value detected)');
                    }
                  }
                } catch (err) {
                  logger.warn({ err, introducedVersion, fixedVersion, lastAffectedVersion, osvId: osvData.id },
                    'Failed to normalize version');
                }

                await tx.oSVAffectedPackage.create({
                  data: {
                    vulnerabilityId: vulnerability.id,
                    ecosystem,
                    packageName,
                    versionType: range.type.toLowerCase(),
                    introducedVersion: introducedVersion ?? null,
                    fixedVersion: fixedVersion ?? null,
                    lastAffectedVersion: lastAffectedVersion ?? null,
                    introducedInt,
                    fixedInt,
                    lastAffectedInt,
                    affectedVersions,
                  },
                });
              };

              for (const event of range.events) {
                if (event.introduced !== undefined) {
                  // If a previous introduced is unclosed, emit with no upper bound
                  if (currentIntroducedVersion !== undefined) {
                    await emitRange(currentIntroducedVersion, undefined, undefined);
                  }
                  currentIntroducedVersion = event.introduced;
                } else if (event.fixed !== undefined) {
                  await emitRange(currentIntroducedVersion, event.fixed, undefined);
                  currentIntroducedVersion = undefined;
                } else if (event.last_affected !== undefined) {
                  await emitRange(currentIntroducedVersion, undefined, event.last_affected);
                  currentIntroducedVersion = undefined;
                }
              }

              // After loop: if an unclosed introduced remains, emit with no upper bound
              if (currentIntroducedVersion !== undefined) {
                await emitRange(currentIntroducedVersion, undefined, undefined);
              }
            }
          }
        }
      }
    });

    logger.info({ osvId: osvData.id }, 'Successfully imported OSV vulnerability');
  } catch (error) {
    logger.error({ error, osvId: osvData.id }, 'Failed to import OSV vulnerability');
    throw error;
  }
}

/**
 * Batch import multiple vulnerabilities
 */
export async function batchImportOSV(osvDataList: OSVVulnerability[]): Promise<{
  total: number;
  succeeded: number;
  failed: number;
}> {
  const total = osvDataList.length;
  let succeeded = 0;
  let failed = 0;

  logger.info({ total }, 'Starting batch import of OSV vulnerabilities');

  for (const osvData of osvDataList) {
    try {
      await importOSVData(osvData);
      succeeded++;
    } catch (error) {
      failed++;
      logger.error({ error, osvId: osvData.id }, 'Failed to import vulnerability in batch');
    }
  }

  logger.info({ total, succeeded, failed }, 'Completed batch import');

  return { total, succeeded, failed };
}
