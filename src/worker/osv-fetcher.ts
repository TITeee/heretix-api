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
 * OSV severity[].score contains only a CVSS vector string, not a numeric base score.
 * A regex on the vector would match the version prefix (e.g. "3.1" from "CVSS:3.1/..."),
 * not the actual score. Numeric scores must come from NVD or database_specific fields.
 */
function extractCVSSScore(_severity?: Array<{ type: string; score: string }>): number | null {
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
 * Delta import for a single OSV ecosystem.
 * Downloads the full ecosystem ZIP (same as importOSVEcosystemStreaming) but skips
 * entries whose `modified` timestamp is not newer than `since`.
 */
export async function importOSVEcosystemDelta(ecosystem: string, since: Date): Promise<{
  total: number;
  skipped: number;
  succeeded: number;
  failed: number;
}> {
  const url = `https://storage.googleapis.com/osv-vulnerabilities/${ecosystem}/all.zip`;

  logger.info({ ecosystem, url, since }, 'Fetching OSV ecosystem ZIP for delta import');

  const response = await axios.get(url, {
    responseType: 'arraybuffer',
    timeout: 300000,
  });

  logger.info({ ecosystem, size: response.data.byteLength }, 'Downloaded ZIP file, applying delta filter...');

  const zip = new AdmZip(Buffer.from(response.data));
  const zipEntries = zip.getEntries();

  let total = 0;
  let skipped = 0;
  let succeeded = 0;
  let failed = 0;

  for (const entry of zipEntries) {
    if (!entry.entryName.endsWith('.json')) continue;

    total++;
    try {
      const content = entry.getData().toString('utf8');
      const vuln = JSON.parse(content) as OSVVulnerability;

      if (vuln.modified && new Date(vuln.modified) <= since) {
        skipped++;
        continue;
      }

      await importOSVData(vuln);
      succeeded++;
    } catch (err) {
      failed++;
      logger.error({ err, entry: entry.entryName }, 'Failed to import OSV entry');
    }

    if (total % 1000 === 0) {
      logger.info({ total, skipped, succeeded, failed }, 'OSV delta import progress');
    }
  }

  logger.info({ ecosystem, since, total, skipped, succeeded, failed }, 'OSV delta import completed');
  return { total, skipped, succeeded, failed };
}

/**
 * Import all malware detections from the ossf/malicious-packages GitHub repository.
 * MAL entries are not exported to the GCS osv-vulnerabilities bucket; the canonical
 * source is https://github.com/ossf/malicious-packages (osv/malicious/**\/*.json).
 *
 * Strategy: one GitHub tree API call to list all file paths, then fetch each JSON
 * from raw.githubusercontent.com (CDN, no rate limit) one at a time.
 * Set GITHUB_TOKEN env var to raise the tree API rate limit from 60 to 5000 req/hour
 * (only needed if running this command more than 60 times per hour).
 */
export async function importMALFromGitHub(): Promise<{
  total: number;
  succeeded: number;
  failed: number;
}> {
  const token = process.env.GITHUB_TOKEN;
  const apiHeaders: Record<string, string> = { Accept: 'application/vnd.github.v3+json' };
  if (token) apiHeaders['Authorization'] = `Bearer ${token}`;

  // One API call to get the full recursive file tree
  const treeUrl = 'https://api.github.com/repos/ossf/malicious-packages/git/trees/main?recursive=1';
  logger.info('Fetching ossf/malicious-packages file tree');

  const treeResp = await axios.get<{ tree: { path: string; type: string }[]; truncated: boolean }>(
    treeUrl, { headers: apiHeaders, timeout: 60000 },
  );

  if (treeResp.data.truncated) {
    logger.warn('GitHub tree response was truncated — some MAL entries may be missing');
  }

  const malPaths = treeResp.data.tree.filter(
    item => item.type === 'blob' && item.path.startsWith('osv/malicious/') && item.path.endsWith('.json'),
  );

  logger.info({ count: malPaths.length }, 'MAL files found, importing...');

  let total = 0;
  let succeeded = 0;
  let failed = 0;

  for (const item of malPaths) {
    total++;
    const rawUrl = `https://raw.githubusercontent.com/ossf/malicious-packages/main/${item.path}`;
    try {
      const resp = await axios.get<OSVVulnerability>(rawUrl, { timeout: 30000 });
      await importOSVData(resp.data);
      succeeded++;
    } catch (err) {
      failed++;
      logger.error({ err, path: item.path }, 'Failed to import MAL entry');
    }

    if (total % 500 === 0) {
      logger.info({ total, succeeded, failed }, 'MAL import progress');
    }
  }

  logger.info({ total, succeeded, failed }, 'MAL import completed');
  return { total, succeeded, failed };
}

/**
 * Delta import for MAL entries from ossf/malicious-packages.
 * Same as importMALFromGitHub but skips entries not modified after `since`.
 */
export async function importMALDelta(since: Date): Promise<{
  total: number;
  skipped: number;
  succeeded: number;
  failed: number;
}> {
  const token = process.env.GITHUB_TOKEN;
  const apiHeaders: Record<string, string> = { Accept: 'application/vnd.github.v3+json' };
  if (token) apiHeaders['Authorization'] = `Bearer ${token}`;

  const treeUrl = 'https://api.github.com/repos/ossf/malicious-packages/git/trees/main?recursive=1';
  logger.info({ since }, 'Fetching ossf/malicious-packages file tree for delta import');

  const treeResp = await axios.get<{ tree: { path: string; type: string }[]; truncated: boolean }>(
    treeUrl, { headers: apiHeaders, timeout: 60000 },
  );

  if (treeResp.data.truncated) {
    logger.warn('GitHub tree response was truncated — some MAL entries may be missing');
  }

  const malPaths = treeResp.data.tree.filter(
    item => item.type === 'blob' && item.path.startsWith('osv/malicious/') && item.path.endsWith('.json'),
  );

  logger.info({ count: malPaths.length, since }, 'MAL files found, applying delta filter...');

  let total = 0;
  let skipped = 0;
  let succeeded = 0;
  let failed = 0;

  for (const item of malPaths) {
    total++;
    const rawUrl = `https://raw.githubusercontent.com/ossf/malicious-packages/main/${item.path}`;
    try {
      const resp = await axios.get<OSVVulnerability>(rawUrl, { timeout: 30000 });
      const vuln = resp.data;

      if (vuln.modified && new Date(vuln.modified) <= since) {
        skipped++;
        continue;
      }

      await importOSVData(vuln);
      succeeded++;
    } catch (err) {
      failed++;
      logger.error({ err, path: item.path }, 'Failed to import MAL entry');
    }

    if (total % 500 === 0) {
      logger.info({ total, skipped, succeeded, failed }, 'MAL delta import progress');
    }
  }

  logger.info({ since, total, skipped, succeeded, failed }, 'MAL delta import completed');
  return { total, skipped, succeeded, failed };
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
          } else if (affectedVersions.length > 0) {
            // No ranges but versions[] present (e.g. MAL ecosystem entries).
            // Store with versionType 'versions' so the search layer can route to exact match.
            await tx.oSVAffectedPackage.create({
              data: {
                vulnerabilityId: vulnerability.id,
                ecosystem,
                packageName,
                versionType: 'versions',
                affectedVersions,
              },
            });
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
