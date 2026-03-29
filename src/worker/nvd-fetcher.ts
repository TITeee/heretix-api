import axios from 'axios';
import { logger } from '../utils/logger.js';
import { prisma } from '../db/client.js';
import { normalizeVersion } from '../utils/version.js';
import type { Prisma } from '@prisma/client';

// ─── NVD API Type Definitions ────────────────────────────────

interface NVDCvssMetricV31 {
  source: string;
  type: string;
  cvssData: {
    version: string;
    vectorString: string;
    baseScore: number;
    baseSeverity: string;
  };
}

interface NVDCvssMetricV2 {
  source: string;
  type: string;
  cvssData: {
    version: string;
    vectorString: string;
    baseScore: number;
  };
  baseSeverity?: string;
}

interface NVDCvssMetricV40 {
  source: string;
  type: string;
  cvssData: {
    version: string;
    vectorString: string;
    baseScore: number;
    baseSeverity: string;
  };
}

interface NVDCpeMatch {
  vulnerable: boolean;
  criteria: string;                    // "cpe:2.3:a:<vendor>:<product>:..."
  versionStartIncluding?: string;
  versionStartExcluding?: string;
  versionEndIncluding?: string;
  versionEndExcluding?: string;
  matchCriteriaId: string;
}

interface NVDNode {
  operator: string;
  negate: boolean;
  cpeMatch?: NVDCpeMatch[];
  children?: NVDNode[];
}

export interface NVDCveItem {
  id: string;                          // "CVE-2024-XXXX"
  sourceIdentifier?: string;
  published: string;
  lastModified: string;
  vulnStatus?: string;
  descriptions?: Array<{ lang: string; value: string }>;
  metrics?: {
    cvssMetricV40?: NVDCvssMetricV40[];
    cvssMetricV31?: NVDCvssMetricV31[];
    cvssMetricV2?: NVDCvssMetricV2[];
  };
  configurations?: Array<{ nodes: NVDNode[] }>;
  references?: Array<{ url: string; source?: string; tags?: string[] }>;
}

interface NVDApiResponse {
  resultsPerPage: number;
  startIndex: number;
  totalResults: number;
  format: string;
  version: string;
  timestamp: string;
  vulnerabilities: Array<{ cve: NVDCveItem }>;
}

// ─── CPE → Ecosystem Mapping ─────────────────────────────────

const VENDOR_ECOSYSTEM_MAP: Record<string, string> = {
  python: 'PyPI',
  pypi: 'PyPI',
  nodejs: 'npm',
  npm: 'npm',
  node: 'npm',
  redhat: 'AlmaLinux',
  almalinux: 'AlmaLinux',
  centos: 'AlmaLinux',
  rockylinux: 'AlmaLinux',
  debian: 'Debian',
  ubuntu: 'Ubuntu',
  suse: 'openSUSE',
  opensuse: 'openSUSE',
  rubygems: 'RubyGems',
  ruby: 'RubyGems',
  packagist: 'Packagist',
  php: 'Packagist',
  maven: 'Maven',
  apache: 'Maven',
  golang: 'Go',
  google: 'Go',
  nuget: 'NuGet',
  microsoft: 'NuGet',
  crates: 'crates.io',
  rust: 'crates.io',
};

/**
 * Parse a CPE string and extract package information
 * cpe:2.3:a:<vendor>:<product>:<version>:...
 */
function parseCPE(cpe: string): { vendor: string; packageName: string; ecosystem: string | null; version: string | null } | null {
  // Target cpe:2.3:a: (application) and cpe:2.3:o: (OS)
  // Exclude h: (hardware) because version is always "-"
  if (!cpe.startsWith('cpe:2.3:a:') && !cpe.startsWith('cpe:2.3:o:')) return null;

  const parts = cpe.split(':');
  // parts: ["cpe", "2.3", "a"/"o", "<vendor>", "<product>", "<version>", ...]
  if (parts.length < 5) return null;

  const vendor = parts[3];
  const product = parts[4];

  if (!vendor || !product || vendor === '*' || product === '*') return null;

  const ecosystem = VENDOR_ECOSYSTEM_MAP[vendor.toLowerCase()] ?? null;

  // Get parts[5] if it is a specific version ('*' and '-' mean wildcard/unspecified)
  const rawVersion = parts[5];
  const version = rawVersion && rawVersion !== '*' && rawVersion !== '-' ? rawVersion : null;

  return { vendor, packageName: product, ecosystem, version };
}

/**
 * Extract CVSS score and severity from NVD CVSS metrics
 */
function extractNVDCvss(metrics?: NVDCveItem['metrics']): {
  cvssScore: number | null;
  cvssVector: string | null;
  severity: string | null;
} {
  if (!metrics) return { cvssScore: null, cvssVector: null, severity: null };

  // Prefer CVSS v3.1
  const v31 = metrics.cvssMetricV31?.[0];
  if (v31) {
    return {
      cvssScore: v31.cvssData.baseScore,
      cvssVector: v31.cvssData.vectorString,
      severity: v31.cvssData.baseSeverity,
    };
  }

  // Fall back to CVSS v4.0
  const v40 = metrics.cvssMetricV40?.[0];
  if (v40) {
    return {
      cvssScore: v40.cvssData.baseScore,
      cvssVector: v40.cvssData.vectorString,
      severity: v40.cvssData.baseSeverity,
    };
  }

  // Fall back to CVSS v2
  const v2 = metrics.cvssMetricV2?.[0];
  if (v2) {
    return {
      cvssScore: v2.cvssData.baseScore,
      cvssVector: v2.cvssData.vectorString,
      severity: v2.baseSeverity ?? null,
    };
  }

  return { cvssScore: null, cvssVector: null, severity: null };
}

/**
 * Flatten CPE match list from NVD configuration nodes
 */
function flattenCpeMatches(nodes: NVDNode[]): NVDCpeMatch[] {
  const matches: NVDCpeMatch[] = [];
  for (const node of nodes) {
    if (node.cpeMatch) {
      matches.push(...node.cpeMatch.filter(m => m.vulnerable));
    }
    if (node.children) {
      matches.push(...flattenCpeMatches(node.children));
    }
  }
  return matches;
}

// ─── API Access ───────────────────────────────────────────────

const NVD_API_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const NVD_API_KEY = process.env.NVD_API_KEY;
// Rate limit: with API key 50 req/min (1200ms), without 10 req/min (6000ms)
const RATE_LIMIT_DELAY_MS = NVD_API_KEY ? 1200 : 6000;

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function buildHeaders(): Record<string, string> {
  return NVD_API_KEY ? { apiKey: NVD_API_KEY } : {};
}

/**
 * Fetch one page of data from the NVD API
 */
async function fetchNVDPage(params: Record<string, string | number>): Promise<NVDApiResponse> {
  const response = await axios.get<NVDApiResponse>(NVD_API_BASE, {
    params: { resultsPerPage: 2000, ...params },
    headers: buildHeaders(),
    timeout: 60000,
  });
  return response.data;
}

/**
 * Determine whether an error is a transient network error
 */
function isTransientError(err: unknown): boolean {
  if (axios.isAxiosError(err)) {
    const code = err.code ?? '';
    if (['ECONNRESET', 'ETIMEDOUT', 'ECONNABORTED', 'ERR_NETWORK'].includes(code)) return true;
    const status = err.response?.status ?? 0;
    if (status >= 500) return true;
  }
  return false;
}

/**
 * Fetch one page of data from the NVD API with exponential-backoff retry
 */
async function fetchNVDPageWithRetry(
  params: Record<string, string | number>,
  retries = 3,
): Promise<NVDApiResponse> {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      return await fetchNVDPage(params);
    } catch (err) {
      if (attempt === retries || !isTransientError(err)) throw err;
      const delay = 2000 * 2 ** (attempt - 1); // 2s → 4s → 8s
      logger.warn({ attempt, delay, params }, 'NVD page fetch failed, retrying...');
      await sleep(delay);
    }
  }
  throw new Error('unreachable');
}

/**
 * Fetch a single vulnerability by CVE ID
 */
export async function fetchNVDById(cveId: string): Promise<NVDCveItem> {
  logger.info({ cveId }, 'Fetching NVD vulnerability by CVE ID');

  const data = await fetchNVDPage({ cveId });
  if (!data.vulnerabilities.length) {
    throw new Error(`CVE not found: ${cveId}`);
  }
  return data.vulnerabilities[0].cve;
}

/**
 * Fetch vulnerabilities by date range (collect all pages)
 * When useLastMod=true, use lastModStartDate/lastModEndDate (for incremental updates)
 */
// NVD API v2.0 maximum date range (120 days)
const NVD_MAX_DATE_RANGE_DAYS = 120;

async function fetchNVDByDateRangeChunk(
  start: Date,
  end: Date,
  options: { useLastMod?: boolean } = {},
): Promise<NVDCveItem[]> {
  const startKey = options.useLastMod ? 'lastModStartDate' : 'pubStartDate';
  const endKey = options.useLastMod ? 'lastModEndDate' : 'pubEndDate';

  const fmt = (d: Date) => d.toISOString().replace('Z', '+00:00');

  const allItems: NVDCveItem[] = [];
  let startIndex = 0;
  let totalResults = Infinity;

  while (startIndex < totalResults) {
    const page = await fetchNVDPageWithRetry({
      [startKey]: fmt(start),
      [endKey]: fmt(end),
      startIndex,
    });

    totalResults = page.totalResults;
    const items = page.vulnerabilities.map(v => v.cve);
    allItems.push(...items);
    startIndex += items.length;

    logger.info({ startIndex, totalResults }, 'Fetched NVD page');

    if (startIndex < totalResults) {
      await sleep(RATE_LIMIT_DELAY_MS);
    }
  }

  return allItems;
}

export async function fetchNVDByDateRange(
  start: Date,
  end: Date,
  options: { useLastMod?: boolean } = {},
): Promise<NVDCveItem[]> {
  logger.info({ start, end, useLastMod: options.useLastMod }, 'Fetching NVD by date range');

  // NVD API only accepts ranges within 120 days; split into chunks
  const chunkMs = NVD_MAX_DATE_RANGE_DAYS * 24 * 60 * 60 * 1000;
  const allItems: NVDCveItem[] = [];

  let chunkStart = new Date(start);
  while (chunkStart < end) {
    const chunkEnd = new Date(Math.min(chunkStart.getTime() + chunkMs, end.getTime()));
    logger.info({ chunkStart, chunkEnd }, 'Fetching NVD chunk');

    const items = await fetchNVDByDateRangeChunk(chunkStart, chunkEnd, options);
    allItems.push(...items);

    chunkStart = new Date(chunkEnd.getTime() + 1);

    if (chunkStart < end) {
      await sleep(RATE_LIMIT_DELAY_MS);
    }
  }

  return allItems;
}

/**
 * Split a date range into 120-day chunks and alternate between fetching and importing
 * On fetch failure, already-imported data is preserved; re-runs are safe via upsert
 */
export async function importNVDByDateRange(
  start: Date,
  end: Date,
): Promise<{ total: number; succeeded: number; failed: number }> {
  logger.info({ start, end }, 'Importing NVD by date range');

  const chunkMs = NVD_MAX_DATE_RANGE_DAYS * 24 * 60 * 60 * 1000;
  let total = 0;
  let succeeded = 0;
  let failed = 0;
  let chunkStart = new Date(start);

  while (chunkStart < end) {
    const chunkEnd = new Date(Math.min(chunkStart.getTime() + chunkMs, end.getTime()));
    logger.info({ chunkStart, chunkEnd }, 'Fetching NVD chunk');

    const items = await fetchNVDByDateRangeChunk(chunkStart, chunkEnd);
    const result = await batchImportNVD(items);
    total += result.total;
    succeeded += result.succeeded;
    failed += result.failed;

    logger.info({ chunkStart, chunkEnd, ...result }, 'NVD chunk imported');

    chunkStart = new Date(chunkEnd.getTime() + 1);
    if (chunkStart < end) await sleep(RATE_LIMIT_DELAY_MS);
  }

  return { total, succeeded, failed };
}

/**
 * Fetch all NVD records via pagination and import sequentially
 * Progress is saved in CollectionJob metadata for resumability
 */
export async function fullDownloadNVD(jobId?: string): Promise<{ total: number; succeeded: number; failed: number }> {
  logger.info('Starting NVD full download');

  // Retrieve previous progress
  let startIndex = 0;
  let savedJobId = jobId;

  if (savedJobId) {
    const job = await prisma.collectionJob.findUnique({ where: { id: savedJobId } });
    const meta = job?.metadata as Record<string, number> | null;
    startIndex = meta?.lastStartIndex ?? 0;
    logger.info({ startIndex }, 'Resuming NVD download from previous checkpoint');
  } else {
    const job = await prisma.collectionJob.create({
      data: { source: 'nvd', status: 'running', startedAt: new Date() },
    });
    savedJobId = job.id;
  }

  let totalResults = Infinity;
  let succeeded = 0;
  let failed = 0;

  while (startIndex < totalResults) {
    let page: NVDApiResponse;
    try {
      page = await fetchNVDPageWithRetry({ startIndex });
    } catch (err) {
      logger.error({ err, startIndex }, 'Failed to fetch NVD page');
      break;
    }

    totalResults = page.totalResults;
    const items = page.vulnerabilities.map(v => v.cve);

    for (const item of items) {
      try {
        await importNVDData(item);
        succeeded++;
      } catch (err) {
        failed++;
        logger.error({ err, cveId: item.id }, 'Failed to import NVD CVE');
      }
    }

    startIndex += items.length;

    // Save progress
    await prisma.collectionJob.update({
      where: { id: savedJobId },
      data: {
        metadata: { lastStartIndex: startIndex, totalResults },
        totalInserted: succeeded,
        totalFailed: failed,
      },
    });

    logger.info({ startIndex, totalResults, succeeded, failed }, 'NVD page imported');

    if (startIndex < totalResults) {
      await sleep(RATE_LIMIT_DELAY_MS);
    }
  }

  await prisma.collectionJob.update({
    where: { id: savedJobId },
    data: { status: 'completed', completedAt: new Date(), totalInserted: succeeded, totalFailed: failed },
  });

  logger.info({ succeeded, failed, total: succeeded + failed }, 'NVD full download completed');
  return { total: succeeded + failed, succeeded, failed };
}

// ─── Import ───────────────────────────────────────────────────

/**
 * Upsert into master table and update NVDVulnerability.masterVulnId
 * NVD is the authoritative CVSS source, so always overwrite
 */
async function upsertMasterFromNVD(
  tx: Parameters<Parameters<typeof prisma.$transaction>[0]>[0],
  nvdRecordId: string,
  cveItem: NVDCveItem,
  cvssScore: number | null,
  cvssVector: string | null,
  severity: string | null,
  summary: string | null,
): Promise<void> {
  const master = await tx.vulnerability.upsert({
    where: { cveId: cveItem.id },
    create: {
      cveId: cveItem.id,
      severity,
      cvssScore,
      cvssVector,
      summary,
      publishedAt: cveItem.published ? new Date(cveItem.published) : null,
      modifiedAt: cveItem.lastModified ? new Date(cveItem.lastModified) : null,
    },
    update: {
      // Always overwrite since NVD is the authoritative source
      severity,
      cvssScore,
      cvssVector,
      summary,
      modifiedAt: cveItem.lastModified ? new Date(cveItem.lastModified) : null,
    },
  });

  await tx.nVDVulnerability.update({
    where: { id: nvdRecordId },
    data: { masterVulnId: master.id },
  });
}

/**
 * Save NVD CVE data to the database
 */
export async function importNVDData(cveItem: NVDCveItem): Promise<void> {
  const { cvssScore, cvssVector, severity } = extractNVDCvss(cveItem.metrics);
  const summary = cveItem.descriptions?.find(d => d.lang === 'en')?.value ?? null;

  await prisma.$transaction(async (tx) => {
    const vulnerability = await tx.nVDVulnerability.upsert({
      where: { cveId: cveItem.id },
      create: {
        cveId: cveItem.id,
        source: 'nvd',
        rawData: cveItem as unknown as Prisma.InputJsonValue,
        severity,
        cvssScore,
        cvssVector,
        summary,
        publishedAt: cveItem.published ? new Date(cveItem.published) : null,
        modifiedAt: cveItem.lastModified ? new Date(cveItem.lastModified) : null,
      },
      update: {
        rawData: cveItem as unknown as Prisma.InputJsonValue,
        severity,
        cvssScore,
        cvssVector,
        summary,
        modifiedAt: cveItem.lastModified ? new Date(cveItem.lastModified) : null,
      },
    });

    // Upsert into master table (NVD is authoritative CVSS source)
    await upsertMasterFromNVD(tx, vulnerability.id, cveItem, cvssScore, cvssVector, severity, summary);

    // Delete existing affected packages
    await tx.nVDAffectedPackage.deleteMany({ where: { vulnerabilityId: vulnerability.id } });

    // Extract and save affected packages from CPE
    for (const config of cveItem.configurations ?? []) {
      const cpeMatches = flattenCpeMatches(config.nodes);

      for (const match of cpeMatches) {
        const parsed = parseCPE(match.criteria);
        if (!parsed) continue;

        const { vendor, packageName, ecosystem, version: cpeVersion } = parsed;

        // Convert version range to BigInt (best-effort)
        const toInt = (v: string | undefined): bigint | null =>
          v ? (normalizeVersion(v) ?? null) : null;

        // If all range fields are absent, use the CPE URI version as a point version
        const hasRangeFields = match.versionStartIncluding || match.versionStartExcluding ||
          match.versionEndIncluding || match.versionEndExcluding;
        const pointVersion = !hasRangeFields ? cpeVersion : null;

        // introduced = versionStartIncluding ?? versionStartExcluding ?? pointVersion
        const introducedInt = toInt(match.versionStartIncluding ?? match.versionStartExcluding ?? pointVersion ?? undefined);
        // fixed = fixedInt when versionEndExcluding is present
        const fixedInt = toInt(match.versionEndExcluding);
        // lastAffected = versionEndIncluding ?? pointVersion
        const lastAffectedInt = toInt(match.versionEndIncluding ?? pointVersion ?? undefined);

        await tx.nVDAffectedPackage.create({
          data: {
            vulnerabilityId: vulnerability.id,
            cpe: match.criteria,
            vendor,
            packageName,
            ecosystem,
            versionStartIncluding: match.versionStartIncluding ?? pointVersion ?? null,
            versionStartExcluding: match.versionStartExcluding ?? null,
            versionEndIncluding: match.versionEndIncluding ?? pointVersion ?? null,
            versionEndExcluding: match.versionEndExcluding ?? null,
            introducedInt,
            fixedInt,
            lastAffectedInt,
          },
        });
      }
    }
  });

  logger.debug({ cveId: cveItem.id }, 'Imported NVD CVE');
}

/**
 * Batch import multiple NVD CVEs
 */
export async function batchImportNVD(cveList: NVDCveItem[]): Promise<{
  total: number;
  succeeded: number;
  failed: number;
}> {
  let succeeded = 0;
  let failed = 0;

  for (const cveItem of cveList) {
    try {
      await importNVDData(cveItem);
      succeeded++;
    } catch (err) {
      failed++;
      logger.error({ err, cveId: cveItem.id }, 'Failed to import NVD CVE in batch');
    }
  }

  return { total: cveList.length, succeeded, failed };
}
