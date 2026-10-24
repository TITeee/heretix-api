import axios from 'axios';
import { logger } from '../utils/logger.js';
import { prisma } from '../db/client.js';
import { createManyChunked } from '../db/bulk-insert.js';
import { normalizeVersion } from '../utils/version.js';
import { cvssFromOsvSeverity } from '../utils/cvss.js';
import { normalizeSeverity, severityFromCvssScore } from '../utils/severity.js';
import AdmZip from 'adm-zip';
import { staleBucketProblem, usesModifiedList } from '../jobs/osv-bucket.js';
import type { Prisma } from '@prisma/client';

/**
 * OSV Schema Types
 */
export interface OSVVulnerability {
  id: string;
  modified: string;
  published?: string;
  // Set when this record has been withdrawn (e.g. superseded by another record
  // as a duplicate) -- see importOSVData()'s handling below.
  withdrawn?: string;
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
    // Debian: { urgency: "unimportant" | "low" | ... } per (release, package).
    ecosystem_specific?: Record<string, unknown>;
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

// Ubuntu's priority scale, as OSV's Ubuntu records carry it in a severity[]
// entry of type "Ubuntu" -- one value for the whole record.
const UBUNTU_PRIORITIES = new Set(['negligible', 'low', 'medium', 'high', 'critical']);

// Debian security tracker's urgency, as OSV's Debian records carry it in each
// affected entry's ecosystem_specific -- one value per (release, package):
// 3,202 of 62,202 Debian records rate the same CVE differently per release.
// "not yet assigned" (not triaged yet) and "end-of-life" (the package is no
// longer supported in that release) are kept too: both are the tracker's own
// statement, and a consumer can decide what to do with them.
const DEBIAN_URGENCIES = new Set(['unimportant', 'low', 'medium', 'high', 'end-of-life', 'not yet assigned']);

/**
 * The distro's own rating of this CVE when it is one value for the whole
 * record -- Ubuntu's priority -- verbatim, or null. Stored on OSVVulnerability.
 *
 * Distro ratings are kept verbatim (not mapped onto CRITICAL..LOW) --
 * "negligible" / "unimportant" have no CVSS counterpart -- and never merged
 * into the CVE-wide Vulnerability.severity. See VulnerabilityResult.distroPriority.
 */
export function extractRecordDistroPriority(osvData: OSVVulnerability): string | null {
  const entry = osvData.severity?.find(s => s.type === 'Ubuntu');
  const priority = typeof entry?.score === 'string' ? entry.score.trim().toLowerCase() : '';
  return UBUNTU_PRIORITIES.has(priority) ? priority : null;
}

/**
 * The distro's own rating of this CVE for one affected entry, when the distro
 * rates per (release, package) -- Debian's urgency -- verbatim, or null.
 * Stored on each OSVAffectedPackage row that entry produces.
 */
export function extractDistroPriority(affected: NonNullable<OSVVulnerability['affected']>[number]): string | null {
  if (!(affected.package?.ecosystem ?? '').startsWith('Debian')) return null;
  const urgency = affected.ecosystem_specific?.urgency;
  const value = typeof urgency === 'string' ? urgency.trim().toLowerCase() : '';
  return DEBIAN_URGENCIES.has(value) ? value : null;
}

/**
 * Severity, CVSS score and vector for an OSV record.
 *
 * severity[].score holds only a CVSS vector, so the score is computed from it
 * (cvssFromOsvSeverity()). The severity is the database_specific one (GHSA's
 * rating) normalized to the API's scale -- GHSA's MODERATE is MEDIUM -- and,
 * when the record has none, the CVSS rating of the computed score.
 */
export function extractOSVSeverityFields(osvData: OSVVulnerability): {
  severity: string | null;
  cvssScore: number | null;
  cvssVector: string | null;
} {
  const cvss = cvssFromOsvSeverity(osvData.severity);
  const dbSeverity = normalizeSeverity((osvData.database_specific as Record<string, unknown> | undefined)?.severity);
  return {
    severity: dbSeverity ?? (cvss ? severityFromCvssScore(cvss.score) : null),
    cvssScore: cvss?.score ?? null,
    cvssVector: cvss?.vector ?? null,
  };
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

type DeltaResult = {
  total: number;
  skipped: number;
  succeeded: number;
  inserted: number;
  updated: number;
  failed: number;
};

const OSV_BUCKET_URL = 'https://storage.googleapis.com/osv-vulnerabilities';

function missingBucketError(ecosystem: string, url: string, cause: unknown): Error {
  return new Error(
    `OSV has no bucket "${ecosystem}" (404 for ${url}). Check osvBucketName() / SHARED_BUCKET_ECOSYSTEMS in ` +
      'src/jobs/osv-bucket.ts against https://storage.googleapis.com/osv-vulnerabilities/ecosystems.txt',
    { cause },
  );
}

/** GET with a few retries: a delta of thousands of single records meets the odd reset or 5xx. */
async function getWithRetry<T>(url: string, responseType: 'json' | 'text', attempts = 4, headers?: Record<string, string>): Promise<T> {
  for (let attempt = 1; ; attempt++) {
    try {
      return (await axios.get<T>(url, { responseType, timeout: 60000, headers })).data;
    } catch (err) {
      const status = axios.isAxiosError(err) ? err.response?.status : undefined;
      // A 404 is an answer, and so is any other 4xx; only a transport error or a 5xx can pass.
      if (attempt >= attempts || (status !== undefined && status < 500)) throw err;
      await new Promise((resolve) => setTimeout(resolve, 500 * attempt));
    }
  }
}

const LISTED_DELTA_CHUNK = 16;

/**
 * Delta import of a bucket too big to download whole every day (Ubuntu: 792 MB): read its
 * modified_id.csv ("<time>,<id>", newest first), then fetch one record per line newer than
 * `since`. Fails on a missing or frozen bucket exactly as the zip variant does, judging by the
 * newest line of the list.
 */
async function importOSVEcosystemDeltaFromList(ecosystem: string, since: Date): Promise<DeltaResult> {
  const base = `${OSV_BUCKET_URL}/${ecosystem}`;
  const listUrl = `${base}/modified_id.csv`;
  logger.info({ ecosystem, url: listUrl, since }, 'Fetching OSV modified-ID list for delta import');

  let text: string;
  try {
    text = await getWithRetry<string>(listUrl, 'text');
  } catch (err) {
    if (axios.isAxiosError(err) && err.response?.status === 404) throw missingBucketError(ecosystem, listUrl, err);
    throw err;
  }

  const entries: Array<{ modified: Date; id: string }> = [];
  for (const line of text.split(/\r?\n/)) {
    const comma = line.indexOf(',');
    if (comma === -1) continue;
    const modified = new Date(line.slice(0, comma));
    const id = line.slice(comma + 1).trim();
    if (id && !Number.isNaN(modified.getTime())) entries.push({ modified, id });
  }
  const newestModified = entries.reduce<Date | null>((newest, e) => (!newest || e.modified > newest ? e.modified : newest), null);
  const changed = entries.filter((e) => e.modified > since);
  logger.info({ ecosystem, listed: entries.length, changed: changed.length }, 'Applying delta filter to the modified-ID list');

  let inserted = 0;
  let updated = 0;
  let failed = 0;
  for (let i = 0; i < changed.length; i += LISTED_DELTA_CHUNK) {
    const chunk = changed.slice(i, i + LISTED_DELTA_CHUNK);
    // The requests of a chunk run together; the records are written one at a time.
    const fetched = await Promise.all(chunk.map(async (e) => {
      try {
        return { id: e.id, vuln: await getWithRetry<OSVVulnerability>(`${base}/${encodeURIComponent(e.id)}.json`, 'json') };
      } catch (err) {
        logger.error({ err, id: e.id }, 'Failed to fetch OSV record');
        return { id: e.id, vuln: null };
      }
    }));
    for (const { id, vuln } of fetched) {
      if (!vuln) {
        failed++;
        continue;
      }
      try {
        const result = await importOSVData(vuln);
        if (result === 'inserted') inserted++; else updated++;
      } catch (err) {
        failed++;
        logger.error({ err, id }, 'Failed to import OSV entry');
      }
    }
    if ((i / LISTED_DELTA_CHUNK) % 50 === 0) {
      logger.info({ done: Math.min(i + LISTED_DELTA_CHUNK, changed.length), of: changed.length, inserted, updated, failed }, 'OSV delta import progress');
    }
  }

  const succeeded = inserted + updated;
  const skipped = entries.length - changed.length;
  logger.info({ ecosystem, since, total: entries.length, skipped, succeeded, failed, newestModified }, 'OSV delta import completed');

  const problem = staleBucketProblem(ecosystem, newestModified);
  if (problem) {
    throw new Error(`OSV delta for "${ecosystem}" listed ${entries.length} records and imported ${succeeded}, but ${problem}`);
  }
  return { total: entries.length, skipped, succeeded, inserted, updated, failed };
}

/**
 * Delta import for a single OSV ecosystem.
 * Downloads the full ecosystem ZIP (same as importOSVEcosystemStreaming) but skips
 * entries whose `modified` timestamp is not newer than `since`. A bucket too big for that
 * (see usesModifiedList) is read from its modified-ID list instead.
 *
 * Throws, rather than returning an empty success, when the bucket is missing (404) or is no
 * longer written to (its newest record is older than osv-bucket.ts's limit for the ecosystem).
 * A run that fetches the same frozen file and imports nothing looks exactly like a quiet day,
 * and Debian, Ubuntu and Alpine went months without an update that way.
 */
export async function importOSVEcosystemDelta(ecosystem: string, since: Date): Promise<DeltaResult> {
  if (usesModifiedList(ecosystem)) return importOSVEcosystemDeltaFromList(ecosystem, since);

  const url = `${OSV_BUCKET_URL}/${ecosystem}/all.zip`;

  logger.info({ ecosystem, url, since }, 'Fetching OSV ecosystem ZIP for delta import');

  let responseData: ArrayBuffer;
  try {
    const response = await axios.get<ArrayBuffer>(url, {
      responseType: 'arraybuffer',
      timeout: 300000,
    });
    responseData = response.data;
  } catch (err) {
    if (axios.isAxiosError(err) && err.response?.status === 404) {
      // osvBucketName() (jobs/osv-bucket.ts) is responsible for mapping a DB
      // ecosystem value to a bucket name that actually exists -- a 404 here
      // means that mapping is missing or wrong for this ecosystem (the
      // AlmaLinux/Rocky Linux case: their per-version DB values 404 against
      // OSV's shared, version-less bucket and returned a fake "0 fetched"
      // success every day for a week, and Alpine 3.21+ and Ubuntu 24.10+ did
      // the same after it). Failing the job is what makes it show up.
      logger.error({ ecosystem, url }, 'No GCS bucket found for ecosystem');
      throw missingBucketError(ecosystem, url, err);
    }
    throw err;
  }

  logger.info({ ecosystem, size: responseData.byteLength }, 'Downloaded ZIP file, applying delta filter...');

  const zip = new AdmZip(Buffer.from(responseData));
  const zipEntries = zip.getEntries();

  let total = 0;
  let skipped = 0;
  let inserted = 0;
  let updated = 0;
  let failed = 0;
  let newestModified: Date | null = null;

  for (const entry of zipEntries) {
    if (!entry.entryName.endsWith('.json')) continue;

    total++;
    try {
      const content = entry.getData().toString('utf8');
      const vuln = JSON.parse(content) as OSVVulnerability;

      if (vuln.modified) {
        const modified = new Date(vuln.modified);
        if (!newestModified || modified > newestModified) newestModified = modified;
      }

      if (vuln.modified && new Date(vuln.modified) <= since) {
        skipped++;
        continue;
      }

      const result = await importOSVData(vuln);
      if (result === 'inserted') inserted++; else updated++;
    } catch (err) {
      failed++;
      logger.error({ err, entry: entry.entryName }, 'Failed to import OSV entry');
    }

    if (total % 1000 === 0) {
      logger.info({ total, skipped, inserted, updated, failed }, 'OSV delta import progress');
    }
  }

  const succeeded = inserted + updated;
  logger.info({ ecosystem, since, total, skipped, succeeded, failed, newestModified }, 'OSV delta import completed');

  const problem = staleBucketProblem(ecosystem, newestModified);
  if (problem) {
    throw new Error(`OSV delta for "${ecosystem}" fetched ${total} records and imported ${succeeded}, but ${problem}`);
  }
  return { total, skipped, succeeded, inserted, updated, failed };
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

const MAL_REPO = 'ossf/malicious-packages';
const MAL_API = `https://api.github.com/repos/${MAL_REPO}`;
const MAL_RAW = `https://raw.githubusercontent.com/${MAL_REPO}`;
/** The cursor is the end of the last run; commits are dated by whoever made them, so start a little before. */
const MAL_CURSOR_MARGIN_MS = 6 * 60 * 60 * 1000;
const MAL_PAGE = 100;
const MAL_FETCH_CHUNK = 16;
/** Longest a run waits for GitHub's rate limit to reset before giving up (the limit resets hourly). */
const MAL_RATE_LIMIT_MAX_WAIT_MS = 70 * 60 * 1000;

type MalCommitFile = { filename: string; status: string; previous_filename?: string };

/**
 * One GET of GitHub's API. Without GITHUB_TOKEN the limit is 60 requests an hour, which a run
 * after a few days away can pass; the run then waits for the limit to reset and goes on,
 * rather than failing or skipping what it has not read.
 */
async function githubGet<T>(url: string, headers: Record<string, string>): Promise<T> {
  for (let waited = 0; ; ) {
    try {
      return await getWithRetry<T>(url, 'json', 4, headers);
    } catch (err) {
      const res = axios.isAxiosError(err) ? err.response : undefined;
      const limited = res && (res.status === 429 || (res.status === 403 && res.headers['x-ratelimit-remaining'] === '0'));
      if (!limited) throw err;
      const reset = Number(res.headers['x-ratelimit-reset']) * 1000;
      const retryAfter = Number(res.headers['retry-after']) * 1000;
      const waitMs = Math.max(Number.isFinite(retryAfter) ? retryAfter : 0, Number.isFinite(reset) ? reset - Date.now() : 0, 0) + 1000;
      if (waited + waitMs > MAL_RATE_LIMIT_MAX_WAIT_MS) {
        throw new Error('GitHub rate limit reached and it does not reset soon enough; set GITHUB_TOKEN (5,000 requests an hour instead of 60)', { cause: err });
      }
      logger.warn({ waitSeconds: Math.round(waitMs / 1000) }, 'GitHub rate limit reached, waiting for it to reset');
      await new Promise((resolve) => setTimeout(resolve, waitMs));
      waited += waitMs;
    }
  }
}

/**
 * The MAL files that exist at the newest commit and changed in the commits made since `from`,
 * read commit by commit, oldest first, so a file added and then removed (or the reverse) ends
 * in the state of the last commit that touched it.
 *
 * GitHub's comparison of two commits is no use here: it lists at most 300 files however long the
 * span, and says nothing of the rest. The commit list has no such limit, and each commit lists
 * its own files (paged, 100 at a time).
 */
async function malFilesChangedSince(from: Date, headers: Record<string, string>): Promise<{ head: string | null; paths: string[] }> {
  const shas: string[] = [];
  for (let page = 1; ; page++) {
    const commits = await githubGet<Array<{ sha: string }>>(
      `${MAL_API}/commits?since=${from.toISOString()}&per_page=${MAL_PAGE}&page=${page}`, headers,
    );
    shas.push(...commits.map((c) => c.sha));
    if (commits.length < MAL_PAGE) break;
  }
  if (shas.length === 0) return { head: null, paths: [] };

  const live = new Set<string>();
  // The commit list is newest first.
  for (const sha of shas.reverse()) {
    for (let page = 1; ; page++) {
      const commit = await githubGet<{ files?: MalCommitFile[] }>(`${MAL_API}/commits/${sha}?per_page=${MAL_PAGE}&page=${page}`, headers);
      const files = commit.files ?? [];
      for (const f of files) {
        if (f.previous_filename) live.delete(f.previous_filename);
        if (!f.filename.startsWith('osv/malicious/') || !f.filename.endsWith('.json')) continue;
        if (f.status === 'removed') live.delete(f.filename);
        else live.add(f.filename);
      }
      if (files.length < MAL_PAGE) break;
    }
  }
  return { head: shas[shas.length - 1], paths: [...live] };
}

/**
 * Delta import for MAL entries from ossf/malicious-packages: the files changed in the commits
 * made since `since`.
 *
 * It used to fetch every file of the repository's recursive tree to look at its `modified`.
 * That took about three hours a day for 1 to 100 changed records, and read only part of the
 * repository: GitHub truncates the tree at 100,000 entries, which left out the PyPI, RubyGems
 * and NuGet files and a part of the npm ones, and the warning for it was only logged.
 *
 * A record imported twice is only written again, so the margin before `since` costs nothing.
 * A run is one request per commit, a hundred or so a day. GITHUB_TOKEN raises the API limit from
 * 60 requests an hour to 5,000.
 */
export async function importMALDelta(since: Date): Promise<{
  total: number;
  skipped: number;
  succeeded: number;
  inserted: number;
  updated: number;
  failed: number;
}> {
  const token = process.env.GITHUB_TOKEN;
  const headers: Record<string, string> = { Accept: 'application/vnd.github.v3+json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  logger.info({ since }, 'Finding the ossf/malicious-packages files changed since the last run');
  const { head, paths } = await malFilesChangedSince(new Date(since.getTime() - MAL_CURSOR_MARGIN_MS), headers);
  logger.info({ head: head?.slice(0, 8) ?? null, files: paths.length }, 'MAL files changed');

  let inserted = 0;
  let updated = 0;
  let failed = 0;
  for (let i = 0; i < paths.length; i += MAL_FETCH_CHUNK) {
    const chunk = paths.slice(i, i + MAL_FETCH_CHUNK);
    // Fetched together, written one at a time. Pinned to the newest commit, so a file that
    // moves while the run goes on is not read from two states of the repository.
    const fetched = await Promise.all(chunk.map(async (path) => {
      try {
        return { path, vuln: await getWithRetry<OSVVulnerability>(`${MAL_RAW}/${head}/${path}`, 'json') };
      } catch (err) {
        logger.error({ err, path }, 'Failed to fetch MAL entry');
        return { path, vuln: null };
      }
    }));
    for (const { path, vuln } of fetched) {
      if (!vuln) {
        failed++;
        continue;
      }
      try {
        const result = await importOSVData(vuln);
        if (result === 'inserted') inserted++; else updated++;
      } catch (err) {
        failed++;
        logger.error({ err, path }, 'Failed to import MAL entry');
      }
    }
    if ((i / MAL_FETCH_CHUNK) % 25 === 0) {
      logger.info({ done: Math.min(i + MAL_FETCH_CHUNK, paths.length), of: paths.length, inserted, updated, failed }, 'MAL delta import progress');
    }
  }

  const succeeded = inserted + updated;
  logger.info({ since, files: paths.length, succeeded, failed }, 'MAL delta import completed');
  return { total: paths.length, skipped: 0, succeeded, inserted, updated, failed };
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
  const { severity, cvssScore, cvssVector } = extractOSVSeverityFields(osvData);
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
          // Use OSV value only when NVD value is absent. An existing severity
          // that is not a rating at all ("CVSS_V3", from an earlier version
          // of this importer) counts as absent; GHSA's MODERATE becomes MEDIUM.
          severity: normalizeSeverity(existing.severity) ?? severity,
          // Score and vector travel together, so a score never sits next to
          // a vector it was not computed from.
          ...(existing.cvssScore === null && cvssScore !== null ? { cvssScore, cvssVector } : {}),
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
          cvssVector,
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
        cvssVector,
        summary: osvData.summary ?? null,
        publishedAt,
        modifiedAt,
      },
      update: {
        severity,
        cvssScore,
        cvssVector,
        summary: osvData.summary ?? null,
        modifiedAt,
      },
    });
    masterId = master.id;
  }

  // Clean up orphaned master row when CVE is assigned after initial import.
  // The OSV record may have been linked to an osvId-keyed master (row A);
  // now that a CVE exists, it should link to the cveId-keyed master (row B).
  // Migrate any remaining references from A to B, then delete A.
  if (osvRecord.cveId) {
    const current = await tx.oSVVulnerability.findUnique({
      where: { id: osvRecord.id },
      select: { masterVulnId: true },
    });
    const oldMasterId = current?.masterVulnId;
    if (oldMasterId && oldMasterId !== masterId) {
      const oldMaster = await tx.vulnerability.findUnique({
        where: { id: oldMasterId },
        select: { cveId: true },
      });
      if (oldMaster && !oldMaster.cveId) {
        await tx.oSVVulnerability.updateMany({ where: { masterVulnId: oldMasterId }, data: { masterVulnId: masterId } });
        await tx.advisoryVulnerability.updateMany({ where: { masterVulnId: oldMasterId }, data: { masterVulnId: masterId } });
        await tx.vulnerability.delete({ where: { id: oldMasterId } });
      }
    }
  }

  await tx.oSVVulnerability.update({
    where: { id: osvRecord.id },
    data: { masterVulnId: masterId },
  });
}

// One record is written in one transaction. Prisma's default of 5 s is too short for a Linux
// kernel CVE, which Ubuntu lists against thousands of package rows: those records failed with
// P2028 on every run, so they were never imported.
const OSV_IMPORT_TRANSACTION_TIMEOUT_MS = 60_000;

/**
 * Convert OSV data to Prisma model and save
 */
export async function importOSVData(osvData: OSVVulnerability): Promise<'inserted' | 'updated'> {
  logger.info({ osvId: osvData.id }, 'Importing OSV vulnerability');

  // Extract CVE ID from aliases, then upstream
  const cveId =
    (osvData.aliases ?? []).find((a: string) => a.startsWith('CVE-')) ??
    (osvData.upstream ?? []).find((u: string) => u.startsWith('CVE-')) ??
    null;

  const { severity, cvssScore } = extractOSVSeverityFields(osvData);
  const recordDistroPriority = extractRecordDistroPriority(osvData);

  try {
    // Save in a transaction
    const result = await prisma.$transaction(async (tx) => {
      const existing = await tx.oSVVulnerability.findUnique({
        where: { osvId: osvData.id },
        select: { id: true },
      });

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
          severity,
          cvssScore,
          distroPriority: recordDistroPriority,
          summary: osvData.summary,
          publishedAt: osvData.published ? new Date(osvData.published) : null,
          modifiedAt: osvData.modified ? new Date(osvData.modified) : null,
        },
        update: {
          cveId,
          aliases: osvData.aliases ?? [],
          rawData: osvData as unknown as Prisma.InputJsonValue,
          packageName: osvData.affected?.[0]?.package?.name,
          severity,
          cvssScore,
          distroPriority: recordDistroPriority,
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

      // Withdrawn records (e.g. duplicates superseded by another advisory) are
      // excluded from search entirely, matching OSV.dev's own reference
      // implementation (it excludes withdrawn records from its search/list
      // results too -- see https://google.github.io/osv.dev/faq/#how-does-osvdev-handle-withdrawn-records).
      // A withdrawn duplicate's own `fixed` event is often missing (folded into
      // the record it duplicates instead), which otherwise leaves an unbounded
      // "introduced, never fixed" range matching every version above it forever
      // -- confirmed live with GHSA-fqj3-h9pc-443h (withdrawn as a duplicate of
      // GHSA-mwf2-3pr3-8698 / CVE-2026-67318) still flagging axios 1.18.1 as
      // vulnerable despite the real fix landing at 1.18.0. The OSVVulnerability
      // row itself (and its rawData) is kept; only the affected-package rows
      // that make it surface in search are skipped.
      if (osvData.withdrawn) {
        logger.info({ osvId: osvData.id, withdrawn: osvData.withdrawn },
          'Skipping affected-package import for withdrawn OSV record');
      } else if (osvData.affected) {
        // Rows are collected across every affected entry and written in one
        // insert below. A record like a Linux kernel advisory emits hundreds
        // of ranges, each of which was previously its own round trip inside
        // this transaction.
        const packageRows: Prisma.OSVAffectedPackageCreateManyInput[] = [];

        for (const affected of osvData.affected) {
          if (!affected.package) continue;

          const ecosystem = affected.package.ecosystem;
          const packageName = affected.package.name;

          // affected.versions: used for exact-match lookups in distro ecosystems
          const affectedVersions: string[] = affected.versions ?? [];
          const distroPriority = extractDistroPriority(affected);

          // Extract version ranges
          if (affected.ranges) {
            for (const range of affected.ranges) {
              if (range.type !== 'SEMVER' && range.type !== 'ECOSYSTEM') continue;

              // OSV events are a state machine: {introduced} → {fixed|last_affected} pairs produce one row
              // Pair events rather than processing each independently to create range rows
              let currentIntroducedVersion: string | undefined = undefined;

              const emitRange = (
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

                packageRows.push({
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
                  distroPriority,
                });
              };

              for (const event of range.events) {
                if (event.introduced !== undefined) {
                  // If a previous introduced is unclosed, emit with no upper bound
                  if (currentIntroducedVersion !== undefined) {
                    emitRange(currentIntroducedVersion, undefined, undefined);
                  }
                  currentIntroducedVersion = event.introduced;
                } else if (event.fixed !== undefined) {
                  emitRange(currentIntroducedVersion, event.fixed, undefined);
                  currentIntroducedVersion = undefined;
                } else if (event.last_affected !== undefined) {
                  emitRange(currentIntroducedVersion, undefined, event.last_affected);
                  currentIntroducedVersion = undefined;
                }
              }

              // After loop: if an unclosed introduced remains, emit with no upper bound
              if (currentIntroducedVersion !== undefined) {
                emitRange(currentIntroducedVersion, undefined, undefined);
              }
            }
          } else if (affectedVersions.length > 0) {
            // No ranges but versions[] present (e.g. MAL ecosystem entries).
            // Store with versionType 'versions' so the search layer can route to exact match.
            packageRows.push({
              vulnerabilityId: vulnerability.id,
              ecosystem,
              packageName,
              versionType: 'versions',
              affectedVersions,
              distroPriority,
            });
          }
        }

        await createManyChunked(packageRows, chunk => tx.oSVAffectedPackage.createMany({ data: chunk }));
      }

      return existing ? 'updated' : 'inserted';
    }, { timeout: OSV_IMPORT_TRANSACTION_TIMEOUT_MS });

    logger.info({ osvId: osvData.id }, 'Successfully imported OSV vulnerability');
    return result;
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
