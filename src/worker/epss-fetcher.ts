import axios from 'axios';
import { logger } from '../utils/logger.js';
import { prisma } from '../db/client.js';

// ─── Type Definitions ─────────────────────────────────────────

interface EPSSEntry {
  cve: string;       // "CVE-YYYY-NNNNN"
  epss: number;      // 0.0–1.0
  percentile: number; // 0.0–1.0
}

const EPSS_API_BASE = 'https://api.first.org/data/v1/epss';

// ─── Fetch ────────────────────────────────────────────────────

/**
 * Fetch the EPSS score for a single CVE
 */
export async function fetchEPSSForCVE(cveId: string): Promise<{ epss: number; percentile: number } | null> {
  const response = await axios.get<{
    data: Array<{ cve: string; epss: string; percentile: string }>;
  }>(EPSS_API_BASE, {
    params: { cve: cveId },
    timeout: 10000,
  });

  const entry = response.data.data?.[0];
  if (!entry) return null;

  return {
    epss: parseFloat(entry.epss),
    percentile: parseFloat(entry.percentile),
  };
}

const EPSS_API_PAGE_SIZE = 10000;

/**
 * Fetch all pages from the FIRST.org EPSS API and return all entries
 * Omitting date uses the latest scores
 */
export async function fetchEPSSBulk(date?: string): Promise<EPSSEntry[]> {
  // When date is omitted, fetch the latest data (omit the date param since today's data may not yet be published)
  logger.info({ date: date ?? 'latest' }, 'Fetching EPSS bulk via FIRST.org API');

  const allEntries: EPSSEntry[] = [];
  let offset = 0;
  let total = Infinity;

  while (offset < total) {
    const params: Record<string, string | number> = { limit: EPSS_API_PAGE_SIZE, offset };
    if (date) params.date = date;

    const response = await axios.get<{
      total: number;
      count: number;
      offset: number;
      data: Array<{ cve: string; epss: string; percentile: string }>;
    }>(EPSS_API_BASE, {
      params,
      timeout: 60000,
    });

    const { data } = response;
    total = data.total;
    const pageItems = data.data ?? [];

    for (const entry of pageItems) {
      const epss = parseFloat(entry.epss);
      const percentile = parseFloat(entry.percentile);
      if (!entry.cve.startsWith('CVE-') || isNaN(epss) || isNaN(percentile)) continue;
      allEntries.push({ cve: entry.cve, epss, percentile });
    }

    offset += pageItems.length;
    logger.info({ offset, total }, 'EPSS page fetched');
  }

  logger.info({ count: allEntries.length, date: date ?? 'latest' }, 'EPSS bulk fetch complete');
  return allEntries;
}

// ─── Import ───────────────────────────────────────────────────

const CHUNK_SIZE = 1000;

/**
 * Apply EPSS entries to the Vulnerability master table
 * Updates in chunks of 1000
 */
export async function importEPSSData(
  entries: EPSSEntry[],
  updatedAt: Date = new Date(),
): Promise<{ updated: number }> {
  let updated = 0;

  for (let i = 0; i < entries.length; i += CHUNK_SIZE) {
    const chunk = entries.slice(i, i + CHUNK_SIZE);

    // Batch update all CVE IDs in this chunk
    const results = await Promise.all(
      chunk.map(entry =>
        prisma.vulnerability.updateMany({
          where: { cveId: entry.cve },
          data: {
            epssScore: entry.epss,
            epssPercentile: entry.percentile,
            epssUpdatedAt: updatedAt,
          },
        }),
      ),
    );

    updated += results.reduce((sum, r) => sum + r.count, 0);

    if (i % 10000 === 0 && i > 0) {
      logger.info({ processed: i, updated }, 'EPSS import progress');
    }
  }

  logger.info({ total: entries.length, updated }, 'EPSS import completed');
  return { updated };
}

/**
 * Fetch the EPSS daily dataset and apply it to the master table
 */
export async function fullImportEPSS(date?: string): Promise<{ updated: number }> {
  const entries = await fetchEPSSBulk(date);
  return importEPSSData(entries);
}
