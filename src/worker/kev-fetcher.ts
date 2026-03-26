import axios from 'axios';
import { logger } from '../utils/logger.js';
import { prisma } from '../db/client.js';

// ─── Type Definitions ─────────────────────────────────────────

interface KEVEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;          // "YYYY-MM-DD"
  shortDescription: string;
  requiredAction: string;
  dueDate: string;            // "YYYY-MM-DD"
  knownRansomwareCampaignUse: string;
  notes: string;
}

interface KEVCatalog {
  title: string;
  catalogVersion: string;
  dateReleased: string;
  count: number;
  vulnerabilities: KEVEntry[];
}

const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

// ─── Fetch ────────────────────────────────────────────────────

/**
 * Fetch the CISA KEV catalog
 */
export async function fetchKEVCatalog(): Promise<KEVEntry[]> {
  logger.info({ url: KEV_URL }, 'Fetching CISA KEV catalog');

  const response = await axios.get<KEVCatalog>(KEV_URL, { timeout: 30000 });

  logger.info({ count: response.data.count }, 'KEV catalog fetched');
  return response.data.vulnerabilities;
}

// ─── Import ───────────────────────────────────────────────────

/**
 * Apply the KEV catalog to the Vulnerability master table
 *
 * Strategy:
 * - Reset all existing isKev=true entries, then re-apply from the current catalog (full-replace)
 *   → Handles the rare case where CISA removes a CVE from the catalog
 * - CVE IDs not present in the DB are skipped (logged only)
 */
export async function importKEVData(entries: KEVEntry[]): Promise<{ updated: number; notFound: number }> {
  // 1. Reset existing KEV flags
  await prisma.vulnerability.updateMany({
    where: { isKev: true },
    data: {
      isKev: false,
      kevDateAdded: null,
      kevDueDate: null,
      kevProduct: null,
      kevVendor: null,
      kevShortDesc: null,
      kevRequiredAction: null,
    },
  });

  let updated = 0;
  let notFound = 0;

  // 2. Set KEV flags from the current catalog
  for (const entry of entries) {
    const result = await prisma.vulnerability.updateMany({
      where: { cveId: entry.cveID },
      data: {
        isKev: true,
        kevDateAdded: new Date(entry.dateAdded),
        kevDueDate: entry.dueDate ? new Date(entry.dueDate) : null,
        kevProduct: entry.product,
        kevVendor: entry.vendorProject,
        kevShortDesc: entry.shortDescription,
        kevRequiredAction: entry.requiredAction,
      },
    });

    if (result.count > 0) {
      updated++;
    } else {
      notFound++;
      logger.debug({ cveId: entry.cveID }, 'KEV entry not found in master table (not yet imported)');
    }
  }

  logger.info({ updated, notFound, total: entries.length }, 'KEV import completed');
  return { updated, notFound };
}

/**
 * Fetch and import the KEV catalog
 */
export async function fullImportKEV(): Promise<{ updated: number; notFound: number }> {
  const entries = await fetchKEVCatalog();
  return importKEVData(entries);
}
