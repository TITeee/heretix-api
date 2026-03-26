import axios from 'axios';
import type { AdvisoryFetcher, NormalizedAdvisory } from './advisory-fetcher.js';
import { logger } from '../utils/logger.js';

const TOKEN_URL    = 'https://id.cisco.com/oauth2/default/v1/token';
const OPENVULN_URL = 'https://apix.cisco.com/security/advisories/v2';

// ─── Cisco openVuln API Type Definitions ──────────────────────

interface CiscoAdvisory {
  advisoryId:      string;
  advisoryTitle:   string;
  sir:             string;   // "Critical" | "High" | "Medium" | "Low" | "Informational"
  cvssBaseScore:   string;
  cvssTemporalScore?: string;
  cves:            string[];
  firstPublished:  string;
  lastUpdated:     string;
  summary:         string;
  publicationUrl:  string;
  csafUrl?:        string;
  workarounds?:    string;
  affectedProducts?: string;
}

interface CiscoAdvisoryResponse {
  advisories: CiscoAdvisory[];
  startIndex?:  number;
  count?:       number;
  totalCount?:  number;
}

// ─── CSAF 2.0 Type Definitions (shared structure with PAN) ────

interface CsafDocument {
  document: {
    title: string;
    tracking: { id: string; initial_release_date: string };
  };
  product_tree?: { branches?: CsafBranch[] };
  vulnerabilities: CsafVulnerability[];
}

interface CsafBranch {
  category: string;
  name: string;
  branches?: CsafBranch[];
  product?: { product_id: string; name: string };
}

interface CsafVulnerability {
  cve?: string;
  scores?: Array<{
    products: string[];
    cvss_v3?: { baseScore: number; baseSeverity: string; vectorString: string };
  }>;
  notes?: Array<{ category: string; title?: string; text: string }>;
  product_status?: {
    known_affected?: string[];
    known_not_affected?: string[];
  };
  remediations?: Array<{ category: string; details: string; product_ids?: string[] }>;
  references?: Array<{ url: string; summary: string }>;
}

// ─── OAuth ───────────────────────────────────────────────────

async function fetchAccessToken(clientId: string, clientSecret: string): Promise<string> {
  const params = new URLSearchParams({
    grant_type:    'client_credentials',
    client_id:     clientId,
    client_secret: clientSecret,
  });

  const { data } = await axios.post<{ access_token: string }>(TOKEN_URL, params.toString(), {
    timeout: 15000,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });

  return data.access_token;
}

// ─── CSAF Parsing ─────────────────────────────────────────────

function collectProductNames(branches: CsafBranch[]): Set<string> {
  const names = new Set<string>();
  function walk(bs: CsafBranch[]) {
    for (const b of bs) {
      if (b.product) names.add(b.product.name);
      if (b.branches) walk(b.branches);
    }
  }
  walk(branches);
  return names;
}

function extractProductName(productId: string, knownProducts: Set<string>): string | null {
  const sorted = [...knownProducts].sort((a, b) => b.length - a.length);
  for (const name of sorted) {
    if (productId === name || productId.startsWith(name + ' ') || productId.startsWith(name + '-')) {
      return name;
    }
  }
  return null;
}

function parseCsafAffectedProducts(
  csaf: CsafDocument,
): NormalizedAdvisory['affectedProducts'] {
  const vulns = csaf.vulnerabilities ?? [];
  const knownProducts = collectProductNames(csaf.product_tree?.branches ?? []);
  const results: NormalizedAdvisory['affectedProducts'] = [];
  const seen = new Set<string>();

  for (const v of vulns) {
    const notAffected = v.product_status?.known_not_affected ?? [];
    const fixedVersions: string[] = [];
    for (const pid of notAffected) {
      const name = extractProductName(pid, knownProducts);
      if (name) {
        const ver = pid.slice(name.length).replace(/^[-\s]+/, '').trim();
        if (ver && /^\d/.test(ver)) fixedVersions.push(ver);
      }
    }

    for (const pid of v.product_status?.known_affected ?? []) {
      if (seen.has(pid)) continue;
      seen.add(pid);

      const name = extractProductName(pid, knownProducts);
      if (!name) continue;

      const versionPart = pid.slice(name.length).replace(/^[-\s]+/, '').trim();
      const branch = versionPart.split('.').slice(0, 2).join('.');
      const versionFixed = fixedVersions.find(v => v.startsWith(branch + '.'));

      results.push({
        vendor:       'cisco',
        product:      name,
        versionStart: versionPart || undefined,
        versionFixed,
        patchAvailable: !!versionFixed,
      });
    }
  }

  return results;
}

// ─── Advisory Conversion ──────────────────────────────────────

/** SIR → normalized severity */
function normalizeSir(sir: string): string {
  const s = sir.toLowerCase();
  if (s === 'critical') return 'CRITICAL';
  if (s === 'high')     return 'HIGH';
  if (s === 'medium')   return 'MEDIUM';
  if (s === 'low')      return 'LOW';
  return sir.toUpperCase();
}

async function advisoryToNormalized(
  adv: CiscoAdvisory,
): Promise<NormalizedAdvisory> {
  const base: NormalizedAdvisory = {
    externalId:  adv.advisoryId,
    cveId:       adv.cves?.[0],
    summary:     adv.advisoryTitle,
    description: adv.summary,
    severity:    normalizeSir(adv.sir),
    cvssScore:   adv.cvssBaseScore ? parseFloat(adv.cvssBaseScore) : undefined,
    url:         adv.publicationUrl,
    workaround:  adv.workarounds && adv.workarounds !== 'No workarounds available' ? adv.workarounds : undefined,
    publishedAt: adv.firstPublished ? new Date(adv.firstPublished) : undefined,
    affectedProducts: [],
    rawData:     adv,
  };

  // Fetch detailed product/version info from CSAF
  if (adv.csafUrl) {
    try {
      const { data: csaf } = await axios.get<CsafDocument>(adv.csafUrl, {
        timeout: 15000,
        headers: { 'User-Agent': 'heretix-api/1.0' },
      });

      // Supplement CVSS vector from CSAF
      for (const v of csaf.vulnerabilities ?? []) {
        for (const s of v.scores ?? []) {
          if (s.cvss_v3 && !base.cvssVector) {
            base.cvssVector = s.cvss_v3.vectorString;
          }
        }
      }

      base.affectedProducts = parseCsafAffectedProducts(csaf);
      base.rawData = csaf;
    } catch (err) {
      logger.warn({ err, advisoryId: adv.advisoryId }, 'Failed to fetch Cisco CSAF, using API data only');
    }
  }

  // If no product info could be extracted from CSAF, register with empty affectedProducts
  // (advisoryId is still linked to master)
  if (base.affectedProducts.length === 0 && adv.affectedProducts) {
    // affectedProducts field is plain text and difficult to parse
    // Register only the product name; omit versionStart/End
    base.affectedProducts = [{
      vendor:  'cisco',
      product: 'cisco',
    }];
  }

  return base;
}

// ─── AdvisoryFetcher Implementation ──────────────────────────

export class CiscoFetcher implements AdvisoryFetcher {
  private readonly clientId:     string;
  private readonly clientSecret: string;
  private readonly delayMs:      number;
  private readonly mode:         'all' | 'latest';
  private readonly latestCount:  number;

  constructor({
    clientId     = process.env['CISCO_CLIENT_ID']     ?? '',
    clientSecret = process.env['CISCO_CLIENT_SECRET'] ?? '',
    delayMs      = 500,
    mode         = 'all' as 'all' | 'latest',
    latestCount  = 100,
  }: {
    clientId?:     string;
    clientSecret?: string;
    delayMs?:      number;
    mode?:         'all' | 'latest';
    latestCount?:  number;
  } = {}) {
    this.clientId     = clientId;
    this.clientSecret = clientSecret;
    this.delayMs      = delayMs;
    this.mode         = mode;
    this.latestCount  = latestCount;
  }

  source(): string { return 'cisco'; }

  async fetch(): Promise<NormalizedAdvisory[]> {
    if (!this.clientId || !this.clientSecret) {
      throw new Error('CISCO_CLIENT_ID and CISCO_CLIENT_SECRET are required');
    }

    logger.info({ mode: this.mode }, 'Fetching Cisco PSIRT advisories');

    const token = await fetchAccessToken(this.clientId, this.clientSecret);
    const authHeaders = {
      'Authorization': `Bearer ${token}`,
      'User-Agent':    'heretix-api/1.0',
    };

    // Fetch advisory list
    const endpoint = this.mode === 'latest'
      ? `${OPENVULN_URL}/advisories/latest/${this.latestCount}`
      : `${OPENVULN_URL}/advisories/all`;

    const { data } = await axios.get<CiscoAdvisoryResponse>(endpoint, {
      timeout: 60000,
      headers: authHeaders,
    });

    const advisories = data.advisories ?? [];
    logger.info({ count: advisories.length }, 'Fetched Cisco advisory list');

    const results: NormalizedAdvisory[] = [];
    let failed = 0;

    for (const adv of advisories) {
      try {
        const normalized = await advisoryToNormalized(adv);
        results.push(normalized);
      } catch (err) {
        failed++;
        logger.error({ err, advisoryId: adv.advisoryId }, 'Failed to process Cisco advisory');
      }

      await new Promise(r => setTimeout(r, this.delayMs));
    }

    logger.info(
      { total: advisories.length, succeeded: results.length, failed },
      'Cisco PSIRT fetch complete',
    );
    return results;
  }
}
