import axios, { isAxiosError } from 'axios';
import type { AdvisoryFetcher, NormalizedAdvisory } from './advisory-fetcher.js';
import { encodeAdvisoryVersion } from '../utils/advisory-version.js';
import { WORDPRESS_VENDOR, wordpressProductName } from '../utils/wordpress.js';
import { logger } from '../utils/logger.js';

/**
 * Wordfence Intelligence's vulnerability data feed (v3): WordPress core, plugins and themes,
 * keyed by the wordpress.org slug a site's directory is named after.
 *
 * The feed needs an API key of the operator's own (a free wordfence.com account, Integrations),
 * which the terms forbid sharing, so heretix-api ships none: without WORDFENCE_API_KEY the job
 * fails with a message saying so. The key is sent as a bearer token and never logged.
 *
 * Every record carries `copyrights` (Defiant's notice and license, and MITRE's for a CVE). The
 * license asks that a copy keep those notices and a link to the record, so the whole record is
 * kept as rawData and `url` is the record's own page.
 */
export const WORDFENCE_FEED_URL = 'https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production';
export const WORDFENCE_SOURCE = 'advisory-wordfence';
const RECORD_URL = 'https://www.wordfence.com/threat-intel/vulnerabilities/id/';

export interface WordfenceRange {
  from_version: string;
  from_inclusive: boolean;
  to_version: string;
  to_inclusive: boolean;
}

export interface WordfenceSoftware {
  type: string;
  name?: string;
  slug: string;
  affected_versions: Record<string, WordfenceRange>;
  patched: boolean;
  patched_versions: string[];
  remediation?: string;
}

export interface WordfenceRecord {
  id: string;
  title?: string;
  software: WordfenceSoftware[];
  informational?: boolean;
  description?: string;
  references?: string[];
  cvss?: { vector?: string | null; score?: number | null; rating?: string | null } | null;
  cve?: string | null;
  published?: string | null;
  updated?: string | null;
  copyrights?: unknown;
}

const SOFTWARE_TYPES = new Set(['core', 'plugin', 'theme']);

/** A bound as the feed writes it, tidied of the stray dots some records carry ("4.1.1."); null for "*". */
function bound(v: string): string | null {
  const t = v.trim().replace(/\.+$/, '');
  return t === '' || t === '*' ? null : t;
}

const encode = (v: string) => encodeAdvisoryVersion(WORDPRESS_VENDOR, v);

// A bound heretix can compare: dotted numbers, with at most a common pre-release tag
// ("3.0.0-beta.4", "4.0.0-rc15"). Anything else ("44.0 (17-08-2023)", "5.8 beta 1", "1.0f") is
// still turned into a number by normalizeVersion(), but into one that orders it wrongly.
const COMPARABLE = /^\d+(\.\d+)*(-?(alpha|beta|rc|pre)[.-]?\d*)?$/i;
const comparable = (v: string) => COMPARABLE.test(v) && encode(v) !== null;

/**
 * The fix for one range: the lowest patched version at or above its end (above it when the end is
 * included). A record lists one fix per branch it patched ("4.1.34", "4.2.31", ...), so the range
 * takes its own branch's, not the lowest of all.
 */
export function fixForRange(range: WordfenceRange, patched: string[]): string | undefined {
  const end = bound(range.to_version);
  if (end === null || !comparable(end)) return undefined;
  const endInt = encode(end)!;
  let best: { v: string; n: bigint } | undefined;
  for (const p of patched) {
    if (!comparable(p)) continue;
    const n = encode(p)!;
    if (range.to_inclusive ? n <= endInt : n < endInt) continue;
    if (!best || n < best.n) best = { v: p, n };
  }
  return best?.v;
}

/**
 * One affected-product row per range. A range whose bound cannot be compared ("5.8 beta 1",
 * "44.0 (17-08-2023)") is left out rather than kept half open, which would match every version
 * past its other end; `skipped` counts them. The feed's lower bound is always inclusive.
 */
export function wordfenceProducts(sw: WordfenceSoftware): { products: NormalizedAdvisory['affectedProducts']; skipped: number } {
  const product = wordpressProductName(sw.type, sw.slug);
  const products: NormalizedAdvisory['affectedProducts'] = [];
  let skipped = 0;
  for (const range of Object.values(sw.affected_versions ?? {})) {
    const start = bound(range.from_version);
    const end = bound(range.to_version);
    if ((start !== null && !comparable(start)) || (end !== null && !comparable(end))) {
      skipped++;
      continue;
    }
    const versionFixed = fixForRange(range, sw.patched_versions ?? []);
    products.push({
      vendor: WORDPRESS_VENDOR,
      product,
      ...(start !== null && { versionStart: start }),
      ...(end !== null && (range.to_inclusive ? { lastAffected: end } : { versionEnd: end })),
      ...(versionFixed && { versionFixed }),
      // The feed says per software, not per range, whether a fix exists. An unpatched range with
      // no end at all ("*" to "*") then has no range data and matches every version, which is
      // what the feed means by it.
      patchAvailable: sw.patched,
    });
  }
  return { products, skipped };
}

const SEVERITIES = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);

/** One feed record as an advisory, or null when it names no software heretix can match. */
export function normalizeWordfenceRecord(rec: WordfenceRecord): { advisory: NormalizedAdvisory | null; skippedRanges: number } {
  let skippedRanges = 0;
  const affectedProducts: NormalizedAdvisory['affectedProducts'] = [];
  for (const sw of rec.software ?? []) {
    if (!SOFTWARE_TYPES.has(sw.type) || !sw.slug) continue;
    const { products, skipped } = wordfenceProducts(sw);
    affectedProducts.push(...products);
    skippedRanges += skipped;
  }
  if (affectedProducts.length === 0) return { advisory: null, skippedRanges };

  const rating = rec.cvss?.rating?.toUpperCase();
  const remediation = [...new Set((rec.software ?? []).map(s => s.remediation).filter((r): r is string => !!r))];
  const advisory: NormalizedAdvisory = {
    externalId: rec.id,
    ...(rec.cve && { cveId: rec.cve }),
    ...(rec.title && { summary: rec.title }),
    ...(rec.description && { description: rec.description }),
    ...(rating && SEVERITIES.has(rating) && { severity: rating }),
    ...(typeof rec.cvss?.score === 'number' && { cvssScore: rec.cvss.score }),
    ...(rec.cvss?.vector && { cvssVector: rec.cvss.vector }),
    url: RECORD_URL + rec.id,
    ...(remediation.length > 0 && { solution: remediation.join('\n') }),
    ...(rec.published && { publishedAt: new Date(rec.published.replace(' ', 'T') + 'Z') }),
    affectedProducts,
    rawData: rec,
  };
  return { advisory, skippedRanges };
}

/** The feed's root is an object keyed by record id. */
export function normalizeWordfenceFeed(feed: Record<string, WordfenceRecord>): { advisories: NormalizedAdvisory[]; skippedRanges: number; skippedRecords: number } {
  const advisories: NormalizedAdvisory[] = [];
  let skippedRanges = 0;
  let skippedRecords = 0;
  for (const rec of Object.values(feed)) {
    const { advisory, skippedRanges: s } = normalizeWordfenceRecord(rec);
    skippedRanges += s;
    if (advisory) advisories.push(advisory);
    else skippedRecords++;
  }
  return { advisories, skippedRanges, skippedRecords };
}

/** What a failed request says, without the request itself (whose headers hold the key). */
function describeFailure(err: unknown): string {
  if (isAxiosError(err)) {
    const status = err.response?.status;
    if (status === 401 || status === 403) return `the feed refused the API key (HTTP ${status}): check WORDFENCE_API_KEY`;
    if (status === 429) return 'the feed is rate limiting this key (HTTP 429): try again later';
    return status ? `HTTP ${status}` : (err.code ?? err.message);
  }
  return err instanceof Error ? err.message : String(err);
}

export class WordfenceFetcher implements AdvisoryFetcher {
  constructor(private readonly apiKey: string | undefined = process.env.WORDFENCE_API_KEY) {}

  source(): string { return WORDFENCE_SOURCE; }
  isCompleteSnapshot(): boolean { return true; }

  async fetch(): Promise<NormalizedAdvisory[]> {
    const key = this.apiKey?.trim();
    if (!key) {
      throw new Error('WORDFENCE_API_KEY is not set. The Wordfence feed needs a free API key of your own (wordfence.com, Account > Integrations)');
    }

    logger.info('Fetching the Wordfence Intelligence vulnerability feed');
    let feed: Record<string, WordfenceRecord> | undefined;
    let failure = '';
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        const { data } = await axios.get<Record<string, WordfenceRecord>>(WORDFENCE_FEED_URL, {
          timeout: 300_000,
          headers: { Authorization: `Bearer ${key}`, 'User-Agent': 'heretix-api/1.0' },
          responseType: 'json',
          maxContentLength: Infinity,
          maxBodyLength: Infinity,
        });
        feed = data;
        break;
      } catch (err) {
        failure = describeFailure(err);
        const status = isAxiosError(err) ? err.response?.status : undefined;
        // A refused key does not get better by asking again.
        if (status === 401 || status === 403 || attempt === 3) break;
        const wait = 10_000 * attempt;
        logger.warn({ attempt, wait, failure }, 'Wordfence feed fetch failed, retrying');
        await new Promise(r => setTimeout(r, wait));
      }
    }
    if (!feed || typeof feed !== 'object') throw new Error(`Wordfence feed: ${failure || 'no data'}`);

    const { advisories, skippedRanges, skippedRecords } = normalizeWordfenceFeed(feed);
    // Ranges that cannot be compared are a property of the data, not a failed fetch: logged only.
    logger.info({ total: advisories.length, skippedRanges, skippedRecords }, 'Wordfence feed fetch complete');
    return advisories;
  }
}
