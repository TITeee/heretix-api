import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { prisma } from '../../db/client.js';
import { normalizeVersion } from '../../utils/version.js';
import { parseCPE } from '../../utils/cpe.js';
import { expandProductAliases } from '../../config/product-aliases.js';
import {
  type VulnerabilityResult,
  dedup,
  versionRangeWhere,
  isDistroEcosystem,
  isDpkgStyleDistro,
  isRpmStyleOsvDistro,
  isLanguageEcosystem,
  normalizeEcosystem,
  rpmAdvisoryVendor,
  matchesDpkgStyleVersion,
  matchesRpmStyleOsvVersion,
  matchesRpmVersionRange,
  buildAliases,
  DISTRO_ECOSYSTEM_PREFIXES,
  RPM_ADVISORY_VENDOR_PREFIXES,
} from '../../utils/search-helpers.js';

const searchSchema = z.object({
  package: z.string().min(1),
  version: z.string().optional(),
  ecosystem: z.string().min(1).optional(),
  severity: z.array(z.string()).optional(),
  limit: z.coerce.number().int().positive().max(500).default(500),
  offset: z.coerce.number().int().nonnegative().default(0),
});

const batchSearchSchema = z.object({
  packages: z.array(z.object({
    package: z.string().min(1),
    version: z.string().min(1),
    ecosystem: z.string().min(1).optional(),
  })).min(1).max(1000),
});

// Fields to select from the master table
const masterSelect = {
  id: true,
  cveId: true,
  osvId: true,
  advisoryId: true,
  severity: true,
  cvssScore: true,
  cvssVector: true,
  summary: true,
  publishedAt: true,
  isKev: true,
  epssScore: true,
  epssPercentile: true,
} as const;

// Convert master row → VulnerabilityResult
function masterToResult(
  master: {
    id: string;
    cveId: string | null;
    osvId: string | null;
    advisoryId: string | null;
    severity: string | null;
    cvssScore: number | null;
    cvssVector: string | null;
    summary: string | null;
    publishedAt: Date | null;
    isKev: boolean;
    epssScore: number | null;
    epssPercentile: number | null;
  },
  approximateMatch: boolean,
  hitSource: string,
  fixedVersion: string | null = null,
  // The id the matching source row carries itself. Unlike externalId it never
  // changes, so it is what lets a consumer follow this finding across a CVE
  // assignment (see VulnerabilityResult.aliases).
  sourceOwnId: string | null = null,
): VulnerabilityResult {
  const primarySource = master.cveId ? 'nvd' : master.osvId ? 'osv' : 'advisory';
  return {
    id: master.id,
    externalId: master.cveId ?? master.osvId ?? master.advisoryId ?? '',
    source: primarySource,
    sources: [hitSource],
    severity: master.severity,
    cvssScore: master.cvssScore,
    cvssVector: master.cvssVector,
    summary: master.summary,
    publishedAt: master.publishedAt,
    approximateMatch,
    isKev: master.isKev,
    epssScore: master.epssScore,
    epssPercentile: master.epssPercentile,
    fixedVersion,
    aliases: buildAliases(master, sourceOwnId),
  };
}

// ─── Search Functions ─────────────────────────────────────────

/**
 * Debian builds many binary packages from one source package (e.g. source
 * "gnupg2" -> binaries "gpgv"/"gpg"/"gpgsm"/...). OSVAffectedPackage.packageName
 * for Debian ecosystems is keyed by source name, but a queried packageName is
 * whatever name is actually installed -- usually the binary name. Resolves it
 * to the source name via DebianSourcePackage (populated by
 * debian-sources-fetcher.ts) so both names can be searched; returns null when
 * there's no mapping (not a Debian ecosystem, or the name already is the
 * source name, or the mapping hasn't been imported).
 */
async function resolveDebianSourceName(ecosystem: string, packageName: string): Promise<string | null> {
  if (!ecosystem.startsWith('Debian:')) return null;
  const row = await prisma.debianSourcePackage.findUnique({
    where: { ecosystem_binaryName: { ecosystem, binaryName: packageName } },
    select: { sourceName: true },
  });
  return row?.sourceName ?? null;
}

/** Search master via OSV table */
async function searchOSV(
  packageName: string,
  version: string | undefined,
  versionInt: bigint | null,
  ecosystem: string | undefined,
): Promise<VulnerabilityResult[]> {
  const isDistro = ecosystem ? isDistroEcosystem(ecosystem) : false;
  const useDpkgRangeFallback = !!(ecosystem && version && isDpkgStyleDistro(ecosystem));
  const useRpmRangeFallback = !!(ecosystem && version && isRpmStyleOsvDistro(ecosystem));
  const debianSourceName = ecosystem ? await resolveDebianSourceName(ecosystem, packageName) : null;
  const packageNameFilter = debianSourceName ? { in: [packageName, debianSourceName] } : packageName;

  const ecosystemFilter = ecosystem
    ? { ecosystem: { startsWith: ecosystem } }
    : { NOT: { OR: DISTRO_ECOSYSTEM_PREFIXES.map(p => ({ ecosystem: { startsWith: p } })) } };

  // distro ecosystem: exact match against the versions field
  // upstream ecosystem: semver range comparison (as before)
  let versionFilter: object;
  let approximate: boolean;
  if (isDistro) {
    approximate = false;
    // When a range fallback applies (dpkg- or RPM-style), the DB-level filter
    // is dropped entirely (fetch by ecosystem+package only, then filter in JS
    // below) — an exact-match-only DB filter would incorrectly exclude rows
    // that only match via range.
    versionFilter = version && !useDpkgRangeFallback && !useRpmRangeFallback
      ? { affectedVersions: { has: version } }
      : {};
  } else {
    approximate = versionInt === null;
    if (versionInt !== null) {
      versionFilter = {
        OR: [
          // Standard semver/ecosystem entries: range comparison (preserves existing behaviour)
          { versionType: { not: 'versions' }, ...versionRangeWhere(versionInt) },
          // Versions-only entries (MAL etc.): exact match against the versions list
          { versionType: 'versions', affectedVersions: { has: version } },
        ],
      };
    } else {
      versionFilter = {};
    }
  }

  const rows = await prisma.oSVAffectedPackage.findMany({
    where: { ...ecosystemFilter, packageName: packageNameFilter, ...versionFilter },
    include: {
      vulnerability: {
        select: {
          masterVulnId: true,
          masterVuln: { select: masterSelect },
          // fallback when masterVuln is null
          id: true,
          osvId: true,
          cveId: true,
          severity: true,
          cvssScore: true,
          summary: true,
          publishedAt: true,
        },
      },
    },
  });

  const filteredRows = useDpkgRangeFallback
    ? rows.filter(r => matchesDpkgStyleVersion(r, version!))
    : useRpmRangeFallback
      ? rows.filter(r => matchesRpmStyleOsvVersion(r, version!))
      : rows;

  return filteredRows.map(r => {
    const v = r.vulnerability;
    if (v.masterVuln) {
      return masterToResult(v.masterVuln, approximate, 'osv', r.fixedVersion ?? null, v.osvId);
    }
    // Fallback before backfill
    return {
      id: v.id,
      externalId: v.osvId,
      source: 'osv',
      sources: ['osv'],
      severity: v.severity,
      cvssScore: v.cvssScore,
      cvssVector: null,
      summary: v.summary,
      publishedAt: v.publishedAt,
      approximateMatch: approximate,
      isKev: false,
      epssScore: null,
      epssPercentile: null,
      fixedVersion: r.fixedVersion ?? null,
      aliases: buildAliases({ cveId: v.cveId }, v.osvId),
    };
  });
}

/** Search master via NVD table */
async function searchNVD(
  packageName: string,
  version: string | undefined,
  versionInt: bigint | null,
  ecosystem: string | undefined,
): Promise<VulnerabilityResult[]> {
  const ecosystemFilter = ecosystem ? { ecosystem: { startsWith: ecosystem } } : {};
  const approximate = versionInt === null;
  // Rows with `exactVersion` set carry a real, specific CPE version (e.g. Huawei's
  // "v200r007c00spcb00", a Jenkins plugin build id) that normalizeVersion() can't
  // range-encode -- introducedInt/fixedInt/lastAffectedInt are all null for them,
  // the same shape a genuine CPE wildcard ("*"/"-", intentionally unbounded) has.
  // Without excluding them from the range branch, they'd match *every* queried
  // version exactly like a real wildcard does. Route them to exact string
  // equality instead so only a query for that same specific version finds them.
  const versionFilter = versionInt !== null
    ? { OR: [{ exactVersion: null, ...versionRangeWhere(versionInt) }, { exactVersion: version }] }
    : {};

  const packageNames = expandProductAliases(packageName);
  const rows = await prisma.nVDAffectedPackage.findMany({
    where: { ...ecosystemFilter, packageName: { in: packageNames }, ...versionFilter },
    include: {
      vulnerability: {
        select: {
          masterVulnId: true,
          masterVuln: { select: masterSelect },
          id: true,
          cveId: true,
          severity: true,
          cvssScore: true,
          summary: true,
          publishedAt: true,
        },
      },
    },
  });

  return rows.map(r => {
    const v = r.vulnerability;
    const fixedVersion = r.versionEndExcluding ?? null;
    if (v.masterVuln) {
      return masterToResult(v.masterVuln, approximate, 'nvd', fixedVersion, v.cveId);
    }
    // Fallback before backfill
    return {
      id: v.id,
      externalId: v.cveId,
      source: 'nvd',
      sources: ['nvd'],
      severity: v.severity,
      cvssScore: v.cvssScore,
      cvssVector: null,
      summary: v.summary,
      publishedAt: v.publishedAt,
      approximateMatch: approximate,
      isKev: false,
      epssScore: null,
      epssPercentile: null,
      fixedVersion,
      aliases: buildAliases({ cveId: v.cveId }),
    };
  });
}

/**
 * Matches a row with `patchAvailable: false` (confirmed unfixed, e.g. from
 * RedHatVexFetcher's Red Hat CSAF VEX ingestion) and no range or list data of
 * any kind — the only case where "unconditional match" is actually correct,
 * since there's nothing to compare the queried version against. A vendor that
 * reports patchAvailable: false *alongside* a real versionStart/versionEnd
 * (e.g. "still open somewhere in this bounded range") must keep going through
 * the ordinary range guard instead, or it would match every version rather
 * than just the ones the bound actually covers.
 */
const UNFIXED_NO_RANGE_WHERE = {
  patchAvailable: false,
  versionStartInt: null,
  versionEndInt: null,
  lastAffectedInt: null,
  affectedVersions: { isEmpty: true },
} as const;

/**
 * Search master via Advisory table (product + version).
 *
 * Excludes RPM module-stream rows (versionEnd containing ".module+") — RHEL/
 * Oracle Linux's OVAL data for module-stream software (postgresql, nodejs,
 * mariadb, php, ruby, redis, podman, qemu-kvm, libvirt, etc., which ship
 * several parallel version streams under one product name) expresses only an
 * exclusive upper bound with no lower bound, so a newer stream's fix version
 * numerically swallows unrelated, older stream queries. Non-module RPM rows
 * (the vast majority — single version lineage) are unaffected and stay
 * visible here; only ecosystem-explicit searchAdvisoryRpm() sees module rows,
 * and it has the same missing-lower-bound gap (not fixed here — see git log).
 */
async function searchAdvisory(
  product: string,
  version: string | undefined,
): Promise<VulnerabilityResult[]> {
  const versionInt = version ? normalizeVersion(version) : null;
  const approximate = version !== undefined && versionInt === null;

  // Version range filter (range OR individual version list OR confirmed-unfixed)
  let versionWhere = {};
  if (versionInt !== null) {
    versionWhere = {
      OR: [
        {
          AND: [
            // Guard: only apply range matching when the row actually carries some range
            // info. Rows with versionStartInt/versionEndInt/lastAffectedInt all null (i.e.
            // affectedVersions-only entries, no range data at all) must be matched solely via
            // the affectedVersions/patchAvailable branches below — otherwise every
            // null-fallback in this block resolves to true and the row incorrectly
            // matches every version.
            {
              OR: [
                { versionStartInt: { not: null } },
                { versionEndInt: { not: null } },
                { lastAffectedInt: { not: null } },
              ],
            },
            { OR: [{ versionStartInt: { lte: versionInt } }, { versionStartInt: null }] },
            {
              OR: [
                { versionEndInt: { gt: versionInt } },
                {
                  versionEndInt: null,
                  OR: [{ lastAffectedInt: null }, { lastAffectedInt: { gte: versionInt } }],
                },
              ],
            },
          ],
        },
        { affectedVersions: { has: version } },
        // Confirmed unfixed (patchAvailable: false) with no range data at all —
        // matches unconditionally, since there is nothing to compare against.
        // Scoped to rows with no range/list data so a *bounded* unfixed range
        // (e.g. Broadcom's versionStart/versionEnd with patchAvailable: false)
        // still goes through the range guard above instead of matching every
        // version.
        UNFIXED_NO_RANGE_WHERE,
      ],
    };
  } else if (version !== undefined) {
    // Could not convert to semver: match individual version list, or a confirmed-unfixed row.
    versionWhere = { OR: [{ affectedVersions: { has: version } }, UNFIXED_NO_RANGE_WHERE] };
  }

  const rows = await prisma.advisoryAffectedProduct.findMany({
    where: {
      product: { in: expandProductAliases(product) },
      // RPM-vendor rows (RedHatFetcher/OracleLinuxFetcher OVAL, RedHatVexFetcher)
      // are reachable only through searchAdvisoryRpm() via an explicit RHEL/Oracle
      // Linux ecosystem -- see RPM_ADVISORY_VENDOR_PREFIXES's doc comment for why
      // leaking them through this vendor-blind product-name search is unsafe.
      NOT: { OR: RPM_ADVISORY_VENDOR_PREFIXES.map(p => ({ vendor: { startsWith: p } })) },
      AND: [
        versionWhere,
        { OR: [{ versionEnd: null }, { versionEnd: { not: { contains: '.module+' } } }] },
      ],
    },
    include: {
      advisory: {
        select: {
          id: true,
          source: true,
          externalId: true,
          cveId: true,
          severity: true,
          cvssScore: true,
          cvssVector: true,
          summary: true,
          publishedAt: true,
          masterVuln: { select: masterSelect },
        },
      },
    },
  });

  return rows.map(r => {
    const adv = r.advisory;
    const fixedVersion = r.versionFixed ?? null;
    if (adv.masterVuln) {
      return masterToResult(adv.masterVuln, version === undefined || approximate, adv.source, fixedVersion, adv.externalId);
    }
    return {
      id: adv.id,
      externalId: adv.externalId,
      source: adv.source,
      sources: [adv.source],
      severity: adv.severity,
      cvssScore: adv.cvssScore,
      cvssVector: adv.cvssVector,
      summary: adv.summary,
      publishedAt: adv.publishedAt,
      approximateMatch: version === undefined || approximate,
      isKev: false,
      epssScore: null,
      epssPercentile: null,
      fixedVersion,
      aliases: buildAliases({ cveId: adv.cveId }, adv.externalId),
    };
  });
}

/** Search Advisory table for RPM-based distros using rpmvercmp */
async function searchAdvisoryRpm(
  product: string,
  version: string | undefined,
  vendor: string,
): Promise<VulnerabilityResult[]> {
  const rows = await prisma.advisoryAffectedProduct.findMany({
    where: { product, vendor },
    include: {
      advisory: {
        select: {
          id: true,
          source: true,
          externalId: true,
          cveId: true,
          severity: true,
          cvssScore: true,
          cvssVector: true,
          summary: true,
          publishedAt: true,
          masterVuln: { select: masterSelect },
        },
      },
    },
  });

  const filtered = version
    ? rows.filter(r => matchesRpmVersionRange(r, version))
    : rows;
  const approximate = version === undefined;

  return filtered.map(r => {
    const adv = r.advisory;
    const fixedVersion = r.versionEnd ?? r.versionFixed ?? null;
    if (adv.masterVuln) {
      return masterToResult(adv.masterVuln, approximate, adv.source, fixedVersion, adv.externalId);
    }
    return {
      id: adv.id,
      externalId: adv.externalId,
      source: adv.source,
      sources: [adv.source],
      severity: adv.severity,
      cvssScore: adv.cvssScore,
      cvssVector: adv.cvssVector,
      summary: adv.summary,
      publishedAt: adv.publishedAt,
      approximateMatch: approximate,
      isKev: false,
      epssScore: null,
      epssPercentile: null,
      fixedVersion,
      aliases: buildAliases({ cveId: adv.cveId }, adv.externalId),
    };
  });
}

/** Search NVD table by CPE */
async function searchByCPE(
  vendor: string,
  product: string,
  version: string | null,
  limit: number,
  offset: number,
): Promise<VulnerabilityResult[]> {
  const versionInt = version ? normalizeVersion(version) : null;
  const approximate = version !== null && versionInt === null;
  const versionFilter = versionInt !== null ? versionRangeWhere(versionInt) : {};

  const productNames = expandProductAliases(product);
  const rows = await prisma.nVDAffectedPackage.findMany({
    where: { vendor, packageName: { in: productNames }, ...versionFilter },
    include: {
      vulnerability: {
        select: {
          masterVulnId: true,
          masterVuln: { select: masterSelect },
          id: true,
          cveId: true,
          severity: true,
          cvssScore: true,
          summary: true,
          publishedAt: true,
        },
      },
    },
    take: limit,
    skip: offset,
  });

  const noVersionSpecified = version === null;

  return rows.map(r => {
    const v = r.vulnerability;
    const fixedVersion = r.versionEndExcluding ?? null;
    if (v.masterVuln) {
      return masterToResult(v.masterVuln, noVersionSpecified || approximate, 'nvd', fixedVersion, v.cveId);
    }
    return {
      id: v.id,
      externalId: v.cveId,
      source: 'nvd',
      sources: ['nvd'],
      severity: v.severity,
      cvssScore: v.cvssScore,
      cvssVector: null,
      summary: v.summary,
      publishedAt: v.publishedAt,
      approximateMatch: noVersionSpecified || approximate,
      isKev: false,
      epssScore: null,
      epssPercentile: null,
      fixedVersion,
      aliases: buildAliases({ cveId: v.cveId }),
    };
  });
}

/** Search OSV + NVD in parallel and deduplicate by master ID */
async function searchVulnerabilities(
  packageName: string,
  version: string | undefined,
  ecosystem: string | undefined,
  limit = 50,
  offset = 0,
): Promise<VulnerabilityResult[]> {
  ecosystem = normalizeEcosystem(ecosystem);
  const versionInt = version ? normalizeVersion(version) : null;
  const isDistro = ecosystem ? isDistroEcosystem(ecosystem) : false;
  // Language ecosystems (npm, PyPI, Go …) are fully covered by OSV.
  // Querying NVD/Advisory for these would surface C-library or OS CVEs that share
  // the same package name (e.g. C bzip2 → npm bzip2 false positive).
  const isLanguage = ecosystem ? isLanguageEcosystem(ecosystem) : false;

  const rpmVendor = ecosystem ? rpmAdvisoryVendor(ecosystem) : null;

  const [osvResults, nvdResults, advisoryResults] = await Promise.all([
    searchOSV(packageName, version, versionInt, ecosystem),
    isDistro || isLanguage ? Promise.resolve([]) : searchNVD(packageName, version, versionInt, ecosystem),
    rpmVendor
      ? searchAdvisoryRpm(packageName, version, rpmVendor)
      : (isDistro || isLanguage ? Promise.resolve([]) : searchAdvisory(packageName, version)),
  ]);

  const all = dedup([...osvResults, ...nvdResults, ...advisoryResults]);
  return all.slice(offset, offset + limit);
}

const cpeSearchSchema = z.object({
  cpe: z.string().min(1),
  limit: z.coerce.number().int().positive().max(100).default(50),
  offset: z.coerce.number().int().nonnegative().default(0),
});

const suggestSchema = z.object({
  q: z.string().min(1),
  ecosystem: z.string().optional(),
  limit: z.coerce.number().int().positive().max(50).default(10),
});

const cpeForCveSchema = z.object({
  product: z.string().min(1),
});

/**
 * Package-name autocomplete for the "Package" search mode. NVD's packageName
 * is the raw CPE <product> identifier ("http_server", not "Apache HTTP
 * Server"), which a user can't reasonably guess up front — this lets the UI
 * suggest real names as they type instead of requiring that lookup elsewhere.
 * Covers NVD and OSV only (not AdvisoryAffectedProduct): those vendor products
 * already have their own curated dropdown in the "Advisory" search mode.
 */
async function suggestPackageNames(prefix: string, ecosystem: string | undefined, limit: number): Promise<string[]> {
  const ecosystemFilter = ecosystem ? { ecosystem: { startsWith: ecosystem } } : {};
  // Case-sensitive startsWith (no `mode: 'insensitive'`), consistent with every
  // other prefix filter in this file — Postgres can use the existing
  // packageName B-tree index for this; ILIKE could not without a separate
  // case-insensitive index.
  const where = { packageName: { startsWith: prefix }, ...ecosystemFilter };

  const [nvdRows, osvRows] = await Promise.all([
    prisma.nVDAffectedPackage.findMany({
      where, distinct: ['packageName'], select: { packageName: true }, take: limit, orderBy: { packageName: 'asc' },
    }),
    prisma.oSVAffectedPackage.findMany({
      where, distinct: ['packageName'], select: { packageName: true }, take: limit, orderBy: { packageName: 'asc' },
    }),
  ]);

  const names = new Set<string>();
  for (const r of nvdRows) names.add(r.packageName);
  for (const r of osvRows) names.add(r.packageName);
  return [...names].sort((a, b) => a.localeCompare(b)).slice(0, limit);
}

// NVD's <product> CPE token is lowercase/underscore ("firepower_management_center"),
// while a vendor advisory page spells the same product with spaces/parens
// ("Firepower Management Center") — this covers the mechanical part of that gap.
// Anything that needs more than mechanical normalization (renames, multiple
// historical spellings) belongs in PRODUCT_ALIASES instead of guessed here.
function candidateProductTokens(product: string): string[] {
  const lower = product.toLowerCase();
  const mechanical = lower.replace(/[\s/-]+/g, '_').replace(/[^a-z0-9_]/g, '');
  return [...new Set([...expandProductAliases(product), mechanical, lower])];
}

/**
 * Reverse-resolves a CVE + a vendor-bulletin product label (e.g. "PAN-OS") to
 * the CPE vendor:product NVD's own analysts already assigned to that specific
 * CVE, instead of maintaining a separate static product→CPE table — such a
 * table can't be verified without hand-checking every entry against the NVD
 * CPE dictionary, and would still drift as NVD's own naming does (e.g. legacy
 * "dell:sonicwall_sonicos" vs current "sonicwall:sonicos" for the same product).
 *
 * A CVE from a shared component can carry CPEs for multiple, unrelated vendors
 * (observed in ~34% of advisory-linked CVEs) — so this narrows to the caller's
 * own product label rather than returning an arbitrary row, and returns nothing
 * if that label still resolves to more than one distinct vendor:product pairing.
 */
async function findCpeForCve(cveId: string, product: string): Promise<{ cpe: string; vendor: string; product: string } | null> {
  const vuln = await prisma.nVDVulnerability.findUnique({ where: { cveId }, select: { id: true } });
  if (!vuln) return null;

  const rows = await prisma.nVDAffectedPackage.findMany({
    where: { vulnerabilityId: vuln.id },
    select: { cpe: true, vendor: true, packageName: true },
  });

  const candidates = new Set(candidateProductTokens(product));
  const matched = rows.filter((r): r is typeof r & { vendor: string } => !!r.vendor && candidates.has(r.packageName));

  const distinct = new Map(matched.map(r => [`${r.vendor}:${r.packageName}`, r]));
  if (distinct.size !== 1) return null;

  const row = [...distinct.values()][0];
  const parsed = row.cpe ? parseCPE(row.cpe) : null;
  return {
    cpe: `cpe:2.3:${parsed?.part ?? 'a'}:${row.vendor}:${row.packageName}:*:*:*:*:*:*:*:*`,
    vendor: row.vendor,
    product: row.packageName,
  };
}

export default async function vulnerabilitiesRoute(fastify: FastifyInstance) {
  fastify.get('/vulnerabilities/suggest', async (request) => {
    const params = suggestSchema.parse(request.query);
    const suggestions = await suggestPackageNames(params.q, params.ecosystem, params.limit);
    return { suggestions };
  });

  fastify.get('/vulnerabilities/:id/cpe', async (request, reply) => {
    const { id } = request.params as { id: string };
    const { product } = cpeForCveSchema.parse(request.query);
    const result = await findCpeForCve(id, product);
    if (!result) return reply.status(404).send({ error: 'No matching CPE found for this CVE and product' });
    return result;
  });

  fastify.get('/vulnerabilities/search/cpe', async (request, reply) => {
    const params = cpeSearchSchema.parse(request.query);
    const parsed = parseCPE(params.cpe);
    if (!parsed) {
      return reply.status(400).send({ error: 'Invalid CPE string. Expected format: cpe:2.3:a:<vendor>:<product>:<version>:...' });
    }
    const results = await searchByCPE(
      parsed.vendor, parsed.product, parsed.version,
      params.limit, params.offset,
    );
    return { cpe: params.cpe, parsed: { vendor: parsed.vendor, product: parsed.product, version: parsed.version }, results };
  });

  fastify.get('/vulnerabilities/search', async (request) => {
    const params = searchSchema.parse(request.query);
    const results = await searchVulnerabilities(
      params.package, params.version, params.ecosystem,
      params.limit, params.offset,
    );
    return { results };
  });

  fastify.post('/vulnerabilities/search/batch', async (request) => {
    const { packages } = batchSearchSchema.parse(request.body);

    // Promise.all over all packages would issue up to 1000×3=3,000 concurrent DB queries and exhaust the pool.
    // Process in chunks of BATCH_CONCURRENCY to cap concurrency.
    const BATCH_CONCURRENCY = 20;
    const results = [];
    for (let i = 0; i < packages.length; i += BATCH_CONCURRENCY) {
      const chunk = packages.slice(i, i + BATCH_CONCURRENCY);
      results.push(
        ...await Promise.all(
          chunk.map(async (pkg) => {
            const vulnerabilities = await searchVulnerabilities(
              pkg.package, pkg.version, pkg.ecosystem, 500,
            );
            return {
              package: pkg.package,
              version: pkg.version,
              ecosystem: pkg.ecosystem,
              vulnerabilities,
            };
          }),
        ),
      );
    }

    return { results };
  });

  const masterInclude = {
    nvdVulnerability: { include: { affectedPackages: true } },
    osvVulnerabilities: { include: { affectedPackages: true } },
    advisoryVulnerabilities: { include: { affectedProducts: true } },
  } as const;

  fastify.get('/vulnerabilities/:id', async (request, reply) => {
    const { id } = request.params as { id: string };

    // Search master table by canonicalId (cveId, osvId, or advisoryId)
    const master = await prisma.vulnerability.findFirst({
      where: { OR: [{ cveId: id }, { osvId: id }, { advisoryId: id }] },
      include: masterInclude,
    });
    if (master) return master;

    // Not found directly on a master row: id may be one a finding used to be
    // reported by, whose master has since been merged into a later CVE-keyed one
    // (see importAdvisoryData / upsertMasterFromOSV). The source row itself keeps
    // its own id forever even after that merge, so it still resolves — through
    // whichever master it currently points at — once looked up this way.
    const viaAdvisory = await prisma.advisoryVulnerability.findFirst({
      where: { externalId: id },
      select: { masterVuln: { include: masterInclude } },
    });
    if (viaAdvisory?.masterVuln) return viaAdvisory.masterVuln;

    const viaOsv = await prisma.oSVVulnerability.findFirst({
      where: { osvId: id },
      select: { masterVuln: { include: masterInclude } },
    });
    if (viaOsv?.masterVuln) return viaOsv.masterVuln;

    return reply.status(404).send({ error: 'Vulnerability not found' });
  });

  fastify.get('/vulnerabilities/stats', async () => {
    const [total, bySeverity, kevCount, withEpss, osvTotal, nvdTotal, advisoryTotal, advisoryBySrc] = await Promise.all([
      prisma.vulnerability.count(),
      prisma.vulnerability.groupBy({ by: ['severity'], _count: true }),
      prisma.vulnerability.count({ where: { isKev: true } }),
      prisma.vulnerability.count({ where: { epssScore: { not: null } } }),
      prisma.oSVVulnerability.count(),
      prisma.nVDVulnerability.count(),
      prisma.advisoryVulnerability.count(),
      prisma.advisoryVulnerability.groupBy({ by: ['source'], _count: true }),
    ]);

    return {
      total,
      bySeverity,
      kevCount,
      withEpss,
      bySource: {
        osv: osvTotal,
        nvd: nvdTotal,
        advisory: advisoryTotal,
        advisoryByVendor: Object.fromEntries(advisoryBySrc.map(r => [r.source, r._count])),
      },
    };
  });
}
