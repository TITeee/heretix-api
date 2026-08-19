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
  isLanguageEcosystem,
  normalizeEcosystem,
  rpmAdvisoryVendor,
  matchesDpkgStyleVersion,
  matchesRpmVersionRange,
  buildAliases,
  DISTRO_ECOSYSTEM_PREFIXES,
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

/** Search master via OSV table */
async function searchOSV(
  packageName: string,
  version: string | undefined,
  versionInt: bigint | null,
  ecosystem: string | undefined,
): Promise<VulnerabilityResult[]> {
  const isDistro = ecosystem ? isDistroEcosystem(ecosystem) : false;
  const useDpkgRangeFallback = !!(ecosystem && version && isDpkgStyleDistro(ecosystem));

  const ecosystemFilter = ecosystem
    ? { ecosystem: { startsWith: ecosystem } }
    : { NOT: { OR: DISTRO_ECOSYSTEM_PREFIXES.map(p => ({ ecosystem: { startsWith: p } })) } };

  // distro ecosystem: exact match against the versions field
  // upstream ecosystem: semver range comparison (as before)
  let versionFilter: object;
  let approximate: boolean;
  if (isDistro) {
    approximate = false;
    // When the dpkg range fallback applies, the DB-level filter is dropped
    // entirely (fetch by ecosystem+package only, then filter in JS below) —
    // an exact-match-only DB filter would incorrectly exclude rows that only
    // match via range.
    versionFilter = version && !useDpkgRangeFallback ? { affectedVersions: { has: version } } : {};
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
    where: { ...ecosystemFilter, packageName, ...versionFilter },
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
  versionInt: bigint | null,
  ecosystem: string | undefined,
): Promise<VulnerabilityResult[]> {
  const ecosystemFilter = ecosystem ? { ecosystem: { startsWith: ecosystem } } : {};
  const approximate = versionInt === null;
  const versionFilter = versionInt !== null ? versionRangeWhere(versionInt) : {};

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

  // Version range filter (range OR individual version list)
  let versionWhere = {};
  if (versionInt !== null) {
    versionWhere = {
      OR: [
        {
          AND: [
            // Guard: only apply range matching when the row actually carries some range
            // info. Rows with versionStartInt/versionEndInt/lastAffectedInt all null (i.e.
            // affectedVersions-only entries, no range data at all) must be matched solely via
            // the affectedVersions branch below — otherwise every null-fallback in this block
            // resolves to true and the row incorrectly matches every version.
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
      ],
    };
  } else if (version !== undefined) {
    // Could not convert to semver: match individual version list only
    versionWhere = { affectedVersions: { has: version } };
  }

  const rows = await prisma.advisoryAffectedProduct.findMany({
    where: {
      product,
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
    isDistro || isLanguage ? Promise.resolve([]) : searchNVD(packageName, versionInt, ecosystem),
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

export default async function vulnerabilitiesRoute(fastify: FastifyInstance) {
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
