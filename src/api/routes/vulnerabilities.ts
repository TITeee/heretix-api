import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { prisma } from '../../db/client.js';
import { normalizeVersion } from '../../utils/version.js';
import { parseCPE } from '../../utils/cpe.js';
import { expandProductAliases } from '../../config/product-aliases.js';

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

type VulnerabilityResult = {
  id: string;               // Vulnerability master ID
  externalId: string;       // cveId or osvId
  source: string;           // backward compat: primary source ("nvd" | "osv" | "advisory" etc.)
  sources: string[];        // list of sources that matched (["nvd", "osv"] etc.)
  severity: string | null;
  cvssScore: number | null;
  cvssVector: string | null;
  summary: string | null;
  publishedAt: Date | null;
  approximateMatch: boolean;
  isKev: boolean;
  epssScore: number | null;
  epssPercentile: number | null;
};

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
  };
}

/** Deduplicate by master ID (merge sources) */
function dedup(items: VulnerabilityResult[]): VulnerabilityResult[] {
  const seen = new Map<string, VulnerabilityResult>();
  for (const item of items) {
    const existing = seen.get(item.id);
    if (existing) {
      for (const s of item.sources) {
        if (!existing.sources.includes(s)) existing.sources.push(s);
      }
    } else {
      seen.set(item.id, { ...item, sources: [...item.sources] });
    }
  }
  return [...seen.values()];
}

// ─── Version Range Filter Conditions ─────────────────────────

function versionRangeWhere(versionInt: bigint) {
  return {
    AND: [
      {
        OR: [
          { introducedInt: { lte: versionInt } },
          { introducedInt: null },
        ],
      },
      {
        OR: [
          { fixedInt: { gt: versionInt } },
          {
            fixedInt: null,
            OR: [
              { lastAffectedInt: null },
              { lastAffectedInt: { gte: versionInt } },
            ],
          },
        ],
      },
    ],
  };
}

// ─── Search Functions ─────────────────────────────────────────

// Prefixes for distro-specific ecosystems.
// These use dpkg/apk version strings and require a different matching strategy
// (exact match against the versions list) instead of upstream semver range comparison.
const DISTRO_ECOSYSTEM_PREFIXES = ['Ubuntu:', 'Debian:', 'Alpine:', 'AlmaLinux:', 'Rocky:', 'Red Hat:'];

function isDistroEcosystem(eco: string): boolean {
  return DISTRO_ECOSYSTEM_PREFIXES.some(p => eco.startsWith(p));
}

/** Search master via OSV table */
async function searchOSV(
  packageName: string,
  version: string | undefined,
  versionInt: bigint | null,
  ecosystem: string | undefined,
): Promise<VulnerabilityResult[]> {
  const isDistro = ecosystem ? isDistroEcosystem(ecosystem) : false;

  const ecosystemFilter = ecosystem
    ? { ecosystem: { startsWith: ecosystem } }
    : { NOT: { OR: DISTRO_ECOSYSTEM_PREFIXES.map(p => ({ ecosystem: { startsWith: p } })) } };

  // distro ecosystem: exact match against the versions field
  // upstream ecosystem: semver range comparison (as before)
  let versionFilter: object;
  let approximate: boolean;
  if (isDistro) {
    approximate = false;
    versionFilter = version ? { affectedVersions: { has: version } } : {};
  } else {
    approximate = versionInt === null;
    versionFilter = versionInt !== null ? versionRangeWhere(versionInt) : {};
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
    if (v.masterVuln) {
      return masterToResult(v.masterVuln, approximate, 'osv');
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
    if (v.masterVuln) {
      return masterToResult(v.masterVuln, approximate, 'nvd');
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
    };
  });
}

/** Search master via Advisory table (product + version) */
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
    where: { product, ...versionWhere },
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
    if (adv.masterVuln) {
      return masterToResult(adv.masterVuln, version === undefined || approximate, adv.source);
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
    if (v.masterVuln) {
      return masterToResult(v.masterVuln, noVersionSpecified || approximate, 'nvd');
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
  const versionInt = version ? normalizeVersion(version) : null;
  const isDistro = ecosystem ? isDistroEcosystem(ecosystem) : false;

  const [osvResults, nvdResults, advisoryResults] = await Promise.all([
    searchOSV(packageName, version, versionInt, ecosystem),
    isDistro ? Promise.resolve([]) : searchNVD(packageName, versionInt, ecosystem),
    searchAdvisory(packageName, version),
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

  fastify.get('/vulnerabilities/:id', async (request, reply) => {
    const { id } = request.params as { id: string };

    // Search master table by canonicalId (cveId or osvId)
    const master = await prisma.vulnerability.findFirst({
      where: { OR: [{ cveId: id }, { osvId: id }, { advisoryId: id }] },
      include: {
        nvdVulnerability: { include: { affectedPackages: true } },
        osvVulnerabilities: { include: { affectedPackages: true } },
        advisoryVulnerabilities: { include: { affectedProducts: true } },
      },
    });
    if (master) return master;

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
