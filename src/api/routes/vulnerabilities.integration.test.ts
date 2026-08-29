import { describe, it, expect, beforeEach, afterAll, beforeAll } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { prisma } from '../../db/client.js';
import { resetDb } from '../../test-utils/db.js';
import { createServer } from '../server.js';

const API_KEY = 'test-api-key'; // matches vitest.integration.config.ts

async function search(app: FastifyInstance, query: string) {
  const res = await app.inject({
    method: 'GET',
    url: `/api/v1/vulnerabilities/search?${query}`,
    headers: { 'x-api-key': API_KEY },
  });
  return { status: res.statusCode, body: res.json() };
}

describe('GET /api/v1/vulnerabilities/search', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = await createServer();
  });

  beforeEach(async () => {
    await resetDb();
  });

  afterAll(async () => {
    await app.close();
    await prisma.$disconnect();
  });

  it('rejects requests without a valid x-api-key', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/v1/vulnerabilities/search?package=lodash&version=4.17.20' });
    expect(res.statusCode).toBe(401);
  });

  it('deduplicates the same CVE seeded across OSV, NVD, and Advisory into one result', async () => {
    // No ecosystem is passed in the query: a language ecosystem (e.g. "npm")
    // would make searchVulnerabilities skip NVD/Advisory entirely (they're
    // known to carry false-positive C-library/OS entries for language
    // packages), which would defeat this test's purpose.
    const master = await prisma.vulnerability.create({
      data: { cveId: 'CVE-2026-5555', severity: 'CRITICAL', cvssScore: 9.8 },
    });

    const osv = await prisma.oSVVulnerability.create({
      data: {
        osvId: 'GHSA-dedup-0001',
        cveId: 'CVE-2026-5555',
        source: 'osv',
        rawData: {},
        masterVulnId: master.id,
      },
    });
    await prisma.oSVAffectedPackage.create({
      data: { vulnerabilityId: osv.id, ecosystem: 'npm', packageName: 'dedup-pkg' },
    });

    const nvd = await prisma.nVDVulnerability.create({
      data: { cveId: 'CVE-2026-5555', source: 'nvd', rawData: {}, masterVulnId: master.id },
    });
    await prisma.nVDAffectedPackage.create({
      data: { vulnerabilityId: nvd.id, cpe: 'cpe:2.3:a:vendor:dedup-pkg:*:*:*:*:*:*:*:*', vendor: 'vendor', packageName: 'dedup-pkg' },
    });

    const advisory = await prisma.advisoryVulnerability.create({
      data: { source: 'fortinet', externalId: 'FG-IR-dedup-0001', cveId: 'CVE-2026-5555', rawData: {}, masterVulnId: master.id },
    });
    await prisma.advisoryAffectedProduct.create({
      data: { advisoryId: advisory.id, vendor: 'fortinet', product: 'dedup-pkg' },
    });

    const { status, body } = await search(app, 'package=dedup-pkg');
    expect(status).toBe(200);
    expect(body.results).toHaveLength(1);
    expect(body.results[0].externalId).toBe('CVE-2026-5555');
    expect(body.results[0].sources.sort()).toEqual(['fortinet', 'nvd', 'osv']);
  });

  it('filters OSV results by version range boundaries (introducedInt/fixedInt)', async () => {
    const master = await prisma.vulnerability.create({ data: { osvId: 'GHSA-range-0001' } });
    const osv = await prisma.oSVVulnerability.create({
      data: { osvId: 'GHSA-range-0001', source: 'osv', rawData: {}, masterVulnId: master.id },
    });
    await prisma.oSVAffectedPackage.create({
      data: {
        vulnerabilityId: osv.id,
        ecosystem: 'npm',
        packageName: 'range-pkg',
        introducedInt: 1000000000n, // 1.0.0
        fixedInt: 2000000000n,      // 2.0.0 (exclusive)
      },
    });

    const inRange = await search(app, 'package=range-pkg&version=1.5.0&ecosystem=npm');
    expect(inRange.body.results).toHaveLength(1);

    const beforeRange = await search(app, 'package=range-pkg&version=0.9.0&ecosystem=npm');
    expect(beforeRange.body.results).toHaveLength(0);

    const atFixedBoundary = await search(app, 'package=range-pkg&version=2.0.0&ecosystem=npm');
    expect(atFixedBoundary.body.results).toHaveLength(0);
  });

  it('resolves a Debian binary package name to its source name via DebianSourcePackage', async () => {
    // OSVAffectedPackage is keyed by the Debian source name ("gnupg2"), but
    // the query below uses the installed binary name ("gpgv") -- the two
    // differ because Debian builds many binaries from one source package.
    const master = await prisma.vulnerability.create({ data: { osvId: 'GHSA-debian-0001' } });
    const osv = await prisma.oSVVulnerability.create({
      data: { osvId: 'GHSA-debian-0001', ecosystem: 'Debian:12', source: 'osv', rawData: {}, masterVulnId: master.id },
    });
    await prisma.oSVAffectedPackage.create({
      data: { vulnerabilityId: osv.id, ecosystem: 'Debian:12', packageName: 'gnupg2', affectedVersions: ['2.2.40-1.1'] },
    });
    await prisma.debianSourcePackage.create({
      data: { ecosystem: 'Debian:12', binaryName: 'gpgv', sourceName: 'gnupg2' },
    });

    const byBinaryName = await search(app, 'package=gpgv&version=2.2.40-1.1&ecosystem=Debian:12');
    expect(byBinaryName.body.results).toHaveLength(1);
    expect(byBinaryName.body.results[0].externalId).toBe('GHSA-debian-0001');

    // The source name itself must still work directly (no mapping needed).
    const bySourceName = await search(app, 'package=gnupg2&version=2.2.40-1.1&ecosystem=Debian:12');
    expect(bySourceName.body.results).toHaveLength(1);

    // An unrelated binary name with no mapping row must not match anything.
    const noMapping = await search(app, 'package=unrelated-binary&version=2.2.40-1.1&ecosystem=Debian:12');
    expect(noMapping.body.results).toHaveLength(0);
  });
});
