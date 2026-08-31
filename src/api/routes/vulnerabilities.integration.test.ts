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

describe('GET /api/v1/vulnerabilities/:id/cpe', () => {
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

  async function getCpe(app: FastifyInstance, id: string, product: string) {
    const res = await app.inject({
      method: 'GET',
      url: `/api/v1/vulnerabilities/${encodeURIComponent(id)}/cpe?product=${encodeURIComponent(product)}`,
      headers: { 'x-api-key': API_KEY },
    });
    return { status: res.statusCode, body: res.json() };
  }

  it('resolves a vendor-bulletin product label to its NVD CPE vendor:product', async () => {
    const nvd = await prisma.nVDVulnerability.create({
      data: { cveId: 'CVE-2026-1001', source: 'nvd', rawData: {} },
    });
    await prisma.nVDAffectedPackage.create({
      data: { vulnerabilityId: nvd.id, cpe: 'cpe:2.3:o:paloaltonetworks:pan-os:10.2.7:h1:*:*:*:*:*:*', vendor: 'paloaltonetworks', packageName: 'pan-os' },
    });

    const { status, body } = await getCpe(app, 'CVE-2026-1001', 'PAN-OS');
    expect(status).toBe(200);
    expect(body).toEqual({
      cpe: 'cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*',
      vendor: 'paloaltonetworks',
      product: 'pan-os',
    });
  });

  it('matches a spaced product label against an underscored CPE product token', async () => {
    const nvd = await prisma.nVDVulnerability.create({
      data: { cveId: 'CVE-2026-1002', source: 'nvd', rawData: {} },
    });
    await prisma.nVDAffectedPackage.create({
      data: { vulnerabilityId: nvd.id, cpe: 'cpe:2.3:a:cisco:firepower_management_center:7.2:*:*:*:*:*:*:*', vendor: 'cisco', packageName: 'firepower_management_center' },
    });

    const { status, body } = await getCpe(app, 'CVE-2026-1002', 'Firepower Management Center');
    expect(status).toBe(200);
    expect(body.vendor).toBe('cisco');
    expect(body.product).toBe('firepower_management_center');
  });

  it('picks the vendor the caller asked about when a shared-component CVE spans multiple vendors', async () => {
    const nvd = await prisma.nVDVulnerability.create({
      data: { cveId: 'CVE-2026-1003', source: 'nvd', rawData: {} },
    });
    await prisma.nVDAffectedPackage.create({
      data: { vulnerabilityId: nvd.id, cpe: 'cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*', vendor: 'paloaltonetworks', packageName: 'pan-os' },
    });
    await prisma.nVDAffectedPackage.create({
      data: { vulnerabilityId: nvd.id, cpe: 'cpe:2.3:o:siemens:ruggedcom_ape1808_firmware:-:*:*:*:*:*:*:*', vendor: 'siemens', packageName: 'ruggedcom_ape1808_firmware' },
    });

    const { status, body } = await getCpe(app, 'CVE-2026-1003', 'PAN-OS');
    expect(status).toBe(200);
    expect(body.vendor).toBe('paloaltonetworks');
  });

  it('returns 404 when the CVE has no CPE configuration data at all', async () => {
    await prisma.nVDVulnerability.create({ data: { cveId: 'CVE-2026-1004', source: 'nvd', rawData: {} } });

    const { status } = await getCpe(app, 'CVE-2026-1004', 'PAN-OS');
    expect(status).toBe(404);
  });

  it('returns 404 for an unknown CVE', async () => {
    const { status } = await getCpe(app, 'CVE-2026-9999', 'PAN-OS');
    expect(status).toBe(404);
  });

  it('returns 404 rather than guessing when the product label matches more than one distinct vendor:product', async () => {
    const nvd = await prisma.nVDVulnerability.create({
      data: { cveId: 'CVE-2026-1005', source: 'nvd', rawData: {} },
    });
    // Same product name string, two different vendors — an ambiguous match
    // that must not be resolved arbitrarily.
    await prisma.nVDAffectedPackage.create({
      data: { vulnerabilityId: nvd.id, cpe: 'cpe:2.3:a:vendor-a:ambiguous_tool:*:*:*:*:*:*:*:*', vendor: 'vendor-a', packageName: 'ambiguous_tool' },
    });
    await prisma.nVDAffectedPackage.create({
      data: { vulnerabilityId: nvd.id, cpe: 'cpe:2.3:a:vendor-b:ambiguous_tool:*:*:*:*:*:*:*:*', vendor: 'vendor-b', packageName: 'ambiguous_tool' },
    });

    const { status } = await getCpe(app, 'CVE-2026-1005', 'ambiguous tool');
    expect(status).toBe(404);
  });
});
