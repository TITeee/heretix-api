import { describe, it, expect, beforeEach, afterAll, beforeAll } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { prisma } from '../../db/client.js';
import { resetDb } from '../../test-utils/db.js';
import { createServer } from '../server.js';
import { importAdvisoryData } from '../../worker/advisory-fetcher.js';
import { importOSVData } from '../../worker/osv-fetcher.js';

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

  it('filters by severity, accepting both a single value and repeated values', async () => {
    for (const [id, severity] of [['CVE-2026-6001', 'CRITICAL'], ['CVE-2026-6002', 'HIGH'], ['CVE-2026-6003', 'MEDIUM']] as const) {
      const master = await prisma.vulnerability.create({ data: { cveId: id, severity } });
      const nvd = await prisma.nVDVulnerability.create({
        data: { cveId: id, source: 'nvd', rawData: {}, masterVulnId: master.id },
      });
      await prisma.nVDAffectedPackage.create({
        data: { vulnerabilityId: nvd.id, cpe: `cpe:2.3:a:vendor:severity-pkg:*:*:*:*:*:*:*:*`, vendor: 'vendor', packageName: 'severity-pkg' },
      });
    }

    // A single occurrence (?severity=X) comes through Fastify's query parser
    // as a bare string, not an array -- the schema must still accept it.
    const single = await search(app, 'package=severity-pkg&severity=CRITICAL');
    expect(single.body.results.map((r: { externalId: string }) => r.externalId)).toEqual(['CVE-2026-6001']);

    const repeated = await search(app, 'package=severity-pkg&severity=CRITICAL&severity=HIGH');
    expect(repeated.body.results.map((r: { externalId: string }) => r.externalId).sort()).toEqual(['CVE-2026-6001', 'CVE-2026-6002']);

    const none = await search(app, 'package=severity-pkg');
    expect(none.body.results).toHaveLength(3);
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

  it('keeps a confirmed-unfixed RPM-vendor advisory row out of the vendor-blind product search', async () => {
    // Shape RedHatVexFetcher writes for a CVE with no fix yet: no version
    // range at all, patchAvailable: false -- matches unconditionally via
    // matchesRpmVersionRange()'s "no versionEnd" branch, which is exactly why
    // it must never be reachable through a query that doesn't name the RHEL
    // ecosystem explicitly (confirmed live: package=php&ecosystem=bitnami
    // surfaced RHEL9's unfixed CVE-2023-0568 for an unrelated container image).
    const advisory = await prisma.advisoryVulnerability.create({
      data: { source: 'red-hat-vex', externalId: 'CVE-2023-0568', cveId: 'CVE-2023-0568', rawData: {} },
    });
    await prisma.advisoryAffectedProduct.create({
      data: { advisoryId: advisory.id, vendor: 'red-hat-9', product: 'php', patchAvailable: false },
    });

    // Unrelated ecosystem, or none at all: must not surface the RHEL-only row.
    const noEcosystem = await search(app, 'package=php');
    expect(noEcosystem.body.results).toHaveLength(0);

    const unrelatedEcosystem = await search(app, 'package=php&ecosystem=bitnami');
    expect(unrelatedEcosystem.body.results).toHaveLength(0);

    // The RHEL ecosystem, explicitly named, must still find it via searchAdvisoryRpm().
    const rhelEcosystem = await search(app, 'package=php&ecosystem=Red%20Hat:9');
    expect(rhelEcosystem.body.results).toHaveLength(1);
    expect(rhelEcosystem.body.results[0].externalId).toBe('CVE-2023-0568');
  });

  it('compares PAN rows in hotfix order, and every other vendor as before', async () => {
    // One PAN-OS maintenance-release range as parseCsaf() now writes it
    // (CVE-2025-0126's 10.2 line: 10.2.5 up to, not including, 10.2.9-h13).
    await importAdvisoryData({
      externalId: 'CVE-2026-7001',
      cveId: 'CVE-2026-7001',
      rawData: {},
      affectedProducts: [
        { vendor: 'paloalto', product: 'PAN-OS', versionStart: '10.2.5', versionEnd: '10.2.9-h13', versionFixed: '10.2.9-h13', patchAvailable: true },
      ],
    }, 'paloalto');
    // A non-PAN vendor whose "-<letter>" suffix still means a pre-release.
    await importAdvisoryData({
      externalId: 'CVE-2026-7002',
      cveId: 'CVE-2026-7002',
      rawData: {},
      affectedProducts: [{ vendor: 'examplevendor', product: 'example-product', versionEnd: '2.0.0', patchAvailable: true }],
    }, 'advisory-example');

    const hits = async (query: string) => (await search(app, query)).body.results.map((r: { externalId: string }) => r.externalId);

    for (const affected of ['10.2.5', '10.2.9', '10.2.9-h1', '10.2.9-h12']) {
      expect(await hits(`package=PAN-OS&version=${affected}`), affected).toEqual(['CVE-2026-7001']);
    }
    // With normalizeVersion() the bound "10.2.9-h13" encoded below 10.2.9, so
    // 10.2.9 itself fell outside the range and the fixed hotfix was not
    // distinguishable from the ones before it.
    for (const unaffected of ['10.2.4', '10.2.4-h30', '10.2.9-h13', '10.2.9-h14', '10.2.10']) {
      expect(await hits(`package=PAN-OS&version=${unaffected}`), unaffected).toEqual([]);
    }

    const pan = await search(app, 'package=PAN-OS&version=10.2.9-h1');
    expect(pan.body.results[0]).toMatchObject({ fixedVersion: '10.2.9-h13', approximateMatch: false });

    expect(await hits('package=example-product&version=2.0.0-beta')).toEqual(['CVE-2026-7002']);
    expect(await hits('package=example-product&version=2.0.0')).toEqual([]);
  });
});

describe('GET /api/v1/vulnerabilities/search — distroPriority', () => {
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

  it('returns Ubuntu\'s own priority next to the CVE-wide severity, only for the Ubuntu match', async () => {
    // NVD rates the CVE HIGH; Ubuntu rates it negligible for its package.
    await prisma.vulnerability.create({ data: { cveId: 'CVE-2026-6161', severity: 'HIGH', cvssScore: 7.5 } });
    await importOSVData({
      id: 'UBUNTU-CVE-2026-6161',
      modified: '2026-01-01T00:00:00Z',
      aliases: [],
      upstream: ['CVE-2026-6161'],
      severity: [
        { type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H' },
        { type: 'Ubuntu', score: 'negligible' },
      ],
      affected: [{ package: { ecosystem: 'Ubuntu:24.04:LTS', name: 'demo-pkg' }, versions: ['1.0-1'] }],
    });
    await importOSVData({
      id: 'GHSA-demo-0001',
      modified: '2026-01-01T00:00:00Z',
      aliases: ['CVE-2026-6161'],
      affected: [{ package: { ecosystem: 'npm', name: 'demo-pkg' }, versions: ['1.0.0'] }],
    });

    const ubuntu = await search(app, 'package=demo-pkg&version=1.0-1&ecosystem=Ubuntu:24.04:LTS');
    expect(ubuntu.body.results).toHaveLength(1);
    expect(ubuntu.body.results[0]).toMatchObject({ externalId: 'CVE-2026-6161', severity: 'HIGH', distroPriority: 'negligible' });

    const npm = await search(app, 'package=demo-pkg&version=1.0.0&ecosystem=npm');
    expect(npm.body.results).toHaveLength(1);
    expect(npm.body.results[0]).toMatchObject({ severity: 'HIGH', distroPriority: null });
  });

  it('returns Debian\'s urgency for the queried release, which can differ between releases', async () => {
    await importOSVData({
      id: 'DEBIAN-CVE-2026-6262',
      modified: '2026-01-01T00:00:00Z',
      upstream: ['CVE-2026-6262'],
      affected: [
        { package: { ecosystem: 'Debian:12', name: 'demo-src' }, versions: ['1.0-1'], ecosystem_specific: { urgency: 'unimportant' } },
        { package: { ecosystem: 'Debian:13', name: 'demo-src' }, versions: ['1.0-1'], ecosystem_specific: { urgency: 'low' } },
      ],
    });

    const bookworm = await search(app, 'package=demo-src&version=1.0-1&ecosystem=Debian:12');
    expect(bookworm.body.results[0]).toMatchObject({ externalId: 'CVE-2026-6262', distroPriority: 'unimportant' });
    const trixie = await search(app, 'package=demo-src&version=1.0-1&ecosystem=Debian:13');
    expect(trixie.body.results[0]).toMatchObject({ externalId: 'CVE-2026-6262', distroPriority: 'low' });
  });

  it('returns Red Hat\'s reason for a missing fix as fixStatus, next to its impact', async () => {
    // Shape RedHatVexFetcher writes for an unfixed CVE Red Hat will not fix.
    await importAdvisoryData({
      externalId: 'CVE-2026-6464',
      cveId: 'CVE-2026-6464',
      distroPriority: 'moderate',
      rawData: {},
      affectedProducts: [{
        vendor: 'red-hat-9', product: 'demo-unfixed', patchAvailable: false,
        fixStatus: 'will_not_fix', fixStatusDetail: 'Will not fix',
      }],
    }, 'red-hat-vex');

    const rhel = await search(app, 'package=demo-unfixed&version=0:2.0-1.el9&ecosystem=Red%20Hat:9');
    expect(rhel.body.results).toHaveLength(1);
    expect(rhel.body.results[0]).toMatchObject({
      externalId: 'CVE-2026-6464',
      fixedVersion: null,
      distroPriority: 'moderate',
      fixStatus: 'will_not_fix',
      fixStatusDetail: 'Will not fix',
    });
  });

  it('returns Red Hat\'s per-CVE impact for an RHEL match', async () => {
    await importAdvisoryData({
      externalId: 'RHSA-2026:0001/CVE-2026-6363',
      cveId: 'CVE-2026-6363',
      severity: 'HIGH', // the whole RHSA's rating
      distroPriority: 'low', // this CVE's own impact
      rawData: {},
      affectedProducts: [{ vendor: 'red-hat-9', product: 'demo-rpm', versionEnd: '0:1.0-2.el9' }],
    }, 'red-hat');

    const rhel = await search(app, 'package=demo-rpm&version=0:1.0-1.el9&ecosystem=Red%20Hat:9');
    expect(rhel.body.results).toHaveLength(1);
    expect(rhel.body.results[0]).toMatchObject({ externalId: 'CVE-2026-6363', distroPriority: 'low' });
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
