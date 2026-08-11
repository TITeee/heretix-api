import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import { prisma } from '../db/client.js';
import { resetDb } from '../test-utils/db.js';
import {
  importAdvisoryData,
  runAdvisoryFetcher,
  type AdvisoryFetcher,
  type NormalizedAdvisory,
} from './advisory-fetcher.js';

function makeAdvisory(overrides: Partial<NormalizedAdvisory> = {}): NormalizedAdvisory {
  return {
    externalId: 'FG-IR-26-001',
    summary: 'Test advisory',
    severity: 'HIGH',
    cvssScore: 7.5,
    affectedProducts: [
      { vendor: 'fortinet', product: 'FortiOS', versionStart: '7.0.0', versionEnd: '7.0.5' },
    ],
    rawData: { raw: true },
    ...overrides,
  };
}

/** Minimal AdvisoryFetcher returning a fixed result set, for driving runAdvisoryFetcher. */
function fakeFetcher(
  source: string,
  advisories: NormalizedAdvisory[],
  isCompleteSnapshot = true,
): AdvisoryFetcher {
  return {
    source: () => source,
    fetch: async () => advisories,
    isCompleteSnapshot: () => isCompleteSnapshot,
  };
}

const missingRunCountOf = (externalId: string) =>
  prisma.advisoryVulnerability
    .findFirst({ where: { externalId }, select: { missingRunCount: true } })
    .then(r => r?.missingRunCount);

const existsAdvisory = (externalId: string) =>
  prisma.advisoryVulnerability.count({ where: { externalId } }).then(n => n > 0);

describe('importAdvisoryData', () => {
  beforeEach(async () => {
    await resetDb();
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  it('creates a master row and affected products on first import (no CVE)', async () => {
    const result = await importAdvisoryData(makeAdvisory(), 'fortinet');
    expect(result).toBe('inserted');

    const master = await prisma.vulnerability.findUnique({ where: { advisoryId: 'FG-IR-26-001' } });
    expect(master).not.toBeNull();
    expect(master?.severity).toBe('HIGH');

    const advisory = await prisma.advisoryVulnerability.findUnique({
      where: { source_externalId: { source: 'fortinet', externalId: 'FG-IR-26-001' } },
      include: { affectedProducts: true },
    });
    expect(advisory?.masterVulnId).toBe(master?.id);
    expect(advisory?.affectedProducts).toHaveLength(1);
    expect(advisory?.affectedProducts[0].product).toBe('FortiOS');
  });

  it('updates on re-import and replaces affected products (delete-then-recreate)', async () => {
    await importAdvisoryData(makeAdvisory(), 'fortinet');

    const updated = makeAdvisory({
      severity: 'CRITICAL',
      affectedProducts: [
        { vendor: 'fortinet', product: 'FortiOS', versionStart: '7.0.0', versionEnd: '7.0.9' },
        { vendor: 'fortinet', product: 'FortiProxy', versionStart: '7.2.0', versionEnd: '7.2.3' },
      ],
    });
    const result = await importAdvisoryData(updated, 'fortinet');
    expect(result).toBe('updated');

    const advisory = await prisma.advisoryVulnerability.findUnique({
      where: { source_externalId: { source: 'fortinet', externalId: 'FG-IR-26-001' } },
      include: { affectedProducts: true },
    });
    expect(advisory?.severity).toBe('CRITICAL');
    // Old single-product row must be gone, replaced by the new two-product set.
    expect(advisory?.affectedProducts).toHaveLength(2);
    expect(advisory?.affectedProducts.map(p => p.product).sort()).toEqual(['FortiOS', 'FortiProxy']);
  });

  it('links to an existing NVD-created master row instead of creating a new one when cveId matches', async () => {
    const nvdMaster = await prisma.vulnerability.create({
      data: { cveId: 'CVE-2026-1111', severity: 'CRITICAL', cvssScore: 9.8 },
    });

    const adv = makeAdvisory({ cveId: 'CVE-2026-1111' });
    await importAdvisoryData(adv, 'fortinet');

    const advisory = await prisma.advisoryVulnerability.findUnique({
      where: { source_externalId: { source: 'fortinet', externalId: 'FG-IR-26-001' } },
    });
    expect(advisory?.masterVulnId).toBe(nvdMaster.id);

    // NVD's authoritative severity must not be overwritten by the advisory import.
    const master = await prisma.vulnerability.findUnique({ where: { id: nvdMaster.id } });
    expect(master?.severity).toBe('CRITICAL');

    const allMasters = await prisma.vulnerability.count();
    expect(allMasters).toBe(1);
  });

  it('creates a placeholder master row when cveId is present but no NVD record exists yet', async () => {
    const adv = makeAdvisory({ cveId: 'CVE-2026-2222' });
    await importAdvisoryData(adv, 'fortinet');

    const master = await prisma.vulnerability.findUnique({ where: { cveId: 'CVE-2026-2222' } });
    expect(master).not.toBeNull();
    expect(master?.severity).toBe('HIGH');
  });

  it('upserts by advisoryId when no CVE is present, without creating duplicate master rows', async () => {
    await importAdvisoryData(makeAdvisory(), 'fortinet');
    await importAdvisoryData(makeAdvisory({ severity: 'LOW' }), 'fortinet');

    const masters = await prisma.vulnerability.findMany({ where: { advisoryId: 'FG-IR-26-001' } });
    expect(masters).toHaveLength(1);
    expect(masters[0].severity).toBe('LOW');
  });

  it('persists the raw lastAffected string, not just its normalized BigInt (regression: was silently dropped)', async () => {
    const adv = makeAdvisory({
      affectedProducts: [
        { vendor: 'apache', product: 'tomcat', versionStart: '9.0.71', lastAffected: '9.0.73' },
      ],
    });
    await importAdvisoryData(adv, 'advisory-tomcat');

    const advisory = await prisma.advisoryVulnerability.findUnique({
      where: { source_externalId: { source: 'advisory-tomcat', externalId: 'FG-IR-26-001' } },
      include: { affectedProducts: true },
    });
    expect(advisory?.affectedProducts[0].lastAffected).toBe('9.0.73');
    expect(advisory?.affectedProducts[0].lastAffectedInt).not.toBeNull();
  });
});

describe('runAdvisoryFetcher — stale-advisory pruning', () => {
  const KEEP = 'FG-IR-26-KEEP';
  const STALE = 'FG-IR-26-STALE';
  const keeper = makeAdvisory({ externalId: KEEP });

  beforeEach(async () => {
    await resetDb();
    // Both start out present in the source.
    await importAdvisoryData(keeper, 'fortinet');
    await importAdvisoryData(makeAdvisory({ externalId: STALE }), 'fortinet');
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  it('skips pruning entirely when the fetch returns zero advisories', async () => {
    // A parser breaking and returning [] without throwing is indistinguishable
    // from "everything was retracted"; treating it as the latter would wipe
    // every advisory for the source. Nothing may be touched, not even counted
    // as missing.
    const result = await runAdvisoryFetcher(fakeFetcher('fortinet', []));

    expect(result.pruned).toBe(0);
    expect(await existsAdvisory(STALE)).toBe(true);
    expect(await missingRunCountOf(STALE)).toBe(0);
  });

  it('skips pruning for a fetcher reporting a partial snapshot', async () => {
    // e.g. PAN/Cisco in mode:'latest' — absence only means "outside the
    // recent window", not "retracted".
    const result = await runAdvisoryFetcher(fakeFetcher('fortinet', [keeper], false));

    expect(result.pruned).toBe(0);
    expect(await existsAdvisory(STALE)).toBe(true);
    expect(await missingRunCountOf(STALE)).toBe(0);
  });

  it('counts a miss without deleting on the first absent run', async () => {
    const result = await runAdvisoryFetcher(fakeFetcher('fortinet', [keeper]));

    expect(result.pruned).toBe(0);
    expect(await existsAdvisory(STALE)).toBe(true);
    expect(await missingRunCountOf(STALE)).toBe(1);
  });

  it('deletes only after three consecutive absent runs, leaving present advisories alone', async () => {
    await runAdvisoryFetcher(fakeFetcher('fortinet', [keeper]));
    await runAdvisoryFetcher(fakeFetcher('fortinet', [keeper]));
    expect(await existsAdvisory(STALE)).toBe(true);
    expect(await missingRunCountOf(STALE)).toBe(2);

    const third = await runAdvisoryFetcher(fakeFetcher('fortinet', [keeper]));

    expect(third.pruned).toBe(1);
    expect(await existsAdvisory(STALE)).toBe(false);
    expect(await existsAdvisory(KEEP)).toBe(true);
  });

  it('resets the miss counter when an advisory reappears', async () => {
    await runAdvisoryFetcher(fakeFetcher('fortinet', [keeper]));
    await runAdvisoryFetcher(fakeFetcher('fortinet', [keeper]));
    expect(await missingRunCountOf(STALE)).toBe(2);

    // Reappears — a transient scrape hiccup, not a retraction.
    await runAdvisoryFetcher(fakeFetcher('fortinet', [keeper, makeAdvisory({ externalId: STALE })]));
    expect(await missingRunCountOf(STALE)).toBe(0);

    // And the count restarts, so it survives what would otherwise be the
    // deleting run.
    await runAdvisoryFetcher(fakeFetcher('fortinet', [keeper]));
    expect(await existsAdvisory(STALE)).toBe(true);
  });

  it('deletes the master row when the pruned advisory was its sole owner', async () => {
    const before = await prisma.vulnerability.findUnique({ where: { advisoryId: STALE } });
    expect(before).not.toBeNull();

    await prisma.advisoryVulnerability.updateMany({ where: { externalId: STALE }, data: { missingRunCount: 2 } });
    await runAdvisoryFetcher(fakeFetcher('fortinet', [keeper]));

    expect(await prisma.vulnerability.findUnique({ where: { advisoryId: STALE } })).toBeNull();
  });

  it('keeps a CVE-keyed master row, which other sources may also point at', async () => {
    await importAdvisoryData(makeAdvisory({ externalId: 'FG-IR-26-CVE', cveId: 'CVE-2026-9999' }), 'fortinet');
    await prisma.advisoryVulnerability.updateMany({ where: { externalId: 'FG-IR-26-CVE' }, data: { missingRunCount: 2 } });

    await runAdvisoryFetcher(fakeFetcher('fortinet', [keeper]));

    expect(await existsAdvisory('FG-IR-26-CVE')).toBe(false);
    expect(await prisma.vulnerability.findUnique({ where: { cveId: 'CVE-2026-9999' } })).not.toBeNull();
  });

  it('keeps the master row while another source still references it', async () => {
    // Same externalId under a second source shares one advisoryId-keyed master.
    await importAdvisoryData(makeAdvisory({ externalId: STALE }), 'advisory-other');
    await prisma.advisoryVulnerability.updateMany({
      where: { externalId: STALE, source: 'fortinet' }, data: { missingRunCount: 2 },
    });

    await runAdvisoryFetcher(fakeFetcher('fortinet', [keeper]));

    expect(await prisma.advisoryVulnerability.count({ where: { externalId: STALE } })).toBe(1);
    expect(await prisma.vulnerability.findUnique({ where: { advisoryId: STALE } })).not.toBeNull();
  });
});
