import { describe, it, expect, beforeEach } from 'vitest';
import { prisma } from '../db/client.js';
import { resetDb } from '../test-utils/db.js';
import { importEPSSData } from './epss-fetcher.js';

// importEPSSData() applies its updates through a raw UPDATE ... FROM (VALUES)
// statement, which Prisma cannot type-check: a wrong column name or a changed
// join condition would only show up at runtime, hence these tests.

async function seed(cveIds: string[]): Promise<void> {
  for (const cveId of cveIds) {
    await prisma.vulnerability.create({ data: { cveId } });
  }
}

const scoresFor = (cveId: string) =>
  prisma.vulnerability.findUnique({
    where: { cveId },
    select: { epssScore: true, epssPercentile: true, epssUpdatedAt: true },
  });

describe('importEPSSData', () => {
  beforeEach(async () => {
    await resetDb();
  });

  it('writes score, percentile and timestamp onto existing master rows', async () => {
    await seed(['CVE-2026-0001', 'CVE-2026-0002']);
    const at = new Date('2026-09-18T00:00:00.000Z');

    const { updated } = await importEPSSData([
      { cve: 'CVE-2026-0001', epss: 0.12345, percentile: 0.54321 },
      { cve: 'CVE-2026-0002', epss: 0.99999, percentile: 0.88888 },
    ], at);

    expect(updated).toBe(2);
    expect(await scoresFor('CVE-2026-0001')).toEqual({
      epssScore: 0.12345, epssPercentile: 0.54321, epssUpdatedAt: at,
    });
    expect(await scoresFor('CVE-2026-0002')).toEqual({
      epssScore: 0.99999, epssPercentile: 0.88888, epssUpdatedAt: at,
    });
  });

  it('ignores entries whose CVE has no master row, and never creates one', async () => {
    // EPSS publishes ~320k CVEs, far more than this database tracks, so most
    // entries in a real run match nothing. They must not be counted or inserted.
    await seed(['CVE-2026-0001']);

    const { updated } = await importEPSSData([
      { cve: 'CVE-2026-0001', epss: 0.5, percentile: 0.5 },
      { cve: 'CVE-1000-99999', epss: 0.9, percentile: 0.9 },
    ]);

    expect(updated).toBe(1);
    expect(await prisma.vulnerability.count()).toBe(1);
    expect(await prisma.vulnerability.count({ where: { cveId: 'CVE-1000-99999' } })).toBe(0);
  });

  it('overwrites values from an earlier run', async () => {
    await seed(['CVE-2026-0001']);
    await importEPSSData([{ cve: 'CVE-2026-0001', epss: 0.1, percentile: 0.1 }], new Date('2026-09-17T00:00:00.000Z'));
    await importEPSSData([{ cve: 'CVE-2026-0001', epss: 0.7, percentile: 0.8 }], new Date('2026-09-18T00:00:00.000Z'));

    expect(await scoresFor('CVE-2026-0001')).toEqual({
      epssScore: 0.7, epssPercentile: 0.8, epssUpdatedAt: new Date('2026-09-18T00:00:00.000Z'),
    });
  });

  it('applies every entry across a chunk boundary', async () => {
    // CHUNK_SIZE is 1000; this spans two statements, so an off-by-one in the
    // loop would leave the tail unapplied.
    const ids = Array.from({ length: 1200 }, (_, i) => `CVE-2026-${String(i).padStart(5, '0')}`);
    await prisma.vulnerability.createMany({ data: ids.map(cveId => ({ cveId })) });

    const { updated } = await importEPSSData(ids.map((cve, i) => ({ cve, epss: i / 10000, percentile: 0.5 })));

    expect(updated).toBe(1200);
    // First and last entries of each chunk.
    expect((await scoresFor(ids[0]))?.epssScore).toBe(0);
    expect((await scoresFor(ids[999]))?.epssScore).toBeCloseTo(0.0999, 6);
    expect((await scoresFor(ids[1000]))?.epssScore).toBeCloseTo(0.1, 6);
    expect((await scoresFor(ids[1199]))?.epssScore).toBeCloseTo(0.1199, 6);
  });

  it('does nothing for an empty entry list', async () => {
    await seed(['CVE-2026-0001']);
    const { updated } = await importEPSSData([]);
    expect(updated).toBe(0);
    expect((await scoresFor('CVE-2026-0001'))?.epssScore).toBeNull();
  });
});
