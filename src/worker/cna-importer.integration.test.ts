import { describe, it, expect, beforeEach } from 'vitest';
import { prisma } from '../db/client.js';
import { resetDb } from '../test-utils/db.js';
import { importCveRecords } from './cna-importer.js';
import type { CveRecord } from './cna-fetcher.js';

// Real shape confirmed live for CVE-2024-3400.
function ssvcAdp(overrides: Partial<Record<'Exploitation' | 'Automatable' | 'Technical Impact', string>> = {}) {
  return {
    metrics: [
      {
        other: {
          type: 'ssvc',
          content: {
            options: [
              { Exploitation: overrides.Exploitation ?? 'active' },
              { Automatable: overrides.Automatable ?? 'yes' },
              { 'Technical Impact': overrides['Technical Impact'] ?? 'total' },
            ],
            timestamp: '2024-04-17T04:00:13.543064Z',
          },
        },
      },
    ],
    providerMetadata: { shortName: 'CISA-ADP' },
  };
}

const vulnerabilityByCveId = (cveId: string) =>
  prisma.vulnerability.findUnique({ where: { cveId } });

describe('importCveRecords / SSVC', () => {
  beforeEach(async () => {
    await resetDb();
  });

  it('stores SSVC fields on the master row even when the record has no usable CNA affected-product data', async () => {
    const record: CveRecord = {
      cveMetadata: { cveId: 'CVE-2024-3400' },
      containers: {
        // defaultStatus "affected" with no versions -- parseCveRecord() drops this.
        cna: { affected: [{ vendor: 'Acme', product: 'Widget', defaultStatus: 'affected' }] },
        adp: [ssvcAdp()],
      },
    };

    const result = await importCveRecords([record]);
    expect(result.ssvcUpdated).toBe(1);

    const master = await vulnerabilityByCveId('CVE-2024-3400');
    expect(master).toMatchObject({
      ssvcExploitation: 'active',
      ssvcAutomatable: 'yes',
      ssvcTechnicalImpact: 'total',
    });
    expect(master?.ssvcTimestamp?.toISOString()).toBe('2024-04-17T04:00:13.543Z');

    // No CNA data survived filtering, so nothing was stored there.
    expect(await prisma.cnaVulnerability.count({ where: { cveId: 'CVE-2024-3400' } })).toBe(0);
  });

  it('stores both SSVC and CNA affected-product data when both are usable', async () => {
    const record: CveRecord = {
      cveMetadata: { cveId: 'CVE-2024-9999' },
      containers: {
        cna: {
          providerMetadata: { shortName: 'acme' },
          affected: [{ vendor: 'Acme', product: 'Widget', versions: [{ version: '0', lessThan: '1.2.3', status: 'affected' }] }],
        },
        adp: [ssvcAdp({ Exploitation: 'poc' })],
      },
    };

    await importCveRecords([record]);

    const master = await vulnerabilityByCveId('CVE-2024-9999');
    expect(master?.ssvcExploitation).toBe('poc');
    expect(await prisma.cnaVulnerability.count({ where: { cveId: 'CVE-2024-9999' } })).toBe(1);
  });

  it('updates SSVC fields on a re-import with revised values', async () => {
    const base: CveRecord = {
      cveMetadata: { cveId: 'CVE-2024-1111' },
      containers: { adp: [ssvcAdp({ Exploitation: 'none' })] },
    };
    await importCveRecords([base]);
    expect((await vulnerabilityByCveId('CVE-2024-1111'))?.ssvcExploitation).toBe('none');

    const revised: CveRecord = {
      cveMetadata: { cveId: 'CVE-2024-1111' },
      containers: { adp: [ssvcAdp({ Exploitation: 'active' })] },
    };
    await importCveRecords([revised]);
    expect((await vulnerabilityByCveId('CVE-2024-1111'))?.ssvcExploitation).toBe('active');
  });

  it('backfills SSVC for a CVE year excluded from the CNA-affected-products year filter', async () => {
    const record: CveRecord = {
      cveMetadata: { cveId: 'CVE-2022-5555' },
      containers: {
        cna: { affected: [{ vendor: 'Acme', product: 'Widget', versions: [{ version: '0', lessThan: '1.0', status: 'affected' }] }] },
        adp: [ssvcAdp()],
      },
    };

    // Mirrors bootstrapCna()'s call shape: CNA storage restricted to 2025/2026,
    // but this record is 2022.
    const result = await importCveRecords([record], new Set(['2025', '2026']));
    expect(result.ssvcUpdated).toBe(1);

    expect((await vulnerabilityByCveId('CVE-2022-5555'))?.ssvcExploitation).toBe('active');
    // CNA affected-products storage was skipped for this excluded year.
    expect(await prisma.cnaVulnerability.count({ where: { cveId: 'CVE-2022-5555' } })).toBe(0);
  });

  it('does nothing when the record has no SSVC assessment', async () => {
    const record: CveRecord = {
      cveMetadata: { cveId: 'CVE-2024-2222' },
      containers: { cna: { affected: [] } },
    };
    const result = await importCveRecords([record]);
    expect(result.ssvcUpdated).toBe(0);
    expect(await vulnerabilityByCveId('CVE-2024-2222')).toBeNull();
  });
});
