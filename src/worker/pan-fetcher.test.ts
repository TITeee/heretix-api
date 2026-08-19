import { describe, it, expect } from 'vitest';
import { parseCsaf, type CsafDocument } from './pan-fetcher.js';

// Real shape confirmed live at https://security.paloaltonetworks.com/csaf/CVE-2026-0291.
// This CSAF document mixes a range-shaped branch ("vers:generic/...>=26.2.2") with a
// discrete/generic placeholder branch ("Prisma Access Agent 0") under the same
// product_name, using an internal product_id scheme ("PANW-Prisma-Access-Agent-3")
// unrelated to the product name or any version number. Before the fix, neither the
// "new" (vers:generic/) nor "legacy" (product-id-contains-version) parsing path could
// resolve these product_ids, so affectedProducts ended up empty and the whole advisory
// -- despite having real vulnerability data -- was silently dropped as unparseable.
// Confirmed this pattern affected 259 of PAN's ~563 CVE advisories (46%).
function prismaAccessAgentCsaf(): CsafDocument {
  return {
    document: {
      title: 'Palo Alto Networks PSIRT provided VEX document: CVE-2026-0291',
      tracking: { id: 'CVE-2026-0291', initial_release_date: '2026-08-01T00:00:00Z' },
    },
    product_tree: {
      branches: [
        {
          name: 'Palo Alto Networks',
          category: 'vendor',
          branches: [
            {
              name: 'Prisma Access Agent',
              category: 'product_name',
              branches: [
                {
                  category: 'product_version',
                  name: 'Prisma Access Agent 0',
                  product: { name: 'Palo Alto Networks Prisma Access Agent', product_id: 'PANW-Prisma-Access-Agent-3' },
                },
                {
                  category: 'product_version_range',
                  name: 'vers:generic/Prisma Access Agent>=26.2.2',
                  product: { name: 'Palo Alto Networks Prisma Access Agent', product_id: 'PANW-Prisma-Access-Agent-5' },
                },
                {
                  category: 'product_version',
                  name: 'Prisma Access Agent All',
                  product: { name: 'Palo Alto Networks Prisma Access Agent', product_id: 'PANW-Prisma-Access-Agent-2' },
                },
              ],
            },
          ],
        },
      ],
    },
    vulnerabilities: [
      {
        cve: 'CVE-2026-0291',
        product_status: {
          known_affected: ['PANW-Prisma-Access-Agent-3'],
          known_not_affected: ['PANW-Prisma-Access-Agent-2'],
          fixed: ['PANW-Prisma-Access-Agent-5'],
        },
        notes: [{ category: 'description', text: 'An improper link resolution vulnerability...' }],
      },
    ],
  };
}

describe('parseCsaf', () => {
  it('parses an advisory whose product_tree mixes a discrete placeholder branch with a range branch', () => {
    const advisory = parseCsaf(prismaAccessAgentCsaf(), 'CVE-2026-0291');

    expect(advisory).not.toBeNull();
    expect(advisory!.cveId).toBe('CVE-2026-0291');
    expect(advisory!.affectedProducts).toHaveLength(1);
    expect(advisory!.affectedProducts[0]).toMatchObject({
      vendor: 'paloalto',
      product: 'Prisma Access Agent',
      versionFixed: '26.2.2',
      patchAvailable: true,
    });
  });

  it('still parses the standard vers:generic/ range-only shape', () => {
    const csaf: CsafDocument = {
      document: { title: 't', tracking: { id: 'CVE-2026-1111', initial_release_date: '2026-01-01T00:00:00Z' } },
      product_tree: {
        branches: [{
          name: 'PAN-OS',
          category: 'product_name',
          branches: [{
            category: 'product_version_range',
            name: 'vers:generic/<11.2.10',
            product: { name: 'PAN-OS', product_id: 'PAN-OS-1' },
          }],
        }],
      },
      vulnerabilities: [{
        cve: 'CVE-2026-1111',
        product_status: { known_affected: ['PAN-OS-1'] },
      }],
    };

    const advisory = parseCsaf(csaf, 'CVE-2026-1111');
    expect(advisory!.affectedProducts[0]).toMatchObject({
      product: 'PAN-OS',
      versionEnd: '11.2.10',
    });
  });

  it('returns null when there are no vulnerabilities at all', () => {
    const csaf: CsafDocument = {
      document: { title: 't', tracking: { id: 'X', initial_release_date: '2026-01-01T00:00:00Z' } },
      vulnerabilities: [],
    };
    expect(parseCsaf(csaf, 'X')).toBeNull();
  });
});
