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

/** A one-product CSAF document: `tree` entries are [branch name, product_id, category?]. */
function csafOf(
  product: string,
  { tree, status }: { tree: Array<[string, string, string?]>; status: NonNullable<CsafDocument['vulnerabilities'][number]['product_status']> },
): CsafDocument {
  return {
    document: { title: 't', tracking: { id: 'X', initial_release_date: '2026-01-01T00:00:00Z' } },
    product_tree: {
      branches: [{
        name: product,
        category: 'product_name',
        branches: tree.map(([name, id, category]) => ({
          category: category ?? 'product_version_range',
          name,
          product: { name: `Palo Alto Networks ${product}`, product_id: id },
        })),
      }],
    },
    vulnerabilities: [{ cve: 'CVE-X', product_status: status }],
  };
}

/** Affected products as "[start, end)" strings, for compact assertions. */
function ranges(advisory: ReturnType<typeof parseCsaf>): string[] {
  return (advisory?.affectedProducts ?? []).map(r =>
    `[${r.versionStart ?? '-inf'}, ${r.versionEnd ?? '+inf'})${r.patchAvailable ? '' : ' unfixed'}`);
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

  it('sets versionStart (not just versionEnd/versionFixed) for a ">=" branch with no known fix', () => {
    // Real shape confirmed live at https://security.paloaltonetworks.com/csaf/CVE-2020-2035:
    // a design-limitation advisory PAN never shipped a version-specific fix for (only a
    // workaround), so every affected branch is an open-ended ">=X" with no corresponding
    // entry in known_not_affected/fixed at all. Before the fix, the ">="/">"  branch under
    // known_affected only fed fixedByProduct's lookup (via a *different*, higher-version
    // entry) -- it was never used as the affected range's own lower bound, so a CVE with
    // no fix at all produced entries with every version field undefined, indistinguishable
    // from "no data available".
    const csaf: CsafDocument = {
      document: { title: 't', tracking: { id: 'CVE-2020-2035', initial_release_date: '2020-08-12T00:00:00Z' } },
      product_tree: {
        branches: [{
          name: 'PAN-OS',
          category: 'product_name',
          branches: [
            { category: 'product_version_range', name: 'vers:generic/PAN-OS>=10.1.0', product: { name: 'PAN-OS', product_id: 'PANW-PAN-OS-118' } },
            { category: 'product_version_range', name: 'vers:generic/PAN-OS>=9.0.0', product: { name: 'PAN-OS', product_id: 'PANW-PAN-OS-371' } },
          ],
        }],
      },
      vulnerabilities: [{
        cve: 'CVE-2020-2035',
        product_status: { known_affected: ['PANW-PAN-OS-118', 'PANW-PAN-OS-371'] },
      }],
    };

    const advisory = parseCsaf(csaf, 'CVE-2020-2035');
    expect(advisory!.affectedProducts).toEqual([
      { vendor: 'paloalto', product: 'PAN-OS', versionStart: '10.1.0', versionEnd: undefined, lastAffected: undefined, versionFixed: undefined, patchAvailable: false },
      { vendor: 'paloalto', product: 'PAN-OS', versionStart: '9.0.0', versionEnd: undefined, lastAffected: undefined, versionFixed: undefined, patchAvailable: false },
    ]);
  });

  it('splits hotfix fix points into one range per maintenance release (CVE-2024-3400 shape)', () => {
    // PAN reuses one product_id for both sides of a fix point ("<10.2.0-h3" and
    // ">=10.2.0-h3"), lists it under known_affected and fixed alike, and fixes
    // every maintenance release with its own hotfix. The bounds used to be
    // dropped (hotfix suffix) and the id's last branch name read as a lower
    // bound, leaving no range at all -- so the CVE matched every version.
    const csaf = csafOf('PAN-OS', {
      tree: [
        ['PAN-OS 9.1 All', 'nA-91', 'product_version'],
        ['vers:generic/PAN-OS<10.2.0-h3', 'p1'], ['vers:generic/PAN-OS>=10.2.0-h3', 'p1'],
        ['vers:generic/PAN-OS>=10.2.1-h2', 'p2'],
        ['vers:generic/PAN-OS>=10.2.9-h1', 'p3'],
        ['vers:generic/PAN-OS<11.1.0-h3', 'p4'], ['vers:generic/PAN-OS>=11.1.0-h3', 'p4'],
        ['vers:generic/PAN-OS>=11.1.2-h3', 'p5'],
      ],
      status: { known_affected: ['p1', 'p4'], fixed: ['p1', 'p2', 'p3', 'p4', 'p5'], known_not_affected: ['nA-91'] },
    });

    expect(ranges(parseCsaf(csaf, 'CVE-2024-3400'))).toEqual([
      '[10.2.0, 10.2.0-h3)',
      '[10.2.1, 10.2.1-h2)',
      '[10.2.2, 10.2.9-h1)',
      '[11.1.0, 11.1.0-h3)',
      '[11.1.1, 11.1.2-h3)',
    ]);
  });

  it('reads "<X" under known_affected and ">=X" under fixed as the same kind of fix point (CVE-2025-0126 shape)', () => {
    const csaf = csafOf('PAN-OS', {
      tree: [
        ['vers:generic/PAN-OS<10.1.14-h11', 'a1'],
        ['vers:generic/PAN-OS<10.2.10-h6', 'a2'], ['vers:generic/PAN-OS>=10.2.10-h6', 'a2'],
        ['vers:generic/PAN-OS>=10.2.4-h25', 'f1'],
        ['vers:generic/PAN-OS>=10.2.9-h13', 'f2'],
        ['vers:generic/PAN-OS>=10.2.11', 'f3'],
      ],
      status: { known_affected: ['a1', 'a2'], fixed: ['a2', 'f1', 'f2', 'f3'] },
    });

    // Nothing says branches are listed individually here, so the lowest one
    // keeps no lower bound (as before); the rest start at their branch.
    expect(ranges(parseCsaf(csaf, 'CVE-2025-0126'))).toEqual([
      '[-inf, 10.1.14-h11)',
      '[10.2.0, 10.2.4-h25)',
      '[10.2.5, 10.2.9-h13)',
      '[10.2.10, 10.2.10-h6)',
    ]);
  });

  it('treats PAN\'s "<product> None" known_affected entries as not affected (CVE-2024-6387 shape)', () => {
    const csaf = csafOf('PAN-OS', {
      tree: [['PAN-OS None', 'n1', 'product_version'], ['PAN-OS All', 'n2', 'product_version']],
      status: { known_affected: ['n1'], known_not_affected: ['n2'] },
    });
    // Previously one row with no range and patchAvailable false -- matched by
    // every PAN-OS version queried.
    expect(parseCsaf(csaf, 'CVE-2024-6387')).toBeNull();
  });

  it('keeps a whole-branch "PAN-OS 10.1 All" entry inside that branch', () => {
    const csaf = csafOf('PAN-OS', {
      tree: [['PAN-OS 10.1 All', 'b1', 'product_version'], ['vers:generic/PAN-OS<10.2.5', 'a1']],
      status: { known_affected: ['b1', 'a1'] },
    });
    expect(ranges(parseCsaf(csaf, 'CVE-X'))).toEqual(['[10.2.0, 10.2.5)', '[10.1.0, 10.2.0) unfixed']);
  });

  it('caps an unfixed branch at the next branch when other branches have fixes (CVE-2025-4232 shape)', () => {
    const csaf = csafOf('GlobalProtect App', {
      tree: [
        ['vers:generic/GlobalProtect App>=6.1.0', 's1'],
        ['vers:generic/GlobalProtect App<6.2.8-h2 [6.2.8-c243]', 'a1'], ['vers:generic/GlobalProtect App>=6.2.8-h2 [6.2.8-c243]', 'a1'],
      ],
      status: { known_affected: ['s1', 'a1'], fixed: ['a1'] },
    });
    expect(ranges(parseCsaf(csaf, 'CVE-2025-4232'))).toEqual([
      '[6.2.0, 6.2.8-h2 [6.2.8-c243])',
      '[6.1.0, 6.2.0) unfixed',
    ]);
  });

  it('returns null when there are no vulnerabilities at all', () => {
    const csaf: CsafDocument = {
      document: { title: 't', tracking: { id: 'X', initial_release_date: '2026-01-01T00:00:00Z' } },
      vulnerabilities: [],
    };
    expect(parseCsaf(csaf, 'X')).toBeNull();
  });
});
