import { describe, it, expect } from 'vitest';
import { buildSonicWallAdvisories } from './sonicwall-fetcher.js';

function baseAdv(overrides: Partial<Parameters<typeof buildSonicWallAdvisories>[0]> = {}) {
  return {
    advisory_id: 'SNWLID-2026-0001',
    title: 'Multiple vulnerabilities in SonicOS',
    published_when: '2026-02-24',
    last_updated_when: '2026-02-24',
    impact: 'CRITICAL',
    cvss: '9.8',
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    cvss_version: 3,
    cwe: 'CWE-89',
    cve: 'CVE-2026-1111, CVE-2026-2222',
    is_workaround_available: false,
    summary: 'Multiple vulnerabilities',
    affected_products: '<table>7.1.3.3</table>',
    vuln_status: 'Applicable',
    patterns: [],
    vulnerable_products: [{ id: 1, name: 'SonicOS' }],
    ...overrides,
  };
}

describe('buildSonicWallAdvisories', () => {
  it('splits a multi-CVE advisory into one entry per CVE with a composite externalId', () => {
    const advisories = buildSonicWallAdvisories(baseAdv());

    expect(advisories).toHaveLength(2);
    expect(advisories.map(a => a.externalId)).toEqual([
      'SNWLID-2026-0001/CVE-2026-1111',
      'SNWLID-2026-0001/CVE-2026-2222',
    ]);
    expect(advisories.map(a => a.cveId)).toEqual(['CVE-2026-1111', 'CVE-2026-2222']);
    for (const a of advisories) {
      expect(a.severity).toBe('CRITICAL');
      expect(a.url).toBe('https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0001');
    }
  });

  it('keeps the plain advisory id as externalId when there is no CVE', () => {
    const advisories = buildSonicWallAdvisories(baseAdv({ cve: '' }));
    expect(advisories).toHaveLength(1);
    expect(advisories[0].externalId).toBe('SNWLID-2026-0001');
    expect(advisories[0].cveId).toBeUndefined();
  });

  it('falls back to a SonicOS product entry when vulnerable_products is empty', () => {
    const advisories = buildSonicWallAdvisories(baseAdv({ cve: '', vulnerable_products: [] }));
    expect(advisories[0].affectedProducts).toEqual([
      { vendor: 'sonicwall', product: 'SonicOS', affectedVersions: ['7.1.3.3'], patchAvailable: true },
    ]);
  });
});
