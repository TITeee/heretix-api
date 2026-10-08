import { describe, it, expect } from 'vitest';
import { buildSonicWallAdvisories, pairAffectedAndFixed } from './sonicwall-fetcher.js';

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

describe('pairAffectedAndFixed', () => {
  it('pairs each release line of a SonicOS advisory', () => {
    const affected = '<p>SonicOS 7.0.1-5145, 7.1.1-7047 and earlier versions</p>';
    const fixed = '<p>SonicOS 7.0.1-5151, SonicOS 7.1.1-7051 and later versions.</p>';
    expect(pairAffectedAndFixed(affected, fixed)).toEqual([
      { lastAffected: '7.0.1-5145', fixed: '7.0.1-5151' },
      { lastAffected: '7.1.1-7047', fixed: '7.1.1-7051' },
    ]);
  });

  it('handles platform-hotfix wording on SMA1000', () => {
    const affected = '<p>12.4.3-03526 (platform-hotfix) and older versions.</p><p>12.5.0-02952 (platform-hotfix) and older versions.</p>';
    const fixed = '<p>12.4.3-03670 (platform-hotfix) and higher versions.</p><p>12.5.0-03082 (platform-hotfix) and higher versions.</p>';
    expect(pairAffectedAndFixed(affected, fixed)).toEqual([
      { lastAffected: '12.4.3-03526', fixed: '12.4.3-03670' },
      { lastAffected: '12.5.0-02952', fixed: '12.5.0-03082' },
    ]);
  });

  it('ignores affected-limit versions repeated in the fixed table and "Pending Release" rows', () => {
    const affected = '<td>7.0.1-R1456 and older</td><td>6.5.4.8-89n and older</td>';
    const fixed = '<td>NSa,TZ- 7.0.1-R1456 and older</td><td>Pending Release</td><td>6.5.4.8 and older</td><td>6.5.4.9-92n</td>';
    expect(pairAffectedAndFixed(affected, fixed)).toEqual([
      { lastAffected: '6.5.4.8-89n', fixed: '6.5.4.9-92n' },
    ]);
  });

  it('does not read library versions such as OpenSSL 1.1.1n as product versions', () => {
    const affected = '<td>10.2.1.4-31sv and earlier versions</td>';
    const fixed = '<td>OpenSSL has been upgraded to 1.1.1n, remediating CVE-2022-0778, in the following releases: 10.2.1.5-34sv</td>';
    expect(pairAffectedAndFixed(affected, fixed)).toEqual([
      { lastAffected: '10.2.1.4-31sv', fixed: '10.2.1.5-34sv' },
    ]);
  });

  it('pairs a patch-level jump within the same minor line', () => {
    expect(pairAffectedAndFixed('<td>10.3.5 and earlier</td>', '<td>10.3.6 and higher versions</td>')).toEqual([
      { lastAffected: '10.3.5', fixed: '10.3.6' },
    ]);
  });

  it('merges several fixes of one release line into the highest', () => {
    const affected = '<td>6.5.0.2-8v-21 and older</td>';
    const fixed = '<td>6.5.0.2-8v-37-481, 6.5.0.2-8v-37-489</td>';
    expect(pairAffectedAndFixed(affected, fixed)).toEqual([
      { lastAffected: '6.5.0.2-8v-21', fixed: '6.5.0.2-8v-37-489' },
    ]);
  });

  it('returns nothing when no affected version precedes the fix in its release line', () => {
    expect(pairAffectedAndFixed('<td>Impacted</td>', '<td>7.0.1-5151</td>')).toEqual([]);
  });
});

describe('buildSonicWallAdvisories with fixed_software', () => {
  const affected = '<td>7.0.1-5145, 7.1.1-7047 and earlier versions</td>';
  const fixed_software = '<td>SonicOS 7.0.1-5151, SonicOS 7.1.1-7051 and later versions.</td>';

  it('emits one ranged row per release line for a single-product advisory', () => {
    const [adv] = buildSonicWallAdvisories(
      baseAdv({ cve: 'CVE-2024-22397', affected_products: affected }),
      { fixed_software },
    );
    expect(adv.affectedProducts).toMatchObject([
      { product: 'SonicOS', versionStart: '7.0.0', lastAffected: '7.0.1-5145', versionFixed: '7.0.1-5151' },
      { product: 'SonicOS', versionStart: '7.1.0', lastAffected: '7.1.1-7047', versionFixed: '7.1.1-7051' },
    ]);
  });

  it('starts each train at its own release line when a minor line has several', () => {
    const [adv] = buildSonicWallAdvisories(
      baseAdv({ cve: 'CVE-2018-1', affected_products: '<td>6.5.1.8 and older, 6.5.4.4 and older</td>' }),
      { fixed_software: '<td>6.5.1.9, 6.5.4.6</td>' },
    );
    expect(adv.affectedProducts).toMatchObject([
      { versionStart: '6.5.1', lastAffected: '6.5.1.8', versionFixed: '6.5.1.9' },
      { versionStart: '6.5.4', lastAffected: '6.5.4.4', versionFixed: '6.5.4.6' },
    ]);
  });

  it('attributes versions to Gen-named products by version line and leaves other products untouched', () => {
    const [adv] = buildSonicWallAdvisories(
      baseAdv({
        cve: 'CVE-2024-1',
        affected_products: '<td>6.5.4.8-89n and older</td><td>7.0.1-5145 and earlier</td>',
        vulnerable_products: [
          { id: 1, name: 'SonicOS Gen6 Platform - TZ/NSa/SM/NSv' },
          { id: 2, name: 'SonicOS Gen7 Platform - TZ/NSa/NSsp/NSv' },
          { id: 3, name: 'Email Security Appliances' },
        ],
      }),
      { fixed_software: '<td>6.5.4.9-92n</td><td>7.0.1-5151</td>' },
    );
    const byProduct = (name: string) => adv.affectedProducts.filter(p => p.product.startsWith(name));
    expect(byProduct('SonicOS Gen6')).toMatchObject([{ versionFixed: '6.5.4.9-92n', versionStart: '6.5.0' }]);
    expect(byProduct('SonicOS Gen7')).toMatchObject([{ versionFixed: '7.0.1-5151', versionStart: '7.0.0' }]);
    expect(byProduct('Email Security')).toEqual([
      { vendor: 'sonicwall', product: 'Email Security Appliances', affectedVersions: ['6.5.4.8', '7.0.1'], patchAvailable: true },
    ]);
  });

  it('keeps the legacy row when no fix can be paired, and keeps fixed_software in rawData', () => {
    const [adv] = buildSonicWallAdvisories(baseAdv({ cve: 'CVE-2024-2' }), { fixed_software: '<td>Pending Release</td>' });
    expect(adv.affectedProducts).toEqual([
      { vendor: 'sonicwall', product: 'SonicOS', affectedVersions: ['7.1.3.3'], patchAvailable: true },
    ]);
    expect(adv.rawData).toMatchObject({ fixed_software: '<td>Pending Release</td>' });
  });
});
