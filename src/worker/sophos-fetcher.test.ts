import { describe, it, expect } from 'vitest';
import { buildSophosAdvisories, extractProduct, type AdvisoryMeta } from './sophos-fetcher.js';

// Real titles confirmed live across ~120 stored Sophos advisories.
describe('extractProduct', () => {
  it('still parses the original "in Sophos X Firmware/Software" shape', () => {
    expect(extractProduct('Resolved: Multiple vulnerabilities in Sophos Firewall Firmware')).toBe('Sophos Firewall');
  });

  it('parses a "Sophos X vY.Z [MR/GA] Resolves ..." bulletin, stripping parens', () => {
    expect(extractProduct('Sophos Firewall v18.5 MR3 Resolves Security Vulnerabilities (CVE-2022-0331)')).toBe('Sophos Firewall');
    expect(extractProduct('Sophos (SG) UTM 9.710 MR10 Resolves Security Vulnerabilities (CVE-2022-0386, CVE-2022-0652)')).toBe('Sophos SG UTM');
  });

  it('parses a "Sophos X N.N.N.N Resolves ..." bulletin with a bare version (no "v" prefix)', () => {
    expect(extractProduct('Sophos Web Appliance 4.3.10.4 Resolves Security Vulnerabilities')).toBe('Sophos Web Appliance');
  });

  it('parses "Resolved ... in ProductName (CVE-...)" even without a "Sophos" prefix', () => {
    expect(extractProduct('Resolved RCE in SG UTM WebAdmin (CVE-2020-25223)')).toBe('SG UTM WebAdmin');
    expect(extractProduct('Resolved LPE in HitmanPro (CVE-2021-25271)')).toBe('HitmanPro');
    expect(extractProduct('Resolved LPE vulnerability in Taegis Endpoint Agent (Linux) (CVE-2024-13861)')).toBe('Taegis Endpoint Agent');
  });

  it('parses "Resolved ... on Sophos ProductName (CVE-...)", preserving the "Sophos " prefix', () => {
    expect(extractProduct('Resolved App Password Bypass on Sophos Secure Workspace for Android (CVE-2021-36808)')).toBe('Sophos Secure Workspace for Android');
  });

  it('drops a version token embedded mid-title instead of folding it into the product name', () => {
    expect(extractProduct('Resolved buffer overflow in XG Firewall v17.x User Portal (CVE-2020-15069)')).toBe('XG Firewall');
  });

  it('falls back to generic "Sophos" when the only captured text is a bare component name', () => {
    expect(extractProduct('Resolved authenticated RCE issues in User Portal (CVE-2020-17352)')).toBe('Sophos');
  });

  it('falls back to generic "Sophos" for third-party/non-product-specific advisories', () => {
    expect(extractProduct('Advisory: OpenSSL DoS vulnerability (CVE-2022-0778)')).toBe('Sophos');
    expect(extractProduct('Advisory: Log4j zero-day vulnerability AKA Log4Shell (CVE-2021-44228)')).toBe('Sophos');
  });
});

function baseMeta(overrides: Partial<AdvisoryMeta> = {}): AdvisoryMeta {
  return {
    externalId: 'sophos-sa-20260224-firewall',
    cveIds: ['CVE-2026-1111', 'CVE-2026-2222', 'CVE-2026-3333'],
    severity: 'HIGH',
    title: 'Resolved: Multiple vulnerabilities in Sophos Firewall',
    pubDate: new Date('2026-02-24T00:00:00Z'),
    url: 'https://www.sophos.com/en-us/security-advisories/sophos-sa-20260224-firewall',
    ...overrides,
  };
}

describe('buildSophosAdvisories', () => {
  it('splits a multi-CVE advisory into one entry per CVE with a composite externalId', () => {
    const advisories = buildSophosAdvisories(baseMeta());

    expect(advisories).toHaveLength(3);
    expect(advisories.map(a => a.externalId)).toEqual([
      'sophos-sa-20260224-firewall/CVE-2026-1111',
      'sophos-sa-20260224-firewall/CVE-2026-2222',
      'sophos-sa-20260224-firewall/CVE-2026-3333',
    ]);
    expect(advisories.map(a => a.cveId)).toEqual(['CVE-2026-1111', 'CVE-2026-2222', 'CVE-2026-3333']);
    for (const a of advisories) {
      expect(a.severity).toBe('HIGH');
      expect(a.affectedProducts[0].patchAvailable).toBe(true);
    }
  });

  it('keeps the plain sitemap id as externalId when there is no CVE', () => {
    const advisories = buildSophosAdvisories(baseMeta({ cveIds: [] }));
    expect(advisories).toHaveLength(1);
    expect(advisories[0].externalId).toBe('sophos-sa-20260224-firewall');
    expect(advisories[0].cveId).toBeUndefined();
  });

  it('skips entries with no title and no CVE (never actually fetched)', () => {
    const advisories = buildSophosAdvisories(baseMeta({ title: undefined, cveIds: [] }));
    expect(advisories).toEqual([]);
  });

  it('still uses a composite externalId for a single-CVE advisory (consistent format)', () => {
    const advisories = buildSophosAdvisories(baseMeta({ cveIds: ['CVE-2026-9999'] }));
    expect(advisories).toHaveLength(1);
    expect(advisories[0].externalId).toBe('sophos-sa-20260224-firewall/CVE-2026-9999');
  });
});
