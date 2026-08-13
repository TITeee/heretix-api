import { describe, it, expect } from 'vitest';
import { buildSophosAdvisories, type AdvisoryMeta } from './sophos-fetcher.js';

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
