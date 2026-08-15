import { describe, it, expect } from 'vitest';
import { buildBroadcomAdvisories } from './broadcom-fetcher.js';

function baseItem(overrides: Partial<Parameters<typeof buildBroadcomAdvisories>[0]> = {}) {
  return {
    documentId: 'VCDSA36947',
    notificationId: 36947,
    published: '24 February 2026',
    status: 'OPEN',
    title: 'VMSA-2026-0006.1: VMware ESX, vCenter, Workstation, and Fusion updates address multiple vulnerabilities',
    updated: '24 February 2026',
    notificationUrl: 'https://support.broadcom.com/web/ecx/security-advisory/-/securityadvisory/VMSA-2026-0006',
    alertType: 'Security Advisory',
    severity: 'CRITICAL',
    supportProducts: 'VMware ESX,VMware vCenter Server',
    affectedCve: 'CVE-2026-59309, CVE-2026-59310, CVE-2026-47876, CVE-2026-41703, CVE-2026-41709',
    workAround: '',
    ...overrides,
  };
}

describe('buildBroadcomAdvisories', () => {
  it('splits a multi-CVE VMSA into one advisory per CVE with a composite externalId', () => {
    const advisories = buildBroadcomAdvisories(baseItem(), []);

    expect(advisories).toHaveLength(5);
    expect(advisories.map(a => a.externalId)).toEqual([
      'VMSA-2026-0006/CVE-2026-59309',
      'VMSA-2026-0006/CVE-2026-59310',
      'VMSA-2026-0006/CVE-2026-47876',
      'VMSA-2026-0006/CVE-2026-41703',
      'VMSA-2026-0006/CVE-2026-41709',
    ]);
    expect(advisories.map(a => a.cveId)).toEqual([
      'CVE-2026-59309', 'CVE-2026-59310', 'CVE-2026-47876', 'CVE-2026-41703', 'CVE-2026-41709',
    ]);
    // Every split shares the same product/severity/url data from the one VMSA
    for (const a of advisories) {
      expect(a.severity).toBe('CRITICAL');
      expect(a.url).toBe(baseItem().notificationUrl);
    }
  });

  it('keeps the plain VMSA id as externalId when there is no CVE at all', () => {
    const advisories = buildBroadcomAdvisories(baseItem({ affectedCve: '' }), []);

    expect(advisories).toHaveLength(1);
    expect(advisories[0].externalId).toBe('VMSA-2026-0006');
    expect(advisories[0].cveId).toBeUndefined();
  });

  it('still uses a composite externalId for a single-CVE VMSA (consistent format)', () => {
    const advisories = buildBroadcomAdvisories(baseItem({ affectedCve: 'CVE-2026-11111' }), []);

    expect(advisories).toHaveLength(1);
    expect(advisories[0].externalId).toBe('VMSA-2026-0006/CVE-2026-11111');
    expect(advisories[0].cveId).toBe('CVE-2026-11111');
  });

  it('falls back to documentId when the title has no VMSA id', () => {
    const advisories = buildBroadcomAdvisories(
      baseItem({ title: 'Some advisory with no VMSA id', affectedCve: 'CVE-2026-11111' }),
      [],
    );
    expect(advisories[0].externalId).toBe('VCDSA36947/CVE-2026-11111');
  });

  it('maps detail-page product versions into affectedProducts, shared across all CVE splits', () => {
    const advisories = buildBroadcomAdvisories(baseItem(), [
      { product: 'VMware ESXi', fixed: ['8.0 U3f', '7.0 U3s'] },
      { product: 'VMware vCenter Server', fixed: [] },
    ]);

    for (const a of advisories) {
      expect(a.affectedProducts).toEqual([
        { vendor: 'broadcom', product: 'VMware ESXi', versionFixed: '8.0 U3f', patchAvailable: true },
        { vendor: 'broadcom', product: 'VMware ESXi', versionFixed: '7.0 U3s', patchAvailable: true },
        { vendor: 'broadcom', product: 'VMware vCenter Server', patchAvailable: false },
      ]);
    }
  });

  it('falls back to supportProducts list when the detail page yields no versions', () => {
    const advisories = buildBroadcomAdvisories(baseItem({ affectedCve: '' }), []);
    expect(advisories[0].affectedProducts).toEqual([
      { vendor: 'broadcom', product: 'VMware ESX', patchAvailable: true },
      { vendor: 'broadcom', product: 'VMware vCenter Server', patchAvailable: true },
    ]);
  });

  it('falls back to a generic VMware entry when neither source has product names', () => {
    const advisories = buildBroadcomAdvisories(baseItem({ affectedCve: '', supportProducts: '' }), []);
    expect(advisories[0].affectedProducts).toEqual([
      { vendor: 'broadcom', product: 'VMware', patchAvailable: true },
    ]);
  });
});
