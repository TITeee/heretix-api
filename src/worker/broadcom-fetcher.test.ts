import { describe, it, expect } from 'vitest';
import { buildBroadcomAdvisories, parseResponseMatrixRow, parseAffectedVersionCell } from './broadcom-fetcher.js';

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

describe('parseResponseMatrixRow', () => {
  it('splits a cell listing multiple products into one entry per product', () => {
    // Real VMSA-2026-0006 row: "VMware Cloud Foundation, +\nVMware vSphere Foundation" | "9.0.2.0100"
    const parsed = parseResponseMatrixRow('VMware Cloud Foundation, +\nVMware vSphere Foundation', '9.0.2.0100');
    expect(parsed).toEqual({
      products: ['VMware Cloud Foundation', 'VMware vSphere Foundation'],
      fixedVersions: ['9.0.2.0100'],
    });
  });

  it('strips a leading footnote marker from the fixed version', () => {
    const parsed = parseResponseMatrixRow('VMware Cloud Foundation', '[1] 9.1.0.0300');
    expect(parsed).toEqual({ products: ['VMware Cloud Foundation'], fixedVersions: ['9.1.0.0300'] });
  });

  it('passes a normal single-product row through unchanged', () => {
    const parsed = parseResponseMatrixRow('VMware vCenter', '8.0 U3k');
    expect(parsed).toEqual({ products: ['VMware vCenter'], fixedVersions: ['8.0 U3k'] });
  });

  it('accepts an ESXi build id with no dotted-decimal version', () => {
    // Real VMSA-2026-0006 row: "VMware ESX" | "ESXi80U3k-25595708"
    const parsed = parseResponseMatrixRow('VMware ESX', 'ESXi80U3k-25595708');
    expect(parsed).toEqual({ products: ['VMware ESX'], fixedVersions: ['ESXi80U3k-25595708'] });
  });

  it('accepts a Workstation/Fusion year-half release', () => {
    // Real VMSA-2026-0006 row: "VMware Workstation" | "26H1"
    const parsed = parseResponseMatrixRow('VMware Workstation', '26H1');
    expect(parsed).toEqual({ products: ['VMware Workstation'], fixedVersions: ['26H1'] });
  });

  it('splits a fixed-version cell listing multiple versions joined by "or"', () => {
    // Real VMSA-2026-0006 row: "VMware ESX" | "ESXi80U3i-25205845 or ESXi80U3j-25429389"
    const parsed = parseResponseMatrixRow('VMware ESX', 'ESXi80U3i-25205845 or ESXi80U3j-25429389');
    expect(parsed).toEqual({
      products: ['VMware ESX'],
      fixedVersions: ['ESXi80U3i-25205845', 'ESXi80U3j-25429389'],
    });
  });

  it('keeps the product with an empty fixedVersions when the cell has no version-shaped text (patch guidance via prose, not a version)', () => {
    const parsed = parseResponseMatrixRow('VMware vCenter', 'Contact Broadcom Support if you have extended support contract.');
    expect(parsed).toEqual({ products: ['VMware vCenter'], fixedVersions: [] });
  });

  it('keeps the product with an empty fixedVersions for a KB article reference, not a version (regression: VMware Telco Cloud Platform/Infrastructure were dropped entirely because every row for them points at KB449886 instead of a version number)', () => {
    expect(parseResponseMatrixRow('VMware Telco Cloud Platform', 'KB449886'))
      .toEqual({ products: ['VMware Telco Cloud Platform'], fixedVersions: [] });
    expect(parseResponseMatrixRow('VMware Cloud Foundation', 'Async Patching Guide: KB88287'))
      .toEqual({ products: ['VMware Cloud Foundation'], fixedVersions: [] });
  });

  it('keeps the product with an empty fixedVersions for "n/a" and "see note" cells', () => {
    expect(parseResponseMatrixRow('VMware ESX', 'N/A')).toEqual({ products: ['VMware ESX'], fixedVersions: [] });
    expect(parseResponseMatrixRow('VMware ESX', 'See note 1.2')).toEqual({ products: ['VMware ESX'], fixedVersions: [] });
  });

  it('returns null when the row names no product at all', () => {
    expect(parseResponseMatrixRow('', '9.0.2.0100')).toBeNull();
    expect(parseResponseMatrixRow('   ', '9.0.2.0100')).toBeNull();
  });

  it('returns null when the fixed-version cell is entirely blank', () => {
    expect(parseResponseMatrixRow('VMware vCenter', '')).toBeNull();
    expect(parseResponseMatrixRow('VMware vCenter', '   ')).toBeNull();
  });
});

describe('parseAffectedVersionCell', () => {
  it('turns a wildcard branch into a versionStart/versionEnd range', () => {
    // Real VMSA-2026-0006 row: "VMware Cloud Foundation / VMware vSphere Foundation" | Version "9.1.x.x"
    expect(parseAffectedVersionCell('9.1.x.x')).toEqual([{ versionStart: '9.1', versionEnd: '9.2' }]);
  });

  it('treats a bare major.minor the same as a wildcard branch', () => {
    // Real VMSA-2026-0006 row: "VMware vCenter" | Version "8.0" | Fixed "8.0 U3k"
    expect(parseAffectedVersionCell('8.0')).toEqual([{ versionStart: '8.0', versionEnd: '8.1' }]);
  });

  it('bumps a single-component wildcard ("5.x") correctly', () => {
    // Real VMSA-2026-0006 row: "VMware Cloud Foundation" | Version "5.x"
    expect(parseAffectedVersionCell('5.x')).toEqual([{ versionStart: '5', versionEnd: '6' }]);
  });

  it('keeps a discrete non-numeric release token as an exact match, not a range', () => {
    // Real VMSA-2026-0006 row: "VMware Workstation" | Version "25H2"
    expect(parseAffectedVersionCell('25H2')).toEqual([{ exact: '25H2' }]);
  });

  it('omits "Any" entirely — it carries no constraint', () => {
    expect(parseAffectedVersionCell('Any')).toEqual([]);
    expect(parseAffectedVersionCell('any')).toEqual([]);
  });

  it('splits a cell listing several affected ranges into separate entries', () => {
    // Real VMSA-2026-0006 row: "VMware Telco Cloud Platform" | Version "3.0, 4.x, 5.0.x, 5.1.x"
    expect(parseAffectedVersionCell('3.0, 4.x, 5.0.x, 5.1.x')).toEqual([
      { versionStart: '3.0', versionEnd: '3.1' },
      { versionStart: '4', versionEnd: '5' },
      { versionStart: '5.0', versionEnd: '5.1' },
      { versionStart: '5.1', versionEnd: '5.2' },
    ]);
  });

  it('returns an empty array for a blank cell', () => {
    expect(parseAffectedVersionCell('')).toEqual([]);
    expect(parseAffectedVersionCell('   ')).toEqual([]);
  });
});

describe('buildBroadcomAdvisories: affected-version ranges', () => {
  it('sets versionStart from the range but leaves versionEnd to versionFixed (a specific patch is a tighter bound than the whole branch)', () => {
    const advisories = buildBroadcomAdvisories(baseItem({ affectedCve: 'CVE-2026-59310' }), [
      { product: 'VMware vCenter', fixed: ['8.0 U3k'], affected: [{ versionStart: '8.0', versionEnd: '8.1' }] },
    ]);
    expect(advisories[0].affectedProducts).toEqual([
      { vendor: 'broadcom', product: 'VMware vCenter', versionStart: '8.0', versionFixed: '8.0 U3k', patchAvailable: true },
    ]);
  });

  it('uses the wildcard-derived versionEnd when there is no versionFixed to defer to', () => {
    // Real VMSA-2026-0006 row: "VMware vCenter" | Version "7.0" | Fixed "Contact Broadcom Support..." (unparseable)
    const advisories = buildBroadcomAdvisories(baseItem({ affectedCve: 'CVE-2026-59310' }), [
      { product: 'VMware vCenter', fixed: [], affected: [{ versionStart: '7.0', versionEnd: '7.1' }] },
    ]);
    expect(advisories[0].affectedProducts).toEqual([
      { vendor: 'broadcom', product: 'VMware vCenter', versionStart: '7.0', versionEnd: '7.1', patchAvailable: false },
    ]);
  });

  it('stores a discrete non-numeric token as affectedVersions, not a range', () => {
    const advisories = buildBroadcomAdvisories(baseItem({ affectedCve: 'CVE-2026-41703' }), [
      { product: 'VMware Workstation', fixed: ['26H1'], affected: [{ exact: '25H2' }] },
    ]);
    expect(advisories[0].affectedProducts).toEqual([
      { vendor: 'broadcom', product: 'VMware Workstation', affectedVersions: ['25H2'], versionFixed: '26H1', patchAvailable: true },
    ]);
  });

  it('produces one row per disjoint affected range for the same product (regression: VMware Telco Cloud Platform lists 4 separate version branches in one cell)', () => {
    const advisories = buildBroadcomAdvisories(baseItem({ affectedCve: 'CVE-2026-59310' }), [
      {
        product: 'VMware Telco Cloud Platform',
        fixed: [],
        affected: [
          { versionStart: '3.0', versionEnd: '3.1' },
          { versionStart: '4', versionEnd: '5' },
        ],
      },
    ]);
    expect(advisories[0].affectedProducts).toEqual([
      { vendor: 'broadcom', product: 'VMware Telco Cloud Platform', versionStart: '3.0', versionEnd: '3.1', patchAvailable: false },
      { vendor: 'broadcom', product: 'VMware Telco Cloud Platform', versionStart: '4', versionEnd: '5', patchAvailable: false },
    ]);
  });

  it('crosses multiple fixed versions with a single affected range ("or"-split Fixed Version cell)', () => {
    const advisories = buildBroadcomAdvisories(baseItem({ affectedCve: 'CVE-2026-47876' }), [
      {
        product: 'VMware ESX',
        fixed: ['ESXi80U3i-25205845', 'ESXi80U3j-25429389'],
        affected: [{ versionStart: '8.0', versionEnd: '8.1' }],
      },
    ]);
    expect(advisories[0].affectedProducts).toEqual([
      { vendor: 'broadcom', product: 'VMware ESX', versionStart: '8.0', versionFixed: 'ESXi80U3i-25205845', patchAvailable: true },
      { vendor: 'broadcom', product: 'VMware ESX', versionStart: '8.0', versionFixed: 'ESXi80U3j-25429389', patchAvailable: true },
    ]);
  });

  it('falls back to the pre-existing shape when a ProductVersion has no affected field at all (backward compatible)', () => {
    const advisories = buildBroadcomAdvisories(baseItem({ affectedCve: 'CVE-2026-11111' }), [
      { product: 'VMware ESXi', fixed: ['8.0 U3f'] },
    ]);
    expect(advisories[0].affectedProducts).toEqual([
      { vendor: 'broadcom', product: 'VMware ESXi', versionFixed: '8.0 U3f', patchAvailable: true },
    ]);
  });
});
