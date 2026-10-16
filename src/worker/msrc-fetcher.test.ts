import { describe, expect, it } from 'vitest';
import {
  buildMsrcAdvisories,
  latestRevisions,
  parseDocumentId,
  parseMsrcDate,
  selectDocuments,
  type CvrfDocument,
} from './msrc-fetcher.js';

// Product IDs and the shape of each entry follow the real October 2026 document.
const PRODUCTS = [
  { ProductID: '10816', Value: 'Windows Server 2016' },
  { ProductID: '11571', Value: 'Windows Server 2019' },
  { ProductID: '11923', Value: 'Windows Server 2022' },
  { ProductID: '11924', Value: 'Windows Server 2022 (Server Core installation)' },
  { ProductID: '10483', Value: 'Windows Server 2012 R2' },
  { ProductID: '11676-11923', Value: 'Microsoft .NET Framework 3.5 AND 4.8 on Windows Server 2022' },
];

const regular = (kb: string, build: string, ids: string[]) =>
  ({ Type: 2, SubType: 'Security Update', Description: { Value: kb }, FixedBuild: build, URL: `https://support.microsoft.com/help/${kb}`, ProductID: ids });

function doc(vulnerabilities: CvrfDocument['Vulnerability']): CvrfDocument {
  return { ProductTree: { FullProductName: PRODUCTS }, Vulnerability: vulnerabilities };
}

const CVE_OCT = {
  CVE: 'CVE-2026-100201',
  Title: { Value: 'Windows Kernel Elevation of Privilege Vulnerability' },
  RevisionHistory: [{ Date: '2026-10-13T07:00:00' }],
  Threats: [
    { Type: 0, Description: { Value: 'Elevation of Privilege' }, ProductID: ['11923'] },
    { Type: 3, Description: { Value: 'Important' }, ProductID: ['11923', '11924'] },
    { Type: 3, Description: { Value: 'Critical' }, ProductID: ['10483'] },
    { Type: 1, Description: { Value: 'Publicly Disclosed:No;Exploited:No' } },
  ],
  CVSSScoreSets: [
    { BaseScore: 7.0, Vector: 'CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H', ProductID: ['11923', '11924'] },
    { BaseScore: 9.8, Vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', ProductID: ['10483'] },
  ],
  Remediations: [
    regular('5126655', '10.0.20348.5761', ['11923', '11924']),
    // Windows Server 2012 R2 is out of support and not imported.
    regular('5126836', '6.3.9600.23470', ['10483']),
    // Remediations of other types name the KB but are not a fix with a build.
    { Type: 3, SubType: '5126655', ProductID: ['11923'] },
    { Type: 6, Description: { Value: '5126655' }, ProductID: ['11923'] },
  ],
};

describe('buildMsrcAdvisories', () => {
  it('turns each fixed Windows Server product into a range ending at the fix build', () => {
    const [adv] = buildMsrcAdvisories(doc([CVE_OCT]), '2026-Oct');
    expect(adv.externalId).toBe('CVE-2026-100201');
    expect(adv.cveId).toBe('CVE-2026-100201');
    expect(adv.affectedProducts).toEqual([
      { vendor: 'microsoft', product: 'Windows Server 2022', versionEnd: '10.0.20348.5761', versionFixed: '10.0.20348.5761', patchAvailable: true },
      { vendor: 'microsoft', product: 'Windows Server 2022 (Server Core installation)', versionEnd: '10.0.20348.5761', versionFixed: '10.0.20348.5761', patchAvailable: true },
    ]);
    expect(adv.solution).toBe(
      'Windows Server 2022: KB5126655 (OS build 10.0.20348.5761); Windows Server 2022 (Server Core installation): KB5126655 (OS build 10.0.20348.5761), or any later cumulative update',
    );
  });

  it('rates the advisory by the imported products only, never by an excluded one', () => {
    const [adv] = buildMsrcAdvisories(doc([CVE_OCT]), '2026-Oct');
    // 2012 R2's Critical / 9.8 must not leak into a Windows Server 2022 finding.
    expect(adv.distroPriority).toBe('Important');
    expect(adv.cvssScore).toBe(7.0);
    expect(adv.severity).toBe('HIGH');
  });

  it('reads the undated CVRF timestamps as UTC', () => {
    const [adv] = buildMsrcAdvisories(doc([CVE_OCT]), '2026-Oct');
    expect(adv.publishedAt?.toISOString()).toBe('2026-10-13T07:00:00.000Z');
    expect((adv.rawData as { revisedAt: string }).revisedAt).toBe('2026-10-13T07:00:00.000Z');
  });

  it('bounds by the regular update, not the hotpatch update with its lower build', () => {
    // June 2025: hotpatch 10.0.20348.3745 next to the regular 10.0.20348.3807.
    const [adv] = buildMsrcAdvisories(doc([{
      CVE: 'CVE-2025-29828',
      Remediations: [
        { Type: 2, SubType: 'SecurityHotpatchUpdate', Description: { Value: '5060525' }, FixedBuild: '10.0.20348.3745', ProductID: ['11923'] },
        regular('5060526', '10.0.20348.3807', ['11923']),
      ],
    }]), '2025-Jun');
    expect(adv.affectedProducts.map(p => p.versionEnd)).toEqual(['10.0.20348.3807']);
    expect((adv.rawData as { hotpatchFixes: unknown[] }).hotpatchFixes).toHaveLength(1);
  });

  it('takes the lower build when two regular updates fix the same product', () => {
    // October 2026, Windows Server 2016: the monthly update and an out-of-band one.
    const [adv] = buildMsrcAdvisories(doc([{
      CVE: 'CVE-2026-69950',
      Remediations: [regular('5126868', '10.0.14393.9612', ['10816']), regular('5126649', '10.0.14393.9596', ['10816'])],
    }]), '2026-Oct');
    expect(adv.affectedProducts.map(p => p.versionEnd)).toEqual(['10.0.14393.9596']);
  });

  it('leaves out what a build number cannot decide', () => {
    const advisories = buildMsrcAdvisories(doc([
      // An ADV advisory, not a CVE.
      { CVE: 'ADV990001', Remediations: [regular('5126655', '10.0.20348.5761', ['11923'])] },
      // An opt-in fix: affected, but no update carries it.
      { CVE: 'CVE-2013-3900', Remediations: [{ Type: 2, SubType: 'Security Update', Description: { Value: 'Release Notes' }, ProductID: ['11923'] }] },
      // A fix only for products not imported (.NET, 2012 R2).
      { CVE: 'CVE-2026-1', Remediations: [regular('5127687', '4.8.4811.0', ['11676-11923']), regular('5126836', '6.3.9600.23470', ['10483'])] },
      // A build of another release, which would be a meaningless bound for this product.
      { CVE: 'CVE-2026-2', Remediations: [regular('5126646', '10.0.26100.33650', ['11923'])] },
    ]), '2026-Oct');
    expect(advisories).toEqual([]);
  });

  it('reads nothing from a document without the imported products', () => {
    expect(buildMsrcAdvisories({ ProductTree: { FullProductName: [{ ProductID: '1', Value: 'Microsoft Office 2019' }] }, Vulnerability: [CVE_OCT] }, 'x')).toEqual([]);
  });
});

describe('latestRevisions', () => {
  it('keeps the most recently revised entry of a CVE listed in several documents', () => {
    const older = buildMsrcAdvisories(doc([{ ...CVE_OCT, RevisionHistory: [{ Date: '2026-09-08T07:00:00' }] }]), '2026-Sep');
    const newer = buildMsrcAdvisories(doc([{ ...CVE_OCT, RevisionHistory: [{ Date: '2026-09-08T07:00:00' }, { Date: '2026-10-13T07:00:00' }] }]), '2026-Oct');
    const kept = latestRevisions([...newer, ...older]);
    expect(kept).toHaveLength(1);
    expect((kept[0].rawData as { document: string }).document).toBe('2026-Oct');
    expect(kept[0].publishedAt?.toISOString()).toBe('2026-09-08T07:00:00.000Z');
  });
});

describe('selectDocuments', () => {
  const updates = [
    { ID: '2019-Jun', CurrentReleaseDate: '2026-10-15T07:00:00Z' },
    { ID: '2021-Feb', CurrentReleaseDate: '2021-02-09T08:00:00Z' },
    { ID: '2021-Mar', CurrentReleaseDate: '2024-01-01T00:00:00Z' },
    { ID: '2026-Apr', CurrentReleaseDate: '2026-10-15T07:00:00Z' },
    { ID: '2026-Sep', CurrentReleaseDate: '2026-09-20T00:00:00Z' },
    { ID: '2026-Oct', CurrentReleaseDate: '2026-09-01T00:00:00Z' },
    { ID: 'not-a-month' },
  ];
  const now = new Date('2026-10-16T00:00:00Z');

  it('reads every document from March 2021 on in a full run', () => {
    expect(selectDocuments(updates, true, now)).toEqual(['2021-Mar', '2026-Apr', '2026-Sep', '2026-Oct']);
  });

  it('reads the recently revised documents and always the latest month in a daily run', () => {
    // 2026-Apr was revised yesterday; 2026-Oct is the latest month though not revised lately;
    // 2019-Jun was revised too but predates FixedBuild.
    expect(selectDocuments(updates, false, now)).toEqual(['2026-Apr', '2026-Oct']);
  });
});

describe('parseDocumentId / parseMsrcDate', () => {
  it('reads a document id', () => {
    expect(parseDocumentId('2026-Oct')).toEqual({ year: 2026, month: 10 });
    expect(parseDocumentId('2021-mar')).toEqual({ year: 2021, month: 3 });
    expect(parseDocumentId('2026-Foo')).toBeNull();
  });

  it('keeps an explicit zone and adds UTC to a bare timestamp', () => {
    expect(parseMsrcDate('2026-10-15T07:00:00Z')?.toISOString()).toBe('2026-10-15T07:00:00.000Z');
    expect(parseMsrcDate('2026-10-13T07:00:00')?.toISOString()).toBe('2026-10-13T07:00:00.000Z');
    expect(parseMsrcDate('nonsense')).toBeUndefined();
    expect(parseMsrcDate(undefined)).toBeUndefined();
  });
});
