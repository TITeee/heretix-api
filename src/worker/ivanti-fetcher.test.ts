import { describe, it, expect } from 'vitest';
import {
  normalizeArticle, buildIvantiAdvisories, parseAffectedCell, parseCveTable, parseResolvedCell, pairIvantiVersions,
  productName, sectionText, articleTitle, type RenderedArticle,
} from './ivanti-fetcher.js';

const CVE_HEADER = ['CVE Number', 'Description', 'CVSS Score (Severity)', 'CVSS Vector', 'CWE'];

function article(overrides: Partial<RenderedArticle> & Pick<RenderedArticle, 'tables'>): RenderedArticle {
  return {
    url: 'https://hub.ivanti.com/s/article/Security-Advisory-Test',
    urlName: 'Security-Advisory-Test',
    bodyText: [
      'Hub Knowledge',
      'Security Advisory Ivanti Test (CVE-2026-0001)',
      'Primary Product', 'Test', 'Article Type', 'Security Advisory',
      'Created Date', 'Jan 29, 2026 6:38:15 PM',
      'Summary', 'Ivanti has released updates.',
      'Solution', 'Update to the resolved version.',
      'Mitigations:', 'Restrict access.',
    ].join('\n'),
    ...overrides,
  };
}

describe('parseAffectedCell', () => {
  it('reads "and prior" lines, one per release line (EPMM, Sentry)', () => {
    expect(parseAffectedCell('12.5.0.0 and prior\n12.6.0.0 and prior\n12.7.0.0 and prior')).toEqual([
      { last: '12.5.0.0' }, { last: '12.6.0.0' }, { last: '12.7.0.0' },
    ]);
    expect(parseAffectedCell('R10.8.1 and prior\nR10.7.2 and prior')).toEqual([{ last: 'R10.8.1' }, { last: 'R10.7.2' }]);
  });

  it('reads "and below / earlier", ranges and exclusive bounds', () => {
    expect(parseAffectedCell('22.7R2.5 and below')).toEqual([{ last: '22.7R2.5' }]);
    expect(parseAffectedCell('22.7R2 through 22.7R2.4')).toEqual([{ start: '22.7R2', last: '22.7R2.4' }]);
    expect(parseAffectedCell('Prior to 12.6.1.1')).toEqual([{ end: '12.6.1.1' }]);
  });

  it('splits a comma-separated cell, as Connect Secure writes it', () => {
    expect(parseAffectedCell('22.7R2.4 and prior,\n9.1R18.9 and prior')).toEqual([{ last: '22.7R2.4' }, { last: '9.1R18.9' }]);
    expect(parseAffectedCell('2025.2, 2025.3')).toEqual([{ exact: '2025.2' }, { exact: '2025.3' }]);
  });

  it('reads Endpoint Manager service updates and the year-only release', () => {
    expect(parseAffectedCell('2024 SU4 and prior')).toEqual([{ last: '2024 SU4' }]);
    expect(parseAffectedCell('2022 SU6 and previous')).toEqual([{ last: '2022 SU6' }]);
    expect(parseAffectedCell('2024')).toEqual([{ exact: '2024' }]);
  });

  it('reads "<line> versions prior to <fix>" (Velocity License Server)', () => {
    expect(parseAffectedCell('5.1 versions prior to 5.1.2')).toEqual([{ start: '5.1', end: '5.1.2' }]);
  });

  it('reads "All versions before X" and a product name in front of a version', () => {
    expect(parseAffectedCell('All versions before 22.7R2.1\nAll versions before 9.1R18.9')).toEqual([{ end: '22.7R2.1' }, { end: '9.1R18.9' }]);
    expect(parseAffectedCell('DSM 2026.1 and prior')).toEqual([{ last: '2026.1' }]);
  });

  it('ignores a note in brackets', () => {
    expect(parseAffectedCell('22.7R2.5 and prior (see below)')).toEqual([{ last: '22.7R2.5' }]);
  });

  it('drops what Ivanti\'s version order cannot place', () => {
    expect(parseAffectedCell('See Detailed Information Below.')).toEqual([]);
    expect(parseAffectedCell('mo2026.2')).toEqual([]);
  });
});

describe('parseResolvedCell', () => {
  it('keeps versions and drops download notes', () => {
    expect(parseResolvedCell('12.6.1.1, 12.7.0.1, 12.8.0.1')).toEqual(['12.6.1.1', '12.7.0.1', '12.8.0.1']);
    expect(parseResolvedCell('R10.8.2\nR10.7.3\nR10.6.4')).toEqual(['R10.8.2', 'R10.7.3', 'R10.6.4']);
    expect(parseResolvedCell('22.7R2.5 and 22.7R2.6')).toEqual(['22.7R2.5', '22.7R2.6']);
    expect(parseResolvedCell('22.7R2.6 (released February 2025)')).toEqual(['22.7R2.6']);
    expect(parseResolvedCell('DSM 2026.1.1')).toEqual(['2026.1.1']);
    expect(parseResolvedCell('Download Portal (login required)')).toEqual([]);
    expect(parseResolvedCell('2025.2 Sept 2026 Security Patch, 2026.2')).toEqual(['2026.2']);
  });
});

describe('pairIvantiVersions', () => {
  it('gives each release line its own range (Sentry)', () => {
    const rows = pairIvantiVersions(
      parseAffectedCell('R10.8.1 and prior\nR10.7.2 and prior\nR10.6.3 and prior'),
      parseResolvedCell('R10.8.2\nR10.7.3\nR10.6.4'),
    );
    // The lowest line stays open below ("and prior"); the others start at their
    // own line, or R10.8.1's range would cover R10.7.3, which is already fixed.
    expect(rows).toEqual([
      { versionFixed: 'R10.6.4', lastAffected: 'R10.6.3' },
      { versionFixed: 'R10.7.3', lastAffected: 'R10.7.2', versionStart: '10.7.0' },
      { versionFixed: 'R10.8.2', lastAffected: 'R10.8.1', versionStart: '10.8.0' },
    ]);
  });

  it('pairs EPMM\'s three lines, whose fixes differ only in the 4th component of their neighbours', () => {
    const rows = pairIvantiVersions(
      parseAffectedCell('12.5.0.0 and prior\n12.6.0.0 and prior\n12.7.0.0 and prior'),
      parseResolvedCell('12.6.1.1, 12.7.0.1, 12.8.0.1'),
    );
    expect(rows).toHaveLength(3);
    expect(rows).toEqual(expect.arrayContaining([
      { versionFixed: '12.6.1.1', lastAffected: '12.6.0.0', versionStart: '12.6.0' },
      { versionFixed: '12.7.0.1', lastAffected: '12.7.0.0', versionStart: '12.7.0' },
      // 12.8.0.1 has no affected entry on its own line, and 12.5.0.0 and prior no fix
      // on its own: the latter stays a range without a fix. The first row of the
      // product (lowest line) is open below, as "and prior" says.
      { lastAffected: '12.5.0.0' },
    ]));
  });

  it('pairs a single affected entry with a single fix across release lines', () => {
    expect(pairIvantiVersions(parseAffectedCell('2024 SU4 and prior'), parseResolvedCell('2024 SU4 SR1'))).toEqual([
      { versionFixed: '2024 SU4 SR1', lastAffected: '2024 SU4' },
    ]);
  });

  it('spans a list of affected releases up to the fix and keeps the list for exact matching', () => {
    expect(pairIvantiVersions(parseAffectedCell('2025.2, 2025.3'), parseResolvedCell('2025.4'))).toEqual([
      { versionFixed: '2025.4', versionStart: '2025.2', lastAffected: '2025.3', affectedVersions: ['2025.2', '2025.3'] },
    ]);
  });

  it('keeps an affected entry with no resolved version as a range without a fix', () => {
    expect(pairIvantiVersions(parseAffectedCell('9.1R18.9 and prior'), [])).toEqual([{ lastAffected: '9.1R18.9' }]);
  });
});

describe('productName', () => {
  it('drops the vendor prefix and a trailing acronym', () => {
    expect(productName('Ivanti Connect Secure (ICS)')).toBe('Connect Secure');
    expect(productName('Ivanti Endpoint Manager Mobile (EPMM)')).toBe('Endpoint Manager Mobile');
    expect(productName('Ivanti Virtual Traffic Manager')).toBe('Virtual Traffic Manager');
    expect(productName('Ivanti  Sentry')).toBe('Sentry');
    expect(productName('Pulse Connect Secure (EoS)')).toBe('Pulse Connect Secure');
  });

  it('drops a CVE id that a table puts in front of the product', () => {
    expect(productName('CVE-2026-18851 Ivanti Endpoint Manager Mobile')).toBe('Endpoint Manager Mobile');
    expect(productName('CVE-2026-18851, CVE-2026-18852 Ivanti Sentry')).toBe('Sentry');
  });

  it('merges the spellings of one product', () => {
    expect(productName('EPMM (Core)')).toBe('Endpoint Manager Mobile');
    expect(productName('Ivanti Neurons for ITSM (on-prem only)')).toBe('Neurons for ITSM');
    expect(productName('Ivanti Neurons for ITSM On-Prem')).toBe('Neurons for ITSM');
    expect(productName('CSA (Cloud Services Appliance)')).toBe('Cloud Services Appliance');
    expect(productName('Ivanti Cloud Services Application (CSA)')).toBe('Cloud Services Appliance');
    expect(productName('Secure Access Client (Windows)')).toBe('Secure Access Client');
    expect(productName('ZTA Gateways')).toBe('Neurons for ZTA gateways');
    expect(productName('Ivanti Neurons for ZTA gateways')).toBe('Neurons for ZTA gateways');
  });
});

describe('article text', () => {
  const body = article({ tables: [] }).bodyText;

  it('takes the title from above "Primary Product"', () => {
    expect(articleTitle(body, 'Security-Advisory-Test')).toBe('Security Advisory Ivanti Test (CVE-2026-0001)');
    expect(articleTitle('nothing here', 'Security-Advisory-Ivanti-Sentry')).toBe('Security Advisory Ivanti Sentry');
  });

  it('cuts a section at the next heading', () => {
    expect(sectionText(body, ['Solution'])).toBe('Update to the resolved version.');
    expect(sectionText(body, ['Mitigation', 'Mitigations'])).toBe('Restrict access.');
    expect(sectionText(body, ['Workaround'])).toBeUndefined();
  });
});

describe('parseCveTable', () => {
  it('reads score, severity and vector per CVE', () => {
    const rows = parseCveTable([[CVE_HEADER, ['CVE-2026-1281', 'A code injection.', '9.8 (Critical)', 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'CWE-94']]]);
    expect(rows).toEqual([{
      cve: 'CVE-2026-1281', description: 'A code injection.', score: 9.8, severity: 'CRITICAL', vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    }]);
  });
});

describe('normalizeArticle', () => {
  it('folds non-breaking spaces, which headers of some articles carry', () => {
    const folded = normalizeArticle(article({
      bodyText: 'Created Date',
      tables: [[['Product Name', 'Affected Version(s)'], ['Ivanti Sentry', 'R10.8.1 and prior']]],
    }));
    expect(folded.bodyText).toBe('Created Date');
    expect(folded.tables[0][0][1]).toBe('Affected Version(s)');
    expect(folded.tables[0][1]).toEqual(['Ivanti Sentry', 'R10.8.1 and prior']);
  });

  it('lets an article whose headers carry them build advisories (EPMM, CVE-2026-1281)', () => {
    const advisories = buildIvantiAdvisories(normalizeArticle(article({
      tables: [
        [CVE_HEADER, ['CVE-2026-1281', 'Code injection.', '9.8 (Critical)', 'v', 'CWE-94']],
        [['Product Name', 'Affected Version(s)', 'Resolved Version(s)'], ['Ivanti Endpoint Manager Mobile', '12.7.0.0 and prior', '12.7.0.1']],
      ],
    })));
    expect(advisories).toHaveLength(1);
    expect(advisories[0].affectedProducts).toEqual([
      expect.objectContaining({ product: 'Endpoint Manager Mobile', lastAffected: '12.7.0.0', versionFixed: '12.7.0.1' }),
    ]);
  });
});

describe('buildIvantiAdvisories', () => {
  it('builds one advisory per CVE with the product versions of the Affected Versions table (EPMM)', () => {
    const advisories = buildIvantiAdvisories(article({
      urlName: 'Security-Advisory-Ivanti-Endpoint-Manager-Mobile-EPMM-CVE-2026-1281-CVE-2026-1340',
      tables: [
        [CVE_HEADER,
          ['CVE-2026-1281', 'Code injection.', '9.8 (Critical)', 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'CWE-94'],
          ['CVE-2026-1340', 'Code injection.', '9.8 (Critical)', 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'CWE-94']],
        [['Product Name', 'Affected Version(s)', 'Affected CPE(s)', 'Resolved Version(s)', 'Patch Availability'],
          ['Ivanti Endpoint Manager Mobile', '12.5.0.0 and prior\n12.6.0.0 and prior\n12.7.0.0 and prior',
            'cpe:2.3:a:ivanti:endpoint_manager_mobile:12.7.0.0:*:*:*:*:*:*:*', '12.6.1.1, 12.7.0.1, 12.8.0.1', 'Download Portal (login required)']],
      ],
    }));

    expect(advisories.map(a => a.externalId)).toEqual([
      'Security-Advisory-Ivanti-Endpoint-Manager-Mobile-EPMM-CVE-2026-1281-CVE-2026-1340/CVE-2026-1281',
      'Security-Advisory-Ivanti-Endpoint-Manager-Mobile-EPMM-CVE-2026-1281-CVE-2026-1340/CVE-2026-1340',
    ]);
    const [first] = advisories;
    expect(first).toMatchObject({
      cveId: 'CVE-2026-1281', severity: 'CRITICAL', cvssScore: 9.8,
      summary: 'Security Advisory Ivanti Test (CVE-2026-0001)',
      solution: 'Update to the resolved version.', workaround: 'Restrict access.',
    });
    expect(first.publishedAt?.getUTCFullYear()).toBe(2026);
    expect(first.affectedProducts.every(p => p.vendor === 'ivanti' && p.product === 'Endpoint Manager Mobile')).toBe(true);
    expect(first.affectedProducts).toEqual(expect.arrayContaining([
      expect.objectContaining({ versionFixed: '12.7.0.1', lastAffected: '12.7.0.0', versionStart: '12.7.0', patchAvailable: true }),
      expect.objectContaining({ versionFixed: '12.6.1.1', lastAffected: '12.6.0.0', versionStart: '12.6.0', patchAvailable: true }),
    ]));
  });

  it('applies a row only to the CVEs its CVE column names (Connect Secure)', () => {
    const advisories = buildIvantiAdvisories(article({
      tables: [
        [CVE_HEADER,
          ['CVE-2025-0282', 'Stack overflow.', '9.0 (Critical)', 'v', 'CWE-121'],
          ['CVE-2025-0283', 'Stack overflow.', '7.0 (High)', 'v', 'CWE-121']],
        [['CVE', 'Product Name', 'Affected Version(s)', 'Affected CPE(s)', 'Resolved Version(s)', 'Patch Availability'],
          ['CVE-2025-0282', 'Ivanti Connect Secure', '22.7R2 through 22.7R2.4', 'cpe', '22.7R2.5', 'Download Portal'],
          ['CVE-2025-0283', 'Ivanti Connect Secure', '22.7R2.4 and prior,\n9.1R18.9 and prior', 'cpe', '22.7R2.5', 'Download Portal']],
      ],
    }));
    const by = (cve: string) => advisories.find(a => a.cveId === cve)!.affectedProducts;
    expect(by('CVE-2025-0282')).toEqual([
      { vendor: 'ivanti', product: 'Connect Secure', versionStart: '22.7R2', lastAffected: '22.7R2.4', versionFixed: '22.7R2.5', patchAvailable: true },
    ]);
    // The one fix is the upgrade target for the end-of-life 9.1 line too, and a
    // range open below 22.7R2.4 already covers 9.1R18.9.
    expect(by('CVE-2025-0283')).toEqual([
      { vendor: 'ivanti', product: 'Connect Secure', lastAffected: '22.7R2.4', versionFixed: '22.7R2.5', patchAvailable: true },
    ]);
  });

  it('skips an Ivanti-run cloud service row, whose fix no customer applies', () => {
    const advisories = buildIvantiAdvisories(article({
      tables: [
        [CVE_HEADER, ['CVE-2026-9614', 'XSS.', '6.1 (Medium)', 'v', 'CWE-79']],
        [['Product Name', 'Affected Version(s)', 'Resolved Version(s)', 'Patch Availability'],
          ['Ivanti Neurons for ITSM (Cloud / SaaS)', '2026.2', 'mo2026.2', 'The fix was applied to all cloud landscapes'],
          ['Ivanti Neurons for ITSM On-Prem', '2025.2, 2025.3', '2025.4', 'Download Available in ILS']],
      ],
    }));
    expect(advisories[0].affectedProducts).toEqual([
      expect.objectContaining({ product: 'Neurons for ITSM', versionStart: '2025.2', lastAffected: '2025.3', versionFixed: '2025.4' }),
    ]);
  });

  it('yields nothing for an article without a CVE table', () => {
    expect(buildIvantiAdvisories(article({ tables: [[['Step', 'Action'], ['1', 'Install']]] }))).toEqual([]);
  });
});
