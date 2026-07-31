import { describe, it, expect } from 'vitest';
import { buildCvrfProductMap, parseCvrf, severityFromScore } from './oracle-cpu-fetcher.js';

describe('severityFromScore', () => {
  it('maps CVSS v3 base scores to severity bands', () => {
    expect(severityFromScore(9.8)).toBe('CRITICAL');
    expect(severityFromScore(9.0)).toBe('CRITICAL');
    expect(severityFromScore(8.9)).toBe('HIGH');
    expect(severityFromScore(7.0)).toBe('HIGH');
    expect(severityFromScore(6.9)).toBe('MEDIUM');
    expect(severityFromScore(4.0)).toBe('MEDIUM');
    expect(severityFromScore(3.9)).toBe('LOW');
    expect(severityFromScore(0.1)).toBe('LOW');
    expect(severityFromScore(0)).toBeUndefined();
    expect(severityFromScore(undefined)).toBeUndefined();
  });
});

describe('buildCvrfProductMap', () => {
  it('associates ProductID with the nearest ancestor Product Name / Product Version branches', () => {
    const root = {
      '@_Name': 'Oracle',
      '@_Type': 'Vendor',
      Branch: {
        '@_Name': 'Communications ASAP Cartridges',
        '@_Type': 'Product Name',
        Branch: [
          {
            '@_Name': '7.2',
            '@_Type': 'Product Version',
            FullProductName: { '#text': 'Communications ASAP Cartridges Version 7.2', '@_ProductID': 'P-1-7.2' },
          },
          {
            '@_Name': '7.3',
            '@_Type': 'Product Version',
            FullProductName: { '#text': 'Communications ASAP Cartridges Version 7.3', '@_ProductID': 'P-1-7.3' },
          },
        ],
      },
    };

    const map = buildCvrfProductMap(root);
    expect(map.get('P-1-7.2')).toEqual({ product: 'Communications ASAP Cartridges', version: '7.2' });
    expect(map.get('P-1-7.3')).toEqual({ product: 'Communications ASAP Cartridges', version: '7.3' });
  });

  it('returns an empty map when root is undefined', () => {
    expect(buildCvrfProductMap(undefined).size).toBe(0);
  });
});

describe('parseCvrf', () => {
  const sampleXml = `<?xml version='1.0' encoding='UTF-8'?>
<cvrf:cvrfdoc xmlns="http://www.icasi.org/CVRF/schema/cvrf/1.1" xmlns:cvrf="http://www.icasi.org/CVRF/schema/cvrf/1.1">
  <DocumentTracking>
    <InitialReleaseDate>2020-04-14T13:00:00-07:00</InitialReleaseDate>
  </DocumentTracking>
  <ProductTree xmlns="http://www.icasi.org/CVRF/schema/prod/1.1">
    <Branch Name="Oracle" Type="Vendor">
      <Branch Name="Communications Services Gatekeeper" Type="Product Name">
        <Branch Name="6.1" Type="Product Version">
          <FullProductName ProductID="P-5381V-6.1">Communications Services Gatekeeper Version 6.1</FullProductName>
        </Branch>
      </Branch>
    </Branch>
  </ProductTree>
  <Vulnerability Ordinal="1" xmlns="http://www.icasi.org/CVRF/schema/vuln/1.1">
    <Title>CVE-2015-3253</Title>
    <Notes>
      <Note Audience="All" Ordinal="1" Title="Details" Type="Details">Vulnerability in Oracle Communications Services Gatekeeper.</Note>
    </Notes>
    <CVE>CVE-2015-3253</CVE>
    <ProductStatuses>
      <Status Type="Known Affected">
        <ProductID>P-5381V-6.1</ProductID>
      </Status>
    </ProductStatuses>
    <CVSSScoreSets>
      <ScoreSet>
        <BaseScore>  9.8</BaseScore>
        <Vector>AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</Vector>
      </ScoreSet>
    </CVSSScoreSets>
  </Vulnerability>
</cvrf:cvrfdoc>`;

  it('parses a CVRF document into NormalizedAdvisory entries', () => {
    const results = parseCvrf(sampleXml, 'cpuapr2020');
    expect(results).toHaveLength(1);
    const adv = results[0];
    expect(adv.externalId).toBe('cpuapr2020-CVE-2015-3253');
    expect(adv.cveId).toBe('CVE-2015-3253');
    expect(adv.cvssScore).toBe(9.8);
    expect(adv.severity).toBe('CRITICAL');
    expect(adv.summary).toBe('Vulnerability in Oracle Communications Services Gatekeeper.');
    expect(adv.affectedProducts).toEqual([
      { vendor: 'oracle', product: 'Communications Services Gatekeeper', affectedVersions: ['6.1'], patchAvailable: true },
    ]);
    expect(adv.publishedAt).toEqual(new Date('2020-04-14T13:00:00-07:00'));
  });

  it('skips vulnerabilities with no CVE ID or no resolvable affected products', () => {
    const noCve = sampleXml.replace('<CVE>CVE-2015-3253</CVE>', '');
    expect(parseCvrf(noCve, 'cpuapr2020')).toHaveLength(0);
  });

  it('merges affected products when the same CVE appears in multiple <Vulnerability> elements', () => {
    const xml = `<?xml version='1.0' encoding='UTF-8'?>
<cvrf:cvrfdoc xmlns="http://www.icasi.org/CVRF/schema/cvrf/1.1" xmlns:cvrf="http://www.icasi.org/CVRF/schema/cvrf/1.1">
  <DocumentTracking><InitialReleaseDate>2020-04-14T13:00:00-07:00</InitialReleaseDate></DocumentTracking>
  <ProductTree xmlns="http://www.icasi.org/CVRF/schema/prod/1.1">
    <Branch Name="Oracle" Type="Vendor">
      <Branch Name="Product A" Type="Product Name">
        <Branch Name="1.0" Type="Product Version">
          <FullProductName ProductID="P-A-1.0">Product A Version 1.0</FullProductName>
        </Branch>
      </Branch>
      <Branch Name="Product B" Type="Product Name">
        <Branch Name="2.0" Type="Product Version">
          <FullProductName ProductID="P-B-2.0">Product B Version 2.0</FullProductName>
        </Branch>
      </Branch>
    </Branch>
  </ProductTree>
  <Vulnerability Ordinal="1" xmlns="http://www.icasi.org/CVRF/schema/vuln/1.1">
    <Title>CVE-2099-0001</Title>
    <CVE>CVE-2099-0001</CVE>
    <ProductStatuses><Status Type="Known Affected"><ProductID>P-A-1.0</ProductID></Status></ProductStatuses>
    <CVSSScoreSets><ScoreSet><BaseScore>5.0</BaseScore><Vector>V1</Vector></ScoreSet></CVSSScoreSets>
  </Vulnerability>
  <Vulnerability Ordinal="2" xmlns="http://www.icasi.org/CVRF/schema/vuln/1.1">
    <Title>CVE-2099-0001</Title>
    <CVE>CVE-2099-0001</CVE>
    <ProductStatuses><Status Type="Known Affected"><ProductID>P-B-2.0</ProductID></Status></ProductStatuses>
    <CVSSScoreSets><ScoreSet><BaseScore>9.1</BaseScore><Vector>V2</Vector></ScoreSet></CVSSScoreSets>
  </Vulnerability>
</cvrf:cvrfdoc>`;

    const results = parseCvrf(xml, 'cpuapr2020');
    expect(results).toHaveLength(1);
    expect(results[0].affectedProducts).toEqual([
      { vendor: 'oracle', product: 'Product A', affectedVersions: ['1.0'], patchAvailable: true },
      { vendor: 'oracle', product: 'Product B', affectedVersions: ['2.0'], patchAvailable: true },
    ]);
    // Highest CVSS score across the merged occurrences wins.
    expect(results[0].cvssScore).toBe(9.1);
    expect(results[0].cvssVector).toBe('V2');
  });
});
