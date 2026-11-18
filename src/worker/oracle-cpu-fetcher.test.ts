import { describe, it, expect, vi, afterEach } from 'vitest';
import axios from 'axios';
import {
  advisoryIdsIn, buildCvrfProductMap, csafUrlFor, cvrfUrlFor, OracleCpuFetcher, parseCsaf, parseCvrf, recentAdvisoryIds, severityFromScore,
} from './oracle-cpu-fetcher.js';

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

describe('parseCvrf', () => {
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

describe('advisoryIdsIn', () => {
  it('takes CPU, CSPU and Security Alert pages, once each, in the order they appear', () => {
    const text = [
      'https://www.oracle.com/security-alerts/alert-cve-2026-114820.html',
      'https://www.oracle.com/security-alerts/cspunov2026.html',
      'https://www.oracle.com/security-alerts/cpuoct2026.html',
      '<a href="/security-alerts/cpuoct2026.html">again</a>',
      'https://www.oracle.com/security-alerts/cpujan2020.html',
    ].join('\n');
    expect(advisoryIdsIn(text)).toEqual(['alert-cve-2026-114820', 'cspunov2026', 'cpuoct2026', 'cpujan2020']);
  });

  it('leaves out pages that only look like advisories', () => {
    const text = [
      '/security-alerts/cpuarchive.html',
      '/security-alerts/cpuapr2024verbose.html',
      '/security-alerts/cve-2026-114820verbose.html',
      '/security-alerts/advisorymatrixglossary.html',
      '/security-alerts/public-vuln-to-advisory-mapping.html',
      '/docs/tech/security-alerts/cpuoct2026csaf.json',
      'https://www.example.com/cpuoct2026.html',
    ].join(' ');
    expect(advisoryIdsIn(text)).toEqual([]);
  });

  it('is empty for an empty text', () => {
    expect(advisoryIdsIn('')).toEqual([]);
  });
});

describe('csafUrlFor and cvrfUrlFor', () => {
  it('names a CPU or CSPU CSAF after it, and an alert CSAF without the "alert-"', () => {
    expect(csafUrlFor('cpuoct2026')).toBe('https://www.oracle.com/docs/tech/security-alerts/cpuoct2026csaf.json');
    expect(csafUrlFor('cspunov2026')).toBe('https://www.oracle.com/docs/tech/security-alerts/cspunov2026csaf.json');
    expect(csafUrlFor('alert-cve-2026-114820')).toBe('https://www.oracle.com/docs/tech/security-alerts/cve-2026-114820csaf.json');
  });

  it('has a CVRF only for the CPUs of 2020 to 2022', () => {
    expect(cvrfUrlFor('cpujan2020')).toBe('https://www.oracle.com/docs/tech/security-alerts/cpujan2020cvrf.xml');
    expect(cvrfUrlFor('cpuapr2022')).toBe('https://www.oracle.com/docs/tech/security-alerts/cpuapr2022cvrf.xml');
    expect(cvrfUrlFor('cpuoct2019')).toBeNull();
    expect(cvrfUrlFor('cpujan2023')).toBeNull();
    expect(cvrfUrlFor('cspunov2026')).toBeNull();
    expect(cvrfUrlFor('alert-cve-2021-44228')).toBeNull();
  });
});

describe('recentAdvisoryIds', () => {
  it('names the CSPU and the CPU of each of the last three months, newest first', () => {
    expect(recentAdvisoryIds(new Date('2026-11-18T09:00:00Z'))).toEqual([
      'cspunov2026', 'cpunov2026', 'cspuoct2026', 'cpuoct2026', 'cspusep2026', 'cpusep2026',
    ]);
  });

  it('runs back over the new year', () => {
    expect(recentAdvisoryIds(new Date('2027-01-05T00:00:00Z'))).toEqual([
      'cspujan2027', 'cpujan2027', 'cspudec2026', 'cpudec2026', 'cspunov2026', 'cpunov2026',
    ]);
  });

  it('takes the month count it is given', () => {
    expect(recentAdvisoryIds(new Date('2026-11-18T09:00:00Z'), 1)).toEqual(['cspunov2026', 'cpunov2026']);
  });
});

describe('OracleCpuFetcher.fetch', () => {
  afterEach(() => { vi.restoreAllMocks(); });

  const NOW = () => new Date('2026-11-18T09:00:00Z');
  const RSS = 'rss-otn-sec.xml';
  const MAP = 'public-vuln-to-advisory-mapping.html';
  const page = (id: string) => `https://www.oracle.com/security-alerts/${id}.html`;
  const rss = (ids: string[]) =>
    `<?xml version="1.0"?><rss><channel>${ids.map(id => `<item><title>${id}</title><link>${page(id)}</link></item>`).join('')}</channel></rss>`;
  const map = (ids: string[]) => `<html><body>${ids.map(id => `<a href="/security-alerts/${id}.html">${id}</a>`).join('')}</body></html>`;
  const csaf = (id: string, cve: string, product = 'Oracle Java SE Version 27.0.1.0.3') => ({
    document: { title: id, tracking: { id: `${id}csaf`, initial_release_date: '2026-11-17T13:00:00-07:00' } },
    product_tree: { branches: [{ category: 'vendor', name: 'Oracle', branches: [{ category: 'product_name', name: product, product: { name: product, product_id: 'P1' } }] }] },
    vulnerabilities: [{
      cve,
      notes: [{ category: 'summary', text: `Vulnerability in ${product}.` }],
      product_status: { known_affected: ['P1'] },
      scores: [{ products: ['P1'], cvss_v3: { baseScore: 8.1, baseSeverity: 'HIGH', vectorString: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H' } }],
    }],
  });
  const axiosError = (extra: Record<string, unknown>, message: string) => Object.assign(new Error(message), { isAxiosError: true, ...extra });
  const notFound = () => axiosError({ response: { status: 404 } }, 'Request failed with status code 404');
  const timeout = () => axiosError({ code: 'ECONNABORTED' }, 'timeout of 60000ms exceeded');
  const serverError = () => axiosError({ response: { status: 503 } }, 'Request failed with status code 503');

  /**
   * axios.get over a table: the first URL fragment that matches answers with its data or
   * throws its error; any URL nothing matches is a 404, as Oracle answers for a missing file.
   */
  function serve(table: Record<string, unknown | Error>) {
    return vi.spyOn(axios, 'get').mockImplementation(async (url: string) => {
      for (const [fragment, answer] of Object.entries(table)) {
        if (!url.includes(fragment)) continue;
        if (answer instanceof Error) throw answer;
        return { data: answer };
      }
      throw notFound();
    });
  }
  const urlsAsked = (get: ReturnType<typeof serve>) => get.mock.calls.map(([u]) => String(u));
  const fetcher = (opts: { latestOnly?: boolean } = {}) => new OracleCpuFetcher({ delayMs: 0, now: NOW, ...opts });

  it('reads a CPU, a CSPU and a Security Alert the feed lists, each from its CSAF', async () => {
    const get = serve({
      [RSS]: rss(['alert-cve-2026-114820', 'cspusep2026', 'cpuoct2026']),
      [MAP]: map([]),
      'cve-2026-114820csaf': csaf('cve-2026-114820', 'CVE-2026-114820'),
      'cspusep2026csaf': csaf('cspusep2026', 'CVE-2026-1001'),
      'cpuoct2026csaf': csaf('cpuoct2026', 'CVE-2026-1002'),
    });
    const f = fetcher();
    const advisories = await f.fetch();

    expect(advisories.map(a => a.externalId).sort()).toEqual([
      'alert-cve-2026-114820-CVE-2026-114820', 'cpuoct2026-CVE-2026-1002', 'cspusep2026-CVE-2026-1001',
    ]);
    const alert = advisories.find(a => a.cveId === 'CVE-2026-114820')!;
    expect(alert).toMatchObject({ url: page('alert-cve-2026-114820'), severity: 'HIGH', cvssScore: 8.1, rawData: { cpuId: 'alert-cve-2026-114820' } });
    expect(alert.affectedProducts).toEqual([{ vendor: 'oracle', product: 'Java SE', affectedVersions: ['27.0.1.0.3'], patchAvailable: true }]);
    // The alert's CSAF is cve-...csaf.json, never alert-cve-...csaf.json.
    expect(urlsAsked(get)).toContain('https://www.oracle.com/docs/tech/security-alerts/cve-2026-114820csaf.json');
    expect(urlsAsked(get).some(u => u.includes('alert-cve-2026-114820csaf'))).toBe(false);
    expect(f.fetchFailedCount()).toBe(0);
  });

  it('takes from the CVE map what the lagging feed does not list yet, alerts included', async () => {
    serve({
      [RSS]: rss(['cpuoct2026']),
      [MAP]: map(['cspunov2026', 'alert-cve-2026-109618', 'cpuoct2026']),
      'cspunov2026csaf': csaf('cspunov2026', 'CVE-2026-114938'),
      'cve-2026-109618csaf': csaf('cve-2026-109618', 'CVE-2026-109618', 'Oracle HTTP Server Version 14.1.2.0.0'),
      'cpuoct2026csaf': csaf('cpuoct2026', 'CVE-2026-1002'),
    });
    const advisories = await fetcher().fetch();
    expect(advisories.map(a => a.externalId).sort()).toEqual([
      'alert-cve-2026-109618-CVE-2026-109618', 'cpuoct2026-CVE-2026-1002', 'cspunov2026-CVE-2026-114938',
    ]);
  });

  it('asks for the latest months by name when neither list has them', async () => {
    serve({
      [RSS]: rss(['cpuoct2026']),
      [MAP]: map(['cpuoct2026']),
      'cpuoct2026csaf': csaf('cpuoct2026', 'CVE-2026-1002'),
      'cspunov2026csaf': csaf('cspunov2026', 'CVE-2026-114938'),
    });
    const f = fetcher();
    const advisories = await f.fetch();
    expect(advisories.find(a => a.cveId === 'CVE-2026-114938')).toMatchObject({
      externalId: 'cspunov2026-CVE-2026-114938', url: page('cspunov2026'), severity: 'HIGH', cvssScore: 8.1,
    });
    // The months with no advisory (cpunov2026, cspuoct2026, cspusep2026, cpusep2026) answer 404: no failure.
    expect(f.fetchFailedCount()).toBe(0);
  });

  it('reads each advisory once, however many lists name it', async () => {
    const get = serve({
      [RSS]: rss(['cpuoct2026', 'alert-cve-2026-114820']),
      [MAP]: map(['cpuoct2026', 'alert-cve-2026-114820']),
      'cpuoct2026csaf': csaf('cpuoct2026', 'CVE-2026-1002'), // also one of the recent months
      'cve-2026-114820csaf': csaf('cve-2026-114820', 'CVE-2026-114820'),
    });
    await fetcher().fetch();
    expect(urlsAsked(get).filter(u => u.endsWith('cpuoct2026csaf.json'))).toHaveLength(1);
    expect(urlsAsked(get).filter(u => u.endsWith('cve-2026-114820csaf.json'))).toHaveLength(1);
  });

  it('skips an alert or a CPU with no structured data (404) without counting it a failure', async () => {
    const get = serve({
      [RSS]: rss(['alert-cve-2021-44228', 'cpuoct2019', 'cpuoct2026']),
      [MAP]: map([]),
      'cpuoct2026csaf': csaf('cpuoct2026', 'CVE-2026-1002'),
    });
    const f = fetcher();
    const advisories = await f.fetch();
    expect(advisories.map(a => a.cveId)).toEqual(['CVE-2026-1002']);
    expect(f.fetchFailedCount()).toBe(0);
    // No CVRF is asked for where none can exist: an alert, a CPU before 2020.
    expect(urlsAsked(get).filter(u => u.endsWith('cvrf.xml'))).toEqual([]);
  });

  it('reads the CVRF of a 2020 to 2022 CPU that has no CSAF', async () => {
    const get = serve({
      [RSS]: rss(['cpuapr2020']),
      [MAP]: map([]),
      'cpuapr2020cvrf': sampleXml,
    });
    const f = fetcher();
    const advisories = await f.fetch();
    expect(advisories.map(a => a.externalId)).toEqual(['cpuapr2020-CVE-2015-3253']);
    expect(urlsAsked(get)).toContain('https://www.oracle.com/docs/tech/security-alerts/cpuapr2020csaf.json');
    expect(f.fetchFailedCount()).toBe(0);
  });

  it('falls back to the CVRF when the CSAF of a 2020 to 2022 CPU fails, and counts nothing when that works', async () => {
    serve({
      [RSS]: rss(['cpujul2021']),
      [MAP]: map([]),
      'cpujul2021csaf': timeout(),
      'cpujul2021cvrf': sampleXml,
    });
    const f = fetcher();
    expect((await f.fetch()).map(a => a.cveId)).toEqual(['CVE-2015-3253']);
    expect(f.fetchFailedCount()).toBe(0);
  });

  it('counts a failure other than 404, for a listed CPU, an alert or a month asked for by name', async () => {
    serve({
      [RSS]: rss(['cpuoct2026', 'alert-cve-2026-91403']),
      [MAP]: map([]),
      'cpuoct2026csaf': serverError(),
      'cve-2026-91403csaf': timeout(),
      'cspunov2026csaf': timeout(),
      'cpujul2026csaf': csaf('cpujul2026', 'CVE-2026-0001'), // not asked for: not listed, not recent
    });
    const f = fetcher();
    const advisories = await f.fetch();
    expect(advisories).toEqual([]);
    expect(f.fetchFailedCount()).toBe(3);
  });

  it('counts a CVRF that fails after a CSAF 404 as a failure', async () => {
    serve({
      [RSS]: rss(['cpuoct2021']),
      [MAP]: map([]),
      'cpuoct2021cvrf': serverError(),
    });
    const f = fetcher();
    await f.fetch();
    expect(f.fetchFailedCount()).toBe(1);
  });

  it('lists from the CVE map alone when the feed fails, and counts that', async () => {
    serve({
      [RSS]: serverError(),
      [MAP]: map(['cspunov2026']),
      'cspunov2026csaf': csaf('cspunov2026', 'CVE-2026-114938'),
    });
    const f = fetcher();
    expect((await f.fetch()).map(a => a.cveId)).toEqual(['CVE-2026-114938']);
    expect(f.fetchFailedCount()).toBe(1);
  });

  it('lists from the feed alone when the CVE map fails, and counts that', async () => {
    serve({
      [RSS]: rss(['cpuoct2026']),
      [MAP]: timeout(),
      'cpuoct2026csaf': csaf('cpuoct2026', 'CVE-2026-1002'),
    });
    const f = fetcher();
    expect((await f.fetch()).map(a => a.cveId)).toEqual(['CVE-2026-1002']);
    expect(f.fetchFailedCount()).toBe(1);
  });

  it('fails when neither the feed nor the CVE map can be read', async () => {
    serve({ [RSS]: serverError(), [MAP]: timeout() });
    await expect(fetcher().fetch()).rejects.toThrow('503');
  });

  it('starts each run with no failures counted', async () => {
    serve({ [RSS]: rss(['cpuoct2026']), [MAP]: timeout(), 'cpuoct2026csaf': csaf('cpuoct2026', 'CVE-2026-1002') });
    const f = fetcher();
    await f.fetch();
    expect(f.fetchFailedCount()).toBe(1);
    vi.restoreAllMocks();
    serve({ [RSS]: rss(['cpuoct2026']), [MAP]: map([]), 'cpuoct2026csaf': csaf('cpuoct2026', 'CVE-2026-1002') });
    await f.fetch();
    expect(f.fetchFailedCount()).toBe(0);
  });

  describe('latest only', () => {
    it('reads the newest CPU or CSPU of the feed and nothing else: no alert, no CVE map, no month by name', async () => {
      const get = serve({
        [RSS]: rss(['alert-cve-2026-114820', 'cspunov2026', 'cpuoct2026']),
        'cspunov2026csaf': csaf('cspunov2026', 'CVE-2026-114938'),
      });
      const advisories = await fetcher({ latestOnly: true }).fetch();
      expect(advisories.map(a => a.externalId)).toEqual(['cspunov2026-CVE-2026-114938']);
      expect(urlsAsked(get)).toEqual([
        'https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/rss-otn-sec.xml',
        'https://www.oracle.com/docs/tech/security-alerts/cspunov2026csaf.json',
      ]);
    });

    it('fails when the feed cannot be read', async () => {
      serve({ [RSS]: timeout() });
      await expect(fetcher({ latestOnly: true }).fetch()).rejects.toThrow('timeout');
    });

    it('reads nothing when the feed lists no CPU or CSPU', async () => {
      serve({ [RSS]: rss(['alert-cve-2026-114820']) });
      expect(await fetcher({ latestOnly: true }).fetch()).toEqual([]);
    });
  });

  it('is a complete snapshot unless it reads only the latest', () => {
    expect(fetcher().isCompleteSnapshot()).toBe(true);
    expect(fetcher({ latestOnly: true }).isCompleteSnapshot()).toBe(false);
  });
});

describe('parseCsaf summary', () => {
  const doc = (notes: Array<{ category: string; text: string }> | undefined) => ({
    document: { title: 't', tracking: { id: 'cspunov2026csaf' } },
    product_tree: { branches: [{ category: 'vendor', name: 'Oracle', branches: [{ category: 'product_name', name: 'Oracle APEX Version 24.1.22', product: { name: 'Oracle APEX Version 24.1.22', product_id: 'P1' } }] }] },
    vulnerabilities: [{ cve: 'CVE-2026-1', notes, product_status: { known_affected: ['P1'] } }],
  });

  it("takes Oracle's first description note, as Oracle writes one per product and no summary", () => {
    const [adv] = parseCsaf(doc([
      { category: 'description', text: '  Vulnerability in the Oracle APEX product of Oracle APEX (component: General).  ' },
      { category: 'description', text: 'Vulnerability in the Oracle Solaris product of Oracle Systems.' },
    ]), 'cspunov2026');
    expect(adv.summary).toBe('Vulnerability in the Oracle APEX product of Oracle APEX (component: General).');
  });

  it('prefers a summary note when there is one', () => {
    const [adv] = parseCsaf(doc([
      { category: 'description', text: 'A description.' },
      { category: 'summary', text: 'A summary.' },
    ]), 'cspunov2026');
    expect(adv.summary).toBe('A summary.');
  });

  it('skips an empty description, and falls back to the advisory and CVE when there is no text', () => {
    expect(parseCsaf(doc([{ category: 'description', text: '  ' }, { category: 'description', text: 'Second.' }]), 'cspunov2026')[0].summary).toBe('Second.');
    expect(parseCsaf(doc(undefined), 'cspunov2026')[0].summary).toBe('CSPUNOV2026: CVE-2026-1');
    expect(parseCsaf(doc([{ category: 'general', text: 'Not a description.' }]), 'cspunov2026')[0].summary).toBe('CSPUNOV2026: CVE-2026-1');
  });
});
