import { describe, it, expect } from 'vitest';
import {
  buildCitrixAdvisories, htmlToLines, parseAffectedLines, parseCveTable, productNames, articleTitle,
} from './citrix-fetcher.js';
import { citrixVersionToInt } from '../utils/citrix-version.js';

// Bulletin HTML in the shape of the real ones, with their wording.
const row = (cells: string[]) => `<tr>${cells.map(c => `<td>${c}</td>`).join('')}</tr>`;
const bulletin = (title: string, body: string, table = '') =>
  `<html><head><title>${title}</title></head><body>${body}${table}</body></html>`;

const CVE_TABLE = `<table>
  <tr><th>CVE-ID</th><th>Description</th><th>Pre-conditions</th><th>CWE</th><th>CVSSv4</th></tr>
  ${row(['CVE-2026-19489', 'Memory overflow vulnerability leading to Denial of Service', 'SIP ALG should be enabled', 'CWE-119', 'CVSS v4.0 Base Score: 8.8<br>(CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/<br>VC:L/VI:L/VA:H/SC:N/SI:N/SA:L)'])}
  ${row(['CVE-2026-19490', 'Authentication bypass using an alternate path', 'The appliance must be configured as a Gateway', 'CWE-288', 'CVSS v4.0 Base Score: 9.3<br>(CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/<br>VC:H/VI:H/VA:H/SC:L/SI:L/SA:L)'])}
</table>`;

const RECENT = bulletin(
  'NetScaler ADC and NetScaler Gateway Security Bulletin for CVE-2026-19489 and CVE-2026-19490',
  `<p>Severity of Bulletin: Critical</p>
   <p>Affected Versions:</p>
   <p>The following supported versions of NetScaler ADC and NetScaler Gateway are affected by the vulnerabilities:</p>
   <p>NetScaler ADC and NetScaler Gateway 14.1 BEFORE 14.1-73.32</p>
   <p>NetScaler ADC and NetScaler Gateway 13.1 BEFORE 13.1-63.21</p>
   <p>NetScaler ADC FIPS BEFORE 14.1-73.32 FIPS</p>
   <p>NetScaler ADC FIPS and NDcPP BEFORE 13.1-37.277</p>
   <p>Note: NetScaler ADC and NetScaler Gateway versions 12.1 and 13.0 are now End Of Life (EOL) and are vulnerable.</p>`,
  CVE_TABLE + `<p>What Customers Should Do</p><p>Install the relevant updated versions as soon as possible.</p>`,
);

describe('htmlToLines', () => {
  it('breaks lines at block ends, folds non-breaking spaces and decodes entities', () => {
    expect(htmlToLines('<p>NetScaler&nbsp;ADC 14.1</p><p>a &amp; b</p>')).toEqual(['NetScaler ADC 14.1', 'a & b']);
  });
});

describe('productNames', () => {
  it('splits "A and B" and gives the old Citrix names their NetScaler name', () => {
    expect(productNames('NetScaler ADC and NetScaler Gateway', false)).toEqual(['NetScaler ADC', 'NetScaler Gateway']);
    expect(productNames('Citrix ADC and Citrix Gateway', false)).toEqual(['NetScaler ADC', 'NetScaler Gateway']);
  });

  it('files the FIPS / NDcPP builds under a product of their own, since they run on their own numbering', () => {
    expect(productNames('NetScaler ADC', true)).toEqual(['NetScaler ADC FIPS and NDcPP']);
    // Only the ADC has FIPS builds.
    expect(productNames('NetScaler ADC and NetScaler Gateway', true)).toEqual(['NetScaler ADC FIPS and NDcPP', 'NetScaler Gateway']);
  });

  it('finds the product behind a lead-in, and the Console / Agent / SDX products', () => {
    expect(productNames('Note: NetScaler ADC and NetScaler Gateway', false)).toEqual(['NetScaler ADC', 'NetScaler Gateway']);
    expect(productNames('NetScaler Console', false)).toEqual(['NetScaler Console']);
    expect(productNames('NetScaler SDX (SVM)', false)).toEqual(['NetScaler SDX (SVM)']);
    expect(productNames('NetScaler Agent', false)).toEqual(['NetScaler Agent']);
  });
});

describe('parseAffectedLines', () => {
  it('reads "<products> <branch> BEFORE <fixed build>", in either case', () => {
    const { affected } = parseAffectedLines([
      'NetScaler ADC and NetScaler Gateway 14.1 BEFORE 14.1-73.32',
      'Citrix ADC and Citrix Gateway 13.0 before 13.0-85.19',
    ]);
    expect(affected).toEqual([
      { product: 'NetScaler ADC', branch: '14.1', fixed: '14.1-73.32', cves: undefined },
      { product: 'NetScaler Gateway', branch: '14.1', fixed: '14.1-73.32', cves: undefined },
      { product: 'NetScaler ADC', branch: '13.0', fixed: '13.0-85.19', cves: undefined },
      { product: 'NetScaler Gateway', branch: '13.0', fixed: '13.0-85.19', cves: undefined },
    ]);
  });

  it('reads a fixed build written with a dot (12.1.65.21) as 12.1-65.21', () => {
    const { affected } = parseAffectedLines(['Citrix ADC and Citrix Gateway 12.1 before 12.1.65.21']);
    expect(affected.map(a => `${a.product}|${a.branch}|${a.fixed}`)).toEqual([
      'NetScaler ADC|12.1|12.1-65.21',
      'NetScaler Gateway|12.1|12.1-65.21',
    ]);
  });

  it('limits the lines under a "CVE-x:" heading to that CVE and reads a single affected build', () => {
    const { affected } = parseAffectedLines([
      'CVE-2026-3055:',
      'NetScaler ADC and NetScaler Gateway 14.1 BEFORE 14.1-60.58',
      'CVE-2026-4368:',
      'NetScaler ADC and NetScaler Gateway 14.1-66.54',
      'Note : CVE-2026-4368 only impacts build version 14.1-66.54.',
      'What Customers Should Do',
      'NetScaler ADC and NetScaler Gateway 14.1-66.59',
    ]);
    expect(affected).toEqual([
      { product: 'NetScaler ADC', branch: '14.1', fixed: '14.1-60.58', cves: ['CVE-2026-3055'] },
      { product: 'NetScaler Gateway', branch: '14.1', fixed: '14.1-60.58', cves: ['CVE-2026-3055'] },
      { product: 'NetScaler ADC', branch: '14.1', fixed: '14.1-66.54', cves: ['CVE-2026-4368'], onlyBuild: '14.1-66.54' },
      { product: 'NetScaler Gateway', branch: '14.1', fixed: '14.1-66.54', cves: ['CVE-2026-4368'], onlyBuild: '14.1-66.54' },
    ]);
  });

  it('reads the FIPS / NDcPP lines, with or without a branch in front and a label after', () => {
    const { affected } = parseAffectedLines([
      'NetScaler ADC 13.1-FIPS before 13.1-37.159',
      'NetScaler ADC 12.1-NDcPP before 12.1-55.297',
      'NetScaler ADC FIPS BEFORE 14.1-73.32 FIPS',
      'NetScaler ADC 13.1-FIPS and NDcPP BEFORE 13.1-37.235-FIPS and NDcPP',
    ]);
    expect(affected.map(a => `${a.product}|${a.branch}|${a.fixed}`)).toEqual([
      'NetScaler ADC FIPS and NDcPP|13.1|13.1-37.159',
      'NetScaler ADC FIPS and NDcPP|12.1|12.1-55.297',
      'NetScaler ADC FIPS and NDcPP|14.1|14.1-73.32',
      'NetScaler ADC FIPS and NDcPP|13.1|13.1-37.235',
    ]);
  });

  it('ignores lines that are not about a NetScaler product or have no fixed build', () => {
    const { affected } = parseAffectedLines([
      'The following supported versions of NetScaler ADC are affected by the vulnerabilities:',
      'Citrix Workspace app 2307 before 2307.1',
      'Customers should upgrade before 2026-10-01',
      'NetScaler ADC and NetScaler Gateway version 13.1 is unaffected',
    ]);
    expect(affected).toEqual([]);
  });

  it('reads an end-of-life branch the bulletin calls vulnerable', () => {
    const { endOfLife } = parseAffectedLines([
      'Note: NetScaler ADC and NetScaler Gateway versions 12.1 and 13.0 are now End Of Life (EOL) and are vulnerable.',
    ]);
    expect(endOfLife.map(e => `${e.product}|${e.branch}`)).toEqual([
      'NetScaler ADC|12.1', 'NetScaler ADC|13.0', 'NetScaler Gateway|12.1', 'NetScaler Gateway|13.0',
    ]);
  });

  it('limits the lines after "affected by CVE-x :" to those CVEs (the Console bulletin)', () => {
    const { affected } = parseAffectedLines([
      'The following supported version of NetScaler Console (formerly NetScaler ADM) is affected by CVE-2024-6235 :',
      'NetScaler Console 14.1 before 14.1-25.53',
      'The following supported versions of NetScaler Console, NetScaler Agent and NetScaler SDX (SVM) are affected by CVE-2024-6236 :',
      'NetScaler Console 13.1 before 13.1-53.22',
      'NetScaler SDX (SVM) 13.1 before 13.1-53.17',
    ]);
    expect(affected).toEqual([
      { product: 'NetScaler Console', branch: '14.1', fixed: '14.1-25.53', cves: ['CVE-2024-6235'] },
      { product: 'NetScaler Console', branch: '13.1', fixed: '13.1-53.22', cves: ['CVE-2024-6236'] },
      { product: 'NetScaler SDX (SVM)', branch: '13.1', fixed: '13.1-53.17', cves: ['CVE-2024-6236'] },
    ]);
  });
});

describe('parseCveTable', () => {
  it('reads the CVE, description, CVSS v4 score and vector', () => {
    expect(parseCveTable(RECENT)).toEqual([
      { cve: 'CVE-2026-19489', description: 'Memory overflow vulnerability leading to Denial of Service', score: 8.8, vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:L' },
      { cve: 'CVE-2026-19490', description: 'Authentication bypass using an alternate path', score: 9.3, vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L' },
    ]);
  });

  it('reads a table without a CVSS column (older bulletins)', () => {
    const html = `<table><tr><th>CVE-ID</th><th>Description</th><th>CWE</th></tr>${row(['CVE-2022-27510', 'Unauthorized access to Gateway user capabilities', 'CWE-288'])}</table>`;
    expect(parseCveTable(html)).toEqual([{ cve: 'CVE-2022-27510', description: 'Unauthorized access to Gateway user capabilities', score: undefined, vector: undefined }]);
  });
});

describe('buildCitrixAdvisories', () => {
  const advisories = buildCitrixAdvisories({ id: 'CTX696939', url: 'https://support.citrix.com/external/article/CTX696939/x.html', html: RECENT });

  it('builds one advisory per CVE with the bulletin\'s title, score, severity and link', () => {
    expect(advisories.map(a => a.externalId)).toEqual(['CTX696939/CVE-2026-19489', 'CTX696939/CVE-2026-19490']);
    expect(advisories[1]).toMatchObject({
      cveId: 'CVE-2026-19490', cvssScore: 9.3, severity: 'CRITICAL',
      summary: 'NetScaler ADC and NetScaler Gateway Security Bulletin for CVE-2026-19489 and CVE-2026-19490',
      url: 'https://support.citrix.com/external/article/CTX696939/x.html',
    });
    expect(advisories[0].severity).toBe('HIGH');
  });

  it('gives each product and branch its first fixed build as the end of the range', () => {
    const rows = advisories[0].affectedProducts.filter(p => p.versionFixed);
    expect(rows.map(r => `${r.product}|${r.versionStart}|${r.versionFixed}`)).toEqual([
      'NetScaler ADC|14.1|14.1-73.32',
      'NetScaler Gateway|14.1|14.1-73.32',
      'NetScaler ADC|13.1|13.1-63.21',
      'NetScaler Gateway|13.1|13.1-63.21',
      'NetScaler ADC FIPS and NDcPP|14.1|14.1-73.32',
      'NetScaler ADC FIPS and NDcPP|13.1|13.1-37.277',
    ]);
    expect(rows.every(r => r.vendor === 'citrix' && r.patchAvailable === true)).toBe(true);
  });

  it('marks an end-of-life branch as affected with no fix, and does not mark the branch of a supported line', () => {
    const eol = advisories[0].affectedProducts.filter(p => p.fixStatus === 'out_of_support');
    expect(eol.map(r => `${r.product}|${r.versionStart}..${r.versionEnd}`)).toEqual([
      'NetScaler ADC|12.1..12.2', 'NetScaler ADC|13.0..13.1', 'NetScaler Gateway|12.1..12.2', 'NetScaler Gateway|13.0..13.1',
    ]);
    expect(eol.every(r => r.versionFixed === undefined)).toBe(true);
  });

  it('gives each CVE only the lines meant for it (Console bulletin)', () => {
    const html = bulletin(
      'NetScaler Console, Agent and SDX (SVM) Security Bulletin for CVE-2024-6235 and CVE-2024-6236',
      `<p>The following supported version of NetScaler Console is affected by CVE-2024-6235 :</p>
       <p>NetScaler Console 14.1 before 14.1-25.53</p>
       <p>The following supported versions of NetScaler Console and NetScaler SDX (SVM) are affected by CVE-2024-6236 :</p>
       <p>NetScaler Console 13.1 before 13.1-53.22</p>
       <p>NetScaler SDX (SVM) 13.1 before 13.1-53.17</p>`,
      `<table><tr><th>CVE-ID</th><th>Description</th></tr>${row(['CVE-2024-6235', 'Sensitive information disclosure'])}${row(['CVE-2024-6236', 'Denial of service'])}</table>`,
    );
    const [a, b] = buildCitrixAdvisories({ id: 'CTX677998', url: 'u', html });
    expect(a.affectedProducts.map(p => `${p.product}|${p.versionFixed}`)).toEqual(['NetScaler Console|14.1-25.53']);
    expect(b.affectedProducts.map(p => `${p.product}|${p.versionFixed}|${p.fixStatus ?? ''}`)).toEqual(['NetScaler Console|13.1-53.22|', 'NetScaler SDX (SVM)|13.1-53.17|']);
  });

  it('falls back to the CVEs in the title when the page has no CVE table, and to the bulletin severity', () => {
    const html = bulletin('Citrix ADC and Citrix Gateway Security Bulletin for CVE-2023-3519', '<p>Severity of Bulletin: Critical</p><p>Citrix ADC and Citrix Gateway 13.1 before 13.1-49.13</p>');
    const [a] = buildCitrixAdvisories({ id: 'CTX561482', url: 'u', html });
    expect(a).toMatchObject({ cveId: 'CVE-2023-3519', severity: 'CRITICAL', cvssScore: undefined });
    expect(a.affectedProducts).toHaveLength(2);
  });

  it('yields nothing for a page that names no CVE', () => {
    expect(buildCitrixAdvisories({ id: 'CTX1', url: 'u', html: bulletin('NetScaler release notes', '<p>NetScaler ADC 14.1 before 14.1-1.1</p>') })).toEqual([]);
  });

  it('writes versions the NetScaler order can encode, which keeps the fixed build out of its own range', () => {
    const r = advisories[0].affectedProducts.find(p => p.product === 'NetScaler ADC' && p.versionFixed === '14.1-73.32')!;
    const fixed = citrixVersionToInt(r.versionFixed!)!;
    const start = citrixVersionToInt(r.versionStart!)!;
    expect(citrixVersionToInt('14.1-73.31')!).toBeLessThan(fixed);
    expect(citrixVersionToInt('14.1-73.31')!).toBeGreaterThanOrEqual(start);
    expect(fixed).not.toBeLessThan(fixed);
  });
});

describe('articleTitle', () => {
  it('takes the page title, or the first "Security Bulletin" line when the title is empty', () => {
    expect(articleTitle('<title> Citrix ADC Security Update (CVE-2019-0140) </title>', [])).toBe('Citrix ADC Security Update (CVE-2019-0140)');
    expect(articleTitle('<title></title>', ['x', 'NetScaler Security Bulletin for CVE-2025-1'])).toBe('NetScaler Security Bulletin for CVE-2025-1');
  });
});
