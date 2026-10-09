import { describe, it, expect } from 'vitest';
import { buildLegacyIvantiAdvisories, IVANTI_LEGACY_ARTICLES } from './ivanti-legacy-advisories.js';
import { compareIvantiVersions, ivantiVersionToInt, parseIvantiVersion } from '../utils/ivanti-version.js';
import { productName } from './ivanti-fetcher.js';

const advisories = buildLegacyIvantiAdvisories();
const rows = advisories.flatMap(a => a.affectedProducts.map(p => ({ cve: a.cveId!, ...p })));
const cmp = (a: string, b: string) => compareIvantiVersions(parseIvantiVersion(a)!, parseIvantiVersion(b)!);

describe('curated Ivanti advisories', () => {
  it('covers the KEV entries no other source gave a fixed version for', () => {
    const cves = new Set(advisories.map(a => a.cveId));
    for (const cve of [
      'CVE-2019-11510', 'CVE-2019-11539', 'CVE-2020-8218', 'CVE-2020-8243', 'CVE-2020-8260',
      'CVE-2021-22893', 'CVE-2021-22894', 'CVE-2021-22899', 'CVE-2021-22900',
      'CVE-2023-46805', 'CVE-2024-21887', 'CVE-2024-21893', 'CVE-2023-38035',
    ]) expect(cves.has(cve), cve).toBe(true);
  });

  it('adds the Pulse Secure bulletins from 2019 on that name a version, and none from before', () => {
    const articles = new Set(advisories.map(a => a.externalId.split('/')[0]));
    for (const a of ['SA44019', 'SA44193', 'SA44503', 'SA44676', 'SA44800', 'SA44846', 'SA44858', 'SA44899', 'SA45520']) {
      expect(articles.has(a), a).toBe(true);
    }
    // 2018 and earlier, and the 2019+ notices that name no version.
    for (const a of ['SA43018', 'SA43730', 'SA43877', 'SA44328', 'SA44426', 'SA44440', 'SA44845']) {
      expect(articles.has(a), a).toBe(false);
    }
  });

  it('has one advisory per article and CVE, with unique ids and a source article', () => {
    const ids = advisories.map(a => a.externalId);
    expect(new Set(ids).size).toBe(ids.length);
    for (const a of advisories) {
      expect(a.externalId).toBe(`${a.url!.split('/').pop()}/${a.cveId}`);
      expect(a.url).toMatch(/^https:\/\/hub\.ivanti\.com\/s\/article\//);
      // A few articles give no score for a CVE; then there is no severity either.
      if (a.cvssScore !== undefined) expect(a.severity).toMatch(/^(CRITICAL|HIGH|MEDIUM|LOW)$/);
      else expect(a.severity).toBeUndefined();
      expect(a.affectedProducts.length, a.externalId).toBeGreaterThan(0);
    }
  });

  it('writes every version in a form Ivanti\'s version order can place', () => {
    for (const r of rows) {
      for (const v of [r.versionStart, r.lastAffected, r.versionFixed]) {
        if (v !== undefined) expect(parseIvantiVersion(v), `${r.cve} ${r.product} ${v}`).not.toBeNull();
      }
    }
  });

  it('never has a range that ends before it starts, and a fix above everything affected', () => {
    for (const r of rows) {
      if (r.versionStart && r.lastAffected) expect(cmp(r.versionStart, r.lastAffected), `${r.cve} ${r.product}`).toBeLessThanOrEqual(0);
      if (r.lastAffected && r.versionFixed) expect(cmp(r.lastAffected, r.versionFixed), `${r.cve} ${r.product}`).toBeLessThan(0);
      if (r.versionStart && r.versionFixed) expect(cmp(r.versionStart, r.versionFixed), `${r.cve} ${r.product}`).toBeLessThan(0);
    }
  });

  it('uses the product names the current template yields, so a search finds both', () => {
    const names = new Set(rows.map(r => r.product));
    for (const name of names) {
      // A name already in canonical form must come back unchanged.
      expect(productName(name), name).toBe(name);
    }
  });

  it('has a fix, or says why not, for every row', () => {
    for (const r of rows) {
      expect(r.versionFixed !== undefined || r.patchAvailable === true, `${r.cve} ${r.product}`).toBe(true);
    }
    // Sentry's fix is an RPM script per version: affected up to 9.18.0, no fixed release.
    expect(rows.filter(r => r.cve === 'CVE-2023-38035')).toEqual([
      expect.objectContaining({ product: 'Sentry', lastAffected: '9.18.0', versionFixed: undefined, patchAvailable: true }),
    ]);
  });
});

describe('what the curated ranges say, in Ivanti\'s version order', () => {
  const inRange = (cve: string, product: string, version: string) => {
    const v = ivantiVersionToInt(version)!;
    return rows.filter(r => r.cve === cve && r.product === product).some(r => {
      const start = r.versionStart ? ivantiVersionToInt(r.versionStart)! : undefined;
      const end = r.versionFixed ? ivantiVersionToInt(r.versionFixed)! : undefined;
      const last = r.lastAffected ? ivantiVersionToInt(r.lastAffected)! : undefined;
      if (start !== undefined && v < start) return false;
      if (end !== undefined) return v < end;
      return last === undefined || v <= last;
    });
  };

  it('CVE-2019-11510 affects 9.0R3.3 on Pulse Connect Secure, not the 9.0R3.4 fix', () => {
    expect(inRange('CVE-2019-11510', 'Pulse Connect Secure', '9.0R3.3')).toBe(true);
    expect(inRange('CVE-2019-11510', 'Pulse Connect Secure', '9.0R3.4')).toBe(false);
    expect(inRange('CVE-2019-11510', 'Pulse Connect Secure', '8.2R12')).toBe(true);
    expect(inRange('CVE-2019-11510', 'Pulse Connect Secure', '8.2R12.1')).toBe(false);
    // 8.1R is listed as not impacted for this CVE.
    expect(inRange('CVE-2019-11510', 'Pulse Connect Secure', '8.1R10')).toBe(false);
  });

  it('SA44588 / SA44601 / SA44516 fix everything below the named release', () => {
    expect(inRange('CVE-2020-8243', 'Pulse Connect Secure', '9.1R8.1')).toBe(true);
    expect(inRange('CVE-2020-8243', 'Pulse Connect Secure', '9.1R8.2')).toBe(false);
    expect(inRange('CVE-2020-8260', 'Pulse Policy Secure', '9.1R8.2')).toBe(true);
    expect(inRange('CVE-2020-8260', 'Pulse Policy Secure', '9.1R9')).toBe(false);
    expect(inRange('CVE-2020-8218', 'Pulse Connect Secure', '9.1R7')).toBe(true);
    expect(inRange('CVE-2020-8218', 'Pulse Connect Secure', '9.1R8')).toBe(false);
  });

  it('CVE-2021-22893 starts at 9.0R3; the other three SA44784 CVEs reach further down', () => {
    expect(inRange('CVE-2021-22893', 'Pulse Connect Secure', '9.0R2')).toBe(false);
    expect(inRange('CVE-2021-22893', 'Pulse Connect Secure', '9.1R11.3')).toBe(true);
    expect(inRange('CVE-2021-22893', 'Pulse Connect Secure', '9.1R11.4')).toBe(false);
    expect(inRange('CVE-2021-22894', 'Pulse Connect Secure', '9.0R2')).toBe(true);
  });

  it('the January 2024 patches cover their own R-train and not the patched build or later', () => {
    // 9.1R18.4 patches train 9.1R18; 9.1R18.3 and below are affected.
    expect(inRange('CVE-2023-46805', 'Connect Secure', '9.1R18.3')).toBe(true);
    expect(inRange('CVE-2023-46805', 'Connect Secure', '9.1R18.4')).toBe(false);
    // A first build of a train (22.2R3) fixes the line before it, and the next train has its own patch (22.2R4.1).
    expect(inRange('CVE-2023-46805', 'Connect Secure', '22.2R2')).toBe(true);
    expect(inRange('CVE-2023-46805', 'Connect Secure', '22.2R3')).toBe(false);
    expect(inRange('CVE-2023-46805', 'Connect Secure', '22.2R4')).toBe(true);
    expect(inRange('CVE-2023-46805', 'Connect Secure', '22.2R4.1')).toBe(false);
    // The two January articles fix different builds of the same train: 9.1R14.4 fixes CVE-2024-21893, 9.1R14.5 CVE-2023-46805.
    expect(inRange('CVE-2024-21893', 'Connect Secure', '9.1R14.4')).toBe(false);
    expect(inRange('CVE-2023-46805', 'Connect Secure', '9.1R14.4')).toBe(true);
    expect(inRange('CVE-2023-46805', 'Connect Secure', '9.1R14.5')).toBe(false);
  });

  it('the 2019-2022 bulletins fix the lines they name and not the fixed build', () => {
    // SA44019 / SA44193: a first build (9.1R3) fixes its line; 9.0 has its own fix (9.0R6, 9.0R5).
    expect(inRange('CVE-2019-1559', 'Pulse Connect Secure', '9.1R2')).toBe(true);
    expect(inRange('CVE-2019-1559', 'Pulse Connect Secure', '9.1R3')).toBe(false);
    expect(inRange('CVE-2019-1559', 'Pulse Connect Secure', '9.0R5')).toBe(true);
    expect(inRange('CVE-2019-1559', 'Pulse Connect Secure', '9.0R6')).toBe(false);
    expect(inRange('CVE-2019-11477', 'Pulse Policy Secure', '9.0R4')).toBe(true);
    expect(inRange('CVE-2019-11477', 'Pulse Policy Secure', '9.0R5')).toBe(false);
    // CVE-2019-11478 names one fix, 9.1R5, for everything.
    expect(inRange('CVE-2019-11478', 'Pulse Connect Secure', '9.0R4')).toBe(true);
    expect(inRange('CVE-2019-11478', 'Pulse Connect Secure', '9.1R5')).toBe(false);
    // SA44858 / SA44899.
    expect(inRange('CVE-2021-22937', 'Pulse Connect Secure', '9.1R11.4')).toBe(true);
    expect(inRange('CVE-2021-22937', 'Pulse Connect Secure', '9.1R12')).toBe(false);
    expect(inRange('CVE-2021-22965', 'Pulse Connect Secure', '9.1R12')).toBe(true);
    expect(inRange('CVE-2021-22965', 'Pulse Connect Secure', '9.1R12.1')).toBe(false);
    // SA44503 is a client-side flaw: the Windows Desktop Client, not the gateways.
    expect(inRange('CVE-2020-13162', 'Pulse Secure Desktop Client (Windows)', '9.1R5')).toBe(true);
    expect(inRange('CVE-2020-13162', 'Pulse Secure Desktop Client (Windows)', '9.1R6')).toBe(false);
    expect(inRange('CVE-2020-13162', 'Pulse Connect Secure', '9.1R5')).toBe(false);
  });

  it('SA45520 bounds each Connect Secure train by its own dot release, and the 22.2 line by 22.2R3', () => {
    expect(inRange('CVE-2022-35254', 'Connect Secure', '9.1R16.1')).toBe(true);
    expect(inRange('CVE-2022-35254', 'Connect Secure', '9.1R16.2')).toBe(false);
    expect(inRange('CVE-2022-35254', 'Connect Secure', '9.1R15.1')).toBe(true);
    expect(inRange('CVE-2022-35254', 'Connect Secure', '9.1R15.2')).toBe(false);
    expect(inRange('CVE-2022-35254', 'Connect Secure', '22.2R1')).toBe(true);
    // 22.2R3 and 22.2R4 are both fixed builds; the second must not pull the first back in.
    expect(inRange('CVE-2022-35254', 'Connect Secure', '22.2R3')).toBe(false);
    expect(inRange('CVE-2022-35254', 'Connect Secure', '22.2R4')).toBe(false);
    expect(inRange('CVE-2022-35254', 'Neurons for ZTA gateways', '22.2R1')).toBe(true);
    expect(inRange('CVE-2022-35254', 'Neurons for ZTA gateways', '22.3R1')).toBe(false);
  });

  it('Sentry CVE-2023-38035 is affected up to 9.18.0 and open below', () => {
    expect(inRange('CVE-2023-38035', 'Sentry', '9.18.0')).toBe(true);
    expect(inRange('CVE-2023-38035', 'Sentry', '9.12.1')).toBe(true);
    expect(inRange('CVE-2023-38035', 'Sentry', '9.19.0')).toBe(false);
  });
});

describe('source data', () => {
  it('names an article for each entry', () => {
    for (const a of IVANTI_LEGACY_ARTICLES) {
      expect(a.article.length).toBeGreaterThan(0);
      expect(a.cves.length).toBeGreaterThan(0);
    }
  });
});
