import { describe, it, expect } from 'vitest';
import {
  fixForRange,
  normalizeWordfenceFeed,
  normalizeWordfenceRecord,
  wordfenceProducts,
  WordfenceFetcher,
  type WordfenceRecord,
  type WordfenceSoftware,
} from './wordfence-fetcher.js';

// Shaped after real records of the v3 production feed (2026-11-28).
const COPYRIGHTS = {
  message: 'This record contains material that is subject to copyright',
  defiant: { notice: 'Copyright 2012-2026 Defiant Inc.', license: 'Defiant hereby grants you ...', license_url: 'https://www.wordfence.com/wordfence-intelligence-terms-and-conditions/' },
  mitre: { notice: 'Copyright 1999-2026 The MITRE Corporation', license: 'CVE Usage: MITRE hereby grants you ...', license_url: 'https://www.cve.org/Legal/TermsOfUse' },
};

const wpvivid: WordfenceRecord = {
  id: '000229b1-9ea9-4303-a79b-9ff24d1a8532',
  title: 'WPvivid < 0.9.138 - Authenticated (Administrator+) Path Traversal',
  software: [{
    type: 'plugin',
    name: 'WPvivid',
    slug: 'wpvivid-backuprestore',
    affected_versions: { '[*, 0.9.138)': { from_version: '*', from_inclusive: true, to_version: '0.9.138', to_inclusive: false } },
    patched: true,
    patched_versions: ['0.9.138'],
    remediation: 'Update to version 0.9.138, or a newer patched version',
  }],
  description: 'The WPvivid plugin for WordPress is vulnerable to Path Traversal ...',
  references: ['https://www.wordfence.com/threat-intel/vulnerabilities/id/000229b1-9ea9-4303-a79b-9ff24d1a8532?source=api-prod'],
  cvss: { vector: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N', score: 4.9, rating: 'Medium' },
  cve: 'CVE-2026-115426',
  published: '2026-11-04 00:00:00',
  copyrights: COPYRIGHTS,
};

const core = (ranges: WordfenceSoftware['affected_versions'], patched_versions: string[]): WordfenceSoftware => ({
  type: 'core', name: 'WordPress', slug: 'wordpress', affected_versions: ranges, patched: true, patched_versions,
});

describe('normalizeWordfenceRecord', () => {
  it('maps a plugin record to one advisory with a row per range, keeping the record whole', () => {
    const { advisory, skippedRanges } = normalizeWordfenceRecord(wpvivid);
    expect(skippedRanges).toBe(0);
    expect(advisory).toMatchObject({
      externalId: wpvivid.id,
      cveId: 'CVE-2026-115426',
      summary: wpvivid.title,
      severity: 'MEDIUM',
      cvssScore: 4.9,
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N',
      url: 'https://www.wordfence.com/threat-intel/vulnerabilities/id/000229b1-9ea9-4303-a79b-9ff24d1a8532',
      solution: 'Update to version 0.9.138, or a newer patched version',
      publishedAt: new Date('2026-11-04T00:00:00Z'),
      affectedProducts: [{ vendor: 'wordpress', product: 'plugin:wpvivid-backuprestore', versionEnd: '0.9.138', versionFixed: '0.9.138', patchAvailable: true }],
    });
    // The copyright notices and licenses the terms ask a copy to keep.
    expect((advisory!.rawData as WordfenceRecord).copyrights).toEqual(COPYRIGHTS);
  });

  it('leaves out the CVE when the record has none, so the record id keys its own master row', () => {
    const { advisory } = normalizeWordfenceRecord({ ...wpvivid, cve: null });
    expect(advisory!.cveId).toBeUndefined();
  });

  it('names themes and core by kind and slug', () => {
    const theme = { ...wpvivid, software: [{ ...wpvivid.software[0], type: 'theme', slug: 'aihub' }] };
    expect(normalizeWordfenceRecord(theme).advisory!.affectedProducts[0].product).toBe('theme:aihub');
    const c = { ...wpvivid, software: [core({ '*-3.3': { from_version: '*', from_inclusive: true, to_version: '3.3', to_inclusive: true } }, ['3.3.1'])] };
    expect(normalizeWordfenceRecord(c).advisory!.affectedProducts[0]).toMatchObject({ product: 'core:wordpress', lastAffected: '3.3', versionFixed: '3.3.1' });
  });

  it('gives no advisory for a record that names no core, plugin or theme', () => {
    const other = { ...wpvivid, software: [{ ...wpvivid.software[0], type: 'library' }] };
    expect(normalizeWordfenceRecord(other).advisory).toBeNull();
  });
});

describe('wordfenceProducts', () => {
  it('keeps an unpatched range open at both ends with no range data, so it matches every version', () => {
    const sw: WordfenceSoftware = {
      type: 'theme', slug: 'aihub', patched: false, patched_versions: [],
      affected_versions: { '*': { from_version: '*', from_inclusive: true, to_version: '*', to_inclusive: true } },
    };
    expect(wordfenceProducts(sw).products).toEqual([{ vendor: 'wordpress', product: 'theme:aihub', patchAvailable: false }]);
  });

  it('gives each branch of a multi-branch record its own fix', () => {
    const sw = core({
      '[4.1, 4.1.34)': { from_version: '4.1', from_inclusive: true, to_version: '4.1.34', to_inclusive: false },
      '[4.2, 4.2.31)': { from_version: '4.2', from_inclusive: true, to_version: '4.2.31', to_inclusive: false },
    }, ['4.1.34', '4.2.31']);
    expect(wordfenceProducts(sw).products).toMatchObject([
      { versionStart: '4.1', versionEnd: '4.1.34', versionFixed: '4.1.34' },
      { versionStart: '4.2', versionEnd: '4.2.31', versionFixed: '4.2.31' },
    ]);
  });

  it('skips a range whose bound cannot be compared rather than leaving it half open', () => {
    const sw: WordfenceSoftware = {
      type: 'plugin', slug: 'x', patched: true, patched_versions: ['45.0'],
      affected_versions: {
        a: { from_version: '*', from_inclusive: true, to_version: '44.0 (17-08-2023)', to_inclusive: true },
        b: { from_version: '*', from_inclusive: true, to_version: '4.1.1.', to_inclusive: true },
      },
    };
    const { products, skipped } = wordfenceProducts(sw);
    expect(skipped).toBe(1);
    // A stray trailing dot is tidied, not a reason to skip.
    expect(products).toMatchObject([{ lastAffected: '4.1.1' }]);
  });
});

describe('fixForRange', () => {
  const range = (to: string, incl: boolean) => ({ from_version: '*', from_inclusive: true, to_version: to, to_inclusive: incl });

  it('takes the lowest patched version at the end of an exclusive range, or past an inclusive one', () => {
    expect(fixForRange(range('2.0', false), ['2.0', '3.0'])).toBe('2.0');
    expect(fixForRange(range('2.0', true), ['2.0', '2.0.1', '3.0'])).toBe('2.0.1');
  });

  it('has no fix for a range with no end or no patched version past it', () => {
    expect(fixForRange(range('*', true), ['2.0'])).toBeUndefined();
    expect(fixForRange(range('2.0', true), ['1.9'])).toBeUndefined();
  });
});

describe('normalizeWordfenceFeed', () => {
  it('reads the root object keyed by record id and counts what it leaves out', () => {
    const other = { ...wpvivid, id: 'other', software: [] };
    const { advisories, skippedRecords } = normalizeWordfenceFeed({ [wpvivid.id]: wpvivid, other });
    expect(advisories.map(a => a.externalId)).toEqual([wpvivid.id]);
    expect(skippedRecords).toBe(1);
  });
});

describe('WordfenceFetcher', () => {
  it('fails with a message naming the setting when no API key is configured', async () => {
    await expect(new WordfenceFetcher('').fetch()).rejects.toThrow(/WORDFENCE_API_KEY is not set/);
  });
});
