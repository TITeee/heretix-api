import { describe, it, expect } from 'vitest';
import { parseVulnerableText, parseNginxPage, groupByAdvisory } from './nginx-fetcher.js';

describe('parseVulnerableText', () => {
  it('parses a single hyphenated range', () => {
    expect(parseVulnerableText('1.3.0-1.29.4')).toEqual([{ introduced: '1.3.0', lastAffected: '1.29.4' }]);
  });

  it('parses multiple comma-separated ranges', () => {
    expect(parseVulnerableText('0.6.18-1.25.2, 1.21.0-1.25.1')).toEqual([
      { introduced: '0.6.18', lastAffected: '1.25.2' },
      { introduced: '1.21.0', lastAffected: '1.25.1' },
    ]);
  });

  it('treats a single version as both bounds', () => {
    expect(parseVulnerableText('1.5.10')).toEqual([{ introduced: '1.5.10', lastAffected: '1.5.10' }]);
  });

  it('returns an empty array for non-version text', () => {
    expect(parseVulnerableText('none')).toEqual([]);
  });
});

describe('parseNginxPage', () => {
  it('extracts CVE, severity, and range from a list item', () => {
    const html = `
      <li>
        <a href="#">Some vulnerability</a>
        Severity: medium<br/>
        CVE-2026-1234<br/>
        Not vulnerable: 1.29.5+<br/>
        Vulnerable: 1.3.0-1.29.4<br/>
      </li>
    `;
    const entries = parseNginxPage(html);
    expect(entries).toEqual([
      { cveId: 'CVE-2026-1234', severity: 'medium', range: { introduced: '1.3.0', lastAffected: '1.29.4' } },
    ]);
  });

  it('does not mistake "Not vulnerable" text for the "Vulnerable" range', () => {
    const html = `
      <li>
        CVE-2026-5678<br/>
        Not vulnerable: 1.29.5-1.29.9<br/>
        Vulnerable: 1.20.0-1.25.1<br/>
      </li>
    `;
    const entries = parseNginxPage(html);
    expect(entries).toEqual([
      { cveId: 'CVE-2026-5678', severity: 'unknown', range: { introduced: '1.20.0', lastAffected: '1.25.1' } },
    ]);
  });

  it('skips entries with no CVE ID', () => {
    const html = '<li>Vulnerable: 1.0.0-1.0.5</li>';
    expect(parseNginxPage(html)).toEqual([]);
  });

  it('skips entries with no Vulnerable: line', () => {
    const html = '<li>CVE-2026-9999<br/></li>';
    expect(parseNginxPage(html)).toEqual([]);
  });
});

describe('groupByAdvisory', () => {
  it('merges multiple ranges for the same CVE into separate affectedProducts', () => {
    const entries = [
      { cveId: 'CVE-2026-1111', severity: 'high', range: { introduced: '0.6.18', lastAffected: '1.25.2' } },
      { cveId: 'CVE-2026-1111', severity: 'high', range: { introduced: '1.21.0', lastAffected: '1.25.1' } },
    ];
    const advisories = groupByAdvisory(entries);
    expect(advisories).toHaveLength(1);
    expect(advisories[0].severity).toBe('HIGH');
    expect(advisories[0].affectedProducts).toEqual([
      { vendor: 'nginx', product: 'nginx', versionStart: '0.6.18', lastAffected: '1.25.2' },
      { vendor: 'nginx', product: 'nginx', versionStart: '1.21.0', lastAffected: '1.25.1' },
    ]);
  });

  it('keeps distinct CVEs separate', () => {
    const entries = [
      { cveId: 'CVE-2026-2222', severity: 'low', range: { introduced: '1.0.0', lastAffected: '1.0.1' } },
      { cveId: 'CVE-2026-3333', severity: 'low', range: { introduced: '1.0.0', lastAffected: '1.0.1' } },
    ];
    expect(groupByAdvisory(entries)).toHaveLength(2);
  });
});
