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
      { cveId: 'CVE-2026-1234', severity: 'medium', range: { introduced: '1.3.0', lastAffected: '1.29.4' }, versionFixed: '1.29.5' },
    ]);
  });

  it('reads a severity written in bold, as nginx.org does for the serious ones', () => {
    const html = `
      <li><p>Memory corruption in HTTP/2 flow control<br>Severity: <b>major</b><br><a href="https://my.f5.com/manage/s/article/K000163926">Advisory</a><br><a href="https://www.cve.org/CVERecord?id=CVE-2026-123007">CVE-2026-123007</a><br>Not vulnerable: 1.31.9+, 1.30.7+<br>Vulnerable: 1.9.5-1.31.8</p></li>
      <li><p>Another<br>Severity: <strong> minor </strong><br>CVE-2026-1235<br>Vulnerable: 1.0.0-1.0.5</p></li>
    `;
    // The CVE is named in the link's URL and in its text, so it is read twice (groupByAdvisory() merges them).
    expect([...new Set(parseNginxPage(html).map(e => `${e.cveId} ${e.severity}`))]).toEqual([
      'CVE-2026-123007 major',
      'CVE-2026-1235 minor',
    ]);
  });

  it('picks the fix candidate that is exactly one patch past the range\'s lastAffected', () => {
    const html = `
      <li>
        CVE-2026-4321<br/>
        Not vulnerable: 1.31.3+, 1.30.4+<br/>
        Vulnerable: 0.9.6-1.31.2<br/>
      </li>
    `;
    expect(parseNginxPage(html)[0].versionFixed).toBe('1.31.3');
  });

  it('matches each of multiple ranges to its own fix candidate', () => {
    const html = `
      <li>
        CVE-2026-8765<br/>
        Not vulnerable: 1.5.0+, 1.4.1+, 1.2.9+<br/>
        Vulnerable: 1.1.4-1.2.8, 1.3.9-1.4.0<br/>
      </li>
    `;
    const entries = parseNginxPage(html);
    expect(entries.map(e => [e.range.lastAffected, e.versionFixed])).toEqual([
      ['1.2.8', '1.2.9'],
      ['1.4.0', '1.4.1'],
    ]);
  });

  it('leaves versionFixed undefined when no candidate lines up exactly', () => {
    const html = `
      <li>
        CVE-2026-1357<br/>
        Not vulnerable: 2.0.0+<br/>
        Vulnerable: 1.3.0-1.29.4<br/>
      </li>
    `;
    expect(parseNginxPage(html)[0].versionFixed).toBeUndefined();
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
      { cveId: 'CVE-2026-1111', severity: 'high', range: { introduced: '0.6.18', lastAffected: '1.25.2' }, versionFixed: '1.25.3' },
      { cveId: 'CVE-2026-1111', severity: 'high', range: { introduced: '1.21.0', lastAffected: '1.25.1' } },
    ];
    const advisories = groupByAdvisory(entries);
    expect(advisories).toHaveLength(1);
    expect(advisories[0].severity).toBe('HIGH');
    expect(advisories[0].affectedProducts).toEqual([
      { vendor: 'nginx', product: 'nginx', versionStart: '0.6.18', lastAffected: '1.25.2', versionFixed: '1.25.3', patchAvailable: true },
      { vendor: 'nginx', product: 'nginx', versionStart: '1.21.0', lastAffected: '1.25.1', versionFixed: undefined, patchAvailable: false },
    ]);
  });

  it("maps nginx.org's own scale: major is HIGH, minor is LOW, and none or unknown has no rating", () => {
    const range = { introduced: '1.0.0', lastAffected: '1.0.1' };
    const severityOf = (severity: string) => groupByAdvisory([{ cveId: 'CVE-2026-4444', severity, range }])[0].severity;
    expect(severityOf('major')).toBe('HIGH');
    expect(severityOf('medium')).toBe('MEDIUM');
    expect(severityOf('minor')).toBe('LOW');
    expect(severityOf('none')).toBeUndefined();
    expect(severityOf('unknown')).toBeUndefined();
  });

  it('keeps distinct CVEs separate', () => {
    const entries = [
      { cveId: 'CVE-2026-2222', severity: 'low', range: { introduced: '1.0.0', lastAffected: '1.0.1' } },
      { cveId: 'CVE-2026-3333', severity: 'low', range: { introduced: '1.0.0', lastAffected: '1.0.1' } },
    ];
    expect(groupByAdvisory(entries)).toHaveLength(2);
  });
});
