import { describe, it, expect } from 'vitest';
import { parseAffectsText, parseTomcatPage, groupByAdvisory } from './tomcat-fetcher.js';

describe('parseAffectsText', () => {
  it('parses "X to Y" as an inclusive range', () => {
    expect(parseAffectsText('9.0.71 to 9.0.73')).toEqual({ introduced: '9.0.71', lastAffected: '9.0.73' });
  });

  it('strips the "Apache Tomcat " prefix', () => {
    expect(parseAffectsText('Apache Tomcat 9.0.71 to 9.0.73')).toEqual({ introduced: '9.0.71', lastAffected: '9.0.73' });
  });

  it('handles milestone versions', () => {
    expect(parseAffectsText('9.0.0.M1 to 9.0.105')).toEqual({ introduced: '9.0.0.M1', lastAffected: '9.0.105' });
  });

  it('treats a single version as both bounds', () => {
    expect(parseAffectsText('9.0.0.M1')).toEqual({ introduced: '9.0.0.M1', lastAffected: '9.0.0.M1' });
  });

  it('returns null for non-version text', () => {
    expect(parseAffectsText('see vendor advisory')).toBeNull();
  });
});

describe('parseTomcatPage', () => {
  it('extracts CVE, severity, and range from the heading area only', () => {
    const html = `
      <p><strong>Important: Fix bypass</strong> <a href="#">CVE-2026-1111</a></p>
      <p>Affects: 9.0.71 to 9.0.73</p>
      <p>The fix for CVE-2026-9999 was incomplete.</p>
    `;
    const entries = parseTomcatPage(html, 9);
    expect(entries).toEqual([
      { cveId: 'CVE-2026-1111', severity: 'important', range: { introduced: '9.0.71', lastAffected: '9.0.73' }, major: 9 },
    ]);
  });

  it('associates multiple CVEs sharing one heading with the same range', () => {
    const html = `
      <p><strong>Moderate: Two issues</strong> <a href="#">CVE-2026-2222</a> <a href="#">CVE-2026-2223</a></p>
      <p>Affects: 10.1.0 to 10.1.5</p>
    `;
    const entries = parseTomcatPage(html, 10);
    expect(entries.map(e => e.cveId)).toEqual(['CVE-2026-2222', 'CVE-2026-2223']);
    expect(entries[0].range).toEqual({ introduced: '10.1.0', lastAffected: '10.1.5' });
  });

  it('returns an empty array when there is no Affects: line', () => {
    expect(parseTomcatPage('<p>no advisories here</p>', 9)).toEqual([]);
  });
});

describe('groupByAdvisory', () => {
  it('merges entries for the same CVE across branches into one advisory with multiple affectedProducts', () => {
    const entries = [
      { cveId: 'CVE-2026-3333', severity: 'critical', range: { introduced: '9.0.0', lastAffected: '9.0.10' }, major: 9 },
      { cveId: 'CVE-2026-3333', severity: 'critical', range: { introduced: '10.1.0', lastAffected: '10.1.2' }, major: 10 },
    ];
    const advisories = groupByAdvisory(entries);
    expect(advisories).toHaveLength(1);
    expect(advisories[0].cveId).toBe('CVE-2026-3333');
    expect(advisories[0].severity).toBe('CRITICAL');
    expect(advisories[0].affectedProducts).toEqual([
      { vendor: 'apache', product: 'tomcat', versionStart: '9.0.0', lastAffected: '9.0.10' },
      { vendor: 'apache', product: 'tomcat', versionStart: '10.1.0', lastAffected: '10.1.2' },
    ]);
  });

  it('keeps distinct CVEs as separate advisories', () => {
    const entries = [
      { cveId: 'CVE-2026-4444', severity: 'low', range: { introduced: '9.0.0', lastAffected: '9.0.1' }, major: 9 },
      { cveId: 'CVE-2026-5555', severity: 'low', range: { introduced: '9.0.0', lastAffected: '9.0.1' }, major: 9 },
    ];
    expect(groupByAdvisory(entries)).toHaveLength(2);
  });

  it('deduplicates identical ranges appearing twice for the same CVE', () => {
    const entries = [
      { cveId: 'CVE-2026-6666', severity: 'low', range: { introduced: '9.0.0', lastAffected: '9.0.1' }, major: 9 },
      { cveId: 'CVE-2026-6666', severity: 'low', range: { introduced: '9.0.0', lastAffected: '9.0.1' }, major: 9 },
    ];
    expect(groupByAdvisory(entries)[0].affectedProducts).toHaveLength(1);
  });
});
