import { describe, it, expect } from 'vitest';
import { oracleVersionParts, oracleVersionToInt, parseOracleAffected } from './oracle-version.js';

const int = (v: string) => {
  const n = oracleVersionToInt(v);
  if (n === null) throw new Error(`${v} did not encode`);
  return n;
};

describe('oracleVersionParts', () => {
  it('reads one to five numbers', () => {
    expect(oracleVersionParts('19')).toEqual([19]);
    expect(oracleVersionParts('19.30')).toEqual([19, 30]);
    expect(oracleVersionParts('8.4.13')).toEqual([8, 4, 13]);
    expect(oracleVersionParts('13.3.0.1')).toEqual([13, 3, 0, 1]);
    expect(oracleVersionParts('12.2.1.4.0')).toEqual([12, 2, 1, 4, 0]);
    expect(oracleVersionParts('21.0.13.0.3')).toEqual([21, 0, 13, 0, 3]);
  });

  it('reads every way Java 8 and 7 updates are written as the same version', () => {
    for (const v of ['8u511', '8u511b33', '8u511-b32', '8u511-perf', '8u511b33-perf', '1.8.0_511', '1.8.0_511-b33']) {
      expect(oracleVersionParts(v), v).toEqual([8, 0, 511]);
    }
    expect(oracleVersionParts('7u251')).toEqual([7, 0, 251]);
    expect(oracleVersionParts('1.8.0')).toEqual([8, 0, 0]);
  });

  it('leaves out the build that java -version prints after a +', () => {
    expect(oracleVersionParts('21.0.13+11-LTS-250')).toEqual([21, 0, 13]);
    expect(oracleVersionParts('v26.10')).toEqual([26, 10]);
  });

  it('is null for what is not a version it can order', () => {
    for (const v of ['19c', 'Cz8.2', '3.9m0p1', 'XCP3120', '', '1.2.3.4.5.6', '12.2.1.100.0', '12.2.1.4.1000']) {
      expect(oracleVersionParts(v), v).toBeNull();
    }
  });
});

describe('oracleVersionToInt', () => {
  it('orders the fourth and fifth numbers that normalizeVersion() dropped', () => {
    expect(int('12.2.1.3.0')).toBeLessThan(int('12.2.1.4.0'));
    expect(int('21.0.13')).toBeLessThan(int('21.0.13.0.2'));
    expect(int('21.0.13.0.2')).toBeLessThan(int('21.0.13.0.3'));
    expect(int('21.0.13.0.3')).toBeLessThan(int('21.0.14'));
    expect(int('18.1.4.1.0')).toBeLessThan(int('18.1.4.48.0'));
  });

  it('gives trailing zeros no weight, so a version written longer is the same version', () => {
    expect(int('12.2.1.4')).toBe(int('12.2.1.4.0'));
    expect(int('19.30.0.0.0')).toBe(int('19.30'));
    expect(int('21')).toBe(int('21.0.0'));
  });

  it('orders numbers as numbers, not as text', () => {
    expect(int('19.3')).toBeLessThan(int('19.30'));
    expect(int('23.4.0')).toBeLessThan(int('23.26.4'));
    expect(int('8u99')).toBeLessThan(int('8u511'));
    expect(int('8u511')).toBeLessThan(int('11'));
  });
});

describe('parseOracleAffected', () => {
  it('reads the CSAF range, both ends affected', () => {
    expect(parseOracleAffected('>=19.3|<=19.32', 'Database Server')).toEqual([
      { product: 'Database Server', versionStart: '19.3', lastAffected: '19.32', affectedVersions: [] },
    ]);
    expect(parseOracleAffected('>=26.4|<26.10', 'MySQL Server')).toEqual([
      { product: 'MySQL Server', versionStart: '26.4', versionEnd: '26.10', affectedVersions: [] },
    ]);
  });

  it('reads a range written with a dash, with or without spaces', () => {
    expect(parseOracleAffected('19.3-19.32', 'Database Server')[0]).toMatchObject({ versionStart: '19.3', lastAffected: '19.32' });
    expect(parseOracleAffected('12.2.3 - 12.2.10', 'Applications Manager')[0]).toMatchObject({ versionStart: '12.2.3', lastAffected: '12.2.10' });
    expect(parseOracleAffected('12.0.0.3.0-12.0.0.7.0', 'Communications Elastic Charging Engine')[0])
      .toMatchObject({ versionStart: '12.0.0.3.0', lastAffected: '12.0.0.7.0' });
  });

  it('starts "and prior" and "prior to" at the start of the line they name', () => {
    expect(parseOracleAffected('8.0.28 and prior', 'MySQL Server')).toEqual([
      { product: 'MySQL Server', versionStart: '8.0', lastAffected: '8.0.28', affectedVersions: [] },
    ]);
    expect(parseOracleAffected('21.5 and Prior', 'Siebel Apps - Marketing')[0]).toMatchObject({ versionStart: '21', lastAffected: '21.5' });
    expect(parseOracleAffected('Prior to 21.4.3', 'Graph Server and Client')).toEqual([
      { product: 'Graph Server and Client', versionStart: '21.4', versionEnd: '21.4.3', affectedVersions: [] },
    ]);
    expect(parseOracleAffected('prior to 6.0.16', 'VM VirtualBox')[0]).toMatchObject({ versionStart: '6.0', versionEnd: '6.0.16' });
    // A bound takes the line by its numbers for every product: APEX's own line (19.1) would leave nothing below 19.1.
    expect(parseOracleAffected('Prior to 19.1', 'Application Express (APEX)')[0]).toMatchObject({ versionStart: '19', versionEnd: '19.1' });
    // No line starts before "Prior to 21": every earlier version is affected.
    expect(parseOracleAffected('Prior to 21', 'Some Product')).toEqual([{ product: 'Some Product', versionEnd: '21', affectedVersions: [] }]);
  });

  it('takes a Java or APEX version as the newest affected one of its line', () => {
    expect(parseOracleAffected('21.0.13.0.3', 'Java SE')).toEqual([
      { product: 'Java SE', versionStart: '21', lastAffected: '21.0.13.0.3', affectedVersions: [] },
    ]);
    expect(parseOracleAffected('27', 'Java SE')[0]).toMatchObject({ versionStart: '27', lastAffected: '27' });
    expect(parseOracleAffected('8u511b33', 'Java SE')).toEqual([
      { product: 'Java SE', versionStart: '8u0', lastAffected: '8u511', affectedVersions: [] },
    ]);
    expect(parseOracleAffected('8u503-perf', 'Java SE')[0]).toMatchObject({ versionStart: '8u0', lastAffected: '8u503' });
    expect(parseOracleAffected('21.3.20.0.3', 'GraalVM Enterprise Edition')[0]).toMatchObject({ versionStart: '21', lastAffected: '21.3.20.0.3' });
    expect(parseOracleAffected('24.1.22', 'APEX')[0]).toMatchObject({ versionStart: '24.1', lastAffected: '24.1.22' });
    expect(parseOracleAffected('24.2.4', 'Application Express')[0]).toMatchObject({ versionStart: '24.2', lastAffected: '24.2.4' });
  });

  it('keeps any other single version exact, and as a range of one so another spelling matches', () => {
    expect(parseOracleAffected('12.2.1.4.0', 'WebLogic Server')).toEqual([
      { product: 'WebLogic Server', versionStart: '12.2.1.4.0', lastAffected: '12.2.1.4.0', affectedVersions: ['12.2.1.4.0'] },
    ]);
  });

  it('keeps what it cannot order as written', () => {
    expect(parseOracleAffected('19c', 'Autonomous Health Framework')).toEqual([
      { product: 'Autonomous Health Framework', affectedVersions: ['19c'] },
    ]);
    expect(parseOracleAffected('prior to XCP3120', 'Fujitsu SPARC Servers Firmware')).toEqual([
      { product: 'Fujitsu SPARC Servers Firmware', affectedVersions: ['prior to XCP3120'] },
    ]);
  });

  it('takes a Java or GraalVM name before the version as the product, and drops any other', () => {
    expect(parseOracleAffected('Oracle GraalVM Enterprise Edition:20.3.8', 'Java SE')[0])
      .toMatchObject({ product: 'GraalVM Enterprise Edition', versionStart: '20', lastAffected: '20.3.8' });
    expect(parseOracleAffected('Java SE: 7u251', 'Java SE')[0]).toMatchObject({ product: 'Java SE', versionStart: '7u0', lastAffected: '7u251' });
    expect(parseOracleAffected('IDIH: 8.0.0-8.2.2', 'Communications Diameter Signaling Router (DSR)')).toEqual([
      { product: 'Communications Diameter Signaling Router (DSR)', versionStart: '8.0.0', lastAffected: '8.2.2', affectedVersions: [] },
    ]);
  });

  it('gives one entry per product when the text names two', () => {
    expect(parseOracleAffected('14; Java SE Embedded: 8u241', 'Java SE')).toEqual([
      { product: 'Java SE', versionStart: '14', lastAffected: '14', affectedVersions: [] },
      { product: 'Java SE Embedded', versionStart: '8u0', lastAffected: '8u241', affectedVersions: [] },
    ]);
  });

  it('gives an entry without a version when there is no text', () => {
    expect(parseOracleAffected(null, 'Solaris')).toEqual([{ product: 'Solaris', affectedVersions: [] }]);
    expect(parseOracleAffected('  ', 'Solaris')).toEqual([{ product: 'Solaris', affectedVersions: [] }]);
  });
});
