import { describe, it, expect } from 'vitest';
import { broadcomVersionToInt } from './broadcom-version.js';
import { encodeAdvisoryVersion, BROADCOM_VENDOR } from './advisory-version.js';
import { normalizeVersion } from './version.js';

describe('broadcomVersionToInt', () => {
  const ordered = (...versions: string[]) => {
    const ints = versions.map(v => broadcomVersionToInt(v) as bigint);
    for (let i = 1; i < ints.length; i++) expect(ints[i - 1], `${versions[i - 1]} < ${versions[i]}`).toBeLessThan(ints[i]);
  };
  const same = (a: string, b: string) => expect(broadcomVersionToInt(a), `${a} = ${b}`).toBe(broadcomVersionToInt(b));

  it('reads every spelling of an update as the "8.0 U3e" one', () => {
    same('6.7u2c', '6.7 U2c');
    same('7.0U3c', '7.0 U3c');
    same('6.5u3', '6.5 U3');
    same('8.0U2', '8.0 U2');
    same('7.0 U3t [1]', '7.0 U3t');
    same('12.1.0**', '12.1.0');
    same('3.3.1+', '3.3.1');
    expect(broadcomVersionToInt('8.0 U3e')).toBe(normalizeVersion('8.0 U3e'));
  });

  it('reads an ESXi image profile as its update, a security-only image as the patch it carries', () => {
    same('ESXi80U2d-24585300', '8.0 U2d');
    same('ESXi80U3-24022510', '8.0 U3');
    same('ESXi70U3sq-23794019', '7.0 U3q');
    same('ESXi_7.0.0-1.20.16321839', '7.0.0-1');
    same('ESXi-9.1.0.0200-25557999', '9.1.0.0200');
    ordered('8.0', 'ESXi80a-20842819', '8.0 U1', 'ESXi80U1d-23299997', '8.0 U2', 'ESXi80U2d-24585300', 'ESXi80U3f-24784735');
  });

  it('puts updates and their patches between the releases', () => {
    ordered('6.7.0', '6.7 U2','6.7u2c', '6.7 U3', '6.7 U3r', '6.8');
    ordered('8.0.3', '8.0 U3e', '8.0 U3f', '8.1');
    ordered('8.0', '8.0a', '8.0b', '8.0 U1');
    same('7.0.0b', '7.0b');
  });

  it('puts a hot fix or patch after its release', () => {
    ordered('8.10', '8.10 Hot Fix 4', '8.10 Hot Fix 9', '8.11');
    ordered('8.18', '8.18 HF 5', '8.18.1', '8.18.1 patch 1', '8.18.1 patch 2', '8.18.2');
    ordered('6.2', '6.2 HF', '6.3');
    same('6.5.x HF', '6.5 HF');
    ordered('8.12.2', '8.12.2 + Patch', '8.12.3');
    same('7.5.0.38179 Build 16188146', '7.5.0.38179');
  });

  it('gives no number to a component\'s patch or a patch bundle', () => {
    for (const v of ['Async patch to 8.0 U2e', 'Async Patch to 4.2.1', 'Async patch to NSX 4.1.2.6', 'NSX-T 3.2.3', 'ESXi670-201912001', 'ESXi80U3xyz-1']) {
      expect(broadcomVersionToInt(v), v).toBeNull();
    }
  });

  it('is what a search encodes both sides with for Broadcom rows', () => {
    expect(encodeAdvisoryVersion(BROADCOM_VENDOR, '6.7u2c')).toBe(broadcomVersionToInt('6.7u2c'));
    expect(encodeAdvisoryVersion('fortinet', '6.7u2c')).toBe(normalizeVersion('6.7u2c'));
  });
});
