import { describe, expect, it } from 'vitest';
import { microsoftVersionToInt, parseMicrosoftVersion } from './microsoft-version.js';
import { normalizeVersion } from './version.js';

const int = (v: string) => {
  const n = microsoftVersionToInt(v);
  if (n === null) throw new Error(`not encodable: ${v}`);
  return n;
};

describe('microsoftVersionToInt', () => {
  it('orders cumulative updates of one release by their UBR', () => {
    expect(int('10.0.20348.5622')).toBeLessThan(int('10.0.20348.5761'));
    expect(int('10.0.20348.5761')).toBeLessThan(int('10.0.20348.10001'));
  });

  it('orders releases by build before UBR', () => {
    // A high UBR of an older release still sorts before the first build of a newer one.
    expect(int('10.0.20348.99999')).toBeLessThan(int('10.0.26100.1'));
    expect(int('10.0.14393.9612')).toBeLessThan(int('10.0.17763.1'));
  });

  it('reads a build without a UBR as UBR 0', () => {
    expect(int('10.0.20348')).toBe(int('10.0.20348.0'));
    expect(int('10.0.20348')).toBeLessThan(int('10.0.20348.1'));
  });

  it('keeps five-digit UBRs apart (Windows Server 2025 reached 26100.33650)', () => {
    expect(int('10.0.26100.33650')).toBeLessThan(int('10.0.26100.33651'));
  });

  it('fits the largest encodable build in a signed 64-bit column', () => {
    expect(int('999.999.999999.999999')).toBeLessThan(2n ** 63n);
  });

  it('rejects what is not a build number', () => {
    for (const v of ['', '10.0', 'KB5126655', '10.0.20348.5761.1', '1000.0.1.1', '10.0.1000000.1', '10.0.20348.x']) {
      expect(parseMicrosoftVersion(v), v).toBeNull();
      expect(microsoftVersionToInt(v), v).toBeNull();
    }
  });

  it('exists because normalizeVersion() collapses every Windows build to one value', () => {
    expect(normalizeVersion('10.0.20348.5622')).toBe(normalizeVersion('10.0.20348.5761'));
    expect(normalizeVersion('10.0.17763.1')).toBe(normalizeVersion('10.0.26100.33650'));
  });
});
