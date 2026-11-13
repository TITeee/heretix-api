import { describe, it, expect } from 'vitest';
import { ecosystemsWithoutData, expectsOsvData } from './osv-coverage.js';

describe('expectsOsvData', () => {
  it('is true for the ecosystems OSV answers', () => {
    for (const eco of ['npm', 'PyPI', 'Go', 'Alpine:v3.24', 'Debian:13', 'Ubuntu:24.04:LTS', 'AlmaLinux:9', 'Rocky Linux:9', 'composer']) {
      expect(expectsOsvData(eco), eco).toBe(true);
    }
  });

  it('is false for sources with their own feeds, and for names it does not know', () => {
    for (const eco of ['Red Hat:9', 'Oracle Linux:9', 'advisory', 'Windows', 'Hex', '']) {
      expect(expectsOsvData(eco), eco).toBe(false);
    }
  });
});

describe('ecosystemsWithoutData', () => {
  const hasData = (have: string[]) => async (eco: string) => have.includes(eco);

  it('lists the expected ecosystems with no data, with how many packages each has', async () => {
    const got = await ecosystemsWithoutData(
      ['npm', 'npm', 'Alpine:v3.24', 'Debian:13', undefined, 'Red Hat:9', 'advisory'],
      hasData(['Debian:13']),
    );
    expect(got).toEqual([{ ecosystem: 'npm', packages: 2 }, { ecosystem: 'Alpine:v3.24', packages: 1 }]);
  });

  it('is empty when every ecosystem has data', async () => {
    expect(await ecosystemsWithoutData(['npm', 'PyPI'], hasData(['npm', 'PyPI']))).toEqual([]);
  });

  it('asks once for each ecosystem', async () => {
    const asked: string[] = [];
    await ecosystemsWithoutData(['npm', 'npm', 'npm'], async (eco) => { asked.push(eco); return true; });
    expect(asked).toEqual(['npm']);
  });
});
