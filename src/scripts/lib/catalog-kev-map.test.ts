import { describe, it, expect } from 'vitest';
import { CATALOG_ENTRIES } from '../../config/product-catalog.js';
import { ACCEPTED_MISSES, KEV_MATCHES } from './catalog-kev-map.js';

describe('catalog-kev-map', () => {
  it('names only entries the catalog has', () => {
    const ids = new Set(CATALOG_ENTRIES.map(e => e.id));
    expect(KEV_MATCHES.filter(m => !ids.has(m.entryId)).map(m => m.entryId)).toEqual([]);
  });

  it('maps no Cisco entry (those are not checked against KEV in this pass)', () => {
    expect(KEV_MATCHES.filter(m => m.entryId.startsWith('cisco-'))).toEqual([]);
  });

  it('gives every accepted miss a CVE id and a reason', () => {
    for (const [cve, reason] of Object.entries(ACCEPTED_MISSES)) {
      expect(cve).toMatch(/^CVE-\d{4}-\d{4,}$/);
      expect(reason.trim().length).toBeGreaterThan(20);
    }
  });
});
