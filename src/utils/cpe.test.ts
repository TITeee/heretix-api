import { describe, it, expect } from 'vitest';
import { parseCPE } from './cpe.js';

describe('parseCPE', () => {
  it('parses a valid application CPE with a version', () => {
    expect(parseCPE('cpe:2.3:a:apache:httpd:2.4.58:*:*:*:*:*:*:*')).toEqual({
      part: 'a',
      vendor: 'apache',
      product: 'httpd',
      version: '2.4.58',
    });
  });

  it('parses an OS CPE', () => {
    const result = parseCPE('cpe:2.3:o:redhat:enterprise_linux:9.0:*:*:*:*:*:*:*');
    expect(result?.part).toBe('o');
  });

  it('treats a wildcard version as null', () => {
    const result = parseCPE('cpe:2.3:a:vercel:next.js:*:*:*:*:*:*:*:*');
    expect(result?.version).toBeNull();
  });

  it('treats an omitted version as null', () => {
    const result = parseCPE('cpe:2.3:a:vendor:product');
    expect(result?.version).toBeNull();
  });

  it('returns null when the vendor is a wildcard', () => {
    expect(parseCPE('cpe:2.3:a:*:product:1.0:*:*:*:*:*:*:*')).toBeNull();
  });

  it('returns null when the product is missing', () => {
    expect(parseCPE('cpe:2.3:a:vendor:-:1.0:*:*:*:*:*:*:*')).toBeNull();
  });

  it('returns null for a non-CPE-2.3 string', () => {
    expect(parseCPE('not-a-cpe-string')).toBeNull();
  });

  it('returns null for a truncated CPE missing the product field', () => {
    expect(parseCPE('cpe:2.3:a:vendor')).toBeNull();
  });
});
