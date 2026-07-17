import { describe, it, expect } from 'vitest';
import { expandProductAliases, PRODUCT_ALIASES } from './product-aliases.js';

describe('expandProductAliases', () => {
  it('expands nginx to all post-acquisition CPE product names', () => {
    expect(expandProductAliases('nginx')).toEqual([
      'nginx',
      'nginx_open_source',
      'nginx_open_source_subscription',
    ]);
  });

  it('expands httpd to include the http_server CPE product name (regression: prior gap dropped Apache Recall to 27%)', () => {
    expect(expandProductAliases('httpd')).toEqual(['httpd', 'http_server']);
  });

  it('expands http_server to the same set as httpd (both keys are searchable)', () => {
    expect(expandProductAliases('http_server')).toEqual(['httpd', 'http_server']);
  });

  it('cross-maps java/jre/jdk to the same NVD product names', () => {
    expect(expandProductAliases('java')).toEqual(['jre', 'jdk']);
    expect(expandProductAliases('jre')).toEqual(['jre', 'jdk']);
    expect(expandProductAliases('jdk')).toEqual(['jre', 'jdk']);
  });

  it('does not cross-map openjdk into jre/jdk (kept separate to avoid unbounded-range false positives)', () => {
    expect(expandProductAliases('openjdk')).toEqual(['openjdk']);
  });

  it('expands acrobat to all four generation-specific product names', () => {
    expect(expandProductAliases('acrobat')).toEqual([
      'acrobat', 'acrobat_dc', 'acrobat_reader', 'acrobat_reader_dc',
    ]);
  });

  it('expands an abbreviation (postgres) to its full CPE product name without including the abbreviation itself', () => {
    // "postgres" is not itself a valid NVD CPE product name, so it must not appear in the result.
    expect(expandProductAliases('postgres')).toEqual(['postgresql']);
  });

  it('expands an abbreviation (k8s) to its full CPE product name without including the abbreviation itself', () => {
    expect(expandProductAliases('k8s')).toEqual(['kubernetes']);
  });

  it('is case-insensitive on the lookup key', () => {
    expect(expandProductAliases('NGINX')).toEqual([
      'nginx',
      'nginx_open_source',
      'nginx_open_source_subscription',
    ]);
    expect(expandProductAliases('Http_Server')).toEqual(['httpd', 'http_server']);
  });

  it('falls back to the original term (unchanged casing) when no alias is defined', () => {
    expect(expandProductAliases('unknown-tool')).toEqual(['unknown-tool']);
    expect(expandProductAliases('Unknown-Tool')).toEqual(['Unknown-Tool']);
  });
});

describe('PRODUCT_ALIASES data integrity', () => {
  it('uses lowercase keys throughout (lookup is case-insensitive, so uppercase keys would be unreachable)', () => {
    for (const key of Object.keys(PRODUCT_ALIASES)) {
      expect(key).toBe(key.toLowerCase());
    }
  });

  it('has no empty alias arrays', () => {
    for (const [key, aliases] of Object.entries(PRODUCT_ALIASES)) {
      expect(aliases.length, `alias list for "${key}" is empty`).toBeGreaterThan(0);
    }
  });

  it('has no duplicate entries within a single alias array', () => {
    for (const [key, aliases] of Object.entries(PRODUCT_ALIASES)) {
      expect(new Set(aliases).size, `alias list for "${key}" has duplicates`).toBe(aliases.length);
    }
  });
});
