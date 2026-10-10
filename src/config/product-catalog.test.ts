import { describe, it, expect } from 'vitest';
import { CATALOG_ENTRIES, catalogProblems, findCatalogEntry, type CatalogEntry } from './product-catalog.js';

function entry(overrides: Partial<CatalogEntry> = {}): CatalogEntry {
  return {
    id: 'acme-widget', name: 'Acme Widget', vendor: 'Acme', product: 'Widget', category: 'application',
    aliases: [], versionHint: '1.0',
    nvd: [{ vendor: 'acme', products: ['widget'] }],
    cna: [],
    ...overrides,
  };
}

describe('the product catalog', () => {
  it('is structurally sound', () => {
    expect(catalogProblems()).toEqual([]);
  });

  it('finds an entry by its exact name only', () => {
    expect(findCatalogEntry('Ivanti Automation')?.id).toBe('ivanti-automation');
    // A raw CPE token or a differently-cased name is not a catalog name: it keeps
    // being searched as the plain product name it always was.
    expect(findCatalogEntry('ivanti automation')).toBeUndefined();
    expect(findCatalogEntry('jenkins')).toBeUndefined();
  });

  it('keeps ivanti\'s "automation" apart from nintex\'s', () => {
    const pairs = (name: string) => findCatalogEntry(name)?.nvd.map(p => `${p.vendor}:${p.products?.join(',')}`);
    expect(pairs('Ivanti Automation')).toEqual(['ivanti:automation']);
    expect(pairs('Nintex Automation')).toEqual(['nintex:automation']);
  });

  it('stands for a family NVD splits into many names by prefix, without the next-generation line', () => {
    expect(findCatalogEntry('F5 BIG-IP')?.nvd).toEqual([
      { vendor: 'f5', productPrefixes: ['big-ip'], excludePrefixes: ['big-ip_next'] },
    ]);
  });

  it('lists every spelling of a vendor the CVE records use', () => {
    expect(findCatalogEntry('MongoDB Server')?.cna[0].vendors).toEqual(
      expect.arrayContaining(['MongoDB', 'MongoDB Inc', 'MongoDB, Inc.', 'MongoDB Inc.']),
    );
  });
});

describe('catalogProblems', () => {
  it('reports a repeated id or name, ignoring case', () => {
    const problems = catalogProblems([entry(), entry({ name: 'acme widget' })]);
    expect(problems).toEqual(expect.arrayContaining([
      'acme-widget: duplicate id',
      'acme-widget: name "acme widget" repeats another entry\'s (case-insensitively)',
    ]));
  });

  it('reports a name that is a PRODUCT_ALIASES key', () => {
    expect(catalogProblems([entry({ id: 'x', name: 'Junos' })])).toContain('x: name "Junos" is a PRODUCT_ALIASES key');
  });

  it('reports an entry that searches nothing, or lists no products', () => {
    expect(catalogProblems([entry({ nvd: [] })])).toContain('acme-widget: searches nothing (no nvd or cna pairs)');
    expect(catalogProblems([entry({ nvd: [{ vendor: 'acme' }] })])).toContain('acme-widget: NVD vendor "acme" lists no products');
    expect(catalogProblems([entry({ cna: [{ vendors: [], products: ['Widget'] }] })]))
      .toContain('acme-widget: a CNA pair lists no vendors or no products');
  });

  it('reports NVD names that are not lowercase CPE tokens', () => {
    const problems = catalogProblems([entry({ nvd: [{ vendor: 'Acme', products: ['Widget'] }] })]);
    expect(problems).toContain('acme-widget: NVD vendor "Acme" must be a lowercase CPE vendor');
    expect(problems).toContain('acme-widget: NVD product "Widget" must be a lowercase CPE product');
  });

  it('reports excludePrefixes that have no productPrefixes to exclude from', () => {
    expect(catalogProblems([entry({ nvd: [{ vendor: 'acme', products: ['widget'], excludePrefixes: ['w'] }] })]))
      .toContain('acme-widget: excludePrefixes without productPrefixes');
  });
});

describe('the catalog entries as data', () => {
  it('has the pilot set', () => {
    expect(CATALOG_ENTRIES.length).toBeGreaterThanOrEqual(20);
  });
});
