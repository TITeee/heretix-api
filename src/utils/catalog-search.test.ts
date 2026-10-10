import { describe, it, expect } from 'vitest';
import { catalogCnaWhere, catalogListing, catalogNvdWhere, searchCatalog } from './catalog-search.js';
import { CATALOG_ENTRIES, findCatalogEntry } from '../config/product-catalog.js';

function entry(name: string) {
  const e = findCatalogEntry(name);
  if (!e) throw new Error(`no catalog entry ${name}`);
  return e;
}

describe('catalogNvdWhere', () => {
  it('pins an exact product to its vendor', () => {
    expect(catalogNvdWhere(entry('Ivanti Automation'))).toEqual({
      OR: [{ vendor: 'ivanti', OR: [{ packageName: { in: ['automation'] } }] }],
    });
  });

  it('turns a product family into prefixes with the excluded ones left out, escaping LIKE wildcards', () => {
    expect(catalogNvdWhere(entry('F5 BIG-IP'))).toEqual({
      OR: [{
        vendor: 'f5',
        OR: [{ packageName: { startsWith: 'big-ip' } }],
        NOT: [{ packageName: { startsWith: 'big-ip\\_next' } }],
      }],
    });
  });

  it('keeps several products of one vendor together', () => {
    const where = catalogNvdWhere(entry('IBM WebSphere Application Server'));
    expect(where.OR).toEqual([{
      vendor: 'ibm',
      OR: [{ packageName: { in: [
        'websphere_application_server', 'websphere_application_server_liberty', 'websphere_application_server_nd',
      ] } }],
    }]);
  });
});

describe('catalogCnaWhere', () => {
  it('matches any listed spelling of the vendor with any listed product', () => {
    expect(catalogCnaWhere(entry('MongoDB Server'))).toEqual({
      OR: [{
        vendor: { in: ['MongoDB', 'MongoDB Inc', 'MongoDB, Inc.', 'MongoDB Inc.'] },
        product: { in: ['MongoDB Server'] },
      }],
    });
  });

  it('matches nothing for an entry without CNA pairs', () => {
    expect(catalogCnaWhere(entry('Ivanti Automation'))).toEqual({ OR: [] });
  });
});

describe('searchCatalog', () => {
  const names = (q?: string, category?: string) => searchCatalog(CATALOG_ENTRIES, q, category).map((e) => e.name);

  it('lists every entry by category and name when nothing is typed', () => {
    const all = searchCatalog(CATALOG_ENTRIES, undefined);
    expect(all).toHaveLength(CATALOG_ENTRIES.length);
    const keys = all.map((e) => `${e.category}/${e.name}`);
    expect(keys).toEqual([...keys].sort((a, b) => a.localeCompare(b)));
  });

  it('finds an entry by a vendor, whatever the case', () => {
    expect(names('ivanti')).toEqual(['Ivanti Automation']);
    expect(names('NINTEX')).toEqual(['Nintex Automation']);
    expect(names('f5')).toEqual(['F5 BIG-IP']);
  });

  it('reads a space, hyphen and underscore alike, and finds an alias', () => {
    expect(names('big ip')).toEqual(['F5 BIG-IP']);
    expect(names('big_ip')).toEqual(['F5 BIG-IP']);
    expect(names('bigip')).toEqual(['F5 BIG-IP']);
    expect(names('postgres')).toEqual(['PostgreSQL']);
  });

  it('puts the exact name before names that merely start or contain it', () => {
    // "automation" is in two names; "elastic" is the vendor of two and an alias of two.
    expect(names('automation')).toEqual(['Ivanti Automation', 'Nintex Automation']);
    expect(names('kibana')[0]).toBe('Kibana');
    expect(names('Nagios XI')[0]).toBe('Nagios XI');
  });

  it('ranks a name that starts with the text above one that contains it', () => {
    const entries = [
      { ...CATALOG_ENTRIES[0], id: 'a', name: 'Acme Server', vendor: 'Acme', product: 'Server', aliases: [] },
      { ...CATALOG_ENTRIES[0], id: 'b', name: 'Server Pro', vendor: 'Other', product: 'Pro', aliases: [] },
    ];
    expect(searchCatalog(entries, 'server').map((e) => e.name)).toEqual(['Server Pro', 'Acme Server']);
  });

  it('filters by category, and finds nothing for text that matches nothing', () => {
    expect(names(undefined, 'database')).toEqual(expect.arrayContaining(['PostgreSQL', 'MongoDB Server', 'Elasticsearch']));
    expect(names(undefined, 'database')).not.toContain('Jenkins');
    expect(names('zzzz-no-such-product')).toEqual([]);
  });
});

describe('catalogListing', () => {
  it('says where a search by the name looks, and passes the pairs on', () => {
    const e = CATALOG_ENTRIES.find((x) => x.name === 'Nintex Automation')!;
    expect(catalogListing(e)).toMatchObject({ name: 'Nintex Automation', sources: ['nvd', 'cna'], versionHint: '5.8' });
    expect(catalogListing(e).nvd).toEqual([{ vendor: 'nintex', products: ['automation'] }]);
    const nvdOnly = CATALOG_ENTRIES.find((x) => x.name === 'Ivanti Automation')!;
    expect(catalogListing(nvdOnly).sources).toEqual(['nvd']);
  });
});
