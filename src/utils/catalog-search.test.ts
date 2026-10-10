import { describe, it, expect } from 'vitest';
import { catalogCnaWhere, catalogNvdWhere } from './catalog-search.js';
import { findCatalogEntry } from '../config/product-catalog.js';

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
