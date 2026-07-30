import { describe, it, expect } from 'vitest';
import { inferPostgresqlModuleVersionStart } from './advisory-helpers.js';

describe('inferPostgresqlModuleVersionStart', () => {
  it('infers the major-version floor for a postgresql module-stream row with no versionStart', () => {
    expect(inferPostgresqlModuleVersionStart('postgresql', undefined, '18.4-2.module+el9.8.0+24359+da7fad50')).toBe('18.0');
    expect(inferPostgresqlModuleVersionStart('postgresql', undefined, '16.14-1.module+el9.8.0+90922+3defa420')).toBe('16.0');
  });

  it('leaves an existing versionStart untouched', () => {
    expect(inferPostgresqlModuleVersionStart('postgresql', '16.0', '18.4-2.module+el9.8.0+24359+da7fad50')).toBe('16.0');
  });

  it('does not apply to non-postgresql products, even with a module marker', () => {
    expect(inferPostgresqlModuleVersionStart('nodejs', undefined, '18.4-2.module+el9.8.0+24359+da7fad50')).toBeUndefined();
  });

  it('does not apply to postgresql rows without a module marker', () => {
    expect(inferPostgresqlModuleVersionStart('postgresql', undefined, '9.2.24-1.el7_5')).toBeUndefined();
  });
});
