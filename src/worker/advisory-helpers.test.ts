import { describe, it, expect } from 'vitest';
import { inferBareVersionStart } from './advisory-helpers.js';

describe('inferBareVersionStart', () => {
  it('infers the major-version floor for a bare nodejs row (no module criterion)', () => {
    expect(inferBareVersionStart('nodejs', '16.16.0-1.el9_0')).toBe('16.0');
  });

  it('infers a single-component major-version floor for a bare postgresql row at version 10+', () => {
    expect(inferBareVersionStart('postgresql', '13.23-5.el9_8')).toBe('13.0');
    expect(inferBareVersionStart('postgresql', '16.14-1.0.1.el10_2')).toBe('16.0');
  });

  it('infers a two-component floor for pre-10 postgresql majors (9.0-9.6 are distinct, incompatible majors)', () => {
    // RHEL7's bare postgresql 9.2 line.
    expect(inferBareVersionStart('postgresql', '9.2.24-9.0.7.el7_9')).toBe('9.2');
    // postgresql:9.6 module stream, whose "Module postgresql:9.6 is enabled"
    // criterion the primary extractModuleMajor() can't parse (dotted stream
    // label) -- must not collapse to the same floor as 9.2 (regression:
    // CVE-2019-10130 is postgresql:9.6-specific per its own RHSA title, yet
    // a single-component "9.0" floor let it match a 9.2.10 query).
    expect(inferBareVersionStart('postgresql', '9.6.20-1.module+el8.3.0+8938+7f0e88b6')).toBe('9.6');
  });

  it('does not apply to products outside the confirmed allowlist, even with the same version shape', () => {
    expect(inferBareVersionStart('nodejs-nodemon', '2.0.19-1.el9_0')).toBeUndefined();
    expect(inferBareVersionStart('httpd', '2.4.37-65.el8')).toBeUndefined();
    expect(inferBareVersionStart('mariadb', '10.5.16-1.el8_5')).toBeUndefined();
  });

  it('returns undefined when versionEnd has no leading major version', () => {
    expect(inferBareVersionStart('nodejs', 'not-a-version')).toBeUndefined();
    expect(inferBareVersionStart('postgresql', 'not-a-version')).toBeUndefined();
  });
});
