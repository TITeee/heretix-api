import { describe, it, expect } from 'vitest';
import { extractOsMajorVersion, inferBareVersionStart, moduleStreamVersionStart } from './advisory-helpers.js';

describe('extractOsMajorVersion', () => {
  it('extracts the major version from a plain ".elN" release', () => {
    expect(extractOsMajorVersion('1.5.1-28.0.1.el9')).toBe('9');
  });

  it('extracts the major version from a ".elN_M" point-release suffix', () => {
    expect(extractOsMajorVersion('1.5.1-25.0.1.el9_6')).toBe('9');
  });

  it('extracts the major version past a ksplice tag, not right after the version', () => {
    // Oracle Linux ksplice-tracked fixes put "ksplice1" between the version
    // and the ".elN" marker, e.g. glibc 2.34-274.0.1.ksplice1.el9_8.
    expect(extractOsMajorVersion('2.34-274.0.1.ksplice1.el9_8')).toBe('9');
  });

  it('extracts a two-digit major version', () => {
    expect(extractOsMajorVersion('9.5-8.0.1.el10_2')).toBe('10');
  });

  it('extracts the major version when a suffix follows with no separator', () => {
    // Oracle Linux's UEK (Unbreakable Enterprise Kernel) packages: confirmed
    // live to be over half of all Oracle Linux OVAL rows, almost entirely
    // kernel-uek* packages in this exact shape.
    expect(extractOsMajorVersion('5.15.0-323.211.3.3.el9uek')).toBe('9');
  });

  it('extracts the major version when "el" follows a "+" instead of a "."', () => {
    // DNF module-stream builds: confirmed live to be a large share of the
    // remaining Oracle Linux OVAL rows after the UEK fix above, e.g.
    // libvirt 8.0.0-10.0.1.module+el8.7.0+20875+5dd40464.
    expect(extractOsMajorVersion('8.0.0-10.0.1.module+el8.7.0+20875+5dd40464')).toBe('8');
  });

  it('does not match "el" embedded in an unrelated word', () => {
    expect(extractOsMajorVersion('novel123-1')).toBeUndefined();
  });

  it('returns undefined when no ".elN" marker is present', () => {
    expect(extractOsMajorVersion('1.2.3-1')).toBeUndefined();
  });
});

describe('moduleStreamVersionStart', () => {
  it('appends ".0" to a plain integer stream label', () => {
    expect(moduleStreamVersionStart('20', '20.8.1-1.module+el9.3.0')).toBe('20.0');
    expect(moduleStreamVersionStart('16', '16.4-1.module+el9.3.0')).toBe('16.0');
  });

  it('passes a dotted major.minor stream label through as-is', () => {
    expect(moduleStreamVersionStart('8.4', '8.4.3-1.module+el9.3.0')).toBe('8.4');
    expect(moduleStreamVersionStart('10.11', '10.11.6-1.module+el9.3.0')).toBe('10.11');
  });

  it('accepts a calendar-date-style label when the package genuinely uses date-based versioning', () => {
    // python2-pytz: real package version is "2017.2-12...", matching the module stream label.
    expect(moduleStreamVersionStart('2017', '2017.2-12.module+el8.3.0')).toBe('2017.0');
  });

  it('rejects a stream label numerically incompatible with the row\'s own versionEnd', () => {
    // javapackages-tools:201801 bundles xmvn, whose real version is 3.0.0 -- unrelated
    // to the module's own build-generation label. See doc comment for the full story.
    expect(moduleStreamVersionStart('201801', '3.0.0-21.module+el8.10.0')).toBeUndefined();
  });

  it('accepts when versionEnd is unparseable by normalizeVersion (nothing to contradict)', () => {
    // Component > 999999 makes normalizeVersion() return null (see version.ts) --
    // with no comparable endInt, the guard has nothing to contradict and passes through.
    expect(moduleStreamVersionStart('20', '99999999.0-1.module+el9.3.0')).toBe('20.0');
  });

  it('rejects a non-version stream label even when it looks superficially plausible', () => {
    // go-toolset-style modules use the RHEL major ("rhel8") as their stream label,
    // not the tool's own version -- same non-version-label class as javapackages-tools.
    expect(moduleStreamVersionStart('rhel8', '1.16.7-2.module+el8.6.0')).toBeUndefined();
  });
});

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

  it('always infers a two-component floor for httpd (Apache never used a single-integer major)', () => {
    // RHEL5/6-era 2.2 line and RHEL7+ 2.4 line are separately maintained,
    // mutually incompatible releases (2.2 EOL'd upstream in 2018) -- unlike
    // postgresql, there is no version range where a single-component floor
    // is correct, so httpd doesn't fall through to the generic branch at all.
    expect(inferBareVersionStart('httpd', '2.2.15-15.0.1.el6_2.1')).toBe('2.2');
    expect(inferBareVersionStart('httpd', '2.4.62-13.el9_8.1')).toBe('2.4');
  });

  it('always infers a two-component floor for the ancient pre-DNF mysql/mariadb/php lines', () => {
    // RHEL5/6-era mysql (predates DNF modularity; mysql:8.0/8.4 module
    // streams are now handled by extractModuleMajor() reading the dotted
    // "Module mysql:8.4 is enabled" label directly, not this fallback).
    expect(inferBareVersionStart('mysql', '5.1.66-2.el6_3')).toBe('5.1');
    expect(inferBareVersionStart('mysql', '5.0.95-3.el5')).toBe('5.0');
    // RHEL7-era mariadb (predates DNF modularity the same way).
    expect(inferBareVersionStart('mariadb', '5.5.68-1.0.1.el7')).toBe('5.5');
    // RHEL5/6-era php (predates DNF modularity; php:8.1's dotted Module
    // criterion is likewise handled by extractModuleMajor(), not this).
    expect(inferBareVersionStart('php', '5.1.6-27.el5_7.4')).toBe('5.1');
    expect(inferBareVersionStart('php', '5.3.3-26.el6')).toBe('5.3');
  });

  it('applies to same-source-RPM subpackages sharing the parent version, not just the base product name', () => {
    // Same version-release string as the mysql/mariadb/php samples above --
    // these are built from the same source RPM, not independently versioned.
    expect(inferBareVersionStart('mysql-server', '5.1.66-2.el6_3')).toBe('5.1');
    expect(inferBareVersionStart('mariadb-bench', '5.5.68-1.0.1.el7')).toBe('5.5');
    expect(inferBareVersionStart('php-cli', '5.3.3-26.el6')).toBe('5.3');
  });

  it('does not apply to independently-versioned bundled tools, even with a family-member-looking name', () => {
    // mysql-selinux versions its SELinux policy ("1.0.14-1.el10_0"), not
    // MySQL itself; mariadb-connector-c versions the Connector/C client
    // library ("3.4.4-2.el10_2") independently of the server; php-pecl-*
    // extensions and php-pear/php-libguestfs are likewise independently
    // versioned -- none of these are in the family allowlists.
    expect(inferBareVersionStart('mysql-selinux', '1.0.14-1.el10_0')).toBeUndefined();
    expect(inferBareVersionStart('mariadb-connector-c', '3.4.4-2.el10_2')).toBeUndefined();
    expect(inferBareVersionStart('php-pecl-xdebug', '3.1.9-2.el6')).toBeUndefined();
    expect(inferBareVersionStart('php-pear', '1.9.4-4.el6')).toBeUndefined();
  });

  it('does not apply to Software Collections-style product names (version baked into the name, already isolated)', () => {
    expect(inferBareVersionStart('php54-php-cli', '5.4.16-1.el6')).toBeUndefined();
    expect(inferBareVersionStart('mysql55-mysql-server', '5.5.68-1.el6')).toBeUndefined();
  });

  it('does not apply to products outside the confirmed allowlist, even with the same version shape', () => {
    expect(inferBareVersionStart('nodejs-nodemon', '2.0.19-1.el9_0')).toBeUndefined();
    expect(inferBareVersionStart('golang', '1.21.0-1.el9')).toBeUndefined();
  });

  it('returns undefined when versionEnd has no leading major version', () => {
    expect(inferBareVersionStart('nodejs', 'not-a-version')).toBeUndefined();
    expect(inferBareVersionStart('postgresql', 'not-a-version')).toBeUndefined();
    expect(inferBareVersionStart('httpd', 'not-a-version')).toBeUndefined();
    expect(inferBareVersionStart('mysql', 'not-a-version')).toBeUndefined();
    expect(inferBareVersionStart('mariadb', 'not-a-version')).toBeUndefined();
    expect(inferBareVersionStart('php', 'not-a-version')).toBeUndefined();
  });
});
