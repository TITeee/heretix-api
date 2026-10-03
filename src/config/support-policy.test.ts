import { describe, it, expect } from 'vitest';
import { isMaintainedOsvEcosystem } from './support-policy.js';

describe('isMaintainedOsvEcosystem', () => {
  it('keeps ecosystems without a release suffix', () => {
    for (const eco of ['npm', 'PyPI', 'Go', 'AlmaLinux', 'Rocky Linux', 'Malware']) {
      expect(isMaintainedOsvEcosystem(eco)).toBe(true);
    }
  });

  it('keeps distros the policy does not cover', () => {
    expect(isMaintainedOsvEcosystem('Packagist:https://packages.drupal.org/8')).toBe(true);
  });

  it('applies the Debian, Alpine and RHEL-clone release lists', () => {
    expect(isMaintainedOsvEcosystem('Debian:11')).toBe(true);
    expect(isMaintainedOsvEcosystem('Debian:14')).toBe(true);
    expect(isMaintainedOsvEcosystem('Debian:10')).toBe(false);
    expect(isMaintainedOsvEcosystem('Debian:3.0')).toBe(false);
    expect(isMaintainedOsvEcosystem('Alpine:v3.21')).toBe(true);
    expect(isMaintainedOsvEcosystem('Alpine:v3.20')).toBe(false);
    expect(isMaintainedOsvEcosystem('Alpine:v3.2')).toBe(false);
    expect(isMaintainedOsvEcosystem('AlmaLinux:10')).toBe(true);
    expect(isMaintainedOsvEcosystem('Rocky Linux:8')).toBe(true);
  });

  it('keeps Ubuntu LTS releases and drops interim and old ones', () => {
    expect(isMaintainedOsvEcosystem('Ubuntu:20.04:LTS')).toBe(true);
    expect(isMaintainedOsvEcosystem('Ubuntu:26.04:LTS')).toBe(true);
    expect(isMaintainedOsvEcosystem('Ubuntu:18.04:LTS')).toBe(false);
    expect(isMaintainedOsvEcosystem('Ubuntu:25.10')).toBe(false);
  });

  it('follows the base LTS release for Ubuntu Pro variants', () => {
    expect(isMaintainedOsvEcosystem('Ubuntu:Pro:22.04:LTS')).toBe(true);
    expect(isMaintainedOsvEcosystem('Ubuntu:Pro:FIPS-updates:20.04:LTS')).toBe(true);
    expect(isMaintainedOsvEcosystem('Ubuntu:Pro:Realtime:24.04:LTS')).toBe(true);
    expect(isMaintainedOsvEcosystem('Ubuntu:Pro:18.04:LTS')).toBe(false);
    expect(isMaintainedOsvEcosystem('Ubuntu:Pro:FIPS:16.04:LTS')).toBe(false);
  });
});
