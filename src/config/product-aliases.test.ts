import { describe, it, expect } from 'vitest';
import { expandProductAliases, PRODUCT_ALIASES, oracleProductPrefixes, ORACLE_PRODUCT_PREFIXES } from './product-aliases.js';

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

  it('cross-maps VMware vCenter / VMware vCenter Server to every Broadcom advisory spelling', () => {
    const expected = [
      'Cloud Foundation (vCenter Server)',
      'Cloud Foundation (vCenter)',
      'vCenter',
      'vCenter Server',
      'vCenter Server Appliance',
      'vCenter Server1',
      'VMware Cloud Foundation (vCenter Server)',
      'VMware Cloud Foundation (vCenter)',
      'VMware Telco Cloud Infrastructure (vCenter)',
      'VMware Telco Cloud Platform (vCenter)',
      'VMware vCenter',
      'VMware vCenter Server',
    ];
    expect(expandProductAliases('VMware vCenter Server')).toEqual(expected);
    expect(expandProductAliases('VMware vCenter')).toEqual(expected);
  });

  it('cross-maps Check Point Security Gateway spellings, including the pre-2026 "Quantum" branding', () => {
    const expected = ['Security Gateway', 'Security Gateways', 'Quantum Security Gateways'];
    expect(expandProductAliases('Security Gateway')).toEqual(expected);
    expect(expandProductAliases('Security Gateways')).toEqual(expected);
    expect(expandProductAliases('Quantum Security Gateway')).toEqual(expected);
    expect(expandProductAliases('Quantum Security Gateways')).toEqual(expected);
  });

  it('cross-maps Check Point Security Management spellings, distinct from Multi-Domain Security Management', () => {
    const expected = ['Security Management', 'Security Management Server', 'Quantum Security Management'];
    expect(expandProductAliases('Security Management')).toEqual(expected);
    expect(expandProductAliases('Security Management Server')).toEqual(expected);
    expect(expandProductAliases('Quantum Security Management')).toEqual(expected);
    expect(expandProductAliases('Multi-Domain Security Management')).toEqual(['Multi-Domain Security Management']);
  });
});

describe('oracleProductPrefixes', () => {
  it('returns the prefix list for a known umbrella category', () => {
    expect(oracleProductPrefixes('PeopleSoft')).toEqual(['PeopleSoft']);
    expect(oracleProductPrefixes('Communications')).toEqual(['Communications']);
  });

  it('is case-insensitive on the lookup key', () => {
    expect(oracleProductPrefixes('peoplesoft')).toEqual(['PeopleSoft']);
    expect(oracleProductPrefixes('SIEBEL CRM')).toEqual(['Siebel']);
  });

  it('lists two prefixes for "database", since "Oracle Database" does not itself start with "Database"', () => {
    expect(oracleProductPrefixes('database')).toEqual(['Database', 'Oracle Database']);
  });

  it('returns undefined for a product with no Oracle prefix mapping (exact-match search unaffected)', () => {
    expect(oracleProductPrefixes('Java SE')).toBeUndefined();
    expect(oracleProductPrefixes('unknown-tool')).toBeUndefined();
  });
});

describe('ORACLE_PRODUCT_PREFIXES data integrity', () => {
  it('uses lowercase keys throughout (lookup is case-insensitive, so uppercase keys would be unreachable)', () => {
    for (const key of Object.keys(ORACLE_PRODUCT_PREFIXES)) {
      expect(key).toBe(key.toLowerCase());
    }
  });

  it('has no empty prefix lists', () => {
    for (const [key, prefixes] of Object.entries(ORACLE_PRODUCT_PREFIXES)) {
      expect(prefixes.length, `prefix list for "${key}" is empty`).toBeGreaterThan(0);
    }
  });
});

describe('Ivanti aliases', () => {
  const IVANTI_KEYS = [
    'connect secure', 'connect_secure', 'ivanti connect secure', 'pulse connect secure', 'pulse_connect_secure',
    'policy secure', 'policy_secure', 'endpoint manager mobile', 'endpoint_manager_mobile', 'epmm',
    'endpoint manager', 'endpoint_manager', 'sentry', 'avalanche', 'secure access client', 'secure_access_client',
    'neurons for itsm', 'neurons_for_itsm', 'virtual traffic manager', 'virtual_traffic_manager',
    'cloud services appliance', 'workspace control', 'application control', 'xtraction',
  ];

  it('reaches Ivanti advisories and NVD rows by any spelling of a product', () => {
    for (const q of ['connect_secure', 'Connect Secure', 'Ivanti Connect Secure', 'Pulse Connect Secure', 'pulse_connect_secure']) {
      expect(expandProductAliases(q), q).toEqual(['connect_secure', 'pulse_connect_secure', 'Connect Secure', 'Pulse Connect Secure']);
    }
    for (const q of ['endpoint_manager_mobile', 'EPMM', 'Ivanti Endpoint Manager Mobile']) {
      expect(expandProductAliases(q), q).toEqual(['endpoint_manager_mobile', 'Endpoint Manager Mobile']);
    }
    expect(expandProductAliases('Sentry')).toEqual(['sentry', 'Sentry']);
    expect(expandProductAliases('neurons_for_itsm')).toEqual(['neurons_for_itsm', 'Neurons for ITSM']);
  });

  it('keeps the NVD token in every list whose key is one, so an NVD search by that token loses nothing', () => {
    // An alias list replaces the searched name; a list holding only the advisory name made
    // a search for connect_secure drop its 130 NVD rows (and endpoint_manager 116 -> 54).
    // 'epmm' is an abbreviation no source stores, so it is not one of these.
    for (const key of IVANTI_KEYS.filter(k => /^[a-z0-9_]+$/.test(k) && k !== 'epmm')) {
      expect(expandProductAliases(key), key).toContain(key);
    }
  });

  it('gives the products of one family the same list', () => {
    expect(expandProductAliases('pulse_policy_secure')).toEqual(expandProductAliases('Policy Secure'));
    expect(expandProductAliases('zta gateways')).toEqual(expandProductAliases('Neurons for ZTA gateways'));
  });

  it('leaves a name it does not know as it is', () => {
    expect(expandProductAliases('Some Other Product')).toEqual(['Some Other Product']);
  });
});

describe('NetScaler aliases', () => {
  it('reaches the bulletins and the NVD rows by any spelling of the ADC and the Gateway', () => {
    for (const q of ['NetScaler ADC', 'Citrix ADC', 'netscaler_application_delivery_controller']) {
      expect(expandProductAliases(q), q).toEqual(['netscaler_application_delivery_controller', 'netscaler_application_delivery_controller_firmware', 'NetScaler ADC']);
    }
    for (const q of ['NetScaler Gateway', 'Citrix Gateway', 'netscaler_gateway']) {
      expect(expandProductAliases(q), q).toEqual(['netscaler_gateway', 'netscaler_gateway_firmware', 'NetScaler Gateway']);
    }
  });

  it('keeps the NVD token in every list whose key is one, so an NVD search by that token loses nothing', () => {
    for (const key of ['netscaler_application_delivery_controller', 'netscaler_gateway', 'netscaler_console', 'netscaler_agent']) {
      expect(expandProductAliases(key), key).toContain(key);
    }
  });

  it('does not pull in the generic tokens other vendors use, or the FIPS builds', () => {
    for (const q of ['NetScaler Gateway', 'NetScaler ADC']) {
      const names = expandProductAliases(q);
      expect(names).not.toContain('gateway');
      expect(names).not.toContain('application_delivery_controller');
      expect(names).not.toContain('NetScaler ADC FIPS and NDcPP');
    }
    expect(expandProductAliases('NetScaler ADC FIPS and NDcPP')).toEqual(['NetScaler ADC FIPS and NDcPP']);
  });

  it('leaves a plain "gateway" search as it was', () => {
    expect(expandProductAliases('gateway')).toEqual(['gateway']);
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
