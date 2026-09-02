import { describe, it, expect } from 'vitest';
import {
  mapSeverity,
  buildRhelComponentMap,
  extractUnfixedComponents,
  parseVexVulnerability,
  normalizeVexDoc,
} from './redhat-vex-fetcher.js';

describe('mapSeverity', () => {
  it('maps known CVSS baseSeverity names', () => {
    expect(mapSeverity('CRITICAL')).toBe('CRITICAL');
    expect(mapSeverity('HIGH')).toBe('HIGH');
    expect(mapSeverity('MEDIUM')).toBe('MEDIUM');
    expect(mapSeverity('LOW')).toBe('LOW');
  });

  it('maps Red Hat threat_severity-style names too', () => {
    expect(mapSeverity('important')).toBe('HIGH');
    expect(mapSeverity('moderate')).toBe('MEDIUM');
  });

  it('returns undefined for empty/nullish input', () => {
    expect(mapSeverity(undefined)).toBeUndefined();
    expect(mapSeverity(null)).toBeUndefined();
    expect(mapSeverity('')).toBeUndefined();
  });
});

describe('buildRhelComponentMap', () => {
  it('maps a default_component_of relationship onto a bare RHEL major to (major, package)', () => {
    const relationships = [
      {
        category: 'default_component_of',
        full_product_name: { name: 'bzip2-libs as a component of Red Hat Enterprise Linux 9', product_id: 'red_hat_enterprise_linux_9:bzip2-libs' },
        product_reference: 'bzip2-libs',
        relates_to_product_reference: 'red_hat_enterprise_linux_9',
      },
    ];
    const map = buildRhelComponentMap(relationships);
    expect(map.get('red_hat_enterprise_linux_9:bzip2-libs')).toEqual({ major: '9', pkg: 'bzip2-libs' });
  });

  it('ignores relationships onto non-RHEL or non-bare-major products (container images, product families)', () => {
    const relationships = [
      {
        category: 'default_component_of',
        full_product_name: { product_id: 'confidential_compute_attestation:openshift-sandboxed-containers/osc-podvm-payload-rhel9' },
        product_reference: 'openshift-sandboxed-containers/osc-podvm-payload-rhel9',
        relates_to_product_reference: 'confidential_compute_attestation',
      },
      {
        category: 'default_component_of',
        full_product_name: { product_id: 'red_hat_ansible_automation_platform_2:ee-supported-rhel9' },
        product_reference: 'ee-supported-rhel9',
        relates_to_product_reference: 'red_hat_ansible_automation_platform_2',
      },
    ];
    expect(buildRhelComponentMap(relationships).size).toBe(0);
  });

  it('ignores RHEL majors outside the currently supported set (8, 9)', () => {
    // The archive tracks every RHEL major back to 5; only 8/9 match
    // RedHatFetcher's own supported variants and are worth the memory to
    // carry through a full-archive run (see git history: unrestricted
    // majors was a direct contributor to an OOM crash).
    const relationships = ['6', '7', '10'].map(major => ({
      category: 'default_component_of',
      full_product_name: { product_id: `red_hat_enterprise_linux_${major}:bzip2-libs` },
      product_reference: 'bzip2-libs',
      relates_to_product_reference: `red_hat_enterprise_linux_${major}`,
    }));
    expect(buildRhelComponentMap(relationships).size).toBe(0);
  });

  it('ignores non-"default_component_of" relationship categories', () => {
    const relationships = [
      {
        category: 'installed_on',
        full_product_name: { product_id: 'red_hat_enterprise_linux_9:bzip2-libs' },
        product_reference: 'bzip2-libs',
        relates_to_product_reference: 'red_hat_enterprise_linux_9',
      },
    ];
    expect(buildRhelComponentMap(relationships).size).toBe(0);
  });

  it('returns an empty map for non-array input', () => {
    expect(buildRhelComponentMap(undefined).size).toBe(0);
    expect(buildRhelComponentMap(null).size).toBe(0);
  });
});

describe('extractUnfixedComponents', () => {
  const componentMap = buildRhelComponentMap([
    {
      category: 'default_component_of',
      full_product_name: { product_id: 'red_hat_enterprise_linux_9:bzip2-libs' },
      product_reference: 'bzip2-libs',
      relates_to_product_reference: 'red_hat_enterprise_linux_9',
    },
    {
      category: 'default_component_of',
      full_product_name: { product_id: 'red_hat_enterprise_linux_9:bzip2' },
      product_reference: 'bzip2',
      relates_to_product_reference: 'red_hat_enterprise_linux_9',
    },
  ]);

  it('returns a component that is known_affected and not in fixed (real CVE-2026-42250/bzip2-libs shape)', () => {
    const productStatus = {
      fixed: ['Red Hat Hardened Images:bzip2-main@x86_64'],
      known_affected: ['red_hat_enterprise_linux_9:bzip2-libs'],
    };
    expect(extractUnfixedComponents(productStatus, componentMap)).toEqual([{ major: '9', pkg: 'bzip2-libs' }]);
  });

  it('excludes a component that appears in both known_affected and fixed', () => {
    const productStatus = {
      fixed: ['red_hat_enterprise_linux_9:bzip2-libs'],
      known_affected: ['red_hat_enterprise_linux_9:bzip2-libs'],
    };
    expect(extractUnfixedComponents(productStatus, componentMap)).toEqual([]);
  });

  it('excludes a known_affected id with no entry in the component map (non-RHEL product)', () => {
    const productStatus = {
      fixed: [],
      known_affected: ['confidential_compute_attestation:openshift-sandboxed-containers/osc-podvm-payload-rhel9'],
    };
    expect(extractUnfixedComponents(productStatus, componentMap)).toEqual([]);
  });

  it('deduplicates repeated (major, package) pairs', () => {
    const productStatus = {
      fixed: [],
      known_affected: ['red_hat_enterprise_linux_9:bzip2-libs', 'red_hat_enterprise_linux_9:bzip2-libs'],
    };
    expect(extractUnfixedComponents(productStatus, componentMap)).toEqual([{ major: '9', pkg: 'bzip2-libs' }]);
  });

  it('returns an empty array when product_status is missing or malformed', () => {
    expect(extractUnfixedComponents(undefined, componentMap)).toEqual([]);
    expect(extractUnfixedComponents({}, componentMap)).toEqual([]);
  });
});

describe('parseVexVulnerability', () => {
  it('parses cve id, title, and CVSS v3 fields from a real-shaped entry', () => {
    const vuln = {
      cve: 'CVE-2026-42250',
      title: 'bzip2: Denial of Service in bzip2recover via a specially crafted file',
      scores: [{ cvss_v3: { baseScore: 5, baseSeverity: 'MEDIUM', vectorString: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:H' } }],
    };
    expect(parseVexVulnerability(vuln)).toEqual({
      cve: 'CVE-2026-42250',
      title: 'bzip2: Denial of Service in bzip2recover via a specially crafted file',
      severity: 'MEDIUM',
      cvssScore: 5,
      cvssVector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:H',
    });
  });

  it('returns null for a non-CVE or missing cve field', () => {
    expect(parseVexVulnerability({ cve: 'not-a-cve' })).toBeNull();
    expect(parseVexVulnerability({})).toBeNull();
  });

  it('returns null for non-object input', () => {
    expect(parseVexVulnerability(null)).toBeNull();
    expect(parseVexVulnerability('CVE-2026-1234')).toBeNull();
  });

  it('tolerates a missing scores array', () => {
    expect(parseVexVulnerability({ cve: 'CVE-2026-1234' })).toEqual({
      cve: 'CVE-2026-1234',
      title: undefined,
      severity: undefined,
      cvssScore: undefined,
      cvssVector: undefined,
    });
  });
});

describe('normalizeVexDoc', () => {
  function buildDoc(overrides: { knownAffected?: string[]; fixed?: string[] } = {}) {
    return {
      product_tree: {
        relationships: [
          {
            category: 'default_component_of',
            full_product_name: { product_id: 'red_hat_enterprise_linux_9:bzip2-libs' },
            product_reference: 'bzip2-libs',
            relates_to_product_reference: 'red_hat_enterprise_linux_9',
          },
        ],
      },
      vulnerabilities: [
        {
          cve: 'CVE-2026-42250',
          title: 'bzip2: Denial of Service in bzip2recover via a specially crafted file',
          scores: [{ cvss_v3: { baseScore: 5, baseSeverity: 'MEDIUM', vectorString: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:H' } }],
          product_status: {
            fixed: overrides.fixed ?? [],
            known_affected: overrides.knownAffected ?? ['red_hat_enterprise_linux_9:bzip2-libs'],
          },
        },
      ],
    };
  }

  it('builds a NormalizedAdvisory with one patchAvailable:false, range-less affectedProduct (real CVE-2026-42250 shape)', () => {
    const result = normalizeVexDoc(buildDoc());
    expect(result).toEqual({
      externalId: 'CVE-2026-42250',
      cveId: 'CVE-2026-42250',
      summary: 'bzip2: Denial of Service in bzip2recover via a specially crafted file',
      severity: 'MEDIUM',
      cvssScore: 5,
      cvssVector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:H',
      affectedProducts: [{ vendor: 'red-hat-9', product: 'bzip2-libs', patchAvailable: false }],
      rawData: { source: 'redhat-vex', cve: 'CVE-2026-42250' },
    });
  });

  it('returns null when the only known_affected component is already fixed', () => {
    expect(normalizeVexDoc(buildDoc({ fixed: ['red_hat_enterprise_linux_9:bzip2-libs'] }))).toBeNull();
  });

  it('returns null when known_affected has no RHEL-mapped component at all', () => {
    expect(normalizeVexDoc(buildDoc({ knownAffected: ['some_other_product:thing'] }))).toBeNull();
  });

  it('returns null for a document with no product_tree or no vulnerabilities', () => {
    expect(normalizeVexDoc({ vulnerabilities: [] })).toBeNull();
    expect(normalizeVexDoc({ product_tree: {} })).toBeNull();
  });

  it('returns null for non-object input', () => {
    expect(normalizeVexDoc(null)).toBeNull();
    expect(normalizeVexDoc(undefined)).toBeNull();
  });
});
