import { PRODUCT_ALIASES } from './product-aliases.js';

/**
 * Product catalog
 *
 * The products a person registers by hand (network devices, middleware, tools
 * outside a package manager), each with the vendor and product the vulnerability
 * data files it under. heretix-management shows it as a picker, so nobody has to
 * know that BIG-IP is "f5" and "big-ip_local_traffic_manager" in NVD or that
 * "automation" belongs to two vendors.
 *
 * The catalog is for products NVD and the CVE records cover. A product with its
 * own vendor-advisory fetcher (Fortinet, Palo Alto, Cisco, ...) is picked from
 * the Advisory list instead, which searches those advisories only; the two are
 * not merged so that where a result comes from stays visible.
 *
 * An entry says exactly which (vendor, product) pairs it stands for, so a search
 * by an entry's name reaches ivanti's "automation" and not nintex's. A pair that
 * is wrong or missing silently loses detections, so `pnpm validate:catalog`
 * checks every pair against the database; run it after changing this file.
 *
 * How to add an entry:
 *   - Find the real names: NVD's <vendor> and <product> (the CPE) and the CNA's
 *     "vendor" / "product" strings (CVE records spell vendors in several ways,
 *     e.g. "MongoDB", "MongoDB Inc", "MongoDB, Inc."; list them all).
 *   - List products exactly. Use productPrefixes (with excludePrefixes) only for
 *     a family NVD splits into dozens of names, like BIG-IP's modules and
 *     per-model firmware.
 *   - `name` is what is stored as the package name, so it is matched
 *     case-sensitively and must not be one of PRODUCT_ALIASES' keys.
 */

export type CatalogCategory = 'network' | 'middleware' | 'database' | 'devops' | 'application';

/** NVD files a product under a CPE vendor and product (both lowercase). */
export interface NvdPairs {
  vendor: string;
  /** Exact CPE product names. */
  products?: string[];
  /** Every CPE product starting with one of these (for a family split into many names). */
  productPrefixes?: string[];
  /** Except the ones starting with one of these. */
  excludePrefixes?: string[];
}

/** CNA records spell a vendor several ways, so a pair is any listed vendor with any listed product. */
export interface CnaPairs {
  vendors: string[];
  products: string[];
}

export interface CatalogEntry {
  /** Stable key; never shown. */
  id: string;
  /** Shown, and stored as the package name. Unique, and matched case-sensitively. */
  name: string;
  /** For display and grouping, e.g. "F5". */
  vendor: string;
  /** For display, e.g. "BIG-IP". */
  product: string;
  category: CatalogCategory;
  /** Other names the entry is found by: abbreviations, old names. */
  aliases: string[];
  /** A version as the vendor writes it, to show what to type. */
  versionHint: string;
  nvd: NvdPairs[];
  cna: CnaPairs[];
}

export const CATALOG_ENTRIES: CatalogEntry[] = [
  // ── Network ─────────────────────────────────────────────────────────────
  {
    id: 'f5-big-ip', name: 'F5 BIG-IP', vendor: 'F5', product: 'BIG-IP', category: 'network',
    aliases: ['bigip', 'big ip'], versionHint: '17.1.1',
    // NVD splits BIG-IP into some 90 names: a name per module and per hardware
    // model's firmware. BIG-IP Next is a separate product line with its own versions.
    nvd: [{ vendor: 'f5', productPrefixes: ['big-ip'], excludePrefixes: ['big-ip_next'] }],
    cna: [{ vendors: ['F5'], products: ['BIG-IP'] }],
  },
  {
    id: 'juniper-junos-os', name: 'Juniper Junos OS', vendor: 'Juniper', product: 'Junos OS', category: 'network',
    aliases: ['junos'], versionHint: '23.4R2',
    nvd: [{ vendor: 'juniper', products: ['junos'] }],
    cna: [{ vendors: ['Juniper Networks'], products: ['Junos OS'] }],
  },
  {
    id: 'aruba-arubaos', name: 'Aruba ArubaOS', vendor: 'Aruba', product: 'ArubaOS', category: 'network',
    aliases: ['aruba'], versionHint: '10.4.1.0',
    nvd: [{ vendor: 'arubanetworks', products: ['arubaos'] }],
    cna: [],
  },
  {
    id: 'mikrotik-routeros', name: 'MikroTik RouterOS', vendor: 'MikroTik', product: 'RouterOS', category: 'network',
    aliases: ['routeros'], versionHint: '7.15.3',
    nvd: [{ vendor: 'mikrotik', products: ['routeros'] }],
    cna: [{ vendors: ['Mikrotik', 'MikroTik'], products: ['RouterOS'] }],
  },
  {
    id: 'watchguard-fireware', name: 'WatchGuard Fireware', vendor: 'WatchGuard', product: 'Fireware', category: 'network',
    aliases: ['fireware os', 'firebox'], versionHint: '12.10.3',
    nvd: [{ vendor: 'watchguard', products: ['fireware'] }],
    cna: [{ vendors: ['WatchGuard'], products: ['Fireware OS'] }],
  },

  // ── Middleware ──────────────────────────────────────────────────────────
  {
    id: 'ibm-websphere-application-server', name: 'IBM WebSphere Application Server', vendor: 'IBM',
    product: 'WebSphere Application Server', category: 'middleware',
    aliases: ['websphere'], versionHint: '9.0.5.17',
    nvd: [{ vendor: 'ibm', products: [
      'websphere_application_server', 'websphere_application_server_liberty', 'websphere_application_server_nd',
    ] }],
    cna: [{ vendors: ['IBM'], products: [
      'WebSphere Application Server', 'WebSphere Application Server - Liberty', 'WebSphere Application Server Liberty',
    ] }],
  },
  {
    id: 'apache-traffic-server', name: 'Apache Traffic Server', vendor: 'Apache', product: 'Traffic Server', category: 'middleware',
    aliases: ['ats'], versionHint: '9.2.4',
    nvd: [{ vendor: 'apache', products: ['traffic_server'] }],
    cna: [{ vendors: ['Apache Software Foundation'], products: ['Apache Traffic Server'] }],
  },
  {
    id: 'squid', name: 'Squid', vendor: 'Squid', product: 'Squid', category: 'middleware',
    aliases: ['squid-cache'], versionHint: '6.10',
    nvd: [{ vendor: 'squid-cache', products: ['squid'] }],
    cna: [],
  },
  {
    id: 'isc-bind', name: 'ISC BIND', vendor: 'ISC', product: 'BIND', category: 'middleware',
    aliases: ['bind9', 'named'], versionHint: '9.18.24',
    nvd: [{ vendor: 'isc', products: ['bind'] }],
    cna: [{ vendors: ['ISC'], products: ['BIND 9'] }],
  },
  {
    id: 'samba', name: 'Samba', vendor: 'Samba', product: 'Samba', category: 'middleware',
    aliases: [], versionHint: '4.19.5',
    nvd: [{ vendor: 'samba', products: ['samba'] }],
    cna: [],
  },

  // ── Database ────────────────────────────────────────────────────────────
  {
    id: 'postgresql', name: 'PostgreSQL', vendor: 'PostgreSQL', product: 'PostgreSQL', category: 'database',
    aliases: ['postgres', 'pgsql'], versionHint: '16.3',
    nvd: [{ vendor: 'postgresql', products: ['postgresql'] }],
    cna: [],
  },
  {
    id: 'mongodb-server', name: 'MongoDB Server', vendor: 'MongoDB', product: 'MongoDB Server', category: 'database',
    aliases: ['mongodb', 'mongo'], versionHint: '7.0.12',
    nvd: [{ vendor: 'mongodb', products: ['mongodb'] }],
    cna: [{ vendors: ['MongoDB', 'MongoDB Inc', 'MongoDB, Inc.', 'MongoDB Inc.'], products: ['MongoDB Server'] }],
  },
  {
    id: 'elastic-elasticsearch', name: 'Elasticsearch', vendor: 'Elastic', product: 'Elasticsearch', category: 'database',
    aliases: ['elastic'], versionHint: '8.13.4',
    nvd: [{ vendor: 'elastic', products: ['elasticsearch'] }],
    cna: [{ vendors: ['Elastic'], products: ['Elasticsearch'] }],
  },

  // ── DevOps and monitoring ───────────────────────────────────────────────
  {
    id: 'elastic-kibana', name: 'Kibana', vendor: 'Elastic', product: 'Kibana', category: 'devops',
    aliases: ['elastic'], versionHint: '8.13.4',
    nvd: [{ vendor: 'elastic', products: ['kibana'] }],
    cna: [{ vendors: ['Elastic'], products: ['Kibana'] }],
  },
  {
    id: 'gitlab', name: 'GitLab', vendor: 'GitLab', product: 'GitLab', category: 'devops',
    aliases: [], versionHint: '17.0.1',
    nvd: [{ vendor: 'gitlab', products: ['gitlab'] }],
    cna: [{ vendors: ['GitLab'], products: ['GitLab'] }],
  },
  {
    id: 'jenkins', name: 'Jenkins', vendor: 'Jenkins', product: 'Jenkins', category: 'devops',
    aliases: [], versionHint: '2.452.1',
    nvd: [{ vendor: 'jenkins', products: ['jenkins'] }],
    cna: [],
  },
  {
    id: 'grafana', name: 'Grafana', vendor: 'Grafana', product: 'Grafana', category: 'devops',
    aliases: [], versionHint: '11.0.0',
    nvd: [{ vendor: 'grafana', products: ['grafana'] }],
    cna: [{ vendors: ['Grafana'], products: ['Grafana', 'Grafana OSS', 'Grafana Enterprise'] }],
  },
  {
    id: 'nagios-xi', name: 'Nagios XI', vendor: 'Nagios', product: 'Nagios XI', category: 'devops',
    aliases: ['nagios'], versionHint: '5.11.3',
    nvd: [{ vendor: 'nagios', products: ['nagios_xi'] }],
    cna: [{ vendors: ['Nagios'], products: ['Nagios XI'] }],
  },

  // ── Applications ────────────────────────────────────────────────────────
  {
    id: 'nextcloud-server', name: 'Nextcloud Server', vendor: 'Nextcloud', product: 'Server', category: 'application',
    aliases: ['nextcloud'], versionHint: '28.0.5',
    nvd: [{ vendor: 'nextcloud', products: ['nextcloud_server'] }],
    cna: [],
  },
  // "automation" is a product name two vendors use: ivanti's (2023.4, 2024.4.0.1 ...)
  // and nintex's (5.8 ...). Matched by name alone, either one's CVEs would land on
  // the other's. These two entries exist to keep them apart.
  {
    id: 'ivanti-automation', name: 'Ivanti Automation', vendor: 'Ivanti', product: 'Automation', category: 'application',
    aliases: [], versionHint: '2024.4',
    nvd: [{ vendor: 'ivanti', products: ['automation'] }],
    cna: [],
  },
  {
    id: 'nintex-automation', name: 'Nintex Automation', vendor: 'Nintex', product: 'Automation', category: 'application',
    aliases: [], versionHint: '5.8',
    nvd: [{ vendor: 'nintex', products: ['automation'] }],
    cna: [{ vendors: ['Nintex'], products: ['Automation'] }],
  },
];

const BY_NAME = new Map(CATALOG_ENTRIES.map(e => [e.name, e]));

/** The entry whose name is exactly this (case-sensitive), or undefined. */
export function findCatalogEntry(name: string): CatalogEntry | undefined {
  return BY_NAME.get(name);
}

/**
 * Structural problems with a catalog, in words; empty when it is sound. The
 * database check (does each pair exist?) is validate-catalog.ts.
 */
export function catalogProblems(entries: CatalogEntry[] = CATALOG_ENTRIES): string[] {
  const problems: string[] = [];
  const ids = new Set<string>();
  const names = new Set<string>();
  const aliasKeys = new Set(Object.keys(PRODUCT_ALIASES).map(k => k.toLowerCase()));

  for (const e of entries) {
    if (ids.has(e.id)) problems.push(`${e.id}: duplicate id`);
    ids.add(e.id);

    const lower = e.name.toLowerCase();
    if (names.has(lower)) problems.push(`${e.id}: name "${e.name}" repeats another entry's (case-insensitively)`);
    names.add(lower);
    if (aliasKeys.has(lower)) problems.push(`${e.id}: name "${e.name}" is a PRODUCT_ALIASES key`);

    for (const field of ['id', 'name', 'vendor', 'product', 'versionHint'] as const) {
      if (!e[field].trim()) problems.push(`${e.id}: ${field} is empty`);
    }
    if (e.nvd.length === 0 && e.cna.length === 0) problems.push(`${e.id}: searches nothing (no nvd or cna pairs)`);

    for (const p of e.nvd) {
      if (!p.vendor || p.vendor !== p.vendor.toLowerCase()) problems.push(`${e.id}: NVD vendor "${p.vendor}" must be a lowercase CPE vendor`);
      if (!(p.products?.length || p.productPrefixes?.length)) problems.push(`${e.id}: NVD vendor "${p.vendor}" lists no products`);
      for (const x of p.products ?? []) {
        if (x !== x.toLowerCase()) problems.push(`${e.id}: NVD product "${x}" must be a lowercase CPE product`);
      }
      if (p.excludePrefixes?.length && !p.productPrefixes?.length) problems.push(`${e.id}: excludePrefixes without productPrefixes`);
    }
    for (const p of e.cna) {
      if (p.vendors.length === 0 || p.products.length === 0) problems.push(`${e.id}: a CNA pair lists no vendors or no products`);
    }
  }
  return problems;
}
