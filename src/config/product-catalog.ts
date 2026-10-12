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
  // ── Added: network ──────────────────────────────────────────────────────
  {
    id: 'pfsense', name: 'pfSense', vendor: 'Netgate', product: 'pfSense', category: 'network',
    aliases: ['netgate pfsense'], versionHint: '2.7.2',
    // NVD files the same product under two vendors (the project's, then Netgate's) and names
    // the Community Edition and Plus apart. Not the add-on packages (pfsense-pkg-*, pfsense_acme_package).
    nvd: [
      { vendor: 'netgate', products: ['pfsense', 'pfsense_ce', 'pfsense_plus'] },
      { vendor: 'pfsense', products: ['pfsense', 'pfsense_plus'] },
    ],
    cna: [],
  },
  {
    id: 'opnsense', name: 'OPNsense', vendor: 'OPNsense', product: 'OPNsense', category: 'network',
    aliases: [], versionHint: '24.1',
    nvd: [{ vendor: 'opnsense', products: ['opnsense'] }],
    cna: [{ vendors: ['OPNsense'], products: ['OPNsense'] }],
  },
  {
    id: 'openvpn', name: 'OpenVPN', vendor: 'OpenVPN', product: 'OpenVPN', category: 'network',
    aliases: [], versionHint: '2.6.8',
    // Not OpenVPN Connect (the client) nor Access Server: separate products.
    nvd: [{ vendor: 'openvpn', products: ['openvpn'] }],
    cna: [{ vendors: ['OpenVPN', 'Openvpn'], products: ['OpenVPN'] }],
  },
  {
    id: 'strongswan', name: 'strongSwan', vendor: 'strongSwan', product: 'strongSwan', category: 'network',
    aliases: [], versionHint: '5.9.13',
    nvd: [{ vendor: 'strongswan', products: ['strongswan'] }],
    cna: [{ vendors: ['strongSwan'], products: ['strongSwan'] }],
  },
  {
    id: 'aruba-arubaos-cx', name: 'Aruba ArubaOS-CX', vendor: 'Aruba', product: 'ArubaOS-CX', category: 'network',
    aliases: ['aos-cx', 'arubaos cx'], versionHint: '10.13.1000',
    nvd: [{ vendor: 'hpe', products: ['arubaos-cx'] }],
    cna: [],
  },

  // ── Added: middleware and platforms ─────────────────────────────────────
  {
    id: 'citrix-xenserver', name: 'Citrix XenServer', vendor: 'Citrix', product: 'XenServer', category: 'middleware',
    aliases: ['xenserver', 'xen server'], versionHint: '8.2',
    nvd: [{ vendor: 'citrix', products: ['xenserver'] }],
    cna: [],
  },
  {
    id: 'envoy-proxy', name: 'Envoy Proxy', vendor: 'Envoy', product: 'Envoy Proxy', category: 'middleware',
    aliases: ['envoy'], versionHint: '1.29.2',
    nvd: [{ vendor: 'envoyproxy', products: ['envoy'] }],
    cna: [],
  },
  {
    id: 'haproxy', name: 'HAProxy', vendor: 'HAProxy', product: 'HAProxy', category: 'middleware',
    aliases: [], versionHint: '2.9.6',
    // Not the Kubernetes Ingress Controller, a separate product.
    nvd: [{ vendor: 'haproxy', products: ['haproxy'] }],
    cna: [{ vendors: ['HAProxy', 'haproxy', 'HAProxy Technologies'], products: ['HAProxy', 'haproxy', 'HAProxy Community Edition'] }],
  },
  {
    id: 'traefik', name: 'Traefik', vendor: 'Traefik', product: 'Traefik', category: 'middleware',
    aliases: [], versionHint: '3.0.0',
    nvd: [{ vendor: 'traefik', products: ['traefik'] }],
    cna: [{ vendors: ['traefik'], products: ['traefik'] }],
  },
  {
    id: 'eclipse-jetty', name: 'Eclipse Jetty', vendor: 'Eclipse', product: 'Jetty', category: 'middleware',
    aliases: ['jetty'], versionHint: '12.0.8',
    nvd: [{ vendor: 'eclipse', products: ['jetty'] }],
    cna: [{ vendors: ['Eclipse Foundation'], products: ['Eclipse Jetty', 'Eclipse Jetty - EE8', 'Eclipse Jetty - EE9', 'Jetty'] }],
  },
  {
    id: 'nodejs', name: 'Node.js', vendor: 'OpenJS Foundation', product: 'Node.js', category: 'middleware',
    aliases: ['nodejs', 'node'], versionHint: '20.11.1',
    nvd: [{ vendor: 'nodejs', products: ['node.js'] }],
    cna: [{ vendors: ['The Node.js Project'], products: ['Node.js'] }],
  },
  {
    id: 'kubernetes', name: 'Kubernetes', vendor: 'Kubernetes', product: 'Kubernetes', category: 'middleware',
    aliases: [], versionHint: '1.29.2',
    nvd: [{ vendor: 'kubernetes', products: ['kubernetes'] }],
    cna: [],
  },

  // ── Added: database ─────────────────────────────────────────────────────
  {
    id: 'mariadb', name: 'MariaDB', vendor: 'MariaDB', product: 'MariaDB', category: 'database',
    aliases: [], versionHint: '10.11.6',
    nvd: [{ vendor: 'mariadb', products: ['mariadb'] }],
    cna: [{ vendors: ['MariaDB'], products: ['MariaDB'] }],
  },
  {
    id: 'redis', name: 'Redis', vendor: 'Redis', product: 'Redis', category: 'database',
    aliases: [], versionHint: '7.2.4',
    // Not Redis Software (Enterprise), the commercial product, nor the redis-parser library.
    nvd: [{ vendor: 'redis', products: ['redis'] }],
    cna: [{ vendors: ['Redis'], products: ['Redis'] }],
  },
  {
    id: 'couchbase-server', name: 'Couchbase Server', vendor: 'Couchbase', product: 'Couchbase Server', category: 'database',
    aliases: ['couchbase'], versionHint: '7.2.4',
    nvd: [{ vendor: 'couchbase', products: ['couchbase_server'] }],
    cna: [],
  },

  // ── Added: DevOps and monitoring ────────────────────────────────────────
  {
    id: 'jetbrains-teamcity', name: 'JetBrains TeamCity', vendor: 'JetBrains', product: 'TeamCity', category: 'devops',
    aliases: ['teamcity'], versionHint: '2024.03',
    nvd: [{ vendor: 'jetbrains', products: ['teamcity'] }],
    cna: [{ vendors: ['JetBrains'], products: ['TeamCity'] }],
  },
  {
    id: 'jfrog-artifactory', name: 'JFrog Artifactory', vendor: 'JFrog', product: 'Artifactory', category: 'devops',
    aliases: ['artifactory'], versionHint: '7.77.8',
    nvd: [{ vendor: 'jfrog', products: ['artifactory'] }],
    cna: [{ vendors: ['jfrog'], products: ['artifactory'] }],
  },
  {
    id: 'sonatype-nexus-repository', name: 'Sonatype Nexus Repository', vendor: 'Sonatype', product: 'Nexus Repository', category: 'devops',
    aliases: ['nexus', 'nexus repository manager', 'nexus3'], versionHint: '3.66.0',
    // NVD kept the earlier name "nexus" for Nexus 1.x/2.x and some 2020 Nexus 3 CVEs; its rows carry versions.
    nvd: [{ vendor: 'sonatype', products: ['nexus_repository_manager', 'nexus'] }],
    cna: [{ vendors: ['Sonatype'], products: ['Nexus Repository 3', 'Nexus Repository', 'Nexus Repository Manager'] }],
  },
  {
    id: 'hashicorp-vault', name: 'HashiCorp Vault', vendor: 'HashiCorp', product: 'Vault', category: 'devops',
    aliases: ['vault'], versionHint: '1.15.4',
    nvd: [{ vendor: 'hashicorp', products: ['vault'] }],
    cna: [{ vendors: ['HashiCorp'], products: ['Vault', 'Vault Enterprise'] }],
  },
  {
    id: 'checkmk', name: 'Checkmk', vendor: 'Checkmk', product: 'Checkmk', category: 'devops',
    aliases: ['check_mk'], versionHint: '2.2.0p23',
    nvd: [{ vendor: 'checkmk', products: ['checkmk'] }],
    cna: [{ vendors: ['Checkmk GmbH'], products: ['Checkmk'] }],
  },
  {
    id: 'solarwinds-orion-platform', name: 'SolarWinds Orion Platform', vendor: 'SolarWinds', product: 'Orion Platform', category: 'devops',
    aliases: ['orion'], versionHint: '2023.4.1',
    nvd: [{ vendor: 'solarwinds', products: ['orion_platform'] }],
    cna: [],
  },

  // ── Added: applications ─────────────────────────────────────────────────
  {
    id: 'atlassian-jira', name: 'Atlassian Jira', vendor: 'Atlassian', product: 'Jira', category: 'application',
    aliases: ['jira', 'jira software'], versionHint: '9.12.4',
    // NVD names the editions apart: Jira (the old name), Server, Data Center, and both together.
    // The CVE records only name Data Center sub-products (Jira Service Management ...), so none is listed.
    // Not Jira Align or the integrations and add-ons (jira_comment, jira_create, ...).
    nvd: [{ vendor: 'atlassian', products: ['jira', 'jira_server', 'jira_data_center', 'jira_server_and_data_center'] }],
    cna: [],
  },
  {
    id: 'trendmicro-apex-one', name: 'Trend Micro Apex One', vendor: 'Trend Micro', product: 'Apex One', category: 'application',
    aliases: ['apex one', 'apexone', 'officescan'], versionHint: '14.0.12',
    // OfficeScan is the earlier name of the same product; NVD keeps both.
    nvd: [{ vendor: 'trendmicro', products: ['apex_one', 'officescan'] }],
    cna: [],
  },
  {
    id: 'mcafee-epo', name: 'McAfee ePolicy Orchestrator', vendor: 'McAfee', product: 'ePolicy Orchestrator', category: 'application',
    aliases: ['epo', 'mcafee epo', 'trellix epo'], versionHint: '5.10.0',
    nvd: [{ vendor: 'mcafee', products: ['epolicy_orchestrator'] }],
    cna: [],
  },
  {
    id: 'veeam-backup-replication', name: 'Veeam Backup & Replication', vendor: 'Veeam', product: 'Backup & Replication', category: 'application',
    aliases: ['veeam', 'vbr'], versionHint: '12.1.0.2131',
    // NVD's CPE keeps the escaped ampersand: veeam_backup_\&_replication.
    nvd: [{ vendor: 'veeam', products: ['veeam_backup_\\&_replication'] }],
    cna: [{ vendors: ['Veeam'], products: ['Backup and Replication'] }],
  },
  // ── Added: batch 3 ──────────────────────────────────────────────────────
  {
    id: 'dell-powerscale-onefs', name: 'Dell PowerScale OneFS', vendor: 'Dell', product: 'PowerScale OneFS', category: 'application',
    aliases: ['onefs', 'powerscale', 'isilon', 'isilon onefs'], versionHint: '9.5.0.0',
    // Isilon is the earlier name of the same OS. The node firmware, InsightIQ and
    // IsilonSD Management Server are separate products.
    nvd: [{ vendor: 'dell', products: ['powerscale_onefs', 'emc_powerscale_onefs', 'emc_isilon_onefs'] }],
    cna: [{ vendors: ['Dell'], products: ['PowerScale OneFS'] }],
  },
  {
    id: 'dell-powerprotect-data-domain', name: 'Dell PowerProtect Data Domain', vendor: 'Dell', product: 'PowerProtect Data Domain', category: 'application',
    aliases: ['data domain', 'dd os', 'ddos', 'powerprotect dd'], versionHint: '7.10.1.0',
    // The operating system (DD OS) under its three names. The CNA records name a
    // release train (LTS2023, Feature Release) and spell it several ways; BoostFS
    // clients and the Management Center are separate products.
    nvd: [{ vendor: 'dell', products: ['data_domain_operating_system', 'emc_data_domain_os', 'powerprotect_data_domain'] }],
    cna: [{
      vendors: ['Dell'],
      products: [
        'PowerProtect Data Domain with Data Domain Operating System (DD OS) LTS2023',
        'PowerProtect Data Domain with Data Domain Operating System (DD OS) LTS2024',
        'PowerProtect Data Domain with Data Domain Operating System (DD OS) LTS2025',
        'PowerProtect Data Domain with Data Domain Operating System (DD OS) LTS 2024',
        'PowerProtect Data Domain with Data Domain Operating System (DD OS) LTS 2025',
        'PowerProtect Data Domain with Data Domain Operating System (DD OS) of Feature Release',
        'PowerProtect Data Domain with Data Domain Operating System (DD OS) Feature Release',
        'Dell PowerProtect Data Domain with Data Domain Operating System (DD OS) LTS2023',
        'Dell PowerProtect Data Domain with Data Domain Operating System (DD OS) LTS2024',
        'Dell PowerProtect Data Domain with Data Domain Operating System (DD OS) LTS2025',
        'Dell PowerProtect Data Domain with Data Domain Operating System (DD OS) of Feature Release',
        'PowerProtect Data Domain LTS 2023',
        'PowerProtect Data Domain LTS2024',
        'PowerProtect Data Domain Feature Release',
        'DD OS 7.10',
        'DD OS 7.13',
        'DD OS 8.3',
      ],
    }],
  },
  {
    id: 'hpe-imc', name: 'HPE Intelligent Management Center', vendor: 'HPE', product: 'Intelligent Management Center', category: 'network',
    aliases: ['imc', 'hp imc', 'hpe imc'], versionHint: '7.3',
    // NVD files it under the old HP vendor, as the platform and a name per module.
    nvd: [{ vendor: 'hp', productPrefixes: ['intelligent_management_center', 'imc_'] }],
    cna: [],
  },
  {
    id: 'docker-engine', name: 'Docker Engine', vendor: 'Docker', product: 'Engine', category: 'middleware',
    aliases: ['dockerd', 'moby'], versionHint: '24.0.7',
    // Not the commercially supported cs_engine, nor Desktop (its own entry).
    nvd: [{ vendor: 'docker', products: ['docker', 'engine'] }],
    cna: [{ vendors: ['Docker'], products: ['Docker Engine'] }],
  },
  {
    id: 'docker-desktop', name: 'Docker Desktop', vendor: 'Docker', product: 'Desktop', category: 'application',
    aliases: [], versionHint: '4.28.0',
    nvd: [{ vendor: 'docker', products: ['docker_desktop', 'desktop'] }],
    cna: [{ vendors: ['Docker'], products: ['Docker Desktop'] }],
  },
  {
    id: 'mattermost-server', name: 'Mattermost Server', vendor: 'Mattermost', product: 'Server', category: 'application',
    aliases: ['mattermost'], versionHint: '9.5.2',
    // Not the desktop or mobile apps, nor the plugins (Confluence, Google Drive, ...).
    nvd: [{ vendor: 'mattermost', products: ['mattermost_server', 'mattermost'] }],
    cna: [{ vendors: ['Mattermost'], products: ['Mattermost'] }],
  },
  {
    id: 'wordpress', name: 'WordPress', vendor: 'WordPress', product: 'WordPress', category: 'application',
    aliases: ['wp'], versionHint: '6.4.2',
    // Core only; plugins and themes are filed under their own vendors.
    nvd: [{ vendor: 'wordpress', products: ['wordpress'] }],
    cna: [{ vendors: ['WordPress'], products: ['WordPress'] }],
  },
  {
    id: 'drupal', name: 'Drupal', vendor: 'Drupal', product: 'Drupal', category: 'application',
    aliases: [], versionHint: '10.2.2',
    // Drupal's own CNA names the core "Drupal core" (20 CVEs), not "Drupal"; its modules are other products.
    nvd: [{ vendor: 'drupal', products: ['drupal'] }],
    cna: [{ vendors: ['Drupal'], products: ['Drupal', 'Drupal core'] }],
  },
  // ── Added: batch 3, edge infrastructure and remote access (often on CISA KEV) ──
  {
    id: 'cisco-asa', name: 'Cisco ASA', vendor: 'Cisco', product: 'Adaptive Security Appliance (ASA) Software', category: 'network',
    aliases: ['asa', 'adaptive security appliance', 'cisco secure firewall asa'], versionHint: '9.18.4',
    // The software (its version is what advisories name), not the 55xx hardware or firmware CPEs.
    nvd: [{ vendor: 'cisco', products: ['adaptive_security_appliance_software'] }],
    cna: [{ vendors: ['Cisco'], products: ['Cisco Adaptive Security Appliance (ASA) Software', 'Cisco Secure Firewall Adaptive Security Appliance (ASA) Software'] }],
  },
  {
    id: 'cisco-ftd', name: 'Cisco Secure Firewall Threat Defense', vendor: 'Cisco', product: 'Secure Firewall Threat Defense (FTD)', category: 'network',
    aliases: ['ftd', 'firepower threat defense', 'firepower', 'cisco ftd'], versionHint: '7.4.1',
    // Firepower Threat Defense is the earlier name.
    nvd: [{ vendor: 'cisco', products: ['secure_firewall_threat_defense', 'firepower_threat_defense'] }],
    cna: [{ vendors: ['Cisco'], products: ['Cisco Secure Firewall Threat Defense (FTD) Software', 'Cisco Firepower Threat Defense Software'] }],
  },
  {
    id: 'cisco-fmc', name: 'Cisco Secure Firewall Management Center', vendor: 'Cisco', product: 'Secure Firewall Management Center (FMC)', category: 'network',
    aliases: ['fmc', 'firepower management center', 'cisco fmc'], versionHint: '7.4.1',
    nvd: [{ vendor: 'cisco', products: ['secure_firewall_management_center', 'firepower_management_center'] }],
    cna: [{ vendors: ['Cisco'], products: ['Cisco Secure Firewall Management Center (FMC)', 'Cisco Firepower Management Center'] }],
  },
  {
    id: 'cisco-ios-xe', name: 'Cisco IOS XE', vendor: 'Cisco', product: 'IOS XE Software', category: 'network',
    aliases: ['ios xe', 'iosxe'], versionHint: '17.9.4',
    // Not the per-release "ios_xe_3.4sg" names NVD kept for old trains, nor the SD-WAN variant (Cisco Catalyst SD-WAN).
    nvd: [{ vendor: 'cisco', products: ['ios_xe'] }],
    cna: [{ vendors: ['Cisco'], products: ['Cisco IOS XE Software'] }],
  },
  {
    id: 'cisco-ios', name: 'Cisco IOS', vendor: 'Cisco', product: 'IOS Software', category: 'network',
    aliases: ['cisco ios software'], versionHint: '15.2(4)M',
    nvd: [{ vendor: 'cisco', products: ['ios'] }],
    cna: [],
  },
  {
    id: 'cisco-nx-os', name: 'Cisco NX-OS', vendor: 'Cisco', product: 'NX-OS Software', category: 'network',
    aliases: ['nxos', 'nx os'], versionHint: '10.3(3)',
    nvd: [{ vendor: 'cisco', products: ['nx-os'] }],
    cna: [],
  },
  {
    id: 'cisco-catalyst-sd-wan', name: 'Cisco Catalyst SD-WAN', vendor: 'Cisco', product: 'Catalyst SD-WAN (Manager, Controller)', category: 'network',
    aliases: ['sd-wan', 'sdwan', 'viptela', 'vmanage', 'vsmart', 'vbond', 'catalyst sd-wan manager'], versionHint: '20.12.1',
    // vManage, vSmart and vBond are the earlier names of the Manager, Controller and Validator.
    nvd: [{
      vendor: 'cisco',
      products: [
        'catalyst_sd-wan_manager', 'sd-wan_vmanage', 'vmanage_network_management', 'vmanage_network_management_system',
        'sd-wan_vsmart_controller', 'sd-wan_vbond_orchestrator', 'sd-wan_manager', 'sd-wan',
      ],
    }],
    cna: [{ vendors: ['Cisco'], products: ['Cisco Catalyst SD-WAN Manager', 'Cisco Catalyst SD-WAN Controller'] }],
  },
  {
    id: 'cisco-ise', name: 'Cisco Identity Services Engine', vendor: 'Cisco', product: 'Identity Services Engine (ISE)', category: 'network',
    aliases: ['ise', 'cisco ise'], versionHint: '3.2',
    nvd: [{ vendor: 'cisco', products: ['identity_services_engine', 'identity_services_engine_software'] }],
    cna: [{ vendors: ['Cisco'], products: ['Cisco Identity Services Engine Software'] }],
  },
  {
    id: 'cisco-unified-cm', name: 'Cisco Unified Communications Manager', vendor: 'Cisco', product: 'Unified Communications Manager', category: 'application',
    aliases: ['cucm', 'unified cm', 'callmanager'], versionHint: '14.0',
    nvd: [{ vendor: 'cisco', products: ['unified_communications_manager'] }],
    cna: [{ vendors: ['Cisco'], products: ['Cisco Unified Communications Manager'] }],
  },
  {
    id: 'arista-eos', name: 'Arista EOS', vendor: 'Arista', product: 'Extensible Operating System (EOS)', category: 'network',
    aliases: ['eos'], versionHint: '4.30.2F',
    nvd: [{ vendor: 'arista', products: ['eos'] }],
    cna: [{ vendors: ['Arista Networks'], products: ['EOS'] }],
  },
  {
    id: 'progress-kemp-loadmaster', name: 'Progress Kemp LoadMaster', vendor: 'Progress', product: 'LoadMaster', category: 'network',
    aliases: ['loadmaster', 'kemp', 'kemp loadmaster'], versionHint: '7.2.60.0',
    nvd: [{ vendor: 'progress', products: ['loadmaster', 'multi-tenant_loadmaster'] }, { vendor: 'kemptechnologies', products: ['loadmaster', 'load_master', 'loadmaster_operating_system'] }],
    cna: [{ vendors: ['Progress', 'Progress Software'], products: ['LoadMaster'] }],
  },
  {
    id: 'ubiquiti-unifi-os-server', name: 'Ubiquiti UniFi OS Server', vendor: 'Ubiquiti', product: 'UniFi OS Server', category: 'network',
    aliases: ['unifi os', 'unifi'], versionHint: '4.3.6',
    // NVD files Ubiquiti's products under the vendor "ui"; the console hardware's firmware
    // is a CPE per model and is not listed here.
    nvd: [{ vendor: 'ui', products: ['unifi_os_server', 'unifi_os'] }],
    cna: [{ vendors: ['Ubiquiti Inc'], products: ['UniFi OS Server'] }],
  },
  {
    id: 'ubiquiti-unifi-network-application', name: 'Ubiquiti UniFi Network Application', vendor: 'Ubiquiti', product: 'UniFi Network Application', category: 'application',
    aliases: ['unifi controller', 'unifi network', 'unifi network controller'], versionHint: '8.0.28',
    nvd: [{ vendor: 'ui', products: ['unifi_network_application', 'unifi_network_controller'] }],
    cna: [{ vendors: ['Ubiquiti Inc'], products: ['UniFi Network Application'] }],
  },
  {
    id: 'zimbra-collaboration', name: 'Zimbra Collaboration Suite', vendor: 'Zimbra', product: 'Collaboration Suite (ZCS)', category: 'application',
    aliases: ['zimbra', 'zcs', 'synacor zimbra'], versionHint: '10.0.6',
    // Synacor sold it to Zimbra; NVD and the CNA records keep both vendors.
    nvd: [
      { vendor: 'synacor', products: ['zimbra_collaboration_suite', 'zimbra_collaboration_server'] },
      { vendor: 'zimbra', products: ['collaboration', 'collaboration_server', 'collaboration_suite', 'zimbra', 'zimbra_collaboration_server', 'zimbra_collaboration_suite'] },
    ],
    cna: [{ vendors: ['Zimbra'], products: ['Collaboration', 'Zimbra Collaboration Suite (ZCS)', 'Zimbra Collaboration Suite'] }],
  },
  {
    id: 'roundcube-webmail', name: 'Roundcube Webmail', vendor: 'Roundcube', product: 'Webmail', category: 'application',
    aliases: ['roundcube'], versionHint: '1.6.6',
    nvd: [{ vendor: 'roundcube', products: ['webmail', 'roundcube_webmail', 'roundcube'] }],
    cna: [{ vendors: ['Roundcube'], products: ['Webmail'] }],
  },
  {
    id: 'smartertools-smartermail', name: 'SmarterMail', vendor: 'SmarterTools', product: 'SmarterMail', category: 'application',
    aliases: ['smarter mail'], versionHint: '100.0.8644',
    nvd: [{ vendor: 'smartertools', products: ['smartermail'] }],
    cna: [{ vendors: ['SmarterTools'], products: ['SmarterMail'] }],
  },
  {
    id: 'connectwise-screenconnect', name: 'ConnectWise ScreenConnect', vendor: 'ConnectWise', product: 'ScreenConnect', category: 'application',
    aliases: ['screenconnect', 'connectwise control'], versionHint: '23.9.7',
    nvd: [{ vendor: 'connectwise', products: ['screenconnect'] }],
    cna: [],
  },
  {
    id: 'simplehelp', name: 'SimpleHelp', vendor: 'SimpleHelp', product: 'SimpleHelp', category: 'application',
    aliases: ['simple-help', 'simple help'], versionHint: '5.5.7',
    // NVD spells the vendor "simple-help"; the CNA records use two capitalisations.
    nvd: [{ vendor: 'simple-help', products: ['simplehelp'] }],
    cna: [{ vendors: ['Simplehelp', 'SimpleHelp'], products: ['Simplehelp', 'SimpleHelp'] }],
  },
  {
    id: 'crushftp', name: 'CrushFTP', vendor: 'CrushFTP', product: 'CrushFTP', category: 'application',
    aliases: ['crush ftp'], versionHint: '11.3.0',
    nvd: [{ vendor: 'crushftp', products: ['crushftp'] }],
    cna: [{ vendors: ['CrushFTP'], products: ['CrushFTP'] }],
  },
  {
    id: 'gladinet-centrestack-triofox', name: 'Gladinet CentreStack and Triofox', vendor: 'Gladinet', product: 'CentreStack / Triofox', category: 'application',
    aliases: ['centrestack', 'triofox', 'gladinet'], versionHint: '16.7.10368.56560',
    nvd: [{ vendor: 'gladinet', products: ['centrestack', 'triofox'] }],
    cna: [{ vendors: ['Gladinet'], products: ['CentreStack', 'Triofox', 'CentreStack and TrioFox'] }],
  },
  {
    id: 'nable-n-central', name: 'N-able N-central', vendor: 'N-able', product: 'N-central', category: 'application',
    aliases: ['ncentral', 'n central'], versionHint: '2024.1',
    nvd: [{ vendor: 'n-able', products: ['n-central'] }],
    cna: [{ vendors: ['N-able'], products: ['N-central'] }],
  },
  {
    id: 'solarwinds-web-help-desk', name: 'SolarWinds Web Help Desk', vendor: 'SolarWinds', product: 'Web Help Desk', category: 'application',
    aliases: ['whd', 'web help desk'], versionHint: '12.8.3',
    nvd: [{ vendor: 'solarwinds', products: ['web_help_desk'] }],
    cna: [],
  },
  {
    id: 'mitel-micollab', name: 'Mitel MiCollab', vendor: 'Mitel', product: 'MiCollab', category: 'application',
    aliases: ['micollab'], versionHint: '9.8.0.33',
    nvd: [{ vendor: 'mitel', products: ['micollab', 'micollab_audio\\,_web_\\&_video_conferencing'] }],
    cna: [],
  },
  {
    id: 'sangoma-freepbx', name: 'Sangoma FreePBX', vendor: 'Sangoma', product: 'FreePBX', category: 'application',
    aliases: ['freepbx', 'free pbx'], versionHint: '16.0.40',
    // Sangoma took over FreePBX; NVD keeps both vendors.
    nvd: [{ vendor: 'sangoma', products: ['freepbx'] }, { vendor: 'freepbx', products: ['freepbx'] }],
    cna: [],
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
