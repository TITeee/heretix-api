/**
 * Which CISA KEV rows belong to which catalog entry.
 *
 * KEV names a product as its vendor's advisory does ("BIG-IP and BIG-IQ
 * Centralized Management", "Zimbra Collaboration Suite (ZCS)"), so the link to
 * a catalog entry is a hand-written match on KEV's vendor and product strings.
 * Only rows that are clearly the entry's own product are listed: a KEV row for
 * a client, a plugin or a sibling product (Jenkins plugins, WordPress plugins,
 * Confluence next to Jira) is left out on purpose, not forgotten.
 *
 * Cisco is not here: its entries are not checked against KEV in this pass.
 */
export interface KevMatch {
  /** CatalogEntry.id */
  entryId: string;
  /** Matched against KEV's vendorProject, whitespace-trimmed. */
  vendor: RegExp;
  /** Matched against KEV's product. */
  product: RegExp;
}

export const KEV_MATCHES: KevMatch[] = [
  // Network and edge
  { entryId: 'f5-big-ip', vendor: /^F5$/, product: /^BIG-IP/ },
  { entryId: 'juniper-junos-os', vendor: /^Juniper$/, product: /^Junos OS$/ },
  { entryId: 'mikrotik-routeros', vendor: /^MikroTik$/, product: /^RouterOS$/ },
  { entryId: 'watchguard-fireware', vendor: /^WatchGuard$/, product: /^Firebox/ },
  { entryId: 'arista-eos', vendor: /^Arista$/, product: /^Extensible Operating System$/ },
  { entryId: 'progress-kemp-loadmaster', vendor: /^Progress$/, product: /LoadMaster/ },
  { entryId: 'ubiquiti-unifi-os-server', vendor: /^Ubiquiti$/, product: /^UniFi OS$/ },
  { entryId: 'mitel-micollab', vendor: /^Mitel$/, product: /^MiCollab/ },
  // Mail, remote access, file transfer
  { entryId: 'zimbra-collaboration', vendor: /^Synacor$/, product: /Zimbra/ },
  { entryId: 'roundcube-webmail', vendor: /^Roundcube$/, product: /Webmail/ },
  { entryId: 'smartertools-smartermail', vendor: /^SmarterTools$/, product: /^SmarterMail$/ },
  { entryId: 'connectwise-screenconnect', vendor: /^ConnectWise$/, product: /^ScreenConnect$/ },
  { entryId: 'simplehelp', vendor: /^SimpleHelp$/, product: /^SimpleHelp$/ },
  { entryId: 'crushftp', vendor: /^CrushFTP$/, product: /^CrushFTP$/ },
  { entryId: 'gladinet-centrestack-triofox', vendor: /^Gladinet$/, product: /(CentreStack|Triofox)/ },
  { entryId: 'nable-n-central', vendor: /^N-able$/, product: /^N-central$/i },
  { entryId: 'sangoma-freepbx', vendor: /^Sangoma$/, product: /^FreePBX$/ },
  { entryId: 'solarwinds-web-help-desk', vendor: /^SolarWinds$/, product: /^Web Help Desk$/ },
  { entryId: 'solarwinds-orion-platform', vendor: /^SolarWinds$/, product: /^Orion$/ },
  // Platforms, tools, applications
  { entryId: 'atlassian-jira', vendor: /^Atlassian$/, product: /^Jira/ },
  { entryId: 'elastic-elasticsearch', vendor: /^Elastic$/, product: /^Elasticsearch$/ },
  { entryId: 'elastic-kibana', vendor: /^Elastic$/, product: /^Kibana$/ },
  { entryId: 'gitlab', vendor: /^GitLab$/, product: /.*/ },
  { entryId: 'jenkins', vendor: /^Jenkins$/, product: /^Jenkins( Command Line Interface \(CLI\))?$/ },
  { entryId: 'grafana', vendor: /^Grafana Labs$/, product: /^Grafana$/ },
  { entryId: 'nagios-xi', vendor: /^Nagios$/, product: /^Nagios XI$/ },
  { entryId: 'mongodb-server', vendor: /^MongoDB$/, product: /MongoDB Server/ },
  { entryId: 'samba', vendor: /^Samba$/, product: /^Samba$/ },
  { entryId: 'ibm-websphere-application-server', vendor: /^IBM$/, product: /^WebSphere Application Server/ },
  { entryId: 'jetbrains-teamcity', vendor: /^JetBrains$/, product: /^TeamCity$/ },
  { entryId: 'jfrog-artifactory', vendor: /^JFrog$/, product: /^Artifactory$/ },
  { entryId: 'sonatype-nexus-repository', vendor: /^Sonatype$/, product: /^Nexus Repository/ },
  { entryId: 'trendmicro-apex-one', vendor: /^Trend Micro$/, product: /^(Apex One|OfficeScan)/ },
  { entryId: 'veeam-backup-replication', vendor: /^Veeam$/, product: /^Backup & Replication$/ },
  { entryId: 'docker-desktop', vendor: /^Docker$/, product: /^Desktop/ },
  { entryId: 'wordpress', vendor: /^WordPress$/, product: /^Core$/ },
  { entryId: 'drupal', vendor: /^Drupal$/, product: /^(Drupal )?core$/i },
];

/**
 * KEV CVEs a catalog entry cannot reach on purpose, with why. Each is filed by NVD
 * under a CPE with no version at all (a wildcard), so listing its pair would make
 * the CVE match every version of the product, which is a false positive for nearly
 * everyone who searches. A CVE belongs here only with a reason that says so.
 */
export const ACCEPTED_MISSES: Record<string, string> = {
  'CVE-2020-10199': 'NVD files it (and 6 of the 8 CVEs there) under the older name sonatype:nexus with no version; listing the pair would flag every Nexus version',
  'CVE-2019-15752': 'NVD files it under docker:docker, edition community, with no version; that pair is shared with the Engine entry, so it cannot be split by product',
  'CVE-2025-64328': 'a FreePBX module (sangoma:filestore) with module versions, not FreePBX versions, and no version in the CPE',
};
