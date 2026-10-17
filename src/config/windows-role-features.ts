/**
 * Optional Windows Server roles, by the component tag MSRC gives their CVEs
 * (AdvisoryVulnerability.component), and the Windows optional features
 * (Win32_OptionalFeature / DISM names, language-neutral) that install them.
 *
 * MSRC files a role's CVEs under the OS product itself ("Windows Server
 * 2022"), so a server is reported for them whether or not it runs the role.
 * A search result carries the features as requiresFeatures, and a client that
 * knows the server's installed features can set the finding aside when none
 * of them is installed: the vulnerable code is not on the server. The fix is
 * the same cumulative update either way.
 *
 * Only tags that name a role and nothing else are listed. Left out on
 * purpose, so their CVEs are always reported: Hyper-V (host and guest parts
 * share the tag), Active Directory Domain Services and Failover Cluster (may
 * cover member servers too), and Print Spooler, SMB, Remote Desktop
 * Protocol / Client, WebDAV and iSCSI, which are on every server or whose tag
 * does not say whether the client or the server part is affected.
 *
 * The tags are matched exactly, as MSRC writes them; one MSRC renames is no
 * longer matched and its CVEs are reported as before.
 */
export const WINDOWS_ROLE_FEATURES: Readonly<Record<string, readonly string[]>> = {
  // "Windows DNS" and "Microsoft Windows DNS", MSRC's older tags, are not
  // here: they cover the DNS client as well as the server.
  'Role: DNS Server': ['DNS-Server-Full-Role'],
  'Windows DHCP Server': ['DHCPServer'],
  // The RAS connection manager, PPTP, L2TP and PPP tags are left out: those
  // parts are on every server, for its own VPN connections.
  'Windows Routing and Remote Access Service (RRAS)': ['RemoteAccessServer', 'RasRoutingProtocols'],
  'Active Directory Federation Services (AD FS)': ['IdentityServer-SecurityTokenService'],
  'Active Directory Federation Services': ['IdentityServer-SecurityTokenService'],
  'Role: Windows AD FS Server': ['IdentityServer-SecurityTokenService'],
  'Network Policy Server (NPS)': ['NPAS-Role'],
  'NPS RADIUS Server': ['NPAS-Role'],
  'Windows Network Policy Server SNMP': ['NPAS-Role'],
  'Windows Message Queuing': ['MSMQ-Server'],
  'Windows Message Queuing Queue Manager': ['MSMQ-Server'],
  'Remote Desktop Gateway Service': ['Gateway'],
  'Windows Server Update Service': ['UpdateServices-Services'],
  'Windows Internet Information Services': ['IIS-WebServer'],
  'Windows IIS': ['IIS-WebServer'],
  'Active Directory Certificate Services (AD CS)': ['ADCertificateServicesRole'],
  'Windows Active Directory Certificate Services': ['ADCertificateServicesRole'],
  'Role: Windows Active Directory Certificate Services': ['ADCertificateServicesRole'],
  'Windows Deployment Services': ['Microsoft-Windows-Deployment-Services'],
};

/**
 * The optional features any one of which a finding in this component needs
 * on the server, or null when the component is not a role listed above (the
 * finding applies to every server).
 */
export function requiredWindowsFeatures(component: string | null | undefined): string[] | null {
  const features = component ? WINDOWS_ROLE_FEATURES[component] : undefined;
  return features ? [...features] : null;
}
