import { describe, expect, it } from 'vitest';
import { requiredWindowsFeatures, WINDOWS_ROLE_FEATURES } from './windows-role-features.js';

describe('requiredWindowsFeatures', () => {
  it('names the features that install a role MSRC tags a CVE with', () => {
    expect(requiredWindowsFeatures('Role: DNS Server')).toEqual(['DNS-Server-Full-Role']);
    // Either part of RRAS puts the vulnerable service on the server.
    expect(requiredWindowsFeatures('Windows Routing and Remote Access Service (RRAS)')).toEqual(['RemoteAccessServer', 'RasRoutingProtocols']);
  });

  it('knows a role by each of the tags MSRC has used for it', () => {
    expect(requiredWindowsFeatures('Windows IIS')).toEqual(['IIS-WebServer']);
    expect(requiredWindowsFeatures('Role: Windows AD FS Server')).toEqual(['IdentityServer-SecurityTokenService']);
    expect(requiredWindowsFeatures('Windows Active Directory Certificate Services')).toEqual(['ADCertificateServicesRole']);
  });

  it('judges RD Licensing, Fax Server and the OCSP responder by their own feature', () => {
    expect(requiredWindowsFeatures('Windows Remote Desktop Licensing Service')).toEqual(['Licensing']);
    expect(requiredWindowsFeatures('Role: Windows Fax Service')).toEqual(['FaxServiceRole']);
    expect(requiredWindowsFeatures('Windows Online Certificate Status Protocol (OCSP)')).toEqual(['OnlineRevocationServices']);
  });

  it('judges every NFS tag by any one NFS feature, client side included', () => {
    const nfs = ['ServerForNFS-Infrastructure', 'ClientForNFS-Infrastructure', 'ServicesForNFS-ServerAndClient'];
    for (const component of ['Windows Network File System', 'Windows Server for NFS', 'Windows Client for NFS',
      'Windows Services for NFS ONCRPC XDR Driver', 'Windows NFS Portmapper']) {
      expect(requiredWindowsFeatures(component), component).toEqual(nfs);
    }
  });

  it('is null for a component on every server, one left out on purpose, or none', () => {
    for (const component of ['Windows Kernel', 'Windows Hyper-V', 'Role: Windows Hyper-V', 'Windows Print Spooler Components',
      'Windows SMB Server', 'Windows Remote Desktop Protocol', 'WebDAV', 'Windows iSCSI', 'Active Directory Domain Services',
      // Older tags that also cover client parts on every server.
      'Windows DNS', 'Microsoft Windows DNS', 'Windows DHCP Client', 'Windows Remote Access Connection Manager',
      'Role: Active Directory Certificate Services; Active Directory Domain Services',
      // A client app and a management console, not the roles.
      'Windows Fax and Scan Service', 'Windows Online Certificate Status Protocol (OCSP) SnapIn']) {
      expect(requiredWindowsFeatures(component), component).toBeNull();
    }
    expect(requiredWindowsFeatures(null)).toBeNull();
    expect(requiredWindowsFeatures(undefined)).toBeNull();
  });

  it('returns a copy, so a caller cannot change the table', () => {
    requiredWindowsFeatures('Role: DNS Server')!.push('x');
    expect(WINDOWS_ROLE_FEATURES['Role: DNS Server']).toEqual(['DNS-Server-Full-Role']);
  });
});
