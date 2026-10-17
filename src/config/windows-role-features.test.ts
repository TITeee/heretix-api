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

  it('is null for a component on every server, one left out on purpose, or none', () => {
    for (const component of ['Windows Kernel', 'Windows Hyper-V', 'Role: Windows Hyper-V', 'Windows Print Spooler Components',
      'Windows SMB Server', 'Windows Remote Desktop Protocol', 'WebDAV', 'Windows iSCSI', 'Active Directory Domain Services',
      // Older tags that also cover client parts on every server.
      'Windows DNS', 'Microsoft Windows DNS', 'Windows DHCP Client', 'Windows Remote Access Connection Manager',
      'Role: Active Directory Certificate Services; Active Directory Domain Services']) {
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
