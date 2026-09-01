import { describe, it, expect } from 'vitest';
import { osvBucketName } from './osv-bucket.js';

describe('osvBucketName', () => {
  it('maps a versioned AlmaLinux/Rocky Linux ecosystem to the shared bare bucket name', () => {
    expect(osvBucketName('AlmaLinux:9')).toBe('AlmaLinux');
    expect(osvBucketName('AlmaLinux:8')).toBe('AlmaLinux');
    expect(osvBucketName('Rocky Linux:8')).toBe('Rocky Linux');
  });

  it('leaves an already-bare shared-bucket ecosystem unchanged', () => {
    expect(osvBucketName('AlmaLinux')).toBe('AlmaLinux');
    expect(osvBucketName('Rocky Linux')).toBe('Rocky Linux');
  });

  it('leaves ecosystems with their own real per-version bucket unchanged', () => {
    expect(osvBucketName('Ubuntu:22.04:LTS')).toBe('Ubuntu:22.04:LTS');
    expect(osvBucketName('Debian:12')).toBe('Debian:12');
    expect(osvBucketName('Red Hat:9')).toBe('Red Hat:9');
  });

  it('leaves non-distro ecosystems unchanged', () => {
    expect(osvBucketName('npm')).toBe('npm');
  });
});
