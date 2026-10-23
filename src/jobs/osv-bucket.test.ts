import { describe, it, expect } from 'vitest';
import { osvBucketName, maxBucketAgeMs, staleBucketProblem } from './osv-bucket.js';

describe('osvBucketName', () => {
  it('maps a versioned AlmaLinux/Rocky Linux ecosystem to the shared bare bucket name', () => {
    expect(osvBucketName('AlmaLinux:9')).toBe('AlmaLinux');
    expect(osvBucketName('AlmaLinux:8')).toBe('AlmaLinux');
    expect(osvBucketName('Rocky Linux:8')).toBe('Rocky Linux');
  });

  it('leaves an already-bare shared-bucket ecosystem unchanged', () => {
    expect(osvBucketName('AlmaLinux')).toBe('AlmaLinux');
    expect(osvBucketName('Rocky Linux')).toBe('Rocky Linux');
    expect(osvBucketName('Debian')).toBe('Debian');
  });

  // OSV stopped writing the per-release Debian and Alpine buckets in October 2024 and serves
  // every release from "Debian" and "Alpine" (https://storage.googleapis.com/osv-vulnerabilities/ecosystems.txt).
  it('maps every Debian and Alpine release to the shared bucket', () => {
    for (const eco of ['Debian:11', 'Debian:12', 'Debian:13', 'Debian:14', 'Debian:3.0', 'Debian:5.0']) {
      expect(osvBucketName(eco)).toBe('Debian');
    }
    for (const eco of ['Alpine:v3.2', 'Alpine:v3.20', 'Alpine:v3.24']) {
      expect(osvBucketName(eco)).toBe('Alpine');
    }
  });

  it('does not take an ecosystem that merely starts with the same letters for a shared one', () => {
    expect(osvBucketName('DebianLike:1')).toBe('DebianLike:1');
    expect(osvBucketName('Alpine-Edge')).toBe('Alpine-Edge');
  });

  it('leaves ecosystems that still use their own bucket unchanged', () => {
    expect(osvBucketName('Red Hat:9')).toBe('Red Hat:9');
    expect(osvBucketName('npm')).toBe('npm');
    expect(osvBucketName('PyPI')).toBe('PyPI');
  });
});

describe('staleBucketProblem', () => {
  const now = new Date('2026-10-23T09:00:00Z');
  const daysAgo = (n: number) => new Date(now.getTime() - n * 24 * 60 * 60 * 1000);

  it('accepts a bucket whose newest record is recent', () => {
    expect(staleBucketProblem('Debian', daysAgo(0), now)).toBeNull();
    expect(staleBucketProblem('Debian', daysAgo(14), now)).toBeNull();
  });

  it('names a frozen distro bucket, the way the per-release Debian ones were from 2024-10-04', () => {
    const problem = staleBucketProblem('Debian:13', new Date('2024-10-04T14:58:33Z'), now);
    expect(problem).toContain('"Debian:13"');
    expect(problem).toContain('748 days old');
    expect(problem).toContain('ecosystems.txt');
    expect(staleBucketProblem('Ubuntu:22.04:LTS', daysAgo(15), now)).not.toBeNull();
  });

  it('lets a quiet non-distro ecosystem go for weeks, but not for months', () => {
    expect(staleBucketProblem('GitHub Actions', daysAgo(28), now)).toBeNull();
    expect(staleBucketProblem('SwiftURL', daysAgo(60), now)).toBeNull();
    expect(staleBucketProblem('npm', daysAgo(91), now)).not.toBeNull();
  });

  it('treats a bucket with no records as a problem', () => {
    expect(staleBucketProblem('Alpine', null, now)).toContain('holds no records');
  });
});

describe('maxBucketAgeMs', () => {
  it('is tighter for the distro feeds, which change daily', () => {
    for (const eco of ['Debian', 'Debian:13', 'Ubuntu:Pro:22.04:LTS', 'Alpine:v3.20', 'AlmaLinux', 'Rocky Linux:9']) {
      expect(maxBucketAgeMs(eco)).toBe(14 * 24 * 60 * 60 * 1000);
    }
    expect(maxBucketAgeMs('npm')).toBe(90 * 24 * 60 * 60 * 1000);
  });
});
