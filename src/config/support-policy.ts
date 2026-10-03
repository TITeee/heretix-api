/**
 * OS version support policy
 *
 * OSV publishes per-release ecosystems back to Debian 3.0, Alpine v3.2 and
 * Ubuntu 14.04. Keeping every one of them correct (matching rules, accuracy
 * checks, upstream format changes) costs maintenance effort for releases that
 * almost nobody still runs. This file lists the releases we maintain:
 * releases still supported upstream, plus older ones that are still widely
 * deployed (e.g. Debian 11 under LTS, Ubuntu 20.04 under ESM).
 *
 * Releases outside this list are not deleted. Their data stays searchable on a
 * best-effort basis, but they are not part of the accuracy guarantee and are
 * folded away on the dashboard.
 *
 * Review this list when SUPPORT_POLICY_REVIEWED_ON is about six months old, or
 * when a distro ships or retires a release. Upstream EOL dates were taken from
 * endoflife.date.
 */

export const SUPPORT_POLICY_REVIEWED_ON = '2026-10-03';

// Release identifiers as they appear in OSV ecosystem names.
const MAINTAINED_RELEASES: Record<string, ReadonlySet<string>> = {
  // 11 is past regular EOL (2026-08-31) but still under Debian LTS.
  'Debian': new Set(['11', '12', '13', '14']),
  // LTS releases only; 20.04 is kept for its ESM period (to 2030). Interim
  // releases (e.g. 25.10) live for nine months and are not maintained.
  'Ubuntu': new Set(['20.04', '22.04', '24.04', '26.04']),
  'Alpine': new Set(['v3.21', 'v3.22', 'v3.23', 'v3.24']),
  'AlmaLinux': new Set(['8', '9', '10']),
  'Rocky Linux': new Set(['8', '9', '10']),
};

/**
 * Whether an OSV ecosystem name falls under the support policy.
 *
 * Ecosystems without a release suffix (npm, PyPI, the shared AlmaLinux
 * bucket, ...) and distros the policy does not cover are always maintained.
 * Ubuntu variants (Pro, Pro:FIPS, Pro:Realtime, ...) follow the LTS release
 * they are based on, so "Ubuntu:Pro:FIPS-updates:22.04:LTS" is maintained and
 * "Ubuntu:Pro:18.04:LTS" is not.
 */
export function isMaintainedOsvEcosystem(ecosystem: string): boolean {
  const sep = ecosystem.indexOf(':');
  if (sep === -1) return true;
  const distro = ecosystem.slice(0, sep);
  const releases = MAINTAINED_RELEASES[distro];
  if (!releases) return true;
  const rest = ecosystem.slice(sep + 1).split(':');
  const release = distro === 'Ubuntu' ? rest.find((part) => /^\d+\.\d+$/.test(part)) : rest[0];
  return release !== undefined && releases.has(release);
}
