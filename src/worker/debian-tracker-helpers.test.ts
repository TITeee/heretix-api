import { describe, it, expect } from 'vitest';
import { unresolvedTrackerRows } from './debian-tracker-helpers.js';

describe('unresolvedTrackerRows', () => {
  it('keeps unresolved entries per release, mapped to the OSV Debian ecosystem (real 389-ds-base / CVE-2023-1055 shape)', () => {
    const data = {
      '389-ds-base': {
        'CVE-2023-1055': {
          scope: 'local',
          releases: {
            bookworm: { status: 'open', repositories: {}, urgency: 'not yet assigned', nodsa: 'Minor issue', nodsa_reason: '' },
            trixie: { status: 'resolved', repositories: {}, fixed_version: '2.3.4+dfsg1-1', urgency: 'not yet assigned' },
            sid: { status: 'open', repositories: {}, urgency: 'not yet assigned' },
          },
        },
      },
      zlib: {
        'TEMP-0000000-ABCDEF': {
          releases: { forky: { status: 'undetermined', repositories: {}, urgency: 'not yet assigned' } },
        },
      },
    };
    expect(unresolvedTrackerRows(data)).toEqual([
      // trixie is resolved (OSV already has its fixedVersion); sid has no OSV ecosystem.
      { ecosystem: 'Debian:12', sourcePackage: '389-ds-base', vulnId: 'CVE-2023-1055', status: 'open', urgency: 'not yet assigned', nodsa: 'Minor issue', nodsaReason: '' },
      { ecosystem: 'Debian:14', sourcePackage: 'zlib', vulnId: 'TEMP-0000000-ABCDEF', status: 'undetermined', urgency: 'not yet assigned', nodsa: null, nodsaReason: null },
    ]);
  });

  it('returns nothing for a malformed export', () => {
    expect(unresolvedTrackerRows(null)).toEqual([]);
    expect(unresolvedTrackerRows({ pkg: { 'CVE-1': { releases: 'nope' } } })).toEqual([]);
  });
});
