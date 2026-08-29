import { describe, it, expect } from 'vitest';
import { parseSourcesFile } from './debian-sources-helpers.js';

describe('parseSourcesFile', () => {
  it('parses a single-line Binary field into a comma-separated list', () => {
    const raw = [
      'Package: acl',
      'Format: 3.0 (quilt)',
      'Binary: libacl1, libacl1-dev, acl',
      'Version: 2.3.1-3',
    ].join('\n');

    expect(parseSourcesFile(raw)).toEqual([
      { source: 'acl', binaries: ['libacl1', 'libacl1-dev', 'acl'] },
    ]);
  });

  it('folds a Binary field wrapped across continuation lines', () => {
    // Real gnupg2 stanza shape: Binary: wraps because the list is long.
    const raw = [
      'Package: gnupg2',
      'Binary: gnupg, gnupg-utils, gpgv, gpgsm, gpg-agent, dirmngr, gnupg-l10n,',
      ' gnupg-udeb, gpgv-udeb',
      'Version: 2.2.40-1.1',
    ].join('\n');

    expect(parseSourcesFile(raw)).toEqual([
      {
        source: 'gnupg2',
        binaries: ['gnupg', 'gnupg-utils', 'gpgv', 'gpgsm', 'gpg-agent', 'dirmngr', 'gnupg-l10n', 'gnupg-udeb', 'gpgv-udeb'],
      },
    ]);
  });

  it('defaults to a single binary matching the source name when there is no Binary field', () => {
    const raw = ['Package: some-tool', 'Version: 1.0-1'].join('\n');

    expect(parseSourcesFile(raw)).toEqual([
      { source: 'some-tool', binaries: ['some-tool'] },
    ]);
  });

  it('parses multiple stanzas separated by blank lines', () => {
    const raw = [
      'Package: acl',
      'Binary: libacl1, libacl1-dev, acl',
      '',
      'Package: gcc-12',
      'Binary: gcc-12, gcc-12-base, cpp-12',
    ].join('\n');

    expect(parseSourcesFile(raw)).toEqual([
      { source: 'acl', binaries: ['libacl1', 'libacl1-dev', 'acl'] },
      { source: 'gcc-12', binaries: ['gcc-12', 'gcc-12-base', 'cpp-12'] },
    ]);
  });

  it('skips a stanza with no Package field', () => {
    const raw = ['Format: 3.0 (quilt)', 'Version: 1.0-1'].join('\n');

    expect(parseSourcesFile(raw)).toEqual([]);
  });

  it('returns an empty array for blank input', () => {
    expect(parseSourcesFile('')).toEqual([]);
  });
});
