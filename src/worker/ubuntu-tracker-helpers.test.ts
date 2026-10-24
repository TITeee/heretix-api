import { describe, it, expect } from 'vitest';
import { TarReader, isCveFileName, parseUbuntuCveFile } from './ubuntu-tracker-helpers.js';

// Lines as they stand in the tracker (retired/CVE-2023-31486 and retired/CVE-2016-2781).
const PERL = `Candidate: CVE-2023-31486
Priority: medium

Patches_libhttp-tiny-perl:
upstream_libhttp-tiny-perl: needed
trusty_libhttp-tiny-perl: ignored (end of standard support)
focal_libhttp-tiny-perl: ignored (end of standard support, was ignored [see notes])
jammy_libhttp-tiny-perl: ignored (see notes)
devel_libhttp-tiny-perl: ignored (see notes)
Patches_perl:
upstream_perl: needed
jammy_perl: ignored (only affects Perl for Windows)
noble_perl: needs-triage
resolute_perl: deferred (2026-10-15)
esm-apps/jammy_perl: needed
questing_perl: pending (5.40.1-6ubuntu0.1)
bionic_perl: needed
`;

describe('parseUbuntuCveFile', () => {
  it('keeps the unfixed statuses of the maintained releases, with their reasons', () => {
    const rows = parseUbuntuCveFile('CVE-2023-31486', PERL);
    expect(rows).toEqual([
      { ecosystem: 'Ubuntu:20.04:LTS', sourcePackage: 'libhttp-tiny-perl', vulnId: 'CVE-2023-31486', status: 'ignored', reason: 'end of standard support, was ignored [see notes]' },
      { ecosystem: 'Ubuntu:22.04:LTS', sourcePackage: 'libhttp-tiny-perl', vulnId: 'CVE-2023-31486', status: 'ignored', reason: 'see notes' },
      { ecosystem: 'Ubuntu:22.04:LTS', sourcePackage: 'perl', vulnId: 'CVE-2023-31486', status: 'ignored', reason: 'only affects Perl for Windows' },
      { ecosystem: 'Ubuntu:24.04:LTS', sourcePackage: 'perl', vulnId: 'CVE-2023-31486', status: 'needs-triage', reason: null },
      { ecosystem: 'Ubuntu:26.04:LTS', sourcePackage: 'perl', vulnId: 'CVE-2023-31486', status: 'deferred', reason: '2026-10-15' },
    ]);
  });

  it('leaves out upstream, the development release, a pocket-qualified archive and releases it does not maintain', () => {
    const rows = parseUbuntuCveFile('CVE-2023-31486', PERL);
    const keys = rows.map((r) => `${r.ecosystem} ${r.sourcePackage}`);
    expect(keys.some((k) => k.includes('esm-apps'))).toBe(false);
    // bionic (18.04) and questing (25.10, interim) are not maintained; devel and upstream are not releases.
    expect(rows.filter((r) => r.sourcePackage === 'perl').map((r) => r.ecosystem)).toEqual([
      'Ubuntu:22.04:LTS', 'Ubuntu:24.04:LTS', 'Ubuntu:26.04:LTS',
    ]);
  });

  it('leaves out the retired kernel flavours, and keeps every other kernel entry', () => {
    const rows = parseUbuntuCveFile('CVE-2026-2', [
      'Patches_linux-azure-5.19:',
      'jammy_linux-azure-5.19: ignored (superseded by linux-azure-6.8)',
      'Patches_linux-oem-6.0:',
      'jammy_linux-oem-6.0: ignored (end of kernel support)',
      'Patches_linux-aws:',
      'jammy_linux-aws: needed',
      'Patches_linux:',
      'jammy_linux: pending (5.15.0-170.180)',
      'Patches_linux-firmware:',
      'jammy_linux-firmware: ignored (code not shipped in this release)',
      // The same wording on a package that is not a kernel flavour is kept.
      'Patches_oldlib:',
      'jammy_oldlib: ignored (end of standard support)',
    ].join('\n'));
    expect(rows.map((r) => `${r.sourcePackage}:${r.status}`)).toEqual([
      'linux-aws:needed', 'linux:pending', 'linux-firmware:ignored', 'oldlib:ignored',
    ]);
  });

  it('drops the statuses that mean a fix exists or there is no problem', () => {
    const rows = parseUbuntuCveFile('CVE-2026-1', [
      'Patches_a:',
      'jammy_a: released (1.2-1ubuntu0.22.04.1)',
      'noble_a: not-affected (1.2-1)',
      'focal_a: DNE',
      'Patches_b:',
      'jammy_b: needed',
    ].join('\n'));
    expect(rows.map((r) => `${r.sourcePackage}:${r.status}`)).toEqual(['b:needed']);
  });

  it('reads a file with Windows line endings the same', () => {
    expect(parseUbuntuCveFile('CVE-2026-1', 'jammy_a: needed\r\nnoble_a: ignored (see notes)\r\n')).toHaveLength(2);
  });
});

describe('isCveFileName', () => {
  it('takes the CVE files of active/ and retired/, and nothing else', () => {
    expect(isCveFileName('active/CVE-2016-2781')).toBe('CVE-2016-2781');
    expect(isCveFileName('retired/CVE-2023-31486')).toBe('CVE-2023-31486');
    expect(isCveFileName('active/10autotriage.linux')).toBeNull();
    expect(isCveFileName('retired/CVE-2023-31486.orig')).toBeNull();
    expect(isCveFileName('scripts/CVE-2023-31486')).toBeNull();
  });
});

/** A ustar archive of the given files, as `git archive` writes it. */
function tar(files: Record<string, string>, extra?: Buffer[]): Buffer {
  const blocks: Buffer[] = [...(extra ?? [])];
  const header = (name: string, size: number, type = '0') => {
    const h = Buffer.alloc(512);
    h.write(name, 0, 100, 'utf8');
    h.write('0000644\0', 100);
    h.write(size.toString(8).padStart(11, '0') + '\0', 124);
    h.write(type, 156);
    h.write('ustar\0', 257);
    return h;
  };
  for (const [name, content] of Object.entries(files)) {
    const body = Buffer.from(content);
    blocks.push(header(name, body.length), body, Buffer.alloc((512 - (body.length % 512)) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return Buffer.concat(blocks);
}

describe('TarReader', () => {
  const files = { 'active/CVE-2026-1': 'jammy_a: needed\n', 'retired/CVE-2026-2': 'x'.repeat(1300) };

  it('hands over every file with its content', () => {
    const seen: Record<string, number> = {};
    new TarReader((name, content) => { seen[name] = content.length; }).push(tar(files));
    expect(seen).toEqual({ 'active/CVE-2026-1': 16, 'retired/CVE-2026-2': 1300 });
  });

  it('reads an archive that arrives in arbitrary pieces', () => {
    const data = tar(files);
    const seen: string[] = [];
    const reader = new TarReader((name) => seen.push(name));
    for (let i = 0; i < data.length; i += 333) reader.push(data.subarray(i, i + 333));
    expect(seen).toEqual(['active/CVE-2026-1', 'retired/CVE-2026-2']);
  });

  it('skips a directory entry and a pax header, using the path the header gives', () => {
    const pax = Buffer.from('30 path=active/CVE-2026-3\n');
    const paxHeader = Buffer.alloc(512);
    paxHeader.write('pax', 0, 100);
    paxHeader.write(pax.length.toString(8).padStart(11, '0') + '\0', 124);
    paxHeader.write('x', 156);
    const dir = Buffer.alloc(512);
    dir.write('active/', 0, 100);
    dir.write('00000000000\0', 124);
    dir.write('5', 156);
    const seen: string[] = [];
    new TarReader((name) => seen.push(name)).push(tar({ 'ignored-name': 'jammy_c: needed\n' }, [dir, paxHeader, pax, Buffer.alloc(512 - pax.length)]));
    expect(seen).toEqual(['active/CVE-2026-3']);
  });
});
