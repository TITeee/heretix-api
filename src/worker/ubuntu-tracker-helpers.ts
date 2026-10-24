/**
 * Pure parsing of the Ubuntu CVE Tracker (https://git.launchpad.net/ubuntu-cve-tracker),
 * kept apart from ubuntu-tracker-fetcher.ts so it can be unit tested without the Prisma
 * client or git.
 *
 * It is the source OSV's UBUNTU-CVE records are generated from, but carries what they drop:
 * whether Ubuntu will fix a package at all. A CVE is a file (active/CVE-2023-31486, or under
 * retired/ once every release is settled -- "ignored" counts as settled, so the decisions
 * not to fix are mostly there), with one block per source package:
 *
 *   Patches_perl:
 *   upstream_perl: needed
 *   focal_perl: ignored (end of standard support, was ignored [see notes])
 *   jammy_perl: ignored (see notes)
 *   noble_perl: needs-triage
 *   esm-apps/jammy_perl: needed
 *
 * heretix-api uses it only to label OSV's unfixed Ubuntu rows -- matching stays on OSV -- so
 * only the statuses that mean "no fix yet" are kept, for the releases it maintains.
 *
 * One kind of entry is left out for its number: the tracker lists every CVE against hundreds
 * of kernel flavours (linux-azure-5.19, linux-oem-6.0, ...) and marks the ones that are no
 * longer built "ignored (superseded by linux-azure-6.8)", "ignored (end of kernel support)".
 * That is 1.5 million rows, 85% of the file, for flavours nobody runs, and all they would
 * add to an OSV row is "out of support".
 */

export interface UbuntuStatusRow {
  ecosystem: string; // "Ubuntu:22.04:LTS", as on OSVAffectedPackage
  sourcePackage: string;
  vulnId: string; // CVE id
  status: string; // "needs-triage" | "needed" | "pending" | "deferred" | "ignored"
  reason: string | null; // the text in brackets, e.g. "end of standard support", "see notes"
}

/**
 * Release codenames and the OSV ecosystem each one is stored under. The releases of
 * support-policy.ts that the tracker still tracks; an older or interim release is not
 * maintained, so its OSV rows are not labelled.
 */
export const UBUNTU_ECOSYSTEM_BY_CODENAME: Record<string, string> = {
  focal: 'Ubuntu:20.04:LTS',
  jammy: 'Ubuntu:22.04:LTS',
  noble: 'Ubuntu:24.04:LTS',
  resolute: 'Ubuntu:26.04:LTS',
};

const UNFIXED_STATUSES = new Set(['needs-triage', 'needed', 'pending', 'deferred', 'ignored']);

// "jammy_perl: ignored (see notes)": codename, source package, status, optional reason. A
// pocket-qualified key ("esm-apps/jammy_perl", "bluefield/noble_x") does not match: it is a
// different archive than the one an Ubuntu:22.04:LTS record is about.
const STATUS_LINE = /^([a-z]+)_(\S+): (\S+)(?: \((.*)\))?\s*$/;

/** A kernel flavour that is no longer built: the "ignored" entries not worth a row (see above). */
function isRetiredKernelFlavour(sourcePackage: string, status: string, reason: string | null): boolean {
  return status === 'ignored' && sourcePackage.startsWith('linux') && !!reason && /^(end of |superseded by )/.test(reason);
}

/** The unfixed (release, package) statuses of one CVE file. */
export function parseUbuntuCveFile(vulnId: string, text: string): UbuntuStatusRow[] {
  const rows: UbuntuStatusRow[] = [];
  for (const line of text.split(/\r?\n/)) {
    const m = STATUS_LINE.exec(line);
    if (!m) continue;
    const [, codename, sourcePackage, status, reason] = m;
    const ecosystem = UBUNTU_ECOSYSTEM_BY_CODENAME[codename];
    if (!ecosystem || !UNFIXED_STATUSES.has(status)) continue;
    const note = reason?.trim() || null;
    if (isRetiredKernelFlavour(sourcePackage, status, note)) continue;
    rows.push({ ecosystem, sourcePackage, vulnId, status, reason: note });
  }
  return rows;
}

/** A tracker file name that is a CVE ("CVE-2023-31486"); the directories also hold notes and scripts. */
export function isCveFileName(path: string): string | null {
  const m = /^(?:active|retired)\/(CVE-\d{4}-\d{4,})$/.exec(path);
  return m ? m[1] : null;
}

/**
 * Entries of a tar stream, one at a time, without holding the archive: `git archive`
 * writes ustar (with pax headers for the odd long name). Each file is passed to `onFile`
 * as it completes. Directories, links and pax records carry no content we want.
 */
export class TarReader {
  private buf: Buffer = Buffer.alloc(0);
  private header: { name: string; size: number; type: string } | null = null;
  private longName: string | null = null;
  private done = false;

  constructor(private readonly onFile: (name: string, content: Buffer) => void) {}

  push(chunk: Buffer): void {
    if (this.done) return;
    this.buf = this.buf.length === 0 ? chunk : Buffer.concat([this.buf, chunk]);
    for (;;) {
      if (!this.header) {
        if (this.buf.length < 512) return;
        const block = this.buf.subarray(0, 512);
        if (block.every((b) => b === 0)) {
          this.done = true;
          return;
        }
        const field = (from: number, len: number) => block.toString('utf8', from, from + len).replace(/\0.*$/s, '');
        const prefix = field(345, 155);
        const name = this.longName ?? (prefix ? `${prefix}/${field(0, 100)}` : field(0, 100));
        this.header = { name, size: parseInt(field(124, 12).trim() || '0', 8), type: field(156, 1) || '0' };
        this.longName = null;
        this.buf = this.buf.subarray(512);
      }
      const padded = Math.ceil(this.header.size / 512) * 512;
      if (this.buf.length < padded) return;
      const content = this.buf.subarray(0, this.header.size);
      const { name, type } = this.header;
      if (type === '0' || type === '') this.onFile(name, content);
      else if (type === 'x') {
        // pax extended header: "<len> path=<name>\n"
        const path = /\d+ path=([^\n]*)\n/.exec(content.toString('utf8'));
        if (path) this.longName = path[1];
      } else if (type === 'L') this.longName = content.toString('utf8').replace(/\0.*$/s, '');
      this.buf = this.buf.subarray(padded);
      this.header = null;
    }
  }
}
