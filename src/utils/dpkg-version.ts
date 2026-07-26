/**
 * Debian package version comparison algorithm (dpkg --compare-versions).
 * Format: [epoch:]upstream_version[-debian_revision]
 * Reference: Debian Policy Manual §5.6.12 ("Version").
 *
 *   1. Compare epoch numerically (missing = 0).
 *   2. Compare upstream_version, then debian_revision, using the same
 *      alternating digit/non-digit segment algorithm ("verrevcmp"):
 *        - Non-digit segments compare by a modified lexical order where
 *          '~' sorts before anything (even the end of the string), letters
 *          sort before all other non-digit characters, and everything else
 *          sorts by ASCII value after letters.
 *        - Digit segments compare numerically (leading zeros stripped).
 */

function nonDigitOrder(c: string | undefined): number {
  if (c === undefined) return 0;
  if (c === '~') return -1;
  if (/[a-zA-Z]/.test(c)) return c.charCodeAt(0);
  return c.charCodeAt(0) + 256;
}

function compareNonDigitSegment(a: string, b: string): number {
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const oa = nonDigitOrder(a[i]);
    const ob = nonDigitOrder(b[i]);
    if (oa !== ob) return oa < ob ? -1 : 1;
  }
  return 0;
}

function compareDigitSegment(a: string, b: string): number {
  const na = a.replace(/^0+(?=\d)/, '');
  const nb = b.replace(/^0+(?=\d)/, '');
  if (na.length !== nb.length) return na.length < nb.length ? -1 : 1;
  if (na < nb) return -1;
  if (na > nb) return 1;
  return 0;
}

function isDigit(c: string): boolean {
  return c >= '0' && c <= '9';
}

/** Compares an upstream_version or debian_revision string (dpkg's verrevcmp). */
export function verrevcmp(a: string, b: string): number {
  let i = 0, j = 0;

  while (i < a.length || j < b.length) {
    let sa = '', sb = '';
    while (i < a.length && !isDigit(a[i])) sa += a[i++];
    while (j < b.length && !isDigit(b[j])) sb += b[j++];
    const nonDigitCmp = compareNonDigitSegment(sa, sb);
    if (nonDigitCmp !== 0) return nonDigitCmp;

    let da = '', db = '';
    while (i < a.length && isDigit(a[i])) da += a[i++];
    while (j < b.length && isDigit(b[j])) db += b[j++];
    const digitCmp = compareDigitSegment(da || '0', db || '0');
    if (digitCmp !== 0) return digitCmp;
  }

  return 0;
}

function parseEvr(s: string): { epoch: number; version: string; revision: string } {
  let epoch = 0;
  let rest = s;

  const colonIdx = rest.indexOf(':');
  if (colonIdx !== -1) {
    epoch = parseInt(rest.slice(0, colonIdx), 10) || 0;
    rest = rest.slice(colonIdx + 1);
  }

  const dashIdx = rest.lastIndexOf('-');
  if (dashIdx !== -1) {
    return { epoch, version: rest.slice(0, dashIdx), revision: rest.slice(dashIdx + 1) };
  }
  return { epoch, version: rest, revision: '' };
}

/** Full comparison including epoch and debian_revision. */
export function compareDpkgVersions(a: string, b: string): number {
  const pa = parseEvr(a);
  const pb = parseEvr(b);

  if (pa.epoch !== pb.epoch) return pa.epoch > pb.epoch ? 1 : -1;

  const vCmp = verrevcmp(pa.version, pb.version);
  if (vCmp !== 0) return vCmp;

  return verrevcmp(pa.revision, pb.revision);
}
