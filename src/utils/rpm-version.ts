/**
 * RPM version comparison algorithm.
 * Implements the same logic as rpm's C rpmvercmp():
 *   1. Split into segments of digits or letters (skip non-alnum separators)
 *   2. Digit segments compare numerically (strip leading zeros)
 *   3. Letter segments compare lexicographically
 *   4. Digit segment > letter segment (type mismatch)
 *   5. Longer string wins when one is exhausted
 */
export function rpmvercmp(a: string, b: string): number {
  if (a === b) return 0;

  let i = 0;
  let j = 0;

  while (i < a.length && j < b.length) {
    // Skip non-alphanumeric characters
    while (i < a.length && !isAlnum(a[i])) i++;
    while (j < b.length && !isAlnum(b[j])) j++;

    if (i >= a.length || j >= b.length) break;

    const aIsDigit = isDigit(a[i]);
    const bIsDigit = isDigit(b[i]);

    // Collect segment of same type from a
    const segStartA = i;
    if (aIsDigit) {
      while (i < a.length && isDigit(a[i])) i++;
    } else {
      while (i < a.length && isAlpha(a[i])) i++;
    }
    const segA = a.slice(segStartA, i);

    // Collect segment of same type from b
    const segStartB = j;
    if (isDigit(b[segStartB])) {
      while (j < b.length && isDigit(b[j])) j++;
    } else {
      while (j < b.length && isAlpha(b[j])) j++;
    }
    const segB = b.slice(segStartB, j);

    // Type mismatch: digit > alpha
    if (aIsDigit && !isDigit(b[segStartB])) return 1;
    if (!aIsDigit && isDigit(b[segStartB])) return -1;

    if (aIsDigit) {
      // Numeric comparison: strip leading zeros then compare by length, then lexicographic
      const na = segA.replace(/^0+/, '') || '0';
      const nb = segB.replace(/^0+/, '') || '0';
      if (na.length !== nb.length) return na.length > nb.length ? 1 : -1;
      if (na > nb) return 1;
      if (na < nb) return -1;
    } else {
      if (segA > segB) return 1;
      if (segA < segB) return -1;
    }
  }

  // One or both exhausted
  if (i < a.length) return 1;
  if (j < b.length) return -1;
  return 0;
}

/**
 * Full RPM version comparison including epoch and release.
 * Format: [epoch:]version[-release]
 * Epoch defaults to 0. Compare epoch → version → release in order.
 */
export function compareRpmVersions(a: string, b: string): number {
  const pa = parseEvr(a);
  const pb = parseEvr(b);

  // Epoch comparison (numeric)
  if (pa.epoch !== pb.epoch) return pa.epoch > pb.epoch ? 1 : -1;

  const vCmp = rpmvercmp(pa.version, pb.version);
  if (vCmp !== 0) return vCmp;

  return rpmvercmp(pa.release, pb.release);
}

function parseEvr(s: string): { epoch: number; version: string; release: string } {
  let epoch = 0;
  let rest = s;

  const colonIdx = rest.indexOf(':');
  if (colonIdx !== -1) {
    epoch = parseInt(rest.slice(0, colonIdx), 10) || 0;
    rest = rest.slice(colonIdx + 1);
  }

  const dashIdx = rest.lastIndexOf('-');
  if (dashIdx !== -1) {
    return { epoch, version: rest.slice(0, dashIdx), release: rest.slice(dashIdx + 1) };
  }

  return { epoch, version: rest, release: '' };
}

function isDigit(c: string): boolean {
  return c >= '0' && c <= '9';
}

function isAlpha(c: string): boolean {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

function isAlnum(c: string): boolean {
  return isDigit(c) || isAlpha(c);
}
