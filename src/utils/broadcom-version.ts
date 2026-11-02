import { normalizeVersion } from './version.js';

/**
 * Version ordering for Broadcom (VMware) products.
 *
 * VMware names a patch level as an update of a release, with a letter for the
 * patches within it: "8.0 U3e" is the fifth patch of 8.0 Update 3. The advisories
 * spell it several ways, and normalizeVersion() only reads the first:
 *   "8.0 U3e"                 the usual spelling
 *   "6.7u2c", "7.0U3c"        no space, either case (normalizeVersion(): 6.72, 7.3)
 *   "ESXi80U2d-24585300"      an ESXi image profile: 8.0 U2d plus its build (null)
 *   "ESXi70U3sq-23794019"     the security-only image of 7.0 U3q
 *   "7.0 U3t [1]"             with a footnote mark (normalizeVersion(): 7.31)
 *   "8.0a", "7.0.0b"          a patch before the first update (normalizeVersion(): 8.0)
 * and other products add a hot fix or patch to a release ("8.18 HF 5", "8.10 Hot
 * Fix 9", "8.18.1 patch 1"), which normalizeVersion() read as digits of the minor
 * or patch number.
 *
 * Every one becomes major.minor.update, with the letter's place in the alphabet
 * (a = 1) in the release slot -- the order normalizeVersion() already gives
 * "8.0 U3e", so an installed "8.0.3" or "8.0 U3e" compares the same way. A hot fix
 * or patch number takes the release slot after its release.
 *
 * Null for what names no version of the row's own product: a fix given as another
 * component's patch ("Async patch to NSX 4.1.2.6" on Cloud Foundation, which the
 * fetcher keeps only to show) and an ESXi patch bundle ("ESXi670-201912001"),
 * which names no update. A null fix is shown but never compared.
 *
 * Used both when AdvisoryAffectedProduct rows are written (advisory-fetcher.ts)
 * and when a search compares against them (routes/vulnerabilities.ts) -- the same
 * arrangement as sonicwall-version.ts.
 */

// "ESXi70U3sq": an "s" before the letter marks the security-only image of that patch.
function letterRank(letters: string): number | null {
  const l = letters.toLowerCase();
  if (l === '') return 0;
  const letter = l.length === 1 ? l : l.length === 2 && l[0] === 's' ? l[1] : null;
  return letter ? letter.charCodeAt(0) - 96 : null;
}

function update(major: string, minor: string, upd: string, letters: string): bigint | null {
  const rank = letterRank(letters);
  if (rank === null) return null;
  return normalizeVersion(`${major}.${minor}.${upd}${rank ? `-${rank}` : ''}`);
}

/** BigInt encoding for AdvisoryAffectedProduct's *Int columns, or null (see above). */
export function broadcomVersionToInt(input: string): bigint | null {
  const v = input.trim().replace(/\s*\[\d+\]$/, '').replace(/\s*\*+$/, '').replace(/\+$/, '').trim();
  if (/^(?:async\s+patch|nsx)/i.test(v)) return null;

  const upd = v.match(/^(\d+)\.(\d+)\s*U(\d+)([a-z]{0,2})$/i);
  if (upd) return update(upd[1], upd[2], upd[3], upd[4]);

  // "ESXi80a-20842819" is 8.0a, a patch of the release before its first update.
  const image = v.match(/^ESXi(\d)(\d)(?:U(\d+))?([a-z]{0,2})-\d+$/i);
  if (image) return update(image[1], image[2], image[3] ?? '0', image[4]);

  // "ESXi_7.0.0-1.20.16321839" (7.0.0 patch release 1), "ESXi-9.1.0.0200-25557999".
  const dotted = v.match(/^ESXi[_-](\d+\.\d+\.\d+(?:\.\d+)?)(?:-(\d+)\.\d+)?(?:[-.]\d{6,})$/i);
  if (dotted) return normalizeVersion(dotted[2] && dotted[2] !== '0' ? `${dotted[1]}-${dotted[2]}` : dotted[1]);
  if (/^ESXi/i.test(v)) return null;

  // vCenter's patches of a release before its first update: "8.0a", "7.0.0b".
  const lettered = v.match(/^(\d+)\.(\d+)(?:\.0)?([a-z])$/i);
  if (lettered) return update(lettered[1], lettered[2], '0', lettered[3]);

  // "6.5.x HF": a hot fix for the whole 6.5 line.
  const fix = v.replace(/(\.x)+(?=\s)/i, '').match(/^(\d+\.\d+(?:\.\d+)?)\s*(?:HF|Hot\s*Fix|patch|\+\s*patch)\s*(\d+)?$/i);
  if (fix) {
    const release = fix[1].split('.').length === 2 ? `${fix[1]}.0` : fix[1];
    return normalizeVersion(`${release}-${fix[2] ?? 1}`);
  }

  const build = v.match(/^(\d+(?:\.\d+){1,3})\s+Build\s+\d+$/i);
  if (build) return normalizeVersion(build[1]);

  return normalizeVersion(v);
}
