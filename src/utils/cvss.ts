// A CommonJS bundle whose named exports Node's ESM loader cannot detect, so
// `import { fromVector }` fails at runtime despite type-checking.
import cvssCalculator from 'ae-cvss-calculator';

const { fromVector } = cvssCalculator;

export interface CvssScore {
  score: number;
  vector: string;
}

/**
 * CVSS base score for a vector string, or null when it is not a CVSS 3.x /
 * 4.0 vector the calculator accepts.
 *
 * OSV's severity[].score carries only the vector ("CVSS:3.1/AV:N/..."), never
 * the number, so without this every OSV-only vulnerability (a GHSA with no
 * CVE, or a CVE NVD has not analyzed yet) had a severity but no CVSS score.
 * The arithmetic is FIRST's, via ae-cvss-calculator: 3.x is a closed formula,
 * 4.0 a macro-vector lookup that is impractical to maintain by hand.
 * CVSS 2.0 vectors are deliberately not scored -- OSV does not publish them,
 * and a 2.0 score is not comparable with the 3.x/4.0 ones stored alongside.
 */
export function cvssBaseScore(vector: string): CvssScore | null {
  const v = vector.trim();
  if (!/^CVSS:(3\.[01]|4\.0)\//.test(v)) return null;
  try {
    const parsed = fromVector(v);
    const base = parsed?.calculateScores().base;
    if (typeof base !== 'number' || !Number.isFinite(base) || base < 0 || base > 10) return null;
    return { score: base, vector: v };
  } catch {
    return null;
  }
}

/**
 * The CVSS score for an OSV record's severity[] entries: CVSS_V3 preferred
 * over CVSS_V4, mirroring the NVD importer's own v3.1-first preference so a
 * CVE's score does not change scale depending on which source supplied it.
 */
export function cvssFromOsvSeverity(entries: Array<{ type: string; score: string }> | undefined): CvssScore | null {
  for (const type of ['CVSS_V3', 'CVSS_V4']) {
    for (const e of entries ?? []) {
      if (e.type !== type || typeof e.score !== 'string') continue;
      const scored = cvssBaseScore(e.score);
      if (scored) return scored;
    }
  }
  return null;
}
