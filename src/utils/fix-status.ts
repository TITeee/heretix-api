/**
 * Why a vulnerable package has no fixed version, normalized across sources.
 * Returned per search result as `fixStatus` (with the source's own wording in
 * `fixStatusDetail`); null when the result has a fixed version, or when the
 * source says nothing beyond "no fix" (see README).
 *
 * The set may grow as more sources are mapped. Consumers must treat a value
 * they do not know like `affected`, so adding one never silently turns a
 * finding into "nothing to do".
 */
export type FixStatus =
  | 'affected'             // not fixed yet; a fix may still come
  | 'deferred'             // the vendor has postponed the fix
  | 'will_not_fix'         // the vendor has decided not to fix it
  | 'out_of_support'       // outside the vendor's support scope; no fix will come
  | 'under_investigation'; // the vendor has not yet confirmed whether it applies

export interface FixStatusInfo {
  fixStatus: FixStatus;
  /** The source's own wording, verbatim (e.g. Red Hat's "Will not fix"). */
  fixStatusDetail: string | null;
}

/**
 * A Red Hat CSAF VEX remediation for an unfixed product, normalized.
 *
 * Red Hat publishes the reason as (category, details); observed on the live
 * VEX archive:
 *   no_fix_planned / "Will not fix"          -> will_not_fix
 *   no_fix_planned / "Out of support scope"  -> out_of_support
 *   none_available / "Fix deferred"          -> deferred
 *   none_available / "Affected"              -> affected
 * An unrecognized details string falls back on its category. Categories that
 * do not describe the absence of a fix (vendor_fix, workaround, mitigation)
 * return null -- a workaround is orthogonal to whether a fix will come.
 */
export function redHatRemediationStatus(category: unknown, details: unknown): FixStatusInfo | null {
  const detail = typeof details === 'string' && details.trim() ? details.trim() : null;
  const d = detail?.toLowerCase();
  if (category === 'no_fix_planned') {
    return { fixStatus: d === 'out of support scope' ? 'out_of_support' : 'will_not_fix', fixStatusDetail: detail };
  }
  if (category === 'none_available') {
    return { fixStatus: d === 'fix deferred' ? 'deferred' : 'affected', fixStatusDetail: detail };
  }
  return null;
}
