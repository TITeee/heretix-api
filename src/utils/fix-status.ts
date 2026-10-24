/**
 * Why a vulnerable package has no fixed version, normalized across sources.
 * Returned per search result as `fixStatus` (with the source's own wording in
 * `fixStatusDetail`). A source that tracks a package as unfixed but gives no
 * reason yields `affected` with a null detail; results from sources that do
 * not track fix status at all carry null (see docs/api.md).
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
 * A Debian security tracker entry for one (package, CVE, release), normalized,
 * or null when it is resolved (the fix is the OSV row's own fixedVersion).
 *
 * The tracker's own wording is kept in fixStatusDetail, prefixed with the tag
 * it came from ("no-dsa: Minor issue", "ignored: ...", "postponed: ...").
 *   end-of-life urgency                   -> out_of_support (checked first:
 *                                            the package is unsupported in
 *                                            that release, whatever else it says)
 *   no-dsa, reason "ignored"              -> will_not_fix
 *   no-dsa, reason "postponed"            -> deferred
 *   no-dsa, no reason                     -> deferred -- no security update
 *                                            will be issued; a regular point
 *                                            release may or may not fix it
 *   undetermined                          -> under_investigation
 *   open, none of the above               -> affected
 */
export function debianTrackerStatus(entry: {
  status: string;
  urgency?: string | null;
  nodsa?: string | null;
  nodsaReason?: string | null;
}): FixStatusInfo | null {
  if (entry.status === 'resolved') return null;
  if (entry.status === 'undetermined') return { fixStatus: 'under_investigation', fixStatusDetail: 'undetermined' };
  const text = entry.nodsa?.trim() ?? '';
  const withText = (tag: string) => (text ? `${tag}: ${text}` : tag);
  if (entry.urgency === 'end-of-life') return { fixStatus: 'out_of_support', fixStatusDetail: 'end-of-life' };
  if (entry.nodsa !== null && entry.nodsa !== undefined) {
    if (entry.nodsaReason === 'ignored') return { fixStatus: 'will_not_fix', fixStatusDetail: withText('ignored') };
    if (entry.nodsaReason === 'postponed') return { fixStatus: 'deferred', fixStatusDetail: withText('postponed') };
    return { fixStatus: 'deferred', fixStatusDetail: withText('no-dsa') };
  }
  return { fixStatus: 'affected', fixStatusDetail: null };
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

/**
 * An Ubuntu CVE Tracker status for one (release, package, CVE) that has no fix, normalized.
 * The tracker's reason, where it gives one, is kept in fixStatusDetail after the status.
 *   needs-triage                  -> under_investigation (Ubuntu has not looked at it yet)
 *   needed                        -> affected (it will be fixed)
 *   pending                       -> affected (a fix is being built or tested)
 *   deferred                      -> deferred (the tracker gives the date to look at it again)
 *   ignored, "end of ..." reason  -> out_of_support (the release or the pocket is no longer maintained)
 *   ignored, any other reason     -> will_not_fix ("see notes", "only affects Perl for Windows", ...)
 * Any other status (released, not-affected, DNE) has a fix or no problem and returns null.
 */
export function ubuntuTrackerStatus(entry: { status: string; reason?: string | null }): FixStatusInfo | null {
  const reason = entry.reason?.trim() || null;
  const withReason = (tag: string) => (reason ? `${tag}: ${reason}` : tag);
  switch (entry.status) {
    case 'needs-triage':
      return { fixStatus: 'under_investigation', fixStatusDetail: 'needs-triage' };
    case 'needed':
      return { fixStatus: 'affected', fixStatusDetail: null };
    case 'pending':
      return { fixStatus: 'affected', fixStatusDetail: withReason('pending') };
    case 'deferred':
      return { fixStatus: 'deferred', fixStatusDetail: withReason('deferred') };
    case 'ignored':
      return {
        fixStatus: reason && /^end of /i.test(reason) ? 'out_of_support' : 'will_not_fix',
        fixStatusDetail: withReason('ignored'),
      };
    default:
      return null;
  }
}
