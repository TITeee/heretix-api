/**
 * Pure parsing of the Debian security tracker's JSON export
 * (https://security-tracker.debian.org/tracker/data/json), kept apart from
 * debian-tracker-fetcher.ts so it can be unit tested without the Prisma client.
 *
 * Shape: { [sourcePackage]: { [CVE-or-TEMP-id]: { releases: { [codename]: {
 *   status: "resolved" | "open" | "undetermined", urgency, fixed_version?,
 *   nodsa?, nodsa_reason?: "" | "ignored" | "postponed" } } } } }
 *
 * It is the source OSV's DEBIAN-CVE records are generated from, but carries
 * what they drop: whether Debian will ship a fix at all (no-dsa / ignored /
 * postponed). heretix-api uses it only for that -- matching stays on the OSV
 * rows -- so only unresolved entries are kept.
 */
import { DEBIAN_CODENAMES } from './debian-sources-helpers.js';

export interface TrackerStatusRow {
  ecosystem: string; // "Debian:12", as on OSVAffectedPackage
  sourcePackage: string;
  vulnId: string; // CVE id, or the tracker's TEMP-... id
  status: string; // "open" | "undetermined"
  urgency: string | null;
  nodsa: string | null;
  nodsaReason: string | null;
}

const ECOSYSTEM_BY_CODENAME = new Map(
  Object.entries(DEBIAN_CODENAMES).map(([major, codename]) => [codename, `Debian:${major}`]),
);

/**
 * Every unresolved (package, id, release) entry, for releases with a Debian
 * ecosystem in OSV. "sid" (unstable) has none and is skipped; so is any
 * codename DEBIAN_CODENAMES does not know yet. bullseye (11) is no longer in
 * the export at all -- it moved to Debian LTS -- so its OSV rows get no status.
 */
export function unresolvedTrackerRows(data: unknown): TrackerStatusRow[] {
  const rows: TrackerStatusRow[] = [];
  if (!data || typeof data !== 'object') return rows;

  for (const [sourcePackage, entries] of Object.entries(data as Record<string, unknown>)) {
    if (!entries || typeof entries !== 'object') continue;
    for (const [vulnId, entry] of Object.entries(entries as Record<string, unknown>)) {
      const releases = (entry as { releases?: unknown } | null)?.releases;
      if (!releases || typeof releases !== 'object') continue;
      for (const [codename, raw] of Object.entries(releases as Record<string, unknown>)) {
        const ecosystem = ECOSYSTEM_BY_CODENAME.get(codename);
        if (!ecosystem || !raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        if (r.status !== 'open' && r.status !== 'undetermined') continue;
        rows.push({
          ecosystem,
          sourcePackage,
          vulnId,
          status: r.status,
          urgency: typeof r.urgency === 'string' ? r.urgency : null,
          nodsa: typeof r.nodsa === 'string' ? r.nodsa : null,
          nodsaReason: typeof r.nodsa_reason === 'string' ? r.nodsa_reason : null,
        });
      }
    }
  }
  return rows;
}
