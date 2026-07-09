/**
 * Job registry types
 *
 * A JobDefinition describes a single collection job: its source key, display
 * label, cron schedule, and the work function. The executor wraps every job
 * with a uniform CollectionJob lifecycle, so run() only needs to return counts.
 */

export interface JobResult {
  fetched?: number;
  inserted?: number;
  updated?: number;
  failed?: number;
}

export interface JobDefinition {
  /** Source key, e.g. 'nvd', 'kev', 'advisory-fortinet', 'osv-npm' */
  source: string;
  /** Display label shown in the dashboard */
  label: string;
  /** Cron schedule (used by the scheduler; ignored for on-demand osv-<eco> jobs) */
  cron: string;
  /** Actual work; returns record counts for the CollectionJob row */
  run: () => Promise<JobResult>;
}
