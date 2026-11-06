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

/**
 * 'full': the first load of a source, which reads everything. 'delta': what the
 * schedule runs, the changes since the last completed run.
 */
export type JobMode = 'full' | 'delta';

export interface JobContext {
  /** The job's own CollectionJob row. */
  jobId: string;
  mode: JobMode;
}

export interface JobDefinition {
  /** Source key, e.g. 'nvd', 'kev', 'advisory-fortinet', 'osv-npm' */
  source: string;
  /** Display label shown in the dashboard */
  label: string;
  /** Cron schedule (used by the scheduler; ignored for on-demand osv-<eco> jobs) */
  cron: string;
  /** Actual work; returns record counts for the CollectionJob row */
  run: (ctx: JobContext) => Promise<JobResult>;
  /**
   * Holds a lot in memory (a whole dataset or archive at once). The job runner
   * runs at most JOB_MAX_HEAVY of these at a time (see runner.ts), so two of
   * them never add up past what a small server has. Measured: EPSS took the
   * process to 2.6GB. A job left unmarked only loses that guard.
   */
  heavy?: boolean;
  /**
   * A source whose schedule reads only changes, so an empty database needs one
   * full load first. A manual Run does that load by itself when `isLoaded()` is
   * false (the job then gets mode 'full'); the schedule skips the job until then.
   */
  firstLoad?: {
    isLoaded: () => Promise<boolean>;
    /** The full load holds a whole dataset in memory: it counts as heavy. */
    heavy?: boolean;
  };
}
