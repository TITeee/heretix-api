/**
 * Job registry
 *
 * Single source of truth for all collection jobs: their source keys, display
 * labels, cron schedules, and run logic. Static jobs are listed in STATIC_JOBS;
 * OSV per-ecosystem jobs are resolved dynamically (ecosystems are discovered
 * from the DB, not enumerated here).
 */
import { prisma } from '../db/client.js';
import { getDeltaCursor } from './executor.js';
import type { JobDefinition, JobResult } from './types.js';

import { importNVDByDateRange } from '../worker/nvd-fetcher.js';
import { fullImportKEV } from '../worker/kev-fetcher.js';
import { fullImportEPSS } from '../worker/epss-fetcher.js';
import { runAdvisoryFetcher } from '../worker/advisory-fetcher.js';
import { FortinetFetcher } from '../worker/fortinet-fetcher.js';
import { PanFetcher } from '../worker/pan-fetcher.js';
import { CiscoFetcher } from '../worker/cisco-fetcher.js';
import { OracleLinuxFetcher } from '../worker/oracle-linux-fetcher.js';
import { SophosFetcher } from '../worker/sophos-fetcher.js';
import { SonicWallFetcher } from '../worker/sonicwall-fetcher.js';
import { OracleCpuFetcher } from '../worker/oracle-cpu-fetcher.js';
import { BroadcomFetcher } from '../worker/broadcom-fetcher.js';
import { RedHatFetcher } from '../worker/redhat-fetcher.js';
import type { AdvisoryFetcher } from '../worker/advisory-fetcher.js';
import { importOSVEcosystemDelta, importMALDelta } from '../worker/osv-fetcher.js';

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;
const OSV_DELTA_FALLBACK_MS = 30 * DAY_MS;

// Wrap an AdvisoryFetcher run into a JobResult
async function runAdvisory(source: string, fetcher: AdvisoryFetcher): Promise<JobResult> {
  const result = await runAdvisoryFetcher(fetcher);
  return {
    fetched: result.total,
    inserted: result.inserted,
    updated: result.updated,
    failed: result.failed,
  };
}

export const STATIC_JOBS: JobDefinition[] = [
  {
    source: 'nvd',
    label: 'NVD',
    cron: '0 */2 * * *',
    run: async () => {
      const start = await getDeltaCursor('nvd', 2 * HOUR_MS);
      const result = await importNVDByDateRange(start, new Date());
      return { fetched: result.total, updated: result.succeeded, failed: result.failed };
    },
  },
  {
    source: 'kev',
    label: 'CISA KEV',
    cron: '0 9 * * *',
    run: async () => {
      const result = await fullImportKEV();
      return { updated: result.updated };
    },
  },
  {
    source: 'epss',
    label: 'EPSS',
    cron: '0 10 * * *',
    run: async () => {
      const result = await fullImportEPSS();
      return { updated: result.updated };
    },
  },
  { source: 'advisory-fortinet',     label: 'Fortinet',         cron: '0 11 * * *',  run: () => runAdvisory('advisory-fortinet', new FortinetFetcher()) },
  { source: 'advisory-pan',          label: 'Palo Alto',        cron: '15 11 * * *', run: () => runAdvisory('advisory-pan', new PanFetcher()) },
  { source: 'advisory-cisco',        label: 'Cisco',            cron: '30 11 * * *', run: () => runAdvisory('advisory-cisco', new CiscoFetcher()) },
  { source: 'advisory-oracle-linux', label: 'Oracle Linux',     cron: '45 11 * * *', run: () => runAdvisory('advisory-oracle-linux', new OracleLinuxFetcher()) },
  { source: 'advisory-sophos',       label: 'Sophos',           cron: '0 12 * * *',  run: () => runAdvisory('advisory-sophos', new SophosFetcher()) },
  { source: 'advisory-sonicwall',    label: 'SonicWall',        cron: '15 12 * * *', run: () => runAdvisory('advisory-sonicwall', new SonicWallFetcher()) },
  { source: 'advisory-oracle-cpu',   label: 'Oracle CPU',       cron: '30 12 * * *', run: () => runAdvisory('advisory-oracle-cpu', new OracleCpuFetcher()) },
  { source: 'advisory-broadcom',     label: 'Broadcom/VMware',  cron: '0 13 * * *',  run: () => runAdvisory('advisory-broadcom', new BroadcomFetcher()) },
  { source: 'advisory-redhat-rhel9', label: 'Red Hat (RHEL 9)', cron: '15 13 * * *', run: () => runAdvisory('advisory-redhat-rhel9', new RedHatFetcher('rhel9')) },
  { source: 'advisory-redhat-rhel8', label: 'Red Hat (RHEL 8)', cron: '30 13 * * *', run: () => runAdvisory('advisory-redhat-rhel8', new RedHatFetcher('rhel8')) },
  {
    source: 'osv-mal',
    label: 'OSV / Malware',
    cron: '30 8 * * *',
    run: async () => {
      const since = await getDeltaCursor('osv-mal', OSV_DELTA_FALLBACK_MS);
      const result = await importMALDelta(since);
      return { fetched: result.total, inserted: result.inserted, updated: result.updated, failed: result.failed };
    },
  },
];

const STATIC_BY_SOURCE = new Map(STATIC_JOBS.map((j) => [j.source, j]));

/** Build an on-demand JobDefinition for a single OSV ecosystem. */
function osvEcosystemJob(ecosystem: string): JobDefinition {
  const source = `osv-${ecosystem}`;
  return {
    source,
    label: `OSV / ${ecosystem}`,
    cron: '0 8 * * *',
    run: async () => {
      const since = await getDeltaCursor(source, OSV_DELTA_FALLBACK_MS);
      const result = await importOSVEcosystemDelta(ecosystem, since);
      return { fetched: result.total, inserted: result.inserted, updated: result.updated, failed: result.failed };
    },
  };
}

/**
 * Resolve a source key to a runnable JobDefinition.
 * Returns null if the source is unknown (e.g. osv-<eco> for a nonexistent ecosystem).
 */
export async function resolveJob(source: string): Promise<JobDefinition | null> {
  const staticJob = STATIC_BY_SOURCE.get(source);
  if (staticJob) return staticJob;

  // osv-<ecosystem> (osv-mal is static and handled above)
  if (source.startsWith('osv-')) {
    const ecosystem = source.slice(4);
    const exists = await prisma.oSVVulnerability.findFirst({
      where: { ecosystem },
      select: { id: true },
    });
    if (exists) return osvEcosystemJob(ecosystem);
  }

  return null;
}

/** Discover all OSV ecosystem jobs currently present in the DB. */
export async function listOsvEcosystemJobs(): Promise<JobDefinition[]> {
  const rows = await prisma.oSVVulnerability.groupBy({
    by: ['ecosystem'],
    where: { ecosystem: { not: null } },
  });
  return rows
    .map((r) => r.ecosystem)
    .filter((e): e is string => !!e)
    .map((e) => osvEcosystemJob(e));
}

/** Display label for a source, used by the dashboard (single source of truth). */
export function labelFor(source: string): string {
  const staticJob = STATIC_BY_SOURCE.get(source);
  if (staticJob) return staticJob.label;
  if (source.startsWith('osv-')) return `OSV / ${source.slice(4)}`;
  if (source.startsWith('advisory-oracle-linux-')) return `Oracle Linux (${source.slice(22)})`;
  return source;
}
