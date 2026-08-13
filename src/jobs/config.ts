/**
 * Job enable/disable configuration
 *
 * The registry (code) is the source of truth for cron schedules and run logic.
 * JobConfig only stores the enabled override. A missing row falls back to
 * defaultEnabled(source): core sources (NVD/KEV/EPSS) default to enabled so a
 * clean environment gets baseline vulnerability data immediately; every
 * vendor advisory and OSV ecosystem defaults to disabled, since those are
 * high-volume/high-request-count scrapers a fresh deployment shouldn't fire
 * off automatically -- they must be opted into explicitly per environment.
 */
import { prisma } from '../db/client.js';

const CORE_SOURCES = new Set(['nvd', 'kev', 'epss']);

export function defaultEnabled(source: string): boolean {
  return CORE_SOURCES.has(source);
}

export async function isEnabled(source: string): Promise<boolean> {
  const row = await prisma.jobConfig.findUnique({ where: { source } });
  return row?.enabled ?? defaultEnabled(source);
}

export async function setEnabled(source: string, enabled: boolean): Promise<void> {
  await prisma.jobConfig.upsert({
    where: { source },
    create: { source, enabled },
    update: { enabled },
  });
}

export async function getEnabledMap(): Promise<Map<string, boolean>> {
  const rows = await prisma.jobConfig.findMany();
  return new Map(rows.map((r) => [r.source, r.enabled]));
}
