/**
 * Job enable/disable configuration
 *
 * The registry (code) is the source of truth for cron schedules and run logic.
 * JobConfig only stores the enabled override. A missing row means enabled
 * (default true), so newly added jobs run without explicit configuration.
 */
import { prisma } from '../db/client.js';

export async function isEnabled(source: string): Promise<boolean> {
  const row = await prisma.jobConfig.findUnique({ where: { source } });
  return row?.enabled ?? true;
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
