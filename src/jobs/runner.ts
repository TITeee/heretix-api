/**
 * Job runner: every collection job runs in a process of its own.
 *
 * Jobs used to run inside the API's own process. A big import blocked its
 * event loop (searches waited up to 13.9 s during EPSS), and anything a job
 * leaked (an unhandled rejection, running out of memory) took the API down
 * with it. Now the API process only schedules: it queues a job, starts a
 * process for it (scripts/run-job.ts) when a slot is free, and records on the
 * job's CollectionJob row whatever that process could not (it crashed, ran out
 * of memory, was stopped).
 *
 * Limits, from the environment:
 *   JOB_MAX_CONCURRENT     jobs running at once (default 2)
 *   JOB_MAX_HEAVY          of those, jobs marked heavy (default 1), so two
 *                          memory-hungry imports never add up
 *   JOB_MAX_OLD_SPACE_MB   each job process's heap limit (default 3072)
 *   JOB_DATABASE_POOL_MAX  each job process's database connections (default 5)
 *
 * A job waits as a 'queued' row until it starts. One source is never queued
 * or run twice at once. On shutdown, waiting jobs are dropped and running
 * ones stopped, each recorded as such on its row.
 */
import { fork, type ChildProcess } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { prisma } from '../db/client.js';
import { logger } from '../utils/logger.js';
import { envInt } from '../api/concurrency-gate.js';
import type { JobDefinition } from './types.js';

export interface RunnerConfig {
  maxConcurrent: number;
  maxHeavy: number;
  maxOldSpaceMb: number;
  childPoolMax: number;
  /** The job process's entry point. */
  script: string;
  /** Node options for the job process (under tsx in development, its loader). */
  execArgv: string[];
  /** How long a stopped job process gets before it is killed. */
  stopGraceMs: number;
}

/** scripts/run-job beside this file's own tree: .ts under tsx, .js once built. */
function defaultScript(): string {
  const here = fileURLToPath(import.meta.url);
  return path.join(path.dirname(here), '..', 'scripts', `run-job${path.extname(here)}`);
}

export function runnerConfigFromEnv(): RunnerConfig {
  return {
    maxConcurrent: Math.max(1, envInt('JOB_MAX_CONCURRENT', 2)),
    maxHeavy: Math.max(1, envInt('JOB_MAX_HEAVY', 1)),
    maxOldSpaceMb: envInt('JOB_MAX_OLD_SPACE_MB', 3072),
    childPoolMax: Math.max(1, envInt('JOB_DATABASE_POOL_MAX', 5)),
    script: defaultScript(),
    execArgv: process.execArgv,
    stopGraceMs: 5_000,
  };
}

export type RequestOutcome = 'started' | 'queued' | 'busy' | 'stopped' | 'failed';

type Waiting = { def: JobDefinition; jobId: string };
type Active = { source: string; jobId: string; heavy: boolean; child?: ChildProcess; done: Promise<void> };

/** Why a job process ended without recording an outcome of its own. */
export function exitReason(code: number | null, signal: string | null, maxOldSpaceMb: number): string {
  // V8 aborts (SIGABRT, exit code 134) when the heap limit is reached.
  if (code === 134 || signal === 'SIGABRT') {
    return `Job process crashed, most likely out of memory (heap limit ${maxOldSpaceMb} MB; exit code ${code ?? signal})`;
  }
  if (signal) return `Job process was killed (${signal}) before recording an outcome`;
  return `Job process exited with code ${code} before recording an outcome`;
}

export class JobRunner {
  private readonly queue: Waiting[] = [];
  private readonly active = new Map<string, Active>();
  /** Sources between the busy check and their queued row being written. */
  private readonly reserving = new Set<string>();
  private stopping = false;

  constructor(private readonly config: RunnerConfig) {}

  /** Queued, starting or running. */
  isBusy(source: string): boolean {
    return this.reserving.has(source) || this.active.has(source) || this.queue.some((w) => w.def.source === source);
  }

  /** Queue a job and start it if a slot is free. Never rejects. */
  async request(def: JobDefinition): Promise<RequestOutcome> {
    if (this.stopping) return 'stopped';
    if (this.isBusy(def.source)) return 'busy';
    this.reserving.add(def.source);
    try {
      const row = await prisma.collectionJob.create({
        data: { source: def.source, status: 'queued' },
        select: { id: true },
      });
      this.queue.push({ def, jobId: row.id });
    } catch (err) {
      logger.error({ job: def.source, err }, 'Failed to queue job');
      return 'failed';
    } finally {
      this.reserving.delete(def.source);
    }
    this.dispatch();
    return this.active.has(def.source) ? 'started' : 'queued';
  }

  /** Start waiting jobs, in order, while the limits allow. */
  private dispatch(): void {
    while (!this.stopping && this.active.size < this.config.maxConcurrent) {
      const heavyRunning = [...this.active.values()].filter((a) => a.heavy).length;
      const index = this.queue.findIndex((w) => !w.def.heavy || heavyRunning < this.config.maxHeavy);
      if (index < 0) return;
      const [next] = this.queue.splice(index, 1);
      this.start(next);
    }
  }

  private start({ def, jobId }: Waiting): void {
    const entry: Active = { source: def.source, jobId, heavy: !!def.heavy, done: Promise.resolve() };
    this.active.set(def.source, entry);
    entry.done = this.run(entry)
      .catch(async (err) => {
        // The runner itself failed (the database, most likely): the row must not stay queued or running.
        logger.error({ job: def.source, err }, 'Job runner error');
        await prisma.collectionJob.updateMany({
          where: { id: jobId, status: { in: ['queued', 'running'] } },
          data: { status: 'failed', completedAt: new Date(), errorMessage: `Job runner error: ${err instanceof Error ? err.message : String(err)}` },
        }).catch(() => {});
      })
      .finally(() => {
        this.active.delete(def.source);
        this.dispatch();
      });
  }

  private async run(entry: Active): Promise<void> {
    const { source, jobId } = entry;
    // Before the process starts, so its own outcome can never be overwritten by this.
    await prisma.collectionJob.update({ where: { id: jobId }, data: { status: 'running', startedAt: new Date() } });

    const child = fork(this.config.script, [source, jobId], {
      execArgv: [...this.config.execArgv, `--max-old-space-size=${this.config.maxOldSpaceMb}`],
      env: { ...process.env, DATABASE_POOL_MAX: String(this.config.childPoolMax) },
    });
    entry.child = child;
    logger.info({ job: source, pid: child.pid }, 'Job process started');

    const { code, signal, error } = await new Promise<{ code: number | null; signal: string | null; error?: Error }>((resolve) => {
      child.once('error', (err) => resolve({ code: null, signal: null, error: err }));
      child.once('exit', (c, s) => resolve({ code: c, signal: s }));
    });

    // The process records its own outcome; a row still 'running' means it
    // could not (crash, out of memory, stopped by shutdown).
    const reason = this.stopping
      ? 'Interrupted: the API was shutting down'
      : error
        ? `Job process could not start: ${error.message}`
        : exitReason(code, signal, this.config.maxOldSpaceMb);
    const { count } = await prisma.collectionJob.updateMany({
      where: { id: jobId, status: 'running' },
      data: { status: 'failed', completedAt: new Date(), errorMessage: reason },
    });

    const row = await prisma.collectionJob.findUnique({ where: { id: jobId }, select: { status: true, metadata: true } });
    const peakMemoryMb = (row?.metadata as { peakMemoryMb?: number } | null)?.peakMemoryMb;
    if (count > 0) logger.error({ job: source, code, signal, reason }, 'Job process ended without an outcome');
    else logger.info({ job: source, status: row?.status, peakMemoryMb }, 'Job process finished');
  }

  /**
   * Stop: drop waiting jobs and stop running ones, recording each on its row.
   * Running jobs get stopGraceMs to exit after SIGTERM, then are killed.
   */
  async stop(): Promise<void> {
    this.stopping = true;
    const waiting = this.queue.splice(0);
    if (waiting.length > 0) {
      await prisma.collectionJob.updateMany({
        where: { id: { in: waiting.map((w) => w.jobId) }, status: 'queued' },
        data: { status: 'failed', completedAt: new Date(), errorMessage: 'Not started: the API was shutting down' },
      }).catch((err) => logger.error({ err }, 'Failed to record dropped jobs'));
    }

    const running = [...this.active.values()];
    for (const a of running) a.child?.kill('SIGTERM');
    const allDone = Promise.all(running.map((a) => a.done));
    const timedOut = await Promise.race([
      allDone.then(() => false),
      new Promise<boolean>((resolve) => setTimeout(() => resolve(true), this.config.stopGraceMs).unref()),
    ]);
    if (timedOut) {
      for (const a of running) a.child?.kill('SIGKILL');
      await allDone;
    }
  }

  /** Resolves once nothing is queued, starting or running. */
  async idle(): Promise<void> {
    for (;;) {
      const active = [...this.active.values()];
      if (active.length === 0 && this.reserving.size === 0 && (this.queue.length === 0 || this.stopping)) return;
      if (active.length > 0) await Promise.all(active.map((a) => a.done));
      else await new Promise((resolve) => setTimeout(resolve, 10));
    }
  }
}

let runner: JobRunner | null = null;

/** The process's job runner, configured from the environment on first use. */
export function getJobRunner(): JobRunner {
  runner ??= new JobRunner(runnerConfigFromEnv());
  return runner;
}
