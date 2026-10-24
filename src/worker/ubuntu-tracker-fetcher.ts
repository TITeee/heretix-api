import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { logger } from '../utils/logger.js';
import { prisma } from '../db/client.js';
import { createManyChunked } from '../db/bulk-insert.js';
import { TarReader, isCveFileName, parseUbuntuCveFile, type UbuntuStatusRow } from './ubuntu-tracker-helpers.js';

const TRACKER_REPO = process.env.UBUNTU_CVE_TRACKER_URL || 'https://git.launchpad.net/ubuntu-cve-tracker';

/** Runs git and resolves with its stdout; `onData` takes the stream instead when given. */
function git(args: string[], opts: { cwd?: string; onData?: (chunk: Buffer) => void; timeoutMs: number }): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn('git', args, { cwd: opts.cwd, stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, GIT_TERMINAL_PROMPT: '0' } });
    const out: Buffer[] = [];
    let stderr = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), opts.timeoutMs);
    child.stdout.on('data', (chunk: Buffer) => (opts.onData ? opts.onData(chunk) : out.push(chunk)));
    child.stderr.on('data', (chunk: Buffer) => { stderr = (stderr + chunk.toString()).slice(-2000); });
    child.on('error', (err) => { clearTimeout(timer); reject(new Error(`git could not be run: ${err.message}`, { cause: err })); });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code === 0) resolve(Buffer.concat(out).toString());
      else reject(new Error(`git ${args[0]} exited with ${code}: ${stderr.trim()}`));
    });
  });
}

/**
 * Replaces UbuntuTrackerStatus with the Ubuntu CVE Tracker's current "no fix yet" entries.
 *
 * The tracker is a git repository of about 84,000 files with no export format, so each run
 * makes a shallow, blob-less-as-far-as-the-server-allows clone into a temporary directory
 * (about 220 MB over the wire), reads the CVE files straight out of it with `git archive`,
 * and deletes the clone. Only unfixed entries of the maintained releases are kept, and the
 * table is replaced in one transaction, as the Debian tracker's is: an entry that has since
 * been released simply stops existing.
 *
 * Throws on a failed clone or an empty result, so the table is never replaced with nothing
 * because the repository moved or changed shape.
 */
export async function importUbuntuTrackerStatus(): Promise<{ fetched: number; inserted: number }> {
  const dir = await mkdtemp(path.join(tmpdir(), 'ubuntu-cve-tracker-'));
  try {
    logger.info({ repo: TRACKER_REPO }, 'Cloning the Ubuntu CVE Tracker');
    await git(['clone', '--quiet', '--depth', '1', '--bare', TRACKER_REPO, dir], { timeoutMs: 20 * 60_000 });

    const rows: UbuntuStatusRow[] = [];
    let files = 0;
    const tar = new TarReader((name, content) => {
      const vulnId = isCveFileName(name);
      if (!vulnId) return;
      files++;
      rows.push(...parseUbuntuCveFile(vulnId, content.toString('utf8')));
    });
    await git(['archive', '--format=tar', 'HEAD', 'active', 'retired'], { cwd: dir, onData: (chunk) => tar.push(chunk), timeoutMs: 20 * 60_000 });

    if (files === 0 || rows.length === 0) {
      throw new Error(`Ubuntu CVE Tracker yielded no unfixed entries from ${files} CVE files -- the layout may have changed`);
    }
    logger.info({ files, rows: rows.length }, 'Parsed the Ubuntu CVE Tracker');

    await prisma.$transaction(async (tx) => {
      await tx.ubuntuTrackerStatus.deleteMany({});
      await createManyChunked(rows, (chunk) => tx.ubuntuTrackerStatus.createMany({ data: chunk }));
    }, { timeout: 300_000 });

    return { fetched: rows.length, inserted: rows.length };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}
