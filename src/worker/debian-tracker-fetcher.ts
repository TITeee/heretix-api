import axios from 'axios';
import { logger } from '../utils/logger.js';
import { prisma } from '../db/client.js';
import { createManyChunked } from '../db/bulk-insert.js';
import { unresolvedTrackerRows } from './debian-tracker-helpers.js';

const TRACKER_URL = 'https://security-tracker.debian.org/tracker/data/json';

/**
 * Replaces DebianTrackerStatus with the tracker's current unresolved entries.
 *
 * The export is one ~80MB JSON document with no incremental form, and only
 * unresolved entries are kept (~26k rows), so a full replace inside one
 * transaction is both the simplest and the cheapest way to stay in sync: an
 * entry that has since been resolved simply stops existing.
 *
 * Throws on a download/parse failure or an empty result (as
 * runAdvisoryFetcher() does for zero advisories) so the table is never
 * replaced with nothing because the export failed or changed shape.
 */
export async function importDebianTrackerStatus(): Promise<{ fetched: number; inserted: number }> {
  const { data } = await axios.get<unknown>(TRACKER_URL, {
    timeout: 300000,
    headers: { 'User-Agent': 'heretix-api/1.0' },
    maxContentLength: Infinity,
  });
  const rows = unresolvedTrackerRows(data);
  if (rows.length === 0) {
    throw new Error('Debian security tracker export yielded no unresolved entries -- format may have changed');
  }
  logger.info({ rows: rows.length }, 'Parsed Debian security tracker export');

  await prisma.$transaction(async (tx) => {
    await tx.debianTrackerStatus.deleteMany({});
    await createManyChunked(rows, chunk => tx.debianTrackerStatus.createMany({ data: chunk }));
  }, { timeout: 120000 });

  return { fetched: rows.length, inserted: rows.length };
}
