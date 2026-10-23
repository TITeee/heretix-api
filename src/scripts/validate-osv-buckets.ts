/**
 * OSV bucket freshness check
 *
 * Every OSV ecosystem job downloads one file from the OSV bucket, picked from the ecosystem
 * names in the DB by osvBucketName() (src/jobs/osv-bucket.ts). OSV has changed what is
 * behind those names before: it stopped writing the per-release Debian, Alpine and Ubuntu
 * buckets in October 2024 and moved them into one bucket per distro, but the old files kept
 * answering 200, so the daily jobs fetched the same records, imported nothing and reported
 * success for months. The jobs now fail on a missing or frozen bucket; this script is the
 * same check made ahead of time, for every bucket the DB would fetch, plus a comparison
 * with OSV's own list of ecosystems (ecosystems.txt).
 *
 * It reports, per bucket: missing (404); frozen (newest record too old for the ecosystem,
 * see staleBucketProblem()); and "superseded" (the DB name is a release of a distro that OSV
 * lists under its bare name, so it belongs in SHARED_BUCKET_ECOSYSTEMS).
 *
 * Exits 1 when any bucket has a problem. Run it after a deploy and now and then:
 *   pnpm validate:osv-buckets
 */
import 'dotenv/config';
import axios from 'axios';
import { prisma } from '../db/client.js';
import { osvBucketName, staleBucketProblem } from '../jobs/osv-bucket.js';

const BASE = 'https://storage.googleapis.com/osv-vulnerabilities';

interface BucketRow {
  bucket: string;
  newest: Date | null;
  problems: string[];
}

/** The newest `modified` of a bucket: the first line of its modified_id.csv ("<time>,<id>", newest first). */
async function newestModified(bucket: string): Promise<{ newest: Date | null; missing: boolean }> {
  const url = `${BASE}/${encodeURI(bucket)}/modified_id.csv`;
  const res = await axios.get<string>(url, {
    responseType: 'text',
    headers: { Range: 'bytes=0-255' },
    timeout: 60000,
    validateStatus: (s) => s === 200 || s === 206 || s === 404,
  });
  if (res.status === 404) {
    // Older buckets may have no list; fall back to when the zip itself was written.
    const head = await axios.head(`${BASE}/${encodeURI(bucket)}/all.zip`, { timeout: 60000, validateStatus: (s) => s === 200 || s === 404 });
    if (head.status === 404) return { newest: null, missing: true };
    const lastModified = head.headers['last-modified'];
    return { newest: lastModified ? new Date(lastModified) : null, missing: false };
  }
  const first = String(res.data).split('\n')[0]?.split(',')[0];
  const newest = first ? new Date(first) : null;
  return { newest: newest && !Number.isNaN(newest.getTime()) ? newest : null, missing: false };
}

async function main() {
  const rows = await prisma.oSVVulnerability.groupBy({ by: ['ecosystem'], where: { ecosystem: { not: null } } });
  const buckets = [...new Set(rows.map((r) => r.ecosystem).filter((e): e is string => !!e).map(osvBucketName))].sort();

  const official = new Set(
    (await axios.get<string>(`${BASE}/ecosystems.txt`, { responseType: 'text', timeout: 60000 })).data
      .split('\n').map((l) => l.trim()).filter(Boolean),
  );

  console.log(`Checking ${buckets.length} OSV bucket(s) the jobs would fetch...\n`);
  const results: BucketRow[] = [];
  for (const bucket of buckets) {
    const problems: string[] = [];
    const base = bucket.split(':')[0];
    if (bucket.includes(':') && official.has(base)) {
      problems.push(`superseded: OSV lists "${base}" as one ecosystem; add it to SHARED_BUCKET_ECOSYSTEMS`);
    }
    let newest: Date | null = null;
    try {
      const found = await newestModified(bucket);
      newest = found.newest;
      if (found.missing) problems.push('missing: no such bucket (404)');
      else {
        const stale = staleBucketProblem(bucket, newest);
        if (stale) problems.push(`frozen: ${stale}`);
      }
    } catch (err) {
      problems.push(`could not be checked: ${err instanceof Error ? err.message : String(err)}`);
    }
    results.push({ bucket, newest, problems });
  }

  console.log('Bucket'.padEnd(40) + 'Newest record'.padEnd(22) + 'Status');
  for (const r of results) {
    console.log(
      r.bucket.padEnd(40) +
      (r.newest ? r.newest.toISOString().slice(0, 16).replace('T', ' ') : 'n/a').padEnd(22) +
      (r.problems.length === 0 ? 'ok' : 'PROBLEM'),
    );
    for (const p of r.problems) console.log(`    - ${p}`);
  }

  const broken = results.filter((r) => r.problems.length > 0);
  console.log(`\n${broken.length} of ${results.length} buckets have a problem.`);
  await prisma.$disconnect();
  if (broken.length > 0) process.exit(1);
}

main().catch(async (err) => {
  console.error(err);
  await prisma.$disconnect();
  process.exit(1);
});
