/**
 * Catalog accuracy against the vendor's own CVE records
 *
 * When a vendor is its own CNA, the CVE record it published states, per CVE, which
 * versions of the product are affected (and where each branch is fixed). That is
 * the vendor's word, in JSON, with no page to scrape. This takes it as ground
 * truth for a catalog entry: for every CVE the vendor's CNA published for the
 * entry's product, it derives boundary versions (each range's start, the version
 * just below it, the version just below the fix, and the fix itself), searches the
 * running API by the entry's NAME at each, and compares the CVEs that come back
 * with the ones the vendor says are affected at that version.
 *
 * Only CVEs the vendor's CNA covers are judged; any other CVE the search returns
 * (NVD-only, or another CNA's) is unknown, neither a hit nor a false positive.
 *
 * The version comparison here is a plain numeric one on dotted versions, written
 * apart from the search's own normalizeVersion on purpose, so it can disagree.
 *
 * Needs the API running (default http://localhost:5000, API_KEY from .env). Reads
 * only. Always exits 0: it is a measurement, not a gate.
 *
 * Usage:
 *   pnpm validate:catalog-cna f5-big-ip --cna f5
 *   API_BASE_URL=http://localhost:3001 pnpm validate:catalog-cna f5-big-ip --cna f5
 */
import 'dotenv/config';
import axios from 'axios';
import { prisma, closeDb } from '../db/client.js';
import { CATALOG_ENTRIES } from '../config/product-catalog.js';
import {
  aggregateSweep, diffSets, mapWithConcurrency, printSweepReport, queryAllPages, restrictToKnownIds,
  type SweepEntry,
} from './lib/accuracy-sweep.js';

const API_BASE = process.env.API_BASE_URL ?? 'http://localhost:5000';
const PAGE = 500;

interface CnaVersion {
  status?: string;
  version?: string;
  lessThan?: string;
  lessThanOrEqual?: string;
}
interface CnaAffected { vendor?: string; product?: string; versions?: CnaVersion[] }

/**
 * A range, as the vendor states it. `end` null means the range has no upper bound.
 * `excluded` marks a range the vendor says is NOT affected (status "unaffected").
 */
interface Range { cve: string; start: number[]; end: number[] | null; endInclusive: boolean; exact: boolean; text: string; excluded: boolean }

function parts(v: string): number[] | null {
  if (!/^\d+(\.\d+)*$/.test(v)) return null;
  return v.split('.').map(Number);
}

function cmp(a: number[], b: number[]): number {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  return 0;
}

const show = (p: number[]) => p.join('.');

/** The version just below, by decrementing the last component; null when it would go negative. */
function below(p: number[]): number[] | null {
  const out = [...p];
  if (out[out.length - 1] === 0) return null;
  out[out.length - 1]--;
  return out;
}

/** The branch of a version: its first two components ("17.1" for 17.1.2.1). */
const branch = (p: number[]) => `${p[0]}.${p[1] ?? 0}`;

function inRange(v: number[], r: Range): boolean {
  if (r.exact) return cmp(v, r.start) === 0;
  if (cmp(v, r.start) < 0) return false;
  if (r.end === null) return true;
  const c = cmp(v, r.end);
  return r.endInclusive ? c <= 0 : c < 0;
}

function argValue(flag: string): string | undefined {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

async function main(): Promise<void> {
  const entryId = process.argv[2];
  const cnaShort = argValue('--cna');
  const entry = CATALOG_ENTRIES.find(e => e.id === entryId);
  if (!entry || !cnaShort) {
    console.error('Usage: pnpm validate:catalog-cna <entry id> --cna <CNA short name>');
    console.error('Example: pnpm validate:catalog-cna f5-big-ip --cna f5');
    process.exitCode = 1;
    return;
  }
  const vendors = new Set(entry.cna.flatMap(p => p.vendors));
  const products = new Set(entry.cna.flatMap(p => p.products));

  const records = await prisma.cnaVulnerability.findMany({
    where: { cnaShortName: cnaShort }, select: { cveId: true, rawAffected: true },
  });
  const ranges: Range[] = [];
  const known = new Set<string>();
  let unparsed = 0;
  for (const rec of records) {
    const affected = (Array.isArray(rec.rawAffected) ? rec.rawAffected : []) as CnaAffected[];
    for (const a of affected) {
      if (!a.vendor || !a.product || !vendors.has(a.vendor) || !products.has(a.product)) continue;
      known.add(rec.cveId);
      const entries = (a.versions ?? []).filter(v => v.version && parts(v.version));
      const starts = entries.map(v => parts(v.version!)!);
      for (const v of a.versions ?? []) {
        if (v.status !== 'affected' && v.status !== 'unaffected') continue;
        const start = v.version ? parts(v.version) : null;
        if (!start) { unparsed++; continue; }
        const endText = v.lessThan ?? v.lessThanOrEqual;
        // F5 writes "lessThan: *" for "every release of this branch, no fix": it ends where
        // the next branch of the same record begins (16.1.0 * stops at 17.1.0), or never.
        const open = endText === '*';
        let end: number[] | null = null;
        if (endText && !open) {
          end = parts(endText);
          if (!end) { unparsed++; continue; }
        } else if (open) {
          const next = starts.filter(x => branch(x) !== branch(start) && cmp(x, start) > 0).sort(cmp)[0];
          end = next ?? null;
        }
        const exact = !endText;
        ranges.push({
          cve: rec.cveId, start, end, endInclusive: v.lessThanOrEqual !== undefined, exact, excluded: v.status === 'unaffected',
          text: `${v.status === 'unaffected' ? 'NOT affected: ' : ''}${exact ? v.version : `${v.version} to ${open ? '*' : v.lessThan ? `< ${v.lessThan}` : `<= ${v.lessThanOrEqual}`}`}`,
        });
      }
    }
  }
  console.log(`${entry.name}: ${known.size} CVEs from the ${cnaShort} CNA, ${ranges.length} ranges (${unparsed} skipped: a version that is not dotted numbers)`);

  // Boundary versions, each with why it was picked.
  const points = new Map<string, { v: number[]; reasons: string[] }>();
  const add = (v: number[] | null, why: string) => {
    if (!v) return;
    const k = show(v);
    (points.get(k) ?? points.set(k, { v, reasons: [] }).get(k)!).reasons.push(why);
  };
  for (const r of ranges) {
    add(r.start, `${r.cve}: start of ${r.text}`);
    add(below(r.start), `${r.cve}: just below the start of ${r.text}`);
    if (r.end) {
      add(r.end, `${r.cve}: end of ${r.text}`);
      add(below(r.end), `${r.cve}: just below the end of ${r.text}`);
    }
  }
  console.log(`${points.size} boundary versions; searching by the name "${entry.name}" at ${API_BASE}\n`);

  const key = process.env.API_KEY;
  const results = await mapWithConcurrency([...points.values()], 4, async (pt): Promise<SweepEntry> => {
    const version = show(pt.v);
    const found = await queryAllPages(async (offset) => {
      const { data } = await axios.get(`${API_BASE}/api/v1/vulnerabilities/search`, {
        params: { package: entry.name, version, limit: PAGE, offset },
        headers: key ? { 'x-api-key': key } : {},
        timeout: 120_000,
      });
      return data.results as { externalId: string }[];
    }, PAGE);
    const actual = restrictToKnownIds(new Set(found.map(r => r.externalId.toUpperCase())), known);
    // Affected by an affected range that no "unaffected" range of the same CVE takes back.
    const hit = (excluded: boolean) => new Set(ranges.filter(r => r.excluded === excluded && inRange(pt.v, r)).map(r => r.cve));
    const cleared = hit(true);
    const expected = new Set([...hit(false)].filter(c => !cleared.has(c)));
    const d = diffSets(expected, actual);
    return {
      version, reasons: pt.reasons.slice(0, 3), tp: d.tp.length, fp: d.fp.length, fn: d.fn.length,
      fpDetail: d.fp, fnDetail: d.fn,
    };
  });

  printSweepReport(`${entry.name} vs ${cnaShort} CNA`, results, aggregateSweep(results),
    "each range's start, the version just below it, the fix, and the version just below the fix");
}

main()
  .catch((err) => { console.error(err); process.exitCode = 1; })
  .finally(() => closeDb());
