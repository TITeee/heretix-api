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
 * The version comparison here is written apart from the search's own
 * normalizeVersion on purpose, so it can disagree. Two schemes:
 *   dotted  17.1.2.1 (default): plain numeric comparison of the components.
 *   junos   23.4R2-S5: release R and service release S, in the order Juniper
 *           publishes them (23.4R2 < 23.4R2-S1 < 23.4R3). Chosen for the Junos entry.
 *
 * Needs the API running (default http://localhost:5000, API_KEY from .env). Reads
 * only. Always exits 0: it is a measurement, not a gate.
 *
 * Usage:
 *   pnpm validate:catalog-cna f5-big-ip --cna f5
 *   pnpm validate:catalog-cna juniper-junos-os --cna juniper
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

type V = number[];

function cmp(a: V, b: V): number {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  return 0;
}

/**
 * A range, as the vendor states it. `matches` says whether a version is inside it;
 * `points` are the versions worth searching at to test its edges. `excluded` marks a
 * range the vendor says is NOT affected (status "unaffected").
 */
interface Range { cve: string; text: string; excluded: boolean; matches: (v: V) => boolean; points: { v: V; why: string }[] }

/** What differs between a dotted version and a Junos one. */
interface Scheme {
  name: string;
  parse(s: string): V | null;
  format(v: V): string;
  /** The version just below, or null when there is none to name. */
  below(v: V): V | null;
  /** The ranges one entry of a record's version list makes, or null when it cannot be read. */
  makeRange(cve: string, entry: CnaVersion, productStarts: V[]): Range | null;
}

// ─── dotted: 17.1.2.1 ───────────────────────────────────────────────────────

/** The branch of a dotted version: its first two components ("17.1" for 17.1.2.1). */
const branch = (p: V) => `${p[0]}.${p[1] ?? 0}`;

const dotted: Scheme = {
  name: 'dotted',
  parse: (s) => (/^\d+(\.\d+)*$/.test(s) ? s.split('.').map(Number) : null),
  format: (v) => v.join('.'),
  below(p) {
    const out = [...p];
    if (out[out.length - 1] === 0) return null;
    out[out.length - 1]--;
    return out;
  },
  makeRange(cve, e, productStarts) {
    const start = e.version ? this.parse(e.version) : null;
    if (!start) return null;
    const endText = e.lessThan ?? e.lessThanOrEqual;
    // F5 writes "lessThan: *" for "every release of this branch, no fix": it ends where
    // the next branch of the same product begins (16.1.0 * stops at 17.1.0), or never.
    const open = endText === '*';
    let end: V | null = null;
    if (endText && !open) {
      end = this.parse(endText);
      if (!end) return null;
    } else if (open) {
      end = productStarts.filter(x => branch(x) !== branch(start) && cmp(x, start) > 0).sort(cmp)[0] ?? null;
    }
    const exact = !endText;
    const inclusive = e.lessThanOrEqual !== undefined;
    const text = exact ? e.version! : `${e.version} to ${open ? '*' : e.lessThan ? `< ${e.lessThan}` : `<= ${e.lessThanOrEqual}`}`;
    const points: Range['points'] = [
      { v: start, why: `start of ${text}` },
      ...(this.below(start) ? [{ v: this.below(start)!, why: `just below the start of ${text}` }] : []),
      ...(end ? [{ v: end, why: `end of ${text}` }] : []),
      ...(end && this.below(end) ? [{ v: this.below(end)!, why: `just below the end of ${text}` }] : []),
    ];
    return {
      cve, text: `${e.status === 'unaffected' ? 'NOT affected: ' : ''}${text}`, excluded: e.status === 'unaffected', points,
      matches(v) {
        if (exact) return cmp(v, start) === 0;
        if (cmp(v, start) < 0) return false;
        if (end === null) return true;
        const c = cmp(v, end);
        return inclusive ? c <= 0 : c < 0;
      },
    };
  },
};

// ─── junos: 23.4R2-S5 ───────────────────────────────────────────────────────

/**
 * A Junos version as [major, minor, R, S]: "23.4R2-S5" is [23, 4, 2, 5], "23.4R2" is
 * [23, 4, 2, 0], and a bare train "23.4" is [23, 4, 0, 0], before its R1. That orders
 * 23.4 < 23.4R1 < 23.4R1-S1 < 23.4R2 < 23.4R2-S1 < 23.4R3, as Juniper's releases go.
 */
const JUNOS_END_OF_TIME: V = [1e9, 0, 0, 0];

function parseJunos(s: string): V | null {
  const t = s.trim();
  if (t === '0' || /^all versions? prior to$/i.test(t)) return [0, 0, 0, 0];
  const m = t.match(/^(\d+)\.(\d+)(?:R(\d+))?(?:-S(\d+))?$/);
  return m ? [Number(m[1]), Number(m[2]), Number(m[3] ?? 0), Number(m[4] ?? 0)] : null;
}

/** The release line of a version: its train and R, without the service release. */
const junosLine = (v: V): V => [v[0], v[1], v[2]];

const junos: Scheme = {
  name: 'junos',
  parse: parseJunos,
  format: (v) => `${v[0]}.${v[1]}${v[2] > 0 || v[3] > 0 ? `R${v[2]}` : ''}${v[3] > 0 ? `-S${v[3]}` : ''}`,
  below(v) {
    if (v[3] > 0) return [v[0], v[1], v[2], v[3] - 1];
    if (v[2] > 1) return [v[0], v[1], v[2] - 1, 0];
    return null;
  },
  makeRange(cve, e, productStarts) {
    const start = e.version ? parseJunos(e.version) : null;
    if (!start) return null;
    const exact = e.lessThan === undefined && e.lessThanOrEqual === undefined;

    // "lessThan" is a list of fixed releases ("23.4R1-S2, 23.4R2"), one per release line;
    // "21.4*" is the whole train and "*" is no fix at all.
    const fixes: V[] = [];
    if (e.lessThan !== undefined) {
      for (const part of e.lessThan.split(',').map(x => x.trim()).filter(Boolean)) {
        // "*": no fix yet; it ends where the next train of the product begins, or never.
        if (part === '*') {
          const train = (x: V) => `${x[0]}.${x[1]}`;
          fixes.push(productStarts.filter(x => train(x) !== train(start) && cmp(x, start) > 0).sort(cmp)[0] ?? JUNOS_END_OF_TIME);
          continue;
        }
        const train = part.match(/^(\d+)\.(\d+)\*$/);
        if (train) { fixes.push([Number(train[1]), Number(train[2]) + 1, 0, 0]); continue; }
        const f = parseJunos(part);
        if (!f) return null;
        fixes.push(f);
      }
      fixes.sort(cmp);
    }
    const lte = e.lessThanOrEqual !== undefined ? parseJunos(e.lessThanOrEqual) : null;
    if (e.lessThanOrEqual !== undefined && !lte) return null;

    const text = exact ? e.version! : `${e.version} to ${e.lessThan !== undefined ? `< ${e.lessThan}` : `<= ${e.lessThanOrEqual}`}`;
    const real = fixes.filter(f => f[0] < 1e9 && !/\*$/.test(text));
    const points: Range['points'] = [
      { v: start, why: `start of ${text}` },
      ...(this.below(start) ? [{ v: this.below(start)!, why: `just below the start of ${text}` }] : []),
      ...real.flatMap(f => [
        { v: f, why: `fix of ${text}` },
        ...(this.below(f) ? [{ v: this.below(f)!, why: `just below the fix of ${text}` }] : []),
      ]),
    ];
    return {
      cve, text: `${e.status === 'unaffected' ? 'NOT affected: ' : ''}${text}`, excluded: e.status === 'unaffected', points,
      matches(v) {
        if (exact) return cmp(v, start) === 0;
        if (cmp(v, start) < 0) return false;
        if (lte) return cmp(v, lte) <= 0;
        // Affected until the fix of its own release line; below the lowest fix of a later line it is
        // affected too, and above every fix there is nothing left to be affected.
        const f = fixes.find(x => cmp(junosLine(x), junosLine(v)) >= 0);
        return f !== undefined && cmp(v, f) < 0;
      },
    };
  },
};

function argValue(flag: string): string | undefined {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

async function main(): Promise<void> {
  const entryId = process.argv[2];
  const cnaShort = argValue('--cna');
  const entry = CATALOG_ENTRIES.find(e => e.id === entryId);
  if (!entry || !cnaShort) {
    console.error('Usage: pnpm validate:catalog-cna <entry id> --cna <CNA short name> [--scheme dotted|junos]');
    console.error('Example: pnpm validate:catalog-cna f5-big-ip --cna f5');
    process.exitCode = 1;
    return;
  }
  const schemeName = argValue('--scheme') ?? (entry.id === 'juniper-junos-os' ? 'junos' : 'dotted');
  const scheme = schemeName === 'junos' ? junos : dotted;
  const vendors = new Set(entry.cna.flatMap(p => p.vendors));
  const products = new Set(entry.cna.flatMap(p => p.products));

  const records = await prisma.cnaVulnerability.findMany({
    where: { cnaShortName: cnaShort }, select: { cveId: true, rawAffected: true },
  });
  const ranges: Range[] = [];
  const known = new Set<string>();
  let unparsed = 0;
  const unparsedSamples = new Set<string>();
  for (const rec of records) {
    const affected = (Array.isArray(rec.rawAffected) ? rec.rawAffected : []) as CnaAffected[];
    const mine = affected.filter(a => a.vendor && a.product && vendors.has(a.vendor) && products.has(a.product));
    // Every version the record lists for the entry's product, whatever entry it sits in:
    // a branch with no fix ends where the next one of the product begins.
    const productStarts = mine.flatMap(a => (a.versions ?? []).map(v => (v.version ? scheme.parse(v.version) : null)).filter((x): x is V => x !== null));
    for (const a of mine) {
      known.add(rec.cveId);
      for (const v of a.versions ?? []) {
        if (v.status !== 'affected' && v.status !== 'unaffected') continue;
        const range = scheme.makeRange(rec.cveId, v, productStarts);
        if (!range) {
          unparsed++;
          if (unparsedSamples.size < 5) unparsedSamples.add(`${v.version ?? ''} ${v.lessThan ?? v.lessThanOrEqual ?? ''}`.trim());
          continue;
        }
        ranges.push(range);
      }
    }
  }
  console.log(`${entry.name} [${scheme.name}]: ${known.size} CVEs from the ${cnaShort} CNA, ${ranges.length} ranges (${unparsed} skipped: a version the ${scheme.name} scheme cannot read${unparsedSamples.size ? `, e.g. ${[...unparsedSamples].join(' | ')}` : ''})`);

  // Boundary versions, each with why it was picked.
  const points = new Map<string, { v: V; reasons: string[] }>();
  for (const r of ranges) {
    for (const p of r.points) {
      const k = scheme.format(p.v);
      (points.get(k) ?? points.set(k, { v: p.v, reasons: [] }).get(k)!).reasons.push(`${r.cve}: ${p.why}`);
    }
  }
  console.log(`${points.size} boundary versions; searching by the name "${entry.name}" at ${API_BASE}\n`);

  const key = process.env.API_KEY;
  const results = await mapWithConcurrency([...points.values()], 4, async (pt): Promise<SweepEntry> => {
    const version = scheme.format(pt.v);
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
    const hit = (excluded: boolean) => new Set(ranges.filter(r => r.excluded === excluded && r.matches(pt.v)).map(r => r.cve));
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
