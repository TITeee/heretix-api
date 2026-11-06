/**
 * OSV's list of ecosystems (ecosystems.txt), fetched at most once an hour.
 *
 * Needed where a name must be checked or chosen: the dashboard's "add an
 * ecosystem" and the job of an ecosystem that has no data here yet.
 */
import axios from 'axios';
import { OSV_ECOSYSTEMS_URL } from './osv-bucket.js';

const TTL_MS = 60 * 60 * 1000;
let cache: { names: string[]; expiresAt: number } | null = null;

/** The ecosystem names OSV lists, or null when the list cannot be fetched. */
export async function fetchOsvEcosystems(): Promise<string[] | null> {
  if (cache && cache.expiresAt > Date.now()) return cache.names;
  try {
    const res = await axios.get<string>(OSV_ECOSYSTEMS_URL, { responseType: 'text', timeout: 30_000 });
    const names = String(res.data).split('\n').map((l) => l.trim()).filter((l) => l && l !== '[EMPTY]').sort();
    if (names.length === 0) return null;
    cache = { names, expiresAt: Date.now() + TTL_MS };
    return names;
  } catch {
    return cache?.names ?? null;
  }
}

/** For tests. */
export function resetOsvEcosystemsCache(): void {
  cache = null;
}
