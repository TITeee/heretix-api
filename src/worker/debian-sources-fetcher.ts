import axios from 'axios';
import { gunzipSync } from 'zlib';
import { logger } from '../utils/logger.js';
import { prisma } from '../db/client.js';
import { DEBIAN_CODENAMES, parseSourcesFile, type SourceStanza } from './debian-sources-helpers.js';

export { DEBIAN_CODENAMES, parseSourcesFile };
export type { SourceStanza };

const COMPONENTS = ['main', 'contrib', 'non-free', 'non-free-firmware'];

/**
 * Downloads and parses every component's Sources index for one Debian
 * major version. A component missing for this suite (older suites drop
 * "non-free-firmware", archived ones may drop others) is logged and
 * skipped rather than aborting the whole suite.
 */
export async function fetchDebianSuiteMapping(majorVersion: number): Promise<SourceStanza[]> {
  const codename = DEBIAN_CODENAMES[majorVersion];
  if (!codename) {
    logger.warn({ majorVersion }, 'No known Debian codename for this major version, skipping');
    return [];
  }

  const results: SourceStanza[] = [];

  for (const component of COMPONENTS) {
    const url = `https://deb.debian.org/debian/dists/${codename}/${component}/source/Sources.gz`;
    try {
      const response = await axios.get<ArrayBuffer>(url, {
        responseType: 'arraybuffer',
        timeout: 60000,
      });
      const raw = gunzipSync(Buffer.from(response.data)).toString('utf-8');
      results.push(...parseSourcesFile(raw));
    } catch (err) {
      logger.warn({ majorVersion, component, url, err }, 'Failed to fetch Debian Sources component, skipping');
    }
  }

  return results;
}

/**
 * Refreshes DebianSourcePackage for every Debian major version actually
 * present in our OSV data (discovered the same way listOsvEcosystemJobs()
 * discovers OSV ecosystem jobs -- no hardcoded suite list to keep in sync).
 */
export async function importDebianSourceMappings(): Promise<{ updated: number }> {
  const rows = await prisma.oSVVulnerability.groupBy({
    by: ['ecosystem'],
    where: { ecosystem: { startsWith: 'Debian:' } },
  });

  // parseInt("3.0") and parseInt("3.1") both yield 3 -- ancient OSV ecosystem
  // strings like these have no entry in DEBIAN_CODENAMES anyway (irrelevant
  // to any container built this century), but dedupe to avoid processing the
  // same major more than once.
  const majors = [...new Set(
    rows
      .map(r => r.ecosystem)
      .filter((e): e is string => !!e)
      .map(e => parseInt(e.slice('Debian:'.length), 10))
      .filter(n => !isNaN(n)),
  )];

  let updated = 0;

  for (const major of majors) {
    const ecosystem = `Debian:${major}`;
    const stanzas = await fetchDebianSuiteMapping(major);
    logger.info({ ecosystem, sourcePackages: stanzas.length }, 'Fetched Debian Sources mapping');

    for (const { source, binaries } of stanzas) {
      for (const binaryName of binaries) {
        if (binaryName === source) continue; // no resolution needed for the identity case
        await prisma.debianSourcePackage.upsert({
          where: { ecosystem_binaryName: { ecosystem, binaryName } },
          create: { ecosystem, binaryName, sourceName: source },
          update: { sourceName: source },
        });
        updated++;
      }
    }
  }

  return { updated };
}
