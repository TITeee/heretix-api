/**
 * Pure Debian Sources-index parsing logic extracted from
 * debian-sources-fetcher.ts for unit testability without pulling in the
 * Prisma client (debian-sources-fetcher.ts imports it at module scope for
 * importDebianSourceMappings(), which requires DATABASE_URL to be set even
 * just to load the module).
 */

// Debian major version -> codename, used only to build the archive URL.
// Extend this as new releases ship.
export const DEBIAN_CODENAMES: Record<number, string> = {
  9: 'stretch',
  10: 'buster',
  11: 'bullseye',
  12: 'bookworm',
  13: 'trixie',
  14: 'forky',
};

export interface SourceStanza {
  source: string;
  binaries: string[];
}

/**
 * Parses a Debian `Sources` index (deb822 format: blank-line-separated
 * stanzas, each a set of "Field: value" lines where a continuation line
 * starting with whitespace folds onto the previous field's value -- the
 * `Binary:` field commonly wraps this way for source packages that build
 * many binaries).
 *
 * Only `Package:` (the source name) and `Binary:` (comma-separated binary
 * names it builds) are extracted; everything else in the stanza is ignored.
 * A stanza with no `Binary:` field at all defaults to a single binary
 * matching the source name -- that's the normal 1:1 case and needs no
 * resolution, matching importDebianSourceMappings()'s skip-when-equal rule.
 */
export function parseSourcesFile(raw: string): SourceStanza[] {
  const stanzas = raw.split(/\r?\n\r?\n+/);
  const results: SourceStanza[] = [];

  for (const stanza of stanzas) {
    const lines = stanza.split(/\r?\n/);
    const fields: Record<string, string> = {};
    let currentField: string | null = null;

    for (const line of lines) {
      if (!line) continue;
      const continuation = /^[ \t]/.test(line);
      if (continuation && currentField) {
        fields[currentField] += line.trim();
        continue;
      }
      const match = line.match(/^([\w-]+):\s?(.*)$/);
      if (!match) continue;
      currentField = match[1];
      fields[currentField] = match[2];
    }

    const source = fields['Package'];
    if (!source) continue;

    const binaries = fields['Binary']
      ? fields['Binary'].split(',').map(b => b.trim()).filter(Boolean)
      : [source];

    results.push({ source, binaries });
  }

  return results;
}
