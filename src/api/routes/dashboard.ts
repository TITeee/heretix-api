import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { readFile } from 'fs/promises';
import path from 'path';
import { requireAdminKey } from '../auth.js';
import { prisma } from '../../db/client.js';
import { STATIC_JOBS } from '../../jobs/registry.js';
import { getEnabledMap, defaultEnabled } from '../../jobs/config.js';
import { isMaintainedOsvEcosystem } from '../../config/support-policy.js';
import { osvBucketName } from '../../jobs/osv-bucket.js';

function isOsvEcosystemSource(source: string): boolean {
  return source.startsWith('osv-') && source !== 'osv-delta';
}

// CollectionJob has an unused `duration` column that's never populated by any
// job runner — derive it instead from startedAt/completedAt, which every
// runner sets around the full fetch+import run (not just the fetch() call).
function jobDurationMs(job: { startedAt: Date | null; completedAt: Date | null } | undefined): number | null {
  if (!job?.startedAt || !job?.completedAt) return null;
  return job.completedAt.getTime() - job.startedAt.getTime();
}

// The per-ecosystem distinct-vulnerability count is a full scan over
// OSVAffectedPackage (~3.07M rows in production) with no selective WHERE
// clause to seek on -- measured at 5.7s even with a covering index (see the
// index's comment in schema.prisma), because COUNT(DISTINCT ...) still has to
// visit every row. The dashboard polls this endpoint every 60s per open tab,
// and the underlying data only changes once a day (the OSV delta cron), so
// re-running that scan on every poll buys nothing but load. Cached across all
// callers for a few minutes instead.
export const ECOSYSTEM_COUNTS_CACHE_TTL_MS = 5 * 60 * 1000;
let ecosystemCountsCache: { rows: { ecosystem: string; count: bigint }[]; expiresAt: number } | null = null;

async function getEcosystemCounts(): Promise<{ ecosystem: string; count: bigint }[]> {
  if (ecosystemCountsCache && ecosystemCountsCache.expiresAt > Date.now()) {
    return ecosystemCountsCache.rows;
  }
  const rows = await prisma.$queryRaw<{ ecosystem: string; count: bigint }[]>`
    SELECT ecosystem, COUNT(DISTINCT "vulnerabilityId") AS count
    FROM "OSVAffectedPackage"
    WHERE ecosystem IS NOT NULL
    GROUP BY ecosystem
    ORDER BY ecosystem ASC
  `;
  ecosystemCountsCache = { rows, expiresAt: Date.now() + ECOSYSTEM_COUNTS_CACHE_TTL_MS };
  return rows;
}

// Maps CollectionJob.source values to the AdvisoryVulnerability.source value
// used by the corresponding fetcher (these naming conventions are inconsistent
// across vendors, e.g. 'advisory-pan' -> 'paloalto', 'advisory-cisco' -> 'cisco').
const ADVISORY_SOURCE_MAP: Record<string, string> = {
  'advisory-fortinet':   'fortinet',
  'advisory-pan':        'paloalto',
  'advisory-cisco':      'cisco',
  'advisory-broadcom':   'advisory-broadcom',
  'advisory-sophos':     'advisory-sophos',
  'advisory-sonicwall':  'advisory-sonicwall',
  'advisory-oracle-cpu': 'advisory-oracle-cpu',
  'advisory-redhat-vex': 'red-hat-vex',
  'advisory-splunk':     'advisory-splunk',
  'advisory-apache':     'advisory-apache',
  'advisory-zabbix':     'advisory-zabbix',
  'advisory-tomcat':     'advisory-tomcat',
  'advisory-nginx':      'advisory-nginx',
  'advisory-checkpoint': 'advisory-checkpoint',
  'advisory-ivanti':     'advisory-ivanti',
  'advisory-citrix':     'advisory-citrix',
  'advisory-microsoft':  'advisory-microsoft',
};

export default async function dashboardRoute(fastify: FastifyInstance) {
  // Enforced per-route rather than by the scope hook in server.ts: the HTML
  // shell below stays public, but the data it renders (job history, failure
  // messages, per-ecosystem counts) does not.
  fastify.get('/api/v1/import-status', { onRequest: requireAdminKey }, async () => {
    const allJobs = await prisma.collectionJob.findMany({
      orderBy: { createdAt: 'desc' },
    });

    const latestBySource = new Map<string, typeof allJobs[0]>();
    for (const job of allJobs) {
      if (!latestBySource.has(job.source)) latestBySource.set(job.source, job);
    }

    // Per-ecosystem distinct vulnerability counts (OSVAffectedPackage is source of truth;
    // OSVVulnerability.ecosystem only stores affected[0] and is not updated on re-import)
    const ecosystemCounts = await getEcosystemCounts();

    const enabledMap = await getEnabledMap();
    const isSourceEnabled = (source: string): boolean => enabledMap.get(source) ?? defaultEnabled(source);

    const osvEcosystems = ecosystemCounts.map((r) => {
      const eco = r.ecosystem;
      // The releases of a distro share one job (osv-Debian runs for Debian:12 and Debian:13 alike).
      const source = `osv-${osvBucketName(eco)}`;
      const job = latestBySource.get(source);
      return {
        ecosystem: eco,
        source,
        enabled: isSourceEnabled(source),
        maintained: isMaintainedOsvEcosystem(eco),
        recordCount: Number(r.count),
        status: job?.status ?? null,
        completedAt: job?.completedAt ?? null,
        durationMs: jobDurationMs(job),
        totalInserted: job?.totalInserted ?? null,
        totalUpdated: job?.totalUpdated ?? null,
        errorMessage: job?.errorMessage ?? null,
      };
    });

    const [nvdCount, osvCount, kevCount, advisoryCount, epssCount, advisorySourceCounts, rhel9Count, rhel8Count, debianTrackerCount, ubuntuTrackerCount] = await Promise.all([
      prisma.nVDVulnerability.count(),
      prisma.oSVVulnerability.count(),
      prisma.vulnerability.count({ where: { isKev: true } }),
      prisma.advisoryVulnerability.count(),
      prisma.vulnerability.count({ where: { epssScore: { not: null } } }),
      prisma.advisoryVulnerability.groupBy({ by: ['source'], _count: { _all: true } }),
      // The RHEL 8 and RHEL 9 jobs both write source "red-hat" -- a per-source
      // count showed the combined total on both rows. Each job's own records are
      // the advisories with an affected product for its major version.
      prisma.advisoryVulnerability.count({ where: { source: 'red-hat', affectedProducts: { some: { vendor: 'red-hat-9' } } } }),
      prisma.advisoryVulnerability.count({ where: { source: 'red-hat', affectedProducts: { some: { vendor: 'red-hat-8' } } } }),
      prisma.debianTrackerStatus.count(),
      prisma.ubuntuTrackerStatus.count(),
    ]);
    const advisoryCountBySource = new Map(advisorySourceCounts.map((r) => [r.source, r._count._all]));

    function recordCountForSource(source: string): number | null {
      if (source === 'nvd') return nvdCount;
      if (source === 'kev') return kevCount;
      if (source === 'epss') return epssCount;
      if (source === 'debian-tracker') return debianTrackerCount;
      if (source === 'ubuntu-tracker') return ubuntuTrackerCount;
      if (source === 'advisory-redhat-rhel9') return rhel9Count;
      if (source === 'advisory-redhat-rhel8') return rhel8Count;
      if (source.startsWith('advisory-oracle-linux')) return advisoryCountBySource.get('oracle-linux') ?? 0;
      const mapped = ADVISORY_SOURCE_MAP[source];
      if (mapped) return advisoryCountBySource.get(mapped) ?? 0;
      return null;
    }

    // Main sources: driven by the registry so every job has a row (even if it
    // has never run). OSV per-ecosystem entries are shown separately.
    // Split into core sources (NVD/KEV/EPSS) and vendor advisories so the
    // dashboard can render them as two distinct tables.
    const allSources = STATIC_JOBS
      .filter((def) => !isOsvEcosystemSource(def.source))
      .map((def) => {
        const j = latestBySource.get(def.source);
        return {
          source: def.source,
          label: def.label,
          enabled: isSourceEnabled(def.source),
          recordCount: recordCountForSource(def.source),
          status: j?.status ?? null,
          startedAt: j?.startedAt ?? null,
          completedAt: j?.completedAt ?? null,
          durationMs: jobDurationMs(j),
          totalInserted: j?.totalInserted ?? null,
          totalUpdated: j?.totalUpdated ?? null,
          totalFailed: j?.totalFailed ?? null,
          fetchFailed: (j?.metadata as { fetchFailed?: number } | null)?.fetchFailed ?? null,
          errorMessage: j?.errorMessage ?? null,
        };
      });

    const coreSources = allSources.filter((s) => !s.source.startsWith('advisory-'));
    const advisorySources = allSources.filter((s) => s.source.startsWith('advisory-'));

    return {
      coreSources,
      advisorySources,
      osvEcosystems,
      recordCounts: { nvd: nvdCount, osv: osvCount, kev: kevCount, advisories: advisoryCount },
    };
  });

  // The dashboard's own files. Served from here rather than a CDN or inline, so the
  // page's CSP below can allow its own origin and nothing else.
  const staticFile = (name: string, type: string) => async (_req: FastifyRequest, reply: FastifyReply) => {
    const body = await readFile(path.join(process.cwd(), 'public', name));
    return reply.type(type).send(body);
  };
  fastify.get('/icon.png', staticFile('icon.png', 'image/png'));
  fastify.get('/dashboard.css', staticFile('dashboard.css', 'text/css; charset=utf-8'));
  fastify.get('/dashboard.js', staticFile('dashboard.js', 'text/javascript; charset=utf-8'));

  fastify.get('/dashboard', async (_req, reply) => {
    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Heretix - Import Dashboard</title>
  <link rel="icon" type="image/png" href="/icon.png" />
  <link rel="stylesheet" href="/dashboard.css" />
</head>
<body>
  <nav class="nav">
    <div class="nav-inner">
      <img src="/icon.png" alt="Heretix" />
      <span class="brand">Heretix</span>
    </div>
  </nav>

  <div id="toast" class="toast hidden"></div>

  <!-- Shown first: the dashboard opens once the server accepts the key. -->
  <main id="sign-in" class="sign-in hidden">
    <form id="sign-in-form" class="sign-in-card" novalidate>
      <h1>Import Dashboard</h1>
      <p class="subtitle">Enter the admin key (ADMIN_API_KEY) to view import status and run jobs.</p>
      <label for="admin-key" class="field-label">Admin key</label>
      <input id="admin-key" class="key-input key-input-wide" type="password" autocomplete="off" required />
      <p id="sign-in-error" class="field-error hidden" role="alert"></p>
      <button id="sign-in-submit" type="submit" class="btn-primary btn-wide">Sign in</button>
      <p class="hint">The key is kept for this tab only, and forgotten when it closes.</p>
    </form>
  </main>

  <div id="dashboard" class="page hidden">
    <div class="header">
      <div>
        <h1>Import Dashboard</h1>
        <p class="subtitle">Data source status and import history</p>
      </div>
      <div class="controls">
        <span id="last-updated" class="muted small"></span>
        <button id="refresh" class="btn-primary">Refresh</button>
        <button id="sign-out" class="btn-secondary">Sign out</button>
      </div>
    </div>

    <div id="summary-cards" class="cards">
      <div class="card card-loading"></div>
      <div class="card card-loading"></div>
      <div class="card card-loading"></div>
      <div class="card card-loading"></div>
    </div>

${statusPanel('Core Sources', 'NVD, CISA KEV, and FIRST.org EPSS', 'Source', 'core-tbody')}

${statusPanel('Vendor Advisories', 'Per-vendor advisory feed import status', 'Vendor', 'advisory-tbody')}

    <div class="panel">
      <div class="panel-head">
        <h2>OSV Ecosystems</h2>
        <p>Per-ecosystem import status and record counts</p>
      </div>
      <div class="table-wrap">
        <table>
          ${tableHead('Ecosystem')}
          <tbody id="osv-tbody">
            <tr><td colspan="9" class="message">Loading...</td></tr>
          </tbody>
        </table>
      </div>
      <!-- Releases outside src/config/support-policy.ts: data is kept but not maintained -->
      <details id="osv-legacy" class="legacy hidden">
        <summary>Outside support policy (<span id="osv-legacy-count">0</span>): data kept, best effort</summary>
        <div class="table-wrap">
          <table>
            ${tableHead('Ecosystem')}
            <tbody id="osv-legacy-tbody"></tbody>
          </table>
        </div>
      </details>
    </div>
  </div>

  <script src="/dashboard.js"></script>
</body>
</html>`;
    return reply
      .type('text/html; charset=utf-8')
      // Scripts, styles and images from this API only; no inline script or handler runs,
      // so markup injected through a data value cannot read the admin key.
      .header('content-security-policy', [
        "default-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self'",
        "connect-src 'self'",
        "base-uri 'none'",
        "form-action 'none'",
        "frame-ancestors 'none'",
      ].join('; '))
      .send(html);
  });
}

function tableHead(nameColumn: string): string {
  return `<thead>
            <tr>
              <th>${nameColumn}</th>
              <th>Status</th>
              <th>Last Completed</th>
              <th class="num">Duration</th>
              <th class="num">Records</th>
              <th class="num">Inserted</th>
              <th class="num">Updated</th>
              <th>Error</th>
              <th class="num">Actions</th>
            </tr>
          </thead>`;
}

function statusPanel(title: string, description: string, nameColumn: string, tbodyId: string): string {
  return `    <div class="panel">
      <div class="panel-head">
        <h2>${title}</h2>
        <p>${description}</p>
      </div>
      <div class="table-wrap">
        <table>
          ${tableHead(nameColumn)}
          <tbody id="${tbodyId}">
            <tr><td colspan="9" class="message">Loading...</td></tr>
          </tbody>
        </table>
      </div>
    </div>`;
}
