import { FastifyInstance } from 'fastify';
import { readFile } from 'fs/promises';
import path from 'path';
import { prisma } from '../../db/client.js';

const SOURCE_LABELS: Record<string, string> = {
  'nvd-delta': 'NVD (Delta)',
  'nvd': 'NVD (Full)',
  'kev': 'CISA KEV',
  'epss': 'EPSS',
  'advisory-fortinet': 'Fortinet',
  'advisory-pan': 'Palo Alto',
  'advisory-cisco': 'Cisco',
  'advisory-oracle-linux': 'Oracle Linux',
  'advisory-sophos':       'Sophos',
  'advisory-sonicwall':    'SonicWall',
  'advisory-oracle-cpu':   'Oracle CPU',
};

function sourceLabel(source: string): string {
  if (source in SOURCE_LABELS) return SOURCE_LABELS[source];
  if (source.startsWith('osv-')) return `OSV / ${source.slice(4)}`;
  if (source.startsWith('advisory-oracle-linux-')) return `Oracle Linux (${source.slice(22)})`;
  return source;
}

function isOsvEcosystemSource(source: string): boolean {
  return source.startsWith('osv-') && source !== 'osv-delta';
}

export default async function dashboardRoute(fastify: FastifyInstance) {
  fastify.get('/api/v1/import-status', async () => {
    const allJobs = await prisma.collectionJob.findMany({
      orderBy: { createdAt: 'desc' },
    });

    const latestBySource = new Map<string, typeof allJobs[0]>();
    for (const job of allJobs) {
      if (!latestBySource.has(job.source)) latestBySource.set(job.source, job);
    }

    // Per-ecosystem distinct vulnerability counts (OSVAffectedPackage is source of truth;
    // OSVVulnerability.ecosystem only stores affected[0] and is not updated on re-import)
    const ecosystemCounts = await prisma.$queryRaw<{ ecosystem: string; count: bigint }[]>`
      SELECT ecosystem, COUNT(DISTINCT "vulnerabilityId") AS count
      FROM "OSVAffectedPackage"
      WHERE ecosystem IS NOT NULL
      GROUP BY ecosystem
      ORDER BY ecosystem ASC
    `;

    const osvEcosystems = ecosystemCounts.map((r) => {
      const eco = r.ecosystem;
      const job = latestBySource.get(`osv-${eco}`);
      return {
        ecosystem: eco,
        recordCount: Number(r.count),
        status: job?.status ?? null,
        completedAt: job?.completedAt ?? null,
        totalInserted: job?.totalInserted ?? null,
        totalUpdated: job?.totalUpdated ?? null,
        errorMessage: job?.errorMessage ?? null,
      };
    });

    // Append Malware as a special OSV entry (GitHub source, no dedicated ecosystem column)
    const malJob = latestBySource.get('osv-mal');
    const malCount = await prisma.vulnerability.count({ where: { osvId: { startsWith: 'MAL-' } } });
    osvEcosystems.push({
      ecosystem: 'Malware',
      recordCount: malCount,
      status: malJob?.status ?? null,
      completedAt: malJob?.completedAt ?? null,
      totalInserted: malJob?.totalInserted ?? null,
      totalUpdated: malJob?.totalUpdated ?? null,
      errorMessage: malJob?.errorMessage ?? null,
    });

    // Main sources: exclude per-ecosystem OSV entries (shown separately)
    const sources = Array.from(latestBySource.values())
      .filter((j) => !isOsvEcosystemSource(j.source))
      .map((j) => ({
        source: j.source,
        label: sourceLabel(j.source),
        status: j.status,
        startedAt: j.startedAt,
        completedAt: j.completedAt,
        totalInserted: j.totalInserted,
        totalUpdated: j.totalUpdated,
        totalFailed: j.totalFailed,
        errorMessage: j.errorMessage,
      }));

    const [nvdCount, osvCount, kevCount, advisoryCount] = await Promise.all([
      prisma.nVDVulnerability.count(),
      prisma.oSVVulnerability.count(),
      prisma.vulnerability.count({ where: { isKev: true } }),
      prisma.advisoryVulnerability.count(),
    ]);

    return {
      sources,
      osvEcosystems,
      recordCounts: { nvd: nvdCount, osv: osvCount, kev: kevCount, advisories: advisoryCount },
    };
  });

  fastify.get('/icon.png', async (_req, reply) => {
    const icon = await readFile(path.join(process.cwd(), 'public', 'icon.png'));
    reply.type('image/png').send(icon);
  });

  fastify.get('/dashboard', async (_req, reply) => {
    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Heretix - Import Dashboard</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    :root {
      --background: oklch(0.145 0 0);
      --foreground: oklch(0.985 0 0);
      --card: oklch(0.205 0 0);
      --card-foreground: oklch(0.985 0 0);
      --border: oklch(1 0 0 / 10%);
      --muted: oklch(0.269 0 0);
      --muted-foreground: oklch(0.708 0 0);
      --accent: oklch(0.371 0 0);
      --primary: oklch(0.87 0 0);
      --primary-foreground: oklch(0.205 0 0);
      --secondary: oklch(0.269 0 0);
      --destructive: oklch(0.704 0.191 22.216);
      --radius: 0.625rem;
    }
  </style>
</head>
<body class="bg-[var(--background)] text-[var(--foreground)] min-h-screen font-sans">
  <!-- Top navbar -->
  <nav class="border-b border-[var(--border)] bg-[var(--background)]">
    <div class="max-w-6xl mx-auto px-6 py-3 flex items-center gap-2">
      <img src="/icon.png" alt="Heretix" class="w-6 h-6 rounded-sm" />
      <span class="text-[var(--foreground)] font-bold text-lg tracking-tight">Heretix</span>
    </div>
  </nav>

  <div class="max-w-6xl mx-auto px-6 py-8">
    <!-- Header -->
    <div class="flex items-center justify-between mb-8">
      <div>
        <h1 class="text-2xl font-bold text-[var(--foreground)]">Import Dashboard</h1>
        <p class="text-[var(--muted-foreground)] text-sm mt-1">Data source status and import history</p>
      </div>
      <div class="flex items-center gap-4">
        <span id="last-updated" class="text-[var(--muted-foreground)] text-sm"></span>
        <button
          onclick="loadData()"
          class="px-4 py-2 bg-[var(--primary)] text-[var(--primary-foreground)] hover:opacity-90 text-sm font-medium rounded-md transition-opacity"
        >Refresh</button>
      </div>
    </div>

    <!-- Summary Cards -->
    <div id="summary-cards" class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
      <div class="bg-[var(--card)] border border-[var(--border)] rounded-xl p-5 animate-pulse h-24"></div>
      <div class="bg-[var(--card)] border border-[var(--border)] rounded-xl p-5 animate-pulse h-24"></div>
      <div class="bg-[var(--card)] border border-[var(--border)] rounded-xl p-5 animate-pulse h-24"></div>
      <div class="bg-[var(--card)] border border-[var(--border)] rounded-xl p-5 animate-pulse h-24"></div>
    </div>

    <!-- Import Status Table -->
    <div class="bg-[var(--card)] border border-[var(--border)] rounded-xl mb-8 overflow-hidden">
      <div class="px-6 py-4 border-b border-[var(--border)]">
        <h2 class="text-lg font-semibold text-[var(--card-foreground)]">Import Status</h2>
      </div>
      <div class="overflow-x-auto">
        <table class="w-full text-sm">
          <thead>
            <tr class="text-[var(--muted-foreground)] text-xs uppercase tracking-wide text-left border-b border-[var(--border)]">
              <th class="px-6 py-3 font-medium">Source</th>
              <th class="px-6 py-3 font-medium">Status</th>
              <th class="px-6 py-3 font-medium">Last Completed</th>
              <th class="px-6 py-3 font-medium text-right">Inserted</th>
              <th class="px-6 py-3 font-medium text-right">Updated</th>
              <th class="px-6 py-3 font-medium">Error</th>
            </tr>
          </thead>
          <tbody id="sources-tbody">
            <tr><td colspan="6" class="px-6 py-8 text-center text-[var(--muted-foreground)]">Loading...</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- OSV Ecosystems -->
    <div class="bg-[var(--card)] border border-[var(--border)] rounded-xl overflow-hidden">
      <div class="px-6 py-4 border-b border-[var(--border)]">
        <h2 class="text-lg font-semibold text-[var(--card-foreground)]">OSV Ecosystems</h2>
        <p class="text-[var(--muted-foreground)] text-xs mt-0.5">Per-ecosystem import status and record counts</p>
      </div>
      <div class="overflow-x-auto">
        <table class="w-full text-sm">
          <thead>
            <tr class="text-[var(--muted-foreground)] text-xs uppercase tracking-wide text-left border-b border-[var(--border)]">
              <th class="px-6 py-3 font-medium">Ecosystem</th>
              <th class="px-6 py-3 font-medium">Status</th>
              <th class="px-6 py-3 font-medium">Last Completed</th>
              <th class="px-6 py-3 font-medium text-right">Records</th>
              <th class="px-6 py-3 font-medium text-right">Inserted</th>
              <th class="px-6 py-3 font-medium text-right">Updated</th>
              <th class="px-6 py-3 font-medium">Error</th>
            </tr>
          </thead>
          <tbody id="osv-tbody">
            <tr><td colspan="7" class="px-6 py-8 text-center text-[var(--muted-foreground)]">Loading...</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <script>
    const REFRESH_INTERVAL_MS = 60000;

    function fmt(n) {
      if (n == null) return '-';
      return n.toLocaleString();
    }

    function relativeTime(iso) {
      if (!iso) return '-';
      const diff = Date.now() - new Date(iso).getTime();
      const minutes = Math.floor(diff / 60000);
      if (minutes < 1) return 'just now';
      if (minutes < 60) return minutes + 'm ago';
      const hours = Math.floor(minutes / 60);
      if (hours < 24) return hours + 'h ago';
      const days = Math.floor(hours / 24);
      return days + 'd ago';
    }

    function statusBadge(status) {
      if (!status) return '<span class="inline-flex items-center gap-1.5 rounded-md border border-[var(--border)] bg-[var(--secondary)] px-2 py-0.5 text-xs font-medium text-[var(--muted-foreground)]">no jobs</span>';
      const map = {
        completed: 'border-emerald-500/20 bg-emerald-500/10 text-emerald-400',
        failed:    'border-[var(--destructive)]/30 bg-[var(--destructive)]/10 text-[var(--destructive)]',
        running:   'border-amber-500/20 bg-amber-500/10 text-amber-400',
        pending:   'border-[var(--border)] bg-[var(--secondary)] text-[var(--muted-foreground)]',
      };
      const cls = map[status] || 'border-[var(--border)] bg-[var(--secondary)] text-[var(--muted-foreground)]';
      const dot = status === 'running'
        ? '<span class="inline-block w-2 h-2 rounded-full bg-amber-400 animate-pulse mr-1.5"></span>'
        : '';
      return '<span class="inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-medium ' + cls + '">' + dot + status + '</span>';
    }

    function errorCell(msg) {
      if (!msg) return '<span class="text-[var(--muted-foreground)]">-</span>';
      return '<span class="text-[var(--destructive)] font-mono text-xs block truncate max-w-xs" title="' +
        msg.replace(/"/g, '&quot;') + '">' +
        msg.substring(0, 60) + (msg.length > 60 ? '…' : '') +
      '</span>';
    }

    function renderCards(counts) {
      const cards = [
        { label: 'NVD',        value: fmt(counts.nvd) },
        { label: 'OSV',        value: fmt(counts.osv) },
        { label: 'KEV',        value: fmt(counts.kev) },
        { label: 'Advisories', value: fmt(counts.advisories) },
      ];
      document.getElementById('summary-cards').innerHTML = cards.map(c =>
        '<div class="bg-[var(--card)] border border-[var(--border)] rounded-xl p-5">' +
          '<p class="text-[var(--muted-foreground)] text-xs font-medium uppercase tracking-wider mb-2">' + c.label + '</p>' +
          '<p class="text-3xl font-bold text-[var(--card-foreground)]">' + c.value + '</p>' +
        '</div>'
      ).join('');
    }

    function renderSources(sources) {
      if (!sources.length) {
        document.getElementById('sources-tbody').innerHTML =
          '<tr><td colspan="6" class="px-6 py-8 text-center text-[var(--muted-foreground)]">No import jobs found.</td></tr>';
        return;
      }
      const sorted = [...sources].sort((a, b) => a.label.localeCompare(b.label));
      document.getElementById('sources-tbody').innerHTML = sorted.map(s =>
        '<tr class="border-t border-[var(--border)] hover:bg-[var(--accent)]/40 transition-colors">' +
          '<td class="px-6 py-4 font-medium text-[var(--foreground)]">' + s.label + '</td>' +
          '<td class="px-6 py-4">' + statusBadge(s.status) + '</td>' +
          '<td class="px-6 py-4 text-[var(--muted-foreground)]">' + relativeTime(s.completedAt) + '</td>' +
          '<td class="px-6 py-4 text-right text-[var(--foreground)] font-mono">' + fmt(s.totalInserted) + '</td>' +
          '<td class="px-6 py-4 text-right text-[var(--foreground)] font-mono">' + fmt(s.totalUpdated) + '</td>' +
          '<td class="px-6 py-4">' + errorCell(s.errorMessage) + '</td>' +
        '</tr>'
      ).join('');
    }

    function renderOsvEcosystems(ecosystems) {
      if (!ecosystems.length) {
        document.getElementById('osv-tbody').innerHTML =
          '<tr><td colspan="7" class="px-6 py-8 text-center text-[var(--muted-foreground)]">No OSV ecosystems imported yet.</td></tr>';
        return;
      }
      document.getElementById('osv-tbody').innerHTML = ecosystems.map(e =>
        '<tr class="border-t border-[var(--border)] hover:bg-[var(--accent)]/40 transition-colors">' +
          '<td class="px-6 py-4 font-medium text-[var(--foreground)]">' + e.ecosystem + '</td>' +
          '<td class="px-6 py-4">' + statusBadge(e.status) + '</td>' +
          '<td class="px-6 py-4 text-[var(--muted-foreground)]">' + relativeTime(e.completedAt) + '</td>' +
          '<td class="px-6 py-4 text-right text-[var(--foreground)] font-mono">' + fmt(e.recordCount) + '</td>' +
          '<td class="px-6 py-4 text-right text-[var(--foreground)] font-mono">' + fmt(e.totalInserted) + '</td>' +
          '<td class="px-6 py-4 text-right text-[var(--foreground)] font-mono">' + fmt(e.totalUpdated) + '</td>' +
          '<td class="px-6 py-4">' + errorCell(e.errorMessage) + '</td>' +
        '</tr>'
      ).join('');
    }

    async function loadData() {
      try {
        const res = await fetch('/api/v1/import-status');
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        renderCards(data.recordCounts);
        renderSources(data.sources);
        renderOsvEcosystems(data.osvEcosystems);
        document.getElementById('last-updated').textContent =
          'Updated ' + new Date().toLocaleTimeString();
      } catch (err) {
        const msg = '<tr><td colspan="6" class="px-6 py-8 text-center text-[var(--destructive)]">Failed to load: ' + err.message + '</td></tr>';
        document.getElementById('sources-tbody').innerHTML = msg;
        document.getElementById('osv-tbody').innerHTML = msg.replace('colspan="6"', 'colspan="7"');
      }
    }

    loadData();
    setInterval(loadData, REFRESH_INTERVAL_MS);
  </script>
</body>
</html>`;
    return reply.type('text/html').send(html);
  });
}
