import { FastifyInstance } from 'fastify';
import { prisma } from '../../db/client.js';

const SOURCE_LABELS: Record<string, string> = {
  'nvd-delta': 'NVD (Delta)',
  'nvd': 'NVD (Full)',
  'kev': 'CISA KEV',
  'epss': 'EPSS',
  'osv-mal': 'OSV / Malware',
  'advisory-fortinet': 'Fortinet',
  'advisory-pan': 'Palo Alto',
  'advisory-cisco': 'Cisco',
};

function sourceLabel(source: string): string {
  if (source in SOURCE_LABELS) return SOURCE_LABELS[source];
  if (source.startsWith('osv-')) return `OSV / ${source.slice(4)}`;
  return source;
}

function isOsvEcosystemSource(source: string): boolean {
  return source.startsWith('osv-') && source !== 'osv-mal' && source !== 'osv-delta';
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

    // Per-ecosystem record counts
    const ecosystemCounts = await prisma.oSVVulnerability.groupBy({
      by: ['ecosystem'],
      where: { ecosystem: { not: null } },
      _count: { id: true },
      orderBy: { ecosystem: 'asc' },
    });

    const osvEcosystems = ecosystemCounts.map((r) => {
      const eco = r.ecosystem as string;
      const job = latestBySource.get(`osv-${eco}`);
      return {
        ecosystem: eco,
        recordCount: r._count.id,
        status: job?.status ?? null,
        completedAt: job?.completedAt ?? null,
        totalInserted: job?.totalInserted ?? null,
        totalUpdated: job?.totalUpdated ?? null,
        errorMessage: job?.errorMessage ?? null,
      };
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

  fastify.get('/dashboard', async (_req, reply) => {
    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Heretix — Import Dashboard</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-950 text-gray-100 min-h-screen font-sans">
  <div class="max-w-6xl mx-auto px-6 py-8">
    <!-- Header -->
    <div class="flex items-center justify-between mb-8">
      <div>
        <h1 class="text-2xl font-bold text-white">Import Dashboard</h1>
        <p class="text-gray-400 text-sm mt-1">Data source status and import history</p>
      </div>
      <div class="flex items-center gap-4">
        <span id="last-updated" class="text-gray-500 text-sm"></span>
        <button
          onclick="loadData()"
          class="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm rounded-lg transition-colors"
        >Refresh</button>
      </div>
    </div>

    <!-- Summary Cards -->
    <div id="summary-cards" class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
      <div class="bg-gray-900 rounded-xl p-5 animate-pulse h-24"></div>
      <div class="bg-gray-900 rounded-xl p-5 animate-pulse h-24"></div>
      <div class="bg-gray-900 rounded-xl p-5 animate-pulse h-24"></div>
      <div class="bg-gray-900 rounded-xl p-5 animate-pulse h-24"></div>
    </div>

    <!-- Import Status Table -->
    <div class="bg-gray-900 rounded-xl mb-8 overflow-hidden">
      <div class="px-6 py-4 border-b border-gray-800">
        <h2 class="text-lg font-semibold text-white">Import Status</h2>
      </div>
      <div class="overflow-x-auto">
        <table class="w-full text-sm">
          <thead>
            <tr class="text-gray-400 text-left border-b border-gray-800">
              <th class="px-6 py-3 font-medium">Source</th>
              <th class="px-6 py-3 font-medium">Status</th>
              <th class="px-6 py-3 font-medium">Last Completed</th>
              <th class="px-6 py-3 font-medium text-right">Inserted</th>
              <th class="px-6 py-3 font-medium text-right">Updated</th>
              <th class="px-6 py-3 font-medium">Error</th>
            </tr>
          </thead>
          <tbody id="sources-tbody">
            <tr><td colspan="6" class="px-6 py-8 text-center text-gray-500">Loading...</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- OSV Ecosystems -->
    <div class="bg-gray-900 rounded-xl overflow-hidden">
      <div class="px-6 py-4 border-b border-gray-800">
        <h2 class="text-lg font-semibold text-white">OSV Ecosystems</h2>
        <p class="text-gray-500 text-xs mt-0.5">Per-ecosystem import status and record counts</p>
      </div>
      <div class="overflow-x-auto">
        <table class="w-full text-sm">
          <thead>
            <tr class="text-gray-400 text-left border-b border-gray-800">
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
            <tr><td colspan="7" class="px-6 py-8 text-center text-gray-500">Loading...</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <script>
    const REFRESH_INTERVAL_MS = 60000;

    function fmt(n) {
      if (n == null) return '—';
      return n.toLocaleString();
    }

    function relativeTime(iso) {
      if (!iso) return '—';
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
      if (!status) return '<span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-800 text-gray-500">no jobs</span>';
      const map = {
        completed: 'bg-green-900 text-green-300',
        failed:    'bg-red-900 text-red-300',
        running:   'bg-yellow-900 text-yellow-300',
        pending:   'bg-gray-800 text-gray-400',
      };
      const cls = map[status] || 'bg-gray-800 text-gray-400';
      const dot = status === 'running'
        ? '<span class="inline-block w-2 h-2 rounded-full bg-yellow-400 animate-pulse mr-1.5"></span>'
        : '';
      return '<span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ' + cls + '">' + dot + status + '</span>';
    }

    function errorCell(msg) {
      if (!msg) return '<span class="text-gray-600">—</span>';
      return '<span class="text-red-400 font-mono text-xs block truncate max-w-xs" title="' +
        msg.replace(/"/g, '&quot;') + '">' +
        msg.substring(0, 60) + (msg.length > 60 ? '…' : '') +
      '</span>';
    }

    function renderCards(counts) {
      const cards = [
        { label: 'NVD',        value: fmt(counts.nvd),        color: 'text-blue-400' },
        { label: 'OSV',        value: fmt(counts.osv),        color: 'text-purple-400' },
        { label: 'KEV',        value: fmt(counts.kev),        color: 'text-orange-400' },
        { label: 'Advisories', value: fmt(counts.advisories), color: 'text-teal-400' },
      ];
      document.getElementById('summary-cards').innerHTML = cards.map(c =>
        '<div class="bg-gray-900 rounded-xl p-5">' +
          '<p class="text-gray-400 text-xs font-medium uppercase tracking-wider mb-2">' + c.label + '</p>' +
          '<p class="text-3xl font-bold ' + c.color + '">' + c.value + '</p>' +
        '</div>'
      ).join('');
    }

    function renderSources(sources) {
      if (!sources.length) {
        document.getElementById('sources-tbody').innerHTML =
          '<tr><td colspan="6" class="px-6 py-8 text-center text-gray-500">No import jobs found.</td></tr>';
        return;
      }
      const sorted = [...sources].sort((a, b) => a.label.localeCompare(b.label));
      document.getElementById('sources-tbody').innerHTML = sorted.map(s =>
        '<tr class="border-t border-gray-800 hover:bg-gray-800/50 transition-colors">' +
          '<td class="px-6 py-4 font-medium text-gray-100">' + s.label + '</td>' +
          '<td class="px-6 py-4">' + statusBadge(s.status) + '</td>' +
          '<td class="px-6 py-4 text-gray-400">' + relativeTime(s.completedAt) + '</td>' +
          '<td class="px-6 py-4 text-right text-gray-300 font-mono">' + fmt(s.totalInserted) + '</td>' +
          '<td class="px-6 py-4 text-right text-gray-300 font-mono">' + fmt(s.totalUpdated) + '</td>' +
          '<td class="px-6 py-4">' + errorCell(s.errorMessage) + '</td>' +
        '</tr>'
      ).join('');
    }

    function renderOsvEcosystems(ecosystems) {
      if (!ecosystems.length) {
        document.getElementById('osv-tbody').innerHTML =
          '<tr><td colspan="7" class="px-6 py-8 text-center text-gray-500">No OSV ecosystems imported yet.</td></tr>';
        return;
      }
      document.getElementById('osv-tbody').innerHTML = ecosystems.map(e =>
        '<tr class="border-t border-gray-800 hover:bg-gray-800/50 transition-colors">' +
          '<td class="px-6 py-4 font-medium text-purple-300">' + e.ecosystem + '</td>' +
          '<td class="px-6 py-4">' + statusBadge(e.status) + '</td>' +
          '<td class="px-6 py-4 text-gray-400">' + relativeTime(e.completedAt) + '</td>' +
          '<td class="px-6 py-4 text-right text-gray-300 font-mono">' + fmt(e.recordCount) + '</td>' +
          '<td class="px-6 py-4 text-right text-gray-300 font-mono">' + fmt(e.totalInserted) + '</td>' +
          '<td class="px-6 py-4 text-right text-gray-300 font-mono">' + fmt(e.totalUpdated) + '</td>' +
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
        const msg = '<tr><td colspan="6" class="px-6 py-8 text-center text-red-400">Failed to load: ' + err.message + '</td></tr>';
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
