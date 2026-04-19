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

export default async function dashboardRoute(fastify: FastifyInstance) {
  fastify.get('/api/v1/import-status', async () => {
    const allJobs = await prisma.collectionJob.findMany({
      orderBy: { createdAt: 'desc' },
    });

    const latestBySource = new Map<string, typeof allJobs[0]>();
    for (const job of allJobs) {
      if (!latestBySource.has(job.source)) latestBySource.set(job.source, job);
    }

    const ecosystemRows = await prisma.oSVVulnerability.groupBy({
      by: ['ecosystem'],
      where: { ecosystem: { not: null } },
      orderBy: { ecosystem: 'asc' },
    });

    const [nvdCount, osvCount, kevCount, advisoryCount] = await Promise.all([
      prisma.nVDVulnerability.count(),
      prisma.oSVVulnerability.count(),
      prisma.vulnerability.count({ where: { isKev: true } }),
      prisma.advisoryVulnerability.count(),
    ]);

    return {
      sources: Array.from(latestBySource.values()).map((j) => ({
        source: j.source,
        label: sourceLabel(j.source),
        status: j.status,
        startedAt: j.startedAt,
        completedAt: j.completedAt,
        totalInserted: j.totalInserted,
        totalUpdated: j.totalUpdated,
        totalFailed: j.totalFailed,
        errorMessage: j.errorMessage,
      })),
      osvEcosystems: ecosystemRows.map((r) => r.ecosystem).filter(Boolean),
      recordCounts: {
        nvd: nvdCount,
        osv: osvCount,
        kev: kevCount,
        advisories: advisoryCount,
      },
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
        <h2 class="text-lg font-semibold text-white">OSV Imported Ecosystems</h2>
      </div>
      <div id="ecosystems" class="px-6 py-5 flex flex-wrap gap-2">
        <span class="text-gray-500 text-sm">Loading...</span>
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
      document.getElementById('sources-tbody').innerHTML = sorted.map(s => {
        const errorCell = s.errorMessage
          ? '<span class="text-red-400 font-mono text-xs truncate max-w-xs block" title="' +
              s.errorMessage.replace(/"/g, '&quot;') + '">' +
              s.errorMessage.substring(0, 60) + (s.errorMessage.length > 60 ? '…' : '') +
            '</span>'
          : '<span class="text-gray-600">—</span>';
        return '<tr class="border-t border-gray-800 hover:bg-gray-800/50 transition-colors">' +
          '<td class="px-6 py-4 font-medium text-gray-100">' + s.label + '</td>' +
          '<td class="px-6 py-4">' + statusBadge(s.status) + '</td>' +
          '<td class="px-6 py-4 text-gray-400">' + relativeTime(s.completedAt) + '</td>' +
          '<td class="px-6 py-4 text-right text-gray-300 font-mono">' + fmt(s.totalInserted) + '</td>' +
          '<td class="px-6 py-4 text-right text-gray-300 font-mono">' + fmt(s.totalUpdated) + '</td>' +
          '<td class="px-6 py-4">' + errorCell + '</td>' +
        '</tr>';
      }).join('');
    }

    function renderEcosystems(ecosystems) {
      const container = document.getElementById('ecosystems');
      if (!ecosystems.length) {
        container.innerHTML = '<span class="text-gray-500 text-sm">No OSV ecosystems imported yet.</span>';
        return;
      }
      container.innerHTML = ecosystems.map(eco =>
        '<span class="px-3 py-1 bg-purple-900/60 text-purple-300 text-xs font-medium rounded-full border border-purple-800/50">' +
          eco + '</span>'
      ).join('');
    }

    async function loadData() {
      try {
        const res = await fetch('/api/v1/import-status');
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        renderCards(data.recordCounts);
        renderSources(data.sources);
        renderEcosystems(data.osvEcosystems);
        document.getElementById('last-updated').textContent =
          'Updated ' + new Date().toLocaleTimeString();
      } catch (err) {
        document.getElementById('sources-tbody').innerHTML =
          '<tr><td colspan="6" class="px-6 py-8 text-center text-red-400">Failed to load data: ' + err.message + '</td></tr>';
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
