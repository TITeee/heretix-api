import { FastifyInstance } from 'fastify';
import { readFile } from 'fs/promises';
import path from 'path';
import { prisma } from '../../db/client.js';
import { STATIC_JOBS } from '../../jobs/registry.js';
import { getEnabledMap } from '../../jobs/config.js';

function isOsvEcosystemSource(source: string): boolean {
  return source.startsWith('osv-') && source !== 'osv-delta';
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
  'advisory-redhat-rhel9': 'red-hat',
  'advisory-redhat-rhel8': 'red-hat',
  'advisory-splunk':     'advisory-splunk',
  'advisory-apache':     'advisory-apache',
  'advisory-zabbix':     'advisory-zabbix',
  'advisory-tomcat':     'advisory-tomcat',
  'advisory-nginx':      'advisory-nginx',
};

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

    const enabledMap = await getEnabledMap();
    const isSourceEnabled = (source: string): boolean => enabledMap.get(source) ?? true;

    const osvEcosystems = ecosystemCounts.map((r) => {
      const eco = r.ecosystem;
      const source = `osv-${eco}`;
      const job = latestBySource.get(source);
      return {
        ecosystem: eco,
        source,
        enabled: isSourceEnabled(source),
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
      source: 'osv-mal',
      enabled: isSourceEnabled('osv-mal'),
      recordCount: malCount,
      status: malJob?.status ?? null,
      completedAt: malJob?.completedAt ?? null,
      totalInserted: malJob?.totalInserted ?? null,
      totalUpdated: malJob?.totalUpdated ?? null,
      errorMessage: malJob?.errorMessage ?? null,
    });

    const [nvdCount, osvCount, kevCount, advisoryCount, epssCount, advisorySourceCounts] = await Promise.all([
      prisma.nVDVulnerability.count(),
      prisma.oSVVulnerability.count(),
      prisma.vulnerability.count({ where: { isKev: true } }),
      prisma.advisoryVulnerability.count(),
      prisma.vulnerability.count({ where: { epssScore: { not: null } } }),
      prisma.advisoryVulnerability.groupBy({ by: ['source'], _count: { _all: true } }),
    ]);
    const advisoryCountBySource = new Map(advisorySourceCounts.map((r) => [r.source, r._count._all]));

    function recordCountForSource(source: string): number | null {
      if (source === 'nvd') return nvdCount;
      if (source === 'kev') return kevCount;
      if (source === 'epss') return epssCount;
      if (source.startsWith('advisory-oracle-linux')) return advisoryCountBySource.get('oracle-linux') ?? 0;
      const mapped = ADVISORY_SOURCE_MAP[source];
      if (mapped) return advisoryCountBySource.get(mapped) ?? 0;
      return null;
    }

    // Main sources: driven by the registry so every job has a row (even if it
    // has never run). OSV per-ecosystem entries and Malware are shown separately.
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
          totalInserted: j?.totalInserted ?? null,
          totalUpdated: j?.totalUpdated ?? null,
          totalFailed: j?.totalFailed ?? null,
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
      --secondary-foreground: oklch(0.985 0 0);
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
        <input
          id="api-key-input"
          type="password"
          placeholder="API key (for actions)"
          onchange="saveApiKey(this.value)"
          class="px-3 py-2 bg-[var(--card)] border border-[var(--border)] text-[var(--foreground)] text-sm rounded-md w-56 placeholder:text-[var(--muted-foreground)] focus:outline-none focus:border-[var(--primary)]"
        />
        <button
          onclick="loadData()"
          class="px-4 py-2 bg-[var(--primary)] text-[var(--primary-foreground)] hover:opacity-90 text-sm font-medium rounded-md transition-opacity"
        >Refresh</button>
      </div>
    </div>

    <!-- Toast -->
    <div id="toast" class="hidden fixed bottom-6 right-6 px-4 py-3 rounded-md text-sm font-medium shadow-lg z-50"></div>

    <!-- Summary Cards -->
    <div id="summary-cards" class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
      <div class="bg-[var(--card)] border border-[var(--border)] rounded-xl p-5 animate-pulse h-24"></div>
      <div class="bg-[var(--card)] border border-[var(--border)] rounded-xl p-5 animate-pulse h-24"></div>
      <div class="bg-[var(--card)] border border-[var(--border)] rounded-xl p-5 animate-pulse h-24"></div>
      <div class="bg-[var(--card)] border border-[var(--border)] rounded-xl p-5 animate-pulse h-24"></div>
    </div>

    <!-- Core Sources Table -->
    <div class="bg-[var(--card)] border border-[var(--border)] rounded-xl mb-8 overflow-hidden">
      <div class="px-4 py-4 border-b border-[var(--border)]">
        <h2 class="text-lg font-semibold text-[var(--card-foreground)]">Core Sources</h2>
        <p class="text-[var(--muted-foreground)] text-xs mt-0.5">NVD, CISA KEV, and FIRST.org EPSS</p>
      </div>
      <div class="overflow-x-auto">
        <table class="w-full text-sm">
          <thead>
            <tr class="text-[var(--muted-foreground)] text-xs uppercase tracking-wide text-left border-b border-[var(--border)]">
              <th class="px-4 py-3 font-medium">Source</th>
              <th class="px-4 py-3 font-medium">Status</th>
              <th class="px-4 py-3 font-medium">Last Completed</th>
              <th class="px-4 py-3 font-medium text-right">Records</th>
              <th class="px-4 py-3 font-medium text-right">Inserted</th>
              <th class="px-4 py-3 font-medium text-right">Updated</th>
              <th class="px-4 py-3 font-medium">Error</th>
              <th class="px-4 py-3 font-medium text-right">Actions</th>
            </tr>
          </thead>
          <tbody id="core-tbody">
            <tr><td colspan="8" class="px-6 py-8 text-center text-[var(--muted-foreground)]">Loading...</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Vendor Advisories Table -->
    <div class="bg-[var(--card)] border border-[var(--border)] rounded-xl mb-8 overflow-hidden">
      <div class="px-4 py-4 border-b border-[var(--border)]">
        <h2 class="text-lg font-semibold text-[var(--card-foreground)]">Vendor Advisories</h2>
        <p class="text-[var(--muted-foreground)] text-xs mt-0.5">Per-vendor advisory feed import status</p>
      </div>
      <div class="overflow-x-auto">
        <table class="w-full text-sm">
          <thead>
            <tr class="text-[var(--muted-foreground)] text-xs uppercase tracking-wide text-left border-b border-[var(--border)]">
              <th class="px-4 py-3 font-medium">Vendor</th>
              <th class="px-4 py-3 font-medium">Status</th>
              <th class="px-4 py-3 font-medium">Last Completed</th>
              <th class="px-4 py-3 font-medium text-right">Records</th>
              <th class="px-4 py-3 font-medium text-right">Inserted</th>
              <th class="px-4 py-3 font-medium text-right">Updated</th>
              <th class="px-4 py-3 font-medium">Error</th>
              <th class="px-4 py-3 font-medium text-right">Actions</th>
            </tr>
          </thead>
          <tbody id="advisory-tbody">
            <tr><td colspan="8" class="px-6 py-8 text-center text-[var(--muted-foreground)]">Loading...</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- OSV Ecosystems -->
    <div class="bg-[var(--card)] border border-[var(--border)] rounded-xl overflow-hidden">
      <div class="px-4 py-4 border-b border-[var(--border)]">
        <h2 class="text-lg font-semibold text-[var(--card-foreground)]">OSV Ecosystems</h2>
        <p class="text-[var(--muted-foreground)] text-xs mt-0.5">Per-ecosystem import status and record counts</p>
      </div>
      <div class="overflow-x-auto">
        <table class="w-full text-sm">
          <thead>
            <tr class="text-[var(--muted-foreground)] text-xs uppercase tracking-wide text-left border-b border-[var(--border)]">
              <th class="px-4 py-3 font-medium">Ecosystem</th>
              <th class="px-4 py-3 font-medium">Status</th>
              <th class="px-4 py-3 font-medium">Last Completed</th>
              <th class="px-4 py-3 font-medium text-right">Records</th>
              <th class="px-4 py-3 font-medium text-right">Inserted</th>
              <th class="px-4 py-3 font-medium text-right">Updated</th>
              <th class="px-4 py-3 font-medium">Error</th>
              <th class="px-4 py-3 font-medium text-right">Actions</th>
            </tr>
          </thead>
          <tbody id="osv-tbody">
            <tr><td colspan="8" class="px-6 py-8 text-center text-[var(--muted-foreground)]">Loading...</td></tr>
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
      const base = 'inline-flex h-5 w-fit shrink-0 items-center justify-center gap-1 rounded-4xl border px-2 py-0.5 text-xs font-medium whitespace-nowrap';
      if (!status) return '<span class="' + base + ' border-transparent bg-[var(--secondary)] text-[var(--secondary-foreground)]">no jobs</span>';
      const map = {
        completed: 'border-[var(--border)] bg-transparent text-[var(--foreground)]',
        failed:    'border-transparent bg-[var(--destructive)]/20 text-[var(--destructive)]',
        running:   'border-transparent bg-[var(--secondary)] text-[var(--secondary-foreground)]',
        pending:   'border-transparent bg-[var(--secondary)] text-[var(--secondary-foreground)]',
      };
      const cls = map[status] || 'border-transparent bg-[var(--secondary)] text-[var(--secondary-foreground)]';
      const dot = status === 'running'
        ? '<span class="inline-block w-2 h-2 rounded-full bg-current animate-pulse mr-1"></span>'
        : '';
      return '<span class="' + base + ' ' + cls + '">' + dot + status + '</span>';
    }

    function errorCell(msg) {
      if (!msg) return '<span class="text-[var(--muted-foreground)]">-</span>';
      return '<span class="text-[var(--destructive)] font-mono text-xs block truncate max-w-[140px]" title="' +
        msg.replace(/"/g, '&quot;') + '">' +
        msg.substring(0, 60) + (msg.length > 60 ? '…' : '') +
      '</span>';
    }

    // ─── API key & actions ────────────────────────────────────────
    const API_KEY_STORAGE = 'heretix_api_key';

    function getApiKey() {
      return localStorage.getItem(API_KEY_STORAGE) || '';
    }
    function saveApiKey(value) {
      localStorage.setItem(API_KEY_STORAGE, value.trim());
      showToast('API key saved', 'ok');
    }

    let toastTimer = null;
    function showToast(msg, kind) {
      const el = document.getElementById('toast');
      el.textContent = msg;
      el.className = 'fixed bottom-6 right-6 px-4 py-3 rounded-md text-sm font-medium shadow-lg z-50 ' +
        (kind === 'error'
          ? 'bg-[var(--destructive)] text-white'
          : 'bg-[var(--primary)] text-[var(--primary-foreground)]');
      if (toastTimer) clearTimeout(toastTimer);
      toastTimer = setTimeout(() => { el.className = 'hidden'; }, 3000);
    }

    function actionCell(row) {
      const running = row.status === 'running';
      const runBtn = '<button onclick="runJob(\\'' + row.source + '\\')" ' +
        (running ? 'disabled ' : '') +
        'class="px-2.5 py-1 text-xs font-medium rounded-md border border-[var(--border)] ' +
        (running ? 'opacity-40 cursor-not-allowed' : 'hover:bg-[var(--accent)]') + '">' +
        (running ? 'Running…' : 'Run') + '</button>';
      const enabled = row.enabled !== false;
      const toggleBtn = '<button onclick="toggleJob(\\'' + row.source + '\\', ' + (!enabled) + ')" ' +
        'class="px-2.5 py-1 text-xs font-medium rounded-md border ' +
        (enabled
          ? 'border-[var(--border)] text-[var(--foreground)] hover:bg-[var(--accent)]'
          : 'border-transparent bg-[var(--destructive)]/20 text-[var(--destructive)]') +
        '">' + (enabled ? 'On' : 'Off') + '</button>';
      return '<div class="flex items-center justify-end gap-2">' + toggleBtn + runBtn + '</div>';
    }

    async function runJob(source) {
      const key = getApiKey();
      if (!key) { showToast('API key required for actions', 'error'); return; }
      try {
        const res = await fetch('/api/v1/jobs/' + encodeURIComponent(source) + '/run', {
          method: 'POST',
          headers: { 'x-api-key': key },
        });
        if (res.status === 401) { showToast('Invalid API key', 'error'); return; }
        if (res.status === 409) { showToast(source + ' is already running', 'error'); return; }
        if (!res.ok) { showToast('Failed: HTTP ' + res.status, 'error'); return; }
        showToast('Started ' + source, 'ok');
        setTimeout(loadData, 800);
      } catch (err) {
        showToast('Failed: ' + err.message, 'error');
      }
    }

    async function toggleJob(source, enabled) {
      const key = getApiKey();
      if (!key) { showToast('API key required for actions', 'error'); return; }
      try {
        const res = await fetch('/api/v1/jobs/' + encodeURIComponent(source), {
          method: 'PATCH',
          headers: { 'x-api-key': key, 'Content-Type': 'application/json' },
          body: JSON.stringify({ enabled }),
        });
        if (res.status === 401) { showToast('Invalid API key', 'error'); return; }
        if (!res.ok) { showToast('Failed: HTTP ' + res.status, 'error'); return; }
        showToast(source + (enabled ? ' enabled' : ' disabled'), 'ok');
        loadData();
      } catch (err) {
        showToast('Failed: ' + err.message, 'error');
      }
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

    // Shared renderer for the three status tables (Core Sources, Vendor
    // Advisories, OSV Ecosystems) — all share the same 8-column layout.
    function renderTable(tbodyId, rows, getName, options) {
      options = options || {};
      const tbody = document.getElementById(tbodyId);
      if (!rows.length) {
        tbody.innerHTML = '<tr><td colspan="8" class="px-6 py-8 text-center text-[var(--muted-foreground)]">' +
          (options.emptyMessage || 'No data found.') + '</td></tr>';
        return;
      }
      const ordered = options.sort ? [...rows].sort((a, b) => getName(a).localeCompare(getName(b))) : rows;
      tbody.innerHTML = ordered.map(r =>
        '<tr class="border-t border-[var(--border)] hover:bg-[var(--accent)]/40 transition-colors' +
          (r.enabled === false ? ' opacity-50' : '') + '">' +
          '<td class="px-4 py-4 font-medium text-[var(--foreground)]">' + getName(r) + '</td>' +
          '<td class="px-4 py-4">' + statusBadge(r.status) + '</td>' +
          '<td class="px-4 py-4 text-[var(--muted-foreground)]">' + relativeTime(r.completedAt) + '</td>' +
          '<td class="px-4 py-4 text-right text-[var(--foreground)] font-mono">' + fmt(r.recordCount) + '</td>' +
          '<td class="px-4 py-4 text-right text-[var(--foreground)] font-mono">' + fmt(r.totalInserted) + '</td>' +
          '<td class="px-4 py-4 text-right text-[var(--foreground)] font-mono">' + fmt(r.totalUpdated) + '</td>' +
          '<td class="px-4 py-4">' + errorCell(r.errorMessage) + '</td>' +
          '<td class="px-4 py-4">' + actionCell(r) + '</td>' +
        '</tr>'
      ).join('');
    }

    async function loadData() {
      try {
        const res = await fetch('/api/v1/import-status');
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        renderCards(data.recordCounts);
        renderTable('core-tbody', data.coreSources, s => s.label, { sort: true, emptyMessage: 'No import jobs found.' });
        renderTable('advisory-tbody', data.advisorySources, s => s.label, { sort: true, emptyMessage: 'No vendor advisories found.' });
        renderTable('osv-tbody', data.osvEcosystems, e => e.ecosystem, { emptyMessage: 'No OSV ecosystems imported yet.' });
        document.getElementById('last-updated').textContent =
          'Updated ' + new Date().toLocaleTimeString();
      } catch (err) {
        const msg = '<tr><td colspan="8" class="px-6 py-8 text-center text-[var(--destructive)]">Failed to load: ' + err.message + '</td></tr>';
        document.getElementById('core-tbody').innerHTML = msg;
        document.getElementById('advisory-tbody').innerHTML = msg;
        document.getElementById('osv-tbody').innerHTML = msg;
      }
    }

    // Prefill API key input from localStorage
    document.getElementById('api-key-input').value = getApiKey();

    loadData();
    setInterval(loadData, REFRESH_INTERVAL_MS);
  </script>
</body>
</html>`;
    return reply.type('text/html').send(html);
  });
}
