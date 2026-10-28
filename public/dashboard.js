// Import dashboard (src/api/routes/dashboard.ts). Served from this API rather than
// inlined in the page, so the page's Content-Security-Policy allows scripts from its
// own origin only: a script injected into the markup does not run.
'use strict';

const REFRESH_INTERVAL_MS = 60000;

// Everything rendered below goes through innerHTML, and several of the
// values are not ours: OSV ecosystem names come from upstream OSV data,
// and errorMessage is whatever a failing fetcher produced -- an axios
// error, for instance, can carry an upstream response body. Without this
// an injected script would run with access to the admin key in sessionStorage.
function esc(v) {
  if (v == null) return '';
  return String(v)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

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

function formatDuration(ms) {
  if (ms == null || ms < 0) return '-';
  const totalSeconds = Math.round(ms / 1000);
  const h = Math.floor(totalSeconds / 3600);
  const m = Math.floor((totalSeconds % 3600) / 60);
  const s = totalSeconds % 60;
  if (h > 0) return h + 'h ' + m + 'm';
  if (m > 0) return m + 'm ' + s + 's';
  return s + 's';
}

function statusBadge(status) {
  if (!status) return '<span class="badge badge-neutral">no jobs</span>';
  const map = {
    completed: 'badge-completed',
    failed:    'badge-failed',
    running:   'badge-neutral',
    queued:    'badge-queued',
    pending:   'badge-neutral',
  };
  const cls = map[status] || 'badge-neutral';
  const dot = status === 'running' ? '<span class="dot"></span>' : '';
  return '<span class="badge ' + cls + '">' + dot + esc(status) + '</span>';
}

function fetchFailedBadge(n) {
  if (!n) return '';
  return ' <span class="badge badge-warning" title="' +
    esc(n) + ' item(s) failed to fetch this run and are missing from the results">⚠ ' + esc(n) + '</span>';
}

function errorCell(msg) {
  if (!msg) return '<span class="muted">-</span>';
  return '<span class="error-text" title="' + esc(msg) + '">' +
    esc(msg.substring(0, 60)) + (msg.length > 60 ? '…' : '') +
  '</span>';
}

// ─── API key & actions ────────────────────────────────────────
// The admin key (ADMIN_API_KEY). Kept for this tab only: closing it forgets the key.
const API_KEY_STORAGE = 'heretix_admin_api_key';

function getApiKey() {
  return sessionStorage.getItem(API_KEY_STORAGE) || '';
}

// ─── Sign-in screen ───────────────────────────────────────────
// The dashboard is shown only once the server has accepted the key; until then,
// and whenever a request is refused with 401, the sign-in screen is.
const signInView = document.getElementById('sign-in');
const dashboardView = document.getElementById('dashboard');
const keyInput = document.getElementById('admin-key');
const signInError = document.getElementById('sign-in-error');
const signInSubmit = document.getElementById('sign-in-submit');

function dashboardShown() {
  return !dashboardView.classList.contains('hidden');
}

function showSignIn(message) {
  dashboardView.classList.add('hidden');
  signInView.classList.remove('hidden');
  signInError.textContent = message || '';
  signInError.classList.toggle('hidden', !message);
  signInSubmit.disabled = false;
  signInSubmit.textContent = 'Sign in';
  keyInput.value = '';
  keyInput.focus();
}

function showDashboard() {
  signInView.classList.add('hidden');
  dashboardView.classList.remove('hidden');
}

function signOut(message) {
  sessionStorage.removeItem(API_KEY_STORAGE);
  showSignIn(message);
}

document.getElementById('sign-in-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const key = keyInput.value.trim();
  if (!key) {
    showSignIn('Enter the admin key.');
    return;
  }
  // The first load can take a while: the per-ecosystem counts are a full scan.
  signInSubmit.disabled = true;
  signInSubmit.textContent = 'Signing in…';
  signInError.classList.add('hidden');
  sessionStorage.setItem(API_KEY_STORAGE, key);
  await loadData();
});

document.getElementById('sign-out').addEventListener('click', () => signOut());

let toastTimer = null;
function showToast(msg, kind) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.className = 'toast ' + (kind === 'error' ? 'toast-error' : 'toast-ok');
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.className = 'toast hidden'; }, 3000);
}

// Handlers are attached by delegation (see below) rather than inlined as
// onclick="...". The source name is upstream-derived for OSV rows, and an
// inline handler would need it escaped for the HTML attribute *and* the JS
// string literal inside it -- a data attribute has only the one context.
// The page's CSP refuses inline handlers anyway.
function actionCell(row) {
  // A queued job waits for a free slot in the job runner; it runs once one opens.
  const busy = row.status === 'running' || row.status === 'queued';
  const runBtn = '<button data-action="run" data-source="' + esc(row.source) + '" ' +
    (busy ? 'disabled ' : '') + 'class="btn-sm btn-run">' +
    (row.status === 'queued' ? 'Queued…' : busy ? 'Running…' : 'Run') + '</button>';
  const enabled = row.enabled !== false;
  const toggleBtn = '<button data-action="toggle" data-source="' + esc(row.source) + '" ' +
    'data-enabled="' + (!enabled) + '" ' +
    'class="btn-sm btn-toggle' + (enabled ? '' : ' btn-off') + '">' + (enabled ? 'On' : 'Off') + '</button>';
  return '<div class="actions">' + toggleBtn + runBtn + '</div>';
}

document.addEventListener('click', (ev) => {
  const btn = ev.target.closest('button[data-action]');
  if (!btn) return;
  if (btn.dataset.action === 'run') void runJob(btn.dataset.source);
  if (btn.dataset.action === 'toggle') void toggleJob(btn.dataset.source, btn.dataset.enabled === 'true');
});

async function runJob(source) {
  const key = getApiKey();
  if (!key) { signOut(); return; }
  try {
    const res = await fetch('/api/v1/jobs/' + encodeURIComponent(source) + '/run', {
      method: 'POST',
      headers: { 'x-api-key': key },
    });
    if (res.status === 401) { signOut('The admin key is no longer accepted. Sign in again.'); return; }
    if (res.status === 409) { showToast(source + ' is already queued or running', 'error'); return; }
    if (!res.ok) { showToast('Failed: HTTP ' + res.status, 'error'); return; }
    const body = await res.json().catch(() => ({}));
    showToast((body.status === 'queued' ? 'Queued ' : 'Started ') + source, 'ok');
    setTimeout(loadData, 800);
  } catch (err) {
    showToast('Failed: ' + err.message, 'error');
  }
}

async function toggleJob(source, enabled) {
  const key = getApiKey();
  if (!key) { signOut(); return; }
  try {
    const res = await fetch('/api/v1/jobs/' + encodeURIComponent(source), {
      method: 'PATCH',
      headers: { 'x-api-key': key, 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled }),
    });
    if (res.status === 401) { signOut('The admin key is no longer accepted. Sign in again.'); return; }
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
    '<div class="card">' +
      '<p class="card-label">' + esc(c.label) + '</p>' +
      '<p class="card-value">' + esc(c.value) + '</p>' +
    '</div>'
  ).join('');
}

function messageRow(html) {
  return '<tr><td colspan="9" class="message">' + html + '</td></tr>';
}

// Shared renderer for the three status tables (Core Sources, Vendor
// Advisories, OSV Ecosystems) — all share the same 9-column layout.
function renderTable(tbodyId, rows, getName, options) {
  options = options || {};
  const tbody = document.getElementById(tbodyId);
  if (!rows.length) {
    tbody.innerHTML = messageRow(esc(options.emptyMessage || 'No data found.'));
    return;
  }
  const ordered = options.sort ? [...rows].sort((a, b) => getName(a).localeCompare(getName(b))) : rows;
  tbody.innerHTML = ordered.map(r =>
    '<tr class="row' + (r.enabled === false ? ' row-disabled' : '') + '">' +
      '<td class="name">' + esc(getName(r)) + '</td>' +
      '<td>' + statusBadge(r.status) + fetchFailedBadge(r.fetchFailed) + '</td>' +
      '<td class="muted">' + esc(relativeTime(r.completedAt)) + '</td>' +
      '<td class="num muted">' + esc(formatDuration(r.durationMs)) + '</td>' +
      '<td class="num">' + esc(fmt(r.recordCount)) + '</td>' +
      '<td class="num">' + esc(fmt(r.totalInserted)) + '</td>' +
      '<td class="num">' + esc(fmt(r.totalUpdated)) + '</td>' +
      '<td>' + errorCell(r.errorMessage) + '</td>' +
      '<td>' + actionCell(r) + '</td>' +
    '</tr>'
  ).join('');
}

function tableMessage(html) {
  const msg = messageRow(html);
  document.getElementById('core-tbody').innerHTML = msg;
  document.getElementById('advisory-tbody').innerHTML = msg;
  document.getElementById('osv-tbody').innerHTML = msg;
}

// Loads the import status and shows the dashboard with it. Called on sign-in too, so
// a key is taken only once the server has accepted it.
async function loadData() {
  const key = getApiKey();
  if (!key) {
    showSignIn();
    return;
  }
  try {
    const res = await fetch('/api/v1/import-status', { headers: { 'x-api-key': key } });
    if (res.status === 401) {
      signOut(dashboardShown()
        ? 'The admin key is no longer accepted. Sign in again.'
        : 'The admin key was not accepted.');
      return;
    }
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    showDashboard();
    renderCards(data.recordCounts);
    renderTable('core-tbody', data.coreSources, s => s.label, { sort: true, emptyMessage: 'No import jobs found.' });
    renderTable('advisory-tbody', data.advisorySources, s => s.label, { sort: true, emptyMessage: 'No vendor advisories found.' });
    renderTable('osv-tbody', data.osvEcosystems.filter(e => e.maintained), e => e.ecosystem, { emptyMessage: 'No OSV ecosystems imported yet.' });
    const legacy = data.osvEcosystems.filter(e => !e.maintained);
    document.getElementById('osv-legacy').classList.toggle('hidden', legacy.length === 0);
    document.getElementById('osv-legacy-count').textContent = legacy.length;
    renderTable('osv-legacy-tbody', legacy, e => e.ecosystem, {});
    document.getElementById('last-updated').textContent =
      'Updated ' + new Date().toLocaleTimeString();
  } catch (err) {
    if (dashboardShown()) {
      tableMessage('<span class="text-destructive">Failed to load: ' + esc(err.message) + '</span>');
    } else {
      // The key was not checked, so it is not kept either.
      signOut('Could not reach the server: ' + err.message);
    }
  }
}

document.getElementById('refresh').addEventListener('click', () => { void loadData(); });

// A key kept from earlier in this tab (a reload) opens the dashboard directly.
loadData();
setInterval(() => { if (dashboardShown()) void loadData(); }, REFRESH_INTERVAL_MS);
