const $ = (sel) => document.querySelector(sel);

let network = null;
let pollTimer = null;
let gatewayIp = null;
let snmpEnabled = false;

const TYPE_COLORS = {
  router: '#fbbf24', switch: '#f59e0b', firewall: '#fb7185', ap: '#f59e0b',
  server: '#a78bfa', nas: '#a78bfa',
  workstation: '#4ea8ff', laptop: '#4ea8ff',
  phone: '#38bdf8', tablet: '#38bdf8',
  tv: '#f472b6', speaker: '#f472b6', streaming: '#f472b6',
  printer: '#4ade80', camera: '#4ade80', iot: '#4ade80',
  gaming: '#c084fc', voip: '#22d3ee',
  unknown: '#8b97a3',
};

const TYPE_ICONS = {
  router: '🛜', switch: '🔀', firewall: '🛡️', ap: '📶',
  server: '🖥️', nas: '🗄️',
  workstation: '💻', laptop: '💻',
  phone: '📱', tablet: '📱',
  tv: '📺', speaker: '🔊', streaming: '🎬',
  printer: '🖨️', camera: '📷', iot: '💡',
  gaming: '🎮', voip: '☎️',
  unknown: '❓',
};

/* ---------------- theme ---------------- */

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('netscan-theme', theme);
  $('#theme-btn').textContent = theme === 'dark' ? '🌙' : '☀️';
  // re-render graph so colors pick up.
  if (window._lastHosts) renderGraph(window._lastHosts, window._lastLinks || []);
}

function initTheme() {
  const saved = localStorage.getItem('netscan-theme');
  const theme = saved || (matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
  applyTheme(theme);
}

$('#theme-btn').addEventListener('click', () => {
  const cur = document.documentElement.getAttribute('data-theme') || 'dark';
  applyTheme(cur === 'dark' ? 'light' : 'dark');
});

/* ---------------- API ---------------- */

async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok) {
    const txt = await res.text();
    throw new Error(`${res.status}: ${txt}`);
  }
  return res.json();
}

/* ---------------- helpers ---------------- */

function fmtPort(p) {
  const label = p.service ? `${p.port}/${p.protocol} ${p.service}` : `${p.port}/${p.protocol}`;
  const title = [p.product, p.version].filter(Boolean).join(' ');
  return `<span class="port-chip" title="${title}">${label}</span>`;
}

function fmtTime(iso) {
  if (!iso) return '';
  return new Date(iso).toLocaleString();
}

function uptimeClass(pct) {
  if (pct == null) return '';
  if (pct >= 0.98) return 'good';
  if (pct >= 0.9) return 'warn';
  return 'bad';
}

function svcChips(h) {
  const out = [];
  if (h.netbios_name) out.push(`<span class="svc-chip" title="NetBIOS">SMB: ${h.netbios_name}</span>`);
  for (const m of h.mdns_services || []) {
    const t = (m.type || '').replace(/\._?tcp\.local\.?$/, '').replace(/^_/, '');
    if (t) out.push(`<span class="svc-chip" title="mDNS ${m.name || ''}">${t}</span>`);
  }
  for (const s of h.ssdp_info || []) {
    const label = s.friendly_name || s.model || (s.server || '').split(' ')[0];
    if (label) out.push(`<span class="svc-chip" title="UPnP ${s.st || ''}">${label}</span>`);
  }
  // dedupe by text
  const seen = new Set();
  return out.filter((html) => {
    const txt = html.replace(/<[^>]+>/g, '');
    if (seen.has(txt)) return false;
    seen.add(txt);
    return true;
  }).join('') || '<span class="muted">—</span>';
}

function sparkline(samples) {
  if (!samples.length) return '<span class="muted">no data</span>';
  const w = 120, h = 22;
  const step = w / Math.max(samples.length, 1);
  const upColor = getComputedStyle(document.documentElement).getPropertyValue('--sparkline-up').trim();
  const downColor = getComputedStyle(document.documentElement).getPropertyValue('--sparkline-down').trim();
  const rects = samples.map((s, i) => {
    const color = s.is_up ? upColor : downColor;
    const x = (i * step).toFixed(2);
    const height = s.is_up ? (s.rtt_ms ? Math.min(h, 4 + Math.log2(1 + s.rtt_ms) * 4) : h * 0.5) : h;
    const y = h - height;
    return `<rect x="${x}" y="${y.toFixed(2)}" width="${(step + 0.5).toFixed(2)}" height="${height.toFixed(2)}" fill="${color}" />`;
  }).join('');
  return `<svg class="sparkline" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">${rects}</svg>`;
}

/* ---------------- status ---------------- */

async function loadStatus() {
  const s = await api('/api/status');
  gatewayIp = s.gateway;
  snmpEnabled = s.snmp_enabled;
  if (!$('#target').value) $('#target').value = s.default_target;

  const statusEl = $('#status');
  if (s.running) {
    statusEl.textContent = s.kind === 'discover'
      ? 'Running discovery (mDNS / SSDP / NetBIOS / topology)…'
      : `Scanning ${s.target}…`;
    statusEl.className = 'running';
    $('#scan-btn').disabled = true;
    $('#discover-btn').disabled = true;
    if (!pollTimer) {
      pollTimer = setInterval(async () => {
        const ss = await api('/api/status');
        if (!ss.running) {
          clearInterval(pollTimer);
          pollTimer = null;
          $('#scan-btn').disabled = false;
          $('#discover-btn').disabled = false;
          $('#status').textContent = 'Done';
          $('#status').className = 'ok';
          await refresh();
        }
      }, 2000);
    }
  } else {
    $('#scan-btn').disabled = false;
    $('#discover-btn').disabled = false;
  }
}

/* ---------------- hosts table ---------------- */

async function loadHosts() {
  const [hosts, links] = await Promise.all([api('/api/hosts'), api('/api/topology')]);
  window._lastHosts = hosts;
  window._lastLinks = links;
  $('#host-count').textContent = hosts.length;

  const tbody = $('#hosts tbody');
  tbody.innerHTML = '';
  for (const h of hosts) {
    const tr = document.createElement('tr');
    const openPorts = (h.ports || []).filter((p) => p.state === 'open');
    const type = h.device_type || 'unknown';
    const color = TYPE_COLORS[type] || TYPE_COLORS.unknown;
    const pct = h.uptime_24h;
    const pctTxt = pct == null ? '—' : `${(pct * 100).toFixed(1)}%`;
    const rttTxt = h.avg_rtt_ms ? `${h.avg_rtt_ms.toFixed(1)} ms` : '';
    tr.innerHTML = `
      <td title="${type}">${TYPE_ICONS[type] || '❓'}</td>
      <td>${h.ip}</td>
      <td>${h.hostname || h.netbios_name || '<span class="muted">—</span>'}</td>
      <td><span class="type-tag" style="border-color:${color};color:${color}">${type}</span></td>
      <td>${h.vendor || '<span class="muted">—</span>'}</td>
      <td>${h.os || '<span class="muted">—</span>'}</td>
      <td>${openPorts.length ? openPorts.map(fmtPort).join('') : '<span class="muted">none</span>'}</td>
      <td>${svcChips(h)}</td>
      <td><div class="uptime-cell">
            <span class="uptime-pct ${uptimeClass(pct)}">${pctTxt}</span>
            <span class="spark-slot" data-host="${h.id}"></span>
            <span class="uptime-meta">${h.uptime_samples || 0} samples${rttTxt ? ' · ' + rttTxt : ''}</span>
          </div></td>
      <td>${fmtTime(h.last_seen)}</td>
      <td><button class="row-del" data-id="${h.id}">×</button></td>
    `;
    tbody.appendChild(tr);
  }
  tbody.querySelectorAll('.row-del').forEach((b) => {
    b.addEventListener('click', async () => {
      await api(`/api/hosts/${b.dataset.id}`, { method: 'DELETE' });
      await refresh();
    });
  });

  // Fetch sparkline data for each host (lazy, parallel, capped).
  const slots = [...tbody.querySelectorAll('.spark-slot')];
  await Promise.all(slots.map(async (slot) => {
    try {
      const samples = await api(`/api/hosts/${slot.dataset.host}/uptime?hours=24`);
      slot.innerHTML = sparkline(samples);
    } catch {
      slot.innerHTML = '';
    }
  }));

  renderGraph(hosts, links);
}

/* ---------------- graph ---------------- */

function renderGraph(hosts, links) {
  const nodes = [];
  const edges = [];
  const seenNodeIds = new Set();
  const ipToId = new Map();

  // Self node represents the scanner host.
  nodes.push({
    id: 'self',
    label: 'Scanner',
    shape: 'diamond',
    color: { background: '#4ea8ff', border: '#fff' },
    font: { color: '#fff', size: 12 },
  });
  seenNodeIds.add('self');

  for (const h of hosts) {
    const type = h.device_type || 'unknown';
    const color = TYPE_COLORS[type] || TYPE_COLORS.unknown;
    const label = [
      `${TYPE_ICONS[type] || ''} ${h.hostname || h.netbios_name || h.ip}`,
      h.ip,
      h.vendor || h.os || '',
    ].filter(Boolean).join('\n');
    const openPorts = (h.ports || []).filter((p) => p.state === 'open').length;
    const isGw = h.ip === gatewayIp;
    nodes.push({
      id: `h:${h.id}`,
      label,
      shape: isGw ? 'box' : 'dot',
      size: 12 + Math.min(openPorts, 12),
      color: { background: color, border: isGw ? '#fff' : 'rgba(0,0,0,0.3)' },
      font: { color: getComputedStyle(document.documentElement).getPropertyValue('--fg').trim(), size: 12 },
      title: `${h.ip}\n${type}\n${openPorts} open ports`,
    });
    ipToId.set(h.ip, `h:${h.id}`);
    seenNodeIds.add(`h:${h.id}`);
  }

  // Build edges from topology links (traceroute / lldp / cdp).
  const edgeColor = getComputedStyle(document.documentElement).getPropertyValue('--border').trim();
  const addEdge = (from, to, dashes = false) => {
    if (!from || !to || from === to) return;
    edges.push({ from, to, color: { color: edgeColor }, dashes });
  };

  const ensureHopNode = (ip) => {
    if (ipToId.has(ip)) return ipToId.get(ip);
    const id = `hop:${ip}`;
    if (!seenNodeIds.has(id)) {
      nodes.push({
        id, label: ip, shape: 'dot', size: 8,
        color: { background: '#8b97a3', border: 'rgba(0,0,0,0.3)' },
        font: { color: getComputedStyle(document.documentElement).getPropertyValue('--muted').trim(), size: 11 },
        title: `transit hop ${ip}`,
      });
      seenNodeIds.add(id);
      ipToId.set(ip, id);
    }
    return id;
  };

  let hasTracerouteLinks = false;
  for (const l of links || []) {
    const src = l.src === '__self__' ? 'self' : ensureHopNode(l.src);
    const dst = ensureHopNode(l.dst);
    addEdge(src, dst, l.discovery !== 'traceroute');
    if (l.discovery === 'traceroute') hasTracerouteLinks = true;
  }

  // Fallback: if no topology data yet, fan out from self.
  if (!hasTracerouteLinks) {
    for (const h of hosts) addEdge('self', `h:${h.id}`);
  }

  const container = document.getElementById('graph');
  const data = { nodes: new vis.DataSet(nodes), edges: new vis.DataSet(edges) };
  const options = {
    physics: {
      solver: 'forceAtlas2Based',
      forceAtlas2Based: { gravitationalConstant: -55, springLength: 110 },
      stabilization: { iterations: 200 },
    },
    interaction: { hover: true, tooltipDelay: 150 },
    nodes: { borderWidth: 2 },
  };

  if (network) network.destroy();
  network = new vis.Network(container, data, options);
}

/* ---------------- scans table ---------------- */

async function loadScans() {
  const scans = await api('/api/scans');
  const tbody = $('#scans tbody');
  tbody.innerHTML = '';
  for (const s of scans) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${s.id}</td>
      <td>${s.target}</td>
      <td>${fmtTime(s.started_at)}</td>
      <td>${fmtTime(s.finished_at)}</td>
      <td>${s.status}</td>
      <td>${s.message || ''}</td>
    `;
    tbody.appendChild(tr);
  }
}

async function refresh() {
  await Promise.all([loadHosts(), loadScans(), loadStatus()]);
}

async function startScan() {
  const target = $('#target').value.trim();
  const profile = $('#profile').value;
  $('#status').textContent = 'Starting…';
  $('#status').className = 'running';
  try {
    await api('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, profile }),
    });
    await loadStatus();
  } catch (e) {
    $('#status').textContent = e.message;
    $('#status').className = 'err';
  }
}

async function startDiscover() {
  $('#status').textContent = 'Starting discovery…';
  $('#status').className = 'running';
  try {
    await api('/api/discover', { method: 'POST' });
    await loadStatus();
  } catch (e) {
    $('#status').textContent = e.message;
    $('#status').className = 'err';
  }
}

$('#scan-btn').addEventListener('click', startScan);
$('#discover-btn').addEventListener('click', startDiscover);
$('#refresh-btn').addEventListener('click', refresh);
$('#clear-btn').addEventListener('click', async () => {
  if (!confirm('Delete all scan data?')) return;
  await api('/api/clear', { method: 'POST' });
  await refresh();
});

initTheme();
refresh();
