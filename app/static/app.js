const $ = (sel) => document.querySelector(sel);

let network = null;
let pollTimer = null;
let gatewayIp = null;

async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok) {
    const txt = await res.text();
    throw new Error(`${res.status}: ${txt}`);
  }
  return res.json();
}

function fmtPort(p) {
  const label = p.service ? `${p.port}/${p.protocol} ${p.service}` : `${p.port}/${p.protocol}`;
  return `<span class="port-chip" title="${(p.product || '') + ' ' + (p.version || '')}">${label}</span>`;
}

function fmtTime(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return d.toLocaleString();
}

async function loadStatus() {
  const s = await api('/api/status');
  gatewayIp = s.gateway;
  if (!$('#target').value) $('#target').value = s.default_target;

  const statusEl = $('#status');
  if (s.running) {
    statusEl.textContent = `Scanning ${s.target}…`;
    statusEl.className = 'running';
    $('#scan-btn').disabled = true;
    if (!pollTimer) {
      pollTimer = setInterval(async () => {
        const ss = await api('/api/status');
        if (!ss.running) {
          clearInterval(pollTimer);
          pollTimer = null;
          $('#scan-btn').disabled = false;
          $('#status').textContent = 'Scan complete';
          $('#status').className = 'ok';
          await refresh();
        }
      }, 2000);
    }
  } else {
    $('#scan-btn').disabled = false;
  }
}

async function loadHosts() {
  const hosts = await api('/api/hosts');
  $('#host-count').textContent = hosts.length;

  const tbody = $('#hosts tbody');
  tbody.innerHTML = '';
  for (const h of hosts) {
    const tr = document.createElement('tr');
    const openPorts = (h.ports || []).filter((p) => p.state === 'open');
    tr.innerHTML = `
      <td>${h.ip}</td>
      <td>${h.hostname || '<span class="muted">—</span>'}</td>
      <td>${h.mac || '<span class="muted">—</span>'}</td>
      <td>${h.vendor || '<span class="muted">—</span>'}</td>
      <td>${h.os || '<span class="muted">—</span>'}</td>
      <td>${openPorts.length ? openPorts.map(fmtPort).join('') : '<span class="muted">none</span>'}</td>
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

  renderGraph(hosts);
}

function renderGraph(hosts) {
  const nodes = [];
  const edges = [];

  const gw = gatewayIp || (hosts[0] && hosts[0].ip) || 'gateway';
  nodes.push({
    id: 'gw',
    label: `Gateway\n${gw}`,
    shape: 'box',
    color: { background: '#2e7fd1', border: '#4ea8ff' },
    font: { color: '#fff', size: 14 },
  });

  for (const h of hosts) {
    const openPorts = (h.ports || []).filter((p) => p.state === 'open').length;
    const label = [h.hostname || h.ip, h.ip !== (h.hostname || '') ? h.ip : '', h.os || '']
      .filter(Boolean)
      .join('\n');
    const isGw = h.ip === gw;
    nodes.push({
      id: h.id,
      label,
      shape: 'dot',
      size: 12 + Math.min(openPorts, 12),
      color: isGw
        ? { background: '#fbbf24', border: '#fff' }
        : { background: '#4ade80', border: '#2c3742' },
      font: { color: '#e6edf3', size: 12 },
      title: `${h.ip}\n${openPorts} open ports`,
    });
    if (!isGw) edges.push({ from: 'gw', to: h.id, color: { color: '#2c3742' } });
  }

  const container = document.getElementById('graph');
  const data = { nodes: new vis.DataSet(nodes), edges: new vis.DataSet(edges) };
  const options = {
    physics: {
      solver: 'forceAtlas2Based',
      forceAtlas2Based: { gravitationalConstant: -50, springLength: 120 },
      stabilization: { iterations: 150 },
    },
    interaction: { hover: true, tooltipDelay: 150 },
    nodes: { borderWidth: 2 },
  };

  if (network) network.destroy();
  network = new vis.Network(container, data, options);
}

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

$('#scan-btn').addEventListener('click', startScan);
$('#refresh-btn').addEventListener('click', refresh);
$('#clear-btn').addEventListener('click', async () => {
  if (!confirm('Delete all scan data?')) return;
  await api('/api/clear', { method: 'POST' });
  await refresh();
});

refresh();
