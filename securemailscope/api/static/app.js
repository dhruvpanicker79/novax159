/* Kavach console.
   Vanilla, no build step, no CDN — the same constraint as the offline report
   (ADR-0018). Charts are hand-drawn SVG rather than a charting library, which
   keeps the dependency story intact and renders identically offline.

   Rule this file follows: every number on screen comes from the capture or the
   store. Where a figure cannot be derived, the panel says so instead of
   inventing one — a dashboard that guesses is worse than one that admits a gap. */

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"]/g, c =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const num = n => (n ?? 0).toLocaleString();
const SEV = ['critical', 'high', 'medium', 'low', 'info'];
const COLOR = {
  critical: '#dc2626', high: '#f97316', medium: '#eab308',
  low: '#22c55e', info: '#64748b', accent: '#dc2626', blue: '#3b82f6', ok: '#22c55e',
};
/* Categories that describe how a server is configured, as opposed to evidence
   that somebody attacked it. The Overview counts them separately because they
   are different work for different people. */
const MISCONFIG = new Set(['tls_version', 'cipher_suite', 'key_exchange', 'certificate',
  'certificate_strength', 'starttls', 'protocol', 'configuration']);

const S = {
  report: null, jobs: [], dispositions: {}, snapshots: [], audit: [], user: null,
  tab: 'overview', focus: null, range: 'all', drift: null,
};

/* ─────────────── plumbing ─────────────── */
async function api(path, opts = {}) {
  const res = await fetch(path, {
    ...opts,
    headers: { ...(opts.body ? { 'Content-Type': 'application/json' } : {}), ...(opts.headers || {}) },
  });
  if (res.status === 401) { location.href = '/login'; return null; }
  const text = await res.text();
  let data; try { data = JSON.parse(text); } catch { data = text; }
  if (!res.ok) throw new Error((data && data.error) || res.statusText);
  return data;
}

function toast(msg, kind = '') {
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'show ' + kind;
  clearTimeout(t._h);
  t._h = setTimeout(() => (t.className = ''), 4200);
}

const KEY = f => `${f.rule_id}@${f.affected_host || 'unknown'}:${f.affected_port || 0}`;
const gradeClass = g => 'grade-' + String(g || '?').replace('+', 'plus').replace('?', 'q');
const findings = () => S.report?.prioritised_findings || [];
const sessions = () => S.report?.sessions || [];
const bytes = f => {
  const n = (f.c2s_bytes || 0) + (f.s2c_bytes || 0);
  if (!n) return '—';
  const s = n < 1024 ? `${n} B` : `${(n / 1024).toFixed(1)} KB`;
  return `${s} (${f.c2s_bytes || 0} out, ${f.s2c_bytes || 0} in)`;
};
const dur = (a, b) => {
  if (!a || !b) return '—';
  const ms = new Date(b) - new Date(a);
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(2)} s`;
};
const ago = iso => {
  if (!iso) return '—';
  const s = (Date.now() - new Date(iso)) / 1000;
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
};

/* ─────────────── icons ─────────────── */
const ICONS = {
  shield: '<path d="M12 2l8 4v6c0 5-3.4 9.3-8 10-4.6-.7-8-5-8-10V6l8-4z"/>',
  activity: '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
  alert: '<path d="M12 3L2 20h20L12 3zm0 6v6m0 3v.5"/>',
  pie: '<path d="M12 3v9h9a9 9 0 11-9-9z"/>',
  upload: '<path d="M12 16V4m-5 5l5-5 5 5M4 20h16"/>',
  archive: '<path d="M3 7h18v13H3zM3 3h18v4H3zm6 8h6"/>',
  list: '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
  network: '<path d="M5 3h5v5H5zM14 16h5v5h-5zM7.5 8v8h9"/>',
  lock: '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 118 0v4"/>',
  file: '<path d="M14 2H6v20h12V6zM14 2v4h4"/>',
  download: '<path d="M12 4v12m-5-5l5 5 5-5M4 20h16"/>',
  brain: '<path d="M9 3a3 3 0 00-3 3 3 3 0 00-2 5 3 3 0 002 5 3 3 0 003 3V3zm6 0a3 3 0 013 3 3 3 0 012 5 3 3 0 01-2 5 3 3 0 01-3 3V3z"/>',
  check: '<path d="M4 12.5l5 5L20 6.5"/>',
  target: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="3.5"/><path d="M12 3v5.5M12 15.5V21M3 12h5.5M15.5 12H21"/>',
  server: '<rect x="3" y="4" width="18" height="6" rx="1.5"/><rect x="3" y="14" width="18" height="6" rx="1.5"/><path d="M7 7h.01M7 17h.01"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3.5 2"/>',
  arrow: '<path d="M5 12h14m-6-6l6 6-6 6"/>',
};
const icon = (n, cls = 'ic') => `<svg class="${cls}" viewBox="0 0 24 24" fill="none"
  stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
  ${ICONS[n] || ICONS.shield}</svg>`;
const head = (t, i, tools) =>
  `<div class="panel-head">${icon(i)}${esc(t)}${tools ? `<div class="tools">${tools}</div>` : ''}</div>`;

/* ─────────────── charts ─────────────── */
function spark(values, colour) {
  if (values.length < 2) {
    // One data point is not a trend. Draw the level, say nothing about direction.
    return `<svg viewBox="0 0 120 30" preserveAspectRatio="none" style="width:100%;height:30px">
      <line x1="0" y1="21" x2="120" y2="21" stroke="${colour}" stroke-width="1.6"
        stroke-dasharray="3 3" opacity=".45"/></svg>`;
  }
  const max = Math.max(...values, 1), min = Math.min(...values, 0);
  const dx = 120 / (values.length - 1);
  const y = v => 27 - ((v - min) / (max - min || 1)) * 22;
  const line = values.map((v, i) => `${i ? 'L' : 'M'}${(i * dx).toFixed(1)},${y(v).toFixed(1)}`).join(' ');
  const id = 'g' + Math.random().toString(36).slice(2, 8);
  return `<svg viewBox="0 0 120 30" preserveAspectRatio="none" style="width:100%;height:30px">
    <defs><linearGradient id="${id}" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="${colour}" stop-opacity=".34"/>
      <stop offset="100%" stop-color="${colour}" stop-opacity="0"/></linearGradient></defs>
    <path d="${line} L120,30 L0,30 Z" fill="url(#${id})"/>
    <path d="${line}" fill="none" stroke="${colour}" stroke-width="1.6"
      stroke-linejoin="round" stroke-linecap="round"/></svg>`;
}

/* Stacked area, one band per severity. x is session order in the capture, which
   is the only time-like axis a single PCAP actually has. */
function stackedArea(series, labels, { h = 230 } = {}) {
  const n = labels.length;
  if (!n) return '<div class="empty">no data</div>';
  const w = 900, padL = 34, padB = 26, padT = 10;
  const iw = w - padL - 8, ih = h - padB - padT;
  const totals = labels.map((_, i) => series.reduce((a, s) => a + s.values[i], 0));
  const max = Math.max(...totals, 4);
  const step = n > 1 ? iw / (n - 1) : 0;
  const X = i => padL + i * step;
  const Y = v => padT + ih - (v / max) * ih;

  let base = new Array(n).fill(0);
  const bands = series.map(s => {
    const top = base.map((b, i) => b + s.values[i]);
    const up = top.map((v, i) => `${i ? 'L' : 'M'}${X(i).toFixed(1)},${Y(v).toFixed(1)}`).join(' ');
    const down = base.map((v, i) => `L${X(n - 1 - i).toFixed(1)},${Y(base[n - 1 - i]).toFixed(1)}`)
      .reverse().join(' ');
    const path = `<path d="${up} ${down} Z" fill="${s.color}" fill-opacity=".22"/>
      <path d="${up}" fill="none" stroke="${s.color}" stroke-width="1.7"
        stroke-linejoin="round" stroke-linecap="round"/>`;
    base = top;
    return path;
  }).join('');

  const ticks = [0, 0.25, 0.5, 0.75, 1].map(f => {
    const v = Math.round(max * f), y = Y(v);
    return `<line x1="${padL}" y1="${y.toFixed(1)}" x2="${w - 8}" y2="${y.toFixed(1)}"
      stroke="#232329" stroke-width="1"/>
      <text x="${padL - 8}" y="${(y + 3.5).toFixed(1)}" text-anchor="end" fill="#6a6a78"
        font-size="10" font-family="var(--mono)">${v}</text>`;
  }).join('');

  const every = Math.max(1, Math.ceil(n / 8));
  const xlabels = labels.map((l, i) => i % every === 0
    ? `<text x="${X(i).toFixed(1)}" y="${h - 8}" text-anchor="middle" fill="#6a6a78"
        font-size="9.5" font-family="var(--mono)">${esc(l)}</text>` : '').join('');

  return `<svg viewBox="0 0 ${w} ${h}" style="width:100%;height:${h}px">
    ${ticks}${bands}${xlabels}</svg>`;
}

function donut(items, centreLabel, { size = 168 } = {}) {
  const total = items.reduce((a, b) => a + b.value, 0);
  if (!total) return '<div class="empty">nothing observed</div>';
  const r = size / 2 - 17, cx = size / 2, cy = size / 2, C = 2 * Math.PI * r;
  let off = 0;
  const rings = items.filter(i => i.value).map(i => {
    const frac = i.value / total;
    const seg = `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${i.color}"
      stroke-width="15" stroke-dasharray="${(frac * C - 1.5).toFixed(2)} ${C.toFixed(2)}"
      stroke-dashoffset="${(-off * C).toFixed(2)}" transform="rotate(-90 ${cx} ${cy})"/>`;
    off += frac;
    return seg;
  }).join('');
  return `<div style="display:flex;align-items:center;gap:20px;flex-wrap:wrap">
    <svg width="${size}" height="${size}" style="flex:none">
      <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="#1c1c22" stroke-width="15"/>
      ${rings}
      <text x="${cx}" y="${cy - 1}" text-anchor="middle" fill="#f2f2f4" font-size="24"
        font-weight="600">${num(total)}</text>
      <text x="${cx}" y="${cy + 16}" text-anchor="middle" fill="#6a6a78" font-size="10.5"
        >${esc(centreLabel)}</text>
    </svg>
    <div class="legend" style="flex-direction:column;gap:9px">
      ${items.filter(i => i.value).map(i => `<span><i style="background:${i.color}"></i>${esc(i.label)}
        <b>${Math.round(i.value / total * 100)}%</b></span>`).join('')}
    </div></div>`;
}

/* ─────────────── KPI deltas from real snapshots ─────────────── */
function snapshotSeries(pick) {
  // Oldest first, so a sparkline reads left to right like every other chart.
  return [...S.snapshots].reverse().map(pick).filter(v => v !== null && v !== undefined);
}
function kpi(label, value, series, colour, { invert = false, note = '' } = {}) {
  let delta = '', against = '';
  if (series.length >= 2) {
    const a = series[series.length - 2], b = series[series.length - 1];
    if (a !== b) {
      const pct = a === 0 ? null : Math.round(((b - a) / Math.abs(a)) * 100);
      const rising = b > a;
      // "Good" depends on the metric: more sessions is fine, more criticals is not.
      const good = invert ? !rising : rising;
      delta = `<span class="delta ${good ? 'up' : 'down'}">
        <svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor"
          stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round">
          <path d="${rising ? 'M6 15l6-6 6 6' : 'M6 9l6 6 6-6'}"/></svg>${
        pct === null || Math.abs(pct) > 999 ? (rising ? '+' : '−') + Math.abs(b - a) : Math.abs(pct) + '%'}</span>`;
      // Say what the comparison is against. Two snapshots are only posture drift
      // when they are the same estate; across unrelated captures the percentage is
      // arithmetically true and completely misleading, so it must be labelled.
      const prev = S.snapshots[1];
      against = `vs previous capture (${a})${prev ? ' · ' + (prev.captured_at || '').slice(11, 16) : ''}`;
    }
  }
  const foot = `<div class="note">${esc(against || note ||
    (S.snapshots.length < 2 ? 'no prior capture to compare' : 'unchanged since the previous capture'))}</div>`;
  return `<div class="kpi">
    <div class="k">${esc(label)}</div>
    <div class="row"><div class="v">${value}</div>${delta}</div>
    <div class="spark">${spark(series, colour)}</div>${foot}</div>`;
}

/* ─────────────── data ─────────────── */
async function refresh(quiet) {
  const [jobs, dispositions, snapshots, audit] = await Promise.all([
    api('/api/jobs').catch(() => []),
    api('/api/dispositions').catch(() => ({})),
    api('/api/snapshots').catch(() => []),
    api('/api/audit?limit=80').catch(() => []),
  ]);
  S.jobs = jobs || []; S.dispositions = dispositions || {};
  S.snapshots = snapshots || []; S.audit = audit || [];

  const done = S.jobs.find(j => j.state === 'completed');
  if (done && (!S.report || S.report._job !== done.job_id)) {
    const r = await api(`/api/reports/${done.job_id}`).catch(() => null);
    if (r) { r._job = done.job_id; S.report = r; }
  }
  paintChrome();
  if (!quiet) render();
}

function severityCounts(list = findings()) {
  const c = Object.fromEntries(SEV.map(s => [s, 0]));
  list.forEach(f => c[f.severity]++);
  return c;
}
function certCount() {
  return sessions().reduce((n, s) => n + (s.certificates?.length || 0), 0);
}
function misconfigCount() {
  return findings().filter(f => MISCONFIG.has(f.category)).length;
}
function openFindings() {
  return findings().filter(f => {
    const d = S.dispositions[KEY(f)];
    return !d || ['new', 'acknowledged', 'in_progress'].includes(d.state);
  });
}
/* Findings grouped by the host they affect, worst first. */
function byHost() {
  const m = new Map();
  findings().forEach(f => {
    const h = f.affected_host || 'unknown';
    if (!m.has(h)) m.set(h, { host: h, total: 0, critical: 0, worst: 'info', ports: new Set() });
    const e = m.get(h);
    e.total++; if (f.severity === 'critical') e.critical++;
    if (SEV.indexOf(f.severity) < SEV.indexOf(e.worst)) e.worst = f.severity;
    if (f.affected_port) e.ports.add(f.affected_port);
  });
  return [...m.values()].sort((a, b) => b.total - a.total);
}

function paintChrome() {
  const c = severityCounts();
  const set = (sel, v, hot) => {
    const el = $(sel); if (!el) return;
    el.textContent = v || ''; el.style.display = v ? '' : 'none';
    el.className = 'badge' + (hot ? ' hot' : '');
  };
  set('#b-sessions', sessions().length);
  set('#b-findings', openFindings().length, c.critical > 0);
  set('#b-captures', S.jobs.filter(j => j.state === 'completed').length);
  set('#b-certs', certCount());
  set('#b-hosts', byHost().length);
  set('#b-plan', S.report?.narrative?.action_plan?.length || 0);

  const running = S.jobs.some(j => ['queued', 'validating', 'running'].includes(j.state));
  $('#sysstate').textContent = running ? 'Analysing…' : 'System Ready';
  const pip = $('#pip');
  if (pip) pip.hidden = c.critical === 0;
}

/* ─────────────── views ─────────────── */
const V = {};

V.overview = () => {
  const r = S.report;
  if (!r) return blank('No capture analysed yet',
    'Submit a PCAP or run a bundled capture to populate the console.');
  const c = severityCounts();
  const ss = sessions();
  const hosts = byHost();

  // Stacked severity by session — real, dense, and the only time-like axis a
  // single capture has.
  const bands = ['critical', 'high', 'medium', 'low'].map(sev => ({
    color: COLOR[sev],
    values: ss.map(s => (s.findings || []).filter(f => f.severity === sev).length),
  }));
  const labels = ss.map(s => s.session_id.replace(/^s0*/, 's'));

  const protos = {};
  ss.forEach(s => { protos[s.protocol] = (protos[s.protocol] || 0) + 1; });
  // Neutral ramp, not the severity ramp: colour means severity everywhere else in
  // this console, and reusing it here would imply IMAP is more dangerous than POP3.
  const pramp = ['#dc2626', '#7f1d1d', '#57575f', '#8a8a94', '#3a3a44'];
  const protoItems = Object.entries(protos)
    .sort((a, b) => b[1] - a[1])
    .map(([k, v], i) => ({ label: k.toUpperCase(), value: v, color: pramp[i % pramp.length] }));

  return `
  <div class="kpis">
    ${kpi('Total Sessions', num(ss.length), snapshotSeries(s => s.session_count), COLOR.ok)}
    ${kpi('Critical Findings', num(c.critical),
          snapshotSeries(s => s.finding_counts?.critical ?? 0), COLOR.critical, { invert: true })}
    ${kpi('Unique Hosts', num(r.fleet?.host_count ?? hosts.length),
          snapshotSeries(s => s.host_count), COLOR.ok)}
    ${kpi('Misconfigurations', num(misconfigCount()), [], COLOR.high,
          { invert: true, note: 'config faults, excluding attack evidence' })}
    ${kpi('Certificates Analysed', num(certCount()), [], COLOR.ok,
          { note: `${ss.filter(s => s.chain?.status === 'opaque_tls13').length} encrypted by TLS 1.3` })}
  </div>

  <div class="grid g-3-2" style="margin-bottom:14px">
    <div class="panel">
      ${head('Risk Profile', 'activity',
             `<span class="faint">findings per session, stacked by severity</span>`)}
      ${stackedArea(bands, labels)}
      <div class="legend" style="margin-top:10px">
        ${['critical', 'high', 'medium', 'low'].map(s =>
          `<span><i style="background:${COLOR[s]}"></i>${s}<b>${c[s]}</b></span>`).join('')}
      </div>
    </div>
    <div class="panel">
      ${head('Protocol Distribution', 'pie')}
      ${donut(protoItems, 'Sessions')}
      <div class="section-title">Transport</div>
      <div class="legend">
        <span><i style="background:${COLOR.ok}"></i>Encrypted
          <b>${ss.filter(s => s.tls_mode !== 'cleartext').length}</b></span>
        <span><i style="background:${COLOR.critical}"></i>Cleartext
          <b>${ss.filter(s => s.tls_mode === 'cleartext').length}</b></span>
      </div>
    </div>
  </div>

  <div class="grid g-3-2">
    <div class="panel flush">
      ${head('Recent Findings', 'alert',
             `<a class="more" href="#findings">View all ${icon('arrow', '')}</a>`)}
      <table><thead><tr>
        <th>Severity</th><th>Finding</th><th>Protocol</th><th>Host</th><th>Disposition</th>
      </tr></thead><tbody>
      ${findings().slice(0, 6).map(f => {
        const sess = sessionFor(f);
        const d = S.dispositions[KEY(f)] || { state: 'new' };
        return `<tr class="clickable" onclick="goFinding('${esc(KEY(f))}')">
          <td><span class="sev sev-${f.severity}">${f.severity}</span></td>
          <td>${esc(f.title)}</td>
          <td class="mono dim">${esc((sess?.protocol || '').toUpperCase() || '—')}</td>
          <td class="mono dim nowrap">${esc(f.affected_host || '')}</td>
          <td><span class="disp disp-${d.state}">${d.state.replace('_', ' ')}</span></td>
        </tr>`; }).join('') || '<tr><td colspan="5" class="empty">No findings.</td></tr>'}
      </tbody></table>
    </div>

    <div class="panel flush">
      ${head('Top Affected Hosts', 'server')}
      <table><thead><tr><th>Host</th><th class="right">Findings</th></tr></thead><tbody>
      ${hosts.slice(0, 6).map(h => `<tr class="clickable" onclick="location.hash='#infrastructure'">
        <td class="mono nowrap">${esc(h.host)}
          <div class="faint" style="font-size:10.5px">ports ${[...h.ports].sort((a,b)=>a-b).join(', ')}</div></td>
        <td><div class="hostbar">
          <div class="bar"><i style="width:${(h.total / hosts[0].total * 100).toFixed(0)}%;
            background:${COLOR[h.worst]}"></i></div>
          <span class="mono" style="width:20px;text-align:right">${h.total}</span></div></td>
      </tr>`).join('') || '<tr><td colspan="2" class="empty">No hosts.</td></tr>'}
      </tbody></table>
    </div>
  </div>`;
};

V.captures = () => `
  <div class="grid g2" style="margin-bottom:14px">
    <div class="panel">
      ${head('Upload', 'upload')}
      <div class="drop" id="drop">
        ${icon('upload', '')}
        <b>Drag and drop a PCAP file here</b>
        <span><em>or click to browse</em> · supports .pcap, .pcapng · max 200 MB</span>
      </div>
      <p class="note" style="margin:13px 0 0">Nothing is decrypted. The file is parsed for
      handshake metadata and protocol state only.</p>
      <input type="file" id="file" accept=".pcap,.pcapng" hidden>
    </div>
    <div class="panel">
      ${head('Bundled Captures', 'archive', '<span class="faint">demo safety net</span>')}
      <div style="display:flex;gap:9px">
        <select class="sel" id="samples" style="flex:1"><option>loading…</option></select>
        <button class="btn accent" id="runSample">Analyse</button>
      </div>
      <p class="note" style="margin:14px 0 0">A live upload that fails in front of an audience is
      only recoverable if a known-good capture is one click away.</p>
    </div>
  </div>
  <div class="panel flush">
    ${head('Recent Captures', 'list')}
    <table><thead><tr>
      <th>Name</th><th>Size</th><th>Uploaded</th><th>Sessions</th><th>Findings</th>
      <th>Grade</th><th>Status</th><th></th></tr></thead>
    <tbody>${S.jobs.map(jobRow).join('') ||
      '<tr><td colspan="8" class="empty">No captures yet.</td></tr>'}</tbody></table>
  </div>`;

function jobRow(j) {
  const pct = Math.round((j.progress || 0) * 100);
  const running = !['completed', 'rejected', 'failed'].includes(j.state);
  return `<tr>
    <td><b style="font-weight:500">${esc(j.filename)}</b>
      <div class="mono faint" style="font-size:10.5px">${esc(j.job_id.slice(0, 8))}</div></td>
    <td class="mono dim">${j.size_bytes ? (j.size_bytes / 1024).toFixed(0) + ' KB' : '—'}</td>
    <td class="dim nowrap">${ago(j.created_at)}</td>
    <td class="mono">${j.state === 'completed' ? num(j.session_count) : '—'}</td>
    <td class="mono">${j.state === 'completed' ? num(j.finding_count) : '—'}</td>
    <td><b class="grade ${gradeClass(j.fleet_grade)}" style="font-size:15px">${esc(j.fleet_grade || '—')}</b></td>
    <td>${running
      ? `<div style="display:flex;align-items:center;gap:8px">
           <span class="state state-${j.state}">${j.state}</span>
           <div class="bar" style="width:54px"><i style="width:${pct}%"></i></div></div>
         <div class="mono faint" style="font-size:10px;margin-top:3px">${esc(j.current_stage || '')}</div>`
      : `<span class="state state-${j.state}">${j.state}</span>
         ${j.reject_reason || j.error
           ? `<div class="faint" style="font-size:10.5px;max-width:200px">${esc(j.reject_reason || j.error)}</div>`
           : ''}`}</td>
    <td class="right">${j.state === 'completed'
      ? `<button class="btn tiny" onclick="loadJob('${j.job_id}')">Open</button>` : ''}</td>
  </tr>`;
}

V.sessions = () => {
  const list = sessions();
  if (!list.length) return blank('No sessions', 'Analyse a capture first.');
  return `
  <div class="panel flush">
    ${head('Reconstructed Sessions', 'network', '<span class="faint">D01–D07</span>')}
    <div style="padding:12px 18px;border-bottom:1px solid var(--line);display:flex;gap:9px;flex-wrap:wrap">
      <input class="inp" id="sessQ" placeholder="Filter by host, protocol, cipher…" style="flex:1;min-width:200px">
      <div class="seg" id="sessFilter">
        <button class="on" data-f="all">All</button>
        <button data-f="cleartext">Cleartext</button>
        <button data-f="anomalous">Anomalous</button>
        <button data-f="risky">Risk &gt; 0.5</button>
      </div>
    </div>
    <div class="t-scroll"><table><thead><tr>
      <th>Session</th><th>Endpoint</th><th>Proto</th><th>Role</th><th>Mode</th>
      <th>Version</th><th>Cipher</th><th>PFS</th><th>Risk</th><th>Anomaly</th>
    </tr></thead><tbody id="sessBody">${list.map(sessionRow).join('')}</tbody></table></div>
  </div>`;
};

function sessionRow(s) {
  const a = s.assessment || {}, h = s.handshake;
  const risk = a.risk_score || 0;
  const col = risk >= .85 ? COLOR.critical : risk >= .6 ? COLOR.high
    : risk >= .35 ? COLOR.medium : risk >= .15 ? COLOR.low : COLOR.info;
  return `<tr class="clickable" data-sid="${esc(s.session_id)}"
      onclick="location.hash='#session/${esc(s.session_id)}'">
    <td class="mono faint">${esc(s.session_id)}</td>
    <td class="mono nowrap">${esc(s.server_host)}:${s.server_port}</td>
    <td class="mono dim">${esc(s.protocol)}</td>
    <td class="dim" style="font-size:11.5px">${esc(s.port_role.replace(/_/g, ' '))}</td>
    <td><span class="state ${s.tls_mode === 'cleartext' ? 'state-failed' : 'state-completed'}">${s.tls_mode}</span></td>
    <td class="mono dim">${esc(h?.negotiated_version || '—')}</td>
    <td class="mono dim" style="font-size:11px;max-width:220px;overflow:hidden;
        text-overflow:ellipsis" title="${esc(h?.cipher_suite_name || '')}">${esc(h?.cipher_suite_name || '—')}</td>
    <td>${h ? (h.has_forward_secrecy
      ? '<span class="sev sev-low">yes</span>' : '<span class="sev sev-high">no</span>')
      : '<span class="faint">—</span>'}</td>
    <td><div style="display:flex;align-items:center;gap:8px">
      <div class="bar" style="width:46px;flex:none"><i style="width:${(risk * 100).toFixed(0)}%;background:${col}"></i></div>
      <span class="mono faint" style="font-size:10.5px">${risk.toFixed(2)}</span></div></td>
    <td>${a.is_anomalous ? `<span class="sev sev-medium">${(a.anomaly_score || 0).toFixed(2)}</span>`
      : `<span class="mono faint" style="font-size:11px">${(a.anomaly_score || 0).toFixed(2)}</span>`}</td>
  </tr>`;
}

V.findings = () => {
  const list = findings();
  if (!list.length) return blank('No findings', 'Analyse a capture first.');
  return `
  <div class="panel flush">
    ${head('Findings', 'alert',
           '<span class="faint">ranked by severity × exploitability × blast radius · D18</span>')}
    <div style="padding:12px 18px;border-bottom:1px solid var(--line);display:flex;gap:9px;flex-wrap:wrap">
      <input class="inp" id="findQ" placeholder="Filter by rule, title, host…" style="flex:1;min-width:200px">
      <div class="seg" id="sevFilter">
        <button class="on" data-s="all">All</button>
        ${SEV.map(s => `<button data-s="${s}">${s}</button>`).join('')}
      </div>
      <div class="seg" id="openFilter">
        <button data-o="all" class="on">Any state</button>
        <button data-o="open">Open only</button>
      </div>
    </div>
    <div class="t-scroll"><table><thead><tr>
      <th style="width:34px">#</th><th>Severity</th><th>Finding</th><th>Host</th>
      <th>Category</th><th>Disposition</th><th style="width:220px">Action</th>
    </tr></thead><tbody id="findBody">${list.map(findingRow).join('')}</tbody></table></div>
  </div>`;
};

const NEXT = {
  new: [['acknowledged', 'Ack'], ['false_positive', 'False +']],
  acknowledged: [['in_progress', 'Start'], ['resolved', 'Resolve'], ['false_positive', 'False +'],
                 ['accepted_risk', 'Accept']],
  in_progress: [['resolved', 'Resolve'], ['false_positive', 'False +'], ['accepted_risk', 'Accept']],
  resolved: [['acknowledged', 'Reopen']],
  false_positive: [['acknowledged', 'Reopen']],
  accepted_risk: [['acknowledged', 'Reopen'], ['in_progress', 'Start']],
};

function findingRow(f, i) {
  const k = KEY(f), d = S.dispositions[k] || { state: 'new' };
  return `<tr data-k="${esc(k)}" data-sev="${f.severity}"
      data-open="${['new','acknowledged','in_progress'].includes(d.state)}">
    <td class="mono faint">${i + 1}</td>
    <td><span class="sev sev-${f.severity}">${f.severity}</span></td>
    <td class="clickable" onclick="goFinding('${esc(k)}')">${esc(f.title)}
      <div class="mono faint" style="font-size:10.5px">${esc(f.rule_id)}</div></td>
    <td class="mono dim nowrap">${esc(f.affected_host || '')}:${f.affected_port || ''}</td>
    <td class="dim" style="font-size:11.5px">${esc(f.category.replace(/_/g, ' '))}</td>
    <td><span class="disp disp-${d.state}">${d.state.replace('_', ' ')}</span></td>
    <td>${(NEXT[d.state] || []).map(([s, l]) =>
      `<button class="btn tiny" onclick="dispose('${esc(k)}','${s}')">${l}</button>`).join(' ')}</td>
  </tr>`;
}

/* ─────────────── session detail, tabbed ─────────────── */
function sessionFor(f) {
  return sessions().find(s => s.server_host === f.affected_host &&
                              s.server_port === f.affected_port)
      || sessions().find(s => (s.findings || []).some(x => KEY(x) === KEY(f)));
}

V.session = sid => {
  const s = sessions().find(x => x.session_id === sid);
  if (!s) return blank('Unknown session', 'It may belong to a different capture.');
  const focus = (s.findings || []).find(f => KEY(f) === S.focus)
             || (s.findings || [])[0] || null;
  const TABS = [['overview', 'Overview'], ['handshake', 'Handshake'],
                ['certificates', 'Certificates'], ['evidence', 'Evidence'],
                ['remediation', 'Remediation']];
  return `
  <div class="panel flush" style="margin-bottom:14px">
    <div style="padding:16px 18px;display:flex;align-items:center;gap:14px;flex-wrap:wrap">
      ${focus ? `<span class="sev sev-${focus.severity}">${focus.severity}</span>
        <b style="font-size:14.5px">${esc(focus.title)}</b>`
        : `<b style="font-size:14.5px">${esc(s.server_host)}:${s.server_port}</b>`}
      <div style="margin-left:auto;text-align:right">
        <div class="faint" style="font-size:10px;letter-spacing:.1em;text-transform:uppercase">Session ID</div>
        <div class="mono dim" style="font-size:11.5px">${esc(s.session_id)} ·
          ${esc(S.report?.capture?.sha256?.slice(0, 12) || '')}</div>
      </div>
    </div>
  </div>

  <div class="tabs" id="stabs">
    ${TABS.map(([k, l]) => `<button data-t="${k}" class="${S.tab === k ? 'on' : ''}">${l}</button>`).join('')}
  </div>

  <div id="tabbody">${sessionTab(s, focus)}</div>`;
};

function sessionTab(s, focus) {
  const h = s.handshake, a = s.assessment || {}, v = s.starttls, f = s.flow || {};

  if (S.tab === 'handshake') {
    if (!h) return `<div class="panel"><p class="note" style="margin:0">No TLS handshake was
      observed in this session. ${s.tls_mode === 'cleartext'
      ? 'The conversation stayed in cleartext from the banner to the last command.' : ''}</p></div>`;
    return `<div class="grid g2">
      <div class="panel">
        ${head('Negotiated Parameters', 'lock')}
        <dl class="kv">
          <dt>Version</dt><dd>${esc(h.negotiated_version)}</dd>
          <dt>Cipher suite</dt><dd>${esc(h.cipher_suite_name || '—')}</dd>
          <dt>Key exchange</dt><dd>${esc(h.key_exchange)}${h.key_exchange_bits ? ` (${h.key_exchange_bits} bit)` : ''}</dd>
          <dt>Forward secrecy</dt><dd>${h.has_forward_secrecy ? 'yes' : 'no'}</dd>
          <dt>Post-quantum</dt><dd>${h.pq_groups_offered?.length
            ? esc(h.pq_groups_offered.join(', ')) : 'not offered'}</dd>
          <dt>SNI</dt><dd>${esc(h.client_hello?.server_name || '—')}</dd>
          <dt>JA3</dt><dd>${esc(h.client_hello?.ja3 || '—')}</dd>
          <dt>JA3S</dt><dd>${esc(h.server_hello?.ja3s || '—')}</dd>
        </dl>
      </div>
      <div class="panel">
        ${head('Message Sequence', 'activity', '<span class="faint">D04</span>')}
        <div class="ladder">${(h.message_sequence || []).map(m => {
          const c2s = m.startsWith('->');
          return `<div class="${c2s ? 'c2s' : 's2c'}"><span class="arrow">${c2s ? 'client →' : '← server'}</span>${esc(m.slice(3))}</div>`;
        }).join('') || '<span class="faint">none observed</span>'}</div>
      </div>
    </div>`;
  }

  if (S.tab === 'certificates') {
    if (s.chain?.status === 'opaque_tls13') {
      return `<div class="panel">${head('Certificate Chain', 'lock')}
        <p class="note" style="margin:0">TLS 1.3 encrypts the Certificate message, so a passive
        observer cannot inspect the chain. <b>This is the expected behaviour of a correctly configured
        modern server</b>, not a missing certificate — which is why this panel says so rather than
        rendering empty (ADR-0014).</p></div>`;
    }
    if (!s.certificates?.length) {
      return `<div class="panel"><p class="note" style="margin:0">No certificate was presented in
        this session.</p></div>`;
    }
    return `<div class="grid g2">${s.certificates.map(c => `
      <div class="panel">
        ${head(c.chain_position === 0 ? 'Leaf Certificate' : `Chain #${c.chain_position}`, 'lock')}
        <dl class="kv">
          <dt>Subject</dt><dd>${esc(c.subject_cn || c.subject)}</dd>
          <dt>Issuer</dt><dd>${esc(c.issuer_cn || c.issuer || '—')}</dd>
          <dt>Public key</dt><dd>${esc(c.public_key_algorithm)}-${c.public_key_bits ?? '?'}</dd>
          <dt>Signature</dt><dd>${esc(c.signature_algorithm)}</dd>
          <dt>Valid from</dt><dd>${esc((c.not_before || '').slice(0, 10))}</dd>
          <dt>Valid to</dt><dd>${esc((c.not_after || '').slice(0, 10))}</dd>
          <dt>Self-signed</dt><dd>${c.is_self_signed ? 'yes' : 'no'}</dd>
          <dt>SANs</dt><dd>${esc((c.san_dns_names || []).join(', ') || '—')}</dd>
        </dl>
      </div>`).join('')}
      <div class="panel">
        ${head('Chain Validation', 'check')}
        <dl class="kv"><dt>Status</dt><dd>${esc(s.chain.status)}</dd></dl>
        ${(s.chain.issues || []).length
          ? `<ul class="dim" style="font-size:12.5px;padding-left:18px;margin:12px 0 0">
             ${s.chain.issues.map(i => `<li style="margin-bottom:4px">${esc(i)}</li>`).join('')}</ul>`
          : '<p class="note" style="margin:12px 0 0">No chain issues.</p>'}
      </div>
    </div>`;
  }

  if (S.tab === 'evidence') {
    const e = focus?.evidence;
    return `<div class="grid g2">
      <div class="panel">
        ${head('Packet Evidence', 'file', '<span class="faint">ADR-0004</span>')}
        ${e ? `<dl class="kv">
            <dt>Capture SHA-256</dt><dd>${esc(S.report?.capture?.sha256 || '—')}</dd>
            <dt>Stream</dt><dd>${e.stream_id}</dd>
            <dt>Frames</dt><dd>${(e.frame_numbers || []).join(', ') || '—'}</dd>
            <dt>Byte range</dt><dd>${(e.byte_range || []).join('–') || '—'}</dd>
            <dt>Direction</dt><dd>${esc(e.direction || '—')}</dd>
          </dl>
          <p class="note" style="margin:14px 0 0">Open the capture in Wireshark and filter on these
          frames to verify this claim independently. Every finding carries this.</p>`
        : '<p class="note" style="margin:0">No finding selected on this session.</p>'}
      </div>
      <div class="panel">
        ${head('Why This Score', 'brain', '<span class="faint">D16</span>')}
        ${shapWaterfall(a)}
        <div class="section-title">Anomaly · D17</div>
        <div style="font-size:24px;font-weight:600;color:${a.is_anomalous ? COLOR.high : COLOR.info}">
          ${(a.anomaly_score || 0).toFixed(2)}</div>
        <div class="faint" style="font-size:11.5px;margin-bottom:9px">
          ${a.is_anomalous ? 'flagged as unusual for this fleet' : 'consistent with the fleet'}</div>
        ${(a.anomaly_reasons || []).map(r =>
          `<div class="dim" style="font-size:12px;margin-bottom:3px">• ${esc(r)}</div>`).join('')}
      </div>
    </div>`;
  }

  if (S.tab === 'remediation') {
    const r = focus?.remediation;
    if (!r) return `<div class="panel"><p class="note" style="margin:0">No remediation attached —
      select a finding from this session.</p></div>`;
    const snips = ['postfix', 'dovecot', 'exchange', 'generic'].filter(k => r[k]);
    return `<div class="panel">
      ${head('Remediation', 'check',
             `<span class="faint">effort ${esc(r.effort || '—')} · change risk ${esc(r.risk_of_change || '—')}</span>`)}
      <p class="dim" style="font-size:13px;line-height:1.65;margin:0 0 6px">${esc(r.summary || '')}</p>
      ${snips.map(k => `<div class="section-title">${k}</div>
        <pre class="snippet">${esc(r[k])}</pre>`).join('')}
      ${(focus.standards || []).length ? `<div class="section-title">Standards</div>
        <div class="chips">${focus.standards.map(st => `<span class="chip-s"
          title="${esc(st.requirement || '')}">${esc(st.body)} ${esc(st.identifier)}${
          st.relation === 'context' ? ' (context)' : ''}</span>`).join('')}</div>` : ''}
    </div>`;
  }

  // overview tab
  const CHECKS = {
    v1_advertised: 'STARTTLS advertised', v2_capability_mangled: 'Capability not mangled',
    v3_client_issued: 'Client issued command', v4_server_accepted: 'Server accepted',
    v5_clienthello_followed: 'ClientHello followed', v6_handshake_completed: 'Handshake completed',
    v7_ehlo_reissued: 'EHLO re-issued after TLS', v8_auth_offered_before_tls: 'No plaintext AUTH before TLS',
    v9_credentials_before_tls: 'No credentials before TLS', v10_command_injection: 'No command injection',
  };
  const INV = new Set(['v2_capability_mangled', 'v8_auth_offered_before_tls',
    'v9_credentials_before_tls', 'v10_command_injection']);

  return `<div class="grid g2">
    <div class="panel">
      ${head('Session Information', 'network')}
      <dl class="kv">
        <dt>Protocol</dt><dd>${esc(s.protocol.toUpperCase())} (${Math.round((s.protocol_confidence || 0) * 100)}% confidence)</dd>
        <dt>Source</dt><dd>${esc(f.src_ip || s.client_host || '—')}:${f.src_port ?? '—'}</dd>
        <dt>Destination</dt><dd>${esc(f.dst_ip || s.server_host)}:${f.dst_port ?? s.server_port}</dd>
        <dt>Port role</dt><dd>${esc(s.port_role.replace(/_/g, ' '))}</dd>
        <dt>TLS mode</dt><dd>${esc(s.tls_mode)}</dd>
        <dt>Start time</dt><dd>${esc((f.started_at || '').slice(0, 19).replace('T', ' ') || '—')}</dd>
        <dt>Duration</dt><dd>${dur(f.started_at, f.ended_at)}</dd>
        <dt>TCP stream</dt><dd>#${f.stream_id ?? '—'}</dd>
        <dt>Packets</dt><dd>${f.packet_count ?? '—'}</dd>
        <dt>Bytes</dt><dd>${bytes(f)}</dd>
        <dt>Reassembly</dt><dd>${f.has_gaps ? 'gaps present' : 'complete'}${
          f.retransmission_count ? ` · ${f.retransmission_count} retransmitted` : ''}</dd>
      </dl>
    </div>

    <div class="panel">
      ${head('Finding Summary', 'alert')}
      ${focus ? `<dl class="kv">
          <dt>Severity</dt><dd><span class="sev sev-${focus.severity}">${focus.severity}</span></dd>
          <dt>Category</dt><dd>${esc(focus.category.replace(/_/g, ' '))}</dd>
          <dt>Rule</dt><dd>${esc(focus.rule_id)}</dd>
        </dl>
        <p class="dim" style="font-size:12.5px;line-height:1.65;margin:13px 0 0">${esc(focus.description)}</p>
        ${focus.severity_adjustment_reason
          ? `<div class="reason"><b>Role-aware severity.</b> ${esc(focus.severity_adjustment_reason)}</div>` : ''}
        ${(focus.related_attacks || []).length ? `<div class="chips">
          ${focus.related_attacks.map(x => `<span class="chip-s atk">${esc(x)}</span>`).join('')}</div>` : ''}
        <div class="section-title">Disposition</div>
        <div style="display:flex;gap:7px;flex-wrap:wrap">
          ${(NEXT[(S.dispositions[KEY(focus)] || { state: 'new' }).state] || []).map(([st, l]) =>
            `<button class="btn tiny" onclick="dispose('${esc(KEY(focus))}','${st}',true)">${l}</button>`).join('')}
        </div>`
        : '<p class="note" style="margin:0">No findings on this session.</p>'}
    </div>

    ${v && v.v1_advertised !== null ? `<div class="panel" style="grid-column:1/-1">
      ${head('STARTTLS Validation', 'check', '<span class="faint">ten checks · D02</span>')}
      ${v.observed_capability_line
        ? `<div class="evidence" style="margin-bottom:11px">observed: ${esc(v.observed_capability_line)}</div>` : ''}
      <div class="checks">${Object.entries(CHECKS).map(([k, label]) => {
        const raw = v[k];
        if (raw === null || raw === undefined)
          return `<div class="check na"><b>–</b><span>${label}
            <span class="faint">(not observable)</span></span></div>`;
        const good = INV.has(k) ? !raw : raw;
        return `<div class="check ${good ? 'pass' : 'fail'}"><b>${good ? '✓' : '✕'}</b>
          <span>${label}</span></div>`;
      }).join('')}</div>
      <p class="note" style="margin:13px 0 0">Check 7 is reported as <b>not observable</b> whenever the
      upgrade succeeds: the re-issued EHLO travels inside the encrypted channel, so a passive observer
      cannot see it. Marking it a pass or a fail would be a guess.</p>
    </div>` : ''}

    ${(s.findings || []).length > 1 ? `<div class="panel flush" style="grid-column:1/-1">
      ${head('All Findings on This Session', 'list')}
      <table><thead><tr><th>Severity</th><th>Finding</th><th>Category</th><th></th></tr></thead><tbody>
      ${s.findings.map(f => `<tr class="clickable" onclick="goFinding('${esc(KEY(f))}')">
        <td><span class="sev sev-${f.severity}">${f.severity}</span></td>
        <td>${esc(f.title)}<div class="mono faint" style="font-size:10.5px">${esc(f.rule_id)}</div></td>
        <td class="dim" style="font-size:11.5px">${esc(f.category.replace(/_/g, ' '))}</td>
        <td class="right">${KEY(f) === S.focus ? '<span class="chip-s">selected</span>' : ''}</td>
      </tr>`).join('')}</tbody></table>
    </div>` : ''}
  </div>`;
}

function shapWaterfall(a) {
  const c = a.shap_contributions || [];
  if (!c.length) return '<div class="faint" style="font-size:12px">No contributions recorded.</div>';
  const max = Math.max(...c.map(x => Math.abs(x.contribution)), .001);
  return `<div class="wf">${c.map(x => `
    <div><div class="b ${x.contribution >= 0 ? 'pos' : 'neg'}"
      style="width:${Math.max(2, Math.abs(x.contribution) / max * 100)}%"></div>
      <div class="lbl">${esc(x.human_readable || x.feature)}</div></div>
    <div class="val">${x.contribution >= 0 ? '+' : ''}${x.contribution.toFixed(3)}</div>`).join('')}</div>`;
}

/* ─────────────── exposure map ─────────────── */
V.exposure = () => {
  const ss = sessions();
  if (!ss.length) return blank('No topology', 'Analyse a capture first.');

  // One node per server endpoint, grouped into the three port roles. Position is
  // computed from the data, not hand-placed.
  const roles = [
    ['mta_relay', 'MTA Relay', 'port 25 · opportunistic (RFC 7435)'],
    ['submission', 'Submission', 'ports 587/465 · RFC 8314'],
    ['mail_access', 'Mail Access', 'ports 143/993/110/995 · RFC 8314'],
  ];
  const nodes = new Map();
  ss.forEach(s => {
    const k = `${s.server_host}:${s.server_port}`;
    if (!nodes.has(k)) nodes.set(k, {
      k, host: s.server_host, port: s.server_port, role: s.port_role,
      sessions: 0, worst: 'info', risk: 0, cleartext: false, clients: new Set(),
    });
    const n = nodes.get(k);
    n.sessions++;
    n.risk = Math.max(n.risk, s.assessment?.risk_score || 0);
    if (s.tls_mode === 'cleartext') n.cleartext = true;
    if (s.client_host) n.clients.add(s.client_host);
    (s.findings || []).forEach(f => {
      if (SEV.indexOf(f.severity) < SEV.indexOf(n.worst)) n.worst = f.severity;
    });
  });
  const all = [...nodes.values()];

  const W = 980, H = 430, laneW = W / 3;
  const svgNodes = roles.map(([role], ri) => {
    const inRole = all.filter(n => n.role === role);
    const cx = laneW * ri + laneW / 2;
    return inRole.map((n, i) => {
      const cols = Math.min(3, Math.max(1, Math.ceil(Math.sqrt(inRole.length))));
      const col = i % cols, row = Math.floor(i / cols);
      const x = cx + (col - (cols - 1) / 2) * 118;
      const y = 120 + row * 96;
      const r = 13 + Math.min(11, n.sessions * 2.6);
      const c = COLOR[n.worst];
      n._x = x; n._y = y;
      return `<g class="clickable" onclick="jumpHost('${esc(n.host)}')" style="cursor:pointer">
        ${n.cleartext ? `<circle cx="${x}" cy="${y}" r="${r + 9}" fill="none"
          stroke="${COLOR.critical}" stroke-opacity=".3" stroke-dasharray="3 3"/>` : ''}
        <circle cx="${x}" cy="${y}" r="${r}" fill="${c}" fill-opacity=".16" stroke="${c}" stroke-width="1.6"/>
        <text x="${x}" y="${y + 4}" text-anchor="middle" fill="${c}" font-size="11"
          font-weight="600" font-family="ui-monospace,monospace">${n.port}</text>
        <text class="node-label" x="${x}" y="${y + r + 15}" text-anchor="middle">${esc(n.host)}</text>
        <text class="node-label" x="${x}" y="${y + r + 26}" text-anchor="middle" opacity=".65"
          >${n.sessions} session${n.sessions > 1 ? 's' : ''}</text>
      </g>`;
    }).join('');
  }).join('');

  const lanes = roles.map(([, label, sub], i) => `
    ${i ? `<line x1="${laneW * i}" y1="46" x2="${laneW * i}" y2="${H - 10}"
      stroke="#232329" stroke-dasharray="4 4"/>` : ''}
    <text x="${laneW * i + laneW / 2}" y="30" text-anchor="middle" fill="#f2f2f4"
      font-size="12.5" font-weight="600">${esc(label)}</text>
    <text x="${laneW * i + laneW / 2}" y="46" text-anchor="middle" fill="#6a6a78"
      font-size="10">${esc(sub)}</text>`).join('');

  const worstFirst = [...all].sort((a, b) =>
    SEV.indexOf(a.worst) - SEV.indexOf(b.worst) || b.risk - a.risk);

  return `
  <p class="note"><b>This is the observed topology, not a geographic map.</b> Every host in this
  capture is RFC 1918 private address space — <span class="mono">10.20.1.0/24</span> has no country,
  and no GeoIP database ships with this tool. A world map with countries on it would be invented data
  in a tool whose whole claim is that every finding is verifiable against the PCAP. What is real is
  which service sits on which port, how exposed it is, and who talked to it.</p>

  <div class="mapwrap" style="margin-bottom:14px">
    <svg viewBox="0 0 ${W} ${H}">${lanes}${svgNodes}</svg>
  </div>

  <div class="grid g-3-2">
    <div class="panel flush">
      ${head('Exposure by Endpoint', 'target')}
      <table><thead><tr>
        <th>Endpoint</th><th>Role</th><th>Sessions</th><th>Transport</th><th>Worst</th><th>Peak risk</th>
      </tr></thead><tbody>
      ${worstFirst.map(n => `<tr class="clickable" onclick="jumpHost('${esc(n.host)}')">
        <td class="mono nowrap">${esc(n.host)}:${n.port}</td>
        <td class="dim" style="font-size:11.5px">${esc(n.role.replace(/_/g, ' '))}</td>
        <td class="mono">${n.sessions}</td>
        <td>${n.cleartext ? '<span class="sev sev-critical">cleartext</span>'
                          : '<span class="sev sev-low">encrypted</span>'}</td>
        <td><span class="sev sev-${n.worst}">${n.worst}</span></td>
        <td class="mono dim">${n.risk.toFixed(2)}</td>
      </tr>`).join('')}
      </tbody></table>
    </div>
    <div class="panel">
      ${head('Legend', 'list')}
      <div class="legend" style="flex-direction:column;gap:11px">
        ${SEV.slice(0, 4).map(s => `<span><i style="background:${COLOR[s]}"></i>worst finding is
          ${s}</span>`).join('')}
        <span><i style="background:transparent;border:1px dashed #dc2626"></i>dashed ring — carried
          cleartext</span>
        <span><i style="background:#2e2e36"></i>circle size — sessions observed</span>
      </div>
      <div class="section-title">Reading it</div>
      <p class="note" style="margin:0">Lanes are port roles, and the role is what sets severity.
      The same expired certificate is <b>INFO</b> in the left lane and <b>CRITICAL</b> in the right
      one, because credentials cross mail access and opportunistic relay has nowhere else to go.</p>
    </div>
  </div>`;
};

/* ─────────────── infrastructure ─────────────── */
V.infrastructure = () => {
  const hosts = byHost();
  if (!hosts.length) return blank('No hosts', 'Analyse a capture first.');
  const ss = sessions();
  const perHost = hosts.map(h => {
    const mine = ss.filter(s => s.server_host === h.host);
    const graded = mine.map(s => s.assessment?.risk_score || 0);
    return {
      ...h,
      sessions: mine.length,
      protocols: [...new Set(mine.map(s => s.protocol))],
      pfs: mine.filter(s => s.handshake?.has_forward_secrecy).length,
      encrypted: mine.filter(s => s.tls_mode !== 'cleartext').length,
      peak: graded.length ? Math.max(...graded) : 0,
      pq: mine.some(s => s.handshake?.pq_groups_offered?.length),
    };
  });
  const f = S.report?.fleet;
  return `
  <div class="kpis" style="grid-template-columns:repeat(4,1fr)">
    ${kpi('Hosts', num(hosts.length), snapshotSeries(s => s.host_count), COLOR.ok)}
    ${kpi('Post-quantum ready', num(f?.pq_ready_hosts ?? perHost.filter(h => h.pq).length), [],
          COLOR.ok, { note: 'offering a hybrid group' })}
    ${kpi('Cleartext credential paths', num(f?.cleartext_credential_sessions ?? 0), [],
          COLOR.critical, { invert: true, note: 'rotate those credentials' })}
    ${kpi('Fleet grade', `<span class="grade ${gradeClass(f?.grade)}">${esc(f?.grade || '?')}</span>`,
          snapshotSeries(s => s.fleet_score), COLOR.ok, { note: `${f?.score ?? 0} / 100` })}
  </div>

  <div class="panel flush">
    ${head('Mail Infrastructure', 'server', '<span class="faint">every host observed in the capture</span>')}
    <table><thead><tr>
      <th>Host</th><th>Ports</th><th>Protocols</th><th>Sessions</th><th>Encrypted</th>
      <th>Forward secrecy</th><th>PQ</th><th>Findings</th><th>Peak risk</th>
    </tr></thead><tbody>
    ${perHost.map(h => `<tr class="clickable" onclick="jumpHost('${esc(h.host)}')">
      <td class="mono nowrap">${esc(h.host)}</td>
      <td class="mono dim">${[...h.ports].sort((a, b) => a - b).join(', ')}</td>
      <td class="dim">${h.protocols.map(p => p.toUpperCase()).join(', ')}</td>
      <td class="mono">${h.sessions}</td>
      <td class="mono ${h.encrypted < h.sessions ? 'down' : 'dim'}">${h.encrypted}/${h.sessions}</td>
      <td class="mono dim">${h.pfs}/${h.encrypted || 0}</td>
      <td>${h.pq ? '<span class="sev sev-low">yes</span>' : '<span class="faint">—</span>'}</td>
      <td><div class="hostbar" style="justify-content:flex-start">
        <div class="bar" style="width:70px"><i style="width:${(h.total / hosts[0].total * 100).toFixed(0)}%;
          background:${COLOR[h.worst]}"></i></div>
        <span class="mono">${h.total}</span></div></td>
      <td class="mono dim">${h.peak.toFixed(2)}</td>
    </tr>`).join('')}
    </tbody></table>
  </div>`;
};

/* ─────────────── certificates ─────────────── */
V.certificates = () => {
  const rows = [];
  sessions().forEach(s => {
    (s.certificates || []).forEach(c => rows.push({ s, c }));
    if (!s.certificates?.length && s.chain?.status === 'opaque_tls13') rows.push({ s, c: null });
  });
  if (!rows.length) return blank('No certificates observed', 'Analyse a capture first.');
  const leaves = rows.filter(r => r.c && r.c.chain_position === 0).map(r => r.c);
  const weakKey = leaves.filter(c => c.public_key_algorithm === 'rsa' && c.public_key_bits < 2048).length;
  const weakSig = leaves.filter(c => /sha1|md5/i.test(c.signature_algorithm || '')).length;
  const selfSigned = leaves.filter(c => c.is_self_signed).length;

  return `
  <div class="kpis" style="grid-template-columns:repeat(4,1fr)">
    ${kpi('Certificates observed', num(leaves.length), [], COLOR.ok,
          { note: `${rows.filter(r => !r.c).length} encrypted by TLS 1.3` })}
    ${kpi('Weak keys', num(weakKey), [], COLOR.critical, { invert: true, note: 'RSA under 2048 bit' })}
    ${kpi('Weak signatures', num(weakSig), [], COLOR.high, { invert: true, note: 'SHA-1 or MD5' })}
    ${kpi('Self-signed', num(selfSigned), [], COLOR.medium, { invert: true, note: 'no public trust path' })}
  </div>

  <div class="panel flush">
    ${head('Certificate Inventory', 'lock', '<span class="faint">D08–D12</span>')}
    <table><thead><tr>
      <th>Subject</th><th>Host</th><th>Issuer</th><th>Key</th><th>Signature</th>
      <th>Expires</th><th>Chain</th></tr></thead><tbody>
    ${rows.map(({ s, c }) => {
      if (!c) return `<tr class="clickable" onclick="location.hash='#session/${esc(s.session_id)}'">
        <td colspan="7" class="dim"><b class="mono">${esc(s.server_host)}:${s.server_port}</b> —
        certificate encrypted by TLS 1.3. <span class="faint">Not observable passively. This is the
        expected behaviour of a correctly configured modern server, not a missing certificate.</span></td></tr>`;
      const ref = s.flow?.started_at ? new Date(s.flow.started_at) : new Date();
      const days = c.not_after ? Math.round((new Date(c.not_after) - ref) / 864e5) : null;
      const wk = c.public_key_algorithm === 'rsa' && c.public_key_bits && c.public_key_bits < 2048;
      const wsig = /sha1|md5/i.test(c.signature_algorithm || '');
      return `<tr class="clickable" onclick="location.hash='#session/${esc(s.session_id)}'">
        <td>${esc(c.subject_cn || c.subject)}${c.is_self_signed
          ? ' <span class="sev sev-medium">self-signed</span>' : ''}</td>
        <td class="mono dim nowrap">${esc(s.server_host)}:${s.server_port}</td>
        <td class="dim" style="font-size:11.5px">${esc(c.issuer_cn || '—')}</td>
        <td class="mono" style="${wk ? 'color:var(--high)' : 'color:var(--dim)'}">
          ${esc(c.public_key_algorithm)}-${c.public_key_bits ?? '?'}</td>
        <td class="mono" style="font-size:11px;${wsig ? 'color:var(--high)' : 'color:var(--dim)'}">
          ${esc(c.signature_algorithm)}</td>
        <td>${days === null ? '—' : days < 0
          ? `<span class="sev sev-critical">expired ${-days}d</span>`
          : days < 30 ? `<span class="sev sev-medium">${days}d</span>`
          : `<span class="mono dim">${days}d</span>`}</td>
        <td><span class="sev ${s.chain?.status === 'valid' ? 'sev-low' : 'sev-high'}">${esc(s.chain?.status || '—')}</span></td>
      </tr>`;
    }).join('')}
    </tbody></table>
  </div>`;
};

/* ─────────────── compliance ─────────────── */
V.compliance = () => {
  const comp = S.report?.fleet?.compliance || {};
  const keys = Object.keys(comp);
  if (!keys.length) return blank('No compliance data', 'Analyse a capture first.');
  const failed = keys.filter(k => comp[k] === 'fail');
  const byStandard = {};
  findings().forEach(f => (f.standards || []).filter(s => s.relation === 'violates').forEach(s => {
    const k = `${s.body} ${s.identifier}`;
    (byStandard[k] = byStandard[k] || []).push(f);
  }));
  return `
  <div class="kpis" style="grid-template-columns:repeat(3,1fr)">
    ${kpi('Standards tracked', keys.length, [], COLOR.ok)}
    ${kpi('Failed', failed.length, [], COLOR.critical,
          { invert: true, note: failed.length ? 'action required' : 'clean' })}
    ${kpi('Passed', keys.length - failed.length, [], COLOR.ok)}
  </div>
  <p class="note">A standard is marked <b>FAIL</b> only where a finding cites it as <i>breached</i>.
  Documents quoted to explain our reasoning — RFC 7435 for the opportunistic-relay downgrade, for
  instance — are recorded as context and never counted as failures. Getting this wrong once put four
  standards in the failed column that we were actually complying with.</p>
  <div class="grid g2">
    ${keys.sort((a, b) => (comp[a] === comp[b] ? a.localeCompare(b) : comp[a] === 'fail' ? -1 : 1))
      .map(k => {
        const fail = comp[k] === 'fail', fs = byStandard[k] || [];
        return `<div class="panel" style="border-left:3px solid ${fail ? COLOR.critical : COLOR.ok}">
          <div style="display:flex;align-items:center;gap:10px">
            <b style="font-size:13.5px">${esc(k)}</b>
            <span class="sev ${fail ? 'sev-critical' : 'sev-low'}" style="margin-left:auto">
              ${fail ? 'FAIL' : 'PASS'}</span>
          </div>
          ${fs.length ? `<div class="faint" style="font-size:11.5px;margin-top:9px">
            ${fs.length} finding${fs.length > 1 ? 's' : ''}:
            ${esc([...new Set(fs.map(f => f.rule_id))].slice(0, 3).join(', '))}</div>`
          : '<div class="faint" style="font-size:11.5px;margin-top:9px">No breach observed.</div>'}
        </div>`;
      }).join('')}
  </div>`;
};

/* ─────────────── audit ─────────────── */
V.audit = () => `
  <p class="note">Append-only. Never updated, never deleted. Serves the forensics persona and the
  CERT-In Directions 2022 six-hour incident-reporting requirement: it records exactly when a finding
  was seen and who acted on it. The actor is a signed-in username, not a header the caller chose
  (ADR-0024).</p>
  <div class="panel flush">
    ${head('Event Log', 'file')}
    <div class="t-scroll"><table><thead><tr>
      <th style="width:150px">Timestamp</th><th>Actor</th><th>Action</th><th>Object</th><th>Detail</th>
    </tr></thead><tbody>
    ${S.audit.map(e => `<tr>
      <td class="mono faint nowrap">${esc((e.timestamp || '').slice(0, 19).replace('T', ' '))}</td>
      <td class="mono">${esc(e.actor)}</td>
      <td><span class="mono" style="color:var(--accent-3);font-size:11.5px">${esc(e.action)}</span></td>
      <td class="mono dim" style="font-size:11px;max-width:230px;overflow:hidden;
          text-overflow:ellipsis">${esc(e.object_id)}</td>
      <td class="dim" style="font-size:11.5px">${esc((e.detail || '').slice(0, 90))}
        ${e.before ? `<span class="faint">${esc(e.before)} → ${esc(e.after)}</span>` : ''}</td>
    </tr>`).join('') || '<tr><td colspan="5" class="empty">No events yet.</td></tr>'}
    </tbody></table></div>
  </div>`;

/* ─────────────── reports ─────────────── */
/* ─────────────── remediation plan (O02) ─────────────── */
V.plan = () => {
  const n = S.report?.narrative;
  if (!n) return blank('No plan yet', 'Analyse a capture first.');
  const src = n.generated_by === 'template'
    ? 'Written deterministically from the rule engine — no model, no network.'
    : `Written by ${esc(n.generated_by)}, verified against the fact sheet.`;

  return `
  <div class="panel" style="margin-bottom:14px">
    ${head('Executive Summary', 'file',
           `<span class="faint">${esc(n.generated_by)}</span>`)}
    <p style="font-size:14px;line-height:1.75;margin:0">${md(n.executive_summary)}</p>
    <div class="section-title">Provenance</div>
    <dl class="kv">
      <dt>Generated by</dt><dd>${esc(n.generated_by)}</dd>
      <dt>Verification</dt><dd>${esc(n.verification)}</dd>
      <dt>Fact sheet</dt><dd>${esc((n.grounding_sha256 || '').slice(0, 32))}</dd>
    </dl>
    <p class="note" style="margin:12px 0 0">${esc(src)} The narrative layer is handed
    the finished report and can only write about it — it cannot add, remove or re-score
    a finding, and any generated sentence naming a host, rule or standard that is not in
    the fact sheet is discarded rather than shown.</p>
  </div>

  <div class="panel flush" style="margin-bottom:14px">
    ${head(`Action Plan — ${n.action_plan.length} actions`, 'check',
           `<span class="faint">from ${findings().length} findings</span>`)}
    <table><thead><tr>
      <th style="width:34px">#</th><th>Severity</th><th>Action</th>
      <th>Affects</th><th>Effort</th><th>Closes</th>
    </tr></thead><tbody>
    ${n.action_plan.map(a => `<tr class="clickable" onclick="toggleAction(${a.order})">
      <td class="mono faint">${a.order}</td>
      <td><span class="sev sev-${a.severity}">${a.severity}</span></td>
      <td>${esc(a.title)}
        <div class="faint" style="font-size:11px;margin-top:3px">${esc(a.rationale)}</div></td>
      <td class="mono dim" style="font-size:11px">${a.affected.length
        ? esc(a.affected.slice(0, 2).join(', ')) +
          (a.affected.length > 2 ? ` +${a.affected.length - 2}` : '') : '—'}</td>
      <td class="dim" style="font-size:11.5px">${esc(a.effort)}</td>
      <td class="mono faint" style="font-size:10.5px">${esc(a.rule_ids.join(', '))}</td>
    </tr>
    <tr id="act-${a.order}" hidden><td colspan="6" style="background:var(--sunken)">
      ${a.config ? `<div class="faint mono" style="font-size:10px;margin-bottom:6px">${esc(a.platform)}</div>
        <pre class="snippet">${esc(a.config)}</pre>` :
        '<span class="faint" style="font-size:12px">No configuration snippet — this one is an investigation.</span>'}
      <div class="faint" style="font-size:11.5px;margin-top:9px">
        risk of the change: ${esc(a.risk_of_change)}${a.standards.length
          ? ' · closes ' + esc(a.standards.join(', ')) : ''}</div>
      ${a.affected.length > 2 ? `<div class="mono faint" style="font-size:11px;margin-top:7px">
        all endpoints: ${esc(a.affected.join(', '))}</div>` : ''}
    </td></tr>`).join('')}
    </tbody></table>
  </div>

  <div class="panel">
    ${head('Scope', 'shield')}
    <p class="dim" style="font-size:13px;line-height:1.7;margin:0">${esc(n.closing_note)}</p>
  </div>`;
};

window.toggleAction = n => {
  const row = $(`#act-${n}`);
  if (row) row.hidden = !row.hidden;
};

/* The narrative uses **bold** sparingly; nothing else is interpreted. */
const md = s => esc(s).replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>');

/* ─────────────── temporal drift (USP-10) ─────────────── */
V.drift = () => {
  if (S.snapshots.length < 2) {
    return `<div class="panel" style="text-align:center;padding:56px 20px">
      <div style="font-size:16px;font-weight:600;margin-bottom:6px">Needs two captures</div>
      <div class="faint" style="font-size:13px;margin-bottom:6px">Drift is a diff. Analyse the
        same estate twice and this fills in.</div>
      <div class="faint" style="font-size:12px;margin-bottom:18px">
        ${S.snapshots.length} snapshot${S.snapshots.length === 1 ? '' : 's'} archived so far.</div>
      <button class="btn accent" onclick="location.hash='#captures'">Go to captures</button></div>`;
  }
  if (!S.drift) { loadDrift(); return '<div class="panel"><div class="empty">comparing…</div></div>'; }
  const d = S.drift;

  if (!d.comparable) {
    return `<div class="panel" style="border-left:3px solid var(--medium)">
      ${head('Not the same estate', 'alert')}
      <p style="font-size:13.5px;line-height:1.7;margin:0">${esc(d.summary)}</p>
      <dl class="kv" style="margin-top:16px">
        <dt>Earlier capture</dt><dd>${esc(d.before_capture)}</dd>
        <dt>Later capture</dt><dd>${esc(d.after_capture)}</dd>
        <dt>Host overlap</dt><dd>${Math.round(d.host_overlap * 100)}%</dd>
      </dl>
      <p class="note" style="margin:14px 0 0">Two snapshots are posture drift only when they cover
      the same infrastructure. Diffing unrelated captures produces a number that is arithmetically
      correct and operationally meaningless, so this panel refuses rather than reports.</p>
      ${driftPicker()}</div>`;
  }

  const moved = d.hosts.filter(h => h.status !== 'unchanged');
  const dirClass = d.direction === 'regressed' ? 'down'
                 : d.direction === 'improved' ? 'up' : 'faint';
  const edge = d.direction === 'regressed' ? 'critical'
             : d.direction === 'improved' ? 'ok' : 'line-2';

  return `
  <div class="kpis" style="grid-template-columns:repeat(4,1fr)">
    <div class="kpi"><div class="k">Fleet grade</div>
      <div class="row"><div class="v">
        <span class="grade ${gradeClass(d.before_grade)}">${esc(d.before_grade)}</span>
        <span class="faint" style="font-size:17px"> &rarr; </span>
        <span class="grade ${gradeClass(d.after_grade)}">${esc(d.after_grade)}</span></div></div>
      <div class="note">${d.before_score.toFixed(1)} &rarr; ${d.after_score.toFixed(1)}
        (${d.after_score >= d.before_score ? '+' : ''}${(d.after_score - d.before_score).toFixed(1)})</div>
    </div>
    ${kpi('New findings', num(d.appeared.length), [], COLOR.critical,
          { invert: true, note: 'not present in the earlier capture' })}
    ${kpi('Resolved', num(d.resolved.length), [], COLOR.ok,
          { note: 'gone since the earlier capture' })}
    ${kpi('Carried forward', num(d.persisted_count), [], COLOR.medium,
          { invert: true, note: 'still open in both' })}
  </div>

  <div class="panel" style="margin-bottom:14px;border-left:3px solid var(--${edge})">
    ${head('What changed', 'activity', `<span class="${dirClass}">${esc(d.direction)}</span>`)}
    <p style="font-size:14px;line-height:1.75;margin:0">${md(d.summary)}</p>
    <dl class="kv" style="margin-top:16px">
      <dt>Earlier</dt><dd>${esc(d.before_capture)} · ${esc((d.before_sha256 || '').slice(0, 12))}</dd>
      <dt>Later</dt><dd>${esc(d.after_capture)} · ${esc((d.after_sha256 || '').slice(0, 12))}</dd>
      <dt>Host overlap</dt><dd>${Math.round(d.host_overlap * 100)}%</dd>
    </dl>
    ${driftPicker()}
  </div>

  <div class="grid g-3-2">
    <div class="panel flush">
      ${head('Hosts that moved', 'server',
             `<span class="faint">${moved.length} of ${d.hosts.length}</span>`)}
      <table><thead><tr>
        <th>Host</th><th>Status</th><th>Grade</th><th>Delta</th><th>Changed findings</th>
      </tr></thead><tbody>
      ${moved.map(h => `<tr>
        <td class="mono nowrap">${esc(h.host)}</td>
        <td><span class="sev ${h.status === 'regressed' ? 'sev-critical'
          : h.status === 'improved' ? 'sev-low'
          : h.status === 'new' ? 'sev-medium' : 'sev-info'}">${h.status}</span></td>
        <td class="mono nowrap">
          <span class="grade ${gradeClass(h.before_grade)}">${esc(h.before_grade || '—')}</span>
          <span class="faint"> &rarr; </span>
          <span class="grade ${gradeClass(h.after_grade)}">${esc(h.after_grade || '—')}</span></td>
        <td class="mono ${h.after_score >= h.before_score ? 'up' : 'down'}">
          ${(h.after_score - h.before_score) >= 0 ? '+' : ''}${(h.after_score - h.before_score).toFixed(1)}</td>
        <td style="font-size:11px">
          ${h.appeared.map(r => `<div class="down mono">+ ${esc(r)}</div>`).join('')}
          ${h.resolved.map(r => `<div class="up mono">&minus; ${esc(r)}</div>`).join('')}
        </td></tr>`).join('') || '<tr><td colspan="5" class="empty">No host changed.</td></tr>'}
      </tbody></table>
    </div>

    <div class="panel flush">
      ${head('New findings', 'alert')}
      <table><thead><tr><th>Severity</th><th>Finding</th><th>Host</th></tr></thead><tbody>
      ${d.appeared.slice(0, 12).map(f => `<tr>
        <td><span class="sev sev-${f.severity}">${f.severity}</span></td>
        <td>${esc(f.title)}<div class="mono faint" style="font-size:10.5px">${esc(f.rule_id)}</div></td>
        <td class="mono dim nowrap">${esc(f.affected_host || '')}</td>
      </tr>`).join('') || '<tr><td colspan="3" class="empty">Nothing new.</td></tr>'}
      </tbody></table>
    </div>
  </div>`;
};

/* Two selects and a button. Defaults to the two most recent snapshots, which is
   what a returning analyst wants without touching anything. */
function driftPicker() {
  const opt = (s, sel) => `<option value="${esc(s.snapshot_id)}"${sel ? ' selected' : ''}>`
    + `${esc((s.captured_at || '').slice(0, 16).replace('T', ' '))} · ${esc(s.fleet_grade)}</option>`;
  return `<div style="display:flex;gap:9px;align-items:center;flex-wrap:wrap;margin-top:16px">
    <span class="faint" style="font-size:12px">compare</span>
    <select class="sel" id="driftBefore">${S.snapshots.map((s, i) => opt(s, i === 1)).join('')}</select>
    <span class="faint" style="font-size:12px">with</span>
    <select class="sel" id="driftAfter">${S.snapshots.map((s, i) => opt(s, i === 0)).join('')}</select>
    <button class="btn" onclick="loadDrift($('#driftBefore').value, $('#driftAfter').value)">Compare</button>
  </div>`;
}

window.loadDrift = async (before, after) => {
  const qs = before && after ? `?before=${before}&after=${after}` : '';
  try {
    S.drift = await api('/api/drift' + qs);
  } catch (e) {
    S.drift = null;
    toast(e.message, 'bad');
    return;
  }
  if (location.hash === '#drift') render();
};

V.reports = () => {
  const job = S.jobs.find(j => j.state === 'completed');
  const drift = S.snapshots.length > 1
    ? S.snapshots[0].fleet_score - S.snapshots[S.snapshots.length - 1].fleet_score : null;
  return `
  <div class="grid g2" style="margin-bottom:14px">
    <div class="panel">
      ${head('Export', 'download')}
      <p class="note" style="margin:0 0 14px">All formats render from one report object, so they can
      never disagree with each other or with the console.</p>
      <div style="display:flex;gap:9px;flex-wrap:wrap">
        <button class="btn accent" ${job ? '' : 'disabled'}
          onclick="window.open('/api/reports/${job?.job_id}/html')">${icon('file', '')} Full HTML report</button>
        <button class="btn" ${job ? '' : 'disabled'}
          onclick="window.open('/api/reports/${job?.job_id}')">${icon('download', '')} Report JSON</button>
      </div>
      <div class="section-title">SIEM forwarding</div>
      <p class="note" style="margin:0 0 11px">Findings as CEF (Splunk, QRadar, Sentinel) or ECS
      (Elastic). Defaults to medium and above — forwarding everything is how a feed gets muted.</p>
      <div style="display:flex;gap:9px;align-items:center;flex-wrap:wrap">
        <select class="sel" id="siemFmt"><option value="cef">CEF</option>
          <option value="ecs">ECS / NDJSON</option></select>
        <select class="sel" id="siemMin">
          <option value="info">info and above</option><option value="low">low and above</option>
          <option value="medium" selected>medium and above</option>
          <option value="high">high and above</option><option value="critical">critical only</option>
        </select>
        <button class="btn accent" ${job ? '' : 'disabled'} onclick="exportSiem('${job?.job_id}')">Export</button>
      </div>
    </div>

    <div class="panel">
      ${head('Posture Archive', 'archive',
             drift !== null ? `<span class="${drift >= 0 ? 'up' : 'down'} mono">${drift > 0 ? '+' : ''}${drift.toFixed(1)} drift</span>` : '')}
      <p class="note" style="margin:0 0 12px">Every completed analysis archives an immutable snapshot.
      Finalising one is a sign-off and cannot be undone. Two snapshots of the same estate are a diff,
      which is how posture drift over time is measured.</p>
      <table><thead><tr><th>Captured</th><th>Grade</th><th>Score</th><th>Status</th><th></th></tr></thead><tbody>
      ${S.snapshots.map(s => `<tr>
        <td class="mono dim nowrap">${esc((s.captured_at || '').slice(0, 16).replace('T', ' '))}</td>
        <td><b class="grade ${gradeClass(s.fleet_grade)}" style="font-size:15px">${esc(s.fleet_grade)}</b></td>
        <td class="mono dim">${s.fleet_score}</td>
        <td>${s.finalised_at ? '<span class="sev sev-low">finalised</span>' : '<span class="disp">draft</span>'}</td>
        <td class="right">${s.finalised_at
          ? `<span class="faint mono" style="font-size:10.5px">by ${esc(s.finalised_by)}</span>`
          : `<button class="btn tiny" onclick="finalise('${s.snapshot_id}')">Finalise</button>`}</td>
      </tr>`).join('') || '<tr><td colspan="5" class="empty">No snapshots yet.</td></tr>'}
      </tbody></table>
    </div>
  </div>

  <div class="panel">
    ${head('Analyst Feedback Loop', 'brain')}
    <p class="note" style="margin:0 0 12px">Every finding marked a false positive becomes a labelled
    training example. Triage work feeds the model instead of evaporating — the difference between a
    one-shot score and a system that improves with use.</p>
    <div id="signal" class="empty">loading…</div>
  </div>`;
};

/* ─────────────── settings ─────────────── */
V.settings = () => {
  const job = S.jobs.find(j => j.state === 'completed');
  return `
  <div class="grid g2">
    <div class="panel">
      ${head('Session', 'shield')}
      <dl class="kv">
        <dt>Signed in as</dt><dd>${esc(S.user?.display_name || '—')}</dd>
        <dt>Username</dt><dd>${esc(S.user?.username || '—')}</dd>
        <dt>Role</dt><dd>${esc(S.user?.role || '—')}</dd>
        <dt>Can finalise</dt><dd>${S.user?.can_finalise ? 'yes' : 'no — analyst role'}</dd>
      </dl>
      <p class="note" style="margin:14px 0 0">Passwords are PBKDF2-HMAC-SHA256, 240,000 iterations,
      stdlib only. There is no reset, no MFA and no lockout: this is an MVP with seeded demo accounts,
      not an identity provider, and pretending otherwise would be worse than saying so (ADR-0024).</p>
    </div>
    <div class="panel">
      ${head('Environment', 'server')}
      <dl class="kv">
        <dt>Analysis engine</dt><dd>stdlib + dpkt</dd>
        <dt>Service</dt><dd>Flask + sqlite3 (ADR-0021)</dd>
        <dt>Risk backend</dt><dd id="backend">—</dd>
        <dt>Schema version</dt><dd>${esc(S.report?.schema_version || '—')}</dd>
        <dt>Capture SHA-256</dt><dd>${esc(S.report?.capture?.sha256 || '—')}</dd>
        <dt>Report job</dt><dd>${esc(job?.job_id || '—')}</dd>
      </dl>
      <p class="note" style="margin:14px 0 0">Seven compiled dependencies are blocked by Smart App
      Control on these machines, which is why the DER parser, the certificate generator and every
      chart on this page are written from scratch.</p>
    </div>
  </div>`;
};

/* ─────────────── helpers ─────────────── */
const blank = (t, s) => `<div class="panel" style="text-align:center;padding:56px 20px">
  <div style="font-size:16px;font-weight:600;margin-bottom:6px">${esc(t)}</div>
  <div class="faint" style="font-size:13px;margin-bottom:18px">${esc(s)}</div>
  <button class="btn accent" onclick="location.hash='#captures'">Go to captures</button></div>`;

/* ─────────────── actions ─────────────── */
window.goFinding = key => {
  const f = findings().find(x => KEY(x) === key);
  if (!f) return;
  const s = sessionFor(f);
  S.focus = key;
  if (s) { S.tab = 'overview'; location.hash = `#session/${s.session_id}`; }
  else toast('No session carries that finding', 'bad');
};

window.jumpHost = host => {
  const s = sessions().find(x => x.server_host === host);
  if (s) { S.focus = null; S.tab = 'overview'; location.hash = `#session/${s.session_id}`; }
};

window.dispose = async (key, state, stay) => {
  const body = { state, job_id: S.report?._job || '' };
  if (state === 'accepted_risk') {
    const j = prompt('Accepting risk requires a justification — an unexplained acceptance is\n'
                   + 'indistinguishable from an unread alert:');
    if (!j) return;
    body.justification = j;
  }
  try {
    await api(`/api/findings/${encodeURIComponent(key)}/disposition`,
      { method: 'POST', body: JSON.stringify(body) });
    toast(`${key.split('@')[0]} → ${state.replace('_', ' ')}`, 'good');
    await refresh();
  } catch (e) { toast(e.message, 'bad'); }
};

window.finalise = async id => {
  if (!confirm('Finalising a posture snapshot is a sign-off and cannot be undone. Continue?')) return;
  try {
    await api(`/api/snapshots/${id}/finalise`, { method: 'POST' });
    toast('Posture finalised — the snapshot is now immutable', 'good');
    await refresh();
  } catch (e) { toast(e.message, 'bad'); }
};

window.loadJob = async id => {
  const r = await api(`/api/reports/${id}`);
  r._job = id; S.report = r; location.hash = '#overview'; toast('Report loaded');
};

window.exportSiem = id => {
  window.open(`/api/reports/${id}/siem?fmt=${$('#siemFmt').value}&min=${$('#siemMin').value}`, '_blank');
};

async function upload(file) {
  const body = new FormData(); body.append('file', file);
  try {
    const res = await fetch('/api/jobs', { method: 'POST', body });
    if (!res.ok) throw new Error((await res.json()).error || 'upload failed');
    toast(`Queued ${file.name}`, 'good');
    S.report = null; await refresh();
  } catch (e) { toast(e.message, 'bad'); }
}

/* ─────────────── global search ─────────────── */
function searchAll(q) {
  q = q.trim().toLowerCase();
  if (q.length < 2) return [];
  const out = [];
  sessions().forEach(s => {
    const hay = `${s.session_id} ${s.server_host} ${s.server_port} ${s.protocol} ${s.port_role}
      ${s.handshake?.cipher_suite_name || ''} ${s.handshake?.negotiated_version || ''}`.toLowerCase();
    if (hay.includes(q)) out.push({
      grp: 'Sessions', label: `${s.server_host}:${s.server_port}`,
      meta: `${s.protocol.toUpperCase()} · ${s.session_id}`, go: `#session/${s.session_id}`,
    });
  });
  findings().forEach(f => {
    const hay = `${f.rule_id} ${f.title} ${f.affected_host} ${f.category}`.toLowerCase();
    if (hay.includes(q)) out.push({
      grp: 'Findings', label: f.title, meta: f.rule_id, key: KEY(f), sev: f.severity,
    });
  });
  sessions().forEach(s => (s.certificates || []).forEach(c => {
    if (`${c.subject_cn || ''} ${c.issuer_cn || ''}`.toLowerCase().includes(q)) out.push({
      grp: 'Certificates', label: c.subject_cn || c.subject,
      meta: `${c.public_key_algorithm}-${c.public_key_bits}`, go: `#session/${s.session_id}`,
    });
  }));
  return out.slice(0, 18);
}

function paintResults(hits) {
  const box = $('#results');
  if (!hits.length) { box.hidden = true; return; }
  let last = '';
  box.innerHTML = hits.map((h, i) => {
    const grp = h.grp !== last ? `<div class="grp">${h.grp}</div>` : '';
    last = h.grp;
    return `${grp}<div class="hit" data-i="${i}">
      ${h.sev ? `<span class="sev sev-${h.sev}">${h.sev}</span>` : ''}
      <span>${esc(h.label)}</span><span class="meta">${esc(h.meta)}</span></div>`;
  }).join('');
  box.hidden = false;
  $$('.hit', box).forEach(el => el.onclick = () => {
    const h = hits[+el.dataset.i];
    box.hidden = true; $('#q').value = '';
    if (h.key) goFinding(h.key); else location.hash = h.go;
  });
}

/* ─────────────── per-view wiring ─────────────── */
function wire(view) {
  if (view === 'captures') {
    const drop = $('#drop'), input = $('#file');
    if (drop) {
      drop.onclick = () => input.click();
      input.onchange = e => e.target.files[0] && upload(e.target.files[0]);
      ['dragover', 'dragenter'].forEach(ev => drop.addEventListener(ev, e => {
        e.preventDefault(); drop.classList.add('over');
      }));
      ['dragleave', 'drop'].forEach(ev => drop.addEventListener(ev, e => {
        e.preventDefault(); drop.classList.remove('over');
      }));
      drop.addEventListener('drop', e => e.dataTransfer.files[0] && upload(e.dataTransfer.files[0]));
    }
    api('/api/samples').then(names => {
      const sel = $('#samples'); if (!sel) return;
      sel.innerHTML = names.length ? names.map(n => `<option>${esc(n)}</option>`).join('')
        : '<option value="">none — run testbed/synth.py</option>';
    });
    const go = $('#runSample');
    if (go) go.onclick = async () => {
      const n = $('#samples').value; if (!n) return;
      go.disabled = true;
      try {
        await api(`/api/samples/${encodeURIComponent(n)}/analyse`, { method: 'POST' });
        toast(`Queued ${n}`, 'good'); S.report = null; await refresh();
      } catch (e) { toast(e.message, 'bad'); }
      go.disabled = false;
    };
  }

  if (view === 'findings') {
    const apply = () => {
      const q = ($('#findQ').value || '').toLowerCase();
      const sev = $('#sevFilter .on').dataset.s;
      const openOnly = $('#openFilter .on').dataset.o === 'open';
      $$('#findBody tr').forEach(tr => {
        const ok = (sev === 'all' || tr.dataset.sev === sev)
          && (!openOnly || tr.dataset.open === 'true')
          && (!q || tr.textContent.toLowerCase().includes(q));
        tr.style.display = ok ? '' : 'none';
      });
    };
    $('#findQ').oninput = apply;
    $$('#sevFilter button, #openFilter button').forEach(b => b.onclick = () => {
      [...b.parentElement.children].forEach(x => x.classList.remove('on'));
      b.classList.add('on'); apply();
    });
  }

  if (view === 'sessions') {
    const apply = () => {
      const q = ($('#sessQ').value || '').toLowerCase();
      const f = $('#sessFilter .on').dataset.f;
      $$('#sessBody tr').forEach(tr => {
        const s = sessions().find(x => x.session_id === tr.dataset.sid) || {};
        const a = s.assessment || {};
        const okF = f === 'all' || (f === 'cleartext' && s.tls_mode === 'cleartext')
          || (f === 'anomalous' && a.is_anomalous) || (f === 'risky' && (a.risk_score || 0) > .5);
        tr.style.display = okF && (!q || tr.textContent.toLowerCase().includes(q)) ? '' : 'none';
      });
    };
    $('#sessQ').oninput = apply;
    $$('#sessFilter button').forEach(b => b.onclick = () => {
      $$('#sessFilter button').forEach(x => x.classList.remove('on'));
      b.classList.add('on'); apply();
    });
  }

  if (view === 'session') {
    $$('#stabs button').forEach(b => b.onclick = () => {
      S.tab = b.dataset.t;
      $$('#stabs button').forEach(x => x.classList.toggle('on', x === b));
      const sid = location.hash.split('/')[1];
      const s = sessions().find(x => x.session_id === sid);
      const focus = (s?.findings || []).find(f => KEY(f) === S.focus) || (s?.findings || [])[0] || null;
      $('#tabbody').innerHTML = sessionTab(s, focus);
    });
  }

  if (view === 'reports') {
    api('/api/training-signal').then(sig => {
      const el = $('#signal'); if (!el) return;
      el.className = sig.length ? '' : 'empty';
      el.innerHTML = sig.length
        ? sig.map(([k, s]) => `<div style="padding:6px 0;border-bottom:1px solid var(--line);
            display:flex;gap:10px;align-items:center">
            <span class="disp disp-${s}">${s.replace('_', ' ')}</span>
            <span class="mono dim" style="font-size:11.5px">${esc(k)}</span></div>`).join('')
        : 'No labelled examples yet — mark a finding resolved or a false positive.';
    });
  }

  if (view === 'settings') {
    const el = $('#backend');
    if (el) {
      const v = sessions()[0]?.assessment?.model_version || '';
      el.textContent = v.startsWith('gradient') ? 'gradient boosting (trained)'
        : v ? 'rule-derived baseline' : '—';
    }
  }
}

/* ─────────────── router ─────────────── */
const TITLES = {
  overview: ['Security Overview', 'Cryptographic posture across your captured email traffic'],
  captures: ['Captures', 'Upload and analyse network captures (PCAP)'],
  sessions: ['Sessions', 'Every reconstructed SMTP, IMAP and POP3 conversation'],
  findings: ['Findings', 'Prioritised weaknesses with analyst dispositions'],
  plan: ['Remediation Plan', 'What to actually do, in the order to do it'],
  drift: ['Posture Drift', 'What changed between two captures of the same estate'],
  session: ['Session Details', 'Full analysis of the selected session'],
  exposure: ['Exposure Map', 'Observed topology of the mail estate'],
  certificates: ['Certificates', 'X.509 chains observed on the wire'],
  infrastructure: ['Infrastructure', 'Every mail host seen in the capture'],
  compliance: ['Compliance', 'Standards breached, and the findings that breach them'],
  audit: ['Audit Log', 'Append-only record of every action'],
  reports: ['Reports', 'Export, SIEM forwarding and the posture archive'],
  settings: ['Settings', 'Session, roles and runtime environment'],
};

function render() {
  const raw = (location.hash || '#overview').slice(1);
  const [name, arg] = raw.split('/');
  const view = V[name] ? name : 'overview';
  const [title, sub] = TITLES[view];

  $$('.nav a, .rail-foot a').forEach(a =>
    a.classList.toggle('on', a.getAttribute('href') === '#' + view));

  const back = view === 'session'
    ? `<button class="btn" onclick="history.back()">← Back to Sessions</button>` : '';
  const primary = ['overview', 'captures'].includes(view)
    ? `<button class="btn accent" onclick="location.hash='#captures'">${icon('upload', '')} Upload Capture</button>`
    : '';

  $('#page').innerHTML = `
    <div class="page-head">
      <div><h1>${esc(title)}</h1><p>${esc(sub)}</p></div>
      <div class="actions">${back}
        <button class="btn" onclick="refresh()">Refresh</button>${primary}</div>
    </div>${V[view](arg)}`;
  wire(view);
  $('.rail')?.classList.remove('open');
  window.scrollTo(0, 0);
}

window.addEventListener('hashchange', render);

/* ─────────────── boot ─────────────── */
(async function boot() {
  S.user = await api('/api/me').catch(() => null);
  if (S.user) {
    $('#who-name').textContent = S.user.display_name;
    $('#avatar').textContent = S.user.initials;
  }
  $('#burger').onclick = () => $('.rail').classList.toggle('open');
  $('#bell').onclick = () => { location.hash = '#findings'; };

  const q = $('#q');
  q.oninput = () => paintResults(searchAll(q.value));
  q.onblur = () => setTimeout(() => ($('#results').hidden = true), 160);
  q.onfocus = () => q.value && paintResults(searchAll(q.value));
  document.addEventListener('keydown', e => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); q.focus(); q.select(); }
    if (e.key === 'Escape') { $('#results').hidden = true; q.blur(); }
  });

  await refresh();
  render();

  // Only poll while something is actually running; otherwise this is a busy loop.
  setInterval(async () => {
    if (S.jobs.some(j => !['completed', 'rejected', 'failed'].includes(j.state))) {
      await refresh(true);
      if (location.hash.startsWith('#captures') || location.hash === '' ||
          location.hash === '#overview') render();
    }
  }, 1100);
})();
