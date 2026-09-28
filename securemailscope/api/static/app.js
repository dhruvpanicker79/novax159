/* SecureMailScope console.
   Vanilla, no build step, no CDN — the same constraint as the offline report
   (ADR-0018). Charts are hand-drawn SVG rather than a charting library, which
   keeps the dependency story intact and renders identically offline. */

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"]/g, c =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const num = n => (n ?? 0).toLocaleString();
const SEV = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const COLOR = {
  critical: '#f43f5e', high: '#fb923c', medium: '#facc15',
  low: '#34d399', info: '#64748b', accent: '#22d3ee', ok: '#10b981',
};

const S = { report: null, jobs: [], dispositions: {}, snapshots: [], audit: [], user: null };

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
  t._h = setTimeout(() => (t.className = ''), 4000);
}

const KEY = f => `${f.rule_id}@${f.affected_host || 'unknown'}:${f.affected_port || 0}`;
const gradeClass = g => 'grade-' + String(g || '?').replace('+', 'plus').replace('?', 'q');

/* ─────────────── tiny SVG charts ─────────────── */
function sparkline(values, { w = 560, h = 120, color = COLOR.accent, fill = true } = {}) {
  if (!values.length) return '<div class="empty">no data</div>';
  const max = Math.max(...values, 1), min = 0;
  const dx = w / Math.max(values.length - 1, 1);
  const pts = values.map((v, i) => [i * dx, h - ((v - min) / (max - min || 1)) * (h - 14) - 7]);
  const line = pts.map((p, i) => `${i ? 'L' : 'M'}${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(' ');
  const area = `${line} L${w},${h} L0,${h} Z`;
  return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" style="width:100%;height:${h}px">
    <defs><linearGradient id="sg" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="${color}" stop-opacity=".28"/>
      <stop offset="100%" stop-color="${color}" stop-opacity="0"/></linearGradient></defs>
    ${[0.25, 0.5, 0.75].map(f => `<line x1="0" y1="${h * f}" x2="${w}" y2="${h * f}"
       stroke="#1a2230" stroke-width="1"/>`).join('')}
    ${fill ? `<path d="${area}" fill="url(#sg)"/>` : ''}
    <path d="${line}" fill="none" stroke="${color}" stroke-width="1.8"
      stroke-linejoin="round" stroke-linecap="round"/>
    ${pts.map(p => `<circle cx="${p[0].toFixed(1)}" cy="${p[1].toFixed(1)}" r="2" fill="${color}"/>`).join('')}
  </svg>`;
}

function barChart(items, { h = 150 } = {}) {
  if (!items.length) return '<div class="empty">no data</div>';
  const max = Math.max(...items.map(i => i.value), 1);
  return `<div style="display:flex;align-items:flex-end;gap:8px;height:${h}px;padding-top:6px">
    ${items.map(i => {
      const pct = (i.value / max) * 100;
      return `<div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:5px;min-width:0">
        <div class="mono faint" style="font-size:10.5px">${num(i.value)}</div>
        <div style="width:100%;background:${i.color || COLOR.accent};height:${Math.max(pct, 2)}%;
             border-radius:3px 3px 0 0;transition:height .4s;min-height:3px"></div>
        <div class="faint" style="font-size:10px;text-align:center;white-space:nowrap;
             overflow:hidden;text-overflow:ellipsis;max-width:100%">${esc(i.label)}</div>
      </div>`;
    }).join('')}
  </div>`;
}

function donut(items, { size = 168 } = {}) {
  const total = items.reduce((a, b) => a + b.value, 0);
  if (!total) return '<div class="empty">no findings</div>';
  const r = size / 2 - 16, cx = size / 2, cy = size / 2, C = 2 * Math.PI * r;
  let offset = 0;
  const rings = items.filter(i => i.value).map(i => {
    const frac = i.value / total;
    const seg = `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${i.color}"
      stroke-width="13" stroke-dasharray="${(frac * C).toFixed(2)} ${C.toFixed(2)}"
      stroke-dashoffset="${(-offset * C).toFixed(2)}"
      transform="rotate(-90 ${cx} ${cy})" stroke-linecap="butt"/>`;
    offset += frac;
    return seg;
  }).join('');
  return `<div style="display:flex;align-items:center;gap:18px;flex-wrap:wrap">
    <svg width="${size}" height="${size}" style="flex:none">
      <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="#111823" stroke-width="13"/>
      ${rings}
      <text x="${cx}" y="${cy - 2}" text-anchor="middle" fill="#e3e9f2"
        font-size="26" font-weight="650" font-family="var(--mono)">${total}</text>
      <text x="${cx}" y="${cy + 15}" text-anchor="middle" fill="#56637a" font-size="10"
        letter-spacing="1">FINDINGS</text>
    </svg>
    <div class="legend" style="flex-direction:column;gap:7px">
      ${items.filter(i => i.value).map(i =>
        `<span><i style="background:${i.color}"></i>${esc(i.label)}
          <b class="mono" style="margin-left:5px">${i.value}</b></span>`).join('')}
    </div>
  </div>`;
}

function gauge(score, grade) {
  const pct = Math.max(0, Math.min(100, score)) / 100;
  const r = 66, C = Math.PI * r; // semicircle
  const colour = score >= 85 ? COLOR.ok : score >= 75 ? COLOR.low
    : score >= 60 ? COLOR.medium : score >= 45 ? COLOR.high : COLOR.critical;
  return `<div style="text-align:center">
    <svg viewBox="0 0 160 96" style="width:100%;max-width:210px">
      <path d="M14,84 A66,66 0 0,1 146,84" fill="none" stroke="#111823" stroke-width="11" stroke-linecap="round"/>
      <path d="M14,84 A66,66 0 0,1 146,84" fill="none" stroke="${colour}" stroke-width="11"
        stroke-linecap="round" stroke-dasharray="${(pct * C).toFixed(1)} ${C.toFixed(1)}"/>
      <text x="80" y="72" text-anchor="middle" fill="${colour}" font-size="38"
        font-weight="700" font-family="var(--mono)" letter-spacing="-2">${esc(grade || '?')}</text>
    </svg>
    <div class="mono dim" style="font-size:12.5px;margin-top:-4px">${score} / 100</div>
    <div class="faint" style="font-size:10px;letter-spacing:.09em;margin-top:2px">FLEET POSTURE · D19</div>
  </div>`;
}

/* ─────────────── data ─────────────── */
async function refresh(quiet) {
  const [jobs, dispositions, snapshots, audit] = await Promise.all([
    api('/api/jobs').catch(() => []),
    api('/api/dispositions').catch(() => ({})),
    api('/api/snapshots').catch(() => []),
    api('/api/audit?limit=60').catch(() => []),
  ]);
  S.jobs = jobs || []; S.dispositions = dispositions || {};
  S.snapshots = snapshots || []; S.audit = audit || [];

  const done = S.jobs.find(j => j.state === 'completed');
  if (done && (!S.report || S.report._job !== done.job_id)) {
    const r = await api(`/api/reports/${done.job_id}`).catch(() => null);
    if (r) { r._job = done.job_id; S.report = r; }
  }
  paintRail();
  if (!quiet) render();
}

function severityCounts() {
  const c = Object.fromEntries(SEV.map(s => [s, 0]));
  (S.report?.prioritised_findings || []).forEach(f => c[f.severity]++);
  return c;
}

/* ─────────────── chrome ─────────────── */
function paintRail() {
  const c = severityCounts();
  const open = (S.report?.prioritised_findings || []).filter(f => {
    const d = S.dispositions[KEY(f)];
    return !d || ['new', 'acknowledged', 'in_progress'].includes(d.state);
  }).length;
  const set = (sel, v, hot) => {
    const el = $(sel); if (!el) return;
    el.textContent = v; el.style.display = v ? '' : 'none';
    el.className = 'badge' + (hot ? ' hot' : '');
  };
  set('#b-sessions', S.report?.sessions?.length || '');
  set('#b-findings', open || '', c.critical > 0);
  set('#b-captures', S.jobs.filter(j => j.state === 'completed').length || '');
  const certs = (S.report?.sessions || []).reduce((n, s) => n + (s.certificates?.length || 0), 0);
  set('#b-certs', certs || '');
  $('#m-sessions').textContent = S.report?.sessions?.length ?? '—';
  $('#m-findings').textContent = (S.report?.prioritised_findings?.length) ?? '—';
  $('#m-grade').textContent = S.report?.fleet?.grade ?? '—';
  paintTicker();
}

/* The topbar ticker carries live attack evidence when there is any, and the
   scope statement when there is not — never filler. */
function paintTicker() {
  const findings = S.report?.prioritised_findings || [];
  const hot = findings.filter(f => ['critical', 'high'].includes(f.severity));
  let items = hot.slice(0, 8).map(f =>
    `${f.severity.toUpperCase()} · ${f.title} · ${f.affected_host || ''}:${f.affected_port || ''}`);
  if (!items.length) {
    items = [
      'PASSIVE ANALYSIS · no traffic is decrypted, injected or modified',
      'RFC 8314 · mail access on 993/995 must use TLS — credentials cross it',
      'RFC 7435 · opportunistic relay on 25 is graded on its own terms',
      'CERT-In 2022 · cyber incidents reportable within six hours',
      findings.length ? `${findings.length} findings · none above medium` : 'Awaiting a capture',
    ];
  }
  $('.ticker').classList.toggle('calm', !hot.length);
  const html = items.map(t => `<span>${esc(t)}</span>`).join('');
  $('#ticker').innerHTML = html + html;   // doubled: the marquee loops at -50%
}

/* ─────────────── views ─────────────── */
const VIEWS = {};

VIEWS.overview = () => {
  const r = S.report, f = r?.fleet;
  if (!r) return emptyState('No capture analysed yet',
    'Submit a PCAP or run a bundled capture to populate the console.', 'captures');
  const c = severityCounts();
  const sessions = r.sessions || [];
  const pfs = sessions.filter(s => s.handshake?.has_forward_secrecy).length;
  const encrypted = sessions.filter(s => s.tls_mode !== 'cleartext').length;
  const risk = sessions.map(s => Math.round((s.assessment?.risk_score || 0) * 100));

  return `
  <div class="stats" style="margin-bottom:14px">
    ${tile('Sessions', num(sessions.length), '', `${encrypted} encrypted`)}
    ${tile('Hosts', num(f?.host_count), '', `${f?.pq_ready_hosts ?? 0} post-quantum ready`)}
    ${tile('Critical', num(c.critical), '', c.critical ? 'act first' : 'none', c.critical ? 'down' : 'up')}
    ${tile('Forward secrecy', encrypted ? Math.round(pfs / encrypted * 100) + '%' : '—', '',
           `${pfs} of ${encrypted}`)}
    ${tile('Cleartext creds', num(f?.cleartext_credential_sessions), '',
           f?.cleartext_credential_sessions ? 'rotate now' : 'none',
           f?.cleartext_credential_sessions ? 'down' : 'up')}
    ${tile('Compliance', `${Object.values(f?.compliance || {}).filter(v => v === 'fail').length}`, '',
           `of ${Object.keys(f?.compliance || {}).length} failed`)}
  </div>

  <div class="grid g-1-2" style="margin-bottom:14px">
    <div class="card">
      ${cardHead('Posture', 'shield')}
      ${gauge(f?.score ?? 0, f?.grade)}
      <p class="faint" style="font-size:12px;margin:14px 0 0;line-height:1.6">${esc(f?.summary || '')}</p>
    </div>
    <div class="card">
      ${cardHead('Risk by session', 'activity', `${sessions.length} sessions`)}
      ${sparkline(risk)}
      <div class="legend" style="margin-top:10px"><span><i style="background:${COLOR.accent}"></i>
        risk score, 0–100, left to right in capture order</span></div>
    </div>
  </div>

  <div class="grid g-2-1">
    <div class="card flush">
      ${cardHead('Priority queue', 'alert', 'D18')}
      <div class="t-scroll"><table><thead><tr>
        <th style="width:34px">#</th><th>Severity</th><th>Finding</th><th>Host</th><th>Disposition</th>
      </tr></thead><tbody>
      ${(r.prioritised_findings || []).slice(0, 12).map((x, i) => {
        const d = S.dispositions[KEY(x)] || { state: 'new' };
        return `<tr class="clickable" onclick="openFinding('${esc(KEY(x))}')">
          <td class="mono faint">${i + 1}</td>
          <td><span class="sev sev-${x.severity}">${x.severity}</span></td>
          <td>${esc(x.title)}<div class="mono faint" style="font-size:10.5px">${esc(x.rule_id)}</div></td>
          <td class="mono dim nowrap">${esc(x.affected_host || '')}:${x.affected_port || ''}</td>
          <td><span class="disp disp-${d.state}">${d.state.replace('_', ' ')}</span></td>
        </tr>`; }).join('') || '<tr><td colspan="5" class="empty">No findings.</td></tr>'}
      </tbody></table></div>
    </div>
    <div class="card">
      ${cardHead('Severity distribution', 'pie')}
      ${donut(SEV.map(s => ({ label: s, value: c[s], color: COLOR[s] })))}
    </div>
  </div>`;
};

VIEWS.captures = () => `
  <div class="grid g2" style="margin-bottom:14px">
    <div class="card">
      ${cardHead('Submit a capture', 'upload')}
      <div class="drop" id="drop">
        <b>Drop a .pcap or .pcapng</b>
        <span>or click to choose · max 200 MB · nothing is decrypted</span>
      </div>
      <input type="file" id="file" accept=".pcap,.pcapng" hidden>
    </div>
    <div class="card">
      ${cardHead('Bundled captures', 'archive', 'demo safety net')}
      <div style="display:flex;gap:8px">
        <select class="sel" id="samples" style="flex:1"><option>loading…</option></select>
        <button class="btn accent" id="runSample">Analyse</button>
      </div>
      <p class="faint" style="font-size:12px;margin:12px 0 0;line-height:1.6">
        A live upload that fails in front of an audience is only recoverable if a
        known-good capture is one click away.</p>
    </div>
  </div>
  <div class="card flush">
    ${cardHead('Analysis queue', 'list')}
    <table><thead><tr>
      <th>Job</th><th>Capture</th><th>State</th><th>Stage</th><th style="width:130px">Progress</th>
      <th>Result</th><th></th></tr></thead>
    <tbody>${S.jobs.map(jobRow).join('') ||
      '<tr><td colspan="7" class="empty">No jobs yet.</td></tr>'}</tbody></table>
  </div>`;

function jobRow(j) {
  const pct = Math.round((j.progress || 0) * 100);
  const res = j.state === 'completed'
    ? `${j.session_count} sessions · ${j.finding_count} findings ·
       <b class="grade ${gradeClass(j.fleet_grade)}">${esc(j.fleet_grade || '?')}</b>`
    : j.state === 'rejected' ? `<span class="faint">${esc(j.reject_reason || 'refused')}</span>`
    : j.state === 'failed' ? `<span class="faint">${esc(j.error || 'failed')}</span>`
    : '<span class="faint">—</span>';
  return `<tr>
    <td class="mono faint">${esc(j.job_id.slice(0, 8))}</td>
    <td>${esc(j.filename)}<div class="mono faint" style="font-size:10.5px">${(j.size_bytes / 1024).toFixed(0)} KB</div></td>
    <td><span class="state state-${j.state}">${j.state}</span></td>
    <td class="mono dim">${esc(j.current_stage || '—')}</td>
    <td><div class="bar"><i style="width:${pct}%"></i></div></td>
    <td>${res}</td>
    <td class="right">${j.state === 'completed'
      ? `<button class="btn tiny" onclick="loadJob('${j.job_id}')">Open</button>` : ''}</td>
  </tr>`;
}

VIEWS.sessions = () => {
  const list = S.report?.sessions || [];
  if (!list.length) return emptyState('No sessions', 'Analyse a capture first.', 'captures');
  return `
  <div class="card flush">
    ${cardHead('Reconstructed mail sessions', 'network', 'D01–D07')}
    <div style="padding:11px 15px;border-bottom:1px solid var(--line);display:flex;gap:8px;flex-wrap:wrap">
      <input class="search" id="sessQ" placeholder="Filter by host, protocol, cipher…">
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
  return `<tr class="clickable" data-sid="${esc(s.session_id)}" onclick="openSession('${esc(s.session_id)}')">
    <td class="mono faint">${esc(s.session_id)}</td>
    <td class="mono nowrap">${esc(s.server_host)}:${s.server_port}</td>
    <td class="mono dim">${esc(s.protocol)}</td>
    <td class="dim" style="font-size:11.5px">${esc(s.port_role.replace('_', ' '))}</td>
    <td><span class="state ${s.tls_mode === 'cleartext' ? 'state-failed' : 'state-completed'}">${s.tls_mode}</span></td>
    <td class="mono dim">${esc(h?.negotiated_version || '—')}</td>
    <td class="mono dim" style="font-size:11px;max-width:210px;overflow:hidden;text-overflow:ellipsis"
        title="${esc(h?.cipher_suite_name || '')}">${esc(h?.cipher_suite_name || '—')}</td>
    <td>${h ? (h.has_forward_secrecy
      ? '<span class="sev sev-low">yes</span>' : '<span class="sev sev-high">no</span>') : '<span class="faint">—</span>'}</td>
    <td><div style="display:flex;align-items:center;gap:7px">
      <div class="bar" style="min-width:52px"><i style="width:${(risk * 100).toFixed(0)}%;background:${col}"></i></div>
      <span class="mono faint" style="font-size:10.5px">${risk.toFixed(2)}</span></div></td>
    <td>${a.is_anomalous ? `<span class="sev sev-medium">${(a.anomaly_score || 0).toFixed(2)}</span>`
      : `<span class="mono faint" style="font-size:11px">${(a.anomaly_score || 0).toFixed(2)}</span>`}</td>
  </tr>`;
}

VIEWS.findings = () => {
  const list = S.report?.prioritised_findings || [];
  if (!list.length) return emptyState('No findings', 'Analyse a capture first.', 'captures');
  return `
  <div class="card flush">
    ${cardHead('Triage queue', 'alert', 'D18 · severity × exploitability × blast radius')}
    <div style="padding:11px 15px;border-bottom:1px solid var(--line);display:flex;gap:8px;flex-wrap:wrap">
      <input class="search" id="findQ" placeholder="Filter by rule, title, host…">
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
      <th>Category</th><th>Disposition</th><th style="width:230px">Action</th>
    </tr></thead><tbody id="findBody">${list.map((f, i) => findingRow(f, i)).join('')}</tbody></table></div>
  </div>`;
};

const NEXT = {
  new: [['acknowledged', 'Ack'], ['false_positive', 'False +']],
  acknowledged: [['in_progress', 'Start'], ['resolved', 'Resolve'], ['false_positive', 'False +'], ['accepted_risk', 'Accept']],
  in_progress: [['resolved', 'Resolve'], ['false_positive', 'False +'], ['accepted_risk', 'Accept']],
  resolved: [['acknowledged', 'Reopen']],
  false_positive: [['acknowledged', 'Reopen']],
  accepted_risk: [['acknowledged', 'Reopen'], ['in_progress', 'Start']],
};

function findingRow(f, i) {
  const k = KEY(f), d = S.dispositions[k] || { state: 'new' };
  return `<tr data-k="${esc(k)}" data-sev="${f.severity}" data-open="${['new','acknowledged','in_progress'].includes(d.state)}">
    <td class="mono faint">${i + 1}</td>
    <td><span class="sev sev-${f.severity}">${f.severity}</span></td>
    <td class="clickable" onclick="openFinding('${esc(k)}')">${esc(f.title)}
      <div class="mono faint" style="font-size:10.5px">${esc(f.rule_id)}</div></td>
    <td class="mono dim nowrap">${esc(f.affected_host || '')}:${f.affected_port || ''}</td>
    <td class="dim" style="font-size:11.5px">${esc(f.category.replace(/_/g, ' '))}</td>
    <td><span class="disp disp-${d.state}">${d.state.replace('_', ' ')}</span></td>
    <td>${(NEXT[d.state] || []).map(([s, l]) =>
      `<button class="btn tiny" onclick="dispose('${esc(k)}','${s}')">${l}</button>`).join(' ')}</td>
  </tr>`;
}

VIEWS.certificates = () => {
  const rows = [];
  (S.report?.sessions || []).forEach(s => {
    (s.certificates || []).forEach(c => rows.push({ s, c }));
    if (!s.certificates?.length && s.chain?.status === 'opaque_tls13') rows.push({ s, c: null });
  });
  if (!rows.length) return emptyState('No certificates observed', 'Analyse a capture first.', 'captures');
  return `
  <div class="card flush">
    ${cardHead('Certificate inventory', 'lock', 'D08–D12')}
    <table><thead><tr>
      <th>Subject</th><th>Host</th><th>Issuer</th><th>Key</th><th>Signature</th>
      <th>Expires</th><th>Chain</th></tr></thead><tbody>
    ${rows.map(({ s, c }) => {
      if (!c) return `<tr><td colspan="7" style="color:var(--dim)">
        <b class="mono">${esc(s.server_host)}:${s.server_port}</b> — certificate encrypted by TLS 1.3.
        <span class="faint">Not observable passively. This is the expected behaviour of a correctly
        configured modern server, not a missing certificate.</span></td></tr>`;
      const days = c.not_after ? Math.round((new Date(c.not_after) - new Date(s.flow?.started_at || Date.now())) / 864e5) : null;
      const weakKey = c.public_key_algorithm === 'rsa' && c.public_key_bits && c.public_key_bits < 2048;
      const weakSig = /sha1|md5/i.test(c.signature_algorithm || '');
      return `<tr class="clickable" onclick="openSession('${esc(s.session_id)}')">
        <td>${esc(c.subject_cn || c.subject)}${c.is_self_signed
          ? ' <span class="sev sev-medium">self-signed</span>' : ''}</td>
        <td class="mono dim nowrap">${esc(s.server_host)}:${s.server_port}</td>
        <td class="dim" style="font-size:11.5px">${esc(c.issuer_cn || '—')}</td>
        <td class="mono ${weakKey ? '' : 'dim'}" style="${weakKey ? 'color:var(--high)' : ''}">
          ${esc(c.public_key_algorithm)}-${c.public_key_bits ?? '?'}</td>
        <td class="mono ${weakSig ? '' : 'dim'}" style="font-size:11px;${weakSig ? 'color:var(--high)' : ''}">
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

VIEWS.compliance = () => {
  const comp = S.report?.fleet?.compliance || {};
  const keys = Object.keys(comp);
  if (!keys.length) return emptyState('No compliance data', 'Analyse a capture first.', 'captures');
  const failed = keys.filter(k => comp[k] === 'fail');
  const byStandard = {};
  (S.report.prioritised_findings || []).forEach(f =>
    (f.standards || []).filter(s => s.relation === 'violates').forEach(s => {
      const k = `${s.body} ${s.identifier}`;
      (byStandard[k] = byStandard[k] || []).push(f);
    }));
  return `
  <div class="stats" style="margin-bottom:14px">
    ${tile('Standards tracked', keys.length)}
    ${tile('Failed', failed.length, '', failed.length ? 'action required' : 'clean',
           failed.length ? 'down' : 'up')}
    ${tile('Passed', keys.length - failed.length)}
  </div>
  <p class="note">A standard is marked <b>FAIL</b> only where a finding cites it as <i>breached</i>.
  Documents quoted to explain our reasoning — RFC 7435 for the opportunistic-relay downgrade, for
  instance — are recorded as context and never counted as failures.</p>
  <div class="grid g2">
    ${keys.sort((a, b) => (comp[a] === comp[b] ? a.localeCompare(b) : comp[a] === 'fail' ? -1 : 1))
      .map(k => {
        const fail = comp[k] === 'fail', fs = byStandard[k] || [];
        return `<div class="card" style="border-left:3px solid ${fail ? COLOR.critical : COLOR.ok}">
          <div style="display:flex;align-items:center;gap:10px">
            <b style="font-size:13.5px">${esc(k)}</b>
            <span class="sev ${fail ? 'sev-critical' : 'sev-low'}" style="margin-left:auto">
              ${fail ? 'FAIL' : 'PASS'}</span>
          </div>
          ${fs.length ? `<div class="faint" style="font-size:11.5px;margin-top:8px">
            ${fs.length} finding${fs.length > 1 ? 's' : ''}: ${esc([...new Set(fs.map(f => f.rule_id))].slice(0, 3).join(', '))}
          </div>` : '<div class="faint" style="font-size:11.5px;margin-top:8px">No breach observed.</div>'}
        </div>`;
      }).join('')}
  </div>`;
};

VIEWS.audit = () => `
  <p class="note">Append-only. Never updated, never deleted. Serves the forensics persona and the
  CERT-In Directions 2022 six-hour incident-reporting requirement: it records exactly when a finding
  was seen and who acted on it.</p>
  <div class="card flush">
    ${cardHead('Event log', 'file')}
    <div class="t-scroll"><table><thead><tr>
      <th style="width:150px">Timestamp</th><th>Actor</th><th>Action</th><th>Object</th><th>Detail</th>
    </tr></thead><tbody>
    ${S.audit.map(e => `<tr>
      <td class="mono faint nowrap">${esc((e.timestamp || '').slice(0, 19).replace('T', ' '))}</td>
      <td class="mono dim">${esc(e.actor)}</td>
      <td><span class="mono" style="color:var(--accent);font-size:11.5px">${esc(e.action)}</span></td>
      <td class="mono dim" style="font-size:11px;max-width:230px;overflow:hidden;text-overflow:ellipsis">
        ${esc(e.object_id)}</td>
      <td class="dim" style="font-size:11.5px">${esc((e.detail || '').slice(0, 90))}
        ${e.before ? `<span class="faint">${esc(e.before)} → ${esc(e.after)}</span>` : ''}</td>
    </tr>`).join('') || '<tr><td colspan="5" class="empty">No events yet.</td></tr>'}
    </tbody></table></div>
  </div>`;

VIEWS.snapshots = () => {
  const drift = S.snapshots.length > 1
    ? S.snapshots[0].fleet_score - S.snapshots[S.snapshots.length - 1].fleet_score : null;
  return `
  <p class="note">Every completed analysis archives an immutable posture snapshot. Finalising one is a
  sign-off and cannot be undone. Two snapshots of the same estate are a diff, which is how posture drift
  over time is measured.</p>
  ${drift !== null ? `<div class="stats" style="margin-bottom:14px">
    ${tile('Snapshots', S.snapshots.length)}
    ${tile('Latest', S.snapshots[0].fleet_grade, '', `${S.snapshots[0].fleet_score}/100`)}
    ${tile('Drift', (drift > 0 ? '+' : '') + drift.toFixed(1), '', 'vs oldest',
           drift >= 0 ? 'up' : 'down')}
  </div>` : ''}
  <div class="card flush">
    ${cardHead('Posture archive', 'archive')}
    <table><thead><tr><th>Captured</th><th>Grade</th><th>Score</th><th>Hosts</th>
      <th>Sessions</th><th>Status</th><th></th></tr></thead><tbody>
    ${S.snapshots.map(s => `<tr>
      <td class="mono dim nowrap">${esc((s.captured_at || '').slice(0, 16).replace('T', ' '))}</td>
      <td><b class="grade ${gradeClass(s.fleet_grade)}" style="font-size:16px">${esc(s.fleet_grade)}</b></td>
      <td class="mono dim">${s.fleet_score}</td>
      <td class="mono dim">${s.host_count}</td>
      <td class="mono dim">${s.session_count}</td>
      <td>${s.finalised_at
        ? `<span class="sev sev-low">finalised</span>`
        : '<span class="disp">draft</span>'}</td>
      <td class="right">${s.finalised_at
        ? `<span class="faint mono" style="font-size:10.5px">by ${esc(s.finalised_by)}</span>`
        : `<button class="btn tiny" onclick="finalise('${s.snapshot_id}')">Finalise</button>`}</td>
    </tr>`).join('') || '<tr><td colspan="7" class="empty">No snapshots yet.</td></tr>'}
    </tbody></table>
  </div>`;
};

VIEWS.settings = () => {
  const job = S.jobs.find(j => j.state === 'completed');
  return `
  <div class="grid g2">
    <div class="card">
      ${cardHead('Export', 'download')}
      <p class="faint" style="font-size:12.5px;margin:0 0 12px">
        All formats render from one report object, so they can never disagree.</p>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn" ${job ? '' : 'disabled'} onclick="window.open('/api/reports/${job?.job_id}/html')">Full HTML report</button>
        <button class="btn" ${job ? '' : 'disabled'} onclick="window.open('/api/reports/${job?.job_id}')">Report JSON</button>
      </div>
      <div class="section-title">SIEM</div>
      <p class="faint" style="font-size:12.5px;margin:0 0 10px">
        Findings as CEF (Splunk, QRadar, Sentinel) or ECS (Elastic). Defaults to medium and above —
        forwarding everything is how a feed gets muted.</p>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <select class="sel" id="siemFmt"><option value="cef">CEF</option><option value="ecs">ECS / NDJSON</option></select>
        <select class="sel" id="siemMin">
          <option value="info">info and above</option><option value="low">low and above</option>
          <option value="medium" selected>medium and above</option>
          <option value="high">high and above</option><option value="critical">critical only</option>
        </select>
        <button class="btn accent" ${job ? '' : 'disabled'} onclick="exportSiem('${job?.job_id}')">Export</button>
      </div>
    </div>
    <div class="card">
      ${cardHead('Analyst feedback loop', 'brain')}
      <p class="faint" style="font-size:12.5px;margin:0 0 12px;line-height:1.6">
        Every finding marked a false positive becomes a labelled training example. Triage work feeds the
        model instead of evaporating — the difference between a one-shot score and a system that
        improves with use.</p>
      <div id="signal" class="empty">loading…</div>
      <div class="section-title">Environment</div>
      <dl class="kv">
        <dt>Analysis engine</dt><dd>stdlib + dpkt</dd>
        <dt>Service</dt><dd>Flask + sqlite3</dd>
        <dt>Risk backend</dt><dd id="backend">—</dd>
        <dt>Signed in as</dt><dd>${esc(S.user?.display_name || '')} (${esc(S.user?.role || '')})</dd>
      </dl>
    </div>
  </div>`;
};

/* ─────────────── helpers ─────────────── */
const ICONS = {
  shield: '<path d="M12 2l8 4v6c0 5-3.4 9.3-8 10-4.6-.7-8-5-8-10V6l8-4z"/>',
  activity: '<path d="M3 12h4l3-8 4 16 3-8h4"/>', alert: '<path d="M12 2L2 20h20L12 2zm0 6v6m0 3v1"/>',
  pie: '<path d="M12 3v9h9a9 9 0 11-9-9z"/>', upload: '<path d="M12 16V4m-5 5l5-5 5 5M4 20h16"/>',
  archive: '<path d="M3 7h18v13H3zM3 3h18v4H3zm6 8h6"/>', list: '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
  network: '<path d="M5 3h6v6H5zM13 15h6v6h-6zM8 9v6h8"/>', lock: '<path d="M5 11h14v10H5zM8 11V7a4 4 0 118 0v4"/>',
  file: '<path d="M14 2H6v20h12V6zM14 2v4h4"/>', download: '<path d="M12 4v12m-5-5l5 5 5-5M4 20h16"/>',
  brain: '<path d="M9 3a3 3 0 00-3 3 3 3 0 00-2 5 3 3 0 002 5 3 3 0 003 3V3zm6 0a3 3 0 013 3 3 3 0 012 5 3 3 0 01-2 5 3 3 0 01-3 3V3z"/>',
  check: '<path d="M4 12l5 5L20 6"/>',
};
const icon = n => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"
  stroke-linecap="round" stroke-linejoin="round">${ICONS[n] || ICONS.shield}</svg>`;
const cardHead = (t, i, tag) =>
  `<div class="card-head">${icon(i)}${esc(t)}${tag ? `<span class="tag">${esc(tag)}</span>` : ''}</div>`;
const tile = (k, v, u, d, cls) => `<div class="stat"><div class="k">${esc(k)}</div>
  <div class="v">${v}${u ? `<span class="u">${esc(u)}</span>` : ''}</div>
  ${d ? `<div class="d ${cls || 'faint'}">${esc(d)}</div>` : ''}</div>`;
const emptyState = (t, s, go) => `<div class="card" style="text-align:center;padding:52px 20px">
  <div style="font-size:16px;font-weight:600;margin-bottom:5px">${esc(t)}</div>
  <div class="faint" style="font-size:13px;margin-bottom:16px">${esc(s)}</div>
  <button class="btn accent" onclick="location.hash='#${go}'">Go to captures</button></div>`;

/* ─────────────── drawers ─────────────── */
function closeDrawer() { $('#drawer').classList.remove('open'); $('#scrim').classList.remove('open'); }
function showDrawer(html) {
  $('#drawer').innerHTML = html;
  $('#drawer').classList.add('open'); $('#scrim').classList.add('open');
  $('#drawer').scrollTop = 0;
}

window.openFinding = key => {
  const f = (S.report?.prioritised_findings || []).find(x => KEY(x) === key);
  if (!f) return;
  const d = S.dispositions[key] || { state: 'new' };
  const r = f.remediation || {};
  const snippets = ['postfix', 'dovecot', 'exchange', 'generic']
    .filter(k => r[k]).map(k => `<div class="faint mono" style="font-size:10px;margin-top:9px">${k}</div>
      <pre class="snippet">${esc(r[k])}</pre>`).join('');
  showDrawer(`
    <div class="drawer-head">
      <div style="flex:1">
        <div style="display:flex;gap:8px;align-items:center;margin-bottom:5px">
          <span class="sev sev-${f.severity}">${f.severity}</span>
          <span class="disp disp-${d.state}">${d.state.replace('_', ' ')}</span>
        </div>
        <h3>${esc(f.title)}</h3>
        <div class="mono faint" style="font-size:11.5px">${esc(f.rule_id)} ·
          ${esc(f.affected_host || '')}:${f.affected_port || ''}</div>
      </div>
      <button class="btn tiny" onclick="closeDrawer()">Close</button>
    </div>
    <div class="drawer-body">
      <p class="dim" style="font-size:13px;line-height:1.65;margin-top:0">${esc(f.description)}</p>
      ${f.severity_adjustment_reason ? `<div style="background:rgba(34,211,238,.07);
        border-left:2px solid var(--accent);border-radius:6px;padding:10px 13px;font-size:12.5px;
        line-height:1.6;margin:13px 0"><b style="color:var(--accent)">Role-aware severity.</b>
        ${esc(f.severity_adjustment_reason)}</div>` : ''}
      ${f.evidence?.frame_numbers?.length ? `<div class="evidence">stream ${f.evidence.stream_id} ·
        frames ${f.evidence.frame_numbers.slice(0, 6).join(', ')} ·
        bytes ${(f.evidence.byte_range || []).join('–')} · ${esc(f.evidence.direction || '')}</div>
        <div class="faint" style="font-size:11px;margin-top:5px">Open the capture in Wireshark and
        filter on these frames to verify this independently.</div>` : ''}
      ${(f.standards || []).length || (f.related_attacks || []).length ? `<div class="chips">
        ${(f.standards || []).map(s => `<span class="chip-s" title="${esc(s.requirement || '')}">
          ${esc(s.body)} ${esc(s.identifier)}${s.relation === 'context' ? ' (context)' : ''}</span>`).join('')}
        ${(f.related_attacks || []).map(a => `<span class="chip-s atk">${esc(a)}</span>`).join('')}
      </div>` : ''}
      ${r.summary ? `<div class="section-title">Remediation</div>
        <p class="dim" style="font-size:12.5px;margin:0">${esc(r.summary)}</p>${snippets}
        <div class="faint" style="font-size:11.5px;margin-top:9px">effort: ${esc(r.effort || '—')} ·
        risk of change: ${esc(r.risk_of_change || '—')}</div>` : ''}
      <div class="section-title">Disposition</div>
      <div style="display:flex;gap:7px;flex-wrap:wrap">
        ${(NEXT[d.state] || []).map(([s, l]) =>
          `<button class="btn" onclick="dispose('${esc(key)}','${s}',true)">${l}</button>`).join('')}
      </div>
    </div>`);
};

window.openSession = sid => {
  const s = (S.report?.sessions || []).find(x => x.session_id === sid);
  if (!s) return;
  const h = s.handshake, a = s.assessment || {}, v = s.starttls;
  const CHECKS = {
    v1_advertised: 'STARTTLS advertised', v2_capability_mangled: 'Capability not mangled',
    v3_client_issued: 'Client issued command', v4_server_accepted: 'Server accepted',
    v5_clienthello_followed: 'ClientHello followed', v6_handshake_completed: 'Handshake completed',
    v7_ehlo_reissued: 'EHLO re-issued after TLS', v8_auth_offered_before_tls: 'No plaintext AUTH before TLS',
    v9_credentials_before_tls: 'No credentials before TLS', v10_command_injection: 'No command injection',
  };
  const INV = new Set(['v2_capability_mangled', 'v8_auth_offered_before_tls',
    'v9_credentials_before_tls', 'v10_command_injection']);
  const contribs = a.shap_contributions || [];
  const maxC = Math.max(...contribs.map(c => Math.abs(c.contribution)), .001);

  showDrawer(`
    <div class="drawer-head">
      <div style="flex:1"><h3>${esc(s.server_host)}:${s.server_port}</h3>
        <div class="mono faint" style="font-size:11.5px">${esc(s.session_id)} · ${esc(s.protocol)} ·
          ${esc(s.port_role.replace('_', ' '))} · ${esc(s.tls_mode)}</div></div>
      <button class="btn tiny" onclick="closeDrawer()">Close</button>
    </div>
    <div class="drawer-body">
      ${h ? `<div class="section-title">Negotiated parameters · D05–D07, D15</div>
      <dl class="kv">
        <dt>Version</dt><dd>${esc(h.negotiated_version)}</dd>
        <dt>Cipher suite</dt><dd>${esc(h.cipher_suite_name || '—')}</dd>
        <dt>Key exchange</dt><dd>${esc(h.key_exchange)}${h.key_exchange_bits ? ` (${h.key_exchange_bits} bit)` : ''}</dd>
        <dt>Forward secrecy</dt><dd>${h.has_forward_secrecy ? 'yes' : 'no'}</dd>
        <dt>Post-quantum</dt><dd>${h.pq_groups_offered?.length ? esc(h.pq_groups_offered.join(', ')) : 'not offered'}</dd>
        <dt>SNI</dt><dd>${esc(h.client_hello?.server_name || '—')}</dd>
        <dt>JA3</dt><dd>${esc(h.client_hello?.ja3 || '—')}</dd>
        <dt>JA3S</dt><dd>${esc(h.server_hello?.ja3s || '—')}</dd>
      </dl>
      <div class="section-title">Handshake reconstruction · D04</div>
      <div class="ladder">${(h.message_sequence || []).map(m => {
        const c2s = m.startsWith('->');
        return `<div class="${c2s ? 'c2s' : 's2c'}"><span class="arrow">${c2s ? 'client →' : '← server'}</span>
          ${esc(m.slice(3))}</div>`; }).join('') || '<span class="faint">none observed</span>'}</div>`
      : '<div class="faint" style="font-size:12.5px">No TLS handshake was observed in this session.</div>'}

      ${v && v.v1_advertised !== null ? `<div class="section-title">STARTTLS validation · D02</div>
        ${v.observed_capability_line ? `<div class="evidence" style="margin-bottom:8px">observed:
          ${esc(v.observed_capability_line)}</div>` : ''}
        <div class="checks">${Object.entries(CHECKS).map(([k, label]) => {
          const raw = v[k];
          if (raw === null || raw === undefined)
            return `<div class="check na"><b>–</b><span>${label}
              <span class="faint">(not observable)</span></span></div>`;
          const good = INV.has(k) ? !raw : raw;
          return `<div class="check ${good ? 'pass' : 'fail'}"><b>${good ? '✓' : '✕'}</b>
            <span>${label}</span></div>`; }).join('')}</div>` : ''}

      ${s.chain ? `<div class="section-title">Certificate chain · D08–D12</div>
        ${s.chain.status === 'opaque_tls13'
          ? `<p class="dim" style="font-size:12.5px;margin:0">TLS 1.3 encrypts the Certificate message,
             so a passive observer cannot inspect the chain. <b>This is the expected behaviour of a
             correctly configured modern server</b>, not a missing certificate.</p>`
          : `<dl class="kv">${(s.certificates || []).map(c => `
              <dt>${c.chain_position === 0 ? 'Leaf' : '#' + c.chain_position}</dt>
              <dd>${esc(c.subject_cn || c.subject)}<br>
                <span class="faint">${esc(c.public_key_algorithm)}-${c.public_key_bits} ·
                ${esc(c.signature_algorithm)} · expires ${esc((c.not_after || '').slice(0, 10))}</span></dd>`).join('')}
              <dt>Status</dt><dd>${esc(s.chain.status)}</dd></dl>
             ${(s.chain.issues || []).length ? `<ul class="dim" style="font-size:12px;
               padding-left:17px;margin:9px 0 0">${s.chain.issues.map(i => `<li>${esc(i)}</li>`).join('')}</ul>` : ''}`}` : ''}

      <div class="section-title">Why this score · D16</div>
      <div class="wf">${contribs.length ? contribs.map(c => `
        <div><div class="b ${c.contribution >= 0 ? 'pos' : 'neg'}"
          style="width:${Math.max(2, Math.abs(c.contribution) / maxC * 100)}%"></div>
          <div class="lbl">${esc(c.human_readable || c.feature)}</div></div>
        <div class="val">${c.contribution >= 0 ? '+' : ''}${c.contribution.toFixed(3)}</div>`).join('')
        : '<div class="faint">no contributions recorded</div>'}</div>

      <div class="section-title">Anomaly · D17</div>
      <div class="mono" style="font-size:22px;color:${a.is_anomalous ? COLOR.high : COLOR.info}">
        ${(a.anomaly_score || 0).toFixed(2)}</div>
      <div class="faint" style="font-size:11.5px;margin-bottom:8px">
        ${a.is_anomalous ? 'flagged as unusual for this fleet' : 'consistent with the fleet'}</div>
      ${(a.anomaly_reasons || []).map(r => `<div class="dim" style="font-size:12px">• ${esc(r)}</div>`).join('')}

      ${s.findings?.length ? `<div class="section-title">Findings</div>
        ${s.findings.map(f => `<div style="display:flex;gap:9px;align-items:center;padding:6px 0;
          border-bottom:1px solid var(--line);cursor:pointer" onclick="openFinding('${esc(KEY(f))}')">
          <span class="sev sev-${f.severity}">${f.severity}</span>
          <span style="font-size:12.5px">${esc(f.title)}</span></div>`).join('')}` : ''}
    </div>`);
};

/* ─────────────── actions ─────────────── */
window.dispose = async (key, state, fromDrawer) => {
  const body = { state, job_id: S.report?._job || '' };
  if (state === 'accepted_risk') {
    const j = prompt('Accepting risk requires a justification — an unexplained acceptance is\nindistinguishable from an unread alert:');
    if (!j) return;
    body.justification = j;
  }
  try {
    await api(`/api/findings/${encodeURIComponent(key)}/disposition`,
      { method: 'POST', body: JSON.stringify(body) });
    toast(`${key.split('@')[0]} → ${state.replace('_', ' ')}`, 'good');
    await refresh();
    if (fromDrawer) openFinding(key);
  } catch (e) { toast(e.message, 'bad'); }
};

window.finalise = async id => {
  if (!confirm('Finalising a posture snapshot is a sign-off and cannot be undone. Continue?')) return;
  try { await api(`/api/snapshots/${id}/finalise`, { method: 'POST' });
    toast('Posture finalised — the snapshot is now immutable', 'good'); await refresh();
  } catch (e) { toast(e.message, 'bad'); }
};

window.loadJob = async id => {
  const r = await api(`/api/reports/${id}`);
  r._job = id; S.report = r; location.hash = '#overview'; toast('Report loaded');
};

window.exportSiem = id => {
  const fmt = $('#siemFmt').value, min = $('#siemMin').value;
  window.open(`/api/reports/${id}/siem?fmt=${fmt}&min=${min}`, '_blank');
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

/* ─────────────── wiring per view ─────────────── */
function wire(view) {
  if (view === 'captures') {
    const drop = $('#drop'), input = $('#file');
    if (drop) {
      drop.onclick = () => input.click();
      input.onchange = e => e.target.files[0] && upload(e.target.files[0]);
      ['dragover', 'dragenter'].forEach(ev => drop.addEventListener(ev, e => {
        e.preventDefault(); drop.classList.add('over'); }));
      ['dragleave', 'drop'].forEach(ev => drop.addEventListener(ev, e => {
        e.preventDefault(); drop.classList.remove('over'); }));
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
      try { await api(`/api/samples/${encodeURIComponent(n)}/analyse`, { method: 'POST' });
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
        const okSev = sev === 'all' || tr.dataset.sev === sev;
        const okOpen = !openOnly || tr.dataset.open === 'true';
        const okQ = !q || tr.textContent.toLowerCase().includes(q);
        tr.style.display = okSev && okOpen && okQ ? '' : 'none';
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
        const s = (S.report.sessions || []).find(x => x.session_id === tr.dataset.sid) || {};
        const a = s.assessment || {};
        const okF = f === 'all' || (f === 'cleartext' && s.tls_mode === 'cleartext')
          || (f === 'anomalous' && a.is_anomalous) || (f === 'risky' && (a.risk_score || 0) > .5);
        const okQ = !q || tr.textContent.toLowerCase().includes(q);
        tr.style.display = okF && okQ ? '' : 'none';
      });
    };
    $('#sessQ').oninput = apply;
    $$('#sessFilter button').forEach(b => b.onclick = () => {
      $$('#sessFilter button').forEach(x => x.classList.remove('on'));
      b.classList.add('on'); apply();
    });
  }

  if (view === 'settings') {
    api('/api/training-signal').then(sig => {
      const el = $('#signal'); if (!el) return;
      el.className = sig.length ? '' : 'empty';
      el.innerHTML = sig.length
        ? `<div class="mono" style="font-size:12px">${sig.map(([k, s]) =>
            `<div style="padding:3px 0;border-bottom:1px solid var(--line)">
              <span class="disp disp-${s}">${s.replace('_', ' ')}</span>
              <span class="dim" style="margin-left:7px">${esc(k)}</span></div>`).join('')}</div>`
        : 'No labelled examples yet — mark a finding resolved or a false positive.';
    });
    const j = S.jobs.find(x => x.state === 'completed');
    if (j) api(`/api/reports/${j.job_id}`).then(r => {
      const el = $('#backend'); if (!el) return;
      const v = r.sessions?.[0]?.assessment?.model_version || '—';
      el.textContent = v.startsWith('gradient') ? 'gradient boosting (trained)'
        : 'rule-derived baseline';
    });
  }
}

/* ─────────────── router ─────────────── */
const TITLES = {
  overview: ['Operations Overview', 'Cryptographic posture across the mail estate'],
  captures: ['Capture Ingestion', 'Submit a PCAP and watch the pipeline run'],
  sessions: ['Mail Sessions', 'Every reconstructed SMTP, IMAP and POP3 conversation'],
  findings: ['Triage Queue', 'Prioritised findings with analyst dispositions'],
  certificates: ['Certificate Inventory', 'X.509 chains observed on the wire'],
  compliance: ['Compliance', 'Standards breached, and the findings that breach them'],
  audit: ['Audit Log', 'Append-only record of every action'],
  snapshots: ['Posture Archive', 'Immutable snapshots and drift over time'],
  settings: ['Export & Integrations', 'Reports, SIEM forwarding and the feedback loop'],
};

function render() {
  const view = (location.hash || '#overview').slice(1);
  const v = VIEWS[view] ? view : 'overview';
  const [title, sub] = TITLES[v];
  $$('.nav a').forEach(a => a.classList.toggle('on', a.getAttribute('href') === '#' + v));
  $('#page').innerHTML = `
    <div class="page-head">
      <div><h1>${esc(title)}</h1><p>${esc(sub)}</p></div>
      <div class="actions">
        <button class="btn" onclick="refresh()">Refresh</button>
      </div>
    </div>${VIEWS[v]()}`;
  wire(v);
  $('.rail')?.classList.remove('open');
}

window.addEventListener('hashchange', render);

/* ─────────────── boot ─────────────── */
(async function boot() {
  S.user = await api('/api/me').catch(() => null);
  if (S.user) {
    $('#who-name').textContent = S.user.display_name;
    $('#who-role').textContent = S.user.role === 'admin' ? 'SOC Manager' : 'Analyst';
    $('#avatar').textContent = S.user.initials;
  }
  $('#scrim').onclick = closeDrawer;
  document.addEventListener('keydown', e => e.key === 'Escape' && closeDrawer());
  $('#burger').onclick = () => $('.rail').classList.toggle('open');

  await refresh();
  render();

  setInterval(async () => {
    const active = S.jobs.some(j => !['completed', 'rejected', 'failed'].includes(j.state));
    if (active) { await refresh(true); if (location.hash === '#captures') render(); }
  }, 1100);
  setInterval(() => { $('#clock').textContent = new Date().toTimeString().slice(0, 5); }, 1000);
})();
