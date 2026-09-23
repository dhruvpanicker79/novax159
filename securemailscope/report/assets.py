"""Styles and client-side script for the HTML report.

Kept as plain strings rather than a template engine so the report generator has
zero dependencies, like the rest of the pipeline. `jinja2` is not installed and
neither is node - see ADR-0018 for why the dashboard is a single self-contained
file rather than a build-step app.

The page is dark by default because analysts work in dark rooms at 2am, with a
light theme available for printing and for the PDF export.
"""

CSS = r"""
:root {
  --bg: #0b0e14;
  --bg-raised: #121722;
  --bg-sunken: #080a0f;
  --line: #1e2635;
  --line-bright: #2b3648;
  --text: #dfe5ef;
  --text-dim: #8c99ad;
  --text-faint: #5b677a;
  --accent: #4da3ff;
  --accent-dim: #1f3a5c;
  --critical: #ff4d5e;
  --high: #ff8f3f;
  --medium: #ffc94d;
  --low: #5fd3a6;
  --info: #6b7a90;
  --ok: #3ddc97;
  --mono: ui-monospace, "SF Mono", "Cascadia Code", "Fira Code", Consolas, monospace;
  --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, sans-serif;
}
[data-theme="light"] {
  --bg: #f7f9fc; --bg-raised: #fff; --bg-sunken: #eef2f7;
  --line: #dde4ee; --line-bright: #c3cede;
  --text: #16202e; --text-dim: #566276; --text-faint: #8794a6;
  --accent: #0f66cc; --accent-dim: #d6e6fa;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font-family: var(--sans); font-size: 14px; line-height: 1.55;
  -webkit-font-smoothing: antialiased;
}
a { color: var(--accent); }
.wrap { max-width: 1280px; margin: 0 auto; padding: 0 24px 80px; }

/* ---------- header ---------- */
header {
  border-bottom: 1px solid var(--line);
  background: linear-gradient(180deg, var(--bg-raised), var(--bg));
  padding: 26px 0 22px; margin-bottom: 26px;
}
.brand { display:flex; align-items:baseline; gap:14px; flex-wrap:wrap; }
.brand h1 { font-size: 20px; margin:0; letter-spacing:-.2px; font-weight:650; }
.brand .sub { color: var(--text-dim); font-size:13px; }
.capmeta { margin-top:10px; display:flex; gap:22px; flex-wrap:wrap;
  font-family: var(--mono); font-size:11.5px; color: var(--text-faint); }
.capmeta b { color: var(--text-dim); font-weight:500; }

/* ---------- layout ---------- */
.grid { display:grid; gap:18px; }
.cols-2 { grid-template-columns: 1fr 1fr; }
.cols-3 { grid-template-columns: repeat(3, 1fr); }
.hero { grid-template-columns: 260px 1fr; align-items:stretch; }
@media (max-width: 900px) {
  .cols-2, .cols-3, .hero { grid-template-columns: 1fr; }
  .wrap { padding: 0 14px 60px; }
}
.card {
  background: var(--bg-raised); border:1px solid var(--line);
  border-radius: 10px; padding:18px 20px;
}
.card h2 { font-size:12px; text-transform:uppercase; letter-spacing:.09em;
  color: var(--text-dim); margin:0 0 14px; font-weight:600; }
.card h2 .tag { color: var(--text-faint); text-transform:none; letter-spacing:0;
  font-weight:400; margin-left:8px; font-family:var(--mono); font-size:10.5px; }

/* ---------- grade ---------- */
.gradebox { display:flex; flex-direction:column; align-items:center;
  justify-content:center; text-align:center; }
.gradeletter { font-size:76px; font-weight:700; line-height:1; letter-spacing:-3px;
  font-family:var(--mono); }
.gradescore { color: var(--text-dim); font-size:12px; margin-top:8px;
  font-family:var(--mono); }
.g-A\+, .g-A { color: var(--ok); } .g-B { color: var(--low); }
.g-C { color: var(--medium); } .g-D { color: var(--high); }
.g-E, .g-F { color: var(--critical); } .g-\? { color: var(--text-faint); }

.summary { font-size:15px; line-height:1.65; }
.summary .warn { color: var(--critical); font-weight:600; }

/* ---------- stats ---------- */
.stats { display:grid; grid-template-columns:repeat(auto-fit,minmax(112px,1fr)); gap:1px;
  background: var(--line); border:1px solid var(--line); border-radius:10px;
  overflow:hidden; margin-bottom:18px; }
.stat { background: var(--bg-raised); padding:13px 15px; }
.stat .v { font-size:22px; font-weight:650; font-family:var(--mono); letter-spacing:-.5px; }
.stat .k { font-size:10.5px; color:var(--text-faint); text-transform:uppercase;
  letter-spacing:.07em; margin-top:2px; }

/* ---------- severity ---------- */
.sev { display:inline-block; padding:1px 7px; border-radius:4px; font-size:10px;
  font-weight:700; letter-spacing:.06em; text-transform:uppercase;
  font-family:var(--mono); }
.sev-critical { background:rgba(255,77,94,.16); color:var(--critical); }
.sev-high     { background:rgba(255,143,63,.16); color:var(--high); }
.sev-medium   { background:rgba(255,201,77,.15); color:var(--medium); }
.sev-low      { background:rgba(95,211,166,.14); color:var(--low); }
.sev-info     { background:rgba(107,122,144,.18); color:var(--info); }

/* ---------- tables ---------- */
table { width:100%; border-collapse:collapse; font-size:13px; }
th { text-align:left; font-size:10.5px; text-transform:uppercase; letter-spacing:.07em;
  color:var(--text-faint); font-weight:600; padding:0 10px 8px; border-bottom:1px solid var(--line); }
td { padding:9px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
tr:last-child td { border-bottom:none; }
tbody tr:hover { background: rgba(77,163,255,.045); }
.mono { font-family:var(--mono); font-size:12px; }
.dim { color: var(--text-dim); }
.faint { color: var(--text-faint); }

/* ---------- findings ---------- */
.finding { border:1px solid var(--line); border-left:3px solid var(--line-bright);
  border-radius:8px; margin-bottom:10px; background: var(--bg-raised); }
.finding.f-critical { border-left-color: var(--critical); }
.finding.f-high { border-left-color: var(--high); }
.finding.f-medium { border-left-color: var(--medium); }
.finding.f-low { border-left-color: var(--low); }
.finding.f-info { border-left-color: var(--info); }
.finding > summary { cursor:pointer; padding:12px 16px; list-style:none;
  display:flex; align-items:center; gap:11px; flex-wrap:wrap; }
.finding > summary::-webkit-details-marker { display:none; }
.finding > summary:hover { background: rgba(255,255,255,.02); }
.finding .rank { font-family:var(--mono); color:var(--text-faint); font-size:11px;
  min-width:22px; }
.finding .title { font-weight:560; flex:1; min-width:220px; }
.finding .where { font-family:var(--mono); font-size:11.5px; color:var(--text-dim); }
.finding .body { padding:2px 16px 16px 16px; border-top:1px solid var(--line); }
.finding .body p { margin:12px 0; color:var(--text-dim); max-width:78ch; }

.adjust { background: var(--accent-dim); border-radius:6px; padding:9px 12px;
  font-size:12.5px; margin:12px 0; border-left:2px solid var(--accent); }
[data-theme="light"] .adjust { background:#eaf3fe; }
.adjust b { color: var(--accent); }

.evidence { font-family:var(--mono); font-size:11.5px; color:var(--text-faint);
  background: var(--bg-sunken); padding:7px 11px; border-radius:6px;
  display:inline-block; margin:6px 0; }

pre.snippet { background: var(--bg-sunken); border:1px solid var(--line);
  border-radius:7px; padding:11px 13px; font-family:var(--mono); font-size:11.5px;
  overflow-x:auto; margin:8px 0; color:#9fd8b4; }
[data-theme="light"] pre.snippet { color:#1f6b45; }
.chips { display:flex; gap:6px; flex-wrap:wrap; margin:8px 0; }
.chip { font-size:10.5px; font-family:var(--mono); padding:2px 8px; border-radius:20px;
  border:1px solid var(--line-bright); color:var(--text-dim); }
.chip.attack { border-color:rgba(255,143,63,.4); color:var(--high); }

/* ---------- waterfall ---------- */
.wf { display:grid; grid-template-columns: 1fr auto; gap:3px 12px; align-items:center;
  font-size:12.5px; }
.wf .bar { height:16px; border-radius:3px; }
.wf .bar.pos { background: linear-gradient(90deg, var(--high), var(--critical)); }
.wf .bar.neg { background: linear-gradient(90deg, var(--low), var(--ok)); }
.wf .lbl { color: var(--text-dim); }
.wf .val { font-family:var(--mono); font-size:11.5px; color:var(--text-faint); }
.wfrow { display:contents; }

/* ---------- ladder ---------- */
.ladder { font-family:var(--mono); font-size:12px; }
.ladder div { padding:3px 0; color:var(--text-dim); }
.ladder .c2s { color:var(--accent); }
.ladder .s2c { color:var(--low); }

/* ---------- checks ---------- */
.checks { display:grid; grid-template-columns:repeat(auto-fit,minmax(215px,1fr)); gap:5px; }
.check { display:flex; gap:9px; align-items:flex-start; font-size:12.5px;
  padding:5px 8px; border-radius:5px; background:var(--bg-sunken); }
.check .m { font-family:var(--mono); font-weight:700; width:15px; flex:none; }
.check.pass .m { color:var(--ok); } .check.fail .m { color:var(--critical); }
.check.na .m { color:var(--text-faint); }
.check.na { opacity:.55; }

/* ---------- sessions ---------- */
.sess { border:1px solid var(--line); border-radius:9px; margin-bottom:10px;
  background:var(--bg-raised); }
.sess > summary { cursor:pointer; padding:12px 16px; list-style:none;
  display:grid; grid-template-columns: 78px 1fr 92px 96px 70px 62px; gap:12px;
  align-items:center; font-size:13px; }
.sess > summary::-webkit-details-marker { display:none; }
.sess > summary:hover { background: rgba(255,255,255,.02); }
@media (max-width: 900px) { .sess > summary { grid-template-columns: 1fr 1fr; } }
.sess .body { padding:4px 16px 18px; border-top:1px solid var(--line); }
.riskbar { height:5px; border-radius:3px; background:var(--bg-sunken); overflow:hidden; }
.riskbar i { display:block; height:100%; }

/* ---------- compliance ---------- */
.comp { display:grid; grid-template-columns:repeat(auto-fit,minmax(230px,1fr)); gap:7px; }
.compitem { display:flex; justify-content:space-between; align-items:center; gap:10px;
  padding:8px 11px; border-radius:6px; background:var(--bg-sunken); font-size:12.5px; }
.compitem .verdict { font-family:var(--mono); font-size:10.5px; font-weight:700;
  letter-spacing:.05em; }
.compitem.fail .verdict { color:var(--critical); }
.compitem.pass .verdict { color:var(--ok); }

/* ---------- controls ---------- */
.controls { display:flex; gap:8px; align-items:center; flex-wrap:wrap; margin-bottom:14px; }
button.f, select.f {
  background:var(--bg-raised); color:var(--text-dim); border:1px solid var(--line-bright);
  border-radius:6px; padding:5px 11px; font-size:12px; cursor:pointer;
  font-family:var(--sans);
}
button.f:hover { color:var(--text); border-color:var(--accent); }
button.f.on { background:var(--accent-dim); color:var(--accent); border-color:var(--accent); }
.spacer { flex:1; }

h3.section { font-size:15px; margin:34px 0 14px; font-weight:620;
  display:flex; align-items:center; gap:10px; }
h3.section .n { font-family:var(--mono); font-size:11px; color:var(--text-faint);
  border:1px solid var(--line-bright); border-radius:4px; padding:1px 6px; }
.note { color:var(--text-faint); font-size:12.5px; margin:-6px 0 14px; max-width:86ch; }

footer { margin-top:44px; padding-top:18px; border-top:1px solid var(--line);
  color:var(--text-faint); font-size:11.5px; font-family:var(--mono); }

@media print {
  body { background:#fff; }
  .controls, .noprint { display:none !important; }
  details { open: true; }
  .card, .finding, .sess { break-inside: avoid; }
}
"""


JS = r"""
const R = JSON.parse(document.getElementById('report-data').textContent);
const $ = (s, r=document) => r.querySelector(s);
const $$ = (s, r=document) => [...r.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"]/g, c =>
  ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const sev = s => `<span class="sev sev-${s}">${s}</span>`;
const SEVRANK = {critical:4, high:3, medium:2, low:1, info:0};

/* ---------------- evidence ---------------- */
function evidenceLine(e) {
  if (!e || !e.frame_numbers || !e.frame_numbers.length) return '';
  const f = e.frame_numbers;
  const contiguous = f.length > 1 && f[f.length-1] - f[0] === f.length - 1;
  const frames = f.length === 1 ? `frame ${f[0]}`
    : contiguous ? `frames ${f[0]}-${f[f.length-1]}`
    : `frames ${f.slice(0,6).join(', ')}${f.length>6?` +${f.length-6}`:''}`;
  const range = e.byte_range ? `, bytes ${e.byte_range[0]}-${e.byte_range[1]}` : '';
  const dir = e.direction ? `, ${e.direction}` : '';
  return `<div class="evidence" title="Open this capture in Wireshark and filter on these frames">
    stream ${e.stream_id ?? '?'}, ${frames}${range}${dir}${e.note ? ' &middot; ' + esc(e.note) : ''}
  </div>`;
}

/* ---------------- findings ---------------- */
function remediationBlock(r) {
  if (!r) return '';
  let out = `<p><b>Remediation.</b> ${esc(r.summary)}</p>`;
  for (const [k, label] of [['postfix','Postfix'],['dovecot','Dovecot'],
                            ['exchange','Exchange'],['generic','General']]) {
    if (r[k]) out += `<div class="faint mono" style="font-size:10.5px;margin-top:9px">${label}</div>
                      <pre class="snippet">${esc(r[k])}</pre>`;
  }
  const meta = [];
  if (r.effort && r.effort !== 'unknown') meta.push(`effort: ${esc(r.effort)}`);
  if (r.risk_of_change && r.risk_of_change !== 'unknown')
    meta.push(`risk of change: ${esc(r.risk_of_change)}`);
  if (meta.length) out += `<div class="faint" style="font-size:12px">${meta.join(' &middot; ')}</div>`;
  return out;
}

function findingCard(f, rank) {
  const adjusted = f.base_severity !== f.severity && f.severity_adjustment_reason;
  const standards = (f.standards||[]).map(s =>
    `<span class="chip" title="${esc(s.requirement||'')}">${esc(s.body)} ${esc(s.identifier)}${
      s.relation === 'context' ? ' (context)' : ''}</span>`).join('');
  const attacks = (f.related_attacks||[]).map(a =>
    `<span class="chip attack">${esc(a)}</span>`).join('');
  return `<details class="finding f-${f.severity}" data-sev="${f.severity}"
            data-rule="${esc(f.rule_id)}" data-host="${esc(f.affected_host||'')}">
    <summary>
      ${rank ? `<span class="rank">${rank}</span>` : ''}
      ${sev(f.severity)}
      <span class="title">${esc(f.title)}</span>
      <span class="where">${esc(f.affected_host||'')}:${f.affected_port||''}</span>
    </summary>
    <div class="body">
      <p>${esc(f.description)}</p>
      ${adjusted ? `<div class="adjust"><b>Role-aware severity.</b> ${esc(f.severity_adjustment_reason)}</div>` : ''}
      ${evidenceLine(f.evidence)}
      ${(standards||attacks) ? `<div class="chips">${standards}${attacks}</div>` : ''}
      ${remediationBlock(f.remediation)}
      <div class="faint mono" style="font-size:10.5px;margin-top:10px">
        ${esc(f.rule_id)} &middot; base ${f.base_severity} &middot; confidence ${f.confidence}
      </div>
    </div>
  </details>`;
}

/* ---------------- sessions ---------------- */
function waterfall(contribs) {
  if (!contribs || !contribs.length) return '<div class="faint">no contributions recorded</div>';
  const max = Math.max(...contribs.map(c => Math.abs(c.contribution))) || 1;
  return `<div class="wf">` + contribs.map(c => {
    const w = Math.max(2, Math.abs(c.contribution) / max * 100);
    const pos = c.contribution >= 0;
    return `<div class="wfrow">
      <div><div class="bar ${pos?'pos':'neg'}" style="width:${w}%"></div>
           <div class="lbl">${esc(c.human_readable || c.feature)}</div></div>
      <div class="val">${pos?'+':''}${c.contribution.toFixed(3)}</div>
    </div>`;
  }).join('') + `</div>`;
}

const CHECK_LABELS = {
  v1_advertised: 'STARTTLS advertised',
  v2_capability_mangled: 'Capability not mangled',
  v3_client_issued: 'Client issued the command',
  v4_server_accepted: 'Server accepted',
  v5_clienthello_followed: 'ClientHello followed',
  v6_handshake_completed: 'Handshake completed',
  v7_ehlo_reissued: 'EHLO re-issued after TLS',
  v8_auth_offered_before_tls: 'No plaintext AUTH before TLS',
  v9_credentials_before_tls: 'No credentials before TLS',
  v10_command_injection: 'No command injection',
};
const INVERTED = new Set(['v2_capability_mangled','v8_auth_offered_before_tls',
                          'v9_credentials_before_tls','v10_command_injection']);

function starttlsPanel(v) {
  if (!v) return '';
  const rows = Object.keys(CHECK_LABELS).map(k => {
    const raw = v[k];
    if (raw === null || raw === undefined)
      return `<div class="check na"><span class="m">–</span><span>${CHECK_LABELS[k]}
              <span class="faint">(not observable)</span></span></div>`;
    const good = INVERTED.has(k) ? !raw : raw;
    return `<div class="check ${good?'pass':'fail'}"><span class="m">${good?'✓':'✕'}</span>
            <span>${CHECK_LABELS[k]}</span></div>`;
  }).join('');
  const line = v.observed_capability_line
    ? `<div class="evidence">observed: ${esc(v.observed_capability_line)}</div>` : '';
  return `<div class="card" style="margin-top:12px">
    <h2>STARTTLS validation <span class="tag">D02 &middot; ten checks</span></h2>
    ${line}<div class="checks">${rows}</div></div>`;
}

function certPanel(s) {
  const chain = s.chain;
  if (!chain) return '';
  if (chain.status === 'opaque_tls13') {
    return `<div class="card" style="margin-top:12px">
      <h2>Certificate <span class="tag">D08–D12</span></h2>
      <p class="dim" style="margin:0">TLS 1.3 encrypts the Certificate message, so a passive
      observer cannot inspect the chain. <b>This is the expected behaviour of a correctly
      configured modern server</b>, not a missing certificate.</p></div>`;
  }
  if (!s.certificates || !s.certificates.length) return '';
  const rows = s.certificates.map(c => `<tr>
      <td class="mono">${c.chain_position === 0 ? 'leaf' : '#'+c.chain_position}</td>
      <td>${esc(c.subject_cn||c.subject)}<div class="faint mono" style="font-size:10.5px">
          issuer: ${esc(c.issuer_cn||c.issuer)}</div></td>
      <td class="mono">${esc(c.public_key_algorithm)}-${c.public_key_bits ?? '?'}</td>
      <td class="mono">${esc(c.signature_algorithm)}</td>
      <td class="mono">${c.not_after ? c.not_after.slice(0,10) : '?'}</td>
    </tr>`).join('');
  const issues = (chain.issues||[]).map(i => `<li>${esc(i)}</li>`).join('');
  return `<div class="card" style="margin-top:12px">
    <h2>Certificate chain <span class="tag">D08–D12 &middot; status: ${esc(chain.status)}</span></h2>
    <table><thead><tr><th>Position</th><th>Subject</th><th>Key</th>
      <th>Signature</th><th>Expires</th></tr></thead><tbody>${rows}</tbody></table>
    ${issues ? `<ul class="dim" style="font-size:12.5px;margin:12px 0 0;padding-left:18px">${issues}</ul>` : ''}
  </div>`;
}

function handshakePanel(h) {
  if (!h) return '';
  const ladder = (h.message_sequence||[]).map(m => {
    const c2s = m.startsWith('->');
    return `<div class="${c2s?'c2s':'s2c'}">${c2s?'client → server':'server → client'}
            &nbsp;&nbsp;${esc(m.slice(3))}</div>`;
  }).join('');
  const facts = [
    ['Version', h.negotiated_version],
    ['Cipher suite', h.cipher_suite_name],
    ['Key exchange', h.key_exchange],
    ['Forward secrecy', h.has_forward_secrecy ? 'yes' : 'no'],
    ['Post-quantum', h.pq_groups_offered?.length ? h.pq_groups_offered.join(', ') : 'not offered'],
    ['SNI', h.client_hello?.server_name || '—'],
    ['JA3', h.client_hello?.ja3 || '—'],
    ['JA3S', h.server_hello?.ja3s || '—'],
  ].map(([k,v]) => `<tr><td class="dim">${k}</td><td class="mono">${esc(v)}</td></tr>`).join('');
  return `<div class="grid cols-2" style="margin-top:12px">
    <div class="card"><h2>Handshake reconstruction <span class="tag">D04</span></h2>
      <div class="ladder">${ladder || '<span class="faint">no handshake observed</span>'}</div></div>
    <div class="card"><h2>Negotiated parameters <span class="tag">D05–D07, D15</span></h2>
      <table><tbody>${facts}</tbody></table></div>
  </div>`;
}

function sessionCard(s) {
  const a = s.assessment || {};
  const risk = a.risk_score ?? 0;
  const colour = risk >= .85 ? 'var(--critical)' : risk >= .6 ? 'var(--high)'
    : risk >= .35 ? 'var(--medium)' : risk >= .15 ? 'var(--low)' : 'var(--info)';
  const ver = s.handshake?.negotiated_version || (s.tls_mode === 'cleartext' ? 'none' : '—');
  return `<details class="sess" id="sess-${esc(s.session_id)}" data-risk="${risk}"
            data-anom="${a.is_anomalous ? 1 : 0}">
    <summary>
      <span class="mono faint">${esc(s.session_id)}</span>
      <span>${esc(s.server_host)}:${s.server_port}
        <span class="faint mono" style="font-size:11px">${esc(s.protocol)} &middot; ${esc(s.port_role)}</span></span>
      <span class="mono dim">${esc(s.tls_mode)}</span>
      <span class="mono dim">${esc(ver)}</span>
      <span>${a.risk_label ? sev(a.risk_label) : ''}</span>
      <span><div class="riskbar"><i style="width:${(risk*100).toFixed(0)}%;background:${colour}"></i></div>
        <span class="faint mono" style="font-size:10.5px">${risk.toFixed(2)}${
          a.is_anomalous ? ' ⚠' : ''}</span></span>
    </summary>
    <div class="body">
      ${s.banner ? `<div class="evidence">banner: ${esc(s.banner)}</div>` : ''}
      ${handshakePanel(s.handshake)}
      ${starttlsPanel(s.starttls)}
      ${certPanel(s)}
      <div class="grid cols-2" style="margin-top:12px">
        <div class="card"><h2>Why this score <span class="tag">D16 &middot; explanation</span></h2>
          ${waterfall(a.shap_contributions)}</div>
        <div class="card"><h2>Anomaly <span class="tag">D17 &middot; unsupervised</span></h2>
          <div class="mono" style="font-size:22px;color:${a.is_anomalous?'var(--high)':'var(--text-faint)'}">
            ${(a.anomaly_score ?? 0).toFixed(2)}</div>
          <div class="faint" style="font-size:11px;margin-bottom:9px">
            ${a.is_anomalous ? 'flagged as unusual for this fleet' : 'consistent with the fleet'}</div>
          ${(a.anomaly_reasons||[]).map(r=>`<div class="dim" style="font-size:12.5px">• ${esc(r)}</div>`).join('')
            || '<div class="faint" style="font-size:12.5px">no deviations recorded</div>'}</div>
      </div>
      ${s.findings?.length ? `<h2 style="margin:18px 0 10px;font-size:12px;text-transform:uppercase;
        letter-spacing:.09em;color:var(--text-dim)">Findings</h2>
        ${s.findings.map(f=>findingCard(f)).join('')}` : ''}
      <details style="margin-top:12px"><summary class="faint mono"
        style="cursor:pointer;font-size:11.5px">Feature vector (O01) — the exact model input</summary>
        <div class="card" style="margin-top:8px"><table><tbody>
        ${Object.entries(s.features||{}).map(([k,v])=>
          `<tr><td class="dim">${esc(k)}</td><td class="mono">${esc(v)}</td></tr>`).join('')}
        </tbody></table></div></details>
    </div>
  </details>`;
}

/* ---------------- render ---------------- */
function render() {
  const f = R.fleet || {};
  $('#grade').textContent = f.grade ?? '?';
  $('#grade').className = 'gradeletter g-' + (f.grade ?? '?');
  $('#gradescore').textContent = `${f.score ?? 0} / 100`;
  $('#summary').innerHTML = esc(f.summary || '');

  const counts = {};
  (R.prioritised_findings||[]).forEach(x => counts[x.severity] = (counts[x.severity]||0)+1);
  $('#stats').innerHTML = [
    ['sessions', f.session_count ?? 0],
    ['hosts', f.host_count ?? 0],
    ['critical', counts.critical||0, 'var(--critical)'],
    ['high', counts.high||0, 'var(--high)'],
    ['forward secrecy', ((f.forward_secrecy_ratio ?? 0)*100).toFixed(0)+'%'],
    ['PQ-ready hosts', `${f.pq_ready_hosts ?? 0}/${f.host_count ?? 0}`],
    ['cleartext creds', f.cleartext_credential_sessions ?? 0,
      (f.cleartext_credential_sessions ? 'var(--critical)' : null)],
  ].map(([k,v,c]) => `<div class="stat"><div class="v" ${c?`style="color:${c}"`:''}>${v}</div>
      <div class="k">${k}</div></div>`).join('');

  $('#hosts').innerHTML = (R.hosts||[]).map(h => `<tr>
      <td class="mono">${esc(h.host)}</td>
      <td><span class="gradeletter g-${h.grade}" style="font-size:16px">${esc(h.grade)}</span></td>
      <td class="mono dim">${h.score}</td>
      <td class="mono dim">${(h.ports||[]).join(', ')}</td>
      <td class="mono dim">${esc(h.worst_tls_version)}</td>
      <td>${Object.entries(h.finding_counts||{})
            .sort((a,b)=>SEVRANK[b[0]]-SEVRANK[a[0]])
            .map(([s,n])=>`${sev(s)}&nbsp;${n}`).join(' ') || '<span class="faint">—</span>'}</td>
    </tr>`).join('');

  $('#queue').innerHTML = (R.prioritised_findings||[])
    .map((x,i)=>findingCard(x, i+1)).join('');

  $('#sessions').innerHTML = (R.sessions||[]).map(sessionCard).join('');

  const comp = Object.entries(f.compliance||{})
    .sort((a,b)=> (a[1]===b[1] ? a[0].localeCompare(b[0]) : (a[1]==='fail'?-1:1)));
  $('#compliance').innerHTML = comp.map(([k,v]) =>
    `<div class="compitem ${v}"><span>${esc(k)}</span>
     <span class="verdict">${v.toUpperCase()}</span></div>`).join('');

  /* USP-01 side by side: the same rule, opposite verdicts */
  const byRule = {};
  (R.prioritised_findings||[]).forEach(x => {
    if (!x.severity_adjustment_reason) return;
    (byRule[x.rule_id] = byRule[x.rule_id] || []).push(x);
  });
  const pairs = Object.values(byRule).filter(g =>
    new Set(g.map(x=>x.severity)).size > 1);
  if (pairs.length) {
    $('#usp1').innerHTML = pairs[0].map(x => `<div class="card">
      <h2>${esc(x.affected_host)}:${x.affected_port} <span class="tag">${esc(x.port_role)}</span></h2>
      <div style="font-size:13px;margin-bottom:8px">
        base ${sev(x.base_severity)} &nbsp;→&nbsp; ${sev(x.severity)}</div>
      <p class="dim" style="font-size:12.5px;margin:0">${esc(x.severity_adjustment_reason)}</p>
    </div>`).join('');
    $('#usp1-wrap').style.display = '';
  }

  const metrics = R.evaluation_metrics || {};
  if (Object.keys(metrics).length) {
    $('#metrics').innerHTML = Object.entries(metrics).map(([k,v]) =>
      `<div class="stat"><div class="v">${v}</div><div class="k">${esc(k.replace(/_/g,' '))}</div></div>`).join('');
    $('#metrics-wrap').style.display = '';
  }
}

/* ---------------- controls ---------------- */
function wireControls() {
  $$('[data-filter]').forEach(b => b.onclick = () => {
    $$('[data-filter]').forEach(x => x.classList.remove('on'));
    b.classList.add('on');
    const want = b.dataset.filter;
    $$('#queue .finding').forEach(el => {
      el.style.display = (want === 'all' || el.dataset.sev === want) ? '' : 'none';
    });
  });
  $('#expand').onclick = () => {
    const any = $$('details.sess').some(d => !d.open);
    $$('details.sess').forEach(d => d.open = any);
    $('#expand').textContent = any ? 'Collapse all' : 'Expand all';
  };
  $('#theme').onclick = () => {
    const light = document.documentElement.getAttribute('data-theme') === 'light';
    document.documentElement.setAttribute('data-theme', light ? 'dark' : 'light');
    $('#theme').textContent = light ? 'Light theme' : 'Dark theme';
  };
  $('#anomonly').onclick = () => {
    const on = $('#anomonly').classList.toggle('on');
    $$('details.sess').forEach(d => {
      d.style.display = (!on || d.dataset.anom === '1') ? '' : 'none';
    });
  };
}

render();
wireControls();
"""
