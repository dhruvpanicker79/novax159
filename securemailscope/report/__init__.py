"""S10 - report export. Deliverable D20, and D21 for the demo.

Three formats from ONE `Report` object, so they can never disagree:

    report.json   the machine-readable artifact the dashboard consumes
    report.html   a single self-contained file - no build step, no server
    report.pdf    the same HTML printed through headless Chromium (ADR-0007)

The HTML is deliberately one file with its CSS, script and data inlined. There
is no npm on the team's machines and no node, and after three separate
dependency blocks (ADR-0012, ADR-0017) a deliverable that needs a build step is
a deliverable that might not exist on demo day. A file you can email, open from
a USB stick or attach to an incident ticket is also simply more useful to the
four personas the PS names. See ADR-0018.

Persona views (USP-06) are the same data with different emphasis:

    soc                ranked triage queue, anomalies first
    forensics          evidence packet - hashes, frames, byte offsets
    incident_response  chronological timeline of encryption transitions
    administrator      per-host configuration diff and remediation batches
"""

from __future__ import annotations

import html as html_lib
import json
from datetime import datetime, timezone
from pathlib import Path

from schema import Persona, Report

from ..ml.priority import remediation_batches
from .assets import CSS, JS

__all__ = ["write_json", "write_html", "write_pdf", "write_persona", "write_all"]


# --------------------------------------------------------------------------- #
# JSON
# --------------------------------------------------------------------------- #


def write_json(report: Report, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report.to_json(), encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #

PERSONA_INTRO = {
    Persona.SOC: (
        "SOC triage view",
        "Ranked by what to do first. Priority folds in exploitability and blast "
        "radius, not severity alone, so an evidenced attack outranks an equally "
        "severe configuration issue."),
    Persona.FORENSICS: (
        "Digital forensics evidence packet",
        "Every finding traces to frame numbers and byte offsets under the "
        "capture's SHA-256. Open the original PCAP in Wireshark and verify any "
        "claim independently."),
    Persona.INCIDENT_RESPONSE: (
        "Incident response timeline",
        "Encryption transitions, credential exposures and attack evidence in the "
        "order they happened on the wire."),
    Persona.ADMINISTRATOR: (
        "Administrator remediation view",
        "Grouped by fix rather than by finding: one configuration change applied "
        "across every host that needs it."),
}


def _escape(text: str) -> str:
    return html_lib.escape(text, quote=True)


def _timeline_section(report: Report) -> str:
    """Chronological view for the incident-response persona."""
    rows: list[tuple[str, str, str, str]] = []
    for session in report.sessions:
        started = session.flow.started_at if session.flow else None
        stamp = started.strftime("%H:%M:%S") if started else "--:--:--"
        where = f"{session.server_host}:{session.server_port}"
        for phase in session.phases:
            rows.append((stamp, where, phase.kind.value,
                         ", ".join(phase.commands[:3])))
        if session.attack_evidence:
            for exposure in session.attack_evidence.credential_exposure:
                rows.append((stamp, where, "CREDENTIALS EXPOSED",
                             f"{exposure.mechanism} — {exposure.username or 'unknown user'}"))
            if session.attack_evidence.starttls_stripping_suspected:
                rows.append((stamp, where, "STARTTLS STRIPPED",
                             "capability mangled in transit"))
    rows.sort(key=lambda r: (r[0], r[1]))

    body = "".join(
        f'<tr><td class="mono">{_escape(t)}</td><td class="mono">{_escape(w)}</td>'
        f'<td class="mono {"dim" if k.islower() else ""}" '
        f'{"style=color:var(--critical)" if not k.islower() else ""}>{_escape(k)}</td>'
        f'<td class="dim">{_escape(d)}</td></tr>'
        for t, w, k, d in rows)
    return (
        '<h3 class="section"><span class="n">IR</span>Session timeline</h3>'
        '<div class="card"><table><thead><tr><th>Time</th><th>Endpoint</th>'
        '<th>Event</th><th>Detail</th></tr></thead>'
        f"<tbody>{body}</tbody></table></div>")


def _batches_section(report: Report) -> str:
    """Remediation grouped by fix, for the administrator persona."""
    blocks = []
    for batch in remediation_batches(report.prioritised_findings):
        remediation = batch.get("remediation") or {}
        snippets = "".join(
            f'<div class="faint mono" style="font-size:10.5px;margin-top:9px">{label}</div>'
            f'<pre class="snippet">{_escape(str(remediation[key]))}</pre>'
            for key, label in (("postfix", "Postfix"), ("dovecot", "Dovecot"),
                               ("exchange", "Exchange"), ("generic", "General"))
            if remediation.get(key))
        hosts = ", ".join(batch["hosts"][:8]) or "—"
        blocks.append(
            f'<div class="card" style="margin-bottom:10px">'
            f'<h2><span class="sev sev-{batch["severity"]}">{batch["severity"]}</span> '
            f'{_escape(str(batch["title"]))}'
            f'<span class="tag">{batch["host_count"]} host(s) &middot; '
            f'effort: {_escape(str(batch["effort"]))}</span></h2>'
            f'<div class="mono dim" style="font-size:11.5px">{_escape(hosts)}</div>'
            f'<p class="dim" style="font-size:13px">{_escape(str(remediation.get("summary","")))}</p>'
            f'{snippets}</div>')
    return ('<h3 class="section"><span class="n">O02</span>Remediation batches</h3>'
            '<p class="note">An administrator does not work finding by finding. '
            'This is the same data grouped by the change that fixes it.</p>'
            + "".join(blocks))


def build_html(report: Report, persona: Persona | None = None) -> str:
    """Render the full single-file report."""
    capture = report.capture
    title, intro = PERSONA_INTRO.get(persona, ("Cryptographic security posture", ""))
    generated = (report.generated_at or datetime.now(tz=timezone.utc))

    extra = ""
    if persona is Persona.INCIDENT_RESPONSE:
        extra = _timeline_section(report)
    elif persona is Persona.ADMINISTRATOR:
        extra = _batches_section(report)

    data = json.dumps(report.to_dict(), ensure_ascii=False)
    # A closing tag inside the JSON would end the <script> element early.
    data = data.replace("</", "<\\/")

    return f"""<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecureMailScope — {_escape(capture.filename if capture else "report")}</title>
<style>{CSS}</style>
</head>
<body>
<header><div class="wrap">
  <div class="brand">
    <h1>SecureMailScope</h1>
    <span class="sub">{_escape(title)}</span>
  </div>
  {f'<p class="note" style="margin:8px 0 0">{_escape(intro)}</p>' if intro else ''}
  <div class="capmeta">
    <span><b>capture</b> {_escape(capture.filename if capture else '—')}</span>
    <span><b>packets</b> {capture.packet_count if capture else 0:,}</span>
    <span><b>sha256</b> {_escape((capture.sha256 if capture else '')[:32])}…</span>
    <span><b>analysed</b> {generated:%Y-%m-%d %H:%M} UTC</span>
  </div>
</div></header>

<div class="wrap">

  <div class="grid hero" style="margin-bottom:18px">
    <div class="card gradebox">
      <div id="grade" class="gradeletter">?</div>
      <div id="gradescore" class="gradescore"></div>
      <div class="faint" style="font-size:10.5px;margin-top:6px">POSTURE · D19</div>
    </div>
    <div class="card">
      <h2>Executive summary</h2>
      <div id="summary" class="summary"></div>
    </div>
  </div>

  <div id="stats" class="stats"></div>

  <div id="usp1-wrap" style="display:none">
    <h3 class="section"><span class="n">USP-01</span>The same defect, judged by what the port is for</h3>
    <p class="note">Server-to-server SMTP is opportunistic by design (RFC 7435), so a certificate
      failure there is expected. On a port carrying credentials, RFC 8314 makes the identical
      defect critical. Generic TLS scanners apply one rule to both and drown analysts in false alarms.</p>
    <div id="usp1" class="grid cols-2"></div>
  </div>

  <h3 class="section"><span class="n">D19</span>Fleet posture</h3>
  <div class="card">
    <table><thead><tr><th>Host</th><th>Grade</th><th>Score</th><th>Ports</th>
      <th>Worst TLS</th><th>Findings</th></tr></thead>
      <tbody id="hosts"></tbody></table>
  </div>

  <h3 class="section"><span class="n">D18</span>Triage queue</h3>
  <p class="note">Ranked by severity, then by exploitability, blast radius and how many hosts
    one fix would cover. Expand any finding for its evidence, the standards it breaches and the
    configuration change that resolves it.</p>
  <div class="controls noprint">
    <button class="f on" data-filter="all">All</button>
    <button class="f" data-filter="critical">Critical</button>
    <button class="f" data-filter="high">High</button>
    <button class="f" data-filter="medium">Medium</button>
    <button class="f" data-filter="low">Low</button>
    <button class="f" data-filter="info">Info</button>
    <span class="spacer"></span>
    <button class="f" id="theme">Light theme</button>
  </div>
  <div id="queue"></div>

  {extra}

  <h3 class="section"><span class="n">D01–D17</span>Sessions</h3>
  <p class="note">Every reconstructed mail session, with its handshake, STARTTLS validation,
    certificate chain, risk explanation and anomaly score.</p>
  <div class="controls noprint">
    <button class="f" id="expand">Expand all</button>
    <button class="f" id="anomonly">Anomalies only</button>
  </div>
  <div id="sessions"></div>

  <h3 class="section"><span class="n">USP-08</span>Compliance report card</h3>
  <p class="note">A standard is marked FAIL only where a finding cites it as breached.
    Documents quoted to explain our reasoning — RFC 7435 for the relay downgrade, for
    instance — are not counted as failures.</p>
  <div id="compliance" class="comp"></div>

  <div id="metrics-wrap" style="display:none">
    <h3 class="section"><span class="n">USP-07</span>Measured accuracy</h3>
    <p class="note">Precision and recall against the ground-truth corpus in
      <span class="mono">testbed/manifest.json</span>, where every capture states
      exactly what was configured.</p>
    <div id="metrics" class="stats"></div>
  </div>

  <footer>
    SecureMailScope · passive cryptographic posture assessment for email infrastructure ·
    schema {_escape(report.schema_version)} · generated {generated:%Y-%m-%d %H:%M} UTC<br>
    No traffic was decrypted. Every finding is derived from data observable without keys.
  </footer>
</div>

<script id="report-data" type="application/json">{data}</script>
<script>{JS}</script>
</body>
</html>"""


def write_html(report: Report, path: str | Path,
               persona: Persona | None = None) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(build_html(report, persona), encoding="utf-8")
    return path


def write_persona(report: Report, persona: Persona, directory: str | Path) -> Path:
    return write_html(report, Path(directory) / f"report-{persona.value}.html", persona)


# --------------------------------------------------------------------------- #
# PDF
# --------------------------------------------------------------------------- #


def write_pdf(report: Report, path: str | Path) -> Path | None:
    """Print the HTML to PDF through headless Chromium (ADR-0007).

    Returns None, with an explanation, when Playwright is unavailable - which
    it currently is on the team's Windows machines. The HTML is the deliverable
    either way and any browser's Print to PDF produces the same document, so a
    missing Playwright degrades the export rather than the report.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    source = path.with_suffix(".html")
    write_html(report, source)

    try:
        from playwright.sync_api import sync_playwright  # noqa: PLC0415
    except Exception as exc:  # noqa: BLE001
        print(f"[report] PDF export unavailable ({type(exc).__name__}). "
              f"The HTML is at {source}; any browser's Print to PDF produces "
              f"the same document, and the print stylesheet is already applied.")
        return None

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        page.goto(source.resolve().as_uri())
        page.emulate_media(media="print")
        page.pdf(path=str(path), format="A4", print_background=True,
                 margin={"top": "14mm", "bottom": "14mm",
                         "left": "12mm", "right": "12mm"})
        browser.close()
    return path


# --------------------------------------------------------------------------- #
# Everything at once
# --------------------------------------------------------------------------- #


def write_all(report: Report, directory: str | Path) -> dict[str, Path | None]:
    """Write every export. Deliverable D20, plus the four persona views."""
    directory = Path(directory)
    out: dict[str, Path | None] = {
        "json": write_json(report, directory / "report.json"),
        "html": write_html(report, directory / "report.html"),
        "pdf": write_pdf(report, directory / "report.pdf"),
    }
    for persona in Persona:
        out[persona.value] = write_persona(report, persona, directory)
    return out
