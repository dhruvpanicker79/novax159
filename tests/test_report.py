"""Tests for S10 - report export. Deliverable D20, and D21 for the demo.

The HTML is a single self-contained file, so these tests check that it really
is self-contained and that the embedded data survives escaping. A report that
silently loses its script when opened from a USB stick is worse than no report.

Run:  python tests/test_report.py
"""

from __future__ import annotations

import json
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "testbed"))

import synth  # noqa: E402

from schema import Persona, Report  # noqa: E402
from securemailscope.pipeline import analyse  # noqa: E402
from securemailscope.report import build_html, write_all, write_html, write_json  # noqa: E402

_TMP = Path(tempfile.mkdtemp(prefix="sms-report-"))
_CACHE: dict[str, Report] = {}


def _report() -> Report:
    if "r" not in _CACHE:
        pcap = _TMP / "fleet.pcap"
        synth.write_pcap(pcap, [factory() for factory in synth.SCENARIOS.values()])
        _CACHE["r"] = analyse(
            pcap, trust_store_paths=[str(ROOT / "testbed" / "certs" / "_ca.der")])
    return _CACHE["r"]


def _html() -> str:
    if "h" not in _CACHE:
        _CACHE["h"] = build_html(_report())
    return _CACHE["h"]


# --------------------------------------------------------------------------- #
# JSON
# --------------------------------------------------------------------------- #


def test_json_round_trips():
    path = write_json(_report(), _TMP / "report.json")
    restored = Report.from_json(path.read_text(encoding="utf-8"))
    assert len(restored.sessions) == len(_report().sessions)
    assert restored.fleet.grade is _report().fleet.grade


# --------------------------------------------------------------------------- #
# HTML: self-containment
# --------------------------------------------------------------------------- #


def _markup_outside_data(html: str) -> str:
    """The document with the JSON data island removed.

    The island legitimately contains RFC URLs as *data* - they are reference
    links in the findings, never fetched. What matters is that the markup
    itself pulls nothing from the network.
    """
    island = re.search(
        r'<script id="report-data" type="application/json">.*?</script>', html, re.S)
    assert island, "the data island is missing"
    return html[: island.start()] + html[island.end():]


def test_html_markup_makes_no_external_requests():
    """No CDN, no font host, no build step. It must work offline and from a
    USB stick, which is how an incident report actually travels."""
    markup = _markup_outside_data(_html())
    for pattern in ("http://", "https://", "<link ", "src=", "@import"):
        assert pattern not in markup, f"external reference found in markup: {pattern}"


def test_html_embeds_everything_inline():
    html = _html()
    assert "<style>" in html and "</style>" in html
    assert '<script id="report-data" type="application/json">' in html
    assert html.count("<script") == 2, "styles, data and behaviour only"


def test_embedded_data_is_valid_json():
    html = _html()
    match = re.search(
        r'<script id="report-data" type="application/json">(.*?)</script>',
        html, re.S)
    assert match, "the data island is missing"
    payload = match.group(1).replace("<\\/", "</")
    data = json.loads(payload)
    assert len(data["sessions"]) == len(_report().sessions)
    assert data["fleet"]["grade"] == _report().fleet.grade.value


def test_closing_tags_in_data_are_escaped():
    """A '</script>' inside the JSON would end the element early and blank the
    page. Remediation text contains angle brackets, so this is not theoretical."""
    html = _html()
    island = re.search(
        r'<script id="report-data" type="application/json">(.*?)</script>',
        html, re.S).group(1)
    assert "</script" not in island.lower()


def test_attacker_controlled_text_never_reaches_the_markup():
    """Banners, capability lines and SNI all come from the observed server, so
    a hostile one could try to inject markup into the report.

    The payload is allowed to sit inside the JSON data island - that element is
    `type="application/json"`, so the browser does not execute it, and the
    script escapes every value before inserting it. What must never happen is
    the payload appearing in the document markup itself.
    """
    report = _report()
    original = report.fleet.summary
    try:
        report.fleet.summary = '<img src=x onerror=alert(1)> & "quoted"'
        markup = _markup_outside_data(build_html(report))
        assert "<img src=x onerror" not in markup
        assert "onerror" not in markup
    finally:
        report.fleet.summary = original


# --------------------------------------------------------------------------- #
# HTML: content
# --------------------------------------------------------------------------- #


def test_html_names_the_capture_and_its_hash():
    """Chain of custody starts here: the report must say which file it read."""
    html = _html()
    capture = _report().capture
    assert capture.filename in html
    assert capture.sha256[:32] in html


def test_html_states_that_nothing_was_decrypted():
    assert "No traffic was decrypted" in _html()


def test_deliverable_markers_present():
    """Each section is labelled with the deliverable it satisfies, so a judge
    can follow the traceability matrix through the report itself."""
    html = _html()
    for marker in ("D19", "D18", "D01–D17", "USP-01", "USP-08", "D02", "D04"):
        assert marker in html, marker


def test_print_stylesheet_exists():
    """PDF export is the same HTML printed, so the print rules matter."""
    assert "@media print" in _html()


def test_light_theme_defined_for_printing():
    assert '[data-theme="light"]' in _html()


# --------------------------------------------------------------------------- #
# Persona views (USP-06)
# --------------------------------------------------------------------------- #


def test_every_persona_renders():
    for persona in Persona:
        html = build_html(_report(), persona)
        assert len(html) > 10_000, persona


def test_incident_response_view_adds_a_timeline():
    html = build_html(_report(), Persona.INCIDENT_RESPONSE)
    assert "Session timeline" in html
    assert "Session timeline" not in build_html(_report())


def test_administrator_view_groups_by_fix():
    html = build_html(_report(), Persona.ADMINISTRATOR)
    assert "Remediation batches" in html
    assert "host(s)" in html


def test_forensics_view_emphasises_provenance():
    html = build_html(_report(), Persona.FORENSICS)
    assert "byte offsets" in html
    assert "SHA-256" in html


def test_personas_share_one_analysis():
    """One analysis, four audiences - the data must be identical."""
    base = re.search(r'report-data" type="application/json">(.*?)</script>',
                     build_html(_report()), re.S).group(1)
    for persona in Persona:
        other = re.search(r'report-data" type="application/json">(.*?)</script>',
                          build_html(_report(), persona), re.S).group(1)
        assert other == base, persona


# --------------------------------------------------------------------------- #
# write_all
# --------------------------------------------------------------------------- #


def test_write_all_produces_every_export():
    out = write_all(_report(), _TMP / "all")
    assert out["json"].exists()
    assert out["html"].exists()
    for persona in Persona:
        assert out[persona.value].exists()


def test_missing_playwright_degrades_rather_than_fails():
    """PDF is optional; the HTML is the deliverable. A missing dependency must
    not take the whole export down."""
    out = write_all(_report(), _TMP / "degraded")
    assert out["html"].exists()
    assert out["pdf"] is None or out["pdf"].exists()


def test_html_file_is_openable_standalone():
    path = write_html(_report(), _TMP / "standalone.html")
    text = path.read_text(encoding="utf-8")
    assert text.startswith("<!doctype html>")
    assert text.rstrip().endswith("</html>")
    assert path.stat().st_size > 50_000


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(list(globals().items())):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  PASS  {name}")
            except AssertionError as exc:
                failures += 1
                print(f"  FAIL  {name}: {exc}")
            except Exception as exc:  # noqa: BLE001
                failures += 1
                print(f"  ERROR {name}: {type(exc).__name__}: {exc}")
    print(f"\n{failures} failure(s)")
    sys.exit(1 if failures else 0)
