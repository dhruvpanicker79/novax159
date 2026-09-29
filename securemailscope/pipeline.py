"""The orchestrator: PCAP in, `Report` out.

Wires the stages together in order and is the single place that knows how they
connect. Stages that are not built yet are simply skipped, so the pipeline runs
end to end today and gets more complete as each one lands - which is what lets
the frontend and reporting work against real output rather than waiting.

    from securemailscope.pipeline import analyse
    report = analyse("testbed/out/fleet.pcap")

Current coverage:
    S0  ingest            done
    S1  reassembly        done
    S2  protocol ID       done
    S3  STARTTLS phase    done
    S4  TLS handshake     done
    S5  certificates      done (pure-Python DER; RSA signatures verified)
    S6  rules             done
    S7  features          done
    S8  AI layers         done (rule baseline; trained model needs WSL)
    S9  aggregation       partial - fleet rollup below, full scoring pending
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from schema import (
    CategoryScore,
    Evidence,
    Finding,
    FindingCategory,
    FleetPosture,
    Grade,
    HostPosture,
    MailSession,
    Remediation,
    Report,
    Severity,
    TlsMode,
    TlsVersion,
)

from . import certs as certs_stage
from . import features as features_stage
from .capture.ingest import load_capture
from .capture.reassemble import reassemble
from .ml import anomaly as anomaly_stage
from .ml import priority as priority_stage
from .ml.classifier import RiskModel
from . import tls
from .proto import detect, starttls
from .rules import pack


def _coverage_finding(capture, sessions) -> Finding | None:
    """Flag a capture we could not read, rather than reporting it as clean.

    Three distinct situations, and only the first two are our problem:

    * **link layer not supported** — we decoded nothing at all. The capture may
      be full of mail and we cannot see it.
    * **decoded, but almost nothing came through** — a truncated file, or a
      link type we half-understand.
    * **decoded fine, no mail** — a perfectly good capture of something else.
      That is not a finding, it is an answer.
    """
    decoded = capture.decoded_frame_count
    frames = capture.packet_count or 0
    if not frames:
        return None

    unsupported = capture.link_type.startswith("unsupported")
    blind = decoded == 0
    thin = 0 < decoded < frames * 0.2

    if not (unsupported or blind or thin):
        return None

    detail = (f"Link type {capture.link_type}: {decoded} of {frames} frames could "
              f"be decoded. {capture.link_layer_note}")
    return Finding(
        rule_id="ANALYSIS-CAPTURE-NOT-READABLE",
        title="Capture could not be read",
        category=FindingCategory.CONFIGURATION,
        base_severity=Severity.HIGH if blind or unsupported else Severity.MEDIUM,
        severity=Severity.HIGH if blind or unsupported else Severity.MEDIUM,
        description=(
            "The capture's link layer could not be decoded, so no mail sessions "
            "could be reconstructed from it. **This is not a clean result** - it "
            "is an absence of evidence, and nothing in this report should be read "
            "as a statement about the security of the hosts in this file. "
            + detail),
        affected_host=capture.filename,
        affected_port=0,
        evidence=Evidence(capture_sha256=capture.sha256, stream_id=-1,
                          note="capture-level coverage check"),
        remediation=Remediation(
            summary=("Re-capture with a supported link layer, or convert the file: "
                     "`tcpdump -r in.pcap -w out.pcap` on a host whose libpcap "
                     "writes Ethernet or raw IP. Supported: Ethernet (including "
                     "802.1Q and QinQ), Linux cooked capture v1 and v2, raw IPv4 "
                     "and IPv6, and BSD loopback."),
            effort="trivial", risk_of_change="None - this is a capture problem."),
    )


def analyse(pcap_path: str | Path, model_dir: str | Path = "models",
            trust_store_paths: list[str] | None = None) -> Report:
    """Run every available stage over a capture and build the report."""
    capture = load_capture(pcap_path)
    model = RiskModel.load(model_dir)

    trust_store = None
    if trust_store_paths:
        from .certs.chain import load_trust_store
        trust_store = load_trust_store(trust_store_paths)

    # Certificate-substitution detection is per capture, not per process.
    certs_stage.reset_fingerprint_cache()

    sessions: list[MailSession] = []
    for flow in reassemble(capture):
        session = detect.identify(flow)
        if session is None:
            continue                      # not mail; correctly ignored
        starttls.attach(session, flow)    # S3
        tls.attach(session, flow)         # S4
        certs_stage.attach(session, flow, trust_store)   # S5
        sessions.append(session)

    # -- coverage: an unreadable capture must never read as a clean one -----
    # If the link layer could not be decoded there are no sessions, and a
    # report with no sessions and no findings is indistinguishable from a
    # healthy estate. Say so instead. Same rule as ADR-0014, one layer down.
    coverage = _coverage_finding(capture, sessions)

    # -- S7, then the fleet baseline the anomaly layer needs ---------------
    for session in sessions:
        session.features = features_stage.extract(session)

    # -- S6 must run BEFORE the baseline -----------------------------------
    # The anomaly layer learns "normal" from this capture, so it has to know
    # which sessions are compromised first. Building the baseline over every
    # session lets the attacks define normal, and the more hosts are
    # compromised the less anomalous compromise looks. See ADR-0019.
    contexts: dict[str, pack.RuleContext] = {}
    all_findings = []
    for session in sessions:
        ctx = pack.RuleContext(
            session.features, host=session.server_host,
            port=session.server_port, port_role=session.port_role,
            evidence=session.evidence,
        )
        contexts[session.session_id] = ctx
        session.findings = pack.evaluate(ctx)
        for finding in session.findings:
            finding.session_ids = [session.session_id]
        all_findings.extend(session.findings)

    scored = [s for s in sessions if s.features]
    contaminated = [
        any(f.severity.rank >= Severity.HIGH.rank for f in s.findings)
        for s in scored
    ]
    baseline = anomaly_stage.FleetBaseline.build(
        [(s.features,
          s.handshake.client_hello.ja3 if s.handshake and s.handshake.client_hello else None,
          s.handshake.server_hello.ja3s if s.handshake and s.handshake.server_hello else None)
         for s in scored],
        contaminated=contaminated,
    )

    # -- S8 -----------------------------------------------------------------
    for session in sessions:
        ctx = contexts[session.session_id]
        session.assessment = model.assess(ctx, session.findings)

        result = anomaly_stage.detect(
            session.features, baseline,
            ja3=(session.handshake.client_hello.ja3
                 if session.handshake and session.handshake.client_hello else None),
            ja3s=(session.handshake.server_hello.ja3s
                  if session.handshake and session.handshake.server_hello else None),
        )
        session.assessment.anomaly_score = result.score
        session.assessment.is_anomalous = result.is_anomalous
        session.assessment.anomaly_reasons = result.reasons

    if coverage is not None:
        all_findings.append(coverage)

    ordered, _ = priority_stage.prioritise(all_findings, sessions)

    hosts = _roll_up_hosts(sessions)
    fleet = _roll_up_fleet(sessions, hosts, all_findings)

    report = Report(
        capture=capture,
        sessions=sessions,
        hosts=hosts,
        fleet=fleet,
        prioritised_findings=ordered,
        executive_summary=fleet.summary,
        generated_at=datetime.now(tz=timezone.utc),
    )

    # USP-09: named attacks with a verdict, including the ones ruled out. Runs
    # before the narrative so the summary could quote it later if wanted.
    from .attacks import assess
    report.attack_matrix = assess(report)

    # S8 layer 3 (O02, USP-04). Deterministic by default: no network, no model,
    # no API key. It writes *about* the rule engine's output and is structurally
    # unable to change it - it is handed the finished report, and only the
    # `narrative` field of that report comes back.
    from .llm import narrate
    report.narrative = narrate(report)
    return report


# --------------------------------------------------------------------------- #
# S9 - aggregation
# --------------------------------------------------------------------------- #


def _grade(score: float) -> Grade:
    for threshold, grade in ((95, Grade.A_PLUS), (85, Grade.A), (75, Grade.B),
                             (60, Grade.C), (45, Grade.D), (25, Grade.E)):
        if score >= threshold:
            return grade
    return Grade.F


def _roll_up_hosts(sessions: list[MailSession]) -> list[HostPosture]:
    hosts: dict[str, HostPosture] = {}
    for s in sessions:
        host = s.server_host or "unknown"
        hp = hosts.setdefault(host, HostPosture(host=host))
        if s.server_port not in hp.ports:
            hp.ports.append(s.server_port)
        if s.protocol not in hp.protocols:
            hp.protocols.append(s.protocol)
        hp.session_count += 1
        if s.handshake and s.handshake.pq_ready:
            hp.pq_ready = True
        for f in s.findings:
            hp.finding_counts[f.severity.value] = hp.finding_counts.get(f.severity.value, 0) + 1

    for host, hp in hosts.items():
        group = [s for s in sessions if (s.server_host or "unknown") == host]
        worst = max((s.assessment.risk_score for s in group if s.assessment), default=0.0)
        hp.score = round(max(0.0, 100.0 - worst * 100), 1)

        # Capping rule. An average that hides a catastrophe is worse than no
        # score: one session leaking credentials means the host is an F,
        # whatever the other sessions look like.
        if any(s.features and s.features.credentials_in_cleartext for s in group):
            hp.score = min(hp.score, 10.0)

        hp.grade = _grade(hp.score)

        # If we could not inspect the host's encrypted sessions, we have not
        # earned the right to grade it. "?" is the honest answer; A+ would
        # claim we looked and found nothing wrong.
        incomplete = any(f.rule_id == "ANALYSIS-INCOMPLETE-HANDSHAKE"
                         for s in group for f in s.findings)
        if incomplete and hp.grade in (Grade.A_PLUS, Grade.A, Grade.B):
            hp.grade = Grade.INCOMPLETE
        encrypted = [s for s in group if s.tls_mode is not TlsMode.CLEARTEXT]
        pfs = [s for s in encrypted if s.handshake and s.handshake.has_forward_secrecy]
        hp.forward_secrecy_ratio = round(len(pfs) / len(encrypted), 2) if encrypted else 0.0
        versions = [s.handshake.negotiated_version for s in group if s.handshake]
        hp.worst_tls_version = (min(versions, key=lambda v: v.numeric)
                                if versions else TlsVersion.UNKNOWN)
        hp.top_findings = sorted((f for s in group for f in s.findings),
                                 key=lambda f: -f.severity.rank)[:3]
    return sorted(hosts.values(), key=lambda h: h.score)


def _roll_up_fleet(sessions: list[MailSession], hosts: list[HostPosture],
                   findings: list) -> FleetPosture:
    encrypted = [s for s in sessions if s.tls_mode is not TlsMode.CLEARTEXT]
    pfs = [s for s in encrypted if s.handshake and s.handshake.has_forward_secrecy]
    score = round(sum(h.score for h in hosts) / len(hosts), 1) if hosts else 100.0

    by_category: dict[FindingCategory, list] = {}
    for f in findings:
        by_category.setdefault(f.category, []).append(f)
    category_scores = [
        CategoryScore(
            category=category,
            score=round(max(0.0, 100.0 - 22.0 * sum(x.severity.rank for x in group)
                            / max(len(group), 1) * len(group) / max(len(sessions), 1) * 4), 1),
            finding_count=len(group),
            worst_severity=max((x.severity for x in group), key=lambda s: s.rank),
        )
        for category, group in sorted(by_category.items(), key=lambda kv: kv[0].value)
    ]

    exposed = sum(1 for s in sessions
                  if s.features and s.features.credentials_in_cleartext)
    deprecated = sum(1 for s in sessions
                     if s.handshake and s.handshake.negotiated_version.is_deprecated)

    if exposed:
        summary = (f"{exposed} of {len(sessions)} sessions authenticated over an "
                   f"unencrypted channel. Treat every credential in this capture as "
                   f"compromised before addressing anything else.")
    elif deprecated:
        summary = (f"{deprecated} sessions negotiated a deprecated TLS version. "
                   f"No credential exposure was observed.")
    else:
        summary = (f"No credential exposure or deprecated protocol versions observed "
                   f"across {len(sessions)} sessions on {len(hosts)} hosts.")

    # State coverage gaps in the executive line. A host scoring well because we
    # could not parse its handshake is more dangerous than an unscored host,
    # and the summary is the one sentence a decision-maker actually reads.
    unparsed = sum(1 for f in findings if f.rule_id == "ANALYSIS-INCOMPLETE-HANDSHAKE")
    if unparsed:
        noun = "session" if unparsed == 1 else "sessions"
        pronoun = "its score reflects" if unparsed == 1 else "their scores reflect"
        summary += (f" Coverage is partial: {unparsed} encrypted {noun} could not be "
                    f"inspected, so {pronoun} what was observable, not a clean result.")

    # A capture we could not read must not grade. Scoring 100/100 because no
    # findings could be produced is the exact failure ADR-0014 exists to stop,
    # one layer further down: absence of evidence is not evidence of absence.
    unreadable = any(f.rule_id == "ANALYSIS-CAPTURE-NOT-READABLE" for f in findings)
    if unreadable:
        grade, score = Grade.INCOMPLETE, 0.0
        summary = ("This capture could not be read, so no posture was assessed. "
                   "The grade is '?' rather than a score: nothing here is a "
                   "statement about these hosts, only about the file.")
    else:
        grade = _grade(score)

    return FleetPosture(
        score=score, grade=grade,
        host_count=len(hosts), session_count=len(sessions),
        category_scores=category_scores,
        forward_secrecy_ratio=round(len(pfs) / len(encrypted), 2) if encrypted else 0.0,
        pq_ready_hosts=sum(1 for h in hosts if h.pq_ready),
        deprecated_version_sessions=deprecated,
        cleartext_credential_sessions=exposed,
        compliance=pack.compliance_report(findings),
        summary=summary,
    )
