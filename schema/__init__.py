"""SecureMailScope data contract.

Zero dependencies by design (ADR-0009): every module in the project imports
this package, so it must never be the thing that fails to install.

    from schema import MailSession, Finding, Severity

Full model documentation: docs/03_ARCHITECTURE.md
"""

from .base import Evidence, JsonModel, from_dict, to_dict
from .enums import (
    ChainStatus,
    Confidence,
    FindingCategory,
    Grade,
    KeyExchange,
    MailProtocol,
    Persona,
    PhaseKind,
    PortRole,
    PubKeyAlgorithm,
    Severity,
    SignatureAlgorithm,
    TlsMode,
    TlsVersion,
)
from .models import (
    PORT_TABLE,
    SCHEMA_VERSION,
    AttackEvidence,
    Capture,
    CategoryScore,
    Certificate,
    ChainResult,
    ClientHelloInfo,
    CredentialExposure,
    FeatureVector,
    Finding,
    FleetPosture,
    Flow,
    HostPosture,
    MailSession,
    Phase,
    ActionItem,
    HostDrift,
    Narrative,
    PostureDrift,
    Remediation,
    Report,
    ServerHelloInfo,
    SessionAssessment,
    ShapContribution,
    StandardRef,
    StarttlsValidation,
    TlsHandshake,
)

__all__ = [
    "SCHEMA_VERSION",
    "PORT_TABLE",
    # base
    "Evidence",
    "JsonModel",
    "to_dict",
    "from_dict",
    # enums
    "ChainStatus",
    "Confidence",
    "FindingCategory",
    "Grade",
    "KeyExchange",
    "MailProtocol",
    "Persona",
    "PhaseKind",
    "PortRole",
    "PubKeyAlgorithm",
    "Severity",
    "SignatureAlgorithm",
    "TlsMode",
    "TlsVersion",
    # models
    "AttackEvidence",
    "Capture",
    "CategoryScore",
    "Certificate",
    "ChainResult",
    "ClientHelloInfo",
    "CredentialExposure",
    "FeatureVector",
    "Finding",
    "FleetPosture",
    "Flow",
    "HostPosture",
    "MailSession",
    "Phase",
    "ActionItem",
    "HostDrift",
    "Narrative",
    "PostureDrift",
    "Remediation",
    "Report",
    "ServerHelloInfo",
    "SessionAssessment",
    "ShapContribution",
    "StandardRef",
    "StarttlsValidation",
    "TlsHandshake",
]
