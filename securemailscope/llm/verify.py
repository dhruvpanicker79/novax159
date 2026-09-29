"""Check generated prose against the fact sheet before trusting it.

The rule this project runs on is that every claim must be checkable against
the capture. A language model breaks that by construction: it produces fluent
text whose relationship to the input is unverified, and the failure mode is not
gibberish — it is a *plausible* host, a *plausible* CVE, a rule identifier that
sounds exactly like one of ours. In a security report, a confident invented
fact is worse than no report.

So generated text is treated as untrusted input and mechanically checked
before it is allowed near the output:

* every IPv4/IPv6 address must be one the capture contained;
* every `RULE-STYLE-IDENTIFIER` must be a rule that actually fired;
* every RFC, NIST or CVE reference must be one the rule pack cited;
* the severity words must not contradict the counts;
* numbers presented as session or host counts must match.

Anything unverifiable means the whole narrative is discarded and the
deterministic template is used instead. Not "flagged" — discarded. A partially
hallucinated report is not a degraded report, it is an untrustworthy one, and
the template is always available and always correct.

This is the guardrail that makes the layer defensible rather than decorative
(ADR-0028).
"""

from __future__ import annotations

import ipaddress
import re

from .grounding import FactSheet

#: Things that look like one of our rule identifiers: CAPS-WITH-HYPHENS.
_RULE_RE = re.compile(r"\b[A-Z][A-Z0-9]+(?:-[A-Z0-9]+){1,5}\b")
#: Standards references in the forms the rule pack uses.
_STD_RE = re.compile(r"\b(?:RFC\s?\d{3,5}|NIST\s?SP\s?[\d-]+|FIPS\s?\d{3}|CVE-\d{4}-\d{4,7})\b",
                     re.I)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
#: DNS-style names. A fabricated `mail.corp.internal` is the most natural
#: thing for a model to write and the easiest to believe, so hostnames have
#: to be checked as well as addresses.
_HOST_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b", re.I)
#: Trailing labels that make a token a filename rather than a hostname.
_FILE_SUFFIXES = {
    "pcap", "pcapng", "json", "html", "htm", "csv", "md", "txt", "log", "py",
    "pem", "crt", "cer", "der", "key", "conf", "cf", "cnf", "db", "sqlite",
    "ipynb", "ts", "js", "css", "yml", "yaml", "toml", "ini", "sh",
}
_IPV6_RE = re.compile(r"\b(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b", re.I)

#: Rule-shaped tokens that are not rule identifiers and must not be flagged.
_ALLOWED_TOKENS = {
    "TLS", "SSL", "SMTP", "IMAP", "POP3", "STARTTLS", "AUTH", "EHLO", "HELO",
    "MTA-STS", "DANE", "TLSA", "DNSSEC", "SHA-1", "SHA-256", "SHA-384", "MD5",
    "RSA", "ECDSA", "DSA", "DH", "ECDHE", "DHE", "AES", "GCM", "CBC", "CCM",
    "CHACHA20", "POLY1305", "3DES", "RC4", "PFS", "SNI", "JA3", "JA3S", "CA",
    "X-509", "X509", "DER", "PEM", "PKI", "MITM", "SOC", "SIEM", "CEF", "ECS",
    "CERT-IN", "DPDP", "BEC", "IP", "TCP", "UDP", "DNS", "HTTP", "HTTPS",
    "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "PASS", "FAIL", "OK",
    "NOT-APPLICABLE", "OPAQUE-TLS13", "POST-QUANTUM", "PQ", "ML-KEM", "X25519",
}


def _normalise_std(text: str) -> str:
    return re.sub(r"\s+", " ", text).upper().replace("RFC ", "RFC ")


def _standards_vocabulary(sheet: FactSheet) -> set[str]:
    vocab = set()
    for item in sheet.allowed_standards:
        vocab.add(_normalise_std(item))
        # "RFC 8314" also licenses "RFC8314".
        vocab.add(_normalise_std(item).replace(" ", ""))
    for issue in sheet.issues:
        for std in issue["standards_violated"]:
            vocab.add(_normalise_std(std))
            vocab.add(_normalise_std(std).replace(" ", ""))
    return vocab


def check(text: str, sheet: FactSheet) -> list[str]:
    """Return the list of problems. Empty means the text is grounded.

    Deliberately strict: a false rejection costs a nicer paragraph, a false
    acceptance costs the one property this tool sells.
    """
    problems: list[str] = []

    # -- addresses --------------------------------------------------------- #
    for candidate in set(_IPV4_RE.findall(text)):
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue                            # a version number, not an address
        if candidate not in sheet.allowed_hosts:
            problems.append(f"host not in capture: {candidate}")

    for candidate in set(_IPV6_RE.findall(text)):
        if candidate.count(":") < 2:
            continue                            # a time, or a ratio
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if candidate not in sheet.allowed_hosts:
            problems.append(f"host not in capture: {candidate}")

    for candidate in set(_HOST_RE.findall(text)):
        lowered_c = candidate.lower()
        if lowered_c == sheet.capture_name.lower():
            continue                        # the capture's own filename
        if lowered_c.rsplit(".", 1)[-1] in _FILE_SUFFIXES:
            continue                        # a filename, not a host
        if _IPV4_RE.fullmatch(candidate):
            continue                        # already checked as an address
        if lowered_c in {h.lower() for h in sheet.allowed_hosts}:
            continue
        problems.append(f"host not in capture: {candidate}")

    # -- rule identifiers -------------------------------------------------- #
    for token in set(_RULE_RE.findall(text)):
        if token in _ALLOWED_TOKENS or token in sheet.allowed_rules:
            continue
        if _STD_RE.fullmatch(token):
            continue
        if token.replace("-", "") in {t.replace("-", "") for t in _ALLOWED_TOKENS}:
            continue
        problems.append(f"rule identifier did not fire: {token}")

    # -- standards and CVEs ------------------------------------------------ #
    vocab = _standards_vocabulary(sheet)
    for raw in set(_STD_RE.findall(text)):
        norm = _normalise_std(raw)
        tight = norm.replace(" ", "")
        # Prefix in either direction: the rule pack cites "NIST SP 800-52 Rev 2",
        # prose says "NIST SP 800-52", and both name the same document.
        if any(v == norm or v == tight or v.startswith(norm)
               or v.replace(" ", "").startswith(tight)
               for v in vocab):
            continue
        problems.append(f"standard not cited by any finding: {raw}")

    # -- claims that contradict the counts --------------------------------- #
    counts = sheet.severity_counts
    lowered = text.lower()
    if not counts.get("critical") and re.search(r"\bcritical (finding|issue|risk)", lowered):
        problems.append("claims a critical finding when there are none")
    if sheet.finding_count == 0 and re.search(r"\b(vulnerab|weakness|finding)", lowered):
        if not re.search(r"\bno\b[^.]{0,30}\b(vulnerab|weakness|finding)", lowered):
            problems.append("describes findings in a report that has none")
    if sheet.cleartext_credential_sessions == 0 and "credential" in lowered:
        if re.search(r"credentials?\s+(were|was)\s+(sent|transmitted|exposed|captured)",
                     lowered):
            problems.append("claims credential exposure that was not observed")

    return problems


def verdict(text: str, sheet: FactSheet) -> tuple[bool, str]:
    """`(ok, reason)`. Reason is "passed" or the first few problems found."""
    problems = check(text, sheet)
    if not problems:
        return True, "passed"
    shown = "; ".join(problems[:3])
    more = f" (+{len(problems) - 3} more)" if len(problems) > 3 else ""
    return False, f"rejected: {shown}{more}"
