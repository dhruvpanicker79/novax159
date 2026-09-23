"""S4 - JA3 / JA3S fingerprints. Feeds the anomaly layer (USP-04 layer 2).

    JA3  = MD5( SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats )
    JA3S = MD5( SSLVersion,Cipher,Extensions )

Fields are decimal, comma-separated between fields and hyphen-separated within
a list. GREASE values (RFC 8701) MUST be removed first - they are randomised
per connection, so leaving them in makes every fingerprint unique and destroys
the rarity signal the anomaly layer depends on. That is the single most common
way a JA3 implementation is quietly wrong: it still produces a hash, it just
produces a useless one.

The version field is the *legacy* version from the hello, not the negotiated
one. That is what the original JA3 specification uses, and matching it is the
whole point - a fingerprint nobody else computes the same way cannot be
compared against public threat intelligence.
"""

from __future__ import annotations

import hashlib

from schema import ClientHelloInfo, ServerHelloInfo

from .ciphers import (
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
    TLS_FALLBACK_SCSV,
    is_grease,
)

_RAW_VERSIONS = {
    "ssl2": 512, "ssl3": 768, "tls1.0": 769,
    "tls1.1": 770, "tls1.2": 771, "tls1.3": 772,
}

#: Signalling values, not real cipher suites. JA3 excludes them along with
#: GREASE, since their presence depends on retry state rather than on the
#: client's identity.
_NOT_REAL_SUITES = {TLS_FALLBACK_SCSV, TLS_EMPTY_RENEGOTIATION_INFO_SCSV}


def _join(values: list[int]) -> str:
    return "-".join(str(v) for v in values)


def _clean(values: list[int], extra_excluded: set[int] | None = None) -> list[int]:
    excluded = extra_excluded or set()
    return [v for v in values if not is_grease(v) and v not in excluded]


def ja3(hello: ClientHelloInfo) -> tuple[str, str]:
    """Return `(md5_hex, ja3_string)` for a ClientHello."""
    version = _RAW_VERSIONS.get(hello.legacy_version.value, 0)
    fields = [
        str(version),
        _join(_clean(hello.cipher_suites, _NOT_REAL_SUITES)),
        _join(_clean(hello.extensions)),
        _join(_clean(hello.supported_groups)),
        _join(hello.ec_point_formats),
    ]
    text = ",".join(fields)
    return hashlib.md5(text.encode(), usedforsecurity=False).hexdigest(), text


def ja3s(hello: ServerHelloInfo) -> tuple[str, str]:
    """Return `(md5_hex, ja3s_string)` for a ServerHello."""
    version = _RAW_VERSIONS.get(hello.legacy_version.value, 0)
    fields = [
        str(version),
        str(hello.cipher_suite if hello.cipher_suite is not None else ""),
        _join(_clean(hello.extensions)),
    ]
    text = ",".join(fields)
    return hashlib.md5(text.encode(), usedforsecurity=False).hexdigest(), text
