# Testbed — the ground-truth capture corpus

This directory is **USP-07**. It is not a pile of test files; it is the thing that lets us answer *"how do you
know it works?"* with numbers instead of a shrug.

The PS dataset guidance says participants may generate their own synthetic captures. Most teams will treat that as
a chore. It is actually permission to **own the ground truth**: we choose the TLS version, cipher, key size and
certificate validity for every capture, so we know the correct answer for every one and can measure precision and
recall per detection rule.

## Files

| File | What it is |
|---|---|
| `manifest.json` | **The ground truth.** 18 captures, each stating exactly what was configured and which findings must fire |
| `make_certs.sh` | Generates the four certificate scenarios with `openssl` |
| `docker-compose.yml` | The mail servers, each pinned to a specific cryptographic configuration |
| `capture.sh` | Drives clients against the servers and records PCAPs with `tshark` |
| `certs/` | Generated, gitignored |
| `out/` | Generated PCAPs plus a `.truth.json` sidecar each, gitignored |

## Running it

Inside WSL2 (ADR-0001):

```bash
bash testbed/make_certs.sh
docker compose -f testbed/docker-compose.yml up -d
bash testbed/capture.sh
```

Then measure ourselves against the truth:

```bash
python scripts/evaluate.py testbed/out/
```

## Coverage, and why it exceeds the brief

The PS names only **IMAPS (993), POP3S (995) and SMTPS (465)** — the implicit-TLS ports, where TLS starts at byte
zero. Those are the easy captures: point any mail client at any provider and hit record.

But **D02 requires STARTTLS detection and validation**, and STARTTLS lives on 25, 587, 143 and 110. Teams that
follow the dataset hint literally will have no cleartext phase to analyse and no upgrade to validate, so they
cannot demonstrate D02 at all. We cover both. See ADR-0008.

| | 465 / 993 / 995 implicit | 25 / 587 / 143 / 110 STARTTLS | cleartext control |
|---|---|---|---|
| healthy | 3 | 3 | — |
| degraded | 3 | 1 | — |
| compromised | 3 | 2 | 3 |

## The three cases that matter most

**`smtp_25_relay_expired_cert` and `imaps_993_compromised_rc4` share the same certificate.** That is deliberate and
it is the USP-01 demo: identical defect, opportunistic relay versus credential-bearing port, INFO versus CRITICAL.
Do not regenerate one without the other.

**`smtp_587_starttls_stripped`** is the demo's emotional peak — a proxy rewrites `250-STARTTLS` to `250-XXXXXXXA`,
preserving the line length so TCP sequence numbers stay valid, and the client falls back to cleartext and
authenticates. We decode the base64 on stage.

**`imaps_993_tls13_opaque_certs`** is a regression guard. In TLS 1.3 the Certificate message is encrypted, so a
passive observer cannot see the chain. The correct output is `ChainStatus.OPAQUE_TLS13` with an explanation — not
an empty panel, and definitely not a false "no certificate presented" finding.

## Adding a case

1. Add an entry to `manifest.json` with its `truth` and `expected_findings`.
2. Add the server configuration to `docker-compose.yml` if it needs a new one.
3. Regenerate, then re-run `scripts/evaluate.py`.

The metrics update automatically, which is what makes the accuracy claim on the metrics slide reproducible rather
than a number we typed in.

## Generating weak configurations

Modern OpenSSL refuses to negotiate RC4, 3DES, SSLv3 and TLS 1.0 by default, which is the point of them being
findings. Three ways round it, in order of preference:

1. **Pinned old images** — `docker run alpine/openssl:1.0.2 s_server -accept 8025 -tls1 -cipher RC4-SHA ...`
2. **Security level 0** on a modern build — `-cipher 'RC4-SHA:@SECLEVEL=0'`
3. **Craft the handshake directly** and write it with `scapy`'s `wrpcap`, for anything the first two cannot produce.

Option 3 is the insurance policy: it gives total control over the bytes, which matters if a live capture misbehaves
twenty minutes before the demo.
