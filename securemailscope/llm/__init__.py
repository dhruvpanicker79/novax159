"""S8 - grounded remediation generation. Objective O02, USP-04 layer 3.

Turns structured findings into an executive narrative and working config
snippets for Postfix / Dovecot / Exchange.

Two hard rules:
    1. GROUNDED. The model sees only extracted facts, never raw capture bytes,
       and may not introduce a finding the rule engine did not produce.
    2. FALLBACK. A deterministic template path must produce acceptable output
       with no network at all. The demo cannot die on an API timeout.
"""
