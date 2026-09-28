"""S10 - the HTTP service. Owner: person D.

**Use Flask, not FastAPI.** Pydantic v2 ships a compiled Rust core
(`_pydantic_core`) which Smart App Control blocks on the team's machines, and
FastAPI imports it unconditionally. Verified: `import fastapi` fails. Flask,
Starlette and stdlib `sqlite3` all import and run. See ADR-0021.

Planned surface:

    POST /api/jobs            upload a PCAP, returns a job id
    GET  /api/jobs/{id}       state, current stage, progress
    GET  /api/reports/{id}    the Report JSON the dashboard consumes
    GET  /api/reports/{id}/export/{fmt}
    POST /api/findings/{id}/disposition   acknowledge / false positive / resolve
    GET  /api/audit                       append-only event log

Serve `fixtures/report.sample.json` and the generated HTML from day one so the
frontend is never blocked on the parser (ADR-0005), and keep a sample-capture
dropdown so a demo never depends on upload working.
"""
