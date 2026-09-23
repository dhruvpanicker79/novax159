"""S10 - the FastAPI service. Owner: person D.

    POST /api/analyse       upload a PCAP, returns a job id
    GET  /api/jobs/{id}     SSE progress stream
    GET  /api/reports/{id}  the Report JSON the dashboard consumes
    GET  /api/reports/{id}/export/{fmt}

Serve `fixtures/report.sample.json` from day one so the frontend is never
blocked on the parser (ADR-0005).
"""
