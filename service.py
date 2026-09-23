#!/usr/bin/env python3
"""
service.py — Day 7. Local HTTP service wrapping the analyzer.

This exists so the deployment answer is "a service any mail system can call"
rather than "a Streamlit script". No analysis logic lives here — it delegates
entirely to analyzer_core.analyze_email, which is the same path the CLI and the
UI use. The Day 5/6 evaluation numbers therefore still describe this service.

  POST /analyze   raw message bytes in, verdict JSON out
  GET  /health    model name + whether Ollama is reachable
  GET  /          service metadata

SECURITY: binds to 127.0.0.1 only.

The VM holds live phishing samples and this endpoint has no authentication. On
0.0.0.0 it would be reachable from the host network and from anything else on
it — an unauthenticated endpoint that accepts arbitrary email bodies and hands
them to a language model. The bind address is enforced in code below, not left
to the command line, so a typo in a uvicorn invocation cannot expose it.

Run:
    uvicorn service:app --host 127.0.0.1 --port 8000
    python3 service.py            # equivalent, with the bind hard-coded
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

from fastapi import Body, FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts"))

from analyzer_core import (AnalyzerError, DEFAULT_BODY_CHARS,  # noqa: E402
                           DEFAULT_PROMPT_VERSION, analyze_email, ping)
from llm_client import DEFAULT_HOST, DEFAULT_MODEL            # noqa: E402

ROOT = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(ROOT, "logs", "service.jsonl")

MAX_BYTES = 10 * 1024 * 1024   # 10 MB; larger is not a real email

SERVICE_VERSION = "0.1.0"

app = FastAPI(
    title="Phishing Email Analyzer",
    description="Local LLM-assisted triage service for reported and "
                "quarantined email. Advisory only — analyst in the loop.",
    version=SERVICE_VERSION,
)


def log_service_call(record: dict) -> None:
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        fh.flush()
        os.fsync(fh.fileno())


@app.get("/")
def root() -> dict:
    return {
        "service": "phishing-analyzer",
        "version": SERVICE_VERSION,
        "endpoints": {
            "POST /analyze": "raw message bytes -> verdict JSON",
            "GET /health": "model and Ollama reachability",
        },
        "positioning": "Out-of-band triage of reported and quarantined mail. "
                       "Not an inline SMTP filter. Verdicts are advisory and "
                       "require analyst confirmation.",
    }


@app.get("/health")
def health(model: str = Query(DEFAULT_MODEL), host: str = Query(DEFAULT_HOST)) -> JSONResponse:
    """
    Reports whether the service can actually do its job, not merely whether the
    process is running. A health check that returns 200 while the model is
    unreachable is worse than none — it hides the failure.
    """
    status = ping()
    body = {
        "service": "up",
        "service_version": SERVICE_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        **status,
    }
    code = 200 if status["ollama_reachable"] else 503
    return JSONResponse(status_code=code, content=body)


@app.post("/analyze")
def analyze(
    raw: bytes = Body(..., media_type="application/octet-stream"),
    prompt_version: str = Query(DEFAULT_PROMPT_VERSION, pattern=r"^[A-Za-z0-9_]{1,20}$"),
    body_chars: int = Query(DEFAULT_BODY_CHARS, ge=200, le=4000),
    retries: int = Query(1, ge=0, le=3),
    include_bundle: bool = Query(False,
                                 description="include the full parsed feature "
                                             "bundle; off by default to keep "
                                             "responses small"),
) -> dict:
    """
    Analyse one raw RFC 822 message.

    Send the message bytes as the request body with Content-Type
    application/octet-stream or message/rfc822.
    """
    if not raw:
        raise HTTPException(status_code=400, detail="empty request body")
    if len(raw) > MAX_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"message too large ({len(raw)} bytes, limit {MAX_BYTES})")

    try:
           result = analyze_email(
            raw, prompt_version=prompt_version, body_chars=body_chars,
            retries=retries, include_bundle=include_bundle)
    except AnalyzerError as exc:
        # Ollama unreachable is a dependency failure, not a client error.
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=422,
            detail=f"could not parse or analyse: {type(exc).__name__}: {exc}"
        ) from exc

    log_service_call({
        "timestamp": result["meta"]["timestamp"],
        "endpoint": "/analyze",
        "raw_sha256": result["meta"]["raw_sha256"],
        "bytes": len(raw),
        "model": result["meta"]["model"],
        "prompt_version": result["meta"]["prompt_version"],
        "latency_s": result["meta"]["latency_s"],
        "verdict": result["verdict"]["verdict"],
        "confidence": result["verdict"]["confidence"],
        "grounding": {k: v for k, v in result["grounding"].items()
                      if k != "details"},
        "reliability": result["reliability"],
    })
    return result


if __name__ == "__main__":
    import uvicorn

    # Bind hard-coded to loopback. See the security note at the top of the file.
    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("PA_PORT", 8000)))
