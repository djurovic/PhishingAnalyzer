#!/usr/bin/env python3
"""
analyzer_core.py — the single analysis entry point.

analyze_email(raw_bytes) -> dict runs the whole pipeline: parse, condense,
prompt, model call, grounding check. service.py, app.py and scripts/analyze.py
all call this one function, so evaluation results describe every client.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from eml_parser import parse_bytes                              # noqa: E402
from grounding_check import check_indicators                  # noqa: E402
from llm_client import (DEFAULT_HOST, DEFAULT_MODEL,          # noqa: E402
                        OllamaClient, OllamaError)
from prompt_builder import (DEFAULT_BODY_CHARS, build_prompt_input,  # noqa: E402
                            budget_report, load_system_prompt,
                            render_user_message)

DEFAULT_PROMPT_VERSION = "v1"

class AnalyzerError(RuntimeError):
    """Raised when analysis cannot be attempted at all (e.g. Ollama down)."""



def analyze_email(raw_bytes: bytes,
                  model: str = DEFAULT_MODEL,
                  host: str = DEFAULT_HOST,
                  prompt_version: str = DEFAULT_PROMPT_VERSION,
                  body_chars: int = DEFAULT_BODY_CHARS,
                  retries: int = 1,
                  timeout: int = 180,
                  include_bundle: bool = True,
                  source_name: str = "message.eml") -> dict:
    """
    Analyse one raw email. Returns a dict with the same shape the Streamlit UI
    already renders.

    Keys:
      meta        timestamp, model, prompt_version, latency_s, source hash
      verdict     verdict / confidence / indicators / explanation /
                  recommended_actions
      grounding   indicator_count, verified, mismatched, unverifiable, details
      reliability attempt_count, json_ok_first_try, repairs, schema_problems
      bundle      the full parsed feature bundle (omit with include_bundle=False)
      raw_response the model's unmodified output, for debugging

    Raises AnalyzerError only for transport failure (Ollama unreachable).
    A model that misbehaves produces a structured result, not an exception.
    """
    bundle = parse_bytes(raw_bytes, source_name=source_name)

    condensed = build_prompt_input(bundle, body_chars)
    user_msg = render_user_message(condensed)
    system_prompt = load_system_prompt(prompt_version)
    budget = budget_report(system_prompt, user_msg)

    client = OllamaClient(host=host, model=model, timeout=timeout)
    try:
        result = client.analyse(system_prompt, user_msg, max_retries=retries)
    except OllamaError as exc:
        raise AnalyzerError(str(exc)) from exc

    verdict = result["verdict"]
    grounding = check_indicators(bundle, verdict)
    last = result["attempts"][-1]

    out = {
        "meta": {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "model": result["model"],
            "prompt_version": prompt_version,
            "latency_s": result["total_latency_s"],
            "source_file": bundle["meta"]["source_file"],
            "raw_sha256": bundle["meta"]["raw_sha256"],
            "estimated_prompt_tokens": budget["estimated_prompt_tokens"],
            "actual_prompt_tokens": last.get("prompt_tokens"),
            "response_tokens": last.get("response_tokens"),
        },
        "verdict": verdict,
        "grounding": grounding,
        "reliability": {
            "attempt_count": len(result["attempts"]),
            "json_ok_first_try": (len(result["attempts"]) == 1
                                  and not result["attempts"][0]["repairs"]),
            "repairs": [r for a in result["attempts"] for r in a["repairs"]],
            "schema_problems": [p for a in result["attempts"]
                                for p in a.get("schema_problems", [])],
        },
        "raw_response": last.get("raw_content", ""),
    }
    if include_bundle:
        out["bundle"] = bundle
    else:
        # Keep the headline facts even when the full bundle is dropped, so a
        # service client still has something to display.
        out["summary"] = {
            "from": bundle["headers"].get("from", ""),
            "subject": bundle["headers"].get("subject", ""),
            "date": bundle["headers"].get("date", ""),
            "spf": bundle["authentication"]["spf"],
            "dkim": bundle["authentication"]["dkim"],
            "dmarc": bundle["authentication"]["dmarc"],
            "url_count": bundle["derived_signals"]["url_count"],
            "attachment_count": bundle["derived_signals"]["attachment_count"],
        }
    return out


def ping(host: str = DEFAULT_HOST, model: str = DEFAULT_MODEL) -> dict:
    """Health probe: is Ollama reachable and is the model present?"""
    client = OllamaClient(host=host, model=model)
    try:
        models = client.ping()
    except OllamaError as exc:
        return {"ollama_reachable": False, "error": str(exc),
                "host": host, "model": model, "models_available": []}
    return {
        "ollama_reachable": True,
        "host": host,
        "model": model,
        "model_present": any(model.split(":")[0] in m for m in models),
        "models_available": models,
    }
