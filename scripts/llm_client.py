#!/usr/bin/env python3
"""
llm_client.py — Day 4. Talks to Ollama on the host and returns validated JSON.

Transport is stdlib urllib, not the `ollama` package: one fewer dependency,
and the host-only network setup (VM -> 192.168.56.1:11434) is a plain HTTP
call. Same reasoning as choosing stdlib `email` over mail-parser on Day 3.

The interesting part is not the HTTP call, it is the failure ladder. Small
models return malformed JSON often enough that "retry until it works" is not
a strategy — you need to know HOW it failed, because that is a measurable
result for the evaluation chapter.

Failure ladder (each rung recorded in the log):
  1. format="json"      Ollama constrains decoding to valid JSON grammar.
  2. local repair       Strip fences/preamble, balance braces. No LLM call.
  3. retry with nudge   Re-ask, appending a "valid JSON only" reminder.
  4. give up            Return a structured failure record, never raise.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request

DEFAULT_HOST = os.environ.get("OLLAMA_HOST", "http://192.168.56.1:11434")
DEFAULT_MODEL = os.environ.get("PA_MODEL", "llama3.2")
DEFAULT_TIMEOUT = 180

VALID_VERDICTS = {"phishing", "suspicious", "legitimate", "insufficient_evidence"}
VALID_SEVERITIES = {"high", "medium", "low"}


class OllamaError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# JSON recovery
# ---------------------------------------------------------------------------

_FENCE_RE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.I | re.M)


def _close_truncated(text: str) -> str | None:
    """
    Close a JSON object cut off mid-generation. Walks the text tracking
    string state and an open-bracket stack, then emits the matching closers
    in reverse order. Returns None if nothing was open.
    """
    stack: list[str] = []
    in_string = False
    escaped = False

    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "{[":
            stack.append(ch)
        elif ch in "}]":
            if stack and stack[-1] == ("{" if ch == "}" else "["):
                stack.pop()

    if not stack and not in_string:
        return None

    patched = text
    if in_string:
        patched += '"'          # close the dangling string literal
    patched = patched.rstrip()
    # A trailing comma or a dangling "key": with no value would still be
    # invalid, so drop those before closing.
    patched = re.sub(r',\s*$', '', patched)
    patched = re.sub(r'"[^"]*"\s*:\s*$', '', patched).rstrip().rstrip(",")

    for opener in reversed(stack):
        patched += "}" if opener == "{" else "]"
    return patched


def repair_json(text: str) -> tuple[dict | None, list[str]]:
    """
    Best-effort recovery of a JSON object from model output.
    Returns (parsed_or_None, list_of_repairs_applied).
    """
    repairs: list[str] = []
    if not text or not text.strip():
        return None, ["empty_response"]

    candidate = text.strip()

    try:
        return json.loads(candidate), repairs
    except json.JSONDecodeError:
        pass

    if "```" in candidate:
        candidate = _FENCE_RE.sub("", candidate).strip()
        repairs.append("stripped_code_fence")

    # Drop any preamble/postamble around the outermost object.
    start = candidate.find("{")
    end = candidate.rfind("}")
    if start > 0 or (end != -1 and end < len(candidate) - 1):
        if start != -1 and end > start:
            candidate = candidate[start:end + 1]
            repairs.append("stripped_surrounding_text")

    try:
        return json.loads(candidate), repairs
    except json.JSONDecodeError:
        pass

    # Trailing commas before a closing brace/bracket.
    fixed = re.sub(r",\s*([}\]])", r"\1", candidate)
    if fixed != candidate:
        candidate = fixed
        repairs.append("removed_trailing_comma")
        try:
            return json.loads(candidate), repairs
        except json.JSONDecodeError:
            pass

    # Truncated output: close unbalanced brackets. Common when the model hits
    # num_predict mid-object. Closers must be emitted in reverse order of
    # opening, so track a stack rather than counting — and ignore brackets
    # that appear inside string literals.
    patched = _close_truncated(candidate)
    if patched is not None:
        try:
            parsed = json.loads(patched)
            repairs.append("closed_truncated_object")
            return parsed, repairs
        except json.JSONDecodeError:
            pass

    repairs.append("unrecoverable")
    return None, repairs


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------


def validate_verdict(obj: dict) -> tuple[dict, list[str]]:
    """
    Coerce the model's object into the expected schema shape.
    Returns (normalised_object, list_of_problems). Never raises — a schema
    problem is data for the evaluation, not a crash.
    """
    problems: list[str] = []
    out: dict = {}

    verdict = str(obj.get("verdict", "")).strip().lower().replace(" ", "_")
    if verdict not in VALID_VERDICTS:
        problems.append(f"invalid_verdict:{verdict or 'missing'}")
        # Salvage a near-miss rather than discarding the whole response.
        for v in VALID_VERDICTS:
            if v in verdict:
                verdict = v
                break
        else:
            verdict = "insufficient_evidence"
    out["verdict"] = verdict

    try:
        conf = float(obj.get("confidence", 0.0))
        if conf > 1.0:
            conf = conf / 100.0 if conf <= 100.0 else 1.0
            problems.append("confidence_rescaled_from_percentage")
        out["confidence"] = round(max(0.0, min(1.0, conf)), 3)
    except (TypeError, ValueError):
        problems.append("invalid_confidence")
        out["confidence"] = 0.0

    indicators = obj.get("indicators", [])
    if not isinstance(indicators, list):
        problems.append("indicators_not_a_list")
        indicators = []
    clean_indicators = []
    for item in indicators[:6]:
        if not isinstance(item, dict):
            problems.append("indicator_not_an_object")
            continue
        sev = str(item.get("severity", "")).strip().lower()
        if sev not in VALID_SEVERITIES:
            problems.append(f"invalid_severity:{sev or 'missing'}")
            sev = "medium"
        entry = {
            "indicator": str(item.get("indicator", "")).strip(),
            "evidence_field": str(item.get("evidence_field", "")).strip(),
            "evidence_value": str(item.get("evidence_value", "")).strip(),
            "severity": sev,
        }
        if not entry["evidence_field"]:
            problems.append("indicator_missing_evidence_field")
        clean_indicators.append(entry)
    out["indicators"] = clean_indicators

    explanation = obj.get("explanation", "")
    if not isinstance(explanation, str) or not explanation.strip():
        problems.append("missing_explanation")
        explanation = ""
    out["explanation"] = explanation.strip()

    actions = obj.get("recommended_actions", [])
    if isinstance(actions, str):
        problems.append("actions_returned_as_string")
        actions = [a.strip(" -•") for a in actions.split("\n") if a.strip()]
    elif not isinstance(actions, list):
        problems.append("invalid_recommended_actions")
        actions = []
    out["recommended_actions"] = [str(a).strip() for a in actions if str(a).strip()][:8]

    return out, problems


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class OllamaClient:
    def __init__(self, host: str = DEFAULT_HOST, model: str = DEFAULT_MODEL,
                 timeout: int = DEFAULT_TIMEOUT, temperature: float = 0.1,
                 num_ctx: int = 4096, num_predict: int = 800):
        self.host = host.rstrip("/")
        if not self.host.startswith("http"):
            self.host = "http://" + self.host
        self.model = model
        self.timeout = timeout
        self.temperature = temperature
        self.num_ctx = num_ctx
        self.num_predict = num_predict

    # -- low level --------------------------------------------------------
    def _post(self, path: str, payload: dict) -> dict:
        req = urllib.request.Request(
            self.host + path,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise OllamaError(f"HTTP {exc.code} from {self.host}{path}: "
                              f"{exc.read().decode('utf-8', 'replace')[:300]}") from exc
        except urllib.error.URLError as exc:
            raise OllamaError(
                f"Cannot reach Ollama at {self.host} ({exc.reason}). "
                "Is `ollama serve` running on the host, with OLLAMA_HOST=0.0.0.0:11434 "
                "and the firewall rule for TCP 11434 in place?"
            ) from exc
        except TimeoutError as exc:
            raise OllamaError(f"Request timed out after {self.timeout}s") from exc

    def ping(self) -> list[str]:
        """Return available model names. Raises OllamaError if unreachable."""
        req = urllib.request.Request(self.host + "/api/tags", method="GET")
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except Exception as exc:
            raise OllamaError(f"Cannot reach Ollama at {self.host}: {exc}") from exc
        return [m.get("name", "") for m in data.get("models", [])]

    def chat_raw(self, system: str, user: str, force_json: bool = True) -> dict:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "num_ctx": self.num_ctx,
                "num_predict": self.num_predict,
                "seed": 42,  # reproducibility for the evaluation run
            },
        }
        if force_json:
            payload["format"] = "json"
        return self._post("/api/chat", payload)

    # -- the failure ladder ----------------------------------------------
    def analyse(self, system: str, user: str, max_retries: int = 1) -> dict:
        """
        Returns a record with the validated verdict plus full telemetry.
        Never raises on model misbehaviour — only on transport failure.
        """
        attempts: list[dict] = []
        started = time.time()
        current_user = user

        for attempt_no in range(max_retries + 1):
            t0 = time.time()
            response = self.chat_raw(system, current_user, force_json=True)
            elapsed = time.time() - t0

            content = response.get("message", {}).get("content", "")
            parsed, repairs = repair_json(content)

            attempt_record = {
                "attempt": attempt_no + 1,
                "latency_s": round(elapsed, 2),
                "prompt_tokens": response.get("prompt_eval_count"),
                "response_tokens": response.get("eval_count"),
                "repairs": repairs,
                "raw_content": content,
            }

            if parsed is not None and isinstance(parsed, dict):
                verdict, problems = validate_verdict(parsed)
                attempt_record["schema_problems"] = problems
                attempts.append(attempt_record)
                # A salvaged-but-empty result is worth one retry.
                if not (problems and not verdict["indicators"] and not verdict["explanation"]) \
                        or attempt_no == max_retries:
                    return {
                        "ok": True,
                        "verdict": verdict,
                        "attempts": attempts,
                        "total_latency_s": round(time.time() - started, 2),
                        "model": self.model,
                    }
            else:
                attempt_record["schema_problems"] = ["json_unrecoverable"]
                attempts.append(attempt_record)

            current_user = (
                user + "\n\nYour previous reply could not be parsed as JSON. "
                "Reply with the JSON object only — no explanation before it, "
                "no markdown fences, no text after the closing brace."
            )

        return {
            "ok": False,
            "verdict": {
                "verdict": "insufficient_evidence",
                "confidence": 0.0,
                "indicators": [],
                "explanation": "The model did not return parseable JSON after retries.",
                "recommended_actions": ["Escalate to manual analyst review"],
            },
            "attempts": attempts,
            "total_latency_s": round(time.time() - started, 2),
            "model": self.model,
        }


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Check connectivity to Ollama.")
    ap.add_argument("--host", default=DEFAULT_HOST)
    args = ap.parse_args()
    client = OllamaClient(host=args.host)
    try:
        models = client.ping()
    except OllamaError as exc:
        print(f"[FAIL] {exc}")
        raise SystemExit(1)
    print(f"[OK] {args.host} reachable. Models: {', '.join(models) or '(none pulled)'}")
