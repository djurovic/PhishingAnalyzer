#!/usr/bin/env python3
"""
grounding_check.py — Day 4. Verifies the model's citations against the bundle.

The system prompt requires every indicator to name the bundle field it came
from. That requirement is only worth anything if it is enforced, so this
module walks each citation and answers: does that field exist, and does the
claimed value match what is actually there?

This turns "hallucination rate" from a metric you eyeball by hand into one
you compute. On Day 6 the manual rubric scores the *reasoning*; this scores
the *grounding*, automatically, across the whole dataset. Two different
things, and having both is what makes the evaluation defensible.

Grades per indicator:
  verified     field exists AND the claimed value matches
  mismatched   field exists BUT the claimed value differs
  unverifiable field path does not resolve in the bundle
"""

from __future__ import annotations

import json
import re


def resolve_path(bundle: dict, path: str):
    """
    Resolve a dotted path like 'derived_signals.spf_result' or 'urls[0].notes'.
    Returns (found: bool, value).
    """
    if not path:
        return False, None

    path = path.strip().lstrip("$.").replace("['", ".").replace("']", "")
    current = bundle
    token_re = re.compile(r"([^.\[\]]+)|\[(\d+)\]")

    for match in token_re.finditer(path):
        key, index = match.group(1), match.group(2)
        if index is not None:
            if not isinstance(current, list):
                return False, None
            i = int(index)
            if i >= len(current):
                return False, None
            current = current[i]
        else:
            key = key.strip()
            if isinstance(current, dict):
                if key in current:
                    current = current[key]
                else:
                    # Tolerate the model citing a bare field name that lives
                    # one level down, e.g. 'spf' for 'authentication.spf'.
                    for sub in current.values():
                        if isinstance(sub, dict) and key in sub:
                            current = sub[key]
                            break
                    else:
                        return False, None
            elif isinstance(current, list):
                # e.g. 'urls.notes' -> gather notes across all urls
                collected = [item[key] for item in current
                             if isinstance(item, dict) and key in item]
                if not collected:
                    return False, None
                current = collected
            else:
                return False, None
    return True, current


def _normalise(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple)):
        return " ".join(_normalise(v) for v in value)
    if isinstance(value, dict):
        return " ".join(f"{k} {_normalise(v)}" for k, v in value.items())
    return str(value).strip().lower()


def value_matches(claimed: str, actual) -> bool:
    c = _normalise(claimed)
    a = _normalise(actual)
    if not c:
        return False
    if c == a:
        return True
    # Substring either way: the model often quotes part of a list or
    # paraphrases a long value.
    if c in a or a in c:
        return True
    # Defanging differences shouldn't count as a mismatch.
    def refang(s):
        return s.replace("hxxps", "https").replace("hxxp", "http").replace("[.]", ".")
    return refang(c) == refang(a) or refang(c) in refang(a)


def check_indicators(bundle: dict, verdict: dict) -> dict:
    results = []
    for ind in verdict.get("indicators", []):
        field = ind.get("evidence_field", "")
        claimed = ind.get("evidence_value", "")
        found, actual = resolve_path(bundle, field)

        if not found:
            grade = "unverifiable"
        elif value_matches(claimed, actual):
            grade = "verified"
        else:
            grade = "mismatched"

        results.append({
            "indicator": ind.get("indicator", ""),
            "evidence_field": field,
            "claimed_value": claimed,
            "actual_value": actual if found else None,
            "grade": grade,
            "severity": ind.get("severity", ""),
        })

    total = len(results)
    counts = {g: sum(1 for r in results if r["grade"] == g)
              for g in ("verified", "mismatched", "unverifiable")}

    return {
        "indicator_count": total,
        "verified": counts["verified"],
        "mismatched": counts["mismatched"],
        "unverifiable": counts["unverifiable"],
        "grounding_rate": round(counts["verified"] / total, 3) if total else None,
        "hallucination_rate": round(
            (counts["mismatched"] + counts["unverifiable"]) / total, 3) if total else None,
        "details": results,
    }


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Check a saved analysis against its bundle.")
    ap.add_argument("bundle_json")
    ap.add_argument("analysis_json")
    args = ap.parse_args()

    bundle = json.load(open(args.bundle_json, encoding="utf-8"))
    analysis = json.load(open(args.analysis_json, encoding="utf-8"))
    verdict = analysis.get("verdict", analysis)
    print(json.dumps(check_indicators(bundle, verdict), indent=2))
