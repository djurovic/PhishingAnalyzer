#!/usr/bin/env python3
"""
test_day4.py — offline tests for the Day 4 layer. No Ollama required.

Feeds known-bad model outputs through the repair/validate/ground path. These
are the actual failure shapes a 3B model produces; catching them here means
the batch run on Day 5 does not fall over at email 47 of 200.

Usage: python3 scripts/test_day4.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from grounding_check import check_indicators   # noqa: E402
from llm_client import repair_json, validate_verdict   # noqa: E402

PASS, FAIL = 0, 0


def check(label, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  ok    {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label} {detail}")


GOOD = json.dumps({
    "verdict": "phishing", "confidence": 0.9,
    "indicators": [{"indicator": "SPF fails", "evidence_field": "authentication.spf",
                    "evidence_value": "fail", "severity": "high"}],
    "explanation": "Bad email.", "recommended_actions": ["Block sender"],
})

print("\n[1] JSON repair")
cases = [
    ("clean json", GOOD, True, []),
    ("markdown fence", f"```json\n{GOOD}\n```", True, ["stripped_code_fence"]),
    ("chatty preamble", f"Here is my analysis:\n{GOOD}", True, ["stripped_surrounding_text"]),
    ("postamble", f"{GOOD}\n\nLet me know if you need more.", True, ["stripped_surrounding_text"]),
    ("trailing comma", '{"verdict": "phishing", "confidence": 0.5,}', True, ["removed_trailing_comma"]),
    ("truncated mid-object", '{"verdict": "phishing", "indicators": [{"indicator": "x"', True,
     ["closed_truncated_object"]),
    ("empty", "", False, ["empty_response"]),
    ("pure prose", "I think this email looks suspicious to me.", False, ["unrecoverable"]),
]
for label, raw, should_parse, expect_repair in cases:
    parsed, repairs = repair_json(raw)
    ok = (parsed is not None) == should_parse
    if expect_repair:
        ok = ok and any(r in repairs for r in expect_repair)
    check(label, ok, f"-> repairs={repairs}")

print("\n[2] Schema validation / coercion")
schema_cases = [
    ("confidence as percentage", {"verdict": "phishing", "confidence": 85},
     lambda v, p: v["confidence"] == 0.85 and "confidence_rescaled_from_percentage" in p),
    ("confidence out of range", {"verdict": "phishing", "confidence": 1.7},
     lambda v, p: 0.0 <= v["confidence"] <= 1.0),
    ("verdict capitalised", {"verdict": "Phishing", "confidence": 0.5},
     lambda v, p: v["verdict"] == "phishing"),
    ("verdict with spaces", {"verdict": "insufficient evidence", "confidence": 0.1},
     lambda v, p: v["verdict"] == "insufficient_evidence"),
    ("verdict invented", {"verdict": "malicious", "confidence": 0.9},
     lambda v, p: v["verdict"] == "insufficient_evidence" and any("invalid_verdict" in x for x in p)),
    ("actions as newline string", {"verdict": "phishing", "recommended_actions": "- Block\n- Report"},
     lambda v, p: v["recommended_actions"] == ["Block", "Report"]),
    ("indicators not a list", {"verdict": "phishing", "indicators": "SPF failed"},
     lambda v, p: v["indicators"] == [] and "indicators_not_a_list" in p),
    ("bad severity", {"verdict": "phishing", "indicators": [
        {"indicator": "x", "evidence_field": "a.b", "evidence_value": "1", "severity": "critical"}]},
     lambda v, p: v["indicators"][0]["severity"] == "medium"),
    ("missing explanation", {"verdict": "legitimate"},
     lambda v, p: "missing_explanation" in p),
    ("too many indicators", {"verdict": "phishing", "indicators": [
        {"indicator": f"i{n}", "evidence_field": "a", "evidence_value": "v", "severity": "low"}
        for n in range(10)]},
     lambda v, p: len(v["indicators"]) == 6),
]
for label, obj, predicate in schema_cases:
    v, p = validate_verdict(obj)
    check(label, predicate(v, p), f"-> {v.get('verdict')}, problems={p}")

print("\n[3] Grounding check against a real bundle")
bundle_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "out", "03_phish_credential.json")
if not os.path.exists(bundle_path):
    print(f"  skip  (no bundle at {bundle_path}; run the Day 3 parser first)")
else:
    bundle = json.load(open(bundle_path, encoding="utf-8"))
    verdict = {"indicators": [
        {"indicator": "SPF fail", "evidence_field": "authentication.spf",
         "evidence_value": "fail", "severity": "high"},
        {"indicator": "Reply-To mismatch", "evidence_field": "derived_signals.reply_to_domain_mismatch",
         "evidence_value": "true", "severity": "high"},
        {"indicator": "Anchor mismatch", "evidence_field": "urls[0].notes",
         "evidence_value": "anchor_text_domain_mismatch", "severity": "high"},
        {"indicator": "Bare field name", "evidence_field": "spf",
         "evidence_value": "fail", "severity": "medium"},
        {"indicator": "Wrong value claimed", "evidence_field": "authentication.dmarc",
         "evidence_value": "pass", "severity": "low"},
        {"indicator": "Invented field", "evidence_field": "derived_signals.virus_detected",
         "evidence_value": "true", "severity": "high"},
    ]}
    g = check_indicators(bundle, verdict)
    grades = [d["grade"] for d in g["details"]]
    check("real field verified", grades[0] == "verified", f"-> {grades[0]}")
    check("boolean signal verified", grades[1] == "verified", f"-> {grades[1]}")
    check("indexed list path verified", grades[2] == "verified", f"-> {grades[2]}")
    check("bare field name resolved", grades[3] == "verified", f"-> {grades[3]}")
    check("wrong value flagged mismatched", grades[4] == "mismatched", f"-> {grades[4]}")
    check("invented field flagged unverifiable", grades[5] == "unverifiable", f"-> {grades[5]}")
    check("hallucination rate computed",
          g["hallucination_rate"] == round(2 / 6, 3), f"-> {g['hallucination_rate']}")

print("\n[4] End-to-end: bad model output survives the whole path")
raw = ("Sure! Here's the analysis:\n```json\n"
       '{"verdict": "Phishing", "confidence": 95, "indicators": '
       '[{"indicator": "SPF failed", "evidence_field": "authentication.spf", '
       '"evidence_value": "fail", "severity": "CRITICAL"}], '
       '"explanation": "Fails auth.", "recommended_actions": "Block the sender",}\n```\nHope that helps!')
parsed, repairs = repair_json(raw)
check("mangled response parsed", parsed is not None, f"-> repairs={repairs}")
if parsed:
    v, problems = validate_verdict(parsed)
    check("verdict normalised", v["verdict"] == "phishing")
    check("confidence rescaled", v["confidence"] == 0.95, f"-> {v['confidence']}")
    check("severity coerced", v["indicators"][0]["severity"] == "medium")
    check("actions listified", v["recommended_actions"] == ["Block the sender"])

print(f"\n{'=' * 50}\n{PASS} passed, {FAIL} failed\n{'=' * 50}")
sys.exit(1 if FAIL else 0)
