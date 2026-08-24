#!/usr/bin/env python3
"""
rule_baseline.py — Day 6. Deterministic classifier, no LLM.

WHY A BASELINE AT ALL

"The LLM got 87% accuracy" means nothing on its own. The question a reviewer
asks is: could a hundred lines of if-statements have done as well? If yes, the
LLM is an expensive way to compute a rule engine. If no, the gap is the
contribution — and if the baseline WINS on accuracy while losing on
explanation quality, that is a more interesting result than either winning
outright.

This writes into the same logs/runs.jsonl as the LLM runs, under
model="rule_baseline_v1", so evaluate.py scores it with identical code on the
identical split. Reusing the metric code is the point: two separately written
scoring paths would invite exactly the kind of subtle mismatch that makes a
comparison meaningless.

METHODOLOGY NOTE — THRESHOLD TUNING

The decision threshold is fitted on the `tune` split ONLY, then frozen and
applied to `eval`. Fitting it on `eval` would let the baseline peek at the
test set the LLM never saw, making the comparison dishonest in the baseline's
favour. `--tune` writes the fitted threshold to rules_config.json; `--run`
reads it back. If you re-tune, re-run.

RULE WEIGHTS

Weights are hand-assigned from the domain literature and from the observed
prevalences in the real phishing corpus (auth_failure 51%, anchor-text
mismatch 11%, IP-literal URLs 0%). They are NOT fitted to the data — only the
single scalar threshold is. That keeps the baseline honest as a
"what a competent analyst would write" comparator rather than a
weakly-trained classifier.

Usage:
    python3 scripts/rule_baseline.py --tune --dataset dataset/
    python3 scripts/rule_baseline.py --run  --dataset dataset/ --split eval
    python3 scripts/evaluate.py --split eval --model rule_baseline_v1
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from eml_parser import parse_eml  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_PATH = os.path.join(ROOT, "logs", "runs.jsonl")
CONFIG_PATH = os.path.join(ROOT, "rules_config.json")

MODEL_NAME = "rule_baseline_v1"
RULES_VERSION = "rules_v1"

# Classic Tier-1 urgency/pretext lexicon. Deliberately small — a large
# keyword list becomes a bag-of-words classifier, which is a different
# experiment from "rules an analyst would write".
URGENCY_TERMS = [
    "urgent", "immediately", "within 24 hours", "account will be",
    "suspended", "verify your", "confirm your", "click here", "act now",
    "final notice", "unusual activity", "security alert", "expire",
    "validate your", "update your payment", "unauthorized", "locked",
]

CREDENTIAL_TERMS = ["password", "sign in", "log in", "login", "credentials",
                    "username", "account access", "re-enter"]


def score_email(bundle: dict) -> tuple[float, list[dict]]:
    """Returns (score, indicators). Each indicator names the field it fired on."""
    d = bundle.get("derived_signals", {})
    auth = bundle.get("authentication", {})
    urls = bundle.get("urls", [])
    html = bundle.get("body", {}).get("html", {})
    hits: list[dict] = []
    score = 0.0

    def fire(points: float, name: str, field: str, value, severity: str):
        nonlocal score
        score += points
        hits.append({"indicator": name, "evidence_field": field,
                     "evidence_value": str(value), "severity": severity,
                     "points": points})

    # --- authentication -------------------------------------------------
    if auth.get("dmarc") in ("fail",):
        fire(3.0, "DMARC alignment fails", "authentication.dmarc",
             auth["dmarc"], "high")
    if auth.get("spf") in ("fail", "softfail"):
        fire(2.0, "SPF check fails", "authentication.spf", auth["spf"], "high")
    if auth.get("dkim") in ("fail",):
        fire(2.0, "DKIM signature invalid", "authentication.dkim",
             auth["dkim"], "high")

    # --- sender identity ------------------------------------------------
    if d.get("reply_to_domain_mismatch"):
        fire(2.5, "Reply-To domain differs from From domain",
             "derived_signals.reply_to_domain_mismatch", True, "high")
    if d.get("return_path_domain_mismatch"):
        fire(1.5, "Return-Path domain differs from From domain",
             "derived_signals.return_path_domain_mismatch", True, "medium")
    if d.get("display_name_contains_email"):
        fire(2.0, "Display name contains an email address",
             "derived_signals.display_name_contains_email", True, "medium")

    # --- URLs -----------------------------------------------------------
    if d.get("has_anchor_text_mismatch"):
        fire(3.0, "Link text claims a different domain than the href",
             "derived_signals.has_anchor_text_mismatch", True, "high")
    if d.get("has_ip_literal_url"):
        fire(3.0, "URL uses a bare IP address", 
             "derived_signals.has_ip_literal_url", True, "high")
    if d.get("has_punycode_url"):
        fire(2.5, "URL uses punycode (possible homograph)",
             "derived_signals.has_punycode_url", True, "high")
    if d.get("has_redirect_wrapper"):
        fire(1.0, "URL passes through a redirector",
             "derived_signals.has_redirect_wrapper", True, "low")
    for u in urls:
        if "userinfo_in_url" in u.get("notes", []):
            fire(2.5, "URL embeds userinfo before the host", "urls[].notes",
                 "userinfo_in_url", "high")
            break
    off = d.get("urls_off_sender_domain") or []
    if len(off) >= 2:
        fire(1.0, f"Links point to {len(off)} domains unrelated to the sender",
             "derived_signals.urls_off_sender_domain", ", ".join(off[:3]), "low")

    # --- attachments ----------------------------------------------------
    if d.get("has_risky_attachment"):
        fire(3.5, "Attachment has an executable or script extension",
             "derived_signals.has_risky_attachment", True, "high")
    for a in bundle.get("attachments", []):
        if "double_extension" in a.get("notes", []):
            fire(2.0, "Attachment uses a double extension",
                 "attachments[].notes", "double_extension", "high")
            break

    # --- HTML structure -------------------------------------------------
    if html.get("form_count"):
        fire(2.5, "HTML body contains a form (credential capture)",
             "body.html.form_count", html["form_count"], "high")
    if html.get("hidden_elements", 0) >= 2:
        fire(1.5, "HTML contains hidden elements (filter evasion)",
             "body.html.hidden_elements", html["hidden_elements"], "medium")
    if html.get("iframe_count"):
        fire(1.0, "HTML contains an iframe", "body.html.iframe_count",
             html["iframe_count"], "low")

    # --- language -------------------------------------------------------
    text = ((bundle.get("headers", {}).get("subject", "") or "") + " "
            + (bundle.get("body", {}).get("text_excerpt", "") or "")).lower()
    urgency = [t for t in URGENCY_TERMS if t in text]
    if urgency:
        pts = 1.0 if len(urgency) == 1 else 2.0
        fire(pts, f"Urgency or pretext language ({len(urgency)} terms)",
             "body.text_excerpt", ", ".join(urgency[:3]), "medium")
    cred = [t for t in CREDENTIAL_TERMS if t in text]
    if cred and (html.get("form_count") or off):
        fire(1.5, "Credential-related language alongside an external link",
             "body.text_excerpt", ", ".join(cred[:3]), "medium")

    hits.sort(key=lambda h: -h["points"])
    return score, hits


def to_verdict(score: float, phish_threshold: float, susp_threshold: float,
               hits: list[dict]) -> dict:
    if score >= phish_threshold:
        verdict = "phishing"
    elif score >= susp_threshold:
        verdict = "suspicious"
    elif not hits:
        verdict = "legitimate"
    else:
        verdict = "legitimate"
    confidence = max(0.0, min(1.0, score / (phish_threshold * 1.6))) if phish_threshold else 0.0
    top = [{k: v for k, v in h.items() if k != "points"} for h in hits[:6]]
    if verdict == "phishing":
        actions = ["Quarantine the message and search for other recipients",
                   "Block the sending domain and any linked domains at the gateway",
                   "Confirm no recipient submitted credentials"]
    elif verdict == "suspicious":
        actions = ["Escalate to an analyst for manual review"]
    else:
        actions = ["No action required"]
    explanation = ("Rule engine scored {:.1f} against thresholds "
                   "(suspicious {:.1f} / phishing {:.1f}). {}").format(
        score, susp_threshold, phish_threshold,
        "Triggered: " + "; ".join(h["indicator"] for h in hits[:4]) if hits
        else "No rules triggered.")
    return {"verdict": verdict, "confidence": round(confidence, 3),
            "indicators": top, "explanation": explanation,
            "recommended_actions": actions, "_score": round(score, 2)}


def load_manifest(dataset: str, split: str | None) -> list[dict]:
    with open(os.path.join(dataset, "manifest.csv"), newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    if split and split != "all":
        rows = [r for r in rows if r["split"] == split]
    return rows


def metrics_at(scored: list[tuple[float, str]], phish_t: float, susp_t: float,
               lenient: bool) -> dict:
    tp = fp = tn = fn = 0
    for score, label in scored:
        if score >= phish_t:
            pred = "phishing"
        elif score >= susp_t:
            pred = "suspicious"
        else:
            pred = "legitimate"
        positive = pred == "phishing" or (lenient and pred == "suspicious")
        actual = label == "phishing"
        if positive and actual:
            tp += 1
        elif positive:
            fp += 1
        elif actual:
            fn += 1
        else:
            tn += 1
    total = tp + fp + tn + fn
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "accuracy": (tp + tn) / total if total else 0.0,
            "precision": prec, "recall": rec, "f1": f1,
            "fpr": fp / (fp + tn) if (fp + tn) else 0.0}


def do_tune(args) -> int:
    rows = load_manifest(args.dataset, "tune")
    if not rows:
        print("[FAIL] no emails in the tune split", file=sys.stderr)
        return 1

    scored: list[tuple[float, str]] = []
    for r in rows:
        try:
            bundle = parse_eml(os.path.join(args.dataset, "eml", r["filename"]))
        except Exception:
            continue
        s, _ = score_email(bundle)
        scored.append((s, r["label"]))

    print(f"Tuning on {len(scored)} emails from the TUNE split "
          f"({sum(1 for _, l in scored if l == 'phishing')} phishing).\n")
    print(f"  Score distribution:")
    for label in ("phishing", "legitimate"):
        vals = sorted(s for s, l in scored if l == label)
        if vals:
            print(f"    {label:<12} min {vals[0]:>5.1f}  median "
                  f"{vals[len(vals) // 2]:>5.1f}  max {vals[-1]:>5.1f}")

    candidates = [x / 2 for x in range(1, 41)]
    results = [(t, metrics_at(scored, t, t, lenient=False)) for t in candidates]
    best_f1 = max(m["f1"] for _, m in results)

    # Several thresholds often tie on F1, especially when the tune set is
    # cleanly separable. Taking the lowest is arbitrary and sits right on the
    # decision boundary, so a slightly different email flips the verdict.
    # Take the midpoint of the tied range instead: same F1 on tune, maximum
    # margin on either side, which generalises better to eval.
    tied = [t for t, m in results if m["f1"] == best_f1]
    phish_t = tied[len(tied) // 2]
    best_metrics = dict(metrics_at(scored, phish_t, phish_t, lenient=False))

    susp_t = max(0.5, round(phish_t * 0.55 * 2) / 2)

    print(f"\n  Best F1 on tune: {best_f1:.3f}")
    if len(tied) > 1:
        print(f"  {len(tied)} thresholds tie ({tied[0]} to {tied[-1]}); "
              f"taking midpoint {phish_t} for margin")
    print(f"  Phishing threshold:   {phish_t}")
    print(f"  Suspicious threshold: {susp_t} (0.55x, not fitted)")

    config = {
        "rules_version": RULES_VERSION,
        "phishing_threshold": phish_t,
        "suspicious_threshold": susp_t,
        "tuned_on": {"dataset": args.dataset, "split": "tune", "n": len(scored)},
        "tune_metrics": {k: round(v, 4) if isinstance(v, float) else v
                         for k, v in best_metrics.items()},
        "tuned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    with open(CONFIG_PATH, "w", encoding="utf-8") as fh:
        json.dump(config, fh, indent=2)
    print(f"\n  Written to {CONFIG_PATH}")
    print("  Thresholds are now FROZEN. Run with --run --split eval.")
    return 0


def do_run(args) -> int:
    if not os.path.exists(CONFIG_PATH):
        print(f"[FAIL] no {CONFIG_PATH}. Run --tune first — thresholds must be "
              "fitted on the tune split before scoring eval.", file=sys.stderr)
        return 1
    with open(CONFIG_PATH, encoding="utf-8") as fh:
        config = json.load(fh)
    phish_t = config["phishing_threshold"]
    susp_t = config["suspicious_threshold"]

    rows = load_manifest(args.dataset, args.split)
    if not rows:
        print("[FAIL] no emails match", file=sys.stderr)
        return 1

    print(f"Rule baseline {RULES_VERSION} | thresholds: suspicious >= {susp_t}, "
          f"phishing >= {phish_t}")
    print(f"Scoring {len(rows)} emails from split={args.split}\n")

    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    counts: dict[str, int] = {}
    with open(LOG_PATH, "a", encoding="utf-8") as log_fh:
        for i, r in enumerate(rows, 1):
            path = os.path.join(args.dataset, "eml", r["filename"])
            t0 = time.time()
            try:
                bundle = parse_eml(path)
            except Exception as exc:
                print(f"  [PARSE FAIL] {r['filename']}: {exc}", file=sys.stderr)
                continue
            score, hits = score_email(bundle)
            verdict = to_verdict(score, phish_t, susp_t, hits)
            elapsed = time.time() - t0
            counts[verdict["verdict"]] = counts.get(verdict["verdict"], 0) + 1

            # Rules cite bundle fields by construction, so grounding is 1.0.
            # Recorded explicitly so evaluate.py's grounding block is
            # comparable rather than empty.
            n_ind = len(verdict["indicators"])
            log_fh.write(json.dumps({
                "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "model": MODEL_NAME,
                "prompt_version": RULES_VERSION,
                "source_file": r["filename"],
                "raw_sha256": r["raw_sha256"],
                "true_label": r["label"],
                "split": r["split"],
                "dataset_source": r.get("source", ""),
                "latency_s": round(elapsed, 4),
                "attempt_count": 1,
                "json_ok_first_try": True,
                "repairs": [],
                "schema_problems": [],
                "rule_score": verdict.pop("_score"),
                "verdict": verdict,
                "grounding": {"indicator_count": n_ind, "verified": n_ind,
                              "mismatched": 0, "unverifiable": 0,
                              "grounding_rate": 1.0 if n_ind else None,
                              "hallucination_rate": 0.0 if n_ind else None},
                "grounding_details": [
                    {"indicator": ind["indicator"],
                     "evidence_field": ind["evidence_field"],
                     "claimed_value": ind["evidence_value"],
                     "actual_value": ind["evidence_value"],
                     "grade": "verified", "severity": ind["severity"]}
                    for ind in verdict["indicators"]],
                "raw_response": "",
            }, ensure_ascii=False) + "\n")

            if args.verbose:
                mark = "ok " if ((verdict["verdict"] in ("phishing", "suspicious"))
                                 == (r["label"] == "phishing")) else "MISS"
                print(f"[{i:>4}/{len(rows)}] {r['filename'][:34]:<34} "
                      f"true={r['label'][:5]:<5} -> {verdict['verdict'][:12]:<12} "
                      f"{mark} score={score:.1f}")

    total_latency = sum(1 for _ in rows)
    print(f"\nScored {len(rows)} emails. Verdicts: "
          + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    print(f"Log: {LOG_PATH}")
    print(f"\nNext: python3 scripts/evaluate.py --split {args.split} "
          f"--model {MODEL_NAME}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Rule-based baseline classifier.")
    ap.add_argument("--tune", action="store_true",
                    help="fit the threshold on the tune split and save it")
    ap.add_argument("--run", action="store_true", help="score a split using the saved threshold")
    ap.add_argument("--dataset", default="dataset")
    ap.add_argument("--split", default="eval")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    if args.tune == args.run:
        ap.error("choose exactly one of --tune or --run")
    return do_tune(args) if args.tune else do_run(args)


if __name__ == "__main__":
    raise SystemExit(main())
