#!/usr/bin/env python3
"""
evaluate.py — Day 5. Computes metrics from logs/runs.jsonl.

Metrics are computed in plain Python rather than scikit-learn. A binary
confusion matrix is four counted integers; importing sklearn to count them
adds a dependency for no accuracy gain, and writing them out makes the
definitions visible in the report. (Cross-check against sklearn once if you
want the reassurance — the numbers agree.)

THE MAPPING PROBLEM

The model emits four verdicts; the ground truth is binary. How you collapse
them changes the numbers, so the choice must be stated, not buried:

  strict   phishing            -> phishing;  everything else -> legitimate
  lenient  phishing/suspicious -> phishing;  everything else -> legitimate

Lenient is the SOC-realistic reading: "suspicious" means it reaches an analyst,
which is what recall measures. Strict measures confident detection. Report
both. If they differ a lot, the model is hedging, and that is a finding.

`insufficient_evidence` is counted as legitimate under both (it triggers no
action) but is also reported separately as an abstention rate, because a tool
that abstains on 40% of mail is not usable regardless of its accuracy on the
rest.

Usage:
    python3 scripts/evaluate.py --dataset dataset/ --split eval
    python3 scripts/evaluate.py --split eval --csv results/predictions.csv
    python3 scripts/evaluate.py --split eval --errors 5
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_PATH = os.path.join(ROOT, "logs", "runs.jsonl")

MAPPINGS = {
    "strict": {"phishing"},
    "lenient": {"phishing", "suspicious"},
}


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    idx = min(int(round(p / 100.0 * (len(s) - 1))), len(s) - 1)
    return s[idx]


def load_runs(log_path: str, model: str | None, prompt_version: str | None,
              split: str | None) -> list[dict]:
    """Latest record wins per (sha256, model, prompt) — so a re-run supersedes."""
    if not os.path.exists(log_path):
        print(f"[FAIL] no log at {log_path}. Run batch_run.py first.", file=sys.stderr)
        raise SystemExit(1)

    latest: dict[tuple, dict] = {}
    with open(log_path, encoding="utf-8") as fh:
        for line in fh:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "true_label" not in rec:
                continue  # single-email runs from analyze.py carry no label
            if model and rec.get("model") != model:
                continue
            if prompt_version and rec.get("prompt_version") != prompt_version:
                continue
            if split and split != "all" and rec.get("split") != split:
                continue
            key = (rec.get("raw_sha256"), rec.get("model"), rec.get("prompt_version"))
            latest[key] = rec
    return list(latest.values())


def confusion(runs: list[dict], positive_verdicts: set[str]) -> dict:
    tp = fp = tn = fn = 0
    for r in runs:
        predicted_phish = r["verdict"]["verdict"] in positive_verdicts
        actually_phish = r["true_label"] == "phishing"
        if predicted_phish and actually_phish:
            tp += 1
        elif predicted_phish and not actually_phish:
            fp += 1
        elif not predicted_phish and actually_phish:
            fn += 1
        else:
            tn += 1

    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn, "total": total,
        "accuracy": (tp + tn) / total if total else 0.0,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": fp / (fp + tn) if (fp + tn) else 0.0,
        "false_negative_rate": fn / (fn + tp) if (fn + tp) else 0.0,
    }


def print_block(name: str, m: dict) -> None:
    print(f"\n  {name.upper()} mapping  (n={m['total']})")
    print("  " + "-" * 52)
    print(f"                    predicted phish   predicted legit")
    print(f"    actual phish  {m['tp']:>15}   {m['fn']:>15}")
    print(f"    actual legit  {m['fp']:>15}   {m['tn']:>15}")
    print("  " + "-" * 52)
    print(f"    Accuracy   {m['accuracy']:.3f}      Precision  {m['precision']:.3f}")
    print(f"    Recall     {m['recall']:.3f}      F1         {m['f1']:.3f}")
    print(f"    FPR        {m['false_positive_rate']:.3f}      FNR        "
          f"{m['false_negative_rate']:.3f}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Compute evaluation metrics.")
    ap.add_argument("--dataset", default="dataset")
    ap.add_argument("--split", default="eval", help="tune | eval | all")
    ap.add_argument("--model", default=None, help="restrict to one model")
    ap.add_argument("--prompt-version", default=None)
    ap.add_argument("--csv", default=None, help="write per-email predictions here")
    ap.add_argument("--json", default=None, help="write the metrics summary here")
    ap.add_argument("--errors", type=int, default=3,
                    help="how many FP/FN examples to print for case studies")
    args = ap.parse_args()

    runs = load_runs(LOG_PATH, args.model, args.prompt_version, args.split)
    if not runs:
        print("[FAIL] no labelled runs matched those filters.", file=sys.stderr)
        return 1

    models = sorted({r["model"] for r in runs})
    prompts = sorted({r["prompt_version"] for r in runs})
    if len(models) > 1 or len(prompts) > 1:
        print(f"[WARN] mixing model(s) {models} and prompt(s) {prompts} in one "
              "evaluation. Use --model / --prompt-version to separate them.\n",
              file=sys.stderr)

    label_counts = Counter(r["true_label"] for r in runs)
    verdict_counts = Counter(r["verdict"]["verdict"] for r in runs)

    print("=" * 62)
    print("EVALUATION")
    print("=" * 62)
    print(f"  Model(s):        {', '.join(models)}")
    print(f"  Prompt(s):       {', '.join(prompts)}")
    print(f"  Split:           {args.split}")
    print(f"  Emails:          {len(runs)}  "
          f"({label_counts['phishing']} phishing, {label_counts['legitimate']} legitimate)")

    print("\n  Raw verdict distribution:")
    for v, c in verdict_counts.most_common():
        print(f"    {v:<24} {c:>4}  ({c / len(runs):.1%})")

    abstentions = verdict_counts.get("insufficient_evidence", 0)
    print(f"\n  Abstention rate: {abstentions / len(runs):.1%}")

    print("\n" + "=" * 62)
    print("CLASSIFICATION METRICS")
    print("=" * 62)
    metrics = {}
    for name, positives in MAPPINGS.items():
        metrics[name] = confusion(runs, positives)
        print_block(name, metrics[name])

    gap = abs(metrics["lenient"]["recall"] - metrics["strict"]["recall"])
    if gap > 0.15:
        print(f"\n  [!] Recall differs by {gap:.2f} between mappings — the model "
              f"leans on\n      'suspicious' rather than committing. Worth discussing.")

    # -- reliability ------------------------------------------------------
    print("\n" + "=" * 62)
    print("OUTPUT RELIABILITY")
    print("=" * 62)
    first_try = sum(1 for r in runs if r.get("json_ok_first_try"))
    retried = sum(1 for r in runs if r.get("attempt_count", 1) > 1)
    repairs = Counter(x for r in runs for x in r.get("repairs", []))
    problems = Counter(p.split(":")[0] for r in runs for p in r.get("schema_problems", []))
    print(f"  Valid JSON first try:  {first_try}/{len(runs)}  ({first_try / len(runs):.1%})")
    print(f"  Needed a retry:        {retried}/{len(runs)}  ({retried / len(runs):.1%})")
    if repairs:
        print("  Repairs applied:")
        for k, c in repairs.most_common():
            print(f"    {k:<32} {c:>4}")
    if problems:
        print("  Schema coercions:")
        for k, c in problems.most_common():
            print(f"    {k:<32} {c:>4}")

    # -- grounding --------------------------------------------------------
    print("\n" + "=" * 62)
    print("EVIDENCE GROUNDING")
    print("=" * 62)
    cited = sum(r["grounding"]["indicator_count"] for r in runs)
    verified = sum(r["grounding"]["verified"] for r in runs)
    mismatched = sum(r["grounding"]["mismatched"] for r in runs)
    unverifiable = sum(r["grounding"]["unverifiable"] for r in runs)
    if cited:
        print(f"  Indicators cited:      {cited}")
        print(f"  Verified:              {verified:>5}  ({verified / cited:.1%})")
        print(f"  Value mismatched:      {mismatched:>5}  ({mismatched / cited:.1%})")
        print(f"  Field unresolvable:    {unverifiable:>5}  ({unverifiable / cited:.1%})")
        print(f"  Hallucination rate:    {(mismatched + unverifiable) / cited:.1%}")
        print(f"  Mean indicators/email: {cited / len(runs):.1f}")
        bad_fields = Counter(d["evidence_field"] for r in runs
                             for d in r.get("grounding_details", [])
                             if d["grade"] == "unverifiable")
        if bad_fields:
            print("\n  Most-invented fields:")
            for f, c in bad_fields.most_common(5):
                print(f"    {f or '(empty)':<40} {c:>4}")
    else:
        print("  No indicators cited across the run.")

    # -- latency ----------------------------------------------------------
    print("\n" + "=" * 62)
    print("PERFORMANCE")
    print("=" * 62)
    lat = [r["latency_s"] for r in runs if r.get("latency_s") is not None]
    if lat:
        print(f"  Latency  mean {sum(lat) / len(lat):>6.2f}s   median "
              f"{percentile(lat, 50):>6.2f}s")
        print(f"           p90  {percentile(lat, 90):>6.2f}s   p99    "
              f"{percentile(lat, 99):>6.2f}s   max {max(lat):>6.2f}s")
        print(f"  Total inference time: {sum(lat) / 60:.1f} min for {len(lat)} emails")
    ptok = [r["actual_prompt_tokens"] for r in runs if r.get("actual_prompt_tokens")]
    rtok = [r["response_tokens"] for r in runs if r.get("response_tokens")]
    if ptok:
        print(f"  Prompt tokens   mean {sum(ptok) / len(ptok):>6.0f}  max {max(ptok):>6}")
    if rtok:
        print(f"  Response tokens mean {sum(rtok) / len(rtok):>6.0f}  max {max(rtok):>6}")

    # -- error cases ------------------------------------------------------
    if args.errors:
        lenient = MAPPINGS["lenient"]
        fps = [r for r in runs if r["true_label"] == "legitimate"
               and r["verdict"]["verdict"] in lenient]
        fns = [r for r in runs if r["true_label"] == "phishing"
               and r["verdict"]["verdict"] not in lenient]

        print("\n" + "=" * 62)
        print(f"ERROR CASES  (lenient mapping; candidates for the report's case studies)")
        print("=" * 62)
        for title, group in (("FALSE POSITIVES", fps), ("FALSE NEGATIVES", fns)):
            print(f"\n  {title}: {len(group)}")
            for r in sorted(group, key=lambda x: -x["verdict"]["confidence"])[:args.errors]:
                print(f"    {r['source_file']}  -> {r['verdict']['verdict']} "
                      f"(conf {r['verdict']['confidence']:.2f})")
                top = r["verdict"]["indicators"][:2]
                for ind in top:
                    print(f"       - {ind['indicator'][:64]}")
                expl = (r['verdict']['explanation'] or '')[:160]
                if expl:
                    print(f"       \"{expl}...\"")

    # -- exports ----------------------------------------------------------
    if args.csv:
        os.makedirs(os.path.dirname(os.path.abspath(args.csv)), exist_ok=True)
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["source_file", "true_label", "verdict", "confidence",
                        "pred_strict", "pred_lenient", "indicators", "grounded",
                        "hallucination_rate", "latency_s", "json_ok_first_try",
                        "explanation"])
            for r in sorted(runs, key=lambda x: x["source_file"]):
                v = r["verdict"]
                g = r["grounding"]
                w.writerow([
                    r["source_file"], r["true_label"], v["verdict"], v["confidence"],
                    "phishing" if v["verdict"] in MAPPINGS["strict"] else "legitimate",
                    "phishing" if v["verdict"] in MAPPINGS["lenient"] else "legitimate",
                    g["indicator_count"], g["verified"], g["hallucination_rate"],
                    r.get("latency_s"), r.get("json_ok_first_try"),
                    (v["explanation"] or "").replace("\n", " "),
                ])
        print(f"\n  Predictions CSV -> {args.csv}")

    if args.json:
        os.makedirs(os.path.dirname(os.path.abspath(args.json)), exist_ok=True)
        summary = {
            "models": models, "prompts": prompts, "split": args.split,
            "n": len(runs), "label_counts": dict(label_counts),
            "verdict_counts": dict(verdict_counts),
            "abstention_rate": round(abstentions / len(runs), 4),
            "metrics": metrics,
            "reliability": {
                "json_ok_first_try_rate": round(first_try / len(runs), 4),
                "retry_rate": round(retried / len(runs), 4),
                "repairs": dict(repairs), "schema_problems": dict(problems),
            },
            "grounding": {
                "indicators_cited": cited, "verified": verified,
                "mismatched": mismatched, "unverifiable": unverifiable,
                "hallucination_rate": round((mismatched + unverifiable) / cited, 4) if cited else None,
            },
            "latency": {
                "mean": round(sum(lat) / len(lat), 3) if lat else None,
                "median": round(percentile(lat, 50), 3) if lat else None,
                "p90": round(percentile(lat, 90), 3) if lat else None,
                "max": round(max(lat), 3) if lat else None,
            },
        }
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2)
        print(f"  Metrics JSON    -> {args.json}")

    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
