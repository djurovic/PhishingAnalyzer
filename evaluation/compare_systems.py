#!/usr/bin/env python3
"""
compare_systems.py — Day 6. LLM vs rule baseline, head to head.

WHY A PAIRED TEST

Both systems were run on the SAME emails. That makes this a paired design, so
comparing two independent accuracy figures with a chi-square test would throw
away the pairing and overstate the uncertainty. McNemar's test is the correct
choice: it looks only at the emails where the two systems DISAGREE, and asks
whether the disagreements are lopsided enough to be more than chance.

  b = emails where system A is right and B is wrong
  c = emails where A is wrong and B is right

Under the null hypothesis (the systems are equally good), b and c are draws
from a binomial with p=0.5. The exact two-tailed p-value follows directly.
Implemented with math.comb — no scipy, and the arithmetic stays visible.

Note what a small b+c means: if the systems disagree on only a handful of
emails, no test can establish a difference, and the honest report says the
comparison is underpowered rather than quoting a non-significant p-value as
if it were evidence of equivalence.

Usage:
    python3 scripts/compare_systems.py --split eval \
        --a llama3.2 --b rule_baseline_v1
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_PATH = os.path.join(ROOT, "logs", "runs.jsonl")

MAPPINGS = {"strict": {"phishing"}, "lenient": {"phishing", "suspicious"}}


def load_runs(model: str, split: str) -> dict[str, dict]:
    """Latest record per email for one model, keyed by raw_sha256."""
    out: dict[str, dict] = {}
    with open(LOG_PATH, encoding="utf-8") as fh:
        for line in fh:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not rec.get("true_label") or rec.get("model") != model:
                continue
            if split != "all" and rec.get("split") != split:
                continue
            out[rec["raw_sha256"]] = rec
    return out


def mcnemar_exact(b: int, c: int) -> float:
    """Two-tailed exact p-value. b, c = discordant pair counts."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(k + 1)) * (0.5 ** n)
    return min(1.0, 2 * tail)


def metrics(records: list[dict], positives: set[str]) -> dict:
    tp = fp = tn = fn = 0
    for r in records:
        pred = r["verdict"]["verdict"] in positives
        actual = r["true_label"] == "phishing"
        if pred and actual:
            tp += 1
        elif pred:
            fp += 1
        elif actual:
            fn += 1
        else:
            tn += 1
    total = tp + fp + tn + fn
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    return {
        "n": total, "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "accuracy": (tp + tn) / total if total else 0.0,
        "precision": prec, "recall": rec,
        "f1": 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0,
        "fpr": fp / (fp + tn) if (fp + tn) else 0.0,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Compare two systems on the same emails.")
    ap.add_argument("--a", default="llama3.2", help="model name of system A")
    ap.add_argument("--b", default="rule_baseline_v1", help="model name of system B")
    ap.add_argument("--split", default="eval")
    ap.add_argument("--mapping", choices=["strict", "lenient", "both"], default="both")
    ap.add_argument("--json", default=None)
    args = ap.parse_args()

    if not os.path.exists(LOG_PATH):
        print(f"[FAIL] no log at {LOG_PATH}", file=sys.stderr)
        return 1

    a_runs = load_runs(args.a, args.split)
    b_runs = load_runs(args.b, args.split)
    shared = sorted(set(a_runs) & set(b_runs))

    if not shared:
        print(f"[FAIL] no emails scored by BOTH '{args.a}' and '{args.b}' "
              f"in split={args.split}.", file=sys.stderr)
        print(f"       '{args.a}': {len(a_runs)} records, "
              f"'{args.b}': {len(b_runs)} records", file=sys.stderr)
        return 1

    only_a, only_b = len(a_runs) - len(shared), len(b_runs) - len(shared)
    print("=" * 66)
    print(f"SYSTEM COMPARISON — split={args.split}")
    print("=" * 66)
    print(f"  A: {args.a}")
    print(f"  B: {args.b}")
    print(f"  Emails scored by both: {len(shared)}")
    if only_a or only_b:
        print(f"  [!] Excluded — only one system scored them: "
              f"{only_a} A-only, {only_b} B-only")

    summary: dict = {"a": args.a, "b": args.b, "split": args.split,
                     "n_paired": len(shared), "mappings": {}}

    mappings = MAPPINGS if args.mapping == "both" else {args.mapping: MAPPINGS[args.mapping]}
    for name, positives in mappings.items():
        a_recs = [a_runs[k] for k in shared]
        b_recs = [b_runs[k] for k in shared]
        ma, mb = metrics(a_recs, positives), metrics(b_recs, positives)

        print(f"\n  {name.upper()} MAPPING")
        print("  " + "-" * 58)
        print(f"    {'metric':<12} {args.a[:18]:>18} {args.b[:18]:>18}   delta")
        for key in ("accuracy", "precision", "recall", "f1", "fpr"):
            delta = ma[key] - mb[key]
            arrow = "A" if delta > 0.001 else ("B" if delta < -0.001 else "=")
            print(f"    {key:<12} {ma[key]:>18.3f} {mb[key]:>18.3f}   "
                  f"{delta:+.3f} {arrow}")

        # -- McNemar ------------------------------------------------------
        both_right = a_only = b_only = both_wrong = 0
        a_wins: list[str] = []
        b_wins: list[str] = []
        for k in shared:
            actual = a_runs[k]["true_label"] == "phishing"
            a_ok = (a_runs[k]["verdict"]["verdict"] in positives) == actual
            b_ok = (b_runs[k]["verdict"]["verdict"] in positives) == actual
            if a_ok and b_ok:
                both_right += 1
            elif a_ok:
                a_only += 1
                a_wins.append(a_runs[k]["source_file"])
            elif b_ok:
                b_only += 1
                b_wins.append(b_runs[k]["source_file"])
            else:
                both_wrong += 1

        p = mcnemar_exact(a_only, b_only)
        print(f"\n    Paired outcomes:")
        print(f"      both correct           {both_right:>4}")
        print(f"      only A correct         {a_only:>4}")
        print(f"      only B correct         {b_only:>4}")
        print(f"      both wrong             {both_wrong:>4}")
        print(f"\n    McNemar exact two-tailed p = {p:.4f}", end="")
        discordant = a_only + b_only
        if discordant < 10:
            print(f"   [underpowered: only {discordant} disagreements]")
            print("      Too few disagreements to conclude anything. Report this")
            print("      as inconclusive rather than as evidence of equivalence.")
        elif p < 0.05:
            better = args.a if a_only > b_only else args.b
            print(f"   -> significant at 0.05; {better} is better")
        else:
            print("   -> no significant difference at 0.05")

        summary["mappings"][name] = {
            "a": ma, "b": mb,
            "mcnemar": {"both_right": both_right, "only_a": a_only,
                        "only_b": b_only, "both_wrong": both_wrong,
                        "p_value": round(p, 6), "discordant": discordant},
            "a_wins_examples": a_wins[:5], "b_wins_examples": b_wins[:5],
        }

    # -- qualities the metrics miss ---------------------------------------
    print("\n" + "=" * 66)
    print("BEYOND ACCURACY")
    print("=" * 66)
    for label, runs in ((args.a, [a_runs[k] for k in shared]),
                        (args.b, [b_runs[k] for k in shared])):
        lat = [r["latency_s"] for r in runs if r.get("latency_s") is not None]
        cited = sum(r["grounding"]["indicator_count"] for r in runs)
        verified = sum(r["grounding"]["verified"] for r in runs)
        expl = [len(r["verdict"]["explanation"] or "") for r in runs]
        abst = sum(1 for r in runs
                   if r["verdict"]["verdict"] == "insufficient_evidence")
        print(f"\n  {label}")
        if lat:
            ordered = sorted(lat)
            print(f"    latency        mean {sum(lat) / len(lat):>7.2f}s   "
                  f"median {ordered[len(ordered) // 2]:>6.2f}s   "
                  f"total {sum(lat) / 60:>5.1f} min")
        print(f"    indicators     {cited / len(runs):>7.1f} per email, "
              f"{verified}/{cited} verified" if cited else
              f"    indicators     none cited")
        print(f"    explanation    {sum(expl) / len(expl):>7.0f} chars mean")
        print(f"    abstentions    {abst:>7}")

    print("\n  Accuracy is not the whole comparison. If the baseline matches or")
    print("  beats the LLM on F1 while producing no usable explanation, the")
    print("  argument for the LLM rests on the rubric scores, not on this table —")
    print("  and that is a legitimate finding worth stating directly.")

    if args.json:
        os.makedirs(os.path.dirname(os.path.abspath(args.json)), exist_ok=True)
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2)
        print(f"\n  Written to {args.json}")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
