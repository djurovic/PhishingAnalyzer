#!/usr/bin/env python3
"""
rubric.py — Day 6. Samples, scores and reports on explanation quality.

WHAT THIS MEASURES THAT THE METRICS DO NOT

evaluate.py answers "was the verdict right?". grounding_check.py answers "were
the cited fields real?". Neither answers "is this explanation any use to an
analyst?" — a model can reach the right verdict, cite genuine fields, and
still produce reasoning that is shallow, misses the strongest indicator, or
gives advice nobody can act on.

That needs a human, which means it needs a rubric, which means it needs to be
systematic rather than an impression formed while scrolling a log.

THE RUBRIC (0-2 per dimension)

  Correctness   Is the reasoning sound? Does it interpret the evidence
                correctly, or does it draw a wrong conclusion from a real
                field? (e.g. treating spf=pass as proof the From header is
                genuine)
                0 = reasoning is wrong  1 = partly sound  2 = sound

  Completeness  Does it mention the STRONGEST available indicator? An
                explanation citing three weak signals while ignoring a
                credential-harvesting form scores low here even if correct.
                0 = misses the main signal  1 = partial  2 = captures it

  Actionability Would a Tier-1 analyst know what to do next? Generic advice
                ("be careful") scores 0; specific containment steps tied to
                this email score 2.
                0 = unusable  1 = generic  2 = specific and actionable

Hallucination is NOT scored by hand — grounding_check.py already computes it
across the whole dataset. Scoring it manually on 40 emails would produce a
worse estimate of something already measured better.

BLIND SCORING

The scorer does not see the true label or whether the verdict was correct.
Knowing an email is phishing makes a confident phishing explanation read as
"complete" and a hedged one as "incomplete", which measures the label rather
than the explanation. Labels are joined back in only at report time.

Usage:
    python3 scripts/rubric.py sample --split eval --n 40
    python3 scripts/rubric.py score          # interactive, resumable
    python3 scripts/rubric.py report
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import random
import sys
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_PATH = os.path.join(ROOT, "logs", "runs.jsonl")
SAMPLE_PATH = os.path.join(ROOT, "results", "rubric_sample.csv")
SCORES_PATH = os.path.join(ROOT, "results", "rubric_scores.csv")

DIMENSIONS = ["correctness", "completeness", "actionability"]
DIM_HELP = {
    "correctness": "Is the reasoning sound? (0 wrong / 1 partly / 2 sound)",
    "completeness": "Does it name the strongest indicator? (0 no / 1 partial / 2 yes)",
    "actionability": "Could a Tier-1 analyst act on it? (0 no / 1 generic / 2 specific)",
}


def load_runs(model: str | None, prompt_version: str | None, split: str | None) -> list[dict]:
    if not os.path.exists(LOG_PATH):
        print(f"[FAIL] no log at {LOG_PATH}", file=sys.stderr)
        raise SystemExit(1)
    latest: dict[tuple, dict] = {}
    with open(LOG_PATH, encoding="utf-8") as fh:
        for line in fh:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not rec.get("true_label"):
                continue
            if model and rec.get("model") != model:
                continue
            if prompt_version and rec.get("prompt_version") != prompt_version:
                continue
            if split and split != "all" and rec.get("split") != split:
                continue
            latest[(rec.get("raw_sha256"), rec.get("model"),
                    rec.get("prompt_version"))] = rec
    return list(latest.values())


def stratum_of(rec: dict) -> str:
    """
    Strata are (verdict x correct/incorrect), not the raw verdict.

    Sampling at random from a run that is 70% confident-phishing gives 28 of
    40 slots to the easy cases and almost none to the errors — but the errors
    are what Discussion is about. Stratifying guarantees the hard cases are
    represented.
    """
    v = rec["verdict"]["verdict"]
    predicted_phish = v in ("phishing", "suspicious")
    actual_phish = rec["true_label"] == "phishing"
    outcome = "hit" if predicted_phish == actual_phish else "miss"
    return f"{v}|{outcome}"


def do_sample(args) -> int:
    runs = load_runs(args.model, args.prompt_version, args.split)
    if not runs:
        print("[FAIL] no labelled runs matched", file=sys.stderr)
        return 1

    by_stratum: dict[str, list[dict]] = defaultdict(list)
    for r in runs:
        by_stratum[stratum_of(r)].append(r)

    print(f"Population: {len(runs)} runs across {len(by_stratum)} strata")
    for s in sorted(by_stratum):
        print(f"  {s:<28} {len(by_stratum[s]):>4}")

    # Round-robin across strata so small strata (the errors) are not
    # squeezed out, then fill remaining slots from the largest.
    rng = random.Random(args.seed)
    pools = {s: rng.sample(v, len(v)) for s, v in by_stratum.items()}
    chosen: list[dict] = []
    while len(chosen) < args.n and any(pools.values()):
        for s in sorted(pools):
            if pools[s] and len(chosen) < args.n:
                chosen.append(pools[s].pop())

    os.makedirs(os.path.dirname(SAMPLE_PATH), exist_ok=True)
    rng.shuffle(chosen)  # present in random order, not grouped by stratum
    with open(SAMPLE_PATH, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["item_id", "raw_sha256", "source_file", "model",
                    "prompt_version", "stratum", "true_label", "verdict",
                    "confidence", "indicator_count", "verified",
                    "hallucination_rate", "explanation", "indicators_json"])
        for i, r in enumerate(chosen, 1):
            v, g = r["verdict"], r["grounding"]
            w.writerow([f"R{i:03d}", r["raw_sha256"], r["source_file"],
                        r["model"], r["prompt_version"], stratum_of(r),
                        r["true_label"], v["verdict"], v["confidence"],
                        g["indicator_count"], g["verified"],
                        g.get("hallucination_rate"),
                        (v["explanation"] or "").replace("\n", " "),
                        json.dumps(v["indicators"], ensure_ascii=False)])

    got = Counter(stratum_of(r) for r in chosen)
    print(f"\nSampled {len(chosen)} items -> {SAMPLE_PATH}")
    for s in sorted(got):
        print(f"  {s:<28} {got[s]:>4}")
    print("\nNext: python3 scripts/rubric.py score")
    return 0


def load_sample() -> list[dict]:
    if not os.path.exists(SAMPLE_PATH):
        print(f"[FAIL] no sample at {SAMPLE_PATH}. Run `rubric.py sample` first.",
              file=sys.stderr)
        raise SystemExit(1)
    with open(SAMPLE_PATH, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def load_scores() -> dict[str, dict]:
    if not os.path.exists(SCORES_PATH):
        return {}
    with open(SCORES_PATH, newline="", encoding="utf-8") as fh:
        return {r["item_id"]: r for r in csv.DictReader(fh)}


def save_scores(scores: dict[str, dict]) -> None:
    os.makedirs(os.path.dirname(SCORES_PATH), exist_ok=True)
    with open(SCORES_PATH, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["item_id"] + DIMENSIONS + ["note"])
        w.writeheader()
        for item_id in sorted(scores):
            w.writerow(scores[item_id])


def do_score(args) -> int:
    sample = load_sample()
    scores = load_scores()
    todo = [row for row in sample if row["item_id"] not in scores]

    if not todo:
        print(f"All {len(sample)} items already scored. "
              f"Run `rubric.py report`, or delete {SCORES_PATH} to start over.")
        return 0

    print("=" * 72)
    print("BLIND RUBRIC SCORING")
    print("=" * 72)
    print("The true label and whether the verdict was correct are HIDDEN — "
          "\nknowing them would bias the score toward the label rather than "
          "\nthe explanation. Judge only what an analyst would see.\n")
    for d in DIMENSIONS:
        print(f"  {d:<15} {DIM_HELP[d]}")
    print("\n  Enter 0, 1 or 2 for each. 's' skips an item, 'q' saves and quits.\n")
    print(f"  {len(todo)} of {len(sample)} remaining.")

    for n, row in enumerate(todo, 1):
        print("\n" + "=" * 72)
        print(f"ITEM {row['item_id']}   ({n} of {len(todo)})")
        print("=" * 72)
        print(f"\nSystem verdict: {row['verdict']}  (confidence {row['confidence']})")
        print(f"\nEXPLANATION:\n  {row['explanation'] or '(none returned)'}")
        try:
            inds = json.loads(row["indicators_json"])
        except json.JSONDecodeError:
            inds = []
        print(f"\nINDICATORS CITED ({len(inds)}):")
        for ind in inds:
            print(f"  [{ind.get('severity', '?'):<6}] {ind.get('indicator', '')}")
            print(f"           field: {ind.get('evidence_field', '')} "
                  f"= {ind.get('evidence_value', '')}")
        if not inds:
            print("  (none)")
        print(f"\n  Grounding: {row['verified']}/{row['indicator_count']} verified")

        entry = {"item_id": row["item_id"], "note": ""}
        quit_now = False
        for d in DIMENSIONS:
            while True:
                raw = input(f"\n  {d} [0/1/2, s=skip, q=quit] > ").strip().lower()
                if raw == "q":
                    quit_now = True
                    break
                if raw == "s":
                    entry = None
                    break
                if raw in ("0", "1", "2"):
                    entry[d] = int(raw)
                    break
                print("    Enter 0, 1, 2, s or q.")
            if quit_now or entry is None:
                break
        if quit_now:
            save_scores(scores)
            print(f"\nSaved {len(scores)} scores to {SCORES_PATH}. "
                  "Re-run `rubric.py score` to continue.")
            return 0
        if entry is None:
            continue
        note = input("  note (optional) > ").strip()
        entry["note"] = note
        scores[row["item_id"]] = entry
        save_scores(scores)

    print(f"\nDone. {len(scores)} items scored -> {SCORES_PATH}")
    print("Next: python3 scripts/rubric.py report")
    return 0


def mean(xs: list[float]) -> float:
    return sum(xs) / len(xs) if xs else 0.0


def do_report(args) -> int:
    sample = {r["item_id"]: r for r in load_sample()}
    scores = load_scores()
    if not scores:
        print(f"[FAIL] no scores at {SCORES_PATH}", file=sys.stderr)
        return 1

    rows = []
    for item_id, s in scores.items():
        if item_id not in sample:
            continue
        base = sample[item_id]
        try:
            vals = {d: int(s[d]) for d in DIMENSIONS}
        except (KeyError, ValueError):
            continue
        rows.append({**base, **vals, "total": sum(vals.values())})

    if not rows:
        print("[FAIL] no complete scored items", file=sys.stderr)
        return 1

    print("=" * 66)
    print(f"RUBRIC REPORT  ({len(rows)} of {len(sample)} sampled items scored)")
    print("=" * 66)
    models = sorted({r["model"] for r in rows})
    print(f"  System(s): {', '.join(models)}")

    print("\n  MEAN SCORES (0-2)")
    print("  " + "-" * 52)
    for d in DIMENSIONS:
        vals = [r[d] for r in rows]
        dist = Counter(vals)
        print(f"    {d:<15} {mean(vals):.2f}   "
              f"(0:{dist[0]:>3}  1:{dist[1]:>3}  2:{dist[2]:>3})")
    print(f"    {'TOTAL (max 6)':<15} {mean([r['total'] for r in rows]):.2f}")

    print("\n  BY VERDICT")
    print("  " + "-" * 52)
    print(f"    {'verdict':<22} {'n':>4}  " + "  ".join(f"{d[:6]:>6}" for d in DIMENSIONS))
    by_v = defaultdict(list)
    for r in rows:
        by_v[r["verdict"]].append(r)
    for v in sorted(by_v):
        g = by_v[v]
        print(f"    {v:<22} {len(g):>4}  "
              + "  ".join(f"{mean([x[d] for x in g]):>6.2f}" for d in DIMENSIONS))

    print("\n  BY OUTCOME  (correct vs incorrect verdict)")
    print("  " + "-" * 52)
    by_o = defaultdict(list)
    for r in rows:
        by_o["correct" if r["stratum"].endswith("hit") else "incorrect"].append(r)
    for o in ("correct", "incorrect"):
        g = by_o.get(o, [])
        if g:
            print(f"    {o:<22} {len(g):>4}  "
                  + "  ".join(f"{mean([x[d] for x in g]):>6.2f}" for d in DIMENSIONS))
    if by_o.get("correct") and by_o.get("incorrect"):
        gap = mean([r["total"] for r in by_o["correct"]]) - \
              mean([r["total"] for r in by_o["incorrect"]])
        print(f"\n    Quality gap (correct - incorrect): {gap:+.2f} of 6")
        if gap < 0.5:
            print("    [!] Explanations for WRONG verdicts score nearly as well as")
            print("        for right ones. The model is equally fluent when mistaken,")
            print("        so explanation quality gives an analyst no signal about")
            print("        when to distrust it. Worth stating plainly in Discussion.")

    print("\n  GROUNDING vs RUBRIC")
    print("  " + "-" * 52)
    hi = [r for r in rows if r.get("hallucination_rate") not in ("", None)
          and float(r["hallucination_rate"] or 0) > 0]
    lo = [r for r in rows if r.get("hallucination_rate") in ("", None)
          or float(r["hallucination_rate"] or 0) == 0]
    for name, g in (("fully grounded", lo), ("some hallucination", hi)):
        if g:
            print(f"    {name:<22} {len(g):>4}  "
                  + "  ".join(f"{mean([x[d] for x in g]):>6.2f}" for d in DIMENSIONS))

    worst = sorted(rows, key=lambda r: r["total"])[:args.examples]
    print(f"\n  LOWEST-SCORING EXPLANATIONS  (case-study candidates)")
    print("  " + "-" * 52)
    for r in worst:
        print(f"    {r['item_id']} {r['source_file'][:30]:<30} total {r['total']}/6 "
              f"({r['verdict']}, true={r['true_label']})")
        print(f"      \"{(r['explanation'] or '')[:120]}...\"")
        if scores[r["item_id"]].get("note"):
            print(f"      note: {scores[r['item_id']]['note']}")

    if args.csv:
        os.makedirs(os.path.dirname(os.path.abspath(args.csv)), exist_ok=True)
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["item_id", "source_file", "model", "true_label", "verdict",
                        "stratum"] + DIMENSIONS + ["total", "note"])
            for r in sorted(rows, key=lambda x: x["item_id"]):
                w.writerow([r["item_id"], r["source_file"], r["model"],
                            r["true_label"], r["verdict"], r["stratum"]]
                           + [r[d] for d in DIMENSIONS]
                           + [r["total"], scores[r["item_id"]].get("note", "")])
        print(f"\n  Written to {args.csv}")
    print()
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Explanation-quality rubric.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("sample", help="draw a stratified sample to score")
    s.add_argument("--n", type=int, default=40)
    s.add_argument("--split", default="eval")
    s.add_argument("--model", default=None)
    s.add_argument("--prompt-version", default=None)
    s.add_argument("--seed", type=int, default=42)
    s.set_defaults(func=do_sample)

    c = sub.add_parser("score", help="score the sample interactively (blind)")
    c.set_defaults(func=do_score)

    r = sub.add_parser("report", help="aggregate the scores")
    r.add_argument("--examples", type=int, default=3)
    r.add_argument("--csv", default=None)
    r.set_defaults(func=do_report)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
