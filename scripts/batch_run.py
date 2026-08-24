#!/usr/bin/env python3
"""
batch_run.py — Day 5. Runs the analyser over a labelled corpus.

Built around one assumption: the run WILL be interrupted. 200 emails at ~6s is
twenty minutes of a laptop staying awake, a VM staying up, and Ollama not
being restarted on the host. Resume is not a nicety.

Resume works by reading logs/runs.jsonl and skipping any raw_sha256 already
recorded for the current model + prompt version. Change either and the run
starts fresh, which is what you want when comparing prompt v1 against v2.

Usage:
    # pilot first — 10 emails, confirms latency before committing
    python3 scripts/batch_run.py --dataset dataset/ --split tune --limit 10

    # the real run
    python3 scripts/batch_run.py --dataset dataset/ --split eval

    # resume after an interruption (same command; already-done work is skipped)
    python3 scripts/batch_run.py --dataset dataset/ --split eval
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import signal
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from eml_parser import parse_eml                              # noqa: E402
from grounding_check import check_indicators                  # noqa: E402
from llm_client import DEFAULT_HOST, DEFAULT_MODEL, OllamaClient, OllamaError  # noqa: E402
from prompt_builder import (build_prompt_input, budget_report,  # noqa: E402
                            load_system_prompt, render_user_message)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_PATH = os.path.join(ROOT, "logs", "runs.jsonl")

_interrupted = False


def _handle_sigint(signum, frame):
    global _interrupted
    if _interrupted:
        print("\n[!] Second interrupt — exiting immediately.", file=sys.stderr)
        raise SystemExit(130)
    _interrupted = True
    print("\n[!] Interrupt received. Finishing the current email, then stopping "
          "cleanly.\n    (Ctrl-C again to abort now; progress so far is already "
          "on disk.)", file=sys.stderr)


def already_done(log_path: str, model: str, prompt_version: str) -> set[str]:
    """
    SHA-256s already analysed under this exact model + prompt combination.

    Only records carrying `true_label` count. Single-email runs from
    analyze.py write to the same log but have no label, so evaluate.py
    ignores them — if resume counted them, an email analysed ad hoc during
    development would be skipped by the batch and then be missing from the
    metrics. That deadlock is silent, which is the worst kind.
    """
    done: set[str] = set()
    if not os.path.exists(log_path):
        return done
    with open(log_path, encoding="utf-8") as fh:
        for line in fh:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not rec.get("true_label"):
                continue
            if rec.get("model") == model and rec.get("prompt_version") == prompt_version:
                if rec.get("raw_sha256"):
                    done.add(rec["raw_sha256"])
    return done


def fmt_duration(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m{seconds % 60:02d}s"
    return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}m"


def main() -> int:
    ap = argparse.ArgumentParser(description="Batch-analyse a labelled corpus.")
    ap.add_argument("--dataset", default="dataset")
    ap.add_argument("--split", choices=["tune", "eval", "all"], default="eval")
    ap.add_argument("--label", choices=["phishing", "legitimate"], help="restrict to one class")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--prompt-version", default="v1")
    ap.add_argument("--body-chars", type=int, default=1200)
    ap.add_argument("--retries", type=int, default=1)
    ap.add_argument("--timeout", type=int, default=180)
    ap.add_argument("--no-resume", action="store_true", help="re-run even if already logged")
    args = ap.parse_args()

    manifest_path = os.path.join(args.dataset, "manifest.csv")
    if not os.path.exists(manifest_path):
        print(f"[FAIL] no manifest at {manifest_path}. Run build_dataset.py first.",
              file=sys.stderr)
        return 1

    with open(manifest_path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))

    if args.split != "all":
        rows = [r for r in rows if r["split"] == args.split]
    if args.label:
        rows = [r for r in rows if r["label"] == args.label]
    if args.limit:
        rows = rows[:args.limit]

    if not rows:
        print("[FAIL] no emails match those filters", file=sys.stderr)
        return 1

    client = OllamaClient(host=args.host, model=args.model, timeout=args.timeout)
    try:
        models = client.ping()
    except OllamaError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    if not any(args.model.split(":")[0] in m for m in models):
        print(f"[WARN] '{args.model}' not among: {', '.join(models)}", file=sys.stderr)

    done = set() if args.no_resume else already_done(LOG_PATH, args.model, args.prompt_version)
    pending = [r for r in rows if r["raw_sha256"] not in done]
    skipped = len(rows) - len(pending)

    print(f"Dataset:  {args.dataset} (split={args.split}"
          + (f", label={args.label}" if args.label else "") + ")")
    print(f"Model:    {args.model} @ {args.host}   prompt={args.prompt_version}")
    print(f"Emails:   {len(rows)} matched, {skipped} already done, {len(pending)} to run")
    if not pending:
        print("\nNothing to do. Run evaluate.py next.")
        return 0
    print()

    system = load_system_prompt(args.prompt_version)
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    signal.signal(signal.SIGINT, _handle_sigint)

    started = time.time()
    latencies: list[float] = []
    failures = 0
    verdict_counts: dict[str, int] = {}

    with open(LOG_PATH, "a", encoding="utf-8") as log_fh:
        for i, row in enumerate(pending, 1):
            if _interrupted:
                print(f"\n[!] Stopped after {i - 1} of {len(pending)}.")
                break

            path = os.path.join(args.dataset, "eml", row["filename"])
            try:
                bundle = parse_eml(path)
            except Exception as exc:
                print(f"  [PARSE FAIL] {row['filename']}: {type(exc).__name__}: {exc}",
                      file=sys.stderr)
                failures += 1
                continue

            condensed = build_prompt_input(bundle, args.body_chars)
            user = render_user_message(condensed)
            budget = budget_report(system, user)

            try:
                result = client.analyse(system, user, max_retries=args.retries)
            except OllamaError as exc:
                print(f"  [LLM FAIL] {row['filename']}: {exc}", file=sys.stderr)
                failures += 1
                if "Cannot reach" in str(exc):
                    print("\n[!] Ollama unreachable — stopping. Fix, then re-run the "
                          "same command; completed work is preserved.", file=sys.stderr)
                    break
                continue

            verdict = result["verdict"]
            grounding = check_indicators(bundle, verdict)
            latencies.append(result["total_latency_s"])
            verdict_counts[verdict["verdict"]] = verdict_counts.get(verdict["verdict"], 0) + 1

            log_fh.write(json.dumps({
                "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "model": result["model"],
                "prompt_version": args.prompt_version,
                "source_file": row["filename"],
                "raw_sha256": row["raw_sha256"],
                "true_label": row["label"],
                "split": row["split"],
                "dataset_source": row.get("source", ""),
                "estimated_prompt_tokens": budget["estimated_prompt_tokens"],
                "actual_prompt_tokens": result["attempts"][-1].get("prompt_tokens"),
                "response_tokens": result["attempts"][-1].get("response_tokens"),
                "latency_s": result["total_latency_s"],
                "attempt_count": len(result["attempts"]),
                "json_ok_first_try": (len(result["attempts"]) == 1
                                      and not result["attempts"][0]["repairs"]),
                "repairs": [r for a in result["attempts"] for r in a["repairs"]],
                "schema_problems": [p for a in result["attempts"]
                                    for p in a.get("schema_problems", [])],
                "verdict": verdict,
                "grounding": {k: v for k, v in grounding.items() if k != "details"},
                "grounding_details": grounding["details"],
                "raw_response": result["attempts"][-1]["raw_content"],
            }, ensure_ascii=False) + "\n")
            log_fh.flush()
            os.fsync(log_fh.fileno())  # survive a VM crash, not just a process exit

            avg = sum(latencies) / len(latencies)
            remaining = len(pending) - i
            eta = fmt_duration(avg * remaining)
            match = "ok " if (
                (verdict["verdict"] in ("phishing", "suspicious") and row["label"] == "phishing")
                or (verdict["verdict"] == "legitimate" and row["label"] == "legitimate")
            ) else "MISS"
            print(f"[{i:>4}/{len(pending)}] {row['filename'][:34]:<34} "
                  f"true={row['label'][:5]:<5} -> {verdict['verdict'][:12]:<12} "
                  f"{match} {result['total_latency_s']:>5.1f}s  ETA {eta}")

    elapsed = time.time() - started
    print("\n" + "=" * 62)
    print(f"Processed {len(latencies)} emails in {fmt_duration(elapsed)}")
    if latencies:
        ordered = sorted(latencies)
        print(f"Latency:  mean {sum(latencies) / len(latencies):.1f}s | "
              f"median {ordered[len(ordered) // 2]:.1f}s | "
              f"min {ordered[0]:.1f}s | max {ordered[-1]:.1f}s")
    if failures:
        print(f"Failures: {failures}")
    if verdict_counts:
        print("Verdicts: " + ", ".join(f"{k}={v}" for k, v in sorted(verdict_counts.items())))
    print(f"Log:      {LOG_PATH}")
    print("=" * 62)
    print("\nNext: python3 scripts/evaluate.py --dataset {} --split {}".format(
        args.dataset, args.split))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
