#!/usr/bin/env python3
"""
build_dataset.py — Day 5. Assembles a labelled evaluation corpus.

Ingests three source shapes and normalises them into one flat directory of
.eml files plus a manifest CSV carrying the ground-truth label.

  mbox     Nazario phishing corpus ships as mbox files
  maildir  Enron ships as a maildir tree (maildir/<user>/<folder>/<n>)
  dir      any directory of loose .eml files

Labels come from the SOURCE, never from content. That is the only defensible
way to label at this scale, and it is also the weak point of the methodology —
see audit_dataset.py, which checks whether the two classes are separable by
provenance artefacts rather than by phishing-ness.

Splits are assigned by hashing the message content, so they are stable across
re-runs and re-orderings:

  tune     small; use freely for prompt iteration (v1 -> v2)
  eval     the rest; touch ONCE, at the end, for reported numbers

The project plan called the held-out set a "dev set". Renamed here to make the
discipline explicit: a dev set you tune against is not held out. If you look at
eval results and then change the prompt, those numbers are no longer clean and
the report has to say so.

Usage:
    python3 scripts/build_dataset.py \
        --phishing-mbox corpora/nazario/phishing3.mbox \
        --legit-maildir corpora/enron/maildir \
        --legit-limit 100 --phishing-limit 100 \
        --out dataset/

    python3 scripts/build_dataset.py --phishing-dir raw/phish --legit-dir raw/ham --out dataset/
"""

from __future__ import annotations

import argparse
import csv
import email
import email.policy
import hashlib
import mailbox
import os
import random
import sys

TUNE_FRACTION = 0.15
MIN_BYTES = 200          # below this it is a fragment, not an email
MAX_BYTES = 2_000_000    # guard against a pathological attachment blob


def content_key(raw: bytes) -> str:
    """
    Dedupe key. Hashes the normalised body + subject rather than the whole
    file, so the same phishing mail collected twice with different Received
    chains collapses to one entry.
    """
    try:
        msg = email.message_from_bytes(raw, policy=email.policy.default)
        subject = (msg.get("Subject") or "").strip().lower()
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    payload = part.get_payload(decode=True) or b""
                    body += payload.decode("utf-8", "replace")
                    break
        else:
            payload = msg.get_payload(decode=True) or b""
            body = payload.decode("utf-8", "replace")
        norm = " ".join((subject + " " + body).split()).lower()[:4000]
        if len(norm) > 40:
            return hashlib.sha256(norm.encode("utf-8")).hexdigest()
    except Exception:
        pass
    return hashlib.sha256(raw).hexdigest()


def split_for(key: str, tune_fraction: float) -> str:
    """Deterministic split from the content hash — stable across runs."""
    bucket = int(key[:8], 16) / 0xFFFFFFFF
    return "tune" if bucket < tune_fraction else "eval"


# ---------------------------------------------------------------------------
# Source readers — each yields raw bytes
# ---------------------------------------------------------------------------


def read_mbox(path: str):
    box = mailbox.mbox(path, factory=None)
    for i, msg in enumerate(box):
        try:
            yield f"{os.path.basename(path)}#{i}", msg.as_bytes()
        except Exception:
            continue


def read_maildir(path: str):
    """
    Walks a maildir tree. Enron's layout is maildir/<user>/<folder>/<n>, which
    is not a valid maildir at the top level, so walk the filesystem directly
    rather than using mailbox.Maildir.
    """
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for name in files:
            if name.startswith("."):
                continue
            full = os.path.join(root, name)
            try:
                if not (MIN_BYTES <= os.path.getsize(full) <= MAX_BYTES):
                    continue
                with open(full, "rb") as fh:
                    yield os.path.relpath(full, path), fh.read()
            except OSError:
                continue


def read_eml_dir(path: str):
    for root, _dirs, files in os.walk(path):
        for name in sorted(files):
            if not name.lower().endswith((".eml", ".txt", ".msg")):
                continue
            full = os.path.join(root, name)
            try:
                with open(full, "rb") as fh:
                    yield os.path.relpath(full, path), fh.read()
            except OSError:
                continue


def collect(sources: list[tuple[str, str]], label: str, limit: int,
            seed: int, seen: set[str]) -> list[dict]:
    """
    Gather up to `limit` unique messages across the given sources.

    Reads everything available, then samples deterministically. Reading the
    whole Enron tree takes a minute but sampling only the first N would bias
    the set toward whichever user sorts first alphabetically — one person's
    mailbox is not a representative sample of legitimate mail.
    """
    pool: list[dict] = []
    for kind, path in sources:
        reader = {"mbox": read_mbox, "maildir": read_maildir, "dir": read_eml_dir}[kind]
        count = 0
        for origin, raw in reader(path):
            if not (MIN_BYTES <= len(raw) <= MAX_BYTES):
                continue
            key = content_key(raw)
            if key in seen:
                continue
            seen.add(key)
            pool.append({"origin": f"{os.path.basename(path)}:{origin}",
                         "raw": raw, "key": key, "source_path": path})
            count += 1
        print(f"    {kind}:{path} -> {count} unique messages", file=sys.stderr)

    if len(pool) > limit:
        rng = random.Random(seed)
        pool = rng.sample(pool, limit)
    elif len(pool) < limit:
        print(f"[WARN] only {len(pool)} available for label '{label}', wanted {limit}",
              file=sys.stderr)

    for entry in pool:
        entry["label"] = label
    return pool


def main() -> int:
    ap = argparse.ArgumentParser(description="Assemble a labelled email corpus.")
    ap.add_argument("--phishing-mbox", action="append", default=[])
    ap.add_argument("--phishing-maildir", action="append", default=[])
    ap.add_argument("--phishing-dir", action="append", default=[])
    ap.add_argument("--legit-mbox", action="append", default=[])
    ap.add_argument("--legit-maildir", action="append", default=[])
    ap.add_argument("--legit-dir", action="append", default=[])
    ap.add_argument("--phishing-limit", type=int, default=100)
    ap.add_argument("--legit-limit", type=int, default=100)
    ap.add_argument("--tune-fraction", type=float, default=TUNE_FRACTION)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default="dataset")
    args = ap.parse_args()

    phish_sources = ([("mbox", p) for p in args.phishing_mbox]
                     + [("maildir", p) for p in args.phishing_maildir]
                     + [("dir", p) for p in args.phishing_dir])
    legit_sources = ([("mbox", p) for p in args.legit_mbox]
                     + [("maildir", p) for p in args.legit_maildir]
                     + [("dir", p) for p in args.legit_dir])

    if not phish_sources or not legit_sources:
        ap.error("need at least one phishing source and one legitimate source")

    for kind, path in phish_sources + legit_sources:
        if not os.path.exists(path):
            ap.error(f"source not found: {path}")

    eml_dir = os.path.join(args.out, "eml")
    os.makedirs(eml_dir, exist_ok=True)

    seen: set[str] = set()
    print("[*] Collecting phishing...", file=sys.stderr)
    phishing = collect(phish_sources, "phishing", args.phishing_limit, args.seed, seen)
    print("[*] Collecting legitimate...", file=sys.stderr)
    legit = collect(legit_sources, "legitimate", args.legit_limit, args.seed + 1, seen)

    entries = phishing + legit
    entries.sort(key=lambda e: e["key"])  # stable ordering independent of read order

    rows = []
    for i, entry in enumerate(entries):
        stem = f"{entry['label'][:5]}_{i:04d}_{entry['key'][:8]}"
        filename = stem + ".eml"
        with open(os.path.join(eml_dir, filename), "wb") as fh:
            fh.write(entry["raw"])
        rows.append({
            "filename": filename,
            "label": entry["label"],
            "split": split_for(entry["key"], args.tune_fraction),
            "content_key": entry["key"],
            "raw_sha256": hashlib.sha256(entry["raw"]).hexdigest(),
            "size_bytes": len(entry["raw"]),
            "source": os.path.basename(entry["source_path"]),
            "origin": entry["origin"][:200],
        })

    manifest = os.path.join(args.out, "manifest.csv")
    with open(manifest, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    counts: dict[tuple[str, str], int] = {}
    for r in rows:
        counts[(r["label"], r["split"])] = counts.get((r["label"], r["split"]), 0) + 1

    print(f"\nWrote {len(rows)} emails to {eml_dir}/")
    print(f"Manifest: {manifest}\n")
    print(f"{'label':<12} {'tune':>6} {'eval':>6} {'total':>6}")
    print("-" * 34)
    for label in ("phishing", "legitimate"):
        t = counts.get((label, "tune"), 0)
        e = counts.get((label, "eval"), 0)
        print(f"{label:<12} {t:>6} {e:>6} {t + e:>6}")
    print("-" * 34)
    print(f"{'TOTAL':<12} {sum(v for k, v in counts.items() if k[1] == 'tune'):>6} "
          f"{sum(v for k, v in counts.items() if k[1] == 'eval'):>6} {len(rows):>6}")
    print("\nNext: python3 scripts/audit_dataset.py --dataset "
          f"{args.out} --out {args.out}/audit.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
