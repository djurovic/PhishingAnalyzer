#!/usr/bin/env python3
"""
audit_dataset.py — Day 5. Checks the corpus for provenance artefacts.

WHY THIS EXISTS

The standard pairing for this project is Nazario (phishing, collected ~2004-2021)
against Enron (legitimate, 1999-2002). These corpora differ in ways that have
nothing to do with whether an email is phishing:

  * SPF was not deployed until ~2004, DKIM ~2007, DMARC ~2012. Enron mail
    PREDATES all three. Every Enron message therefore has no
    Authentication-Results header, while a 2015 phishing sample may well have
    one showing a failure.

    A classifier that learns "no auth headers -> legitimate" scores brilliantly
    on this dataset and is worthless in production, where the mapping is
    closer to the reverse.

  * Enron is internal corporate mail: plain text, few URLs, no HTML, mostly
    intra-domain. Nazario is external, HTML-heavy, URL-heavy. A model keying
    on "has HTML" or "has any URL" is detecting corpus, not intent.

  * Nazario samples often passed through collection infrastructure that
    rewrote or stripped headers; Enron went through the FERC disclosure
    pipeline. Both leave fingerprints.

This script quantifies the problem instead of hand-waving at it. For each
extracted feature it reports prevalence per class and a separation score. A
feature separating the classes almost perfectly is either a genuinely powerful
phishing indicator or an artefact — and the date distribution usually tells
you which.

Reporting this is not an admission of a broken experiment. It is the
difference between an MSc evaluation and a demo. Cite it in Limitations and,
better, act on it: report metrics with the suspect features suppressed as a
sensitivity analysis.

Usage:
    python3 scripts/audit_dataset.py --dataset dataset/ --out dataset/audit.json
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
from collections import Counter, defaultdict
from email.utils import parsedate_to_datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from eml_parser import parse_eml  # noqa: E402

# Features whose separation is expected and legitimate vs. suspicious.
# Anything above HIGH_SEPARATION that is not a known-good phishing signal
# gets flagged for manual review.
EXPECTED_SIGNALS = {
    "auth_failure", "reply_to_domain_mismatch", "return_path_domain_mismatch",
    "has_anchor_text_mismatch", "has_ip_literal_url", "has_punycode_url",
    "has_risky_attachment", "has_redirect_wrapper", "display_name_contains_email",
}
HIGH_SEPARATION = 0.70

BOOLEAN_FEATURES = [
    "reply_to_domain_mismatch", "return_path_domain_mismatch",
    "display_name_contains_email", "auth_failure", "has_ip_literal_url",
    "has_punycode_url", "has_anchor_text_mismatch", "has_redirect_wrapper",
    "has_risky_attachment", "html_present",
]
COUNT_FEATURES = ["url_count", "attachment_count", "html_hidden_elements",
                  "html_form_count", "body_length_chars"]


def median(values: list[float]) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    mid = len(s) // 2
    return float(s[mid]) if len(s) % 2 else (s[mid - 1] + s[mid]) / 2.0


def load_manifest(dataset_dir: str) -> list[dict]:
    path = os.path.join(dataset_dir, "manifest.csv")
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def year_of(date_header: str) -> int | None:
    if not date_header:
        return None
    try:
        return parsedate_to_datetime(date_header).year
    except Exception:
        m = re.search(r"\b(19|20)\d{2}\b", date_header)
        return int(m.group(0)) if m else None


def main() -> int:
    ap = argparse.ArgumentParser(description="Audit a corpus for provenance artefacts.")
    ap.add_argument("--dataset", default="dataset")
    ap.add_argument("--out", default=None)
    ap.add_argument("--limit", type=int, default=0, help="audit only the first N (for a quick look)")
    args = ap.parse_args()

    rows = load_manifest(args.dataset)
    if args.limit:
        rows = rows[:args.limit]
    eml_dir = os.path.join(args.dataset, "eml")

    by_class: dict[str, list[dict]] = defaultdict(list)
    years: dict[str, Counter] = defaultdict(Counter)
    auth_present: dict[str, int] = defaultdict(int)
    parse_failures = 0

    print(f"[*] Parsing {len(rows)} emails...", file=sys.stderr)
    for i, row in enumerate(rows):
        if i and i % 50 == 0:
            print(f"    {i}/{len(rows)}", file=sys.stderr)
        try:
            bundle = parse_eml(os.path.join(eml_dir, row["filename"]))
        except Exception:
            parse_failures += 1
            continue
        label = row["label"]
        by_class[label].append(bundle["derived_signals"])

        y = year_of(bundle["headers"].get("date", ""))
        if y and 1990 < y < 2030:
            years[label][y] += 1
        if bundle["authentication"]["raw_headers"]:
            auth_present[label] += 1

    labels = ["phishing", "legitimate"]
    n = {lab: len(by_class[lab]) for lab in labels}
    if not all(n.values()):
        print("[FAIL] need both classes present", file=sys.stderr)
        return 1

    report: dict = {
        "counts": n,
        "parse_failures": parse_failures,
        "boolean_features": {},
        "count_features": {},
        "temporal": {},
        "auth_header_presence": {},
        "flags": [],
    }

    # -- boolean features -------------------------------------------------
    print("\n" + "=" * 78)
    print("BOOLEAN FEATURE PREVALENCE BY CLASS")
    print("=" * 78)
    print(f"{'feature':<32} {'phishing':>10} {'legit':>10} {'separation':>12}  note")
    print("-" * 78)
    for feat in BOOLEAN_FEATURES:
        rates = {}
        for lab in labels:
            vals = [bool(s.get(feat)) for s in by_class[lab]]
            rates[lab] = sum(vals) / len(vals) if vals else 0.0
        sep = abs(rates["phishing"] - rates["legitimate"])
        note = ""
        if sep >= HIGH_SEPARATION:
            if feat in EXPECTED_SIGNALS:
                note = "strong signal (verify not temporal)"
            else:
                note = "SUSPECT ARTEFACT"
                report["flags"].append({
                    "feature": feat, "separation": round(sep, 3),
                    "reason": "separates classes strongly but is not a "
                              "recognised phishing indicator",
                })
        report["boolean_features"][feat] = {
            "phishing_rate": round(rates["phishing"], 3),
            "legitimate_rate": round(rates["legitimate"], 3),
            "separation": round(sep, 3),
        }
        print(f"{feat:<32} {rates['phishing']:>9.1%} {rates['legitimate']:>9.1%} "
              f"{sep:>11.2f}  {note}")

    # -- count features ---------------------------------------------------
    print("\n" + "=" * 78)
    print("COUNT FEATURE MEDIANS BY CLASS")
    print("=" * 78)
    print(f"{'feature':<32} {'phishing':>12} {'legit':>12}")
    print("-" * 78)
    for feat in COUNT_FEATURES:
        meds = {lab: median([float(s.get(feat, 0) or 0) for s in by_class[lab]])
                for lab in labels}
        report["count_features"][feat] = {lab: meds[lab] for lab in labels}
        print(f"{feat:<32} {meds['phishing']:>12.1f} {meds['legitimate']:>12.1f}")

    # -- temporal separation ---------------------------------------------
    print("\n" + "=" * 78)
    print("TEMPORAL DISTRIBUTION  (the usual source of artefacts)")
    print("=" * 78)
    overlap_years = set(years["phishing"]) & set(years["legitimate"])
    for lab in labels:
        ys = years[lab]
        if ys:
            span = f"{min(ys)}-{max(ys)}"
            common = ", ".join(f"{y}({c})" for y, c in ys.most_common(5))
        else:
            span, common = "(no parseable dates)", ""
        report["temporal"][lab] = {
            "span": span, "parsed": sum(ys.values()),
            "by_year": dict(sorted(ys.items())),
        }
        print(f"  {lab:<12} {span:<14} top years: {common}")

    report["temporal"]["overlapping_years"] = sorted(overlap_years)
    total_dated = sum(years[lab].total() for lab in labels)
    overlap_count = sum(years[lab][y] for lab in labels for y in overlap_years)
    overlap_ratio = overlap_count / total_dated if total_dated else 0.0
    report["temporal"]["overlap_ratio"] = round(overlap_ratio, 3)
    print(f"\n  Overlapping years: {sorted(overlap_years) or 'NONE'}")
    print(f"  Share of dated mail in overlapping years: {overlap_ratio:.1%}")

    if overlap_ratio < 0.20:
        report["flags"].append({
            "feature": "date", "separation": round(1 - overlap_ratio, 3),
            "reason": "the classes barely overlap in time; any feature whose "
                      "deployment changed over that period (SPF/DKIM/DMARC, HTML "
                      "mail, TLS) will separate them for non-phishing reasons",
        })

    # -- authentication header presence -----------------------------------
    print("\n" + "=" * 78)
    print("AUTHENTICATION HEADER PRESENCE  (SPF ~2004, DKIM ~2007, DMARC ~2012)")
    print("=" * 78)
    for lab in labels:
        rate = auth_present[lab] / n[lab]
        report["auth_header_presence"][lab] = round(rate, 3)
        print(f"  {lab:<12} {auth_present[lab]:>4}/{n[lab]:<4} have any auth header  ({rate:.1%})")

    presence_gap = abs(report["auth_header_presence"]["phishing"]
                       - report["auth_header_presence"]["legitimate"])
    if presence_gap >= 0.5:
        report["flags"].append({
            "feature": "authentication_headers_present",
            "separation": round(presence_gap, 3),
            "reason": "presence of auth headers (not their verdict) differs sharply "
                      "between classes — a deployment-era artefact, not a phishing signal",
        })

    # -- verdict ----------------------------------------------------------
    print("\n" + "=" * 78)
    print("AUDIT FLAGS")
    print("=" * 78)
    if not report["flags"]:
        print("  None. Classes do not appear trivially separable by provenance.")
    else:
        for f in report["flags"]:
            print(f"  [!] {f['feature']}  (separation {f['separation']})")
            print(f"      {f['reason']}")
        print("\n  Recommended, in order of preference:")
        print("   1. Source legitimate mail from the same era as the phishing set.")
        print("      NOTE: SpamAssassin (2002-03) and Enron (1999-2002) BOTH predate")
        print("      SPF/DKIM/DMARC deployment, so neither fixes this. Use a personal")
        print("      inbox export, or generate era-matched mail with make_ham.py using")
        print("      --year set to match the phishing corpus.")
        print("   2. If you cannot, run the evaluation twice: once as-is, once with")
        print("      the flagged features suppressed. Report both. The gap between")
        print("      them IS a finding, and a more interesting one than raw accuracy.")
        print("   3. Either way, state this explicitly in Limitations.")

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"\nWritten to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
