#!/usr/bin/env python3
"""
prompt_builder.py — Day 4. Turns a Day 3 feature bundle into LLM prompt input.

The full bundle is too big and too noisy for a 3B model. This module selects a
subset, trims it to a token budget, and renders it as the user message.

Design rule: everything the model is asked to cite as evidence MUST be present
in the condensed view. If a field is dropped here, the model cannot ground an
indicator in it, and grounding_check.py would then flag the citation as
unverifiable. Condensing and verification are two halves of the same contract.

Usage as a library:
    from prompt_builder import build_prompt_input, render_user_message
"""

from __future__ import annotations

import json
import os
import re

# Roughly 4 characters per token for English text with Llama tokenizers.
# Only an estimate for pre-flight budgeting — Ollama returns the exact
# prompt_eval_count after the call, and that is what gets logged.
CHARS_PER_TOKEN = 4.0

DEFAULT_BODY_CHARS = 1200
MAX_URLS = 8
MAX_ATTACHMENTS = 6
MAX_HOPS = 3

PROMPT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "prompts")


def estimate_tokens(text: str) -> int:
    return int(len(text) / CHARS_PER_TOKEN)


_URL_IN_TEXT = re.compile(r"(?i)\b(?:https?://|www\d{0,3}\.)[^\s<>\"'`\\\])}]+")


def defang_body(text: str) -> str:
    """
    The parser defangs the `urls` list but leaves body text raw. The system
    prompt tells the model every URL it sees is defanged, so make that true
    here — otherwise the model sees two formats for the same URL and has
    sometimes reported the difference as an indicator in its own right.
    """
    def _sub(m):
        u = m.group(0)
        return (u.replace("http://", "hxxp://")
                 .replace("https://", "hxxps://")
                 .replace(".", "[.]"))
    return _URL_IN_TEXT.sub(_sub, text)


def load_system_prompt(version: str = "v1") -> str:
    path = os.path.join(PROMPT_DIR, f"system_{version}.txt")
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read().strip()


def _condense_url(u: dict) -> dict:
    out = {
        "url": u.get("url", ""),
        "registered_domain": u.get("registered_domain", ""),
        "source": u.get("source", ""),
    }
    if u.get("notes"):
        out["notes"] = u["notes"]
    if u.get("anchor_text"):
        out["anchor_text"] = u["anchor_text"][:120]
    if u.get("unicode_host"):
        out["unicode_host"] = u["unicode_host"]
    if u.get("redirect_wrapper"):
        out["redirect_wrapper"] = u["redirect_wrapper"]
    return out


def _condense_attachment(a: dict) -> dict:
    out = {
        "filename": a.get("filename", ""),
        "declared_mime": a.get("declared_mime", ""),
        "size_bytes": a.get("size_bytes", 0),
    }
    if a.get("sniffed_mime"):
        out["sniffed_mime"] = a["sniffed_mime"]
    if a.get("notes"):
        out["notes"] = a["notes"]
    return out


def _interesting_signals(derived: dict) -> dict:
    """
    Drop signals that are False or zero. A 3B model treats a long list of
    "false" values as noise and, worse, sometimes cites them as if they were
    positive findings. Absent means not observed.
    """
    keep = {}
    always = {"from_registered_domain", "spf_result", "dkim_result",
              "dmarc_result", "url_count", "attachment_count"}
    for k, v in derived.items():
        if k in always:
            keep[k] = v
        elif isinstance(v, bool) and v:
            keep[k] = v
        elif isinstance(v, list) and v:
            keep[k] = v
        elif isinstance(v, (int, float)) and not isinstance(v, bool) and v:
            keep[k] = v
        elif isinstance(v, str) and v:
            keep[k] = v
    keep.pop("body_length_chars", None)  # not analytically useful to the model
    return keep


def build_prompt_input(bundle: dict, body_chars: int = DEFAULT_BODY_CHARS) -> dict:
    """Select the subset of the feature bundle that the LLM actually sees."""
    headers = bundle.get("headers", {})
    auth = bundle.get("authentication", {})

    condensed = {
        "headers": {k: v for k, v in {
            "from": headers.get("from", ""),
            "reply_to": headers.get("reply_to", ""),
            "return_path": headers.get("return_path", ""),
            "to": headers.get("to", ""),
            "subject": headers.get("subject", ""),
            "date": headers.get("date", ""),
            "x_mailer": headers.get("x_mailer", ""),
        }.items() if v},
        "authentication": {
            "spf": auth.get("spf", "not_found"),
            "dkim": auth.get("dkim", "not_found"),
            "dmarc": auth.get("dmarc", "not_found"),
            "dkim_signature_present": auth.get("dkim_signature_present", False),
        },
        "derived_signals": _interesting_signals(bundle.get("derived_signals", {})),
        "urls": [_condense_url(u) for u in bundle.get("urls", [])[:MAX_URLS]],
        "attachments": [_condense_attachment(a) for a in bundle.get("attachments", [])[:MAX_ATTACHMENTS]],
        "body_excerpt": defang_body((bundle.get("body", {}).get("text_excerpt", "") or "")[:body_chars]),
    }

    html = bundle.get("body", {}).get("html", {})
    if html.get("present"):
        condensed["html_structure"] = {
            k: v for k, v in html.items()
            if k != "present" and isinstance(v, int) and v
        } or {"present": True}

    hops = bundle.get("received_chain", [])
    if hops:
        condensed["originating_hop"] = {
            k: v for k, v in hops[-1].items() if k in ("from", "by", "ip") and v
        }

    # Record what was truncated, so the model knows its view is partial.
    dropped = []
    if len(bundle.get("urls", [])) > MAX_URLS:
        dropped.append(f"{len(bundle['urls']) - MAX_URLS} additional URLs")
    if len(bundle.get("attachments", [])) > MAX_ATTACHMENTS:
        dropped.append(f"{len(bundle['attachments']) - MAX_ATTACHMENTS} additional attachments")
    full_body = bundle.get("body", {}).get("text_length_chars", 0)
    if full_body > body_chars:
        dropped.append(f"body truncated from {full_body} chars")
    if dropped:
        condensed["_truncation_note"] = "Not shown: " + "; ".join(dropped)

    return condensed


def render_user_message(condensed: dict) -> str:
    return ("FEATURE BUNDLE:\n"
            + json.dumps(condensed, indent=1, ensure_ascii=False)
            + "\n\nOutput JSON only.")


def budget_report(system_prompt: str, user_message: str) -> dict:
    return {
        "system_chars": len(system_prompt),
        "user_chars": len(user_message),
        "estimated_prompt_tokens": estimate_tokens(system_prompt + user_message),
    }


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Preview the prompt built from a feature bundle.")
    ap.add_argument("bundle_json")
    ap.add_argument("--body-chars", type=int, default=DEFAULT_BODY_CHARS)
    ap.add_argument("--full", action="store_true", help="print the system prompt too")
    args = ap.parse_args()

    with open(args.bundle_json, encoding="utf-8") as fh:
        bundle = json.load(fh)

    system = load_system_prompt()
    condensed = build_prompt_input(bundle, args.body_chars)
    user = render_user_message(condensed)

    if args.full:
        print("=" * 70)
        print("SYSTEM PROMPT")
        print("=" * 70)
        print(system)
    print("=" * 70)
    print("USER MESSAGE")
    print("=" * 70)
    print(user)
    print("=" * 70)
    b = budget_report(system, user)
    print(f"system: {b['system_chars']} chars | user: {b['user_chars']} chars "
          f"| estimated total: ~{b['estimated_prompt_tokens']} tokens")
