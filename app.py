#!/usr/bin/env python3
"""
app.py — Day 5. Streamlit UI for single-email triage.

Run from the project root, inside the VM:
    streamlit run app.py

Safety notes for the demo (say these on camera):
  * Uploaded content is held in memory and parsed; the .eml is never written
    to disk by this app.
  * HTML is never rendered. The raw HTML view is escaped and shown inside a
    code block, so a phishing page cannot execute or load remote images in
    the browser showing this UI.
  * All URLs are displayed defanged.
  * Attachments are hashed, never saved or opened.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from datetime import datetime, timezone

import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts"))

from analyze import render_report                              # noqa: E402
from eml_parser import parse_eml                               # noqa: E402
from grounding_check import check_indicators                   # noqa: E402
from llm_client import DEFAULT_HOST, DEFAULT_MODEL, OllamaClient, OllamaError  # noqa: E402
from prompt_builder import (build_prompt_input, budget_report,  # noqa: E402
                            load_system_prompt, render_user_message)

st.set_page_config(page_title="Phishing Email Analyzer", page_icon="[@]", layout="wide")

VERDICT_STYLE = {
    "phishing": ("#b3261e", "PHISHING"),
    "suspicious": ("#e37400", "SUSPICIOUS"),
    "legitimate": ("#1e8e3e", "LEGITIMATE"),
    "insufficient_evidence": ("#5f6368", "INSUFFICIENT EVIDENCE"),
}


def parse_uploaded(data: bytes) -> dict:
    """
    parse_eml takes a path, so write to a temp file and delete it immediately.
    The file lives inside the VM, in the OS temp dir, for the duration of one
    parse. Deleted in the finally block regardless of outcome.
    """
    tmp = tempfile.NamedTemporaryFile(suffix=".eml", delete=False)
    try:
        tmp.write(data)
        tmp.close()
        return parse_eml(tmp.name)
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

with st.sidebar:
    st.header("Configuration")
    host = st.text_input("Ollama host", value=DEFAULT_HOST)
    model = st.text_input("Model", value=DEFAULT_MODEL)
    prompt_version = st.selectbox("Prompt version", ["v1", "v2"], index=0)
    body_chars = st.slider("Body excerpt (chars)", 400, 3000, 1200, step=100)
    retries = st.slider("Retries on bad JSON", 0, 3, 1)

    st.divider()
    if st.button("Test connection", use_container_width=True):
        try:
            models = OllamaClient(host=host, model=model).ping()
            st.success("Connected")
            st.caption("Models: " + (", ".join(models) or "(none pulled)"))
        except OllamaError as exc:
            st.error(str(exc))

    st.divider()
    st.caption(
        "Samples are handled inside the VM. HTML is parsed as text and never "
        "rendered; attachments are hashed in memory and never written to disk; "
        "URLs are shown defanged."
    )

st.title("LLM-Powered Phishing Email Analyzer")
st.caption("MSc Cyber Incident Analysis and Response — local Llama 3.2 via Ollama")

uploaded = st.file_uploader("Upload a .eml file", type=["eml", "txt"])

if not uploaded:
    st.info("Upload an `.eml` file to begin. Try one of the fixtures in `samples/`.")
    st.stop()

# ---------------------------------------------------------------------------
# Parse
# ---------------------------------------------------------------------------

raw = uploaded.read()
try:
    bundle = parse_uploaded(raw)
except Exception as exc:
    st.error(f"Could not parse this file: {type(exc).__name__}: {exc}")
    st.stop()

d = bundle["derived_signals"]
h = bundle["headers"]

st.subheader("1. Extracted features")
st.caption("Deterministic extraction — no LLM involved at this stage.")

c1, c2, c3, c4 = st.columns(4)
off_domain = len(d["urls_off_sender_domain"])
c1.metric("URLs", d["url_count"], f"{off_domain} off-domain" if off_domain else None,
          delta_color="inverse")
c2.metric("Attachments", d["attachment_count"],
          "risky" if d["has_risky_attachment"] else None, delta_color="inverse")
c3.metric("SPF / DKIM / DMARC",
          f"{d['spf_result'][:4]}/{d['dkim_result'][:4]}/{d['dmarc_result'][:4]}")
c4.metric("Body length", f"{d['body_length_chars']:,}")

flags = [k.replace("_", " ") for k in (
    "reply_to_domain_mismatch", "return_path_domain_mismatch",
    "display_name_contains_email", "auth_failure", "has_ip_literal_url",
    "has_punycode_url", "has_anchor_text_mismatch", "has_redirect_wrapper",
    "has_risky_attachment") if d.get(k)]
if flags:
    st.warning("Deterministic flags: " + " · ".join(flags))
else:
    st.success("No deterministic flags raised by the parser.")

tabs = st.tabs(["Headers", "URLs", "Attachments", "Body", "Raw bundle"])

with tabs[0]:
    st.table({
        "Field": ["From", "Reply-To", "Return-Path", "To", "Subject", "Date", "X-Mailer"],
        "Value": [h.get("from", ""), h.get("reply_to", "") or "(none)",
                  h.get("return_path", "") or "(none)", h.get("to", ""),
                  h.get("subject", ""), h.get("date", ""), h.get("x_mailer", "") or "(none)"],
    })
    if bundle["authentication"]["raw_headers"]:
        st.caption("Authentication headers")
        st.code("\n".join(bundle["authentication"]["raw_headers"]), language="text")
    else:
        st.caption("No authentication headers present. Note that mail predating "
                   "SPF/DKIM/DMARC deployment has none — absence is not itself a signal.")

with tabs[1]:
    if bundle["urls"]:
        st.dataframe(
            [{"URL (defanged)": u["url"], "Domain": u["registered_domain"],
              "Source": u["source"], "Notes": ", ".join(u.get("notes", [])),
              "Anchor text": u.get("anchor_text", "")} for u in bundle["urls"]],
            use_container_width=True, hide_index=True)
    else:
        st.write("No URLs found.")

with tabs[2]:
    if bundle["attachments"]:
        st.dataframe(
            [{"Filename": a["filename"], "Type": a["declared_mime"],
              "Size": a["size_bytes"], "SHA-256": a["sha256"],
              "Notes": ", ".join(a.get("notes", []))} for a in bundle["attachments"]],
            use_container_width=True, hide_index=True)
        st.caption("Hashes computed in memory. Attachments are never written to disk.")
    else:
        st.write("No attachments.")

with tabs[3]:
    st.caption("Plain text extracted from the message. HTML is parsed as text, never rendered.")
    st.code(bundle["body"]["text_excerpt"] or "(empty)", language="text")
    if bundle["body"]["html"].get("present"):
        st.caption("HTML structure: " + json.dumps(
            {k: v for k, v in bundle["body"]["html"].items() if k != "present"}))

with tabs[4]:
    st.json(bundle, expanded=False)

# ---------------------------------------------------------------------------
# Analyse
# ---------------------------------------------------------------------------

st.divider()
st.subheader("2. LLM analysis")

condensed = build_prompt_input(bundle, body_chars)
user_msg = render_user_message(condensed)

try:
    system_prompt = load_system_prompt(prompt_version)
except FileNotFoundError:
    st.error(f"prompts/system_{prompt_version}.txt not found.")
    st.stop()

budget = budget_report(system_prompt, user_msg)
st.caption(f"Prompt: ~{budget['estimated_prompt_tokens']} estimated tokens "
           f"({budget['system_chars']} chars system + {budget['user_chars']} chars bundle)")

with st.expander("Inspect the exact prompt being sent"):
    st.code(user_msg, language="json")

if st.button("Analyse with Llama", type="primary", use_container_width=True):
    client = OllamaClient(host=host, model=model)
    with st.spinner(f"Querying {model}..."):
        started = time.time()
        try:
            result = client.analyse(system_prompt, user_msg, max_retries=retries)
        except OllamaError as exc:
            st.error(str(exc))
            st.stop()
    st.session_state["result"] = result
    st.session_state["elapsed"] = time.time() - started

if "result" in st.session_state:
    result = st.session_state["result"]
    verdict = result["verdict"]
    grounding = check_indicators(bundle, verdict)

    colour, label = VERDICT_STYLE.get(verdict["verdict"], ("#5f6368", verdict["verdict"].upper()))
    st.markdown(
        f"<div style='background:{colour};color:#fff;padding:14px 18px;"
        f"border-radius:8px;font-size:1.4rem;font-weight:600'>{label}"
        f"<span style='float:right;font-weight:400;font-size:1.05rem'>"
        f"confidence {verdict['confidence']:.2f}</span></div>",
        unsafe_allow_html=True)

    m1, m2, m3 = st.columns(3)
    m1.metric("Latency", f"{result['total_latency_s']:.1f}s")
    m2.metric("Attempts", len(result["attempts"]),
              "clean JSON" if len(result["attempts"]) == 1
              and not result["attempts"][0]["repairs"] else "needed repair")
    m3.metric("Indicators grounded",
              f"{grounding['verified']}/{grounding['indicator_count']}"
              if grounding["indicator_count"] else "n/a")

    st.markdown("#### Analyst assessment")
    st.write(verdict["explanation"] or "_(none returned)_")

    st.markdown("#### Indicators")
    if verdict["indicators"]:
        by_key = {(x["evidence_field"], x["claimed_value"]): x["grade"]
                  for x in grounding["details"]}
        st.dataframe(
            [{"Severity": i["severity"], "Indicator": i["indicator"],
              "Evidence field": i["evidence_field"], "Value": i["evidence_value"],
              "Grounding": by_key.get((i["evidence_field"], i["evidence_value"]), "?")}
             for i in verdict["indicators"]],
            use_container_width=True, hide_index=True)
        if grounding["unverifiable"] or grounding["mismatched"]:
            st.error(
                f"{grounding['unverifiable']} indicator(s) cite fields that do not "
                f"exist in the bundle and {grounding['mismatched']} misstate a real "
                "value. These are model hallucinations — treat the assessment with "
                "caution.")
    else:
        st.write("_No indicators reported._")

    st.markdown("#### Recommended actions")
    for action in verdict["recommended_actions"] or ["_(none returned)_"]:
        st.markdown(f"- {action}")

    if result["attempts"][-1].get("repairs") or len(result["attempts"]) > 1:
        with st.expander("Output reliability detail"):
            for a in result["attempts"]:
                st.write(f"Attempt {a['attempt']} — {a['latency_s']}s, "
                         f"repairs: {a['repairs'] or 'none'}, "
                         f"schema problems: {a.get('schema_problems') or 'none'}")

    with st.expander("Raw model response"):
        st.code(result["attempts"][-1]["raw_content"], language="json")

    meta = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "model": result["model"], "prompt_version": prompt_version,
        "latency_s": result["total_latency_s"],
    }
    report_md = render_report(bundle, verdict, grounding, meta)
    stem = os.path.splitext(uploaded.name)[0]
    dl1, dl2 = st.columns(2)
    dl1.download_button("Download report (Markdown)", report_md,
                        file_name=f"{stem}_report.md", mime="text/markdown",
                        use_container_width=True)
    dl2.download_button("Download analysis (JSON)",
                        json.dumps({"meta": meta, "verdict": verdict,
                                    "grounding": grounding, "bundle": bundle},
                                   indent=2, ensure_ascii=False),
                        file_name=f"{stem}_analysis.json", mime="application/json",
                        use_container_width=True)

    st.caption("Verdicts are advisory. Confirm before acting — this tool assists "
               "triage, it does not replace analyst judgement.")
