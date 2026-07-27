# LLM-Powered Phishing Email Analyzer

**Course:** Cyber Incident Analysis and Response (MSc)
**Project type:** Beginner-friendly, LLM-assisted incident response tool

---

## 1. Project Overview

Build a small tool that ingests a raw email file (`.eml`), extracts its technical components (headers, URLs, attachments, sender info), and uses a Large Language Model to:

1. Classify the email as **Phishing / Suspicious / Legitimate**
2. Produce an **analyst-style explanation** of *why*, in the format an IR analyst would write in a ticket
3. Suggest **recommended response actions** aligned with a standard IR playbook (contain / eradicate / recover)

The core research angle is not classification accuracy alone — it is the **quality of the explanation** the LLM adds on top of a classification, since that is what makes it useful for a human analyst compared to a plain ML classifier.

---

## 2. Learning Goals

- Understand the anatomy of a phishing email (headers, SPF/DKIM/DMARC, URL obfuscation, attachment types).
- Apply the NIST SP 800-61 incident response lifecycle (Preparation → Detection & Analysis → Containment/Eradication/Recovery → Post-incident) to a real workflow.
- Use an LLM API responsibly: prompt design, structured output, hallucination handling.
- Evaluate an AI-assisted security tool with a defensible methodology.

---

## 3. Scope

### In scope
- Single-email analysis (one `.eml` file at a time).
- Local, command-line tool + a minimal Streamlit UI.
- Use of a **local LLM (Llama 3.2 via Ollama)**. No fine-tuning, only prompt engineering.
- Evaluation on ~100–200 emails from public datasets.

### Out of scope (keep it simple)
- Real-time email gateway integration.
- Automated URL sandbox detonation (mention as future work).
- Full SOAR-style automation.
- Multi-language email handling (stick to English).

---

## 4. Tech Stack

| Layer | Choice | Why |
|---|---|---|
| Language | Python 3.11+ | Rich email/security libraries |
| Email parsing | `email` (stdlib), `mail-parser` | Robust `.eml` parsing |
| URL/IOC extraction | `tldextract`, `re`, `iocextract` | Simple, well-maintained |
| Attachment inspection | `python-magic`, `hashlib` | File type + hashing (VirusTotal lookup optional) |
| LLM (local) | Llama 3.2 via Ollama | Runs offline, no API cost, good for privacy-sensitive email data |
| UI | Streamlit | Beginner-friendly, no frontend code needed |
| Evaluation | `pandas`, `scikit-learn` (metrics only) | Standard for accuracy/precision/recall |

---

## 5. Architecture (High Level)

```
┌─────────────┐    ┌──────────────────┐    ┌─────────────────┐    ┌──────────────┐
│  .eml file  │ -> │  Email Parser    │ -> │  Feature Bundle │ -> │  LLM Prompt  │
└─────────────┘    │ (headers, URLs,  │    │  (structured    │    │  + Response  │
                   │  attachments,    │    │  JSON of        │    │  (classify + │
                   │  auth results)   │    │  extracted data)│    │  explain +   │
                   └──────────────────┘    └─────────────────┘    │  recommend)  │
                                                                  └──────┬───────┘
                                                                         │
                                                                         v
                                                             ┌────────────────────┐
                                                             │  Analyst Report    │
                                                             │  (Markdown / JSON) │
                                                             └────────────────────┘
```

Key idea: **you do the deterministic extraction in Python**, and the LLM only reasons about a clean structured summary. This drastically reduces hallucination and token cost.

---

## 6. Datasets

- **Phishing:** [Nazario Phishing Corpus](https://monkey.org/~jose/phishing/), [PhishTank](https://phishtank.org/) archives
- **Legitimate:** [Enron email dataset](https://www.cs.cmu.edu/~enron/) (sample a subset)
- **Aim:** ~100 phishing + ~100 legitimate for evaluation. Keep a small labeled dev set (10–20) that you never use for prompt tuning, only for final evaluation.

> ⚠️ Handle phishing samples in an isolated folder. Never click links or open attachments outside a VM.

---

## 7. Implementation Milestones (~6–8 days)

### Day 1 — VM setup & foundations
- [ ] Download and install **VirtualBox** (free) or **VMware Workstation Player**.
- [ ] Download **Ubuntu 22.04 LTS Desktop** ISO.
- [ ] Create a new VM: 4 CPU cores, 8+ GB RAM, 40 GB disk, enable virtualization in BIOS if needed.
- [ ] Install Ubuntu inside the VM. Take a **snapshot** once clean ("clean-install").
- [ ] Install VirtualBox Guest Additions (shared clipboard, better resolution).
- [ ] Set the VM network to **NAT** (safer for handling phishing samples — no bridged access to your LAN).
- [ ] Update system: `sudo apt update && sudo apt upgrade -y`.
- [ ] Install basics: `sudo apt install -y python3-pip python3-venv git curl build-essential`.
- [ ] Install Git, create a GitHub repo, clone it into the VM.
- [ ] Read: NIST SP 800-61 §3 (Detection & Analysis), Brathwaite phishing chapter, Murdoch's phishing triage section.
- [ ] Take a second snapshot ("dev-ready").

### Day 2 — Ollama + Llama 3.2 setup
- [ ] Install Ollama: `curl -fsSL https://ollama.com/install.sh | sh`.
- [ ] Pull the model: `ollama pull llama3.2` (start with the 3B variant; try 1B if RAM is tight).
- [ ] Verify it runs: `ollama run llama3.2` → ask it a test question.
- [ ] Test the HTTP API on `http://localhost:11434/api/generate` with `curl`.
- [ ] Set up Python project: virtualenv, `requirements.txt` (`ollama`, `mail-parser`, `tldextract`, `iocextract`, `python-magic`, `streamlit`, `pandas`).
- [ ] Write a minimal Python script that sends a prompt to Llama 3.2 via the `ollama` Python client and prints the response.
- [ ] Benchmark: how long does one query take? (This shapes your evaluation.)

### Day 3 — Email parser
- [ ] Parse `.eml` files: extract `From`, `Reply-To`, `Return-Path`, `Received` chain, `Subject`, body (text + HTML).
- [ ] Extract URLs from body + HTML `href`s. Decode obfuscated URLs.
- [ ] Extract attachments: filename, MIME type, SHA-256 hash.
- [ ] Extract auth results: SPF, DKIM, DMARC from headers.
- [ ] **Output:** a clean JSON "feature bundle" per email.
- [ ] Test on 3–5 sample emails (mix of phishing and legit).

### Day 4 — LLM integration (v1)
- [ ] Design the prompt: system message defining the analyst persona + expected structured output (JSON schema: `verdict`, `confidence`, `indicators`, `explanation`, `recommended_actions`).
- [ ] Include a few-shot example in the prompt (Llama 3.2 needs this more than bigger models).
- [ ] Send the feature bundle to Llama, parse the JSON response.
- [ ] Handle errors: malformed JSON (very common with small local models — add a retry with a "please return valid JSON only" reminder), timeouts, refusals.
- [ ] Log every request/response to disk for later analysis.

### Day 5 — Streamlit UI + evaluation setup
- [ ] Streamlit: upload button → shows parsed features → shows LLM verdict + explanation.
- [ ] Downloadable analyst report (Markdown).
- [ ] Assemble evaluation dataset (~100 phishing + ~100 legit).
- [ ] Write a batch runner: process all emails, log verdicts + explanations + latency.
- [ ] Compute: accuracy, precision, recall, F1, false positive rate.

### Day 6 — Explanation quality evaluation
- [ ] Design a rubric to score the LLM's explanations:
  - **Correctness** (does it cite real indicators from the email?)
  - **Completeness** (does it mention the strongest indicators?)
  - **Hallucination rate** (does it invent indicators that aren't there?)
  - **Actionability** (would an analyst know what to do next?)
- [ ] Score a sample of 30–50 explanations manually against the rubric.
- [ ] Build the rule-based baseline classifier and run it on the same dataset.

### Day 7 — Write-up
- [ ] Report structure: Introduction → Background (IR lifecycle, phishing landscape) → Design → Implementation → Evaluation → Discussion → Limitations → Future Work.
- [ ] Include: architecture diagram, screenshots, evaluation tables, 2–3 case-study emails walked through in detail.

### Day 8 — Buffer / polish / demo
- [ ] Record a short demo video (from inside the VM).
- [ ] Clean up the repo, add a README with install instructions.
- [ ] Final VM snapshot ("submission").

---

## 8. Prompt Design Notes

- Force **structured output** (JSON) — makes downstream parsing reliable.
- Include a **few-shot example** of a good analyst response in the system prompt.
- Instruct the model to say `"insufficient_evidence"` rather than guess when unsure.
- Ask for **evidence quoting**: every indicator must reference a specific field from the feature bundle (mitigates hallucination).
- Keep the prompt versioned in Git — you'll iterate on it a lot.

---

## 9. Evaluation Metrics

| Metric | Why it matters |
|---|---|
| Accuracy, Precision, Recall, F1 | Standard classifier metrics |
| False Positive Rate | Critical — analysts drown in FPs |
| Explanation correctness (rubric) | The real value-add of using an LLM |
| Hallucination rate | Trust / safety of the tool |
| Avg. latency per email | Practical usability (local models are slower — this matters) |
| Avg. RAM / CPU usage | Feasibility on modest hardware |

Compare against a **naive baseline**: a rule-based classifier (e.g. "phishing if SPF fails AND URL domain ≠ sender domain"). This makes your LLM results meaningful.

---

## 10. Deliverables

1. **Source code repo** (GitHub) with README, install instructions, and example emails.
2. **Streamlit demo app**.
3. **Written report** (~25–40 pages) covering design, implementation, evaluation, discussion.
4. **Evaluation dataset + results** (CSV of predictions vs. ground truth).
5. **Short demo video** (5–10 min).

---

## 11. Key References (from course materials)

- **Brathwaite, S.** — *What To Do When You Get Hacked* → phishing IR chapters, tone for analyst reporting.
- **Murdoch, D.** — *Blue Team Handbook: Incident Response* → practical phishing triage steps.
- **NIST SP 800-61** — Computer Security Incident Handling Guide → IR lifecycle framework.
- **ENISA Incident Management Guide** → European IR process alignment.
- **Kyriazoglou, J.** — *Information Security Incident and Data Breach Management* → notification / documentation requirements.
- **IRCopilot (arXiv 2505.20945)** → related work on LLMs in IR; cite as motivation and contrast with your simpler design.

---

## 12. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| LLM hallucinates indicators | Force evidence quoting; add rubric check |
| Phishing samples risky to handle | Work inside a VM; never render HTML in a browser |
| Llama 3.2 too weak for good explanations | Try the 3B model first; if quality is poor, document it as a finding (interesting result in itself) |
| Local model slow on your hardware | Use the 1B variant; batch overnight; report latency honestly |
| Malformed JSON output from small model | Add retry logic + JSON repair fallback (`json-repair` library) |
| Dataset label noise | Manually verify a small gold set; report as limitation |
| Scope creep (e.g., "let's do URL sandboxing too") | Freeze scope at end of Week 1; put extras in Future Work |

---

## 13. Future Work (mention in report)

- URL detonation in a sandbox (e.g., urlscan.io API).
- Attachment analysis via VirusTotal / static malware analysis.
- Multi-email thread analysis (BEC detection).
- Fine-tuning Llama 3.2 on phishing-specific data to improve explanation quality.
- Comparing against larger local models (Llama 3.1 8B, Mistral) or hosted APIs as a quality ceiling.
- Integration with an email gateway (Microsoft Graph, Gmail API).

---

*Good luck. Keep the scope tight and let the evaluation section carry the intellectual weight — that's what makes it an MSc project rather than a demo.*
