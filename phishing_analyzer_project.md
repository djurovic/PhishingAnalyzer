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
- [X] Download and install **VirtualBox** (free) or **VMware Workstation Player**.
- [X] Download **Ubuntu 22.04 LTS Desktop** ISO.
- [X] Create a new VM: 4 CPU cores, 8+ GB RAM, 40 GB disk, enable virtualization in BIOS if needed.
- [X] Install Ubuntu inside the VM. Take a **snapshot** once clean ("clean-install").
- [X] Install VirtualBox Guest Additions (shared clipboard, better resolution).
- [X] Set the VM network to **NAT** (safer for handling phishing samples — no bridged access to your LAN).
- [X] Update system: `sudo apt update && sudo apt upgrade -y`.
- [X] Install basics: `sudo apt install -y python3-pip python3-venv git curl build-essential`.
- [X] Install Git, create a GitHub repo, clone it into the VM.
- [X] Read: NIST SP 800-61 §3 (Detection & Analysis), Brathwaite phishing chapter, Murdoch's phishing triage section.
- [X] Take a second snapshot ("dev-ready").

### Day 2 — Ollama + Llama 3.2 setup
- [X] Install Ollama: `curl -fsSL https://ollama.com/install.sh | sh`.
- [X] Pull the model: `ollama pull llama3.2` (start with the 3B variant; try 1B if RAM is tight).
- [X] Verify it runs: `ollama run llama3.2` → ask it a test question.
- [X] Test the HTTP API on `http://localhost:11434/api/generate` with `curl`.
- [X] Set up Python project: virtualenv, `requirements.txt` (`ollama`, `mail-parser`, `tldextract`, `iocextract`, `python-magic`, `streamlit`, `pandas`).
- [X] Write a minimal Python script that sends a prompt to Llama 3.2 via the `ollama` Python client and prints the response.
- [X] Benchmark: how long does one query take? (This shapes your evaluation.)

### Day 3 — Email parser
- [X] Parse `.eml` files: extract `From`, `Reply-To`, `Return-Path`, `Received` chain, `Subject`, body (text + HTML).
- [X] Extract URLs from body + HTML `href`s. Decode obfuscated URLs.
- [X] Extract attachments: filename, MIME type, SHA-256 hash.
- [X] Extract auth results: SPF, DKIM, DMARC from headers.
- [X] **Output:** a clean JSON "feature bundle" per email.
- [X] Test on 3–5 sample emails (mix of phishing and legit).

### Day 4 — LLM integration (v1)
- [X] Design the prompt: system message defining the analyst persona + expected structured output (JSON schema: `verdict`, `confidence`, `indicators`, `explanation`, `recommended_actions`).
- [X] Include a few-shot example in the prompt (Llama 3.2 needs this more than bigger models).
- [X] Send the feature bundle to Llama, parse the JSON response.
- [X] Handle errors: malformed JSON (very common with small local models — add a retry with a "please return valid JSON only" reminder), timeouts, refusals.
- [X] Log every request/response to disk for later analysis.

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
---

## Day 2 Notes — Final Architecture Decision

### Host-based LLM inference over host-only network

Ollama runs on the **host** (Windows, NVIDIA GTX 1660 Ti, 6 GB VRAM) rather than
inside the VM. The VM reaches Ollama via a VirtualBox **host-only network
adapter** at `192.168.56.1:11434`. The VM keeps its NAT adapter for outbound
internet access.

**Rationale:**
- VirtualBox does not pass through the host GPU to guest VMs. Running Ollama in
  the VM meant CPU-only inference, which was too slow for iterative prompt
  development or batch evaluation on 200 emails.
- Host inference on the GTX 1660 Ti reduces per-query latency from ~15s (CPU in
  VM, 3B model) to ~1–3s. This makes overnight batch evaluation feasible on a
  full dataset instead of a subsample.

**Isolation guarantees preserved:**
- The VM still handles all untrusted content: `.eml` parsing, URL/attachment
  extraction, HTML rendering, and the Streamlit UI.
- The host-only network is not reachable from the LAN or the internet — only
  the host and the VM see it.
- The host never touches phishing samples directly; it only receives structured
  JSON "feature bundles" over HTTP for classification.

### Configuration

**Host (Windows):**
- User environment variables: `OLLAMA_HOST=0.0.0.0:11434`, `OLLAMA_ORIGINS=*`
- Ollama run manually via `ollama serve` in a Command Prompt (tray app spawned
  a duplicate listener that conflicted with VirtualBox NAT port-forwarding).
- Windows Firewall inbound rule allowing TCP 11434.

**VM (Ubuntu 22.04):**
- Adapter 1: NAT (outbound internet).
- Adapter 2: Host-only, `192.168.56.101/24`.
- `~/.bashrc` exports `OLLAMA_HOST=http://192.168.56.1:11434`.
- Local Ollama service stopped and disabled to save RAM.

### Pitfalls encountered (worth documenting)

1. **VirtualBox NAT port-forwarding on the same port as Ollama caused
   intermittent "connection reset by peer".** VirtualBoxVM.exe binds host port
   11434 for the forward, colliding with Ollama's listener on the same port.
   Removing the NAT forward and routing traffic exclusively through the
   host-only adapter resolved this.
2. **The Ollama tray app on Windows can spawn multiple `ollama.exe` processes**
   with duplicate listeners after force-killing. Running `ollama serve`
   manually from a Command Prompt gives a single, controllable instance.
3. **`OLLAMA_ORIGINS=*` is required** for connections from IPs outside
   `127.0.0.1`/`0.0.0.0`, including the VM's `192.168.56.101`.

### Benchmark (Llama 3.2 3B on GTX 1660 Ti)

*(fill in from `scripts/benchmark.py` output)*

    time    tokens  prompt

------------------------------------------------------------

   7.84s       303  What is phishing?

   4.97s       274  List 5 red flags in a suspicious email.

   5.64s       347  Explain SPF, DKIM, and DMARC in one para

------------------------------------------------------------

Total: 18.45s across 3 prompts (avg 6.15s each)



Compare against the CPU-in-VM baseline briefly, then move on.

---

## Day 3 Notes — Email Parser (deterministic extraction stage)

### Milestone status

- [X] Parse `.eml` files: `From`, `Reply-To`, `Return-Path`, `Received` chain, `Subject`, body (text + HTML).
- [X] Extract URLs from body + HTML `href`s. Decode obfuscated URLs.
- [X] Extract attachments: filename, MIME type, SHA-256 hash.
- [X] Extract auth results: SPF, DKIM, DMARC from headers.
- [X] **Output:** a clean JSON "feature bundle" per email.
- [X] Test on 3–5 sample emails (mix of phishing and legit).

### What was built

`scripts/eml_parser.py` — a single-file, stdlib-first parser. Input: one `.eml`
(or a directory of them). Output: one JSON feature bundle per email.

`scripts/make_samples.py` — generates five synthetic `.eml` fixtures, each
targeting a specific extraction path. Real corpus data arrives Day 5; testing
against controlled fixtures first means a Day 5 failure is a data problem, not
a code problem.

### Design decision: stdlib `email` instead of `mail-parser`

The original tech-stack table listed `mail-parser`. Switched to the standard
library's `email` module with `policy=email.policy.default`, because:

- It handles RFC 2047 encoded-word headers, multipart traversal, transfer
  encodings, and charset decoding natively — `mail-parser` is a thin wrapper
  over the same module.
- One fewer dependency to justify and pin in the report.
- No unmaintained-package risk in a security tool.

`tldextract` and `python-magic` are imported defensively (`try/except`). The
parser degrades gracefully without them: registered-domain extraction falls
back to a last-two-labels heuristic, and MIME sniffing is simply omitted.
This matters for reproducibility — a grader can run the parser with zero
`pip install`.

### Feature bundle schema

| Key | Contents |
|---|---|
| `meta` | source filename, size, SHA-256 of the raw file, parse timestamp, parser version |
| `headers` | From, To, Cc, Reply-To, Return-Path, Sender, Subject, Date, Message-ID, X-Mailer, List-Unsubscribe |
| `authentication` | spf / dkim / dmarc verdicts, DKIM-Signature presence, raw auth headers |
| `received_chain` | up to 12 hops: `from`, `by`, IP, truncated raw (index 0 = closest to recipient) |
| `body` | plain-text excerpt (3000 chars), full length, HTML structural counts |
| `urls` | one entry per unique URL: host, registered domain, path, source, per-URL notes |
| `attachments` | filename, extension, declared vs sniffed MIME, size, SHA-256, notes |
| `derived_signals` | flat booleans and counts — the LLM's input summary and the Day 6 rule baseline |

### Safety properties (state these in the report)

1. **HTML is parsed, never rendered.** `html.parser.HTMLParser` walks the tree
   as text. No browser engine, no network fetch, no image loading — so no
   tracking-pixel callback confirming the mailbox is live.
2. **Attachments are never written to disk or opened.** They are read into
   memory from the MIME part, hashed, and discarded. Only the SHA-256 leaves
   the parser, which is also what a VirusTotal lookup would need (Future Work).
3. **All URLs are defanged on output** (`hxxps://`, `[.]`). Nothing in a JSON
   bundle, terminal summary, or generated report is clickable.
4. **`<script>` and `<style>` contents are excluded** from extracted body text,
   so JavaScript source cannot leak into the LLM prompt as if it were prose.

Together these mean the feature bundle is safe to move across the host-only
network boundary to the host running Ollama — which is exactly the isolation
argument made in the Day 2 architecture decision.

### Obfuscation handling implemented

| Technique | Handling |
|---|---|
| Percent-encoding (`%2E` for `.`) | `urllib.parse.unquote` before parsing |
| HTML entities (`&#46;`) | `html.unescape` before parsing |
| Analyst defanging (`hxxp`, `[.]`, `[dot]`) | re-fanged before URL regex, so pre-defanged corpus samples still parse |
| Redirect wrappers (`?url=`, `?u=`, `?q=`…) | recursively unwrapped; wrapper host recorded in `redirect_wrapper` |
| Punycode / IDN homographs | flagged, and the host is decoded back to Unicode in `unicode_host` |
| `http://trusted.com@evil.com` | userinfo-in-URL flagged |
| IP-literal hosts | flagged |
| Anchor text showing a different domain than the `href` | flagged as `anchor_text_domain_mismatch` |
| Hidden HTML (`display:none`, `font-size:0`) | counted — a common Bayesian-filter poisoning technique |
| Double extensions (`Invoice.pdf.js`) | flagged |
| RLO / bidi override in filenames | flagged |

### Sample fixture results

| Fixture | spf/dkim/dmarc | URLs (off-domain) | Attach | Flags raised |
|---|---|---|---|---|
| `01_legit_newsletter` | pass / pass / pass | 3 (0) | 0 | none |
| `02_legit_internal` | pass / pass / pass | 0 (0) | 0 | none |
| `03_phish_credential` | fail / none / fail | 3 (2) | 0 | reply-to mismatch, return-path mismatch, auth failure, anchor-text mismatch |
| `04_phish_invoice` | softfail / none / fail | 1 (1) | 2 | reply-to mismatch, return-path mismatch, auth failure, IP-literal URL, risky attachment |
| `05_phish_redirect` | pass / fail / fail | 3 (1) | 0 | return-path mismatch, auth failure, punycode URL, redirect wrapper |

Note that `05` passes SPF. That is the intended lesson: SPF validates the
envelope sender's right to use the sending IP, not the alignment between the
envelope domain and the visible `From:` header. A rule baseline keyed on
"SPF fails ⇒ phishing" misses this email entirely — which is the argument for
DMARC alignment checks, and a useful contrast to raise when the Day 6 baseline
is compared against the LLM.

### Robustness

Tested against a zero-byte file, a file of non-UTF-8 garbage, and a
headers-only email. All three parse without raising; missing fields come back
empty rather than absent, so downstream code (Day 4 prompt assembly) can rely
on the schema shape. Batch mode logs and skips a failing file instead of
aborting the run — necessary before pointing it at ~200 uncurated corpus emails.

### Known limitations (carry into the report)

- Proofpoint URLDefense v3 encoding is not decoded (only the generic
  `?url=`-style wrappers are). Note as a limitation, not a bug.
- The registered-domain fallback without `tldextract` mishandles multi-label
  suffixes such as `.co.uk`. Install `tldextract` before the evaluation run.
- `Received` chain parsing is regex-based and lenient. Sufficient for
  identifying the originating IP; not a full RFC 5321 trace validator.
- No lookalike/homograph *scoring* (e.g. Levenshtein distance from a brand
  list). Deliberately left to the LLM — measuring whether it spots this
  unaided is part of the explanation-quality evaluation.

### Handoff to Day 4

`derived_signals` is the block that goes into the LLM prompt, plus the header
summary, body excerpt, and the URL/attachment lists. The full bundle stays on
disk for logging and for the analyst report. Keeping the prompt input to a
subset is a deliberate token-budget decision for a 3B model — record the
prompt token count on Day 4 and compare against the latency benchmark from
Day 2.

---

## Day 4 Notes — LLM Integration (v1)

### Milestone status

- [X] Design the prompt: analyst persona + structured output schema (`verdict`, `confidence`, `indicators`, `explanation`, `recommended_actions`).
- [X] Include a few-shot example in the prompt.
- [X] Send the feature bundle to Llama, parse the JSON response.
- [X] Handle errors: malformed JSON, timeouts, refusals.
- [X] Log every request/response to disk for later analysis.
- [X] *(added)* Automated evidence-grounding check.

### What was built

| File | Role |
|---|---|
| `prompts/system_v1.txt` | The system prompt, versioned as a file so git tracks every iteration |
| `scripts/prompt_builder.py` | Condenses the Day 3 bundle into token-budgeted prompt input |
| `scripts/llm_client.py` | Ollama transport, JSON repair ladder, schema validation |
| `scripts/grounding_check.py` | Verifies each cited indicator against the bundle |
| `scripts/analyze.py` | End-to-end CLI: `.eml` → verdict → Markdown report → log |
| `scripts/test_day4.py` | 30 offline tests; no Ollama required |

### Design decision: condense the bundle, don't send it whole

A full Day 3 bundle runs 4–8 KB of JSON. Sent verbatim to a 3B model with a
4096-token context, it crowds out the instructions and the model starts
ignoring the schema. `prompt_builder.py` selects a subset: headers, auth
results, non-empty derived signals, up to 8 URLs, up to 6 attachments, and a
1200-character body excerpt. Measured result on `03_phish_credential`: ~1755
estimated tokens total, of which ~1220 is the system prompt.

Two details that turned out to matter more than expected:

1. **False and zero signals are dropped, not sent as `false`.** A 3B model
   given twenty `false` values sometimes cites them as positive findings.
   Absent means not observed.
2. **The body excerpt is defanged to match the URL list.** The parser defangs
   `urls[]` but leaves body text raw, so the model was seeing the same URL in
   two formats and occasionally reporting the discrepancy as an indicator in
   its own right.

Both are small, and both are the kind of thing only visible once you read the
assembled prompt rather than trusting the code that builds it. `--dry-run`
prints the prompt and makes no LLM call, for exactly this reason.

### The JSON failure ladder

Malformed JSON was flagged as a risk at project start. Rather than "retry
until it works", each rung is recorded so the failure *mode* becomes a
measurable result:

1. **`format: "json"`** — Ollama constrains token sampling to valid JSON
   grammar. This is the single highest-value setting in the whole integration
   and eliminates most malformation before it happens.
2. **Local repair** — strip markdown fences, strip chatty preamble/postamble,
   remove trailing commas, close objects truncated by `num_predict`. No second
   LLM call, so no latency cost.
3. **One retry with a nudge** — re-ask with a reminder appended.
4. **Structured failure** — return `insufficient_evidence` with a
   "escalate to manual review" action. Never raises, never crashes a batch.

Truncation repair uses a bracket **stack**, not bracket counting. Counting
appends closers in the wrong nesting order and produces
`[{"indicator": "x"]}` — still invalid. The stack also tracks string state so
brackets inside string literals are ignored, and closes a dangling string
before closing its containers.

Schema validation coerces rather than rejects, and records what it coerced:
confidence given as `92` becomes `0.92`, `"Phishing"` becomes `phishing`,
`"insufficient evidence"` becomes `insufficient_evidence`, a newline-delimited
action string becomes a list, an invented severity like `"CRITICAL"` becomes
`medium`. An invented *verdict* is not salvaged — it falls back to
`insufficient_evidence`. Every coercion is logged, so the report can state how
often the model needed rescuing rather than just asserting it worked.

`seed: 42` and `temperature: 0.1` are set for reproducibility across
evaluation runs.

### Automated grounding check (addition to the original plan)

The system prompt requires every indicator to cite the bundle field it came
from. `grounding_check.py` enforces that: it resolves the dotted path
(`derived_signals.spf_result`, `urls[0].notes`) and compares the claimed value
against the actual one.

| Grade | Meaning |
|---|---|
| `verified` | Field resolves and the claimed value matches |
| `mismatched` | Field resolves but the value differs — model misread real data |
| `unverifiable` | Path does not resolve — model invented the field |

Path resolution is deliberately lenient: it tolerates a bare field name that
lives one level down (`spf` for `authentication.spf`), list-wide gathering
(`urls.notes`), and defanging differences. Being strict here would penalise
correct reasoning for citation formatting, which is not the thing being
measured.

**Why this matters for the report:** the plan listed hallucination rate as a
manually-scored rubric item over 30–50 emails. This computes a grounding rate
over the *entire* dataset automatically. The two are complementary, not
redundant — the rubric scores whether the reasoning is *good*, this scores
whether the citations are *real*. Having a hard number over 200 emails
alongside hand-scored depth over 40 is a materially stronger evaluation
chapter than either alone.

Verified with a deliberately-bad mocked response containing a fabricated
`derived_signals.malware_found` field: correctly graded `unverifiable`, giving
a hallucination rate of 0.67 on that response.

### Logging

Every run appends one JSON line to `logs/runs.jsonl`: timestamp, model, prompt
version, source file and raw SHA-256, estimated vs actual prompt tokens,
response tokens, attempt count, `json_ok_first_try`, repairs applied, schema
problems, the full verdict, the grounding result, and the raw model output.

Keeping the raw output means a prompt change can be re-scored later without
re-running inference. Keeping `raw_sha256` means a log line can be tied back
to its exact input even if sample files get reorganised.

### Testing

`test_day4.py` runs 30 assertions with no Ollama dependency, covering markdown
fences, chatty preamble and postamble, trailing commas, three shapes of
truncation (mid-object, mid-array, mid-string with escaped quotes), empty
responses, pure prose, and nine schema coercions. It caught one real bug: the
bracket-counting truncation repair described above.

Running these offline matters because Ollama latency is ~2–6s per call. A test
suite that needs 30 model calls does not get run often enough to be useful.

### Known limitations

- Prompt v1 is not yet tuned against real corpus data — Day 5 will show
  whether the few-shot example biases toward `phishing` on legitimate mail.
- The few-shot example is a phishing case. A legitimate counter-example may be
  needed if false positives run high; that becomes prompt v2, and the v1/v2
  comparison is itself a reportable result.
- Grounding checks citations, not reasoning. A model can cite `spf=pass`
  correctly and still draw the wrong conclusion from it. That is what the Day 6
  rubric is for.
- No token-level cost accounting; `num_ctx` is fixed at 4096. If real corpus
  emails overflow it, `--body-chars` is the dial to turn.

### Handoff to Day 5

The batch runner is effectively already here: `analyze.py --dir` iterates a
directory, logs each result, and continues past failures. Day 5 needs the
corpus assembled with ground-truth labels, a label column joined onto the log,
and the metrics computed from `runs.jsonl`.

Before the batch run: install `tldextract` (the `.co.uk` fallback is
imprecise), confirm `num_ctx` covers the largest real email, and run a
10-email pilot to check latency against the Day 2 benchmark of ~6s per query.
200 emails at 6s is roughly 20 minutes — feasible, but not something to
discover is broken at email 190.
