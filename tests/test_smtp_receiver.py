#!/usr/bin/env python3
"""End-to-end test of smtp_receiver.py against a stand-in service."""
import json, os, smtplib, socket, subprocess, sys, threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
LOG = os.path.join(ROOT, "logs", "smtp_receiver.jsonl")
PASS = FAIL = 0


def check(label, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"  ok    {label}")
    else:
        FAIL += 1; print(f"  FAIL  {label} {detail}")


# --------------------------------------------------------------- fake service
class Svc(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def do_GET(self):
        body = json.dumps({"service": "up", "ollama_reachable": True,
                           "model": "llama3.2", "host": "http://fake:11434"})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body.encode())

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(n)
        phish = b"verify" in raw.lower() or b"spf=fail" in raw.lower()
        body = json.dumps({
            "meta": {"model": "llama3.2", "prompt_version": "v1",
                     "latency_s": 1.4, "raw_sha256": "x" * 64},
            "verdict": {
                "verdict": "phishing" if phish else "legitimate",
                "confidence": 0.9 if phish else 0.2,
                "indicators": ([{"indicator": "SPF fails",
                                 "evidence_field": "authentication.spf",
                                 "evidence_value": "fail",
                                 "severity": "high"}] if phish else []),
                "explanation": "Fails authentication." if phish else "Looks fine.",
                "recommended_actions": ["Block sender"] if phish else ["None"]},
            "grounding": {"indicator_count": 1 if phish else 0,
                          "verified": 1 if phish else 0, "mismatched": 0,
                          "unverifiable": 0, "grounding_rate": 1.0 if phish else None,
                          "hallucination_rate": 0.0 if phish else None},
            "reliability": {"attempt_count": 1, "json_ok_first_try": True,
                            "repairs": [], "schema_problems": []}})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body.encode())


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close()
    return p


MSG = ("From: IT Helpdesk <it@corp-example.xyz>\r\n"
       "To: abuse@example.com\r\n"
       "Subject: Urgent: verify your mailbox\r\n"
       "Date: Mon, 1 Apr 2024 09:00:00 +0000\r\n\r\n"
       "Please verify your account.\r\n")
HAM = ("From: Marta <marta@example.com>\r\n"
       "To: abuse@example.com\r\n"
       "Subject: lunch\r\n\r\nSee you at one.\r\n")


def start_receiver(port, extra=(), svc=None):
    cmd = [sys.executable, os.path.join(ROOT, "scripts", "smtp_receiver.py"),
           "--host", "127.0.0.1", "--port", str(port), "--quiet", *extra]
    if svc:
        cmd += ["--service", svc]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         text=True)
    for _ in range(80):
        try:
            smtplib.SMTP("127.0.0.1", port, timeout=2).quit(); return p
        except Exception:
            if p.poll() is not None:
                out, err = p.communicate()
                print("receiver died:\n", out, err); return p
            time.sleep(0.1)
    return p


def send(port, body=MSG, mail_from="bounce@mx.example.com",
         rcpt="abuse@example.com"):
    s = smtplib.SMTP("127.0.0.1", port, timeout=10)
    try:
        return s.sendmail(mail_from, [rcpt], body.encode())
    finally:
        s.quit()


def read_log():
    if not os.path.exists(LOG):
        return []
    with open(LOG, encoding="utf-8") as fh:
        return [json.loads(l) for l in fh if l.strip()]


def reset_log():
    if os.path.exists(LOG):
        os.remove(LOG)


def wait_for(n, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        if len(read_log()) >= n:
            return read_log()
        time.sleep(0.2)
    return read_log()


# --------------------------------------------------------------------- tests
svc_port = free_port()
httpd = HTTPServer(("127.0.0.1", svc_port), Svc)
threading.Thread(target=httpd.serve_forever, daemon=True).start()
SVC = f"http://127.0.0.1:{svc_port}"

print("\n[1] Normal flow: accept, analyse, log")
reset_log()
port = free_port()
p = start_receiver(port, svc=SVC)
send(port, MSG)
send(port, HAM)
recs = wait_for(2)
check("two messages logged", len(recs) == 2, f"-> {len(recs)}")
if len(recs) == 2:
    by_sub = {r["subject"][:6]: r for r in recs}
    check("phishing verdict recorded",
          any(r.get("verdict") == "phishing" for r in recs))
    check("legitimate verdict recorded",
          any(r.get("verdict") == "legitimate" for r in recs))
    check("envelope sender captured",
          all(r["mail_from"] == "bounce@mx.example.com" for r in recs))
    check("envelope recipient captured",
          all(r["rcpt_tos"] == ["abuse@example.com"] for r in recs))
    check("peer captured", all(r["peer"] == "127.0.0.1" for r in recs))
    check("status analysed", all(r["status"] == "analysed" for r in recs))
    check("sha256 recorded", all(len(r["raw_sha256"]) == 64 for r in recs))
    check("subject parsed from the raw bytes",
          any("verify" in r["subject"].lower() for r in recs))
p.terminate(); p.wait(timeout=10)

print("\n[2] SMTP session returns before analysis (accept fast)")
reset_log()
port = free_port()
p = start_receiver(port, svc=SVC)
t0 = time.time()
send(port, MSG)
elapsed = time.time() - t0
check("session completes quickly", elapsed < 1.0, f"-> {elapsed:.2f}s")
wait_for(1)
p.terminate(); p.wait(timeout=10)

print("\n[3] Peer allowlist")
reset_log()
port = free_port()
p = start_receiver(port, ["--allow", "10.99.0.0/24"], svc=SVC)
refused = False
try:
    send(port, MSG)
except smtplib.SMTPSenderRefused as exc:
    refused = 550 == exc.smtp_code
except smtplib.SMTPException:
    refused = True
check("disallowed peer rejected at MAIL", refused)
check("nothing analysed", len(read_log()) == 0, f"-> {len(read_log())}")
p.terminate(); p.wait(timeout=10)

print("\n[4] Recipient filter")
reset_log()
port = free_port()
p = start_receiver(port, ["--recipient", "abuse@example.com"], svc=SVC)
ok_rcpt = True
try:
    send(port, MSG, rcpt="someone-else@example.com")
    ok_rcpt = False
except smtplib.SMTPRecipientsRefused:
    pass
check("non-matching recipient refused", ok_rcpt)
send(port, MSG, rcpt="abuse@example.com")
check("matching recipient accepted", len(wait_for(1)) == 1)
p.terminate(); p.wait(timeout=10)

print("\n[5] Service down: accept anyway, log the failure")
reset_log()
port = free_port()
dead = f"http://127.0.0.1:{free_port()}"
p = start_receiver(port, ["--retries", "0"], svc=dead)
accepted = True
try:
    send(port, MSG)
except Exception as exc:
    accepted = False
    print("   send raised:", exc)
check("message still accepted (no bounce)", accepted)
recs = wait_for(1)
check("failure recorded", recs and recs[0]["status"] == "analysis_failed",
      f"-> {recs[0]['status'] if recs else 'none'}")
check("error detail kept", recs and recs[0].get("error"))
p.terminate(); p.wait(timeout=10)

print("\n[6] --no-analyze plumbing mode")
reset_log()
port = free_port()
p = start_receiver(port, ["--no-analyze"])
send(port, MSG)
recs = wait_for(1)
check("accepted and logged", recs and recs[0]["status"] == "not_analysed",
      f"-> {recs[0]['status'] if recs else 'none'}")
p.terminate(); p.wait(timeout=10)

print("\n[7] Oversized message accepted but not analysed")
reset_log()
port = free_port()
p = start_receiver(port, svc=SVC)
import smtp_receiver as sr_mod  # noqa - only for the size constant
# Real mail wraps; a single 10 MB line violates RFC 5321's 1000-char limit and
# any MTA would refuse it at the protocol level, ours included.
line = "X" * 900 + "\r\n"
big = MSG + line * (sr_mod.ANALYZE_MAX_BYTES // len(line) + 20)
try:
    send(port, big)
    sent_ok = True
except Exception as exc:
    sent_ok = False; print("   send raised:", exc)
check("oversized message accepted at SMTP", sent_ok)
recs = wait_for(1, timeout=30)
check("logged as too_large", recs and recs[0]["status"] == "too_large",
      f"-> {recs[0]['status'] if recs else 'none'}")
p.terminate(); p.wait(timeout=10)

print("\n[8] Queue full drops rather than bounces")
reset_log()
port = free_port()
# queue of 1, no workers draining it quickly: point at a slow service
slow_port = free_port()


class Slow(Svc):
    def do_POST(self):
        time.sleep(3); Svc.do_POST(self)


slow = HTTPServer(("127.0.0.1", slow_port), Slow)
threading.Thread(target=slow.serve_forever, daemon=True).start()
p = start_receiver(port, ["--queue-size", "1", "--workers", "1"],
                   svc=f"http://127.0.0.1:{slow_port}")
errs = []
for i in range(6):
    try:
        send(port, MSG.replace("Urgent", f"Urgent {i}"))
    except Exception as exc:
        errs.append(exc)
check("no sender ever bounced", not errs, f"-> {errs[:1]}")
time.sleep(2)
recs = read_log()
check("some dropped, recorded as such",
      any(r["status"] == "dropped_queue_full" for r in recs),
      f"-> statuses {[r['status'] for r in recs]}")
p.terminate(); p.wait(timeout=10)

httpd.shutdown(); slow.shutdown()
print(f"\n{'=' * 50}\n{PASS} passed, {FAIL} failed\n{'=' * 50}")
sys.exit(1 if FAIL else 0)
