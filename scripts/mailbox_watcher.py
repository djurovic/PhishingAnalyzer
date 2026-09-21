#!/usr/bin/env python3
"""
mailbox_watcher.py — Day 7. Polls a mailbox and triages new mail via the service.

This is what makes "a mail system can use it" demonstrable rather than
theoretical. It logs in over IMAP, fetches unseen messages, POSTs each raw
message to the local /analyze endpoint, and appends the verdict to a log.

Stdlib only: imaplib, email, urllib. No new dependencies.

POSITIONING — say this during the demo

This deliberately watches a MAILBOX, not the SMTP delivery path. It is the
abuse@ / phishing-report inbox pattern: users forward suspicious mail, or a
gateway quarantines it, and this triages what lands there. It is NIST SP 800-61
detection and analysis, not a prevention control. Reasons:

  * ~1-3s per message on a 3B model will not keep up inline at real volume
  * generative output is not deterministic enough to accept/reject unsupervised
  * an analyst stays in the loop, which is exactly why explanation quality is
    the variable this project measures

SAFETY

  * Read-only by default. It marks messages Seen so they are not re-analysed;
    it never deletes, moves or replies.
  * --dry-run reads and analyses without marking anything.
  * Credentials come from environment variables, never command-line arguments
    (argv is visible to other users via ps) and never a committed file.

Setup:
    export PA_IMAP_HOST=imap.example.com
    export PA_IMAP_USER=abuse@example.com
    export PA_IMAP_PASS='app-specific-password'

Usage:
    python3 scripts/mailbox_watcher.py --once            # single pass
    python3 scripts/mailbox_watcher.py                   # poll every 10s
    python3 scripts/mailbox_watcher.py --dry-run --once  # don't mark Seen
"""

from __future__ import annotations

import argparse
import email
import email.policy
import hashlib
import imaplib
import json
import os
import signal
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_PATH = os.path.join(ROOT, "logs", "mailbox_watcher.jsonl")

DEFAULT_SERVICE = os.environ.get("PA_SERVICE_URL", "http://127.0.0.1:8000")
MAX_BYTES = 10 * 1024 * 1024

_stop = False

VERDICT_TAG = {
    "phishing": "[PHISHING]",
    "suspicious": "[SUSPICIOUS]",
    "legitimate": "[LEGITIMATE]",
    "insufficient_evidence": "[INSUFFICIENT]",
}


def _handle_sigint(signum, frame):
    global _stop
    _stop = True
    print("\n[!] Stopping after the current message.", file=sys.stderr)


def log_line(record: dict) -> None:
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        fh.flush()
        os.fsync(fh.fileno())


def post_to_service(service_url: str, raw: bytes, timeout: int = 240) -> dict:
    req = urllib.request.Request(
        service_url.rstrip("/") + "/analyze",
        data=raw,
        headers={"Content-Type": "application/octet-stream"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def service_healthy(service_url: str) -> tuple[bool, str]:
    try:
        req = urllib.request.Request(service_url.rstrip("/") + "/health", method="GET")
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        if not body.get("ollama_reachable"):
            return False, f"service up but Ollama unreachable: {body.get('error', '')}"
        return True, f"{body.get('model')} via {body.get('host')}"
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read().decode("utf-8"))
            return False, f"HTTP {exc.code}: {detail}"
        except Exception:
            return False, f"HTTP {exc.code}"
    except Exception as exc:
        return False, (f"cannot reach {service_url} ({exc}). "
                       "Is `uvicorn service:app --host 127.0.0.1 --port 8000` running?")


def connect(host: str, user: str, password: str, port: int,
            folder: str, insecure: bool) -> imaplib.IMAP4_SSL:
    context = ssl.create_default_context()
    if insecure:
        # Only for a local Dovecot with a self-signed certificate.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    conn = imaplib.IMAP4_SSL(host, port, ssl_context=context)
    conn.login(user, password)
    status, _ = conn.select(folder)
    if status != "OK":
        raise RuntimeError(f"cannot select folder '{folder}'")
    return conn


def header_summary(raw: bytes) -> dict:
    try:
        msg = email.message_from_bytes(raw, policy=email.policy.default)
        return {
            "from": " ".join(str(msg.get("From") or "").split())[:200],
            "subject": " ".join(str(msg.get("Subject") or "").split())[:200],
            "date": " ".join(str(msg.get("Date") or "").split())[:100],
        }
    except Exception:
        return {"from": "", "subject": "", "date": ""}


def process_once(conn: imaplib.IMAP4_SSL, service_url: str,
                 dry_run: bool, limit: int) -> int:
    status, data = conn.search(None, "UNSEEN")
    if status != "OK":
        print("[WARN] IMAP search failed", file=sys.stderr)
        return 0
    ids = data[0].split()
    if not ids:
        return 0
    if limit:
        ids = ids[:limit]

    handled = 0
    for msg_id in ids:
        if _stop:
            break
        # BODY.PEEK[] does not implicitly set \Seen, so --dry-run stays honest.
        status, msg_data = conn.fetch(msg_id, "(BODY.PEEK[])")
        if status != "OK" or not msg_data or not msg_data[0]:
            print(f"[WARN] could not fetch message {msg_id!r}", file=sys.stderr)
            continue
        raw = msg_data[0][1]
        if not isinstance(raw, (bytes, bytearray)):
            continue
        raw = bytes(raw)

        summary = header_summary(raw)
        sha = hashlib.sha256(raw).hexdigest()
        print(f"\n  New message: {summary['subject'][:60]!r}")
        print(f"    from {summary['from'][:60]}")

        if len(raw) > MAX_BYTES:
            print(f"    [SKIP] {len(raw)} bytes exceeds service limit")
            continue

        try:
            result = post_to_service(service_url, raw)
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")[:200]
            print(f"    [FAIL] service returned HTTP {exc.code}: {body}",
                  file=sys.stderr)
            continue
        except Exception as exc:
            print(f"    [FAIL] {type(exc).__name__}: {exc}", file=sys.stderr)
            continue

        v = result["verdict"]
        g = result["grounding"]
        tag = VERDICT_TAG.get(v["verdict"], "[?]")
        print(f"    {tag} confidence {v['confidence']:.2f}  "
              f"({g['verified']}/{g['indicator_count']} grounded, "
              f"{result['meta']['latency_s']}s)")
        if v["explanation"]:
            print(f"    {v['explanation'][:150]}")

        log_line({
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "raw_sha256": sha,
            "bytes": len(raw),
            **summary,
            "verdict": v["verdict"],
            "confidence": v["confidence"],
            "indicators": [i["indicator"] for i in v["indicators"]],
            "explanation": v["explanation"],
            "recommended_actions": v["recommended_actions"],
            "grounding": {k: val for k, val in g.items() if k != "details"},
            "latency_s": result["meta"]["latency_s"],
            "model": result["meta"]["model"],
            "dry_run": dry_run,
        })

        if not dry_run:
            conn.store(msg_id, "+FLAGS", "\\Seen")
        handled += 1

    return handled


def main() -> int:
    ap = argparse.ArgumentParser(description="Poll a mailbox and triage new mail.")
    ap.add_argument("--service", default=DEFAULT_SERVICE)
    ap.add_argument("--host", default=os.environ.get("PA_IMAP_HOST"))
    ap.add_argument("--user", default=os.environ.get("PA_IMAP_USER"))
    ap.add_argument("--port", type=int,
                    default=int(os.environ.get("PA_IMAP_PORT", 993)))
    ap.add_argument("--folder", default=os.environ.get("PA_IMAP_FOLDER", "INBOX"))
    ap.add_argument("--interval", type=int, default=10, help="seconds between polls")
    ap.add_argument("--once", action="store_true", help="single pass, then exit")
    ap.add_argument("--limit", type=int, default=0, help="max messages per pass")
    ap.add_argument("--dry-run", action="store_true",
                    help="analyse but do not mark messages as Seen")
    ap.add_argument("--insecure", action="store_true",
                    help="skip TLS verification (local Dovecot with self-signed cert)")
    args = ap.parse_args()

    password = os.environ.get("PA_IMAP_PASS")
    missing = [n for n, v in (("PA_IMAP_HOST", args.host),
                              ("PA_IMAP_USER", args.user),
                              ("PA_IMAP_PASS", password)) if not v]
    if missing:
        print(f"[FAIL] missing environment variable(s): {', '.join(missing)}",
              file=sys.stderr)
        print("\n  export PA_IMAP_HOST=imap.example.com", file=sys.stderr)
        print("  export PA_IMAP_USER=abuse@example.com", file=sys.stderr)
        print("  export PA_IMAP_PASS='app-specific-password'", file=sys.stderr)
        return 1

    ok, detail = service_healthy(args.service)
    if not ok:
        print(f"[FAIL] {detail}", file=sys.stderr)
        return 1
    print(f"Service:  {args.service}  ({detail})")

    try:
        conn = connect(args.host, args.user, password, args.port,
                       args.folder, args.insecure)
    except Exception as exc:
        print(f"[FAIL] IMAP connection: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    print(f"Mailbox:  {args.user}@{args.host}:{args.port} folder={args.folder}")
    print(f"Log:      {LOG_PATH}")
    if args.dry_run:
        print("Mode:     DRY RUN — messages will not be marked as Seen")
    print(f"\nWatching for unseen mail"
          + ("" if args.once else f", polling every {args.interval}s")
          + ". Ctrl-C to stop.")

    signal.signal(signal.SIGINT, _handle_sigint)
    total = 0
    try:
        while not _stop:
            try:
                n = process_once(conn, args.service, args.dry_run, args.limit)
                total += n
            except (imaplib.IMAP4.abort, imaplib.IMAP4.error) as exc:
                print(f"[WARN] IMAP error ({exc}); reconnecting...", file=sys.stderr)
                try:
                    conn.logout()
                except Exception:
                    pass
                time.sleep(3)
                conn = connect(args.host, args.user, password, args.port,
                               args.folder, args.insecure)
                continue
            if args.once:
                break
            for _ in range(args.interval):
                if _stop:
                    break
                time.sleep(1)
    finally:
        try:
            conn.close()
            conn.logout()
        except Exception:
            pass

    print(f"\nProcessed {total} message(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
