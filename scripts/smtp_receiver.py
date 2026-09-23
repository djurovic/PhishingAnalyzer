#!/usr/bin/env python3
"""
smtp_receiver.py — accepts mail from a real mail server and triages it.

HOW THIS FITS

The mail server sends a COPY of each message here over SMTP: Postfix
always_bcc or a transport map, an Exchange journal rule or connector, a Google
Workspace routing rule. This analyses the copy through the local service and
writes a verdict to logs/smtp_receiver.jsonl. Nothing is delivered, forwarded,
replied to or stored.

We are NOT in the delivery path. If this process is stopped, mail keeps
flowing on the mail server exactly as before. That is the same out-of-band
positioning as the IMAP poller, reached from the other side: push instead of
pull.

DESIGN — ACCEPT FAST, ANALYSE LATER

The SMTP session ends as soon as the message is queued. Analysis takes 1-3
seconds and runs on a background worker thread. An MTA that has to wait
seconds per message will slow down, defer or retry, and a triage copy has no
business causing any of that.

For the same reason this never returns a permanent SMTP failure because of an
analysis problem. A bounce from a triage copy is worse than a missed analysis:
it sends mail back at the original sender and makes the mail admin's logs lie.
If the queue is full or the analyser is down, the message is still accepted
and the failure is recorded in our own log.

The queue is in memory and bounded. A restart loses whatever is queued, which
is acceptable for a copy — the original is still in the mail system — and it
preserves the project's rule that message bytes are never written to disk.

WHY IT POSTS TO THE SERVICE RATHER THAN IMPORTING THE ANALYSER

Same reason as mailbox_watcher.py: one analysis path, so the evaluation
results describe what this produces. It also means the receiver can run on a
different machine from the model.

SECURITY

Unlike service.py, this has to be reachable from the mail server, so it cannot
be pinned to loopback. It still defaults to 127.0.0.1; opening it up is an
explicit --host, and --allow restricts which peers may send. Binding a
non-loopback address without --allow prints a warning, because an open SMTP
listener on a network is trouble even when it delivers nothing.

Usage:
    # local test
    python3 scripts/smtp_receiver.py

    # reachable from the mail server, restricted to it
    python3 scripts/smtp_receiver.py --host 0.0.0.0 --port 10025 \
        --allow 192.168.56.0/24

    # plumbing test: accept and log, never call the model
    python3 scripts/smtp_receiver.py --no-analyze
"""

from __future__ import annotations

import argparse
import email
import email.policy
import hashlib
import ipaddress
import json
import os
import queue
import signal
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

try:
    from aiosmtpd.controller import Controller
except ImportError:  # pragma: no cover
    print("[FAIL] aiosmtpd is not installed.  pip install aiosmtpd",
          file=sys.stderr)
    raise SystemExit(1)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_PATH = os.path.join(ROOT, "logs", "smtp_receiver.jsonl")

DEFAULT_SERVICE = os.environ.get("PA_SERVICE_URL", "http://127.0.0.1:8000")

# Matches the cap in service.py. A message over this is accepted at SMTP level
# and recorded as skipped, rather than bounced.
ANALYZE_MAX_BYTES = 10 * 1024 * 1024

VERDICT_TAG = {
    "phishing": "[PHISHING]",
    "suspicious": "[SUSPICIOUS]",
    "legitimate": "[LEGITIMATE]",
    "insufficient_evidence": "[INSUFFICIENT]",
}

_log_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


class Stats:
    """Counters shared between the SMTP thread and the worker threads."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.accepted = 0
        self.analysed = 0
        self.too_large = 0
        self.dropped_queue_full = 0
        self.failed = 0
        self.rejected_peer = 0
        self.rejected_rcpt = 0
        self.verdicts: dict[str, int] = {}

    def bump(self, field: str, n: int = 1) -> None:
        with self._lock:
            setattr(self, field, getattr(self, field) + n)

    def record_verdict(self, verdict: str) -> None:
        with self._lock:
            self.verdicts[verdict] = self.verdicts.get(verdict, 0) + 1

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "accepted": self.accepted,
                "analysed": self.analysed,
                "too_large": self.too_large,
                "dropped_queue_full": self.dropped_queue_full,
                "failed": self.failed,
                "rejected_peer": self.rejected_peer,
                "rejected_rcpt": self.rejected_rcpt,
                "verdicts": dict(self.verdicts),
            }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def log_line(record: dict) -> None:
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with _log_lock:
        with open(LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            fh.flush()
            os.fsync(fh.fileno())


def header_summary(raw: bytes) -> dict:
    try:
        msg = email.message_from_bytes(raw, policy=email.policy.default)
        return {
            "from": " ".join(str(msg.get("From") or "").split())[:200],
            "subject": " ".join(str(msg.get("Subject") or "").split())[:200],
            "date": " ".join(str(msg.get("Date") or "").split())[:100],
            "message_id": " ".join(str(msg.get("Message-ID") or "").split())[:200],
        }
    except Exception:
        return {"from": "", "subject": "", "date": "", "message_id": ""}


def peer_ip(peer) -> ipaddress._BaseAddress | None:
    """Normalise a (host, port) peer tuple to an IP, unwrapping IPv6-mapped v4."""
    if not peer:
        return None
    try:
        ip = ipaddress.ip_address(peer[0])
    except (ValueError, IndexError, TypeError):
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip


def post_to_service(service_url: str, raw: bytes, timeout: int) -> dict:
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
        req = urllib.request.Request(service_url.rstrip("/") + "/health",
                                     method="GET")
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
                       "Is `uvicorn service:app --host 127.0.0.1 --port 8000` "
                       "running?")


# ---------------------------------------------------------------------------
# SMTP handler
# ---------------------------------------------------------------------------


class TriageHandler:
    """
    Accepts a message and hands it to the queue. Does nothing slow.

    Peer and recipient checks happen at MAIL/RCPT so a disallowed sender is
    turned away before transferring a whole message. Those are the only
    rejections this issues; everything after DATA is accepted.
    """

    def __init__(self, work_queue: queue.Queue, allowed_networks: list,
                 recipients: list[str], stats: Stats, quiet: bool = False):
        self.queue = work_queue
        self.allowed_networks = allowed_networks
        self.recipients = [r.lower() for r in recipients]
        self.stats = stats
        self.quiet = quiet

    def _peer_allowed(self, peer) -> bool:
        if not self.allowed_networks:
            return True
        ip = peer_ip(peer)
        if ip is None:
            return False
        return any(ip in net for net in self.allowed_networks)

    def _rcpt_allowed(self, address: str) -> bool:
        if not self.recipients:
            return True
        addr = address.lower().strip("<>")
        domain = addr.rsplit("@", 1)[-1] if "@" in addr else ""
        return any(addr == r or domain == r.lstrip("@") for r in self.recipients)

    async def handle_MAIL(self, server, session, envelope, address, mail_options):
        if not self._peer_allowed(session.peer):
            self.stats.bump("rejected_peer")
            if not self.quiet:
                print(f"  [REJECT] {session.peer[0] if session.peer else '?'} "
                      f"not in --allow", file=sys.stderr)
            return "550 5.7.1 Sender host not permitted"
        envelope.mail_from = address
        envelope.mail_options.extend(mail_options)
        return "250 OK"

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        if not self._rcpt_allowed(address):
            self.stats.bump("rejected_rcpt")
            return "550 5.1.1 Recipient not accepted here"
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        raw = envelope.content
        if isinstance(raw, str):
            raw = raw.encode("utf-8", "replace")
        raw = bytes(raw or b"")

        item = {
            "received_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "peer": session.peer[0] if session.peer else "",
            "mail_from": envelope.mail_from or "",
            "rcpt_tos": list(envelope.rcpt_tos)[:10],
            "raw": raw,
        }
        self.stats.bump("accepted")

        try:
            self.queue.put_nowait(item)
        except queue.Full:
            # Accepted and dropped, deliberately. Refusing here would bounce a
            # copy back at the original sender because our analyser is behind.
            self.stats.bump("dropped_queue_full")
            summary = header_summary(raw)
            log_line({
                "timestamp": item["received_at"],
                "status": "dropped_queue_full",
                "peer": item["peer"], "mail_from": item["mail_from"],
                "rcpt_tos": item["rcpt_tos"], "bytes": len(raw),
                "raw_sha256": hashlib.sha256(raw).hexdigest(),
                **summary,
            })
            if not self.quiet:
                print(f"  [DROP] queue full — {summary['subject'][:50]!r} "
                      "accepted but not analysed", file=sys.stderr)
            return "250 Message accepted (analysis queue full, not analysed)"

        return "250 Message accepted for triage"

    async def handle_exception(self, error):  # pragma: no cover
        print(f"  [SMTP ERROR] {type(error).__name__}: {error}", file=sys.stderr)
        return "451 4.3.0 Internal error, message not analysed"


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------


def worker(name: str, work_queue: queue.Queue, stop: threading.Event,
           service_url: str, timeout: int, retries: int, retry_delay: int,
           stats: Stats, no_analyze: bool, quiet: bool) -> None:
    while True:
        try:
            item = work_queue.get(timeout=0.5)
        except queue.Empty:
            if stop.is_set():
                return
            continue

        try:
            process(item, service_url, timeout, retries, retry_delay,
                    stats, no_analyze, quiet)
        except Exception as exc:  # a worker must never die
            stats.bump("failed")
            print(f"  [WORKER ERROR] {type(exc).__name__}: {exc}", file=sys.stderr)
        finally:
            work_queue.task_done()


def process(item: dict, service_url: str, timeout: int, retries: int,
            retry_delay: int, stats: Stats, no_analyze: bool,
            quiet: bool) -> None:
    raw = item.pop("raw")
    summary = header_summary(raw)
    sha = hashlib.sha256(raw).hexdigest()
    base = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "received_at": item["received_at"],
        "peer": item["peer"],
        "mail_from": item["mail_from"],
        "rcpt_tos": item["rcpt_tos"],
        "raw_sha256": sha,
        "bytes": len(raw),
        **summary,
    }

    if not quiet:
        print(f"\n  {summary['subject'][:60]!r}")
        print(f"    from {summary['from'][:60] or '(no From header)'}"
              f"   envelope {item['mail_from'] or '(empty)'}")

    if len(raw) > ANALYZE_MAX_BYTES:
        stats.bump("too_large")
        log_line({**base, "status": "too_large"})
        if not quiet:
            print(f"    [SKIP] {len(raw)} bytes exceeds the {ANALYZE_MAX_BYTES} "
                  "byte analysis limit")
        return

    if no_analyze:
        log_line({**base, "status": "not_analysed"})
        if not quiet:
            print("    [OK] accepted and logged (--no-analyze)")
        return

    result = None
    last_error = ""
    for attempt in range(retries + 1):
        try:
            result = post_to_service(service_url, raw, timeout)
            last_error = ""
            break
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")[:200]
            last_error = f"HTTP {exc.code}: {body}"
            # 4xx means the message or the request is the problem, not a
            # transient one — retrying changes nothing.
            if 400 <= exc.code < 500:
                break
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"
        if attempt < retries:
            time.sleep(retry_delay)

    if result is None:
        stats.bump("failed")
        log_line({**base, "status": "analysis_failed", "error": last_error})
        if not quiet:
            print(f"    [FAIL] {last_error}", file=sys.stderr)
        return

    v = result["verdict"]
    g = result["grounding"]
    stats.bump("analysed")
    stats.record_verdict(v["verdict"])

    log_line({
        **base,
        "status": "analysed",
        "verdict": v["verdict"],
        "confidence": v["confidence"],
        "indicators": [i["indicator"] for i in v["indicators"]],
        "explanation": v["explanation"],
        "recommended_actions": v["recommended_actions"],
        "grounding": {k: val for k, val in g.items() if k != "details"},
        "latency_s": result["meta"]["latency_s"],
        "model": result["meta"]["model"],
        "prompt_version": result["meta"]["prompt_version"],
    })

    if not quiet:
        tag = VERDICT_TAG.get(v["verdict"], "[?]")
        print(f"    {tag} confidence {v['confidence']:.2f}  "
              f"({g['verified']}/{g['indicator_count']} grounded, "
              f"{result['meta']['latency_s']}s)")
        if v["explanation"]:
            print(f"    {v['explanation'][:150]}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_networks(values: list[str]) -> list:
    nets = []
    for v in values:
        for part in v.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                nets.append(ipaddress.ip_network(part, strict=False))
            except ValueError as exc:
                raise SystemExit(f"[FAIL] bad --allow value {part!r}: {exc}")
    return nets


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Receive mail over SMTP and triage it out of band.")
    ap.add_argument("--host", default="127.0.0.1",
                    help="bind address (default 127.0.0.1; use 0.0.0.0 to "
                         "accept from the mail server)")
    ap.add_argument("--port", type=int, default=10025)
    ap.add_argument("--allow", action="append", default=[],
                    help="CIDR or IP permitted to send; repeatable. "
                         "Strongly recommended with a non-loopback --host.")
    ap.add_argument("--recipient", action="append", default=[],
                    help="only accept these addresses or @domains; repeatable")
    ap.add_argument("--service", default=DEFAULT_SERVICE)
    ap.add_argument("--workers", type=int, default=1,
                    help="parallel analyses (Ollama serialises anyway)")
    ap.add_argument("--queue-size", type=int, default=100)
    ap.add_argument("--timeout", type=int, default=240)
    ap.add_argument("--retries", type=int, default=1)
    ap.add_argument("--retry-delay", type=int, default=5)
    ap.add_argument("--max-bytes", type=int, default=25 * 1024 * 1024,
                    help="SMTP-level size limit (default 25 MB)")
    ap.add_argument("--no-analyze", action="store_true",
                    help="accept and log only; never call the service")
    ap.add_argument("--require-service", action="store_true",
                    help="refuse to start if the service is unreachable")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args()

    allowed = parse_networks(args.allow)

    if not args.no_analyze:
        ok, detail = service_healthy(args.service)
        if ok:
            print(f"Service:   {args.service}  ({detail})")
        elif args.require_service:
            print(f"[FAIL] {detail}", file=sys.stderr)
            return 1
        else:
            # Starting anyway is deliberate: the mail server should get a
            # listener, not a connection refused, while the model is restarted.
            print(f"[WARN] {detail}", file=sys.stderr)
            print("[WARN] Starting anyway. Messages will be accepted and "
                  "logged as failed until the service returns.", file=sys.stderr)
    else:
        print("Service:   (not used — --no-analyze)")

    loopback = args.host in ("127.0.0.1", "localhost", "::1")
    if not loopback and not allowed:
        print("[WARN] Binding a non-loopback address with no --allow. Anything "
              "that can reach this port\n"
              "       can submit mail for analysis. Restrict it, e.g. "
              "--allow 192.168.56.0/24", file=sys.stderr)

    work_queue: queue.Queue = queue.Queue(maxsize=args.queue_size)
    stats = Stats()
    stop = threading.Event()

    workers = []
    for i in range(max(1, args.workers)):
        t = threading.Thread(
            target=worker, name=f"triage-{i}",
            args=(f"triage-{i}", work_queue, stop, args.service, args.timeout,
                  args.retries, args.retry_delay, stats, args.no_analyze,
                  args.quiet),
            daemon=True)
        t.start()
        workers.append(t)

    handler = TriageHandler(work_queue, allowed, args.recipient, stats,
                            args.quiet)
    controller = Controller(handler, hostname=args.host, port=args.port,
                            data_size_limit=args.max_bytes)
    try:
        controller.start()
    except Exception as exc:
        print(f"[FAIL] cannot listen on {args.host}:{args.port}: {exc}",
              file=sys.stderr)
        return 1

    print(f"Listening: smtp://{args.host}:{args.port}")
    print(f"Allow:     {', '.join(str(n) for n in allowed) if allowed else 'any peer'}")
    if args.recipient:
        print(f"Recipients:{' ' + ', '.join(args.recipient)}")
    print(f"Workers:   {len(workers)}   queue {args.queue_size}")
    print(f"Log:       {LOG_PATH}")
    print("\nNot in the delivery path — this analyses copies and delivers "
          "nothing.\nCtrl-C to stop.")

    def _sigint(signum, frame):
        stop.set()

    signal.signal(signal.SIGINT, _sigint)
    signal.signal(signal.SIGTERM, _sigint)

    while not stop.is_set():
        stop.wait(0.5)

    print("\n\nStopping. No new mail will be accepted.")
    controller.stop()

    pending = work_queue.qsize()
    if pending:
        print(f"Finishing {pending} queued message(s)...")
        deadline = time.time() + args.timeout
        while not work_queue.empty() and time.time() < deadline:
            time.sleep(0.2)
    for t in workers:
        t.join(timeout=5)

    s = stats.snapshot()
    print("\n" + "=" * 58)
    print(f"  accepted            {s['accepted']:>6}")
    print(f"  analysed            {s['analysed']:>6}")
    if s["too_large"]:
        print(f"  skipped (too large) {s['too_large']:>6}")
    if s["dropped_queue_full"]:
        print(f"  dropped (queue full){s['dropped_queue_full']:>6}")
    if s["failed"]:
        print(f"  analysis failed     {s['failed']:>6}")
    if s["rejected_peer"]:
        print(f"  rejected (peer)     {s['rejected_peer']:>6}")
    if s["rejected_rcpt"]:
        print(f"  rejected (rcpt)     {s['rejected_rcpt']:>6}")
    if s["verdicts"]:
        print("  verdicts            "
              + ", ".join(f"{k}={v}" for k, v in sorted(s["verdicts"].items())))
    print("=" * 58)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
