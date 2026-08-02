#!/usr/bin/env python3
"""
eml_parser.py — Day 3 of the LLM-Powered Phishing Email Analyzer.

Deterministic extraction stage: turns a raw .eml file into a clean JSON
"feature bundle". No LLM involved here. The LLM (Day 4) only ever sees
the JSON this produces, never the raw email.

Safety notes:
  * HTML is never rendered, only parsed as text.
  * Attachments are never written to disk or executed — only hashed.
  * URLs are defanged in the output (hxxp://, [.]) so nothing in a report
    or terminal is clickable.

Usage:
    python3 scripts/eml_parser.py samples/example.eml
    python3 scripts/eml_parser.py samples/example.eml -o out/example.json
    python3 scripts/eml_parser.py --dir samples/ -o out/
"""

from __future__ import annotations

import argparse
import email
import email.policy
import hashlib
import html
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import parse_qs, unquote, urlparse

# ---------------------------------------------------------------------------
# Optional dependencies. The parser works without them, just with less detail.
# ---------------------------------------------------------------------------

try:
    import tldextract

    _TLD = tldextract.TLDExtract(suffix_list_urls=None)  # offline-safe: uses bundled snapshot
except Exception:  # pragma: no cover
    _TLD = None

try:
    import magic  # python-magic

    _MAGIC = magic.Magic(mime=True)
except Exception:  # pragma: no cover
    _MAGIC = None


BODY_EXCERPT_CHARS = 3000  # how much body text we keep for the LLM prompt
MAX_RECEIVED_HOPS = 12

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

RISKY_EXTENSIONS = {
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".js", ".jse", ".vbs",
    ".vbe", ".wsf", ".wsh", ".hta", ".msi", ".jar", ".ps1", ".lnk", ".iso",
    ".img", ".vhd", ".chm", ".reg", ".cpl", ".dll", ".apk",
}
# Archives and Office docs: not risky by themselves, but common phishing carriers.
CARRIER_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".gz", ".tar", ".cab", ".ace",
    ".docm", ".xlsm", ".pptm", ".doc", ".xls", ".ppt", ".rtf",
    ".html", ".htm", ".svg", ".pdf",
}

# Query parameters commonly used by redirectors to carry the real destination.
REDIRECT_PARAMS = ("url", "u", "q", "target", "redirect", "redirect_uri", "r",
                   "link", "dest", "destination", "next", "continue", "to")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def registered_domain(host: str) -> str:
    """example: 'login.mail.example.co.uk' -> 'example.co.uk'"""
    if not host or IPV4_RE.match(host):
        return host or ""
    if _TLD is not None:
        ext = _TLD(host)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
        return ext.domain or host
    # Fallback without tldextract: last two labels (imperfect for .co.uk etc.)
    parts = host.strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def defang(url: str) -> str:
    """Make a URL non-clickable for safe display in reports and terminals."""
    return url.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")


def refang(text: str) -> str:
    """Undo common defanging so we can still find URLs an analyst pre-defanged."""
    out = text
    for a, b in (
        ("hxxps", "https"), ("hxxp", "http"), ("hXXp", "http"),
        ("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."), (" dot ", "."),
        ("[:]", ":"), ("[://]", "://"), ("[at]", "@"),
    ):
        out = out.replace(a, b)
    return out


def domain_of_address(addr: str) -> str:
    """'Support <a@b.example.com>' or 'a@b.example.com' -> 'b.example.com'"""
    if not addr:
        return ""
    _, parsed = email.utils.parseaddr(addr)
    if "@" in parsed:
        return parsed.rsplit("@", 1)[1].strip(">").lower()
    return ""


def truncate(text: str, limit: int) -> str:
    if text is None:
        return ""
    text = text.strip()
    return text if len(text) <= limit else text[:limit] + f"\n...[truncated, {len(text)} chars total]"


# ---------------------------------------------------------------------------
# HTML parsing (no rendering, no external requests)
# ---------------------------------------------------------------------------


class MailHTMLParser(HTMLParser):
    """Pulls anchors, resource URLs, visible text, and structural counts out of HTML."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.anchors: list[tuple[str, str]] = []      # (href, anchor_text)
        self.resource_urls: list[str] = []            # img/iframe/form/script targets
        self.tag_counts: Counter = Counter()
        self.hidden_elements = 0
        self._text_parts: list[str] = []
        self._current_anchor: dict | None = None
        self._suppress_depth = 0                       # inside <script>/<style>

    # -- tags -------------------------------------------------------------
    def handle_starttag(self, tag: str, attrs) -> None:
        self.tag_counts[tag] += 1
        d = {k.lower(): (v or "") for k, v in attrs}

        style = d.get("style", "").lower().replace(" ", "")
        if ("display:none" in style or "visibility:hidden" in style
                or "font-size:0" in style or "opacity:0" in style
                or d.get("hidden") is not None):
            self.hidden_elements += 1

        if tag in ("script", "style"):
            self._suppress_depth += 1
        elif tag == "a":
            self._current_anchor = {"href": d.get("href", ""), "text": []}
        elif tag in ("img", "iframe", "embed", "source"):
            if d.get("src"):
                self.resource_urls.append(d["src"])
        elif tag == "form":
            if d.get("action"):
                self.resource_urls.append(d["action"])
        elif tag == "meta":
            # <meta http-equiv="refresh" content="0;url=http://...">
            if d.get("http-equiv", "").lower() == "refresh":
                m = re.search(r"url\s*=\s*(\S+)", d.get("content", ""), re.I)
                if m:
                    self.resource_urls.append(m.group(1).strip("'\""))

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style"):
            self._suppress_depth = max(0, self._suppress_depth - 1)
        elif tag == "a" and self._current_anchor is not None:
            text = " ".join("".join(self._current_anchor["text"]).split())
            self.anchors.append((self._current_anchor["href"], text))
            self._current_anchor = None

    def handle_startendtag(self, tag: str, attrs) -> None:
        self.handle_starttag(tag, attrs)

    # -- text -------------------------------------------------------------
    def handle_data(self, data: str) -> None:
        if self._suppress_depth:
            return
        if self._current_anchor is not None:
            self._current_anchor["text"].append(data)
        self._text_parts.append(data)

    @property
    def visible_text(self) -> str:
        raw = "".join(self._text_parts)
        raw = re.sub(r"[ \t\r\f\v]+", " ", raw)
        return re.sub(r"\n\s*\n+", "\n\n", raw).strip()


# ---------------------------------------------------------------------------
# URL extraction and normalisation
# ---------------------------------------------------------------------------

URL_RE = re.compile(
    r"""(?ix)
    \b
    (?: (?:https?|ftp)://  |  www\d{0,3}\. )
    [^\s<>"'`\\\]\)}]+
    """
)

TRAILING_PUNCT = ".,;:!?'\"»)]}>"


def find_urls_in_text(text: str) -> list[str]:
    if not text:
        return []
    candidate_text = refang(html.unescape(text))
    found = []
    for match in URL_RE.finditer(candidate_text):
        url = match.group(0).rstrip(TRAILING_PUNCT)
        if url.lower().startswith("www"):
            url = "http://" + url
        found.append(url)
    return found


def unwrap_redirect(url: str) -> tuple[str, str | None]:
    """
    If the URL is a redirector carrying a real destination in a query param,
    return (final_url, wrapper_host). Otherwise (url, None).
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return url, None
    if not parsed.query:
        return url, None
    qs = parse_qs(parsed.query)
    for key in REDIRECT_PARAMS:
        for variant in (key, key.upper(), key.capitalize()):
            if variant in qs and qs[variant]:
                inner = unquote(qs[variant][0])
                if inner.lower().startswith(("http://", "https://")):
                    deeper, _ = unwrap_redirect(inner)
                    return deeper, parsed.hostname or ""
    return url, None


def analyse_url(raw_url: str, source: str, anchor_text: str = "") -> dict | None:
    raw_url = raw_url.strip()
    if not raw_url or raw_url.lower().startswith(("mailto:", "tel:", "#", "javascript:", "data:")):
        if raw_url.lower().startswith(("javascript:", "data:")):
            return {
                "url": defang(raw_url[:200]),
                "scheme": raw_url.split(":", 1)[0].lower(),
                "host": "",
                "registered_domain": "",
                "source": source,
                "anchor_text": anchor_text,
                "notes": ["non_http_scheme"],
            }
        return None

    decoded = unquote(html.unescape(raw_url))
    final_url, wrapper = unwrap_redirect(decoded)

    try:
        parsed = urlparse(final_url)
    except Exception:
        return None

    host = (parsed.hostname or "").lower()
    notes: list[str] = []

    if IPV4_RE.match(host):
        notes.append("ip_literal_host")
    unicode_host = ""
    if "xn--" in host:
        notes.append("punycode_idn")
        try:
            unicode_host = host.encode("ascii").decode("idna")
        except Exception:
            unicode_host = ""
    if parsed.port and parsed.port not in (80, 443):
        notes.append(f"nonstandard_port_{parsed.port}")
    if "@" in (parsed.netloc or ""):
        notes.append("userinfo_in_url")  # http://trusted.com@evil.com
    if wrapper:
        notes.append("redirect_unwrapped")
    if raw_url != decoded:
        notes.append("percent_encoded")
    if parsed.scheme == "http":
        notes.append("plaintext_http")
    if host.count(".") >= 4:
        notes.append("deep_subdomain")
    if len(final_url) > 150:
        notes.append("long_url")

    entry = {
        "url": defang(final_url[:500]),
        "scheme": parsed.scheme,
        "host": host,
        "registered_domain": registered_domain(host),
        "path": parsed.path[:200],
        "source": source,
        "notes": notes,
    }
    if unicode_host:
        entry["unicode_host"] = unicode_host
    if anchor_text:
        entry["anchor_text"] = anchor_text[:200]
        # Classic trick: link text claims one domain, href points elsewhere.
        shown = find_urls_in_text(anchor_text)
        if shown:
            shown_host = (urlparse(shown[0]).hostname or "").lower()
            if shown_host and registered_domain(shown_host) != entry["registered_domain"]:
                entry["notes"].append("anchor_text_domain_mismatch")
        elif re.search(r"\b[a-z0-9-]+\.(com|net|org|co\.uk|de|io|gov|edu)\b", anchor_text, re.I):
            m = re.search(r"\b([a-z0-9-]+\.(?:com|net|org|co\.uk|de|io|gov|edu))\b", anchor_text, re.I)
            if m and registered_domain(m.group(1).lower()) != entry["registered_domain"]:
                entry["notes"].append("anchor_text_domain_mismatch")
    if wrapper:
        entry["redirect_wrapper"] = wrapper
    return entry


def dedupe_urls(urls: list[dict]) -> list[dict]:
    seen: dict[str, dict] = {}
    for u in urls:
        key = u["url"]
        if key in seen:
            merged = seen[key]
            merged["notes"] = sorted(set(merged["notes"]) | set(u["notes"]))
            if u.get("anchor_text") and not merged.get("anchor_text"):
                merged["anchor_text"] = u["anchor_text"]
            merged["source"] = ",".join(sorted(set(merged["source"].split(",")) | {u["source"]}))
        else:
            seen[key] = dict(u)
    return list(seen.values())


# ---------------------------------------------------------------------------
# Header extraction
# ---------------------------------------------------------------------------


def header_str(msg, name: str) -> str:
    value = msg.get(name)
    if value is None:
        return ""
    return " ".join(str(value).split())


def extract_received_chain(msg) -> list[dict]:
    hops = []
    received = msg.get_all("Received") or []
    for i, hop in enumerate(received[:MAX_RECEIVED_HOPS]):
        raw = " ".join(str(hop).split())
        m_from = re.search(r"\bfrom\s+([^\s;]+)", raw, re.I)
        m_by = re.search(r"\bby\s+([^\s;]+)", raw, re.I)
        m_ip = re.search(r"\[((?:\d{1,3}\.){3}\d{1,3})\]", raw)
        hops.append({
            "index": i,  # 0 = most recent (added last, closest to recipient)
            "from": m_from.group(1) if m_from else "",
            "by": m_by.group(1) if m_by else "",
            "ip": m_ip.group(1) if m_ip else "",
            "raw": raw[:300],
        })
    return hops


AUTH_RE = re.compile(r"\b(spf|dkim|dmarc|compauth)\s*=\s*([a-z_]+)", re.I)


def extract_auth_results(msg) -> dict:
    """Parse Authentication-Results / Received-SPF / ARC headers into verdicts."""
    results = {"spf": "not_found", "dkim": "not_found", "dmarc": "not_found",
               "raw_headers": [], "dkim_signature_present": False}

    headers = []
    for name in ("Authentication-Results", "ARC-Authentication-Results",
                 "Received-SPF", "X-Forefront-Antispam-Report"):
        for value in msg.get_all(name) or []:
            headers.append(f"{name}: {' '.join(str(value).split())}")

    for line in headers:
        results["raw_headers"].append(line[:400])
        for mech, verdict in AUTH_RE.findall(line):
            mech = mech.lower()
            if mech in results and results[mech] == "not_found":
                results[mech] = verdict.lower()
        if line.lower().startswith("received-spf:") and results["spf"] == "not_found":
            m = re.match(r"received-spf:\s*(\w+)", line, re.I)
            if m:
                results["spf"] = m.group(1).lower()

    results["dkim_signature_present"] = bool(msg.get_all("DKIM-Signature"))
    return results


# ---------------------------------------------------------------------------
# Body and attachments
# ---------------------------------------------------------------------------


def decode_part(part) -> str:
    try:
        content = part.get_content()
        if isinstance(content, str):
            return content
    except Exception:
        pass
    payload = part.get_payload(decode=True)
    if payload is None:
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def is_attachment(part) -> bool:
    disp = (part.get_content_disposition() or "").lower()
    if disp == "attachment":
        return True
    if disp == "inline" and part.get_filename():
        return True
    return bool(part.get_filename())


def walk_parts(msg):
    if msg.is_multipart():
        for part in msg.walk():
            if not part.is_multipart():
                yield part
    else:
        yield msg


def extract_bodies_and_attachments(msg) -> tuple[str, str, list[dict]]:
    text_parts, html_parts, attachments = [], [], []

    for part in walk_parts(msg):
        ctype = (part.get_content_type() or "").lower()
        if is_attachment(part):
            payload = part.get_payload(decode=True) or b""
            filename = part.get_filename() or "(unnamed)"
            try:
                filename = str(email.header.make_header(email.header.decode_header(filename)))
            except Exception:
                pass
            ext = os.path.splitext(filename)[1].lower()
            sniffed = ""
            if _MAGIC is not None and payload:
                try:
                    sniffed = _MAGIC.from_buffer(payload[:4096])
                except Exception:
                    sniffed = ""
            entry = {
                "filename": filename,
                "extension": ext,
                "declared_mime": ctype,
                "sniffed_mime": sniffed,
                "size_bytes": len(payload),
                "sha256": sha256_bytes(payload) if payload else "",
                "notes": [],
            }
            if ext in RISKY_EXTENSIONS:
                entry["notes"].append("executable_or_script_extension")
            if ext in CARRIER_EXTENSIONS:
                entry["notes"].append("common_phishing_carrier")
            if filename.count(".") >= 2:
                entry["notes"].append("double_extension")
            if re.search(r"[\u202e\u200f\u200e]", filename):
                entry["notes"].append("bidi_override_in_filename")  # RLO filename spoofing
            if sniffed and ctype and sniffed.split("/")[0] != ctype.split("/")[0]:
                entry["notes"].append("mime_type_mismatch")
            attachments.append(entry)
        elif ctype == "text/plain":
            text_parts.append(decode_part(part))
        elif ctype == "text/html":
            html_parts.append(decode_part(part))

    return "\n\n".join(text_parts), "\n\n".join(html_parts), attachments


# ---------------------------------------------------------------------------
# Derived signals (deterministic — these also form the Day 6 rule baseline)
# ---------------------------------------------------------------------------


def build_derived(headers: dict, auth: dict, urls: list[dict],
                  attachments: list[dict], body_text: str, html_stats: dict) -> dict:
    from_domain = domain_of_address(headers["from"])
    from_reg = registered_domain(from_domain)
    reply_domain = domain_of_address(headers["reply_to"])
    return_domain = domain_of_address(headers["return_path"])

    url_domains = sorted({u["registered_domain"] for u in urls
                          if u.get("registered_domain")})
    off_domain_urls = [d for d in url_domains if d and d != from_reg]

    display_name, _ = email.utils.parseaddr(headers["from"])

    signals = {
        "from_domain": from_domain,
        "from_registered_domain": from_reg,
        "display_name": display_name,
        "reply_to_domain_mismatch": bool(reply_domain and registered_domain(reply_domain) != from_reg),
        "return_path_domain_mismatch": bool(return_domain and registered_domain(return_domain) != from_reg),
        "display_name_contains_email": bool(re.search(r"[\w.+-]+@[\w.-]+", display_name)),
        "spf_result": auth["spf"],
        "dkim_result": auth["dkim"],
        "dmarc_result": auth["dmarc"],
        "auth_failure": any(auth[k] in ("fail", "softfail", "none", "permerror", "temperror")
                            for k in ("spf", "dkim", "dmarc")),
        "url_count": len(urls),
        "url_registered_domains": url_domains,
        "urls_off_sender_domain": off_domain_urls,
        "has_ip_literal_url": any("ip_literal_host" in u["notes"] for u in urls),
        "has_punycode_url": any("punycode_idn" in u["notes"] for u in urls),
        "has_anchor_text_mismatch": any("anchor_text_domain_mismatch" in u["notes"] for u in urls),
        "has_redirect_wrapper": any("redirect_unwrapped" in u["notes"] for u in urls),
        "attachment_count": len(attachments),
        "has_risky_attachment": any("executable_or_script_extension" in a["notes"] for a in attachments),
        "html_present": html_stats.get("present", False),
        "html_hidden_elements": html_stats.get("hidden_elements", 0),
        "html_form_count": html_stats.get("form_count", 0),
        "body_length_chars": len(body_text),
    }
    return signals


# ---------------------------------------------------------------------------
# Main parse routine
# ---------------------------------------------------------------------------


def parse_eml(path: str) -> dict:
    with open(path, "rb") as fh:
        raw = fh.read()
    msg = email.message_from_bytes(raw, policy=email.policy.default)

    headers = {
        "from": header_str(msg, "From"),
        "to": header_str(msg, "To"),
        "cc": header_str(msg, "Cc"),
        "reply_to": header_str(msg, "Reply-To"),
        "return_path": header_str(msg, "Return-Path"),
        "sender": header_str(msg, "Sender"),
        "subject": header_str(msg, "Subject"),
        "date": header_str(msg, "Date"),
        "message_id": header_str(msg, "Message-ID"),
        "x_mailer": header_str(msg, "X-Mailer") or header_str(msg, "User-Agent"),
        "content_type": header_str(msg, "Content-Type")[:200],
        "list_unsubscribe": header_str(msg, "List-Unsubscribe")[:200],
    }

    auth = extract_auth_results(msg)
    received = extract_received_chain(msg)
    body_text, body_html, attachments = extract_bodies_and_attachments(msg)

    # URLs from the plain-text body
    urls = [analyse_url(u, "text_body") for u in find_urls_in_text(body_text)]
    urls = [u for u in urls if u]

    html_stats = {"present": bool(body_html.strip())}
    if body_html.strip():
        hp = MailHTMLParser()
        try:
            hp.feed(body_html)
            hp.close()
        except Exception:
            pass
        for href, anchor_text in hp.anchors:
            entry = analyse_url(href, "html_href", anchor_text)
            if entry:
                urls.append(entry)
        for res in hp.resource_urls:
            entry = analyse_url(res, "html_resource")
            if entry:
                urls.append(entry)
        for u in find_urls_in_text(hp.visible_text):
            entry = analyse_url(u, "html_text")
            if entry:
                urls.append(entry)
        html_stats.update({
            "hidden_elements": hp.hidden_elements,
            "form_count": hp.tag_counts.get("form", 0),
            "script_count": hp.tag_counts.get("script", 0),
            "iframe_count": hp.tag_counts.get("iframe", 0),
            "image_count": hp.tag_counts.get("img", 0),
            "anchor_count": len(hp.anchors),
        })
        if not body_text.strip():
            body_text = hp.visible_text  # HTML-only email

    urls = dedupe_urls(urls)
    derived = build_derived(headers, auth, urls, attachments, body_text, html_stats)

    return {
        "meta": {
            "source_file": os.path.basename(path),
            "file_size_bytes": len(raw),
            "raw_sha256": sha256_bytes(raw),
            "parsed_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "parser_version": "0.1.0",
        },
        "headers": headers,
        "authentication": auth,
        "received_chain": received,
        "body": {
            "text_excerpt": truncate(body_text, BODY_EXCERPT_CHARS),
            "text_length_chars": len(body_text),
            "html": html_stats,
        },
        "urls": urls,
        "attachments": attachments,
        "derived_signals": derived,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def summarise(bundle: dict) -> str:
    d = bundle["derived_signals"]
    lines = [
        f"  From:     {bundle['headers']['from'][:70]}",
        f"  Subject:  {bundle['headers']['subject'][:70]}",
        f"  Auth:     spf={d['spf_result']} dkim={d['dkim_result']} dmarc={d['dmarc_result']}",
        f"  URLs:     {d['url_count']} ({len(d['urls_off_sender_domain'])} off sender domain)",
        f"  Attach:   {d['attachment_count']}"
        + (" [risky]" if d["has_risky_attachment"] else ""),
    ]
    flags = [k for k in (
        "reply_to_domain_mismatch", "return_path_domain_mismatch",
        "display_name_contains_email", "auth_failure", "has_ip_literal_url",
        "has_punycode_url", "has_anchor_text_mismatch", "has_redirect_wrapper",
        "has_risky_attachment") if d.get(k)]
    lines.append(f"  Flags:    {', '.join(flags) if flags else '(none)'}")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Parse .eml into a JSON feature bundle.")
    ap.add_argument("eml", nargs="?", help="path to a single .eml file")
    ap.add_argument("--dir", help="parse every .eml in this directory")
    ap.add_argument("-o", "--out", help="output .json file, or output directory with --dir")
    ap.add_argument("-q", "--quiet", action="store_true", help="suppress the summary")
    args = ap.parse_args()

    if not args.eml and not args.dir:
        ap.error("give an .eml path or --dir")

    targets: list[str] = []
    if args.dir:
        targets = sorted(
            os.path.join(args.dir, f) for f in os.listdir(args.dir)
            if f.lower().endswith(".eml")
        )
        if not targets:
            print(f"No .eml files found in {args.dir}", file=sys.stderr)
            return 1
        if args.out:
            os.makedirs(args.out, exist_ok=True)
    else:
        targets = [args.eml]

    failures = 0
    for path in targets:
        try:
            bundle = parse_eml(path)
        except Exception as exc:  # keep the batch running
            print(f"[FAIL] {path}: {type(exc).__name__}: {exc}", file=sys.stderr)
            failures += 1
            continue

        if args.dir and args.out:
            dest = os.path.join(args.out, os.path.splitext(os.path.basename(path))[0] + ".json")
        else:
            dest = args.out

        payload = json.dumps(bundle, indent=2, ensure_ascii=False)
        if dest:
            with open(dest, "w", encoding="utf-8") as fh:
                fh.write(payload + "\n")
            if not args.quiet:
                print(f"[OK] {os.path.basename(path)} -> {dest}")
                print(summarise(bundle))
                print()
        else:
            print(payload)

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
