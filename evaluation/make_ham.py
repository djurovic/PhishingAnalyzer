#!/usr/bin/env python3
"""
make_ham.py — generates synthetic legitimate mail as an mbox.

WHY THIS EXISTS, AND WHAT IT IS NOT

The evaluation needs legitimate mail from the same era as the phishing corpus
(Nazario phishing-2024). Real options are a personal inbox export (not
publicly redistributable) or an era-matched public ham corpus (none exists —
SpamAssassin and Enron both predate SPF/DKIM/DMARC deployment).

This generator is the fallback. It produces structurally realistic mail:
full Received chains, Authentication-Results with a realistic mix of verdicts,
DKIM-Signature headers, multipart/alternative bodies with both text and HTML,
on-domain links, List-Unsubscribe on bulk mail, and benign attachments.

WHAT IT IS NOT: a substitute for real mail in reported results.

  * Real inboxes contain forwarded threads, quoted replies, broken encodings,
    mixed languages, marketing mail that looks nearly identical to phishing,
    and messages that legitimately fail SPF because of forwarding. None of
    that is here.
  * Every message here was written from a template. Real phishing was written
    by humans. An LLM analyst may separate the two on PROSE STYLE rather than
    on phishing indicators — and audit_dataset.py cannot detect that, because
    it only inspects structural features.

So: use this to develop, debug and demonstrate the pipeline. State clearly in
the report that legitimate samples are synthetic, and treat the headline
metrics as a demonstration of the pipeline rather than a measurement of
real-world detection accuracy. If you can get even 50 real messages from your
own inbox, report those numbers alongside these — the comparison is itself
worth writing about.

Usage:
    python3 scripts/make_ham.py --count 200 --out corpora/ham/synthetic_ham.mbox
    python3 scripts/make_ham.py --count 200 --year 2024 --seed 42 --out corpora/ham/synthetic_ham.mbox
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import random
import string
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime, make_msgid

# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------

FIRST = ["Marta", "Tomas", "Jelena", "Nikola", "Ana", "Petar", "Ivana", "Luka",
         "Sara", "Milos", "Katarina", "Vuk", "Dunja", "Filip", "Teodora",
         "Andrej", "Maja", "Stefan", "Lena", "Bojan", "Priya", "Daniel",
         "Ingrid", "Marcus", "Chloe", "Hassan", "Yuki", "Olga", "Rafael", "Nora"]
LAST = ["Petrovic", "Jovanovic", "Nikolic", "Markovic", "Stojanovic", "Ilic",
        "Pavlovic", "Kovac", "Novak", "Horvat", "Sharma", "Weber", "Lindqvist",
        "Okafor", "Tanaka", "Duarte", "Fischer", "Moreau", "Rossi", "Nowak"]

INTERNAL_DOMAIN = "novatek-systems.com"
INTERNAL_MX = "mx01.novatek-systems.com"

VENDORS = [
    ("GitHub", "github.com", "notifications@github.com"),
    ("Atlassian", "atlassian.com", "jira@atlassian.com"),
    ("Slack", "slack.com", "feedback@slack.com"),
    ("Zoom", "zoom.us", "no-reply@zoom.us"),
    ("Dropbox", "dropbox.com", "no-reply@dropbox.com"),
    ("Stripe", "stripe.com", "receipts@stripe.com"),
    ("LinkedIn", "linkedin.com", "messages-noreply@linkedin.com"),
    ("Grammarly", "grammarly.com", "info@grammarly.com"),
    ("DigitalOcean", "digitalocean.com", "billing@digitalocean.com"),
    ("Notion", "notion.so", "team@notion.so"),
]

UNIVERSITIES = [
    ("University Library", "lib.ac.rs", "circulation@lib.ac.rs"),
    ("Faculty Registry", "fon.ac.rs", "registry@fon.ac.rs"),
    ("IEEE Xplore", "ieee.org", "onlinesupport@ieee.org"),
]

PROJECTS = ["Halcyon", "Redwood", "Northwind", "Blue Harbour", "Tessellate",
            "Ironwood", "Corvus", "Meridian", "Saffron", "Lightkeeper"]
TOPICS = ["the migration plan", "Q3 headcount", "the vendor review",
          "the incident postmortem", "onboarding docs", "the pricing model",
          "sprint capacity", "the compliance checklist", "the data retention policy",
          "the customer escalation", "the release notes", "the budget forecast"]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def rand_ip(rng: random.Random, public: bool = True) -> str:
    if public:
        blocks = [(52, 95), (34, 200), (104, 47), (192, 0), (13, 107), (40, 92)]
        a, b = rng.choice(blocks)
        return f"{a}.{b}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
    return f"10.{rng.randint(0, 40)}.{rng.randint(0, 255)}.{rng.randint(2, 254)}"


def rand_id(rng: random.Random, n: int = 12) -> str:
    return "".join(rng.choice(string.ascii_uppercase + string.digits) for _ in range(n))


def dkim_sig(rng: random.Random, domain: str) -> str:
    b = base64.b64encode(bytes(rng.getrandbits(8) for _ in range(96))).decode()
    return (f"v=1; a=rsa-sha256; c=relaxed/relaxed; d={domain}; "
            f"s=selector{rng.randint(1, 3)}; t={rng.randint(1700000000, 1735000000)};\r\n"
            f"\th=from:to:subject:date:message-id:mime-version;\r\n"
            f"\tbh={base64.b64encode(hashlib.sha256(b.encode()).digest()).decode()};\r\n"
            f"\tb={b[:60]}\r\n\t{b[60:]}")


def auth_results(rng: random.Random, sender_domain: str, envelope_domain: str) -> tuple[str, str]:
    """
    Returns (Authentication-Results value, Received-SPF value).

    Not everything passes. Real legitimate mail fails SPF when forwarded, and
    plenty of small senders never set up DKIM. Making every legitimate message
    pass all three would hand the classifier a perfect separator and recreate
    exactly the artefact this corpus is meant to avoid.
    """
    roll = rng.random()
    if roll < 0.78:
        spf, dkim, dmarc = "pass", "pass", "pass"
    elif roll < 0.88:
        spf, dkim, dmarc = "pass", "none", "pass"        # no DKIM configured
    elif roll < 0.94:
        spf, dkim, dmarc = "neutral", "pass", "pass"     # relaxed SPF record
    elif roll < 0.98:
        spf, dkim, dmarc = "softfail", "pass", "pass"    # forwarded mail
    else:
        spf, dkim, dmarc = "none", "none", "none"        # internal, unauthenticated

    ar = (f"{INTERNAL_MX};\r\n"
          f"\tspf={spf} (sender IP is authorised) smtp.mailfrom={envelope_domain};\r\n"
          f"\tdkim={dkim} header.d={sender_domain};\r\n"
          f"\tdmarc={dmarc} header.from={sender_domain}")
    spf_hdr = (f"{spf.capitalize()} ({INTERNAL_MX}: domain of {envelope_domain} "
               f"designates the sending host as permitted sender)")
    return ar, spf_hdr


def received_chain(rng: random.Random, when: datetime, sender_host: str,
                   sender_ip: str, internal: bool) -> list[str]:
    t2 = when + timedelta(seconds=rng.randint(1, 4))
    t3 = t2 + timedelta(seconds=rng.randint(1, 3))
    hops = []
    if internal:
        hops.append(
            f"from {sender_host} ({sender_host} [{sender_ip}])\r\n"
            f"\tby {INTERNAL_MX} (Postfix) with ESMTP id {rand_id(rng, 10)};\r\n"
            f"\t{format_datetime(t3)}")
    else:
        hops.append(
            f"from {INTERNAL_MX} ({INTERNAL_MX} [10.20.0.11])\r\n"
            f"\tby mailstore01.{INTERNAL_DOMAIN} with LMTP id {rand_id(rng, 10)};\r\n"
            f"\t{format_datetime(t3)}")
        hops.append(
            f"from {sender_host} ({sender_host} [{sender_ip}])\r\n"
            f"\tby {INTERNAL_MX} (Postfix) with ESMTPS id {rand_id(rng, 10)}\r\n"
            f"\t(version=TLSv1.3 cipher=TLS_AES_256_GCM_SHA384 bits=256);\r\n"
            f"\t{format_datetime(t2)}")
    return hops  # most recent first, as in a real message


def html_wrap(body_html: str, brand: str = "", footer: str = "") -> str:
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#f4f5f7;font-family:-apple-system,Segoe UI,Roboto,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:24px 12px">
<table width="600" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:6px">
<tr><td style="padding:24px 32px">
{f'<p style="font-size:18px;font-weight:600;margin:0 0 16px">{brand}</p>' if brand else ''}
{body_html}
</td></tr></table>
{f'<p style="font-size:12px;color:#8a8f98;padding:16px">{footer}</p>' if footer else ''}
</td></tr></table></body></html>"""


# ---------------------------------------------------------------------------
# Message genres
# ---------------------------------------------------------------------------


def person(rng: random.Random) -> tuple[str, str]:
    name = f"{rng.choice(FIRST)} {rng.choice(LAST)}"
    handle = name.lower().replace(" ", ".")
    return name, handle


def genre_internal_thread(rng: random.Random) -> dict:
    name, handle = person(rng)
    topic = rng.choice(TOPICS)
    project = rng.choice(PROJECTS)
    replying = rng.random() < 0.6
    subject = f"{'Re: ' if replying else ''}{project}: {topic}"
    text = (
        f"Hi,\r\n\r\n"
        f"{rng.choice(['Quick update on', 'Following up on', 'Circling back on', 'Thoughts on'])} "
        f"{topic}. {rng.choice(['I have pushed the revised figures to the shared drive.', 'The numbers are in the deck from Tuesday.', 'Nothing blocking on our side.', 'We are still waiting on legal to come back.'])}\r\n\r\n"
        f"{rng.choice(['Can you review before Thursday?', 'Let me know if that works.', 'Happy to walk through it if easier.', 'No rush, but ideally before the end of the week.'])}\r\n\r\n"
        f"{rng.choice(['Thanks,', 'Best,', 'Cheers,'])}\r\n{name.split()[0]}\r\n")
    if replying:
        text += (f"\r\nOn {rng.choice(['Mon', 'Tue', 'Wed'])}, "
                 f"{rng.choice(FIRST)} wrote:\r\n"
                 f"> {rng.choice(['Can we get an update on this?', 'Where did we land on the timeline?', 'Adding Marta for visibility.'])}\r\n")
    return {
        "from_name": name, "from_addr": f"{handle}@{INTERNAL_DOMAIN}",
        "from_domain": INTERNAL_DOMAIN, "subject": subject, "text": text,
        "html": None, "internal": True,
        "sender_host": f"desk-{rng.randint(100, 999)}.{INTERNAL_DOMAIN}",
        "sender_ip": rand_ip(rng, public=False),
    }


def genre_vendor_notification(rng: random.Random) -> dict:
    brand, domain, addr = rng.choice(VENDORS)
    name, _ = person(rng)
    repo = f"{rng.choice(['core', 'api', 'infra', 'web'])}-{rng.choice(PROJECTS).lower().replace(' ', '-')}"
    kinds = [
        (f"[{repo}] Pull request #{rng.randint(100, 900)} needs review",
         f"{name} requested your review on pull request #{rng.randint(100, 900)}.",
         f"https://{domain}/{INTERNAL_DOMAIN.split('.')[0]}/{repo}/pull/{rng.randint(100, 900)}"),
        (f"Your {brand} invoice for {rng.choice(['March', 'April', 'May', 'June'])}",
         f"Your monthly invoice of EUR {rng.randint(9, 240)}.00 has been charged.",
         f"https://{domain}/account/billing/invoices"),
        (f"{name} shared a document with you",
         f"{name} shared \"{rng.choice(PROJECTS)} {rng.choice(['Spec', 'Notes', 'Roadmap'])}\" with you.",
         f"https://{domain}/s/{rand_id(rng, 16).lower()}"),
        (f"New sign-in to your {brand} account",
         f"We noticed a new sign-in from Belgrade, Serbia on {rng.choice(['Chrome', 'Firefox'])}.",
         f"https://{domain}/account/security"),
    ]
    subject, line, link = rng.choice(kinds)
    text = (f"{line}\r\n\r\nView it here: {link}\r\n\r\n"
            f"--\r\n{brand}\r\nYou are receiving this because you have a {brand} account.\r\n")
    html = html_wrap(
        f'<p style="font-size:15px;color:#24292f">{line}</p>'
        f'<p style="margin:24px 0"><a href="{link}" '
        f'style="background:#0969da;color:#fff;padding:10px 18px;border-radius:6px;'
        f'text-decoration:none;font-size:14px">Open in {brand}</a></p>'
        f'<p style="font-size:13px;color:#57606a">Or paste this link: {link}</p>',
        brand=brand,
        footer=f"{brand} · <a href='https://{domain}/settings/notifications'>Notification settings</a>")
    return {
        "from_name": brand, "from_addr": addr, "from_domain": domain,
        "subject": subject, "text": text, "html": html, "internal": False,
        "sender_host": f"mail-{rng.randint(1, 40)}.{domain}",
        "sender_ip": rand_ip(rng),
        "list_unsubscribe": f"<https://{domain}/settings/notifications>, "
                            f"<mailto:unsubscribe@{domain}>",
    }


def genre_newsletter(rng: random.Random) -> dict:
    brand, domain, addr = rng.choice(VENDORS + UNIVERSITIES)
    items = [(rng.choice(["Inside the new", "What we learned building", "A short guide to",
                          "Rethinking", "Notes on"]) + " " + rng.choice(
        ["incident response", "platform migrations", "on-call rotations", "data pipelines",
         "code review culture", "postmortems", "observability"]),
        f"https://{domain}/blog/{rand_id(rng, 8).lower()}") for _ in range(rng.randint(2, 4))]
    subject = f"{brand} {rng.choice(['Weekly', 'Monthly', 'Digest', 'Roundup'])}: " + items[0][0]
    text = f"{brand} newsletter\r\n\r\n" + "".join(
        f"* {t}\r\n  {u}\r\n\r\n" for t, u in items) + \
        f"Unsubscribe: https://{domain}/unsubscribe?id={rand_id(rng, 10).lower()}\r\n"
    html = html_wrap(
        "".join(f'<p style="margin:0 0 18px"><a href="{u}" style="color:#0969da;'
                f'font-size:15px;text-decoration:none">{t}</a></p>' for t, u in items),
        brand=brand,
        footer=f"You are subscribed as a reader. "
               f"<a href='https://{domain}/unsubscribe?id={rand_id(rng, 10).lower()}'>Unsubscribe</a>")
    return {
        "from_name": f"{brand} Newsletter", "from_addr": addr, "from_domain": domain,
        "subject": subject, "text": text, "html": html, "internal": False,
        "sender_host": f"bulk-{rng.randint(1, 20)}.{domain}", "sender_ip": rand_ip(rng),
        "list_unsubscribe": f"<https://{domain}/unsubscribe>, <mailto:u@{domain}>",
        "precedence": "bulk",
    }


def genre_receipt_with_attachment(rng: random.Random) -> dict:
    brand, domain, addr = rng.choice(VENDORS)
    inv = f"INV-{rng.randint(10000, 99999)}"
    amount = f"{rng.randint(12, 480)}.{rng.choice(['00', '50', '99'])}"
    subject = f"Your receipt from {brand} [{inv}]"
    text = (f"Thanks for your payment.\r\n\r\nInvoice: {inv}\r\nAmount: EUR {amount}\r\n"
            f"Method: Visa ending {rng.randint(1000, 9999)}\r\n\r\n"
            f"A PDF copy is attached.\r\n\r\n{brand}\r\n")
    html = html_wrap(
        f'<p style="font-size:15px">Thanks for your payment.</p>'
        f'<table style="font-size:14px;color:#24292f"><tr><td style="padding:4px 16px 4px 0">Invoice</td>'
        f'<td><b>{inv}</b></td></tr><tr><td style="padding:4px 16px 4px 0">Amount</td>'
        f'<td><b>EUR {amount}</b></td></tr></table>', brand=brand)
    return {
        "from_name": f"{brand} Billing", "from_addr": addr, "from_domain": domain,
        "subject": subject, "text": text, "html": html, "internal": False,
        "sender_host": f"billing.{domain}", "sender_ip": rand_ip(rng),
        "attachment": (f"receipt_{inv}.pdf", "application/pdf",
                       b"%PDF-1.4\n% synthetic placeholder for parser testing\n%%EOF\n"),
    }


def genre_calendar(rng: random.Random) -> dict:
    name, handle = person(rng)
    project = rng.choice(PROJECTS)
    subject = f"Invitation: {project} {rng.choice(['sync', 'review', 'retro', 'planning'])} " \
              f"@ {rng.choice(['Mon', 'Tue', 'Wed', 'Thu'])} {rng.randint(9, 16)}:00"
    text = (f"You have been invited to a meeting.\r\n\r\n"
            f"Organiser: {name} <{handle}@{INTERNAL_DOMAIN}>\r\n"
            f"Join: https://meet.{INTERNAL_DOMAIN}/{rand_id(rng, 10).lower()}\r\n\r\n"
            f"Agenda:\r\n- {rng.choice(TOPICS)}\r\n- {rng.choice(TOPICS)}\r\n")
    return {
        "from_name": name, "from_addr": f"{handle}@{INTERNAL_DOMAIN}",
        "from_domain": INTERNAL_DOMAIN, "subject": subject, "text": text,
        "html": None, "internal": True,
        "sender_host": f"cal01.{INTERNAL_DOMAIN}", "sender_ip": rand_ip(rng, public=False),
    }


def genre_university(rng: random.Random) -> dict:
    org, domain, addr = rng.choice(UNIVERSITIES)
    subject = rng.choice([
        f"Loan due {rng.randint(1, 28)} {rng.choice(['March', 'April', 'May'])}",
        "Your interlibrary loan request has arrived",
        f"Reading list update for {rng.choice(['CS', 'IS', 'NET'])}{rng.randint(300, 599)}",
        "Access to your saved search results",
    ])
    text = (f"Dear student,\r\n\r\n"
            f"{rng.choice(['This is a reminder about an item on your account.', 'The item you requested is now available for collection.', 'Your reading list has been updated by the module leader.'])}\r\n\r\n"
            f"Details: https://{domain}/account/loans\r\n\r\n{org}\r\n")
    html = html_wrap(f'<p style="font-size:15px">{text.splitlines()[2]}</p>'
                     f'<p><a href="https://{domain}/account/loans">View your account</a></p>',
                     brand=org)
    return {
        "from_name": org, "from_addr": addr, "from_domain": domain,
        "subject": subject, "text": text, "html": html, "internal": False,
        "sender_host": f"mail.{domain}", "sender_ip": rand_ip(rng),
    }


GENRES = [
    (genre_internal_thread, 0.30),
    (genre_vendor_notification, 0.26),
    (genre_newsletter, 0.16),
    (genre_receipt_with_attachment, 0.10),
    (genre_calendar, 0.10),
    (genre_university, 0.08),
]


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------


def build_message(rng: random.Random, when: datetime, recipient: str) -> str:
    genres, weights = zip(*GENRES)
    spec = rng.choices(genres, weights=weights, k=1)[0](rng)

    sender_domain = spec["from_domain"]
    envelope_domain = sender_domain if spec["internal"] else f"bounce.{sender_domain}"
    ar, spf_hdr = auth_results(rng, sender_domain, envelope_domain)
    hops = received_chain(rng, when, spec["sender_host"], spec["sender_ip"], spec["internal"])

    boundary = "----=_Part_" + rand_id(rng, 16)
    mixed_boundary = "----=_Mixed_" + rand_id(rng, 16)
    attachment = spec.get("attachment")

    headers = [
        f"Return-Path: <{rand_id(rng, 8).lower()}@{envelope_domain}>",
    ]
    for hop in hops:
        headers.append(f"Received: {hop}")
    headers += [
        f"Authentication-Results: {ar}",
        f"Received-SPF: {spf_hdr}",
    ]
    if rng.random() < 0.90:
        headers.append(f"DKIM-Signature: {dkim_sig(rng, sender_domain)}")
    headers += [
        f"From: \"{spec['from_name']}\" <{spec['from_addr']}>",
        f"To: {recipient}",
        f"Subject: {spec['subject']}",
        f"Date: {format_datetime(when)}",
        f"Message-ID: {make_msgid(domain=sender_domain)}",
        "MIME-Version: 1.0",
    ]
    if spec.get("list_unsubscribe"):
        headers.append(f"List-Unsubscribe: {spec['list_unsubscribe']}")
        headers.append("List-Unsubscribe-Post: List-Unsubscribe=One-Click")
    if spec.get("precedence"):
        headers.append(f"Precedence: {spec['precedence']}")
    if rng.random() < 0.4:
        headers.append(f"X-Mailer: {rng.choice(['Microsoft Outlook 16.0', 'Apple Mail (2.3774.600.62)', 'Thunderbird 115.7.0', 'Nodemailer 6.9.8'])}")
    if spec["internal"] and rng.random() < 0.5:
        headers.append(f"In-Reply-To: {make_msgid(domain=INTERNAL_DOMAIN)}")

    text = spec["text"]
    html = spec.get("html")

    if attachment:
        fname, mime, data = attachment
        headers.append(f'Content-Type: multipart/mixed; boundary="{mixed_boundary}"')
        body = [f"--{mixed_boundary}"]
        if html:
            body += [f'Content-Type: multipart/alternative; boundary="{boundary}"', "",
                     f"--{boundary}", 'Content-Type: text/plain; charset="utf-8"',
                     "Content-Transfer-Encoding: 8bit", "", text,
                     f"--{boundary}", 'Content-Type: text/html; charset="utf-8"',
                     "Content-Transfer-Encoding: 8bit", "", html, f"--{boundary}--"]
        else:
            body += ['Content-Type: text/plain; charset="utf-8"', "", text]
        b64 = base64.b64encode(data).decode()
        body += [f"--{mixed_boundary}",
                 f'Content-Type: {mime}; name="{fname}"',
                 f'Content-Disposition: attachment; filename="{fname}"',
                 "Content-Transfer-Encoding: base64", "", b64,
                 f"--{mixed_boundary}--"]
    elif html:
        headers.append(f'Content-Type: multipart/alternative; boundary="{boundary}"')
        body = [f"--{boundary}", 'Content-Type: text/plain; charset="utf-8"',
                "Content-Transfer-Encoding: 8bit", "", text,
                f"--{boundary}", 'Content-Type: text/html; charset="utf-8"',
                "Content-Transfer-Encoding: 8bit", "", html, f"--{boundary}--"]
    else:
        headers.append('Content-Type: text/plain; charset="utf-8"')
        headers.append("Content-Transfer-Encoding: 8bit")
        body = ["", text]

    return "\r\n".join(headers) + "\r\n" + "\r\n".join(body) + "\r\n"


def mbox_escape(message: str) -> str:
    """Escape lines that would otherwise be read as an mbox From_ separator."""
    return "\r\n".join(
        (">" + line) if line.startswith("From ") else line
        for line in message.split("\r\n"))


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate synthetic legitimate mail.")
    ap.add_argument("--count", type=int, default=200)
    ap.add_argument("--year", type=int, default=2024,
                    help="match the phishing corpus year to avoid a temporal artefact")
    ap.add_argument("--recipient", default="stefan@novatek-systems.com")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default="corpora/ham/synthetic_ham.mbox")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)

    start = datetime(args.year, 1, 6, 8, 0, tzinfo=timezone.utc)
    span_days = 350

    with open(args.out, "w", encoding="utf-8", newline="") as fh:
        for i in range(args.count):
            when = start + timedelta(
                days=rng.randint(0, span_days),
                hours=rng.randint(0, 11), minutes=rng.randint(0, 59),
                seconds=rng.randint(0, 59))
            msg = build_message(rng, when, args.recipient)
            envelope = f"From ham{i:04d}@synthetic.invalid {when.strftime('%a %b %d %H:%M:%S %Y')}"
            fh.write(envelope + "\r\n" + mbox_escape(msg) + "\r\n")

    size = os.path.getsize(args.out)
    print(f"Wrote {args.count} synthetic legitimate messages to {args.out} "
          f"({size / 1024:.0f} KB)")
    print(f"Dated across {args.year}. Genre mix: "
          + ", ".join(f"{g.__name__.replace('genre_', '')} {int(w * 100)}%"
                      for g, w in GENRES))
    print("\nREMINDER: these are synthetic. State that in the report, and treat the "
          "\nheadline metrics as a pipeline demonstration rather than a measurement "
          "\nof real-world detection accuracy.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
