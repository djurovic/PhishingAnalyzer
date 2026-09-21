#!/usr/bin/env python3
"""
make_samples.py — generates synthetic .eml fixtures for testing the parser.

These are NOT real phishing emails. They are hand-built test cases, each one
designed to exercise a specific extraction path in eml_parser.py:

  01_legit_newsletter.eml   multipart, auth all pass, aligned domains
  02_legit_internal.eml     plain text only, no URLs, no attachments
  03_phish_credential.eml   SPF fail, anchor-text mismatch, lookalike domain,
                            percent-encoded URL, hidden HTML element, form
  04_phish_invoice.eml      Reply-To mismatch, risky attachment, double
                            extension, IP-literal URL
  05_phish_redirect.eml     redirector wrapping the real destination,
                            punycode host, HTML-only body

Real corpus samples arrive on Day 5 (Nazario + Enron). Using synthetic
fixtures now means the parser is already proven before you introduce
messy real-world input, so a failure on Day 5 is a data problem, not a
code problem.

Usage:
    python3 scripts/make_samples.py samples/
"""

import os
import sys

SAMPLES: dict[str, str] = {}

# ---------------------------------------------------------------------------
SAMPLES["01_legit_newsletter.eml"] = """\
Return-Path: <bounce@news.exampleshop.com>
Received: from mx1.corp.example.org (mx1.corp.example.org [198.51.100.10])
 by mail.corp.example.org with ESMTPS id A1B2C3; Tue, 15 Apr 2025 09:14:02 +0000
Received: from smtp.news.exampleshop.com (smtp.news.exampleshop.com [203.0.113.44])
 by mx1.corp.example.org with ESMTPS id D4E5F6; Tue, 15 Apr 2025 09:14:01 +0000
Authentication-Results: mx1.corp.example.org;
 spf=pass smtp.mailfrom=news.exampleshop.com;
 dkim=pass header.d=exampleshop.com;
 dmarc=pass header.from=exampleshop.com
DKIM-Signature: v=1; a=rsa-sha256; d=exampleshop.com; s=sel1; h=from:subject;
 b=abcdef1234567890
From: ExampleShop News <news@exampleshop.com>
To: stefan@corp.example.org
Subject: Your April product roundup
Date: Tue, 15 Apr 2025 09:14:00 +0000
Message-ID: <20250415091400.111@news.exampleshop.com>
List-Unsubscribe: <https://exampleshop.com/unsubscribe?id=9931>
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="BOUND1"

--BOUND1
Content-Type: text/plain; charset="utf-8"

Hello Stefan,

Here is what is new this month. Browse the full catalogue at
https://exampleshop.com/april-roundup

To stop receiving these, visit https://exampleshop.com/unsubscribe?id=9931

-- The ExampleShop team
--BOUND1
Content-Type: text/html; charset="utf-8"

<html><body>
<h1>April roundup</h1>
<p>Hello Stefan, here is what is new this month.</p>
<p><a href="https://exampleshop.com/april-roundup">Browse the catalogue</a></p>
<img src="https://cdn.exampleshop.com/logo.png" alt="logo">
<p><a href="https://exampleshop.com/unsubscribe?id=9931">Unsubscribe</a></p>
</body></html>
--BOUND1--
"""

# ---------------------------------------------------------------------------
SAMPLES["02_legit_internal.eml"] = """\
Return-Path: <marta.k@corp.example.org>
Received: from desk-042.corp.example.org (desk-042.corp.example.org [10.20.30.42])
 by mail.corp.example.org with ESMTP id 77AA88; Wed, 16 Apr 2025 11:02:10 +0000
Authentication-Results: mail.corp.example.org;
 spf=pass smtp.mailfrom=corp.example.org;
 dkim=pass header.d=corp.example.org;
 dmarc=pass header.from=corp.example.org
From: "Marta K." <marta.k@corp.example.org>
To: stefan@corp.example.org
Subject: Re: standup moved to 10:15
Date: Wed, 16 Apr 2025 11:02:09 +0000
Message-ID: <c0ffee.20250416@corp.example.org>
In-Reply-To: <beef.20250416@corp.example.org>
Content-Type: text/plain; charset="utf-8"

Works for me. I'll bring the numbers from the sprint board.

Marta
"""

# ---------------------------------------------------------------------------
SAMPLES["03_phish_credential.eml"] = """\
Return-Path: <bounce@mail-relay-7742.xyz>
Received: from mx1.corp.example.org (mx1.corp.example.org [198.51.100.10])
 by mail.corp.example.org with ESMTPS id 9F8E7D; Thu, 17 Apr 2025 03:41:55 +0000
Received: from unknown (unknown [45.155.205.233])
 by mx1.corp.example.org with SMTP id 1A2B3C; Thu, 17 Apr 2025 03:41:50 +0000
Authentication-Results: mx1.corp.example.org;
 spf=fail smtp.mailfrom=mail-relay-7742.xyz;
 dkim=none;
 dmarc=fail header.from=corp-example.org
Received-SPF: Fail (mx1.corp.example.org: domain of mail-relay-7742.xyz does
 not designate 45.155.205.233 as permitted sender)
From: IT Helpdesk <it-helpdesk@corp-example.org>
Reply-To: recovery-desk@mail-relay-7742.xyz
To: stefan@corp.example.org
Subject: Action required: mailbox verification
Date: Thu, 17 Apr 2025 03:41:48 +0000
Message-ID: <7742.20250417034148@mail-relay-7742.xyz>
X-Mailer: PHPMailer 5.2.9
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="BOUND3"

--BOUND3
Content-Type: text/plain; charset="utf-8"

Your mailbox quota could not be verified. Confirm your account within 24
hours at https://corp-example.org.account-check%2Email-relay-7742%2Exyz/verify

IT Helpdesk
--BOUND3
Content-Type: text/html; charset="utf-8"

<html><body>
<p>Your mailbox quota could not be verified.</p>
<p><a href="https://corp-example.org.account-check.mail-relay-7742.xyz/verify">
https://mail.corp.example.org/verify</a></p>
<form action="https://mail-relay-7742.xyz/collect.php" method="post">
  <input type="text" name="user">
  <input type="password" name="pass">
</form>
<div style="display:none;font-size:0">quota mailbox storage account limit</div>
<span style="visibility:hidden">filler text</span>
</body></html>
--BOUND3--
"""

# ---------------------------------------------------------------------------
SAMPLES["04_phish_invoice.eml"] = """\
Return-Path: <billing@invoice-portal-cdn.top>
Received: from mx1.corp.example.org (mx1.corp.example.org [198.51.100.10])
 by mail.corp.example.org with ESMTPS id 5C6D7E; Fri, 18 Apr 2025 06:12:33 +0000
Received: from vps-8842.hosting-cheap.net (vps-8842.hosting-cheap.net [185.220.101.7])
 by mx1.corp.example.org with SMTP id 8H9I0J; Fri, 18 Apr 2025 06:12:30 +0000
Authentication-Results: mx1.corp.example.org;
 spf=softfail smtp.mailfrom=invoice-portal-cdn.top;
 dkim=none;
 dmarc=fail header.from=accounts-payable.com
From: "Accounts Payable" <billing@accounts-payable.com>
Reply-To: "Accounts Payable" <remit-updates@invoice-portal-cdn.top>
To: stefan@corp.example.org
Subject: Invoice INV-88213 overdue
Date: Fri, 18 Apr 2025 06:12:28 +0000
Message-ID: <inv88213@invoice-portal-cdn.top>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUND4"

--BOUND4
Content-Type: text/plain; charset="utf-8"

Invoice INV-88213 remains unpaid. The statement is attached.
Payment portal: http://185.220.101.7/pay/inv88213

Accounts Payable
--BOUND4
Content-Type: application/octet-stream; name="Invoice_INV-88213.pdf.js"
Content-Disposition: attachment; filename="Invoice_INV-88213.pdf.js"
Content-Transfer-Encoding: base64

dmFyIHggPSAidGhpcyBpcyBhIGhhcm1sZXNzIHBsYWNlaG9sZGVyIGZvciBwYXJzZXIgdGVzdGlu
ZyI7Cg==
--BOUND4
Content-Type: application/zip; name="statement.zip"
Content-Disposition: attachment; filename="statement.zip"
Content-Transfer-Encoding: base64

UEsDBAoAAAAAAOaKjVoAAAAAAAAAAAAAAAAJAAAAcGxhY2Vob2xkZXJQSwUGAAAAAAAAAAAAAAAA
AAAAAAAA
--BOUND4--
"""

# ---------------------------------------------------------------------------
SAMPLES["05_phish_redirect.eml"] = """\
Return-Path: <no-reply@track.clickwrap-svc.io>
Received: from mx1.corp.example.org (mx1.corp.example.org [198.51.100.10])
 by mail.corp.example.org with ESMTPS id 3K4L5M; Sat, 19 Apr 2025 22:05:09 +0000
Authentication-Results: mx1.corp.example.org;
 spf=pass smtp.mailfrom=track.clickwrap-svc.io;
 dkim=fail header.d=clickwrap-svc.io;
 dmarc=fail header.from=secure-docs.io
From: Document Share <notify@secure-docs.io>
To: stefan@corp.example.org
Subject: A document was shared with you
Date: Sat, 19 Apr 2025 22:05:07 +0000
Message-ID: <share-9921@track.clickwrap-svc.io>
MIME-Version: 1.0
Content-Type: text/html; charset="utf-8"

<html><body>
<p>A document was shared with your address.</p>
<p><a href="https://track.clickwrap-svc.io/r?url=https%3A%2F%2Fxn--secure-dcs-9db.io%2Flogin%3Fid%3D9921">
Open document</a></p>
<p>Or paste this into your browser:
https://track.clickwrap-svc.io/r?url=https%3A%2F%2Fxn--secure-dcs-9db.io%2Flogin</p>
<iframe src="https://xn--secure-dcs-9db.io/pixel"></iframe>
</body></html>
"""


def main() -> int:
    out_dir = sys.argv[1] if len(sys.argv) > 1 else "samples"
    os.makedirs(out_dir, exist_ok=True)
    for name, content in SAMPLES.items():
        path = os.path.join(out_dir, name)
        with open(path, "w", encoding="utf-8", newline="\r\n") as fh:
            fh.write(content)
        print(f"wrote {path}")
    print(f"\n{len(SAMPLES)} sample emails written to {out_dir}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
