"""
Phishing Email Analyser
=======================
Analyses .eml files or raw email text for phishing indicators.
Outputs a risk score, flagged indicators, and a structured report.

Author: Poushali Majumder
"""

import re
import email
import argparse
import json
from email import policy
from email.parser import BytesParser, Parser
from datetime import datetime
from urllib.parse import urlparse


# ── Indicator Definitions ────────────────────────────────────────────────────

SUSPICIOUS_KEYWORDS = [
    "urgent", "verify your account", "confirm your identity", "click here",
    "your account has been suspended", "unusual activity", "update your payment",
    "you have won", "congratulations", "limited time", "act now", "immediately",
    "password expired", "security alert", "reset your password", "log in now",
    "your account will be closed", "invoice attached", "refund", "claim your prize",
    "dear customer", "dear user", "valued customer", "kindly",
]

SUSPICIOUS_DOMAINS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "shorturl.at",
    "cutt.ly", "rebrand.ly", "is.gd", "buff.ly",
]

FREE_EMAIL_PROVIDERS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "aol.com", "protonmail.com", "mail.com", "icloud.com",
]

SUSPICIOUS_ATTACHMENTS = [
    ".exe", ".bat", ".vbs", ".js", ".jar", ".scr",
    ".ps1", ".cmd", ".com", ".pif", ".reg", ".msi",
]

URGENCY_PHRASES = [
    "within 24 hours", "immediately", "as soon as possible", "asap",
    "right now", "do not delay", "before it's too late", "expires today",
    "last chance", "final warning",
]


# ── Analyser Class ────────────────────────────────────────────────────────────

class PhishingAnalyser:
    def __init__(self):
        self.indicators = []
        self.score = 0
        self.email_data = {}

    def analyse_file(self, filepath: str) -> dict:
        """Parse and analyse a .eml file."""
        with open(filepath, "rb") as f:
            msg = BytesParser(policy=policy.default).parse(f)
        return self._analyse_message(msg)

    def analyse_text(self, raw_text: str) -> dict:
        """Parse and analyse raw email text."""
        msg = Parser(policy=policy.default).parsestr(raw_text)
        return self._analyse_message(msg)

    def _analyse_message(self, msg) -> dict:
        """Run all checks and return structured report."""
        self.indicators = []
        self.score = 0

        # Extract fields
        subject = str(msg.get("subject", ""))
        sender = str(msg.get("from", ""))
        reply_to = str(msg.get("reply-to", ""))
        body = self._get_body(msg)
        attachments = self._get_attachments(msg)
        urls = self._extract_urls(body)

        self.email_data = {
            "subject": subject,
            "from": sender,
            "reply_to": reply_to,
            "attachment_count": len(attachments),
            "url_count": len(urls),
        }

        # Run checks
        self._check_sender(sender, reply_to)
        self._check_subject(subject)
        self._check_body(body)
        self._check_urls(urls)
        self._check_attachments(attachments)
        self._check_urgency(body)

        return self._build_report()

    def _get_body(self, msg) -> str:
        """Extract plain text body from email."""
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                if ctype == "text/plain":
                    try:
                        body += part.get_content()
                    except Exception:
                        body += str(part.get_payload(decode=True) or "")
        else:
            try:
                body = msg.get_content()
            except Exception:
                body = str(msg.get_payload(decode=True) or "")
        return body.lower()

    def _get_attachments(self, msg) -> list:
        """Return list of attachment filenames."""
        attachments = []
        for part in msg.walk():
            if part.get_content_disposition() == "attachment":
                filename = part.get_filename()
                if filename:
                    attachments.append(filename)
        return attachments

    def _extract_urls(self, body: str) -> list:
        """Extract all URLs from body text."""
        url_pattern = r'https?://[^\s<>"\'()]+'
        return re.findall(url_pattern, body)

    def _check_sender(self, sender: str, reply_to: str):
        """Check sender and reply-to for suspicious patterns."""
        sender_lower = sender.lower()

        # Mismatch between display name and email domain
        display_match = re.search(r'"?([^"<]+)"?\s*<([^>]+)>', sender)
        if display_match:
            display_name = display_match.group(1).lower()
            email_addr = display_match.group(2).lower()
            trusted_brands = ["paypal", "amazon", "microsoft", "apple", "google", "netflix", "hmrc", "barclays"]
            for brand in trusted_brands:
                if brand in display_name and brand not in email_addr:
                    self._flag(f"Display name '{brand}' does not match sender domain — possible spoofing", 30)

        # Free email provider impersonating a business
        for provider in FREE_EMAIL_PROVIDERS:
            if provider in sender_lower:
                self._flag(f"Sender uses free email provider ({provider}) — unusual for business communication", 10)
                break

        # Reply-to differs from sender
        if reply_to and reply_to != sender:
            self._flag("Reply-To address differs from sender — replies may go to attacker", 20)

        # Numeric or random-looking local part
        local_part = re.search(r'[\w.+-]+@', sender_lower)
        if local_part:
            lp = local_part.group(0).replace("@", "")
            if re.search(r'\d{4,}', lp):
                self._flag("Sender local part contains long numeric sequence — may be auto-generated", 10)

    def _check_subject(self, subject: str):
        """Check subject line for phishing patterns."""
        subject_lower = subject.lower()

        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in subject_lower:
                self._flag(f"Suspicious keyword in subject: '{keyword}'", 15)
                break

        # ALL CAPS subject
        if subject.isupper() and len(subject) > 5:
            self._flag("Subject line is ALL CAPS — common urgency manipulation tactic", 10)

        # Excessive punctuation
        if subject.count("!") >= 2 or subject.count("?") >= 2:
            self._flag("Excessive punctuation in subject line", 5)

        # Re: / Fwd: spoofing
        if re.match(r'^(re:|fwd:)\s', subject_lower):
            self._flag("Subject begins with Re:/Fwd: — may be spoofing a reply chain", 10)

    def _check_body(self, body: str):
        """Check body text for suspicious content."""
        keyword_hits = []
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in body:
                keyword_hits.append(keyword)

        if keyword_hits:
            self._flag(f"Suspicious keywords in body: {', '.join(keyword_hits[:5])}", min(len(keyword_hits) * 5, 25))

        # Requests for credentials
        credential_patterns = ["enter your password", "confirm your password",
                                "provide your details", "verify your identity",
                                "enter your card", "bank account number"]
        for pattern in credential_patterns:
            if pattern in body:
                self._flag(f"Body requests sensitive information: '{pattern}'", 25)

    def _check_urls(self, urls: list):
        """Analyse extracted URLs for suspicious patterns."""
        for url in urls:
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()

                # URL shortener
                for shortener in SUSPICIOUS_DOMAINS:
                    if shortener in domain:
                        self._flag(f"URL shortener detected: {url[:60]}", 20)

                # IP address instead of domain
                if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
                    self._flag(f"URL uses raw IP address instead of domain: {domain}", 25)

                # Misleading subdomain (e.g. paypal.com.evil.com)
                trusted_brands = ["paypal", "amazon", "microsoft", "apple", "google", "hmrc"]
                for brand in trusted_brands:
                    if brand in domain and not domain.endswith(f"{brand}.com"):
                        self._flag(f"Possible domain spoofing — '{brand}' in URL but not root domain: {domain}", 25)

                # HTTP (not HTTPS)
                if parsed.scheme == "http":
                    self._flag(f"Non-HTTPS URL detected: {url[:60]}", 10)

            except Exception:
                pass

    def _check_attachments(self, attachments: list):
        """Flag dangerous attachment types."""
        for filename in attachments:
            ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            if ext in SUSPICIOUS_ATTACHMENTS:
                self._flag(f"Dangerous attachment type: {filename}", 35)
            elif filename.lower().endswith((".zip", ".rar", ".7z")):
                self._flag(f"Compressed archive attachment (may conceal malicious files): {filename}", 15)

    def _check_urgency(self, body: str):
        """Check for urgency/pressure language."""
        hits = [phrase for phrase in URGENCY_PHRASES if phrase in body]
        if hits:
            self._flag(f"Urgency language detected: {', '.join(hits[:3])}", min(len(hits) * 8, 20))

    def _flag(self, message: str, points: int):
        """Add an indicator and increment score."""
        self.indicators.append({"indicator": message, "points": points})
        self.score += points

    def _build_report(self) -> dict:
        """Build and return the final report."""
        if self.score >= 70:
            verdict = "HIGH RISK — Very likely phishing"
            verdict_code = "HIGH"
        elif self.score >= 35:
            verdict = "MEDIUM RISK — Suspicious, treat with caution"
            verdict_code = "MEDIUM"
        elif self.score >= 10:
            verdict = "LOW RISK — Some indicators present, verify sender"
            verdict_code = "LOW"
        else:
            verdict = "CLEAN — No significant phishing indicators detected"
            verdict_code = "CLEAN"

        return {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "verdict": verdict,
            "verdict_code": verdict_code,
            "risk_score": self.score,
            "email_metadata": self.email_data,
            "indicators": self.indicators,
            "indicator_count": len(self.indicators),
            "mitre_techniques": self._map_mitre(),
        }

    def _map_mitre_techniques(self) -> list:
        """Map findings to MITRE ATT&CK techniques."""
        techniques = []
        codes = [i["indicator"] for i in self.indicators]
        combined = " ".join(codes).lower()

        if "spoof" in combined or "display name" in combined:
            techniques.append("T1566.001 — Spearphishing Attachment / Sender Spoofing")
        if "url" in combined or "shortener" in combined:
            techniques.append("T1566.002 — Spearphishing Link")
        if "attachment" in combined:
            techniques.append("T1566.001 — Spearphishing Attachment")
        if "credential" in combined or "password" in combined:
            techniques.append("T1598 — Phishing for Information")
        if "urgency" in combined:
            techniques.append("T1585 — Social Engineering via Urgency")

        return techniques if techniques else ["No specific MITRE techniques mapped"]

    def _map_mitre(self) -> list:
        return self._map_mitre_techniques()


# ── Report Printer ────────────────────────────────────────────────────────────

def print_report(report: dict):
    verdict_colours = {
        "HIGH": "\033[91m",    # red
        "MEDIUM": "\033[93m",  # yellow
        "LOW": "\033[94m",     # blue
        "CLEAN": "\033[92m",   # green
    }
    reset = "\033[0m"
    colour = verdict_colours.get(report["verdict_code"], "")

    print("\n" + "═" * 60)
    print("  PHISHING EMAIL ANALYSER — REPORT")
    print("═" * 60)
    print(f"  Timestamp  : {report['timestamp']}")
    print(f"  From       : {report['email_metadata'].get('from', 'N/A')}")
    print(f"  Subject    : {report['email_metadata'].get('subject', 'N/A')}")
    print(f"  Reply-To   : {report['email_metadata'].get('reply_to', 'N/A')}")
    print(f"  URLs found : {report['email_metadata'].get('url_count', 0)}")
    print(f"  Attachments: {report['email_metadata'].get('attachment_count', 0)}")
    print("─" * 60)
    print(f"  Risk Score : {report['risk_score']}/100+")
    print(f"  Verdict    : {colour}{report['verdict']}{reset}")
    print("─" * 60)

    if report["indicators"]:
        print("  INDICATORS FLAGGED:")
        for i, ind in enumerate(report["indicators"], 1):
            print(f"  {i:02d}. [{ind['points']:+d} pts] {ind['indicator']}")
    else:
        print("  No indicators flagged.")

    print("─" * 60)
    print("  MITRE ATT&CK MAPPING:")
    for t in report["mitre_techniques"]:
        print(f"  → {t}")
    print("═" * 60 + "\n")


# ── CLI Entry Point ───────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Phishing Email Analyser — analyse .eml files for phishing indicators"
    )
    parser.add_argument("input", help="Path to .eml file or '-' to read from stdin")
    parser.add_argument("--json", action="store_true", help="Output report as JSON")
    parser.add_argument("--output", help="Save JSON report to file")
    args = parser.parse_args()

    analyser = PhishingAnalyser()

    if args.input == "-":
        import sys
        raw = sys.stdin.read()
        report = analyser.analyse_text(raw)
    else:
        report = analyser.analyse_file(args.input)

    if args.json or args.output:
        json_output = json.dumps(report, indent=2)
        if args.output:
            with open(args.output, "w") as f:
                f.write(json_output)
            print(f"Report saved to {args.output}")
        else:
            print(json_output)
    else:
        print_report(report)


if __name__ == "__main__":
    main()
