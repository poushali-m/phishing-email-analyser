# 🎣 Phishing Email Analyser

A command-line Python tool that analyses `.eml` email files for phishing indicators, produces a risk score, and maps findings to the **MITRE ATT&CK framework**.

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white)
![Security](https://img.shields.io/badge/Domain-Email%20Security-E31837?style=flat-square)
![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-orange?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

---

## 📌 What It Does

- Parses `.eml` files or raw email text
- Checks 6 indicator categories: sender, subject, body, URLs, attachments, urgency language
- Produces a **risk score** and **verdict** (HIGH / MEDIUM / LOW / CLEAN)
- Maps findings to **MITRE ATT&CK** techniques (T1566, T1598, T1585)
- Outputs a human-readable terminal report or structured **JSON**

---

## 🧠 Detection Logic

| Category | What's Checked |
|---|---|
| 📨 Sender | Display name spoofing, free email providers, Reply-To mismatch, random local parts |
| 📋 Subject | Suspicious keywords, ALL CAPS, excessive punctuation, fake Re:/Fwd: |
| 📝 Body | Phishing keywords, credential requests, pressure language |
| 🔗 URLs | URL shorteners, raw IP addresses, domain spoofing, HTTP (non-HTTPS) |
| 📎 Attachments | Executable types (.exe, .bat, .ps1, .vbs etc), compressed archives |
| ⏰ Urgency | Time-pressure phrases ("within 24 hours", "final warning" etc) |

---

## 🚀 Usage

```bash
# Analyse a .eml file
python phishing_analyser.py samples/sample_phishing.eml

# Output as JSON
python phishing_analyser.py samples/sample_phishing.eml --json

# Save JSON report to file
python phishing_analyser.py samples/sample_phishing.eml --output report.json

# Read from stdin
cat email.eml | python phishing_analyser.py -
```

---

## 📊 Sample Output

```
════════════════════════════════════════════════════════════
  PHISHING EMAIL ANALYSER — REPORT
════════════════════════════════════════════════════════════
  Timestamp  : 2026-04-14T09:00:00Z
  From       : "PayPal Security" <security-alert@gmail.com>
  Subject    : URGENT: Your PayPal Account Has Been Suspended
  Reply-To   : collect@evil-domain.ru
  URLs found : 1
  Attachments: 0
────────────────────────────────────────────────────────────
  Risk Score : 145/100+
  Verdict    : HIGH RISK — Very likely phishing
────────────────────────────────────────────────────────────
  INDICATORS FLAGGED:
  01. [+30 pts] Display name 'paypal' does not match sender domain — possible spoofing
  02. [+10 pts] Sender uses free email provider (gmail.com)
  03. [+20 pts] Reply-To address differs from sender — replies may go to attacker
  04. [+15 pts] Suspicious keyword in subject: 'urgent'
  05. [+10 pts] Subject line is ALL CAPS — common urgency manipulation tactic
  06. [+25 pts] Body requests sensitive information: 'enter your password'
  07. [+25 pts] Possible domain spoofing — 'paypal' in URL but not root domain
  08. [+10 pts] Non-HTTPS URL detected
  09. [+20 pts] Urgency language detected: 'within 24 hours', 'final warning'
────────────────────────────────────────────────────────────
  MITRE ATT&CK MAPPING:
  → T1566.001 — Spearphishing Attachment / Sender Spoofing
  → T1566.002 — Spearphishing Link
  → T1598 — Phishing for Information
  → T1585 — Social Engineering via Urgency
════════════════════════════════════════════════════════════
```

---

## 📁 Repository Structure

```
phishing-email-analyser/
├── phishing_analyser.py     # Main analyser script
├── samples/
│   └── sample_phishing.eml  # Example phishing email for testing
├── requirements.txt
└── README.md
```

---

## ⚙️ Requirements

Python 3.8+ — no external dependencies. Uses standard library only (`email`, `re`, `json`, `argparse`, `urllib`).

```bash
# No install needed — just run:
python phishing_analyser.py <file.eml>
```

---

## ⚔️ MITRE ATT&CK Coverage

| Technique | ID | Description |
|---|---|---|
| Spearphishing Link | T1566.002 | Malicious URLs in email body |
| Spearphishing Attachment | T1566.001 | Dangerous file attachments |
| Phishing for Information | T1598 | Credential harvesting attempts |
| Social Engineering | T1585 | Urgency and pressure tactics |

---

## 🔭 Planned Improvements

- [ ] VirusTotal API integration for URL reputation checking
- [ ] SPF/DKIM/DMARC header validation
- [ ] HTML body parsing (not just plain text)
- [ ] Batch analysis of multiple `.eml` files
- [ ] Streamlit web UI

---

## ⚠️ Disclaimer

This tool is for educational and defensive security purposes only. All sample emails are synthetic and created for testing. Do not use against real email infrastructure without authorisation.

---

## 👩‍💻 Author

**Poushali Majumder** — Aspiring Cyber Security Analyst, London 🇬🇧

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0A66C2?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/poushali23)
[![Portfolio](https://img.shields.io/badge/Portfolio-50C8A0?style=flat-square)](https://poushali-m.github.io)
[![GitHub](https://img.shields.io/badge/GitHub-181717?style=flat-square&logo=github&logoColor=white)](https://github.com/poushali-m)
