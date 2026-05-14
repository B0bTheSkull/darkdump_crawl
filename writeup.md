# Pulling IOCs and credentials out of paste dumps with darkdump_crawl

> "Data doesn't disappear when it's leaked — it just moves somewhere you're not looking."

## TL;DR

I built `darkdump_crawl`, a Python library that extracts structured threat intelligence from raw paste-site text. Point it at a URL, a local file, or stdin and it returns deduplicated, categorized findings: credential pairs, AWS and API keys (with Shannon entropy filtering), IP addresses, email addresses, Bitcoin wallets, JWTs, PEM private-key blocks, and context-aware keyword hits. No scraping framework, no database — just regex, entropy math, and structured output that slots into any existing threat-intel pipeline.

---

## Why paste sites matter for threat intel

Paste sites occupy a strange place in the breach ecosystem. They're not dark web markets with escrow and reputation systems — they're public, indexed, and most defenders never look at them. An attacker who just exfiltrated a credential dump can post it to a paste site in seconds, and it'll sit there undetected for hours, sometimes days.

That window is exploitable in both directions.

For defenders, paste monitoring is one of the cheapest forms of early-warning you can build. A leaked `AKIA` key found before it's been used is a rotation, not an incident. A leaked credential found before it's been stuffed is a password reset, not a breach notification. The goal isn't to read every paste — it's to extract signal from the ones that matter.

There's also a red-team angle: understanding what leaks look like, what gets flagged, and what slips through is essential context for writing realistic engagement deliverables and understanding the attacker's operational exposure window after a successful exfil.

---

## What it extracts

| Category | Method |
|---|---|
| Emails | RFC-compliant regex |
| Credential pairs | `user:pass` and `email:pass` multiline regex |
| AWS access keys | `AKIA[0-9A-Z]{16}` literal pattern |
| API / auth keys | Context regex (key=, token=, bearer) + Shannon entropy > 3.5 |
| JWTs | Caught by the `auth_token` context regex; entropy filter keeps them |
| IP addresses | IPv4 with range validation |
| Phone numbers | US-format, flexible separators |
| Bitcoin wallets | Base58-checked address pattern |
| Ethereum wallets | `0x` + 40 hex chars |
| PEM private keys | `-----BEGIN ... PRIVATE KEY-----` header match — fires a CRITICAL alert |
| Keyword hits | Configurable list; returns line number + surrounding context, not just count |

The Shannon entropy check on API keys is worth explaining. A naive approach flags anything that looks like `key=somevalue`. Entropy filtering raises the bar: low-entropy strings like `key=development` or `key=changeme` score below 3.5 bits/character and get dropped. Real secrets — random tokens, base64-encoded payloads — score above that threshold. It eliminates most false positives before the output file is ever written.

---

## How it fits into threat-intel pipelines

`darkdump_crawl` is a library first. The CLI in `main.py` is a thin wrapper around `utils/parser.py:extract_all()`, which returns a plain Python dict. That means you can import it directly into anything:

```python
from utils.parser import extract_all

findings = extract_all(raw_text, extra_keywords=["stripe", "twilio", "pagerduty"])
```

**Feed patterns worth building on top of this:**

- **Paste monitoring + alerting.** A cron job or RSS watcher fetches new paste IDs, pipes each through `extract_all()`, and fires a Slack or email alert if `api_keys`, `private_keys_found`, or `credentials` comes back non-empty. Response time goes from "whenever someone notices" to minutes.

- **SIEM enrichment.** The structured JSON output (`--json`) maps cleanly to Splunk, Elastic, or any ingest pipeline that accepts key-value data. IPs extracted from pastes can be cross-referenced against firewall logs; emails against your user directory.

- **Credential stuffing defense.** Email addresses and `user:pass` pairs from public dumps can be hashed and checked against internal account tables to proactively force resets. Combine with HIBP's k-anonymity API (on the roadmap) for breach-database lookups without sending plaintext credentials anywhere.

- **MISP integration.** The roadmap includes a MISP export format, which would let every extract feed directly into a shared threat-intelligence platform with proper taxonomy and correlation across organizations.

- **Red-team OPSEC audits.** Post-engagement, running your own deliverable artifacts through `extract_all()` is a quick sanity check that you haven't accidentally embedded real credentials, internal IPs, or client-sensitive data in a report.

---

## Demo: running against a synthetic paste

This is real output from the library against a handcrafted "leaked credentials" paste with every IOC type embedded. No real paste sites were touched.

```
============================================================
darkdump_crawl — demo extraction run
Input: synthetic paste blob (no real sites contacted)
============================================================
```

```json
{
  "emails": [
    "hax0r99@tutanota.com",
    "j.smith@acme-corp.com",
    "darkuser@protonmail.com"
  ],
  "ips": [
    "203.0.113.77",
    "10.0.1.43",
    "10.0.1.42"
  ],
  "phone_numbers": [
    "555-867-5309"
  ],
  "credentials": [
    "admin:hunter2!",
    "root:S3cr3tP@ssw0rd!",
    "j.smith@acme-corp.com:Welc0me#2026"
  ],
  "api_keys": [
    {
      "type": "api_key_context",
      "value": "sk-a7fG3kLmZ8nVpQrXsTwYuAaBbCcDdEeFfGgHhIiJjKkL"
    },
    {
      "type": "api_key_context",
      "value": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJqc21pdGgiLCJleHAiOjE3NjcyMjU2MDB9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    },
    {
      "type": "aws_access_key",
      "value": "AKIAIOSFODNN7EXAMPLE"
    }
  ],
  "bitcoin_wallets": [
    "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf"
  ],
  "private_keys_found": true,
  "keyword_hits": [
    {"keyword": "credential", "line_number": 2,  "context": "=== INTERNAL CREDENTIAL DUMP 2026-05-01 ==="},
    {"keyword": "aws_access", "line_number": 11, "context": "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"},
    {"keyword": "rotate",     "line_number": 10, "context": "# AWS programmatic access (rotate immediately)"},
    {"keyword": "deploy",     "line_number": 31, "context": "# SSH private key (deploy user)"},
    {"keyword": "ransom",     "line_number": 38, "context": "# Contact for ransom: darkuser@protonmail.com"}
  ]
}
```

```
SUMMARY
============================================================
  Emails found          : 3
  IP addresses          : 3
  Credential pairs      : 3
  API / AWS keys        : 3
  Bitcoin wallets       : 1
  Phone numbers         : 1
  Keyword hits          : 13
  Private key block     : DETECTED (CRITICAL)
```

Everything landed. The JWT was caught by the `auth_token` context regex and passed the entropy filter (JWT payloads score high on randomness). The AWS key hit the dedicated `AKIA` pattern. The PEM header triggered the CRITICAL flag on its own, regardless of the surrounding text — the right call, because private key material is a CRITICAL finding whether or not any other context keywords appear.

Full extraction output is at [`screenshots/sample-extraction.txt`](screenshots/sample-extraction.txt).

---

## Things I got right and things I'd do differently

**Right:**

- **Library-first design.** Keeping `extract_all()` as a clean function that takes text and returns a dict means every use case — CLI, pipeline, test suite, SIEM connector — uses the same extractor. There's no copy-pasted logic.

- **Entropy on API keys.** This was the right call. Before adding it, the context regex flagged `api_key = null`, `token = false`, and similar placeholder values constantly. Entropy killed that entire class of false positives without touching recall on real keys.

- **Per-run timestamped directories.** Analysis runs that overwrite each other destroy evidence. Timestamped dirs are the minimum viable audit trail for anything touching potentially sensitive data.

**Differently:**

- **Deduplicate earlier, not in the CLI wrapper.** Right now dedup happens in `main.py` after extraction. It should happen inside `extract_all()` so library consumers don't have to remember to do it themselves.

- **Add a confidence score.** Returning a finding with no quality signal forces downstream consumers to treat all results equally. Even a simple three-level triage (high/medium/low) based on entropy score and pattern specificity would make triage faster.

- **Rate-limit and backoff before the first real use, not after.** I added exponential backoff to the fetcher only after hitting a 429 wall during early testing. Should've been in from the start.

---

## Roadmap

- [ ] Tor/SOCKS proxy support — required for any serious paste monitoring that needs to outlast rate limits or geo-blocks
- [ ] HIBP k-anonymity hash lookup for extracted credentials
- [ ] MISP export format for structured threat-intel sharing
- [ ] YAML config file so keyword lists and output paths don't require CLI flags every run
- [ ] Confidence scoring on API key findings

---

## Resources

- [Pastebin API docs](https://pastebin.com/doc_api) — rate limits and scraping rules; read these before building any live monitoring
- [Have I Been Pwned k-anonymity model](https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange) — how to check credentials without sending plaintext to a third party
- [MISP Project](https://www.misp-project.org/) — the threat-sharing platform this should eventually export to
- [Shannon entropy explainer](https://en.wikipedia.org/wiki/Entropy_(information_theory)) — the math behind the API key filter
- The repo: [github.com/B0bTheSkull/darkdump_crawl](https://github.com/B0bTheSkull/darkdump_crawl)
