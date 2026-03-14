# darkdump_crawl

> **Paste & leak intelligence extractor — pull IOCs, credentials, API keys, and crypto wallets from paste dumps.**

![Python](https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![OSINT](https://img.shields.io/badge/use-OSINT%20%2F%20threat--intel-orange?style=flat-square)

---

## What It Extracts

| Category | Detail |
|----------|--------|
| **Emails** | Regex-validated email addresses |
| **Credentials** | `user:pass` and `email:pass` pairs |
| **IP Addresses** | IPv4 addresses |
| **URLs** | HTTP/HTTPS links |
| **Phone Numbers** | US-format phone numbers |
| **API Keys** | High-entropy strings in key contexts + AWS AKIA keys |
| **Crypto Wallets** | Bitcoin and Ethereum addresses |
| **Private Keys** | PEM private key block detection |
| **Keyword Hits** | Lines matching configurable sensitive keywords with line numbers |

---

## Installation

```bash
git clone https://github.com/B0bTheSkull/darkdump_crawl.git
cd darkdump_crawl
pip install -r requirements.txt
```

---

## Usage

```bash
# Analyze a single paste URL
python main.py --url https://pastebin.com/raw/XXXXXXXX

# Save with JSON output
python main.py --url https://pastebin.com/raw/XXXXXXXX --output results/ --json

# Batch process a list of URLs
python main.py --file urls.txt --output results/

# Analyze a local text file (no HTTP)
python main.py --text dump.txt

# Pipe text via stdin
cat leak.txt | python main.py --stdin

# Add custom keywords to flag
python main.py --text dump.txt --keyword "stripe" --keyword "twilio"

# Quiet mode (no banner, just results)
python main.py --url https://pastebin.com/raw/XXXXXXXX --quiet --json
```

---

## Example Output

```
╔══════════════════════════════════════════╗
║      darkdump_crawl v2.0               ║
║  Paste & Leak Intelligence Extractor   ║
╚══════════════════════════════════════════╝

[*] Output directory: output/20241015_143201
[*] Fetching: https://pastebin.com/raw/XXXXXXXX

───────────────────────────────────────────────────────
Source: https://pastebin.com/raw/XXXXXXXX
  [!] Credentials:      47
  [!] API keys:         2
  [*] Crypto BTC/ETH:   3/1
  [*] Emails:           89
  [*] IPs:              12
  [*] Keyword hits:     34
      URLs:             23
      Phones:           4

[✓] Done. Results in: output/20241015_143201
```

---

## Output Structure

```
output/
└── 20241015_143201/
    ├── pastebin_com_raw_XXXXXX_emails.txt
    ├── pastebin_com_raw_XXXXXX_credentials.txt
    ├── pastebin_com_raw_XXXXXX_api_keys.txt
    ├── pastebin_com_raw_XXXXXX_ips.txt
    ├── pastebin_com_raw_XXXXXX_urls.txt
    ├── pastebin_com_raw_XXXXXX_keyword_hits.txt
    ├── pastebin_com_raw_XXXXXX_crypto_bitcoin.txt
    └── pastebin_com_raw_XXXXXX_results.json   ← with --json
```

Each run gets a timestamped directory so results never overwrite each other.

---

## URL File Format

```
# urls.txt
https://pastebin.com/raw/AAAA
https://pastebin.com/raw/BBBB
# lines starting with # are skipped
```

---

## What's New in v2.0

- **Proper CLI** — no more hardcoded URLs or `input()` prompts
- **Batch processing** via `--file urls.txt`
- **stdin support** — pipe raw text directly
- **Local file analysis** — no HTTP required
- **Retry + rate limit handling** — exponential backoff on 429s
- **User-agent rotation** to reduce blocking
- **API key detection** — context-aware + Shannon entropy filtering
- **Crypto wallet extraction** — Bitcoin + Ethereum addresses
- **Private key detection** — flags PEM blocks immediately (CRITICAL alert)
- **Keyword context** — shows line number and snippet for every hit
- **JSON output** alongside categorized text files
- **Timestamped output directories** — runs never overwrite each other
- **Deduplication** by default

---

## Roadmap

- [ ] Tor/SOCKS proxy support
- [ ] HIBP k-anonymity hash lookup for found credentials
- [ ] YAML config file
- [ ] MISP export format

---

## License

MIT
