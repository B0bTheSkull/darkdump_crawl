"""Write extraction results to organized output files."""
import json
import re
from datetime import datetime
from pathlib import Path

RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
BOLD = "\033[1m"
WHITE = "\033[37m"


def _safe_filename(s):
    s = re.sub(r'https?://', '', s)
    s = re.sub(r'[^\w\-.]', '_', s)
    return s[:40]


def write_results(results, out_dir, source_label):
    """Write each result category to its own .txt file."""
    out_dir = Path(out_dir)
    prefix = _safe_filename(source_label)

    mappings = {
        "emails": "emails.txt",
        "ips": "ips.txt",
        "urls": "urls.txt",
        "phone_numbers": "phones.txt",
        "credentials": "credentials.txt",
        "bitcoin_wallets": "crypto_bitcoin.txt",
        "ethereum_wallets": "crypto_ethereum.txt",
    }

    for key, filename in mappings.items():
        items = results.get(key, [])
        if items:
            filepath = out_dir / f"{prefix}_{filename}"
            with open(filepath, "w") as f:
                for item in items:
                    f.write(f"{item}\n")

    api_keys = results.get("api_keys", [])
    if api_keys:
        filepath = out_dir / f"{prefix}_api_keys.txt"
        with open(filepath, "w") as f:
            for entry in api_keys:
                f.write(f"[{entry.get('type','?')}] {entry.get('value','')}\n")

    keyword_hits = results.get("keyword_hits", [])
    if keyword_hits:
        filepath = out_dir / f"{prefix}_keyword_hits.txt"
        with open(filepath, "w") as f:
            for hit in keyword_hits:
                f.write(f"[line {hit['line_number']}] [{hit['keyword']}] {hit['context']}\n")

    if results.get("private_keys_found"):
        filepath = out_dir / f"{prefix}_PRIVATE_KEY_FOUND.txt"
        filepath.write_text(
            f"ALERT: PEM private key block detected in: {source_label}\n"
            f"Timestamp: {datetime.now().isoformat()}\n"
        )


def write_json(results, out_dir, source_label):
    """Write full results as JSON."""
    out_dir = Path(out_dir)
    prefix = _safe_filename(source_label)
    filepath = out_dir / f"{prefix}_results.json"
    payload = {
        "source": source_label,
        "extracted_at": datetime.now().isoformat(),
        "results": results
    }
    with open(filepath, "w") as f:
        json.dump(payload, f, indent=2)


def print_summary(source_label, results):
    """Print a color-coded extraction summary."""
    counts = {
        "emails": len(results.get("emails", [])),
        "ips": len(results.get("ips", [])),
        "credentials": len(results.get("credentials", [])),
        "api_keys": len(results.get("api_keys", [])),
        "urls": len(results.get("urls", [])),
        "phones": len(results.get("phone_numbers", [])),
        "btc": len(results.get("bitcoin_wallets", [])),
        "eth": len(results.get("ethereum_wallets", [])),
        "keyword_hits": len(results.get("keyword_hits", [])),
    }
    has_privkey = results.get("private_keys_found", False)

    print(f"\n{'─'*55}")
    short = source_label if len(source_label) <= 50 else source_label[:47] + "..."
    print(f"{BOLD}Source:{RESET} {short}")

    if sum(counts.values()) == 0 and not has_privkey:
        print(f"  {WHITE}No findings.{RESET}")
        return

    if counts["credentials"]:
        print(f"  {RED}[!] Credentials:      {counts['credentials']}{RESET}")
    if has_privkey:
        print(f"  {RED}[!] PRIVATE KEY DETECTED!{RESET}")
    if counts["api_keys"]:
        print(f"  {RED}[!] API keys:         {counts['api_keys']}{RESET}")
    if counts["btc"] or counts["eth"]:
        print(f"  {YELLOW}[*] Crypto BTC/ETH:   {counts['btc']}/{counts['eth']}{RESET}")
    if counts["emails"]:
        print(f"  {CYAN}[*] Emails:           {counts['emails']}{RESET}")
    if counts["ips"]:
        print(f"  {CYAN}[*] IPs:              {counts['ips']}{RESET}")
    if counts["keyword_hits"]:
        print(f"  {YELLOW}[*] Keyword hits:     {counts['keyword_hits']}{RESET}")
    if counts["urls"]:
        print(f"      URLs:             {counts['urls']}")
    if counts["phones"]:
        print(f"      Phones:           {counts['phones']}")
