#!/usr/bin/env python3
"""
darkdump_crawl — Paste & Leak Intelligence Extractor
Extract emails, credentials, IPs, crypto wallets, and sensitive keywords
from paste sites and raw text dumps.
"""

import argparse
import sys
from datetime import datetime
from pathlib import Path

from utils.fetcher import fetch_url, fetch_urls_from_file
from utils.parser import extract_all
from utils.writer import write_results, write_json, print_summary


def parse_args():
    parser = argparse.ArgumentParser(
        description="darkdump_crawl — extract IOCs and credentials from paste dumps",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --url https://pastebin.com/raw/XXXXXXXX
  python main.py --url https://pastebin.com/raw/XXXXXXXX --output results/ --json
  python main.py --file urls.txt --output results/
  python main.py --text dump.txt --keyword "aws" --keyword "stripe"
  cat dump.txt | python main.py --stdin

Output:
  Writes categorized .txt files to ./output/<timestamp>/
  Use --json for machine-readable JSON alongside text files.
        """
    )

    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--url", "-u", help="Single URL to fetch and parse")
    source.add_argument("--file", "-f", help="File containing one URL per line")
    source.add_argument("--stdin", action="store_true", help="Read raw text from stdin")
    source.add_argument("--text", "-t", help="Analyze a local text file directly (no HTTP)")

    parser.add_argument("--output", "-o", default="output",
                        help="Output directory (default: output/)")
    parser.add_argument("--json", "-j", dest="json_output", action="store_true",
                        help="Also write a JSON results file")
    parser.add_argument("--keyword", "-k", action="append", dest="keywords", default=[],
                        help="Extra keywords to search for (repeat: -k aws -k stripe)")
    parser.add_argument("--no-dedup", action="store_true",
                        help="Keep duplicate entries (default: deduplicate)")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Suppress banner and progress output")
    parser.add_argument("--timeout", type=int, default=15,
                        help="HTTP request timeout in seconds (default: 15)")

    return parser.parse_args()


def banner():
    print("""
\033[36m╔══════════════════════════════════════════╗
║      darkdump_crawl v2.0               ║
║  Paste & Leak Intelligence Extractor   ║
╚══════════════════════════════════════════╝\033[0m
""")


def process_text(text, source_label, args, run_dir):
    """Run extraction on a block of text and write results."""
    results = extract_all(text, extra_keywords=args.keywords)

    if not args.no_dedup:
        for key in results:
            if isinstance(results[key], list):
                results[key] = sorted(set(str(x) for x in results[key]))

    if not args.quiet:
        print_summary(source_label, results)

    write_results(results, run_dir, source_label)

    if args.json_output:
        write_json(results, run_dir, source_label)

    return results


def main():
    args = parse_args()

    if not args.quiet:
        banner()

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = Path(args.output) / ts
    run_dir.mkdir(parents=True, exist_ok=True)

    if not args.quiet:
        print(f"\033[36m[*]\033[0m Output directory: {run_dir}\n")

    if args.stdin:
        if not args.quiet:
            print("\033[36m[*]\033[0m Reading from stdin...")
        text = sys.stdin.read()
        process_text(text, "stdin", args, run_dir)

    elif args.text:
        p = Path(args.text)
        if not p.exists():
            print(f"\033[91m[!]\033[0m File not found: {args.text}")
            sys.exit(1)
        if not args.quiet:
            print(f"\033[36m[*]\033[0m Analyzing: {p.name}")
        text = p.read_text(errors="replace")
        process_text(text, p.name, args, run_dir)

    elif args.url:
        if not args.quiet:
            print(f"\033[36m[*]\033[0m Fetching: {args.url}")
        text = fetch_url(args.url, timeout=args.timeout)
        if text is None:
            print(f"\033[91m[!]\033[0m Failed to fetch {args.url}")
            sys.exit(1)
        process_text(text, args.url, args, run_dir)

    elif args.file:
        urls = fetch_urls_from_file(args.file)
        if not urls:
            print(f"\033[91m[!]\033[0m No URLs found in {args.file}")
            sys.exit(1)
        if not args.quiet:
            print(f"\033[36m[*]\033[0m Processing {len(urls)} URLs...\n")
        for i, url in enumerate(urls, 1):
            if not args.quiet:
                print(f"\033[36m[{i}/{len(urls)}]\033[0m {url}")
            text = fetch_url(url, timeout=args.timeout)
            if text is None:
                print(f"  \033[91m[!]\033[0m Failed to fetch, skipping.")
                continue
            process_text(text, url, args, run_dir)

    if not args.quiet:
        print(f"\n\033[32m[✓]\033[0m Done. Results in: {run_dir}")


if __name__ == "__main__":
    main()
