#!/usr/bin/env python3

import argparse
import sys
from datetime import datetime
from rich.console import Console
from rich.panel import Panel

from scanner.enumerator import SubdomainEnumerator
from scanner.detector import TakeoverDetector
from reports.terminal_report import TerminalReporter
from reports.html_report import HTMLReporter
from reports.pdf_report import PDFReporter

console = Console()

BANNER = """
 ███████╗██╗   ██╗██████╗ ██████╗  ██████╗ ███╗   ███╗ █████╗ ██╗███╗   ██╗
 ██╔════╝██║   ██║██╔══██╗██╔══██╗██╔═══██╗████╗ ████║██╔══██╗██║████╗  ██║
 ███████╗██║   ██║██████╔╝██║  ██║██║   ██║██╔████╔██║███████║██║██╔██╗ ██║
 ╚════██║██║   ██║██╔══██╗██║  ██║██║   ██║██║╚██╔╝██║██╔══██║██║██║╚██╗██║
 ███████║╚██████╔╝██████╔╝██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║██║ ╚████║
 ╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝
  Takeover Scanner — AWS S3 | GitHub Pages | Azure
  For authorized security testing only.
  Made By Adarshvardhan Singh & Lincy Pandit
"""


def parse_args():
    parser = argparse.ArgumentParser(
        description="Subdomain Takeover Scanner",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g. example.com)")
    parser.add_argument("-w", "--wordlist", default="wordlists/subdomains.txt",
                        help="Wordlist for brute-force (default: wordlists/subdomains.txt)")
    parser.add_argument("-o", "--output", default="takeover_report",
                        help="Output file base name (default: takeover_report)")
    parser.add_argument("-t", "--threads", type=int, default=20,
                        help="Threads for DNS resolution (default: 20)")
    parser.add_argument("--timeout", type=int, default=4,
                        help="DNS/HTTP timeout in seconds (default: 4)")
    parser.add_argument("--no-pdf",  action="store_true", help="Skip PDF report")
    parser.add_argument("--no-html", action="store_true", help="Skip HTML report")
    parser.add_argument("--no-bruteforce", action="store_true",
                        help="Only use passive (crt.sh) enumeration, skip wordlist")
    return parser.parse_args()


def main():
    args = parse_args()
    console.print(BANNER, style="bold red")
    console.print(Panel(
        f"[bold]Target domain:[/bold] {args.domain}\n"
        f"[bold]Wordlist:[/bold] {'disabled' if args.no_bruteforce else args.wordlist}\n"
        f"[bold]Threads:[/bold] {args.threads}\n"
        f"[bold]Started:[/bold] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        title="Scan Configuration", border_style="red"
    ))

    # --- Step 1: Enumerate subdomains ---
    console.rule("[bold red]Step 1 — Subdomain Enumeration[/bold red]")
    enumerator = SubdomainEnumerator(
        domain=args.domain,
        wordlist=args.wordlist if not args.no_bruteforce else "__disabled__",
        threads=args.threads,
        timeout=args.timeout,
    )
    subdomains = enumerator.enumerate()

    if not subdomains:
        console.print("[yellow]No live subdomains found. Exiting.[/yellow]")
        sys.exit(0)

    # --- Step 2: Detect takeover vulnerabilities ---
    console.rule("[bold red]Step 2 — Takeover Detection[/bold red]")
    detector = TakeoverDetector(
        subdomains=subdomains,
        threads=args.threads,
        timeout=args.timeout + 2,
    )
    findings = detector.detect()

    # --- Step 3: Reports ---
    console.rule("[bold red]Step 3 — Generating Reports[/bold red]")

    TerminalReporter(domain=args.domain, subdomains=subdomains, findings=findings).print()

    if not args.no_html:
        html_path = f"{args.output}.html"
        HTMLReporter(domain=args.domain, subdomains=subdomains,
                     findings=findings, output_path=html_path).generate()
        console.print(f"[green]  HTML report:[/green] {html_path}")

    if not args.no_pdf:
        pdf_path = f"{args.output}.pdf"
        PDFReporter(domain=args.domain, subdomains=subdomains,
                    findings=findings, output_path=pdf_path).generate()
        console.print(f"[green]  PDF report:[/green] {pdf_path}")

    console.print(Panel(
        f"[bold green]Scan complete.[/bold green]\n"
        f"Subdomains found: {len(subdomains)}\n"
        f"Vulnerable: [bold red]{len(findings)}[/bold red]\n"
        f"Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        border_style="green"
    ))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold red]Scan interrupted.[/bold red]")
        sys.exit(0)
