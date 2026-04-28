import dns.resolver
import requests
import httpx
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

console = Console()


class SubdomainEnumerator:
    """
    Enumerates subdomains for a target domain using:
    - Wordlist brute-forcing via DNS resolution
    - Certificate Transparency logs (crt.sh) for passive recon
    """

    def __init__(self, domain: str, wordlist: str, threads: int = 20, timeout: int = 3):
        self.domain = domain.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0]
        self.wordlist = wordlist
        self.threads = threads
        self.timeout = timeout
        self.found = []

    def _load_wordlist(self) -> list[str]:
        try:
            with open(self.wordlist) as f:
                return [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            console.print(f"[red]  Wordlist not found: {self.wordlist}[/red]")
            return []

    def _resolve(self, subdomain: str) -> dict | None:
        fqdn = f"{subdomain}.{self.domain}"
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = self.timeout

            # Try CNAME first
            try:
                cname_answer = resolver.resolve(fqdn, "CNAME")
                cname_target = str(cname_answer[0].target).rstrip(".")
                a_records = []
                try:
                    a_answer = resolver.resolve(fqdn, "A")
                    a_records = [str(r) for r in a_answer]
                except Exception:
                    pass
                return {
                    "subdomain": fqdn,
                    "cname": cname_target,
                    "a_records": a_records,
                    "source": "wordlist",
                }
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass

            # Try A record only
            a_answer = resolver.resolve(fqdn, "A")
            return {
                "subdomain": fqdn,
                "cname": None,
                "a_records": [str(r) for r in a_answer],
                "source": "wordlist",
            }

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.Timeout, dns.exception.DNSException):
            return None

    def _fetch_crtsh(self) -> list[dict]:
        console.print(f"  [dim]Fetching subdomains from crt.sh for {self.domain}...[/dim]")
        found = []
        try:
            resp = requests.get(
                f"https://crt.sh/?q=%.{self.domain}&output=json",
                timeout=10
            )
            if resp.status_code == 200:
                entries = resp.json()
                seen = set()
                for entry in entries:
                    name = entry.get("name_value", "").strip().lower()
                    for sub in name.splitlines():
                        sub = sub.strip().lstrip("*.")
                        if sub.endswith(self.domain) and sub not in seen:
                            seen.add(sub)
                            found.append({
                                "subdomain": sub,
                                "cname": None,
                                "a_records": [],
                                "source": "crt.sh",
                            })
                console.print(f"  [dim]crt.sh returned {len(found)} unique subdomains.[/dim]")
        except Exception as e:
            console.print(f"  [yellow]  crt.sh lookup failed: {e}[/yellow]")
        return found

    def _resolve_passive(self, entry: dict) -> dict | None:
        fqdn = entry["subdomain"]
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = self.timeout
            try:
                cname_answer = resolver.resolve(fqdn, "CNAME")
                entry["cname"] = str(cname_answer[0].target).rstrip(".")
            except Exception:
                pass
            try:
                a_answer = resolver.resolve(fqdn, "A")
                entry["a_records"] = [str(r) for r in a_answer]
            except Exception:
                pass
            if entry["cname"] or entry["a_records"]:
                return entry
        except Exception:
            pass
        return None

    def enumerate(self) -> list[dict]:
        all_subdomains = []
        seen = set()

        # --- Passive: crt.sh ---
        passive = self._fetch_crtsh()
        console.print(f"  [dim]Resolving {len(passive)} passive subdomains...[/dim]")
        with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(),
                      TextColumn("{task.percentage:>3.0f}%"), console=console, transient=True) as progress:
            task = progress.add_task("  Resolving crt.sh subdomains...", total=len(passive))
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(self._resolve_passive, e): e for e in passive}
                for future in as_completed(futures):
                    progress.advance(task)
                    result = future.result()
                    if result and result["subdomain"] not in seen:
                        seen.add(result["subdomain"])
                        all_subdomains.append(result)
                        console.print(f"  [green]LIVE[/green] {result['subdomain']}")

        # --- Active: Wordlist brute-force ---
        words = self._load_wordlist()
        if words:
            console.print(f"\n  [dim]Brute-forcing {len(words)} subdomains...[/dim]")
            with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(),
                          TextColumn("{task.percentage:>3.0f}%"), console=console, transient=True) as progress:
                task = progress.add_task("  Brute-forcing DNS...", total=len(words))
                with ThreadPoolExecutor(max_workers=self.threads) as executor:
                    futures = {executor.submit(self._resolve, word): word for word in words}
                    for future in as_completed(futures):
                        progress.advance(task)
                        result = future.result()
                        if result and result["subdomain"] not in seen:
                            seen.add(result["subdomain"])
                            all_subdomains.append(result)
                            console.print(f"  [green]FOUND[/green] {result['subdomain']} -> {result['cname'] or result['a_records']}")

        console.print(f"\n  [bold]Enumeration complete.[/bold] {len(all_subdomains)} live subdomains found.")
        self.found = all_subdomains
        return all_subdomains
