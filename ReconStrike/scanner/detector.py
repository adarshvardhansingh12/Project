import httpx
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from scanner.fingerprints import FINGERPRINTS

console = Console()

SEVERITY_COLOR = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


class TakeoverDetector:
    """
    Checks each live subdomain against known cloud service fingerprints.
    Detection strategy:
      1. Match CNAME against known vulnerable cloud CNAME patterns
      2. Fetch HTTP response and look for error page fingerprints
      3. Confirm takeover possibility
    """

    def __init__(self, subdomains: list[dict], threads: int = 10, timeout: int = 6):
        self.subdomains = subdomains
        self.threads = threads
        self.timeout = timeout
        self.findings = []

    def _match_cname(self, cname: str) -> dict | None:
        if not cname:
            return None
        cname_lower = cname.lower()
        for fp in FINGERPRINTS:
            for pattern in fp["cname_patterns"]:
                if pattern in cname_lower:
                    return fp
        return None

    def _fetch_http(self, subdomain: str) -> tuple[int, str]:
        for scheme in ["https", "http"]:
            try:
                resp = httpx.get(
                    f"{scheme}://{subdomain}",
                    timeout=self.timeout,
                    follow_redirects=True,
                    verify=False,
                )
                return resp.status_code, resp.text
            except Exception:
                continue
        return 0, ""

    def _check(self, entry: dict) -> dict | None:
        subdomain = entry["subdomain"]
        cname = entry.get("cname")

        matched_fp = self._match_cname(cname)

        status_code, body = self._fetch_http(subdomain)

        if matched_fp:
            # Check HTTP body for takeover fingerprints
            for fingerprint_str in matched_fp["http_fingerprints"]:
                if fingerprint_str.lower() in body.lower():
                    return {
                        "subdomain": subdomain,
                        "cname": cname,
                        "a_records": entry.get("a_records", []),
                        "service": matched_fp["service"],
                        "severity": matched_fp["severity"],
                        "status_code": status_code,
                        "matched_fingerprint": fingerprint_str,
                        "takeover_possible": matched_fp["takeover_possible"],
                        "description": matched_fp["description"],
                        "remediation": matched_fp["remediation"],
                        "references": matched_fp["references"],
                        "confidence": "high",
                    }

            # CNAME matched but no body fingerprint — lower confidence
            if status_code in [404, 0]:
                return {
                    "subdomain": subdomain,
                    "cname": cname,
                    "a_records": entry.get("a_records", []),
                    "service": matched_fp["service"],
                    "severity": "medium",
                    "status_code": status_code,
                    "matched_fingerprint": None,
                    "takeover_possible": False,
                    "description": f"CNAME points to {matched_fp['service']} but body fingerprint not confirmed. Manual verification needed.",
                    "remediation": matched_fp["remediation"],
                    "references": matched_fp["references"],
                    "confidence": "low",
                }

        return None

    def detect(self) -> list[dict]:
        if not self.subdomains:
            console.print("  [yellow]No subdomains to check.[/yellow]")
            return []

        console.print(f"  [dim]Checking {len(self.subdomains)} subdomains for takeover...[/dim]")
        findings = []

        with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(),
                      TextColumn("{task.percentage:>3.0f}%"), console=console, transient=True) as progress:
            task = progress.add_task("  Probing subdomains...", total=len(self.subdomains))
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(self._check, entry): entry for entry in self.subdomains}
                for future in as_completed(futures):
                    progress.advance(task)
                    result = future.result()
                    if result:
                        findings.append(result)
                        sev = result["severity"]
                        color = SEVERITY_COLOR.get(sev, "white")
                        confidence = result.get("confidence", "?")
                        console.print(
                            f"  [{color}]VULNERABLE[/{color}] {result['subdomain']} "
                            f"-> {result['service']} [{sev.upper()}] [confidence: {confidence}]"
                        )

        console.print(f"\n  [bold]Detection complete.[/bold] {len(findings)} vulnerable subdomains found.")
        self.findings = findings
        return findings
