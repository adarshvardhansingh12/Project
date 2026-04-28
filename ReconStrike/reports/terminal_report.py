from rich.console import Console

class TerminalReporter:
    def __init__(self, domain, subdomains, findings):
        self.console = Console()
        self.domain = domain
        self.subdomains = subdomains
        self.findings = findings

    def print(self):
        self.console.print(f"\n[bold cyan]Target:[/bold cyan] {self.domain}")
        self.console.print(f"[bold green]Subdomains Found:[/bold green] {len(self.subdomains)}")

        if self.findings:
            self.console.print(f"[bold red]Vulnerabilities Found:[/bold red] {len(self.findings)}")
            for f in self.findings:
                self.console.print(f"[red]- {f}[/red]")
        else:
            self.console.print("[green]No vulnerabilities found[/green]")
