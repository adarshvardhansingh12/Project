from datetime import datetime

SEVERITY_COLOR = {
    "critical": "#c0392b",
    "high": "#e74c3c",
    "medium": "#e67e22",
    "low": "#2980b9",
    "info": "#7f8c8d",
}


class HTMLReporter:
    def __init__(self, domain: str, subdomains: list[dict], findings: list[dict], output_path: str):
        self.domain = domain
        self.subdomains = subdomains
        self.findings = findings
        self.output_path = output_path

    def _badge(self, sev: str) -> str:
        color = SEVERITY_COLOR.get(sev, "#999")
        return f'<span style="background:{color};color:#fff;padding:3px 12px;border-radius:12px;font-size:12px;font-weight:bold;">{sev.upper()}</span>'

    def _summary_cards(self) -> str:
        counts = {}
        for f in self.findings:
            sev = f.get("severity", "info")
            counts[sev] = counts.get(sev, 0) + 1

        cards = f"""
        <div style="background:#2ecc71;color:#fff;border-radius:10px;padding:18px 28px;text-align:center;min-width:110px;">
          <div style="font-size:28px;font-weight:bold;">{len(self.subdomains)}</div>
          <div style="font-size:13px;margin-top:4px;">SUBDOMAINS</div>
        </div>
        <div style="background:#e74c3c;color:#fff;border-radius:10px;padding:18px 28px;text-align:center;min-width:110px;">
          <div style="font-size:28px;font-weight:bold;">{len(self.findings)}</div>
          <div style="font-size:13px;margin-top:4px;">VULNERABLE</div>
        </div>"""

        for sev in ["critical", "high", "medium", "low"]:
            count = counts.get(sev, 0)
            color = SEVERITY_COLOR.get(sev, "#999")
            cards += f"""
        <div style="background:{color};color:#fff;border-radius:10px;padding:18px 28px;text-align:center;min-width:110px;">
          <div style="font-size:28px;font-weight:bold;">{count}</div>
          <div style="font-size:13px;margin-top:4px;">{sev.upper()}</div>
        </div>"""
        return f'<div style="display:flex;gap:16px;flex-wrap:wrap;margin:20px 0;">{cards}</div>'

    def _finding_rows(self) -> str:
        if not self.findings:
            return '<tr><td colspan="6" style="text-align:center;color:#aaa;padding:24px;">No vulnerable subdomains found.</td></tr>'
        rows = ""
        for i, f in enumerate(self.findings, 1):
            sev = f.get("severity", "info")
            confidence = f.get("confidence", "unknown")
            conf_color = "#27ae60" if confidence == "high" else "#e67e22"
            rows += f"""
            <tr>
              <td style="color:#888;font-size:13px;">{i}</td>
              <td><code style="font-size:13px;font-weight:bold;">{f.get('subdomain','')}</code></td>
              <td>{self._badge(sev)}</td>
              <td>{f.get('service','')}</td>
              <td><span style="color:{conf_color};font-weight:bold;font-size:12px;">{confidence.upper()}</span></td>
              <td style="font-size:12px;">{f.get('status_code','')}</td>
            </tr>
            <tr style="background:#fafafa;">
              <td colspan="6" style="padding:10px 16px 16px;font-size:12px;color:#444;">
                <strong>CNAME:</strong> <code>{f.get('cname') or 'N/A'}</code><br>
                <strong>Description:</strong> {f.get('description','')}<br>
                <strong>Remediation:</strong> {f.get('remediation','')}<br>
                <strong>References:</strong> <a href="{f.get('references','#')}" target="_blank">{f.get('references','')}</a>
              </td>
            </tr>"""
        return rows

    def _subdomain_rows(self) -> str:
        rows = ""
        vuln_subs = {f["subdomain"] for f in self.findings}
        for s in self.subdomains:
            sub = s["subdomain"]
            is_vuln = sub in vuln_subs
            badge = '<span style="background:#e74c3c;color:#fff;padding:2px 8px;border-radius:8px;font-size:11px;">VULNERABLE</span>' if is_vuln else '<span style="background:#27ae60;color:#fff;padding:2px 8px;border-radius:8px;font-size:11px;">CLEAN</span>'
            rows += f"""
            <tr>
              <td><code style="font-size:12px;">{sub}</code></td>
              <td style="font-size:12px;color:#555;">{s.get('cname') or '—'}</td>
              <td style="font-size:12px;color:#555;">{', '.join(s.get('a_records', [])) or '—'}</td>
              <td style="font-size:12px;color:#777;">{s.get('source','')}</td>
              <td>{badge}</td>
            </tr>"""
        return rows

    def generate(self):
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Subdomain Takeover Report – {self.domain}</title>
<style>
  * {{ box-sizing:border-box;margin:0;padding:0; }}
  body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f0f2f5;color:#222; }}
  header {{ background:#1a1a2e;color:#fff;padding:28px 40px; }}
  header h1 {{ font-size:22px;font-weight:600; }}
  header p {{ font-size:13px;color:#aaa;margin-top:6px; }}
  main {{ max-width:1100px;margin:32px auto;padding:0 24px; }}
  .card {{ background:#fff;border-radius:12px;padding:28px;margin-bottom:24px;box-shadow:0 1px 4px rgba(0,0,0,.07); }}
  h2 {{ font-size:16px;font-weight:600;margin-bottom:16px;color:#1a1a2e;border-left:4px solid #e74c3c;padding-left:10px; }}
  table {{ width:100%;border-collapse:collapse;font-size:14px; }}
  th {{ background:#1a1a2e;color:#fff;padding:10px 14px;text-align:left;font-weight:500;font-size:13px; }}
  td {{ padding:10px 14px;border-bottom:1px solid #eee;vertical-align:top; }}
  tr:hover > td {{ background:#f7f9fc; }}
  footer {{ text-align:center;font-size:12px;color:#aaa;padding:24px; }}
  a {{ color:#2980b9; }}
</style>
</head>
<body>
<header>
  <h1>Subdomain Takeover Scanner Report</h1>
  <p>Target: {self.domain} &nbsp;|&nbsp; Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp; Subdomains: {len(self.subdomains)} &nbsp;|&nbsp; Vulnerable: {len(self.findings)}</p>
</header>
<main>
  <div class="card">
    <h2>Executive Summary</h2>
    {self._summary_cards()}
  </div>

  <div class="card">
    <h2>Vulnerable Subdomains</h2>
    <table>
      <thead>
        <tr><th>#</th><th>Subdomain</th><th>Severity</th><th>Service</th><th>Confidence</th><th>HTTP Status</th></tr>
      </thead>
      <tbody>{self._finding_rows()}</tbody>
    </table>
  </div>

  <div class="card">
    <h2>All Discovered Subdomains ({len(self.subdomains)})</h2>
    <table>
      <thead>
        <tr><th>Subdomain</th><th>CNAME</th><th>A Records</th><th>Source</th><th>Status</th></tr>
      </thead>
      <tbody>{self._subdomain_rows()}</tbody>
    </table>
  </div>
</main>
<footer>Generated by Subdomain Takeover Scanner — For authorized use only.</footer>
</body>
</html>"""
        with open(self.output_path, "w") as f:
            f.write(html)
