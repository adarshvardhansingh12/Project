# Subdomain Takeover Scanner

A Python tool that discovers subdomains and checks them for takeover vulnerabilities against AWS S3, GitHub Pages, and Azure.

> For authorized use only. Always obtain written permission before scanning.

---

## How It Works

1. **Passive recon** — Queries crt.sh (Certificate Transparency logs) for known subdomains
2. **Active brute-force** — Resolves subdomains from a wordlist via multi-threaded DNS
3. **CNAME matching** — Checks CNAME records against known vulnerable cloud service patterns
4. **HTTP fingerprinting** — Fetches each subdomain and looks for "unclaimed" error pages
5. **Reporting** — Outputs terminal table, HTML dashboard, and PDF report

---

## Setup

```bash
cd subdomain-takeover-scanner
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Usage

```bash
# Basic scan (passive + brute-force)
python3 main.py -d example.com

# Passive only (no brute-force)
python3 main.py -d example.com --no-bruteforce

# Custom wordlist + output name
python3 main.py -d example.com -w wordlists/subdomains.txt -o results/example_scan

# More threads for faster scanning
python3 main.py -d example.com -t 50
```

---

## Output

Each run produces:
- **Terminal** — color-coded findings table with severity and confidence
- **HTML report** — executive summary cards + full findings + all subdomains table
- **PDF report** — professional pentest-style report with remediation steps

---

## Supported Takeover Services

| Service | Severity | Detection Method |
|---|---|---|
| AWS S3 | Critical | CNAME + `NoSuchBucket` response |
| GitHub Pages | High | CNAME + `There isn't a GitHub Pages site here` |
| Azure | Critical | CNAME + `404 Web Site not found` |

---

## Resume Line

> *"Built a subdomain takeover scanner that combines passive CT log enumeration (crt.sh) with active DNS brute-forcing and HTTP fingerprinting to detect unclaimed AWS S3, GitHub Pages, and Azure resources. Generates PDF/HTML pentest reports with remediation guidance."*

---

## Roadmap

- [x] crt.sh passive enumeration
- [x] Multi-threaded DNS brute-force
- [x] AWS S3 / GitHub Pages / Azure detection
- [x] HTML + PDF + terminal reports
- [ ] Heroku / Netlify / Fastly fingerprints
- [ ] Slack/email alerting
- [ ] CI/CD integration mode
