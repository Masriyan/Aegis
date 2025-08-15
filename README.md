# AEGIS — Automated Enrichment & Global Intelligence Scanner

**AEGIS** is a Windows-friendly, single-file web app for URL reconnaissance, OSINT enrichment, and light semi-offensive checks (opt-in). It’s built for blue/purple teams and learners who want actionable results in a clean UI with history, exports, and subdomain intelligence.

> **Legal & Ethical**  
> Use **only** on assets you own or have explicit permission to test. You are responsible for complying with laws and terms of service.

---

## ✨ Features

- **Passive & semi-offensive** modules (semi-offensive is opt-in)
- **Subdomain scanner**
  - Defensive: Certificate Transparency via **crt.sh** (passive)
  - Semi: adds **DNS brute-force** (limited, concurrent)
- **Presets** picker (Recon / Passive / Semi-offensive)
- **Results filter**, **Expand/Collapse all**
- **History** & **permalinks** (`/history`, `/view/<id>`)
- **Summary header** + **per-module timings**
- **Exports**: JSON, CSV, **Subdomains CSV**, PDF (optional via WeasyPrint)
- **Clean, human-readable** rendering for every implemented module
- **Windows-friendly**: SQLite DB path anchored to the script folder

---

## 🧰 Tech Stack

- Python 3.9+  
- Flask, Requests, BeautifulSoup4  
- dnspython, python-whois  
- python-dotenv (optional)  
- WeasyPrint (optional for PDF export)

---

## 📦 Installation

### 1) Clone & enter the project
```bash
git clone <your-repo-url> aegis
cd aegis
```

### 2) Create & activate a virtual environment
```bash
# Windows (PowerShell)
python -m venv .venv
.venv\Scripts\Activate.ps1

# macOS/Linux
python3 -m venv .venv
source .venv/bin/activate
```

### 3) Install dependencies
Create **requirements.txt** with:
```txt
Flask
requests
beautifulsoup4
dnspython
python-whois
python-dotenv
weasyprint  # optional; install only if you want PDF export
```

Then install:
```bash
pip install -r requirements.txt
```

> **WeasyPrint on Windows (optional)**  
> PDF export is optional. WeasyPrint may require additional system libraries. If it’s troublesome, skip it—the app runs fine without PDF export.

### 4) Configure environment variables (optional)
Create a **.env** in the project root if you have API keys:
```env
# Optional: used when you enable related modules
VT_API_KEY=your_virustotal_key
OTX_API_KEY=your_alienvault_otx_key
GITHUB_TOKEN=your_github_token
SHODAN_API_KEY=your_shodan_key
GREYNOISE_API_KEY=your_greynoise_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
```

---

## 🚀 Run

```bash
python aegis.py
```

By default it binds to:
```
http://127.0.0.1:8080
```

> Binding to localhost avoids Windows firewall prompts for public networks.

---

## 🖥️ Using the App

1. Open the app in your browser.  
2. Enter a **URL** to investigate.
3. Choose **Scan Mode**:
   - **Defensive**: passive modules only
   - **Semi-offensive**: enables light exposure checks and JS secret discovery (authorized use only)
4. (Optional) Select a **Preset**:
   - **Recon (Passive OSINT)** — safe, passive
   - **Passive (safe defaults)** — broader passive enrichment
   - **Semi-offensive (authorized)** — passive + light brute force/exposure checks
5. Pick modules and hit **Start Hunt**.

### UI Goodies
- **Summary tiles**: Subdomain count, missing security headers, VT malicious flags, total duration  
- **Per-module timings**: Toggle under “Module timings”  
- **Filter box**: Quick narrow down results  
- **Expand/Collapse all**: For details sections  
- **Permalinks**: Each run has `/view/<id>`  
- **History**: `/history` lists your last 100 scans

---

## 🔍 Modules

- **Crawler**: Shallow site crawl, emails, external links
- **HTTP Headers**: Raw headers
- **Tech Fingerprint**: Simple header/markup signatures (e.g., WordPress, React; server & X-Powered-By)
- **Security Headers**: Presence check for:
  - `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`,
  - `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`
- **TLS**: Cert subject/issuer validity
- **DNS Records**: A/AAAA/MX/NS/TXT/SOA via dnspython
- **WHOIS**: Domain WHOIS
- **Subdomain Scan**:
  - **crt.sh** CT lookup (passive)
  - **DNS brute-force** (semi) with a compact wordlist
  - Renders a table with source, A/AAAA, CNAME + **Export Subdomains CSV**
- **VirusTotal**: URL report (aggregated stats)
- **urlscan.io**: Recent scans for domain
- **OTX**: Domain pulses/validation info
- **GitHub code search**: Quick matches for the domain
- **Shodan**: Host summary by resolved IP
- **GreyNoise**: Community classification for IP
- **AbuseIPDB**: Abuse confidence & report stats
- **Semi-offensive extras (mode=semi)**:
  - **Exposure checks**: HEAD requests to `/.git/config`, `/.env`, `/server-status`, `/phpinfo.php`
  - **JS Secret scan**: Downloads external JS to check for naive secret patterns (e.g., AWS AKIA keys)

---

## 🗂️ Data & Storage

- **SQLite DB**: `threat_hunter.db` next to the script  
  - Table: `scans (id, url, results, scan_date)`  
  - Results are stored as JSON for repeat viewing & export
- **Exports**
  - **JSON**: `/export/json`
  - **CSV**: `/export/csv` (flattened rows)
  - **Subdomains CSV**: `/export/subdomains.csv`
  - **PDF**: `/export/pdf` (only if WeasyPrint installed)

---

## 🔧 Configuration Notes

- **User-Agent**: `Mozilla/5.0 (AegisSparks/6.0; +https://security-life.org)`  
  Edit `USER_AGENT` in code if you need a different identifier.
- **Timeouts**: `DEFAULT_TIMEOUT = 15` seconds; adjust if your network is slow.
- **DNS brute force**: small, safe list; see `_BRUTE_WORDS` in code to customize.
- **Threading**: DNS brute-force uses a small thread pool (`max_workers=20`) to stay polite.

---

## 🧪 API Keys (Optional)

Modules gracefully degrade without keys:

| Service       | Variable             | Used For                    |
|---------------|----------------------|-----------------------------|
| VirusTotal    | `VT_API_KEY`         | URL reputation/stats        |
| OTX           | `OTX_API_KEY`        | Pulses & domain intel       |
| GitHub        | `GITHUB_TOKEN`       | Raise rate limits           |
| Shodan        | `SHODAN_API_KEY`     | IP/port/host info           |
| GreyNoise     | `GREYNOISE_API_KEY`  | IP classification           |
| AbuseIPDB     | `ABUSEIPDB_API_KEY`  | Abuse confidence & reports  |

---

## 🧭 Routes

- `/` — New scan form  
- `/scan` — Form POST handler  
- `/history` — Recent scans (last 100)  
- `/view/<id>` — View a past scan  
- `/export/json` — Latest scan JSON  
- `/export/csv` — Latest scan CSV (flattened)  
- `/export/subdomains.csv` — Subdomains only  
- `/export/pdf` — Latest scan PDF (if WeasyPrint installed)

---

## 🛟 Troubleshooting

- **WeasyPrint / PDF export fails on Windows**  
  It’s optional. If installation is painful, skip it. The app works without PDF.
- **`whois` issues**  
  The pip package is **`python-whois`** but you import it as `whois`. Ensure the package installs successfully.
- **`crt.sh` slow or rate-limited**  
  It’s a public service; try again later or add caching.
- **API rate limits**  
  VT/OTX/GitHub/Shodan/GreyNoise/AbuseIPDB rate limits may apply. Add API keys and/or back off requests.
- **TLS errors**  
  Some hosts block or require SNI; TLS handshake may fail—module will show an error message in the UI.
- **Corporate proxies**  
  Configure system or `requests` proxies via env vars if required.

---

## 🧱 Security & Safety

- Semi-offensive mode performs:
  - HEAD requests to a few common exposure paths
  - Download of linked JS files for pattern matching
- These checks are restrained and **must be authorized**. Respect targets’ **robots.txt** and policies.

---

## 🧩 Development

- **Single file** by design—easy to tweak.
- Add a module:
  1. Write a function that returns a **dict/list** suited for rendering.
  2. Register it in the `run_scan()` section with a friendly key.
  3. Add a **human-readable** rendering block in `RESULTS_HTML`.
- **Wordlist** for brute force: edit `_BRUTE_WORDS`.
- **Styling**: Tailwind via CDN.
---

## 🗺️ Roadmap Ideas

- Additional passive sources (e.g., DNSDB, SecurityTrails if keys available)  
- CSP parser & misconfiguration hints  
- WAF/CDN inference  
- Advanced secret scanning & entropy checks (with allowlists)

---

## 🙌 Acknowledgements

- Community services: **crt.sh**, **urlscan.io**, **AlienVault OTX**, **VirusTotal**, **Shodan**, **GreyNoise**, **AbuseIPDB**  
- Libraries: Flask, Requests, BeautifulSoup, dnspython, python-whois

---

## 🏁 Quick Start (TL;DR)

```bash
python -m venv .venv
. .venv/Scripts/activate  # Windows
pip install Flask requests beautifulsoup4 dnspython python-whois python-dotenv
# (optional) pip install weasyprint

# Add .env with API keys if you have them

python aegis.py
# open http://127.0.0.1:8080
```

Happy hunting—stay ethical and precise.
