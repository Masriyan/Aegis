#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Threat Hunter Swiss Army Knife — Pro Windows Build (2025-08)

Features
- Passive & semi-offensive modules (opt-in)
- Subdomain scanner:
    * Defensive: CT logs via crt.sh (passive)
    * Semi: adds DNS brute-force (limited, concurrent)
- Presets picker (Recon / Passive / Semi-offensive)
- Results filter + expand/collapse all
- History & permalinks (/history, /view/<id>)
- Summary header + per-module timings
- Per-module export: Subdomains CSV
- Human-readable rendering for all modules
- Export CSV/JSON; PDF via WeasyPrint if installed (optional)
- Windows-friendly: DB path anchored to script folder

IMPORTANT: For educational and authorized testing only.
"""

import asyncio
import base64
import csv
import io
import json
import os
import re
import socket
import ssl
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from flask import Flask, render_template_string, request, Response, g, make_response

# Optional .env support
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Optional PDF support (WeasyPrint is tricky on Windows; optional)
try:
    from weasyprint import HTML
except ImportError:
    HTML = None

import dns.resolver
import whois

# ---------------- Config ----------------
HERE = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(HERE, 'aegis.db')  # Windows-safe path
DEFAULT_TIMEOUT = 15
USER_AGENT = "Mozilla/5.0 (AegisSparks/6.0; +https://security-life.org)"
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": USER_AGENT})

# API keys (optional)
VT_API_KEY = os.getenv("VT_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
SECURITYTRAILS_API_KEY = os.getenv("SECURITYTRAILS_API_KEY", "")
HIBP_API_KEY = os.getenv("HIBP_API_KEY", "")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
SCREENSHOT_TIMEOUT = int(os.getenv("SCREENSHOT_TIMEOUT", "20"))
ALERT_THRESHOLD = int(os.getenv("ALERT_THRESHOLD", "60"))
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
MALWARE_SANDBOX_URL = os.getenv("MALWARE_SANDBOX_URL", "")
MALWARE_SANDBOX_KEY = os.getenv("MALWARE_SANDBOX_KEY", "")
TICKET_WEBHOOK_URL = os.getenv("TICKET_WEBHOOK_URL", "")
AUTO_TICKET_THRESHOLD = int(os.getenv("AUTO_TICKET_THRESHOLD", "70"))
WORKFLOW_MAX_STEPS = int(os.getenv("WORKFLOW_MAX_STEPS", "15"))

try:
    from pyppeteer import launch
except ImportError:
    launch = None

try:
    import boto3
except ImportError:
    boto3 = None

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None

# ---------------- Flask & DB ----------------
app = Flask(__name__)
app.config.from_object(__name__)
app.config["_processing_schedule"] = False

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

def init_db():
    schema = """
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL,
        results TEXT NOT NULL,
        scan_date TIMESTAMP NOT NULL
    );
    CREATE TABLE IF NOT EXISTS scheduled_scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL,
        services TEXT NOT NULL,
        mode TEXT NOT NULL,
        extras TEXT,
        interval_minutes INTEGER NOT NULL,
        next_run TEXT NOT NULL,
        last_run TEXT,
        last_results TEXT
    );
    """
    db = get_db()
    db.cursor().executescript(schema)
    db.commit()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# ---------------- HTML ----------------
INDEX_HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>AEGIS — Automated Enrichment & Global Intelligence Scanner</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css" rel="stylesheet">
  <style>
    #loadingOverlay { display:none; position:fixed; inset:0; background:rgba(0,0,0,0.9); z-index:9999; }
    .spinner { border:4px solid rgba(255,255,255,0.3); border-radius:50%; border-top:4px solid #3498db; width:40px; height:40px; animation:spin 1s linear infinite; }
    @keyframes spin { 0% {transform:rotate(0deg);} 100% {transform:rotate(360deg);} }
  </style>
</head>
<body class="bg-gray-900 text-gray-200 font-sans">
  <div id="loadingOverlay" class="flex items-center justify-center">
    <div class="text-center">
      <div class="spinner mx-auto"></div>
      <div class="text-white text-lg font-semibold mt-4">Hunting for Threats...</div>
      <div class="text-gray-400 text-sm">Analyzing and enriching data</div>
    </div>
  </div>

  <div class="container mx-auto p-4 md:p-8">
    <div class="flex items-center justify-between mb-6">
      <div>
        <h1 class="text-4xl md:text-5xl font-bold text-blue-400">AEGIS by sudo3rs</h1>
        <p class="text-gray-400 mt-2">Automated Enrichment & Global Intelligence Scanner. Windows-friendly.</p>
      </div>
      <div class="flex items-center gap-2">
        <a href="/history" class="bg-gray-800 hover:bg-gray-700 px-3 py-2 rounded">History</a>
        <a href="/scheduled" class="bg-gray-800 hover:bg-gray-700 px-3 py-2 rounded">Scheduled</a>
        <button id="themeToggle" class="bg-gray-800 hover:bg-gray-700 px-3 py-2 rounded">Toggle theme</button>
      </div>
    </div>

    <form id="scanForm" action="/scan" method="post" class="bg-gray-800 border border-gray-700 rounded-lg p-6 shadow-lg">
      <div class="grid md:grid-cols-3 gap-6">
        <div class="md:col-span-2">
          <label class="block text-sm font-medium mb-2 text-blue-300">URL to Investigate</label>
          <input type="url" name="url" placeholder="https://example.com" required
                 class="w-full rounded-md bg-gray-700 border border-gray-600 px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-500" />
        </div>
        <div>
          <label class="block text-sm font-medium mb-2 text-blue-300">Scan Mode</label>
          <select name="mode" class="w-full rounded-md bg-gray-700 border border-gray-600 px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-500">
            <option value="defensive" selected>Defensive</option>
            <option value="semi">Semi-offensive</option>
          </select>
        </div>
      </div>

      <div class="mt-4 flex items-center gap-3">
        <label class="text-sm font-medium text-blue-300">Presets</label>
        <select id="presetSelect" class="rounded-md bg-gray-700 border border-gray-600 px-3 py-2 text-sm">
          <option value="">-- Choose preset --</option>
          <option value="recon">Recon (Passive OSINT)</option>
          <option value="passive">Passive (safe defaults)</option>
          <option value="semi">Semi-offensive (authorized)</option>
        </select>
      </div>

      <div class="mt-6">
        <h3 class="text-sm font-medium text-blue-300 mb-3">Select Modules to Run</h3>
        <div class="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-4">
          {% for label, val in [
            ('Crawler', 'crawler'), ('Tech Fingerprint', 'tech'), ('Security Headers', 'sec_headers'),
            ('TLS Certificate', 'tls'), ('HTTP Headers', 'headers'), ('DNS Records', 'dns'),
            ('WHOIS Lookup', 'whois'), ('Subdomain Scan', 'subdomains'), ('security.txt', 'security_txt'),
            ('Robots.txt', 'robots_txt'), ('Passive DNS (SecurityTrails)', 'securitytrails'),
            ('Signature Scan', 'signatures'), ('CVE Alerts', 'cve_alerts'), ('Cloud Assets', 'cloud_assets'),
            ('VirusTotal', 'virustotal'), ('urlscan.io', 'urlscan'), ('AlienVault OTX', 'otx'),
            ('Archive.org', 'archive'), ('GitHub Code', 'github'), ('Code Scan (GitHub)', 'code_scan'),
            ('Shodan', 'shodan'), ('GreyNoise', 'greynoise'), ('AbuseIPDB', 'abuseipdb'),
            ('Screenshot Capture', 'screenshot'), ('Param Fuzzer', 'fuzzer'),
            ('Workflow Runner', 'workflow'), ('Sandbox Submission', 'sandbox'),
            ('HIBP Exposure Watch', 'hibp'), ('Sensitive Path Probe', 'exposure_checks'),
            ('OWASP Top 10', 'owasp_top10')
          ] %}
          <label class="flex items-center gap-2 bg-gray-700 border border-gray-600 rounded-md px-3 py-2 cursor-pointer hover:bg-gray-600">
            <input type="checkbox" name="services" value="{{ val }}" class="h-4 w-4 text-blue-500 bg-gray-600 border-gray-500 rounded focus:ring-blue-500">
            <span class="text-sm">{{ label }}</span>
          </label>
          {% endfor %}
        </div>
      </div>

      <div class="mt-6 grid md:grid-cols-2 gap-6">
        <div>
          <label class="block text-sm font-medium mb-2 text-blue-300">Custom Subdomain Words</label>
          <textarea name="extra_subdomains" rows="4" placeholder="admin\nportal\nblue-team"
                    class="w-full rounded-md bg-gray-700 border border-gray-600 px-3 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-blue-500"></textarea>
          <p class="text-xs text-gray-400 mt-1">One per line (commas OK). Added to bruteforce list when applicable.</p>
        </div>
        <div>
          <label class="block text-sm font-medium mb-2 text-blue-300">Custom Exposure Paths</label>
          <textarea name="extra_exposures" rows="4" placeholder="/backup.tgz\nhigh::/admin/.env"
                    class="w-full rounded-md bg-gray-700 border border-gray-600 px-3 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-blue-500"></textarea>
          <p class="text-xs text-gray-400 mt-1">Prefix with <code>high::</code>, <code>medium::</code>, or <code>low::</code> to set severity.</p>
        </div>
      </div>

      <div class="mt-6">
        <label class="block text-sm font-medium mb-2 text-blue-300">Workflow JSON (optional)</label>
        <textarea name="workflow_steps" rows="4" placeholder='[{"action":"click","selector":"#login"}]'
                  class="w-full rounded-md bg-gray-700 border border-gray-600 px-3 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-blue-500"></textarea>
        <p class="text-xs text-gray-400 mt-1">Provide Playwright-style steps when enabling the Workflow Runner.</p>
      </div>

      <div class="mt-8 flex items-center justify-between">
        <div>
          <span class="text-sm font-medium text-blue-300">Output Format:</span>
          <label class="inline-flex items-center gap-1 ml-2">
            <input type="radio" name="view_mode" value="human" checked class="h-4 w-4 text-blue-500">
            <span class="text-sm">Human-readable</span>
          </label>
          <label class="inline-flex items-center gap-1 ml-4">
            <input type="radio" name="view_mode" value="json" class="h-4 w-4 text-blue-500">
            <span class="text-sm">JSON</span>
          </label>
        </div>
        <button type="submit" class="bg-blue-600 hover:bg-blue-500 text-white font-bold px-6 py-2 rounded-full transition duration-300">
          <i class="fas fa-search mr-2"></i>Start Hunt
        </button>
      </div>

      <div class="mt-6">
        <label class="block text-sm font-medium mb-2 text-blue-300">Schedule (minutes)</label>
        <input type="number" name="schedule_minutes" min="0" placeholder="0"
               class="w-40 rounded-md bg-gray-700 border border-gray-600 px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-500" />
        <p class="text-xs text-gray-400 mt-1">Enter minutes (>0) to queue recurring scans. They run sequentially when the app is active.</p>
      </div>
    </form>
  </div>

  <script>
    const form = document.getElementById('scanForm');
    const overlay = document.getElementById('loadingOverlay');
    form.addEventListener('submit', function() { overlay.style.display = 'flex'; });

    // Presets
    const presets = {
      recon:   ["crawler","tech","headers","sec_headers","dns","whois","archive","urlscan","github","code_scan","security_txt","robots_txt","securitytrails","signatures","cve_alerts","owasp_top10"],
      passive: ["crawler","tech","headers","sec_headers","tls","dns","whois","subdomains","security_txt","robots_txt","securitytrails","signatures","cve_alerts","virustotal","urlscan","otx","hibp","shodan","greynoise","abuseipdb","cloud_assets","owasp_top10"],
      semi:    ["crawler","tech","headers","sec_headers","tls","dns","whois","subdomains","security_txt","robots_txt","securitytrails","signatures","cve_alerts","screenshot","virustotal","urlscan","otx","code_scan","hibp","shodan","greynoise","abuseipdb","exposure_checks","fuzzer","workflow","sandbox","owasp_top10"]
    };
    document.getElementById('presetSelect').addEventListener('change', (e) => {
      const vals = presets[e.target.value] || [];
      document.querySelectorAll('input[name="services"]').forEach(cb => cb.checked = false);
      vals.forEach(v => {
        const cb = document.querySelector(`input[name="services"][value="${v}"]`);
        if (cb) cb.checked = true;
      });
      if (e.target.value === 'semi') {
        document.querySelector('select[name="mode"]').value = 'semi';
      }
    });

    // Theme toggle (simple invert trick)
    const toggle = document.getElementById('themeToggle');
    if (toggle) {
      toggle.addEventListener('click', () => {
        document.documentElement.classList.toggle('invert');
        document.body.classList.toggle('bg-white');
        document.body.classList.toggle('text-gray-900');
      });
    }
  </script>
</body>
</html>
"""

RESULTS_HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Threat Hunt Results</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css" rel="stylesheet">
  <style>
    .result-card { background-color: #1f2937; border: 1px solid #374151; border-radius: 0.5rem; padding: 1.5rem; margin-bottom: 1.5rem; }
    .result-title { color: #60a5fa; font-size: 1.5rem; font-weight: bold; margin-bottom: 1rem; }
    .badge { display: inline-block; padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; }
    .ok { background-color: #10b981; color:white; }
    .warn { background-color: #f59e0b; color:white; }
    .bad { background-color: #ef4444; color:white; }
    .badge.sev-high { background-color: #dc2626; color:white; }
    .badge.sev-medium { background-color: #f97316; color:white; }
    .badge.sev-low { background-color: #0ea5e9; color:white; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 8px 12px; border: 1px solid #374151; text-align: left; }
    th { background-color: #374151; }
    details summary { cursor: pointer; }
  </style>
</head>
<body class="bg-gray-900 text-gray-200 font-sans">
  <div class="container mx-auto p-4 md:p-8">
    <div class="text-center mb-8">
      <h1 class="text-3xl md:text-4xl font-bold text-blue-400">Threat Hunt Results</h1>
      <p class="text-gray-400 mt-2">Analysis for: <a href="{{ url }}" class="text-blue-500 hover:underline" target="_blank">{{ url }}</a></p>
    </div>

    {% if results.get('_summary') %}
    <div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
      <div class="bg-gray-800 border border-gray-700 rounded p-3">
        <div class="text-sm text-gray-400">Subdomains</div>
        <div class="text-2xl font-bold">{{ results['_summary']['subdomains'] }}</div>
      </div>
      <div class="bg-gray-800 border border-gray-700 rounded p-3">
        <div class="text-sm text-gray-400">Missing Sec Headers</div>
        <div class="text-2xl font-bold">{{ results['_summary']['missing_sec_headers'] }}</div>
      </div>
      <div class="bg-gray-800 border border-gray-700 rounded p-3">
        <div class="text-sm text-gray-400">VT Malicious</div>
        <div class="text-2xl font-bold">{{ results['_summary']['vt_malicious'] }}</div>
      </div>
      <div class="bg-gray-800 border border-gray-700 rounded p-3">
        <div class="text-sm text-gray-400">Risk Score</div>
        <div class="text-2xl font-bold">{{ results['_summary']['risk_score'] }} <span class="text-sm uppercase ml-1">{{ results['_summary']['risk_level'] }}</span></div>
      </div>
      <div class="bg-gray-800 border border-gray-700 rounded p-3">
        <div class="text-sm text-gray-400">Duration (s)</div>
        <div class="text-2xl font-bold">{{ results.get('_meta', {}).get('total_seconds', '-') }}</div>
      </div>
    </div>
    {% endif %}

    {% if scan_id %}
    <div class="mb-6">
      <a href="/graph/{{ scan_id }}" class="bg-gray-800 hover:bg-gray-700 px-4 py-2 rounded text-sm">View Relationship Graph</a>
    </div>
    {% endif %}

    {% if results.get('_meta', {}).get('module_times') %}
    <details class="mb-6">
      <summary class="cursor-pointer text-blue-400">Module timings</summary>
      <table class="mt-3 w-full border border-gray-700">
        <thead class="bg-gray-800"><tr><th class="p-2 text-left">Module</th><th class="p-2 text-left">Seconds</th></tr></thead>
        <tbody>
          {% for m, secs in results['_meta']['module_times'].items() %}
          <tr class="border-t border-gray-700"><td class="p-2">{{ m }}</td><td class="p-2">{{ secs }}</td></tr>
          {% endfor %}
        </tbody>
      </table>
    </details>
    {% endif %}

    <div class="flex items-center justify-between mb-6">
      <div>
        <button id="btnHuman" class="px-4 py-2 text-sm font-semibold rounded-l-lg {% if view_mode == 'human' %}bg-blue-600{% else %}bg-gray-700{% endif %}">Human-readable</button>
        <button id="btnJSON" class="px-4 py-2 text-sm font-semibold rounded-r-lg {% if view_mode == 'json' %}bg-blue-600{% else %}bg-gray-700{% endif %}">JSON</button>
      </div>
      <div class="flex items-center space-x-2">
        {% if scan_id %}
          <a href="/view/{{ scan_id }}" class="bg-gray-700 hover:bg-gray-600 px-4 py-2 rounded-full text-sm font-semibold"><i class="fas fa-link mr-1"></i>Permalink</a>
        {% endif %}
        <a href="/export/json" class="bg-gray-700 hover:bg-gray-600 px-4 py-2 rounded-full text-sm font-semibold"><i class="fas fa-file-code mr-1"></i>Export JSON</a>
        <a href="/export/csv" class="bg-gray-700 hover:bg-gray-600 px-4 py-2 rounded-full text-sm font-semibold"><i class="fas fa-file-csv mr-1"></i>Export CSV</a>
        {% if pdf_available %}
        <a href="/export/pdf" class="bg-red-600 hover:bg-red-500 px-4 py-2 rounded-full text-sm font-semibold"><i class="fas fa-file-pdf mr-1"></i>Export PDF</a>
        {% endif %}
      </div>
    </div>

    <div class="flex items-center gap-3 mb-4">
      <input id="resultFilter" type="text" placeholder="Filter results (module name or text)…"
             class="w-full md:w-1/2 rounded-md bg-gray-800 border border-gray-700 px-3 py-2 text-sm">
      <button id="btnExpandAll" class="bg-gray-700 hover:bg-gray-600 px-3 py-2 rounded text-sm">Expand all</button>
      <button id="btnCollapseAll" class="bg-gray-700 hover:bg-gray-600 px-3 py-2 rounded text-sm">Collapse all</button>
    </div>

    <!-- Human View -->
    <div id="humanView" class="{% if view_mode != 'human' %}hidden{% endif %} space-y-6">
      {% for key, value in results.items() if value and not key.startswith('_') %}
      <div class="result-card">
        <h2 class="result-title">{{ key.replace('_', ' ')|title }}</h2>

        {% if value is mapping and value.get('error') %}
          <p class="text-red-400">Error: {{ value.error }}</p>

        {% elif key == 'crawler' %}
          <table>
            <tr><th>Type</th><th>Count</th><th>Details</th></tr>
            <tr><td>Pages Found</td><td>{{ value.urls|length }}</td>
              <td><details><summary class="text-blue-400">View</summary>
                <ul class="list-disc pl-5 mt-2">{% for u in value.urls %}<li><a href="{{ u }}" target="_blank" class="hover:underline">{{ u }}</a></li>{% endfor %}</ul>
              </details></td></tr>
            <tr><td>External Links</td><td>{{ value.external_links|length }}</td>
              <td><details><summary class="text-blue-400">View</summary>
                <ul class="list-disc pl-5 mt-2">{% for l in value.external_links %}<li><a href="{{ l }}" target="_blank" class="hover:underline">{{ l }}</a></li>{% endfor %}</ul>
              </details></td></tr>
            <tr><td>Emails Found</td><td>{{ value.emails|length }}</td>
              <td><details><summary class="text-blue-400">View</summary>
                <ul class="list-disc pl-5 mt-2">{% for e in value.emails %}<li>{{ e }}</li>{% endfor %}</ul>
              </details></td></tr>
          </table>

        {% elif key == 'http_headers' %}
          <table><thead><tr><th>Header</th><th>Value</th></tr></thead>
          <tbody>{% for k,v in value.items() %}<tr><td>{{ k }}</td><td>{{ v }}</td></tr>{% endfor %}</tbody></table>

        {% elif key == 'tech' and value.get('stack') %}
          <table><thead><tr><th>Technology</th></tr></thead>
          <tbody>{% for t in value.stack %}<tr><td>{{ t }}</td></tr>{% endfor %}</tbody></table>

        {% elif key == 'sec_headers' and value.get('rows') %}
          <table><thead><tr><th>Header</th><th>Status</th><th>Message</th></tr></thead>
          <tbody>{% for row in value.rows %}<tr><td>{{ row.header }}</td>
          <td><span class="badge {{ 'ok' if row.status == 'OK' else 'warn' if row.status == 'WARN' else 'bad' }}">{{ row.status }}</span></td>
          <td>{{ row.message }}</td></tr>{% endfor %}</tbody></table>

        {% elif key == 'tls' and value.get('subject') %}
          <table>
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>Subject</td><td>{{ value.subject.get('commonName', 'N/A') }}</td></tr>
            <tr><td>Issuer</td><td>{{ value.issuer.get('commonName', 'N/A') }}</td></tr>
            <tr><td>Valid From</td><td>{{ value.not_before }}</td></tr>
            <tr><td>Valid Until</td><td>{{ value.not_after }}</td></tr>
          </table>

        {% elif key == 'dns_records' %}
          <table><thead><tr><th>Type</th><th>Value</th></tr></thead>
          <tbody>
            {% for rtype, rvals in value.items() %}
              {% for rv in rvals %}<tr><td>{{ rtype }}</td><td><code>{{ rv }}</code></td></tr>{% endfor %}
            {% endfor %}
          </tbody></table>

        {% elif key == 'whois_lookup' %}
          <table><thead><tr><th>Property</th><th>Value</th></tr></thead>
          <tbody>
            {% for k, v in value.items() if k != 'error' and v %}
              <tr><td>{{ k|replace('_',' ')|title }}</td><td>{{ v }}</td></tr>
            {% endfor %}
          </tbody></table>

        {% elif key == 'subdomain_scan' and value.get('rows') %}
          <div class="mb-2">
            <a href="/export/subdomains.csv" class="bg-gray-700 hover:bg-gray-600 px-3 py-1 rounded text-sm">Export Subdomains CSV</a>
          </div>
          <table>
            <thead><tr><th>Subdomain</th><th>Source</th><th>A/AAAA</th><th>CNAME</th></tr></thead>
            <tbody>
              {% for r in value.rows[:500] %}
                <tr>
                  <td>{{ r.subdomain }}</td>
                  <td>{{ r.source }}</td>
                  <td>{{ (r.a_records or [])|join(', ') }}</td>
                  <td>{{ r.cname or '' }}</td>
                </tr>
              {% endfor %}
            </tbody>
          </table>

        {% elif key == 'subdomain_scan' and value.get('found') %}
          <div class="mb-2">
            <a href="/export/subdomains.csv" class="bg-gray-700 hover:bg-gray-600 px-3 py-1 rounded text-sm">Export Subdomains CSV</a>
          </div>
          <table><thead><tr><th>Found Subdomain</th></tr></thead>
          <tbody>{% for s in value.found %}<tr><td>{{ s }}</td></tr>{% endfor %}</tbody></table>

        {% elif key == 'securitytrails' %}
          <div class="grid md:grid-cols-2 gap-4">
            <div>
              <h3 class="text-sm font-semibold text-blue-300 mb-2">Current DNS</h3>
              {% set current = value.get('current') %}
              {% if current and not current.get('error') %}
                <pre class="bg-gray-800 border border-gray-700 rounded p-3 text-xs whitespace-pre-wrap">{{ current | tojson(indent=2) }}</pre>
              {% else %}
                <p class="text-sm text-gray-400">{{ current.get('error', 'No data') }}</p>
              {% endif %}
            </div>
            <div>
              <h3 class="text-sm font-semibold text-blue-300 mb-2">Passive DNS</h3>
              {% set history = value.get('history') %}
              {% if history and history is sequence %}
                <table>
                  <thead><tr><th>Hostname</th><th>IP</th><th>First Seen</th><th>Last Seen</th></tr></thead>
                  <tbody>
                    {% for rec in history[:10] %}
                      <tr>
                        <td>{{ rec.get('hostname', 'N/A') }}</td>
                        <td>{{ rec.get('value', 'N/A') }}</td>
                        <td>{{ rec.get('first_seen', '-') }}</td>
                        <td>{{ rec.get('last_seen', '-') }}</td>
                      </tr>
                    {% endfor %}
                  </tbody>
                </table>
              {% elif history and history.get('error') %}
                <p class="text-sm text-gray-400">{{ history.get('error') }}</p>
              {% else %}
                <p class="text-sm text-gray-400">No passive records returned.</p>
              {% endif %}
            </div>
          </div>

        {% elif key == 'security_txt' %}
          {% if value.get('found') and value.get('files') %}
            {% for file in value.files %}
              <p class="text-sm text-gray-400 mb-2">Discovered at <a href="{{ file.url }}" target="_blank" class="text-blue-400 hover:underline">{{ file.url }}</a> (HTTP {{ file.status }}){% if file.last_modified %} · updated {{ file.last_modified }}{% endif %}</p>
              <table>
                <thead><tr><th>Field</th><th>Value</th></tr></thead>
                <tbody>
                  {% for entry in file.entries %}
                    <tr><td>{{ entry.field }}</td><td>{{ entry.value }}</td></tr>
                  {% endfor %}
                </tbody>
              </table>
            {% endfor %}
          {% else %}
            <p class="text-gray-400 text-sm">{{ value.get('message', 'security.txt not discovered') }}</p>
          {% endif %}
          {% if value.get('errors') %}
            <details class="mt-3 text-sm text-gray-400">
              <summary class="cursor-pointer text-blue-400">Fetch errors</summary>
              <ul class="list-disc pl-5 mt-2 space-y-1">
                {% for err in value.errors %}
                  <li>{{ err.path }} → {{ err.error }}</li>
                {% endfor %}
              </ul>
            </details>
          {% endif %}

        {% elif key == 'robots_txt' %}
          <p class="text-sm text-gray-400 mb-2">Fetched from <a href="{{ value.get('url') }}" target="_blank" class="text-blue-400 hover:underline">{{ value.get('url') }}</a> (HTTP {{ value.get('status', '-') }}){% if value.get('last_modified') %} · updated {{ value.get('last_modified') }}{% endif %}</p>
          {% if value.get('rules') %}
            <table>
              <thead><tr><th>Directive</th><th>Path</th></tr></thead>
              <tbody>
                {% for rule in value.rules[:200] %}
                  <tr><td>{{ rule.directive }}</td><td><code>{{ rule.path }}</code></td></tr>
                {% endfor %}
              </tbody>
            </table>
          {% else %}
            <p class="text-gray-400 text-sm">No Allow/Disallow directives parsed.</p>
          {% endif %}
          {% if value.get('suspicious') %}
            <div class="mt-4">
              <h3 class="text-sm font-semibold text-red-300 mb-2">Potentially sensitive entries</h3>
              <table>
                <thead><tr><th>Directive</th><th>Path</th><th>Keyword</th></tr></thead>
                <tbody>
                  {% for rule in value.suspicious %}
                    <tr>
                      <td>{{ rule.directive }}</td>
                      <td>{{ rule.path }}</td>
                      <td><span class="badge bad">{{ rule.keyword }}</span></td>
                    </tr>
                  {% endfor %}
                </tbody>
              </table>
            </div>
          {% endif %}

        {% elif key == 'signature_hits' %}
          {% if value.get('rows') %}
            <table>
              <thead><tr><th>Signature</th><th>Severity</th></tr></thead>
              <tbody>
                {% for hit in value.rows %}
                  <tr>
                    <td>{{ hit.name }}</td>
                    <td><span class="badge {% if hit.severity == 'high' %}bad{% elif hit.severity == 'medium' %}warn{% else %}ok{% endif %}">{{ hit.severity|capitalize }}</span></td>
                  </tr>
                {% endfor %}
              </tbody>
            </table>
          {% else %}
            <p class="text-sm text-gray-400">No signatures matched.</p>
          {% endif %}

        {% elif key == 'cve_alerts' %}
          {% if value.get('rows') %}
            <table>
              <thead><tr><th>Tech</th><th>CVE</th><th>CVSS</th><th>Summary</th></tr></thead>
              <tbody>
                {% for alert in value.rows %}
                  <tr>
                    <td>{{ alert.tech }}</td>
                    <td>{{ alert.id }}</td>
                    <td>{{ alert.cvss or '-' }}</td>
                    <td>{{ alert.summary }}</td>
                  </tr>
                {% endfor %}
              </tbody>
            </table>
          {% else %}
            <p class="text-sm text-gray-400">No recent CVEs found for detected tech stack.</p>
          {% endif %}

        {% elif key == 'cloud_assets' %}
          {% if value.get('error') %}
            <p class="text-red-400 text-sm">{{ value.error }}</p>
          {% else %}
            <div>
              <h3 class="text-sm font-semibold mb-2">S3 Buckets</h3>
              {% if value.get('s3') %}
                <ul class="list-disc pl-5 text-sm space-y-1">
                  {% for bucket in value.s3 %}
                    <li>{{ bucket.name }} <span class="text-xs text-gray-400">{{ bucket.created }}</span></li>
                  {% endfor %}
                </ul>
              {% else %}
                <p class="text-sm text-gray-400">{{ value.get('message', 'No buckets matched domain keyword.') }}</p>
              {% endif %}
            </div>
          {% endif %}

        {% elif key == 'code_scan' %}
          {% if value.get('rows') %}
            <table>
              <thead><tr><th>Repository</th><th>File</th><th>Findings</th></tr></thead>
              <tbody>
                {% for row in value.rows %}
                  <tr>
                    <td>{{ row.repo }}</td>
                    <td><a href="{{ row.file }}" target="_blank" class="text-blue-400 hover:underline">View file</a></td>
                    <td>{{ row.findings|join(', ') }}</td>
                  </tr>
                {% endfor %}
              </tbody>
            </table>
          {% else %}
            <p class="text-sm text-gray-400">{{ value.get('message', 'No risky patterns detected in sampled files.') }}</p>
          {% endif %}

        {% elif key == 'fuzzer' %}
          {% if value.get('baseline') %}
            <p class="text-xs text-gray-400 mb-2">Baseline: status {{ value.baseline.status or 'N/A' }}, length {{ value.baseline.length or '-' }} bytes</p>
          {% endif %}
          <table>
            <thead><tr><th>Payload</th><th>Method</th><th>Status</th><th>Length</th><th>Severity</th><th>Redirected</th><th>Details</th></tr></thead>
            <tbody>
              {% for row in value.get('rows', []) %}
                <tr>
                  <td>{{ row.name }}</td>
                  <td>{{ row.method }}</td>
                  <td>{{ row.status or row.error }}</td>
                  <td>{{ row.length or '-' }}</td>
                  <td>
                    <span class="badge {% if row.severity == 'high' %}sev-high{% elif row.severity == 'medium' %}sev-medium{% else %}sev-low{% endif %}">
                      {{ row.severity|capitalize }}
                    </span>
                  </td>
                  <td>{{ row.redirected }}</td>
                  <td class="text-xs text-gray-400">
                    {% if row.description %}<div>{{ row.description }}</div>{% endif %}
                    {% if row.params %}<div>Params: {{ row.params }}</div>{% endif %}
                    {% if row.notes %}<div>Notes: {{ row.notes|join('; ') }}</div>{% endif %}
                    {% if row.error %}<div class="text-red-400">Error: {{ row.error }}</div>{% endif %}
                  </td>
                </tr>
              {% endfor %}
            </tbody>
          </table>

        {% elif key == 'workflow' %}
          {% if value.get('error') %}
            <p class="text-red-400 text-sm">{{ value.error }}</p>
          {% else %}
            <div class="space-y-2">
              <h3 class="text-sm font-semibold text-blue-300">Logs</h3>
              <ul class="list-disc pl-5 text-sm text-gray-300">
                {% for log in value.get('logs', []) %}
                  <li>{{ log }}</li>
                {% endfor %}
              </ul>
              {% if value.get('snapshot') %}
                <details>
                  <summary class="text-blue-400 cursor-pointer">HTML Snapshot</summary>
                  <pre class="bg-gray-800 border border-gray-700 rounded p-3 text-xs overflow-x-auto">{{ value.snapshot[:5000] }}{% if value.snapshot|length > 5000 %}...{% endif %}</pre>
                </details>
              {% endif %}
            </div>
          {% endif %}

        {% elif key == 'sandbox_report' %}
          {% if value.get('error') %}
            <p class="text-red-400 text-sm">{{ value.error }}</p>
          {% else %}
            <pre class="bg-gray-800 border border-gray-700 rounded p-3 text-xs whitespace-pre-wrap">{{ value | tojson(indent=2) }}</pre>
          {% endif %}

        {% elif key == 'owasp_top10' %}
          <table>
            <thead><tr><th>Category</th><th>Status</th><th>Evidence</th></tr></thead>
            <tbody>
              {% for row in value.get('rows', []) %}
                <tr>
                  <td>{{ row.category }}</td>
                  <td>
                    {% set badge_class = 'ok' %}
                    {% if row.status == 'fail' %}
                      {% set badge_class = 'bad' %}
                    {% elif row.status == 'warn' %}
                      {% set badge_class = 'warn' %}
                    {% elif row.status == 'unknown' %}
                      {% set badge_class = 'warn' %}
                    {% endif %}
                    <span class="badge {{ badge_class }}">
                      {{ row.status|upper }}
                    </span>
                  </td>
                  <td>{{ row.evidence }}</td>
                </tr>
              {% endfor %}
            </tbody>
          </table>

        {% elif key == 'virustotal' and value.get('data', {}).get('attributes') %}
          {% set stats = value.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}) %}
          <table>
            <tr><th>Malicious</th><th>Suspicious</th><th>Harmless</th></tr>
            <tr><td><span class="badge bad">{{ stats.get('malicious', 0) }}</span></td>
                <td><span class="badge warn">{{ stats.get('suspicious', 0) }}</span></td>
                <td><span class="badge ok">{{ stats.get('harmless', 0) }}</span></td></tr>
          </table>

        {% elif key == 'urlscan' and value.get('results') %}
          <table><thead><tr><th>Domain</th><th>Scan Time</th><th>Link</th></tr></thead>
          <tbody>
            {% for r in value.results[:5] %}
              <tr>
                <td>{{ r.get('task', {}).get('domain', 'N/A') }}</td>
                <td>{{ r.get('task', {}).get('time', '') | replace('T',' ') | replace('Z','') }}</td>
                <td><a href="{{ r.get('result', '#') }}" target="_blank" class="text-blue-400 hover:underline">View Scan</a></td>
              </tr>
            {% endfor %}
          </tbody></table>

        {% elif key == 'otx' and value.get('general') %}
          <table>
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>Pulse Count</td><td>{{ value.get('general', {}).get('pulse_info', {}).get('count', 'N/A') }}</td></tr>
            {% set validation_list = value.get('validation', []) %}
            {% set validation_msg = 'N/A' %}
            {% if validation_list and validation_list[0] is mapping %}
              {% set validation_msg = validation_list[0].get('message', 'N/A') %}
            {% endif %}
            <tr><td>Validation</td><td>{{ validation_msg }}</td></tr>
          </table>

        {% elif key == 'github' and value.get('items') %}
          <table><thead><tr><th>Repository</th><th>Path</th><th>Link</th></tr></thead>
          <tbody>
            {% for item in value.get('items', [])[:5] %}
              <tr>
                <td>{{ item.get('repository', {}).get('full_name', 'N/A') }}</td>
                <td>{{ item.get('path', 'N/A') }}</td>
                <td><a href="{{ item.get('html_url', '#') }}" target="_blank" class="text-blue-400 hover:underline">View Code</a></td>
              </tr>
            {% endfor %}
          </tbody></table>

        {% elif key == 'archive_org' and value is sequence and value|length > 1 %}
          <table><thead><tr><th>Timestamp</th><th>Original URL</th><th>MIME</th><th>Status</th><th>Link</th></tr></thead>
          <tbody>
            {% for row in value[1:11] %}
              <tr>
                <td>{{ row[1] }}</td>
                <td>{{ row[2] }}</td>
                <td>{{ row[3] }}</td>
                <td>{{ row[4] }}</td>
                <td><a target="_blank" class="text-blue-400 hover:underline" href="https://web.archive.org/web/{{ row[1] }}/{{ row[2] }}">Open</a></td>
              </tr>
            {% endfor %}
          </tbody></table>

        {% elif key == 'shodan' and value.get('data') %}
          <table><thead><tr><th>IP</th><th>Org</th><th>Open Ports</th><th>Hostnames</th><th>Tags</th></tr></thead>
          <tbody>
            <tr>
              <td>{{ value.get('ip_str', 'N/A') }}</td>
              <td>{{ value.get('org', 'N/A') }}</td>
              <td>{{ value.get('ports', [])|join(', ') }}</td>
              <td>{{ value.get('hostnames', [])|join(', ') }}</td>
              <td>{{ value.get('tags', [])|join(', ') }}</td>
            </tr>
          </tbody></table>

        {% elif key == 'greynoise' and (value.get('ip') or value.get('classification')) %}
          <table>
            <tr><th>IP</th><td>{{ value.get('ip', 'N/A') }}</td></tr>
            <tr><th>Classification</th><td>{{ value.get('classification', 'unknown') }}</td></tr>
            <tr><th>Name</th><td>{{ value.get('name', 'N/A') }}</td></tr>
            <tr><th>Last Seen</th><td>{{ value.get('last_seen', 'N/A') }}</td></tr>
          </table>

        {% elif key == 'abuseipdb' and value.get('data') %}
          {% set d = value.get('data', {}) %}
          <table>
            <tr><th>IP</th><td>{{ d.get('ipAddress', 'N/A') }}</td></tr>
            <tr><th>Total Reports</th><td>{{ d.get('totalReports', 0) }}</td></tr>
            <tr><th>Abuse Confidence</th><td>{{ d.get('abuseConfidenceScore', 0) }}%</td></tr>
            <tr><th>Last Reported</th><td>{{ d.get('lastReportedAt', 'N/A') }}</td></tr>
            <tr><th>Country</th><td>{{ d.get('countryCode', 'N/A') }}</td></tr>
            <tr><th>Usage Type</th><td>{{ d.get('usageType', 'N/A') }}</td></tr>
            <tr><th>ISP</th><td>{{ d.get('isp', 'N/A') }}</td></tr>
          </table>

        {% elif key == 'screenshot' %}
          {% if value.get('data_uri') %}
            <img src="{{ value.data_uri }}" alt="Screenshot" class="w-full border border-gray-700 rounded-lg" />
          {% else %}
            <p class="text-sm text-gray-400">{{ value.get('error', 'Screenshot capture unavailable.') }}</p>
          {% endif %}

        {% elif key == 'exposure_checks' and value.get('rows') %}
          <table>
            <thead><tr><th>Path</th><th>Severity</th><th>Status</th><th>Length</th><th>Details</th></tr></thead>
            <tbody>
              {% for row in value.rows %}
                <tr>
                  <td><a href="{{ row.url }}" target="_blank" class="text-blue-400 hover:underline">{{ row.path }}</a></td>
                  <td>
                    <span class="badge {% if row.severity == 'high' %}sev-high{% elif row.severity == 'medium' %}sev-medium{% else %}sev-low{% endif %}">
                      {{ row.severity|capitalize }}
                    </span>
                  </td>
                  <td>{{ row.status }}</td>
                  <td>{{ row.length or '-' }}</td>
                  <td>
                    <div>{{ row.description }}</div>
                    {% if row.content_type %}<div class="text-xs text-gray-400">Type: {{ row.content_type }}</div>{% endif %}
                    {% if row.error %}<div class="text-xs text-red-400">Error: {{ row.error }}</div>{% endif %}
                  </td>
                </tr>
              {% endfor %}
            </tbody>
          </table>

        {% elif key == 'hibp' and value.get('rows') %}
          <table>
            <thead><tr><th>Email</th><th>Status</th><th>Breaches</th></tr></thead>
            <tbody>
              {% for row in value.rows %}
                <tr>
                  <td>{{ row.email }}</td>
                  <td>
                    {% if row.error %}
                      <span class="badge bad">Error</span>
                    {% elif row.breached %}
                      <span class="badge bad">Breached</span>
                    {% else %}
                      <span class="badge ok">Clear</span>
                    {% endif %}
                  </td>
                  <td>
                    {% if row.error %}
                      <span class="text-red-400 text-sm">{{ row.error }}</span>
                    {% elif row.breaches %}
                      {{ row.breaches|join(', ') }}
                    {% else %}
                      <span class="text-gray-400 text-sm">No hits</span>
                    {% endif %}
                  </td>
                </tr>
              {% endfor %}
            </tbody>
          </table>

        {% else %}
          <p class="text-gray-400 text-sm">No structured data available.</p>
        {% endif %}
      </div>
      {% endfor %}
    </div>

    <!-- JSON View -->
    <div id="jsonView" class="{% if view_mode != 'json' %}hidden{% endif %}">
      <pre class="bg-gray-800 border border-gray-700 rounded-lg p-4 overflow-x-auto text-sm whitespace-pre-wrap">{{ results | tojson(indent=2) }}</pre>
    </div>

    <div class="text-center mt-8 flex items-center justify-center gap-4">
      <a href="/export/report" class="inline-block bg-gray-700 hover:bg-gray-600 px-6 py-3 rounded-full font-bold text-white"><i class="fas fa-file-alt mr-2"></i>Export Report</a>
      <a href="/" class="inline-block bg-blue-600 hover:bg-blue-500 px-6 py-3 rounded-full font-bold text-white"><i class="fas fa-arrow-left mr-2"></i>New Hunt</a>
    </div>
  </div>

  <script>
    const humanBtn = document.getElementById('btnHuman');
    const jsonBtn = document.getElementById('btnJSON');
    const humanView = document.getElementById('humanView');
    const jsonView = document.getElementById('jsonView');
    humanBtn.addEventListener('click', () => {
      humanView.classList.remove('hidden');
      jsonView.classList.add('hidden');
      humanBtn.classList.add('bg-blue-600','text-white');
      jsonBtn.classList.remove('bg-blue-600','text-white');
    });
    jsonBtn.addEventListener('click', () => {
      jsonView.classList.remove('hidden');
      humanView.classList.add('hidden');
      jsonBtn.classList.add('bg-blue-600','text-white');
      humanBtn.classList.remove('bg-blue-600','text-white');
    });

    // Filter + expand/collapse
    const filterInput = document.getElementById('resultFilter');
    const cards = () => Array.from(document.querySelectorAll('.result-card'));
    if (filterInput) {
      filterInput.addEventListener('input', () => {
        const q = filterInput.value.toLowerCase();
        cards().forEach(c => {
          const text = c.innerText.toLowerCase();
          c.style.display = text.includes(q) ? '' : 'none';
        });
      });
    }
    const btnExpandAll = document.getElementById('btnExpandAll');
    const btnCollapseAll = document.getElementById('btnCollapseAll');
    if (btnExpandAll) btnExpandAll.addEventListener('click', () => document.querySelectorAll('details').forEach(d => d.open = true));
    if (btnCollapseAll) btnCollapseAll.addEventListener('click', () => document.querySelectorAll('details').forEach(d => d.open = false));
  </script>
</body>
</html>
"""

HISTORY_HTML = r"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Scan History</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-gray-200 font-sans">
  <div class="container mx-auto p-6">
    <div class="flex items-center justify-between mb-6">
      <h1 class="text-3xl font-bold text-blue-400">Scan History</h1>
      <a href="/" class="bg-blue-600 hover:bg-blue-500 px-4 py-2 rounded text-white">New Scan</a>
    </div>
    <input id="histFilter" placeholder="Filter…" class="w-full md:w-1/2 mb-4 rounded-md bg-gray-800 border border-gray-700 px-3 py-2 text-sm">
    <table class="w-full border border-gray-700">
      <thead class="bg-gray-800">
        <tr><th class="p-2 text-left">ID</th><th class="p-2 text-left">URL</th><th class="p-2 text-left">Date</th><th class="p-2">Open</th></tr>
      </thead>
      <tbody id="histBody">
        {% for it in items %}
          <tr class="border-t border-gray-700">
            <td class="p-2">{{ it['id'] }}</td>
            <td class="p-2">{{ it['url'] }}</td>
            <td class="p-2">{{ it['scan_date'] }}</td>
            <td class="p-2 text-center">
              <a href="/view/{{ it['id'] }}" class="text-blue-400 hover:underline">View</a>
            </td>
          </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  <script>
    const input = document.getElementById('histFilter');
    const rows = Array.from(document.querySelectorAll('#histBody tr'));
    input.addEventListener('input', () => {
      const q = input.value.toLowerCase();
      rows.forEach(r => { r.style.display = r.innerText.toLowerCase().includes(q) ? '' : 'none'; });
    });
  </script>
</body>
</html>
"""

GRAPH_HTML = r"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Relationship Graph</title>
  <script type="text/javascript" src="https://unpkg.com/vis-network@9.1.2/dist/vis-network.min.js"></script>
  <link rel="stylesheet" href="https://unpkg.com/vis-network@9.1.2/dist/vis-network.min.css">
  <style>
    body { background:#0f172a; color:#e2e8f0; font-family:system-ui, sans-serif; }
    #network { width: 100%; height: 85vh; border: 1px solid #1e293b; border-radius: 0.5rem; background:#0f172a; }
    .panel { max-width: 1200px; margin: 2rem auto; }
    a { color:#60a5fa; }
  </style>
</head>
<body>
  <div class="panel">
    <h1>Graph for scan {{ scan_id }}</h1>
    <p>Nodes sized by type; drag to explore. <a href="/">Back</a></p>
    <div id="network"></div>
  </div>
  <script>
    const nodes = new vis.DataSet({{ nodes | tojson }});
    const edges = new vis.DataSet({{ edges | tojson }});
    new vis.Network(document.getElementById('network'), { nodes, edges }, {
      nodes: { font: { color: '#e2e8f0' }, borderWidth: 1 },
      edges: { color: '#64748b' },
      physics: { stabilization: true }
    });
  </script>
</body>
</html>
"""

REPORT_HTML = r"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>AEGIS Scan Report</title>
  <style>
    body { font-family: "Segoe UI", Arial, sans-serif; margin: 0; padding: 0; background:#0f172a; color:#e2e8f0; }
    .wrapper { max-width: 960px; margin: 0 auto; padding: 40px 30px; }
    h1, h2, h3 { color:#60a5fa; margin-bottom: 10px; }
    .cards { display:flex; flex-wrap:wrap; gap:16px; margin-bottom:24px; }
    .card { flex:1 1 200px; background:#1f2937; border:1px solid #334155; border-radius:8px; padding:16px; }
    .card .label { font-size:12px; text-transform:uppercase; letter-spacing:1px; color:#94a3b8; }
    .card .value { font-size:24px; font-weight:bold; margin-top:8px; }
    table { width:100%; border-collapse:collapse; margin-bottom:24px; }
    th, td { padding:10px 12px; border:1px solid #334155; text-align:left; font-size:14px; }
    th { background:#1e293b; color:#e2e8f0; }
    .badge { display:inline-block; padding:2px 10px; border-radius:999px; font-size:12px; font-weight:600; color:#0f172a; }
    .badge.ok { background:#22c55e; }
    .badge.warn { background:#f97316; }
    .badge.bad { background:#ef4444; }
    .section { margin-bottom:32px; }
    .meta { font-size:14px; color:#94a3b8; margin-bottom:24px; }
  </style>
</head>
<body>
  <div class="wrapper">
    <h1>AEGIS Scan Report</h1>
    <div class="meta">
      Target: <strong>{{ url }}</strong><br>
      Generated: {{ generated }}<br>
      Risk Level: {{ summary.get('risk_level', 'n/a') }} (Score: {{ summary.get('risk_score', 0) }})
    </div>

    <div class="cards">
      <div class="card">
        <div class="label">Duration (s)</div>
        <div class="value">{{ meta.get('total_seconds', '-') }}</div>
      </div>
      <div class="card">
        <div class="label">Subdomains</div>
        <div class="value">{{ summary.get('subdomains', 0) }}</div>
      </div>
      <div class="card">
        <div class="label">Missing Sec Headers</div>
        <div class="value">{{ summary.get('missing_sec_headers', 0) }}</div>
      </div>
      <div class="card">
        <div class="label">VT Malicious</div>
        <div class="value">{{ summary.get('vt_malicious', 0) }}</div>
      </div>
    </div>

    {% if owasp %}
    <div class="section">
      <h2>OWASP Top 10 Snapshot</h2>
      <table>
        <thead><tr><th>Category</th><th>Status</th><th>Evidence</th></tr></thead>
        <tbody>
          {% for row in owasp %}
          <tr>
            <td>{{ row.category }}</td>
            <td>
              {% set badge = 'ok' %}
              {% if row.status == 'fail' %}{% set badge = 'bad' %}{% elif row.status in ['warn','unknown'] %}{% set badge = 'warn' %}{% endif %}
              <span class="badge {{ badge }}">{{ row.status|upper }}</span>
            </td>
            <td>{{ row.evidence }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    {% endif %}

    {% if exposures %}
    <div class="section">
      <h2>Exposed Paths</h2>
      <table>
        <thead><tr><th>Path</th><th>Status</th><th>Severity</th><th>Description</th></tr></thead>
        <tbody>
          {% for row in exposures %}
          <tr>
            <td>{{ row.path }}</td>
            <td>{{ row.status }}</td>
            <td>{{ row.severity|capitalize }}</td>
            <td>{{ row.description }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    {% endif %}

    {% if fuzzer %}
    <div class="section">
      <h2>Fuzzer Highlights</h2>
      <table>
        <thead><tr><th>Payload</th><th>Method</th><th>Status</th><th>Severity</th><th>Notes</th></tr></thead>
        <tbody>
          {% for row in fuzzer %}
          <tr>
            <td>{{ row.name }}</td>
            <td>{{ row.method }}</td>
            <td>{{ row.status or row.error }}</td>
            <td>{{ row.severity|capitalize }}</td>
            <td>{{ (row.notes or [])|join('; ') }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    {% endif %}

    {% if subdomains %}
    <div class="section">
      <h2>Sample Subdomains</h2>
      <table>
        <thead><tr><th>Subdomain</th><th>Source</th><th>Resolved IPs</th></tr></thead>
        <tbody>
          {% for row in subdomains %}
          <tr>
            <td>{{ row.subdomain }}</td>
            <td>{{ row.source }}</td>
            <td>{{ (row.a_records or [])|join(', ') }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    {% endif %}

    {% if signatures %}
    <div class="section">
      <h2>Detected Signatures</h2>
      <ul>
        {% for sig in signatures %}
          <li>{{ sig.name }} ({{ sig.severity }})</li>
        {% endfor %}
      </ul>
    </div>
    {% endif %}

    <div class="section">
      <h2>Module Timings</h2>
      <table>
        <thead><tr><th>Module</th><th>Seconds</th></tr></thead>
        <tbody>
          {% for name, secs in meta.get('module_times', {}).items() %}
          <tr><td>{{ name }}</td><td>{{ secs }}</td></tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
</body>
</html>
"""

SCHEDULED_HTML = r"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Scheduled Scans</title>
  <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head>
<body class="bg-gray-900 text-gray-100">
  <div class="max-w-5xl mx-auto py-10">
    <div class="flex items-center justify-between mb-6">
      <h1 class="text-3xl font-semibold text-blue-400">Scheduled Scans</h1>
      <a href="/" class="bg-gray-700 hover:bg-gray-600 px-4 py-2 rounded">Back</a>
    </div>
    <div class="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
      <table class="min-w-full text-sm">
        <thead class="bg-gray-700">
          <tr>
            <th class="px-3 py-2 text-left">ID</th>
            <th class="px-3 py-2 text-left">URL</th>
            <th class="px-3 py-2 text-left">Modules</th>
            <th class="px-3 py-2 text-left">Interval (min)</th>
            <th class="px-3 py-2 text-left">Next Run</th>
            <th class="px-3 py-2 text-left">Last Run</th>
          </tr>
        </thead>
        <tbody>
        {% for row in items %}
          <tr class="border-t border-gray-700">
            <td class="px-3 py-2">{{ row.id }}</td>
            <td class="px-3 py-2">{{ row.url }}</td>
            <td class="px-3 py-2 text-xs">{{ row.services }}</td>
            <td class="px-3 py-2">{{ row.interval_minutes }}</td>
            <td class="px-3 py-2">{{ row.next_run }}</td>
            <td class="px-3 py-2">{{ row.last_run or '-' }}</td>
          </tr>
        {% endfor %}
        </tbody>
      </table>
      {% if not items %}
        <p class="p-4 text-sm text-gray-400">No schedules defined yet.</p>
      {% endif %}
    </div>
  </div>
</body>
</html>
"""

# ---------------- Utilities ----------------
def url_normalize(u: str) -> str:
    u = u.strip()
    if not u.startswith(('http://', 'https://')):
        u = "http://" + u
    return u

def get_domain(u: str) -> str:
    try:
        return urlparse(u).hostname or ""
    except Exception:
        return ""

def http_get(u: str):
    try:
        r = SESSION.get(u, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        r.raise_for_status()
        return r
    except requests.RequestException as e:
        # response-like object with 'error'
        return type('obj', (object,), {'status_code': 0, 'text': '', 'headers': {}, 'url': u, 'error': str(e)})

def parse_multiline_values(raw: str):
    if not raw:
        return []
    values = []
    for chunk in raw.replace(",", "\n").splitlines():
        val = chunk.strip()
        if val:
            values.append(val)
    return values

# ---------------- Subdomain Scanner ----------------
def _crtsh_subdomains(domain: str):
    """Passive OSINT from Certificate Transparency (crt.sh)."""
    names = set()
    try:
        r = SESSION.get(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            timeout=DEFAULT_TIMEOUT,
        )
        if r.status_code != 200:
            return names
        data = r.json()
        for entry in data:
            raw = entry.get("name_value", "") or ""
            for line in raw.split("\n"):
                name = line.strip().lower()
                if not name or name.startswith("*."):
                    continue
                if name.endswith("." + domain) or name == domain:
                    names.add(name)
    except Exception:
        pass
    return names

def _resolve_records(host: str):
    """Resolve A/AAAA and CNAME with short timeouts."""
    res = {"A": [], "AAAA": [], "CNAME": None}
    try:
        answers = dns.resolver.resolve(host, "A", lifetime=3)
        res["A"] = [a.to_text() for a in answers]
    except Exception:
        pass
    try:
        answers = dns.resolver.resolve(host, "AAAA", lifetime=3)
        res["AAAA"] = [a.to_text() for a in answers]
    except Exception:
        pass
    try:
        answers = dns.resolver.resolve(host, "CNAME", lifetime=3)
        for a in answers:
            try:
                res["CNAME"] = a.target.to_unicode().rstrip(".")
            except Exception:
                res["CNAME"] = str(a.target).rstrip(".")
            break
    except Exception:
        pass
    return res

_BRUTE_WORDS = [
    "www","mail","ftp","webmail","smtp","pop","imap","api","dev","test","staging",
    "cdn","assets","static","portal","admin","vpn","sso","blog","shop","mx","gw",
    "ns1","ns2","m","beta","qa","help","support","status","git","repo","office",
]

def _bruteforce_subdomains(domain: str, extra_words=None, max_workers=20):
    words = list(dict.fromkeys((extra_words or []) + _BRUTE_WORDS))
    candidates = [f"{w}.{domain}" for w in words]
    found = {}

    def probe(host):
        rec = _resolve_records(host)
        if rec["A"] or rec["AAAA"] or rec["CNAME"]:
            return host, rec
        return None

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(probe, h): h for h in candidates}
        for fut in as_completed(futures):
            out = fut.result()
            if out:
                host, rec = out
                found[host] = rec
    return found

def subdomain_scan(domain: str, mode: str = "defensive", extra_words=None):
    """
    Returns:
      {
        "rows": [{"subdomain": str, "source": "crt.sh|bruteforce", "a_records": [..], "cname": str|None}],
        "found": [list]  # simple view
      }
    """
    rows = []
    found_set = set()

    crt_names = _crtsh_subdomains(domain)
    for name in crt_names:
        rec = _resolve_records(name)
        rows.append({
            "subdomain": name,
            "source": "crt.sh",
            "a_records": rec["A"] + rec["AAAA"],
            "cname": rec["CNAME"],
        })
        found_set.add(name)

    should_bruteforce = mode == "semi" or extra_words
    if should_bruteforce:
        brute = _bruteforce_subdomains(domain, extra_words=extra_words)
        for name, rec in brute.items():
            if name not in found_set:
                rows.append({
                    "subdomain": name,
                    "source": "bruteforce",
                    "a_records": rec["A"] + rec["AAAA"],
                    "cname": rec["CNAME"],
                })
                found_set.add(name)

    rows.sort(key=lambda r: r["subdomain"])
    return {"rows": rows, "found": sorted(found_set)}

# ---------------- Other Modules ----------------
def crawl_website(start_url, max_depth=1):
    visited = set()
    q = [(url_normalize(start_url), 0)]
    crawled = {'urls': [], 'emails': [], 'external_links': []}
    base_netloc = urlparse(start_url).netloc
    email_rx = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")  # fixed 0-9
    while q:
        url, depth = q.pop(0)
        if url in visited or depth > max_depth:
            continue
        try:
            r = http_get(url)
            if hasattr(r, 'error'):
                continue
            visited.add(url)
            crawled['urls'].append(url)
            soup = BeautifulSoup(r.text, 'html.parser')
            for m in email_rx.findall(r.text):
                if m not in crawled['emails']:
                    crawled['emails'].append(m)
            for a in soup.find_all('a', href=True):
                absolute = urljoin(url, a['href'])
                netloc = urlparse(absolute).netloc
                if netloc == base_netloc and absolute not in visited:
                    q.append((absolute, depth + 1))
                elif netloc and netloc != base_netloc and absolute not in crawled['external_links']:
                    crawled['external_links'].append(absolute)
        except Exception:
            continue
    return crawled

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        return {k: str(v) for k, v in w.items()}
    except Exception as e:
        return {"error": str(e)}

def get_dns_records(domain):
    records = {}
    for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [r.to_text() for r in answers]
        except dns.resolver.NoAnswer:
            records[rtype] = []
        except Exception as e:
            records[rtype] = [str(e)]
    return records

def get_http_headers(url):
    try:
        r = SESSION.get(url, timeout=DEFAULT_TIMEOUT)
        return dict(r.headers)
    except Exception as e:
        return {"error": str(e)}

def fingerprint(headers: dict, html_text: str):
    stack = set()
    if "Server" in headers: stack.add(f"Server: {headers['Server']}")
    if "X-Powered-By" in headers: stack.add(f"X-Powered-By: {headers['X-Powered-By']}")
    signatures = {
        "WordPress": re.compile(r"/wp-content/|wp-includes", re.I),
        "React": re.compile(r"data-reactroot", re.I),
    }
    for name, rx in signatures.items():
        if rx.search(html_text):
            stack.add(name)
    return {"stack": sorted(list(stack))}

def security_headers_report(headers: dict):
    rows = []
    sec_headers = {
        "Strict-Transport-Security": "OK",
        "Content-Security-Policy": "OK",
        "X-Frame-Options": "OK",
        "X-Content-Type-Options": "OK",
        "Referrer-Policy": "OK",
        "Permissions-Policy": "OK"
    }
    for header, status in sec_headers.items():
        if header not in headers:
            rows.append({"header": header, "status": "WARN", "message": "Missing"})
        else:
            rows.append({"header": header, "status": status, "message": headers[header]})
    return {"rows": rows}

def tls_info(domain: str, port: int = 443):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        return {
            "subject": dict(x[0] for x in cert['subject']),
            "issuer": dict(x[0] for x in cert['issuer']),
            "not_before": cert['notBefore'],
            "not_after": cert['notAfter']
        }
    except Exception as e:
        return {"error": str(e)}

def vt_url_lookup(u: str):
    if not VT_API_KEY: return {"error": "VT_API_KEY not set."}
    url_id = base64.urlsafe_b64encode(u.encode()).decode().strip("=")
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    try:
        r = SESSION.get(url, headers={"x-apikey": VT_API_KEY})
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def otx_domain_general(domain: str):
    if not OTX_API_KEY: return {"error": "OTX_API_KEY not set."}
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
    try:
        r = SESSION.get(url, headers={"X-OTX-API-KEY": OTX_API_KEY})
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def urlscan_search_domain(domain: str):
    try:
        r = SESSION.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}")
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def archive_cdx(u: str):
    dom = get_domain(u)
    url = f"http://web.archive.org/cdx/search/cdx?url={dom}/*&output=json&limit=10"
    try:
        r = SESSION.get(url, timeout=DEFAULT_TIMEOUT)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def github_code_search(query: str):
    headers = {"Accept": "application/vnd.github+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    url = f"https://api.github.com/search/code?q={query}"
    try:
        r = SESSION.get(url, headers=headers)
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def securitytrails_lookup(domain: str):
    if not SECURITYTRAILS_API_KEY:
        return {"error": "SECURITYTRAILS_API_KEY not set."}
    headers = {"APIKEY": SECURITYTRAILS_API_KEY}
    base = f"https://api.securitytrails.com/v1/domain/{domain}"
    history_url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
    result = {}
    try:
        resp = SESSION.get(base, headers=headers, timeout=DEFAULT_TIMEOUT)
        result["current"] = resp.json() if resp.ok else {"error": resp.text}
    except Exception as exc:
        result["current"] = {"error": str(exc)}
    try:
        hist_resp = SESSION.get(history_url, headers=headers, timeout=DEFAULT_TIMEOUT)
        if hist_resp.ok:
            payload = hist_resp.json()
            result["history"] = payload.get("records", [])[:25]
        else:
            result["history"] = {"error": hist_resp.text}
    except Exception as exc:
        result["history"] = {"error": str(exc)}
    return result

def shodan_lookup(domain: str):
    if not SHODAN_API_KEY: return {"error": "SHODAN_API_KEY not set."}
    try:
        ip = socket.gethostbyname(domain)
        r = SESSION.get(f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}")
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def greynoise_lookup(ip: str):
    if not GREYNOISE_API_KEY: return {"error": "GREYNOISE_API_KEY not set."}
    try:
        r = SESSION.get(f"https://api.greynoise.io/v3/community/{ip}", headers={"key": GREYNOISE_API_KEY})
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def abuseipdb_lookup(ip: str):
    if not ABUSEIPDB_API_KEY: return {"error": "ABUSEIPDB_API_KEY not set."}
    try:
        r = SESSION.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip},
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        )
        return r.json()
    except Exception as e:
        return {"error": str(e)}

SECURITY_TXT_PATHS = [
    "/.well-known/security.txt",
    "/security.txt",
]

SENSITIVE_ROBOTS_KEYWORDS = [
    "admin",
    "backup",
    "config",
    "secret",
    "internal",
    "staging",
    "dev",
    "test",
    "beta",
    "private",
    "tmp",
    "hidden",
]

EXPOSURE_PATHS = [
    {"path": "/.git/config", "severity": "high", "description": "Git repository configuration"},
    {"path": "/.env", "severity": "high", "description": "Environment variables"},
    {"path": "/server-status", "severity": "medium", "description": "Apache status handler"},
    {"path": "/phpinfo.php", "severity": "medium", "description": "PHP configuration dump"},
    {"path": "/.svn/entries", "severity": "medium", "description": "SVN metadata"},
    {"path": "/backup.zip", "severity": "high", "description": "Backup archive"},
    {"path": "/db.sql", "severity": "high", "description": "Database dump"},
    {"path": "/config.old", "severity": "medium", "description": "Legacy configuration file"},
    {"path": "/.idea/workspace.xml", "severity": "low", "description": "IDE project metadata"},
    {"path": "/.DS_Store", "severity": "low", "description": "Directory index leak"},
    {"path": "/aws.yml", "severity": "medium", "description": "Cloud configuration"},
    {"path": "/storage.tar.gz", "severity": "high", "description": "Archive of application data"},
]

SIGNATURE_PATTERNS = [
    {"name": "Magecart Skimmer", "pattern": re.compile(r"skimmer|magecart", re.I), "severity": "high"},
    {"name": "Crypto Miner", "pattern": re.compile(r"CoinHive|cryptonight", re.I), "severity": "medium"},
    {"name": "Phishing Kit", "pattern": re.compile(r"login\.php\?auth|otp-bypass", re.I), "severity": "high"},
]

FUZZ_PAYLOADS = [
    {"name": "debug_flag", "method": "GET", "params": {"debug": "1"}, "description": "Attempt to enable verbose/debug output"},
    {"name": "verbose_mode", "method": "GET", "params": {"verbose": "true"}, "description": "Toggle verbose flag"},
    {"name": "path_traversal", "method": "GET", "params": {"file": "../../../../etc/passwd"}, "description": "Probe file traversal"},
    {"name": "sql_injection_id", "method": "GET", "params": {"id": "1' OR '1'='1"}, "description": "Classic SQLi id param"},
    {"name": "sqli_search", "method": "GET", "params": {"search": "\" OR \"1\"=\"1"}, "description": "Quote-based SQLi"},
    {"name": "json_admin", "method": "POST", "json": {"role": "admin", "debug": True}, "description": "POST JSON privilege escalation"},
    {"name": "form_override", "method": "POST", "data": {"is_admin": "true", "price": "0"}, "description": "Form tampering"},
    {"name": "header_origin", "method": "GET", "params": {}, "headers": {"X-Forwarded-For": "127.0.0.1", "Origin": "https://evil.tld"}, "description": "Header manipulation"},
    {"name": "template_injection", "method": "GET", "params": {"msg": "{{7*7}}"}, "description": "SSTI probe"},
    {"name": "command_injection", "method": "GET", "params": {"cmd": "1; cat /etc/passwd"}, "description": "Command injection test"},
]

FUZZ_ALERT_TERMS = [
    "exception",
    "stack trace",
    "sql syntax",
    "mysql",
    "postgres",
    "syntax error",
    "warning",
    "fatal",
    "undefined",
    "traceback",
    "internal server error",
]

CVE_TECH_MAPPING = {
    "apache": ("apache", "http_server"),
    "nginx": ("nginx", "nginx"),
    "wordpress": ("wordpress", "wordpress"),
    "react": ("facebook", "react"),
    "django": ("djangoproject", "django"),
    "express": ("nodejs", "express"),
}

CODE_SCAN_PATTERNS = [
    ("Hardcoded password", re.compile(r"password\s*=\s*['\"]", re.I)),
    ("API key literal", re.compile(r"api_key\s*=\s*['\"]", re.I)),
    ("Suspicious eval", re.compile(r"eval\(", re.I)),
    ("AWS Secret", re.compile(r"(?i)aws_secret_access_key")),
]

def fetch_security_txt(base_url: str):
    files = []
    errors = []
    for path in SECURITY_TXT_PATHS:
        url = urljoin(base_url, path)
        try:
            resp = SESSION.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        except requests.RequestException as exc:
            errors.append({"path": path, "url": url, "error": str(exc)})
            continue
        if resp.status_code >= 400 or not resp.text.strip():
            continue
        entries = []
        for raw_line in resp.text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or ":" not in line:
                continue
            key, value = line.split(":", 1)
            entries.append({"field": key.strip(), "value": value.strip()})
        if entries:
            files.append({
                "path": path,
                "url": url,
                "status": resp.status_code,
                "entries": entries,
                "size": len(resp.text),
                "last_modified": resp.headers.get("Last-Modified"),
            })
    result = {"found": bool(files), "files": files}
    if not files:
        result["message"] = "security.txt not found"
    if errors:
        result["errors"] = errors
    return result

def robots_txt_report(base_url: str):
    url = urljoin(base_url, "/robots.txt")
    try:
        resp = SESSION.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
    except requests.RequestException as exc:
        return {"error": str(exc)}
    if resp.status_code >= 400:
        return {"error": f"robots.txt returned status {resp.status_code}"}
    rules = []
    suspicious = []
    for raw_line in resp.text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        directive, value = line.split(":", 1)
        directive = directive.strip()
        value = value.strip()
        directive_norm = directive.lower()
        if directive_norm in ("allow", "disallow"):
            rule = {"directive": directive.capitalize(), "path": value}
            rules.append(rule)
            lowered = value.lower()
            for keyword in SENSITIVE_ROBOTS_KEYWORDS:
                if keyword in lowered:
                    suspicious.append({**rule, "keyword": keyword})
                    break
    return {
        "url": url,
        "status": resp.status_code,
        "rules": rules,
        "suspicious": suspicious,
        "last_modified": resp.headers.get("Last-Modified"),
    }

def exposure_checks(base_url: str, extra_paths=None):
    rows = []
    targets = list(EXPOSURE_PATHS)
    for raw in extra_paths or []:
        value = raw.strip()
        if not value:
            continue
        severity = "medium"
        desc = "Custom path"
        path = value
        if "::" in value:
            prefix, remainder = value.split("::", 1)
            severity = prefix.lower() or severity
            path = remainder.strip() or path
        if not path.startswith("/"):
            path = "/" + path.lstrip("/")
        targets.append({"path": path, "severity": severity, "description": desc})
    for entry in targets:
        path = entry["path"]
        severity = entry.get("severity", "medium")
        description = entry.get("description", "Custom path")
        url = urljoin(base_url, path)
        status = "Error"
        length = None
        content_type = None
        error = None
        try:
            resp = SESSION.head(url, timeout=5, allow_redirects=True)
            status = resp.status_code
            length = resp.headers.get("Content-Length")
            content_type = resp.headers.get("Content-Type")
            if status in (403, 405):
                resp = SESSION.get(url, timeout=5, allow_redirects=True)
                status = resp.status_code
                length = resp.headers.get("Content-Length") or len(resp.content)
                content_type = resp.headers.get("Content-Type")
        except requests.RequestException as exc:
            error = str(exc)
        rows.append({
            "path": path,
            "url": url,
            "status": status,
            "length": length,
            "severity": severity,
            "description": description,
            "content_type": content_type,
            "error": error,
        })
    return {"rows": rows}

JS_SECRET_PATTERNS = [("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}"))]
def js_secrets_from_page(url: str):
    rows = []
    try:
        r = http_get(url)
        if hasattr(r, 'error'):
            return {"rows": []}
        soup = BeautifulSoup(r.text, "html.parser")
        for script in soup.find_all("script", src=True):
            script_url = urljoin(url, script['src'])
            script_r = http_get(script_url)
            if hasattr(script_r, 'error'):
                continue
            for name, pattern in JS_SECRET_PATTERNS:
                for match in pattern.finditer(script_r.text):
                    rows.append({"file": script_url, "type": name, "value": match.group(0)})
    except Exception:
        pass
    return {"rows": rows}

def hibp_lookup(emails):
    if not HIBP_API_KEY:
        return {"error": "HIBP_API_KEY not set."}
    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "user-agent": USER_AGENT,
    }
    checked = []
    rows = []
    for idx, email in enumerate(emails or []):
        email_norm = email.strip()
        if not email_norm or email_norm in checked:
            continue
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email_norm}"
        try:
            resp = SESSION.get(url, headers=headers, params={"truncateResponse": "true"}, timeout=DEFAULT_TIMEOUT)
            if resp.status_code == 404:
                rows.append({"email": email_norm, "breached": False, "breaches": []})
            elif resp.ok:
                breaches = resp.json()
                rows.append({"email": email_norm, "breached": True, "breaches": [b.get("Name") for b in breaches]})
            else:
                rows.append({"email": email_norm, "error": f"{resp.status_code}: {resp.text}"})
        except Exception as exc:
            rows.append({"email": email_norm, "error": str(exc)})
        checked.append(email_norm)
        if idx != len(emails) - 1:
            time.sleep(1.6)
    return {"rows": rows}

async def _screenshot_async(url: str):
    browser = await launch(headless=True, args=["--no-sandbox", "--disable-gpu"])
    page = await browser.newPage()
    await page.setViewport({"width": 1280, "height": 720})
    await page.goto(url, timeout=SCREENSHOT_TIMEOUT * 1000, waitUntil="networkidle2")
    data = await page.screenshot(fullPage=True)
    await browser.close()
    return base64.b64encode(data).decode()

def capture_screenshot(url: str):
    if launch is None:
        return {"error": "pyppeteer is not installed"}
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        encoded = loop.run_until_complete(_screenshot_async(url))
        return {"data_uri": f"data:image/png;base64,{encoded}"}
    except Exception as exc:
        return {"error": str(exc)}
    finally:
        loop.close()

def signature_scan(html_text: str):
    rows = []
    if not html_text:
        return {"rows": rows}
    for sig in SIGNATURE_PATTERNS:
        if sig["pattern"].search(html_text):
            rows.append({"name": sig["name"], "severity": sig["severity"]})
    return {"rows": rows}

def parameter_fuzzer(url: str):
    rows = []
    baseline = {}
    try:
        base_resp = SESSION.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        baseline = {
            "status": base_resp.status_code,
            "length": int(base_resp.headers.get("Content-Length") or len(base_resp.content)),
        }
    except requests.RequestException:
        baseline = {}

    for payload in FUZZ_PAYLOADS:
        method = (payload.get("method") or "GET").upper()
        headers = payload.get("headers") or {}
        req_kwargs = {
            "timeout": DEFAULT_TIMEOUT,
            "allow_redirects": True,
            "headers": headers if headers else None,
        }
        if method == "GET":
            req_kwargs["params"] = payload.get("params")
        else:
            req_kwargs["params"] = payload.get("params")
            if payload.get("json") is not None:
                req_kwargs["json"] = payload.get("json")
            if payload.get("data") is not None:
                req_kwargs["data"] = payload.get("data")
        req_kwargs = {k: v for k, v in req_kwargs.items() if v is not None}

        try:
            resp = SESSION.request(method, url, **req_kwargs)
            try:
                body = resp.text
            except Exception:
                body = resp.content.decode("latin-1", errors="ignore")
            length = int(resp.headers.get("Content-Length") or len(body))
            keywords = []
            low_body = body.lower()
            for term in FUZZ_ALERT_TERMS:
                if term in low_body:
                    keywords.append(term)
            reflected = False
            candidate_values = []
            for source in ("params", "data", "json"):
                values = payload.get(source)
                if isinstance(values, dict):
                    candidate_values.extend([str(v) for v in values.values() if isinstance(v, (str, int, float))])
            for value in candidate_values:
                val = str(value).strip()
                if val and val.lower() in low_body:
                    reflected = True
                    break
            severity = "info"
            notes = []
            if resp.status_code >= 500:
                severity = "high"
                notes.append("Server error response")
            elif resp.status_code >= 400:
                severity = "medium"
                notes.append("Client error response")

            if baseline:
                delta = abs(length - baseline.get("length", length))
                threshold = max(200, baseline.get("length", 1) * 0.3)
                if delta > threshold:
                    severity = "medium" if severity == "info" else severity
                    notes.append(f"Response size deviates by {delta} bytes")

            if keywords:
                severity = "high" if severity != "high" else severity
                notes.append(f"Keywords: {', '.join(keywords[:5])}")

            if reflected:
                severity = "high"
                notes.append("Payload reflected in response body")

            rows.append({
                "name": payload["name"],
                "method": method,
                "params": payload.get("params") or payload.get("data") or payload.get("json"),
                "status": resp.status_code,
                "length": length,
                "redirected": bool(resp.history),
                "severity": severity,
                "notes": notes,
                "keywords": keywords,
                "reflected": reflected,
                "description": payload.get("description"),
            })
        except requests.RequestException as exc:
            rows.append({
                "name": payload["name"],
                "method": method,
                "params": payload.get("params") or payload.get("data") or payload.get("json"),
                "error": str(exc),
                "severity": "info",
                "notes": [],
                "keywords": [],
                "reflected": False,
                "description": payload.get("description"),
            })
    return {"rows": rows, "baseline": baseline}

def cloud_asset_inventory(domain: str):
    if not domain:
        return {"error": "Domain required"}
    if boto3 is None:
        return {"error": "boto3 is not installed"}
    session = boto3.session.Session(region_name=AWS_REGION)
    findings = {"s3": []}
    try:
        s3 = session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        for bucket in buckets:
            name = bucket.get("Name", "")
            if domain.split(".")[0] in name:
                findings["s3"].append({"name": name, "created": str(bucket.get("CreationDate"))})
    except Exception as exc:
        return {"error": str(exc)}
    if not findings["s3"]:
        findings["message"] = "No S3 buckets matched the domain keyword."
    return findings

def code_static_analysis(github_results):
    items = (github_results or {}).get("items", [])
    if not items:
        return {"rows": [], "message": "No GitHub code to analyze."}
    rows = []
    headers = {"Accept": "application/vnd.github+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    for item in items[:3]:
        meta_url = item.get("url")
        if not meta_url:
            continue
        try:
            meta_resp = SESSION.get(meta_url, headers=headers, timeout=DEFAULT_TIMEOUT)
            if not meta_resp.ok:
                continue
            meta = meta_resp.json()
            download_url = meta.get("download_url")
            if not download_url:
                continue
            content_resp = SESSION.get(download_url, timeout=DEFAULT_TIMEOUT)
            if not content_resp.ok:
                continue
            text = content_resp.text
            findings = []
            for name, pattern in CODE_SCAN_PATTERNS:
                if pattern.search(text):
                    findings.append(name)
            if findings:
                rows.append({
                    "file": item.get("html_url"),
                    "repo": item.get("repository", {}).get("full_name"),
                    "findings": findings,
                })
        except requests.RequestException:
            continue
    return {"rows": rows}

def cve_lookup_from_stack(stack_entries):
    alerts = []
    queried = set()
    for entry in stack_entries or []:
        if not isinstance(entry, str):
            continue
        lowered = entry.lower()
        for keyword, (vendor, product) in CVE_TECH_MAPPING.items():
            if keyword in lowered:
                if keyword in queried:
                    continue
                try:
                    resp = SESSION.get(f"https://cve.circl.lu/api/search/{vendor}/{product}", timeout=DEFAULT_TIMEOUT)
                    if resp.ok:
                        payload = resp.json()
                        if isinstance(payload, dict):
                            if isinstance(payload.get("data"), list):
                                entries = payload["data"]
                            elif isinstance(payload.get("results"), list):
                                entries = payload["results"]
                            else:
                                entries = list(payload.values()) if all(isinstance(v, dict) for v in payload.values()) else [payload]
                        else:
                            entries = payload or []
                        for item in (entries or [])[:3]:
                            if not isinstance(item, dict):
                                continue
                            alerts.append({
                                "tech": keyword,
                                "id": item.get("id"),
                                "summary": item.get("summary", "")[:200],
                                "cvss": item.get("cvss"),
                            })
                        queried.add(keyword)
                except requests.RequestException:
                    continue
    return {"rows": alerts}

def owasp_top10_audit(results, scheme="http"):
    findings = []
    exposure_mod = results.get("exposure_checks")
    exposures = exposure_mod.get("rows", []) if isinstance(exposure_mod, dict) else None
    sec_headers_mod = results.get("sec_headers")
    sec_headers = sec_headers_mod.get("rows", []) if isinstance(sec_headers_mod, dict) else None
    fuzzer_mod = results.get("fuzzer")
    fuzzer = fuzzer_mod.get("rows", []) if isinstance(fuzzer_mod, dict) else None
    cves_mod = results.get("cve_alerts")
    cves = cves_mod.get("rows", []) if isinstance(cves_mod, dict) else None
    tls = results.get("tls")
    security_txt = results.get("security_txt")

    def add(category, status, evidence):
        findings.append({
            "category": category,
            "status": status,
            "evidence": evidence,
        })

    # A01: Broken Access Control
    if exposures is None:
        add("A01: Broken Access Control", "unknown", "Exposure module not executed")
    else:
        exposed = [
            row for row in exposures
            if isinstance(row.get("status"), int) and 200 <= row["status"] < 400 and row.get("severity") in ("high", "medium")
        ]
        if exposed:
            add("A01: Broken Access Control", "fail", f"{len(exposed)} sensitive paths accessible (e.g., {exposed[0]['path']})")
        else:
            add("A01: Broken Access Control", "ok", "No sensitive paths responded successfully")

    # A02: Cryptographic Failures
    if scheme != "https":
        add("A02: Cryptographic Failures", "fail", "Site served over non-HTTPS scheme")
    elif not tls:
        add("A02: Cryptographic Failures", "unknown", "TLS module not executed")
    elif tls.get("error"):
        add("A02: Cryptographic Failures", "warn", f"TLS error: {tls['error']}")
    else:
        add("A02: Cryptographic Failures", "ok", "HTTPS enforced and TLS handshake succeeded")

    # A03: Injection
    if fuzzer is None:
        add("A03: Injection", "unknown", "Fuzzer module not executed")
    else:
        injection_hits = [row for row in fuzzer if row.get("severity") == "high"]
        if injection_hits:
            add("A03: Injection", "fail", f"High-risk fuzzer payload detected ({injection_hits[0]['name']})")
        else:
            add("A03: Injection", "ok", "No high-risk payload reflections detected")

    # A05: Security Misconfiguration (using OWASP 2021 numbering where A05)
    if sec_headers is None:
        add("A05: Security Misconfiguration", "unknown", "Security headers module not executed")
    else:
        missing_headers = [row for row in sec_headers if row.get("status") != "OK"]
        if missing_headers:
            add("A05: Security Misconfiguration", "warn", f"{len(missing_headers)} missing security headers")
        else:
            add("A05: Security Misconfiguration", "ok", "Core security headers present")

    # A06: Vulnerable and Outdated Components
    if cves is None:
        add("A06: Vulnerable Components", "unknown", "CVE lookup module not executed")
    elif cves:
        add("A06: Vulnerable Components", "warn", f"{len(cves)} known CVEs related to stack (e.g., {cves[0]['id']})")
    else:
        add("A06: Vulnerable Components", "ok", "No CVE alerts for detected technologies")

    # A07: Identification and Authentication Failures (heuristic using exposures to auth endpoints)
    if exposures is None:
        add("A07: Identification & Auth Failures", "unknown", "Exposure module not executed")
    else:
        auth_exposures = [
            row for row in exposures
            if isinstance(row.get("path"), str) and ("login" in row["path"].lower() or "auth" in row["path"].lower())
        ]
        if auth_exposures:
            add("A07: Identification & Auth Failures", "warn", f"Potential auth endpoint exposed ({auth_exposures[0]['path']})")
        else:
            add("A07: Identification & Auth Failures", "ok", "No obvious authentication endpoints exposed")

    # A09: Security Logging and Monitoring Failures (heuristic)
    if security_txt is None:
        add("A09: Security Logging & Monitoring", "unknown", "security.txt module not executed")
    elif not security_txt.get("found"):
        add("A09: Security Logging & Monitoring", "warn", "security.txt not discovered (limited contact info)")
    else:
        add("A09: Security Logging & Monitoring", "ok", "security.txt present")

    return {"rows": findings}

def extract_relationships(results):
    nodes = {}
    edges = []
    def add_node(identifier, label, group):
        if identifier in nodes:
            return
        nodes[identifier] = {"id": identifier, "label": label, "group": group}

    subdomains = results.get("subdomain_scan", {}).get("rows", [])
    for row in subdomains:
        sub = row.get("subdomain")
        if not sub:
            continue
        add_node(sub, sub, "subdomain")
        for addr in row.get("a_records", []):
            add_node(addr, addr, "ip")
            edges.append({"from": sub, "to": addr})
    emails = results.get("crawler", {}).get("emails", [])
    for email in emails:
        add_node(email, email, "email")
        if results.get("_meta", {}).get("base_domain"):
            edges.append({"from": results["_meta"]["base_domain"], "to": email})
    links = results.get("crawler", {}).get("external_links", [])
    for link in links[:200]:
        add_node(link, link, "link")
        if results.get("_meta", {}).get("base_domain"):
            edges.append({"from": results["_meta"]["base_domain"], "to": link})
    base = results.get("_meta", {}).get("base_domain")
    if base:
        add_node(base, base, "domain")
    return list(nodes.values()), edges

def submit_to_sandbox(content, url):
    if not MALWARE_SANDBOX_URL or not content:
        return {"error": "Sandbox not configured or no payload."}
    try:
        resp = SESSION.post(
            MALWARE_SANDBOX_URL,
            headers={"Authorization": f"Bearer {MALWARE_SANDBOX_KEY}"} if MALWARE_SANDBOX_KEY else None,
            json={"url": url, "content": content[:500000]},
            timeout=DEFAULT_TIMEOUT,
        )
        if resp.ok:
            return resp.json()
        return {"error": f"{resp.status_code}: {resp.text}"}
    except requests.RequestException as exc:
        return {"error": str(exc)}

def run_workflow(url, steps):
    if not steps:
        return {"logs": ["No steps provided."], "status": "skipped"}
    if sync_playwright is None:
        return {"error": "playwright is not installed"}
    logs = []
    steps = steps[:WORKFLOW_MAX_STEPS]
    def log(msg):
        logs.append(msg)
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, timeout=DEFAULT_TIMEOUT * 1000)
            log(f"Goto {url}")
            for step in steps:
                action = (step.get("action") or "").lower()
                if action == "goto":
                    target = step.get("url", url)
                    page.goto(target, timeout=DEFAULT_TIMEOUT * 1000)
                    log(f"Goto {target}")
                elif action == "click":
                    selector = step.get("selector")
                    if selector:
                        page.click(selector, timeout=DEFAULT_TIMEOUT * 1000)
                        log(f"Click {selector}")
                elif action == "type":
                    selector = step.get("selector")
                    value = step.get("value", "")
                    if selector:
                        page.fill(selector, value)
                        log(f"Type into {selector}")
                elif action == "wait":
                    delay = int(step.get("ms", 1000))
                    page.wait_for_timeout(delay)
                    log(f"Wait {delay}ms")
            snapshot = page.content()
            browser.close()
        return {"logs": logs, "snapshot": snapshot}
    except Exception as exc:
        return {"error": str(exc), "logs": logs}

# ---------------- Summary & Orchestrator ----------------
def build_summary(results):
    s = {
        "subdomains": len(results.get("subdomain_scan", {}).get("rows", [])) or len(results.get("subdomain_scan", {}).get("found", [])),
        "missing_sec_headers": 0,
        "vt_malicious": 0,
        "risk_score": 0,
        "risk_level": "low",
    }
    sh = results.get("sec_headers", {})
    for r in sh.get("rows", []):
        if r.get("status") != "OK":
            s["missing_sec_headers"] += 1
    vt = results.get("virustotal", {})
    stats = (vt.get("data", {}) or {}).get("attributes", {}).get("last_analysis_stats", {})
    try:
        s["vt_malicious"] = int(stats.get("malicious", 0) or 0)
    except Exception:
        s["vt_malicious"] = 0
    score = 0
    score += s["missing_sec_headers"] * 2
    score += min(50, s["vt_malicious"] * 5)
    exposures = results.get("exposure_checks", {}).get("rows", [])
    severity_weight = {"high": 15, "medium": 7, "low": 3, "custom": 5}
    for row in exposures:
        status = row.get("status")
        if isinstance(status, int) and 200 <= status < 400:
            score += severity_weight.get(row.get("severity"), 5)
    robots = results.get("robots_txt", {}).get("suspicious") or []
    score += len(robots) * 2
    signatures = results.get("signature_hits", {}).get("rows", [])
    score += len(signatures) * 5
    cve_hits = results.get("cve_alerts", {}).get("rows", [])
    score += len(cve_hits) * 3
    owasp = results.get("owasp_top10", {}).get("rows", [])
    for item in owasp:
        if item.get("status") == "fail":
            score += 8
        elif item.get("status") == "warn":
            score += 4
    hibp = results.get("hibp", {}).get("rows", [])
    for entry in hibp:
        if entry.get("breached"):
            score += 10 + len(entry.get("breaches") or []) * 2
    s["risk_score"] = score
    if score >= 60:
        s["risk_level"] = "high"
    elif score >= 30:
        s["risk_level"] = "medium"
    return s

def maybe_send_notification(url, summary, results):
    if not SLACK_WEBHOOK_URL:
        return
    score = summary.get("risk_score", 0)
    if score < ALERT_THRESHOLD:
        return
    payload = {
        "text": f"AEGIS alert ({summary.get('risk_level')}) for {url}",
        "attachments": [
            {
                "color": "#dc2626" if summary.get("risk_level") == "high" else "#f59e0b",
                "fields": [
                    {"title": "Risk Score", "value": str(score), "short": True},
                    {"title": "VT Malicious", "value": str(summary.get("vt_malicious", 0)), "short": True},
                    {"title": "Missing Sec Headers", "value": str(summary.get("missing_sec_headers", 0)), "short": True},
                ]
            }
        ]
    }
    try:
        requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=5)
    except requests.RequestException:
        pass

def summarize_changes(old_results, new_results):
    diffs = {}
    old_sd = set((old_results or {}).get("subdomain_scan", {}).get("found", []))
    new_sd = set(new_results.get("subdomain_scan", {}).get("found", []))
    added_sd = sorted(new_sd - old_sd)
    if added_sd:
        diffs["subdomains_added"] = added_sd

    def successful_exposures(res):
        rows = (res or {}).get("exposure_checks", {}).get("rows", [])
        paths = set()
        for row in rows:
            status = row.get("status")
            if isinstance(status, int) and 200 <= status < 400:
                paths.add(row.get("path"))
        return paths

    new_exposures = successful_exposures(new_results) - successful_exposures(old_results or {})
    if new_exposures:
        diffs["new_exposures"] = sorted(new_exposures)
    return diffs

def notify_diff(url, diff):
    if not SLACK_WEBHOOK_URL or not diff:
        return
    fields = []
    if diff.get("subdomains_added"):
        fields.append({"title": "New Subdomains", "value": "\n".join(diff["subdomains_added"][:5]), "short": False})
    if diff.get("new_exposures"):
        fields.append({"title": "New Exposures", "value": "\n".join(diff["new_exposures"][:5]), "short": False})
    payload = {
        "text": f"AEGIS scheduled diff for {url}",
        "attachments": [{"color": "#2563eb", "fields": fields}]
    }
    try:
        requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=5)
    except requests.RequestException:
        pass

def schedule_recurring_scan(url, services, mode, extras, minutes):
    if minutes <= 0:
        return
    db = get_db()
    next_run = (datetime.utcnow() + timedelta(minutes=minutes)).isoformat()
    db.execute(
        """
        INSERT INTO scheduled_scans (url, services, mode, extras, interval_minutes, next_run)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            url,
            json.dumps(services),
            mode,
            json.dumps(extras or {}),
            minutes,
            next_run,
        ),
    )
    db.commit()

def process_schedules():
    if app.config.get("_processing_schedule"):
        return
    db = get_db()
    now = datetime.utcnow().isoformat()
    try:
        row = db.execute(
            "SELECT * FROM scheduled_scans WHERE next_run <= ? ORDER BY next_run ASC LIMIT 1",
            (now,),
        ).fetchone()
    except sqlite3.OperationalError:
        return
    if not row:
        return
    app.config["_processing_schedule"] = True
    try:
        services = json.loads(row["services"])
        extras = json.loads(row["extras"] or "{}")
        old_results = json.loads(row["last_results"]) if row["last_results"] else {}
        results, url_norm = run_scan(
            row["url"],
            services,
            row["mode"],
            extras.get("subdomains"),
            extras.get("exposures"),
            extras.get("workflow"),
            scheduled_run=True,
        )
        next_run = (datetime.utcnow() + timedelta(minutes=row["interval_minutes"])).isoformat()
        db.execute(
            "UPDATE scheduled_scans SET next_run=?, last_run=?, last_results=? WHERE id=?",
            (next_run, datetime.utcnow().isoformat(), json.dumps(results), row["id"]),
        )
        db.commit()
        diff = summarize_changes(old_results, results)
        notify_diff(url_norm, diff)
    finally:
        app.config["_processing_schedule"] = False

@app.before_request
def _schedule_tick():
    process_schedules()

def compute_anomalies(url, summary):
    db = get_db()
    rows = db.execute(
        "SELECT results FROM scans WHERE url=? ORDER BY id DESC LIMIT 10",
        (url,),
    ).fetchall()
    if not rows:
        return {"message": "Baseline unavailable."}
    metrics = {"missing_sec_headers": [], "vt_malicious": [], "risk_score": []}
    for row in rows:
        try:
            data = json.loads(row["results"])
            summ = data.get("_summary", {})
            for key in metrics:
                if key in summ:
                    metrics[key].append(float(summ.get(key, 0)))
        except Exception:
            continue
    anomalies = {}
    for key, values in metrics.items():
        if not values:
            continue
        avg = sum(values) / len(values)
        diff = summary.get(key, 0) - avg
        if abs(diff) >= max(1, avg * 0.5):
            anomalies[key] = {"average": round(avg, 2), "current": summary.get(key, 0), "delta": round(diff, 2)}
    return anomalies or {"message": "No significant deviations."}

def maybe_create_ticket(url, summary, results):
    if not TICKET_WEBHOOK_URL:
        return
    if summary.get("risk_score", 0) < AUTO_TICKET_THRESHOLD:
        return
    exposures = results.get("exposure_checks", {}).get("rows", [])
    high_exposures = [r for r in exposures if r.get("severity") == "high" and isinstance(r.get("status"), int) and r["status"] < 400]
    payload = {
        "summary": f"AEGIS alert for {url} (risk {summary.get('risk_score')})",
        "details": {
            "missing_sec_headers": summary.get("missing_sec_headers"),
            "vt_malicious": summary.get("vt_malicious"),
            "high_exposures": high_exposures[:5],
            "timestamp": datetime.utcnow().isoformat()
        }
    }
    try:
        requests.post(TICKET_WEBHOOK_URL, json=payload, timeout=5)
    except requests.RequestException:
        pass

def run_scan(url_to_scan, selected_services, mode, extra_subdomain_words=None, extra_exposure_paths=None, workflow_steps=None, scheduled_run=False):
    url_norm = url_normalize(url_to_scan)
    parsed_url = urlparse(url_norm)
    domain = parsed_url.hostname or get_domain(url_norm)
    results = {}
    module_times = {}
    t0 = time.perf_counter()

    workflow_steps = workflow_steps or []
    def run_mod(name, cond, func, *args, **kwargs):
        if not cond:
            return
        start = time.perf_counter()
        try:
            out = func(*args, **kwargs)
        finally:
            module_times[name] = round(time.perf_counter() - start, 3)
        results[name] = out

    # Base response for fingerprinting
    base_resp = http_get(url_norm)
    headers = base_resp.headers if not hasattr(base_resp, 'error') else {}
    html_text = base_resp.text if not hasattr(base_resp, 'error') else ""

    run_mod("crawler",      "crawler" in selected_services, crawl_website, url_norm)
    run_mod("http_headers", "headers" in selected_services, get_http_headers, url_norm)
    run_mod("tech",         "tech" in selected_services, fingerprint, headers, html_text)
    run_mod("signature_hits", "signatures" in selected_services, signature_scan, html_text)
    run_mod("cve_alerts",   "cve_alerts" in selected_services and results.get("tech"), cve_lookup_from_stack, results.get("tech", {}).get("stack"))
    run_mod("sec_headers",  "sec_headers" in selected_services, security_headers_report, headers)
    run_mod("tls",          "tls" in selected_services and domain, tls_info, domain)
    run_mod("whois_lookup", "whois" in selected_services and domain, get_whois_info, domain)
    run_mod("dns_records",  "dns" in selected_services and domain, get_dns_records, domain)
    run_mod("subdomain_scan", "subdomains" in selected_services and domain, subdomain_scan, domain, mode, extra_subdomain_words or [])
    run_mod("securitytrails", "securitytrails" in selected_services and domain, securitytrails_lookup, domain)
    run_mod("cloud_assets", "cloud_assets" in selected_services and domain, cloud_asset_inventory, domain)
    run_mod("virustotal",   "virustotal" in selected_services, vt_url_lookup, url_norm)
    run_mod("urlscan",      "urlscan" in selected_services and domain, urlscan_search_domain, domain)
    run_mod("archive_org",  "archive" in selected_services, archive_cdx, url_norm)
    run_mod("security_txt", "security_txt" in selected_services, fetch_security_txt, url_norm)
    run_mod("robots_txt",   "robots_txt" in selected_services, robots_txt_report, url_norm)
    run_mod("otx",          "otx" in selected_services and domain, otx_domain_general, domain)
    run_mod("github",       "github" in selected_services and domain, github_code_search, domain)
    run_mod("code_scan",    "code_scan" in selected_services and results.get("github"), code_static_analysis, results.get("github"))

    ip = ""
    if domain:
        try:
            ip = socket.gethostbyname(domain)
        except socket.gaierror:
            ip = ""

    run_mod("shodan",     "shodan" in selected_services and domain, shodan_lookup, domain)
    run_mod("greynoise",  "greynoise" in selected_services and ip, greynoise_lookup, ip)
    run_mod("abuseipdb",  "abuseipdb" in selected_services and ip, abuseipdb_lookup, ip)
    run_mod("workflow",    "workflow" in selected_services and workflow_steps, run_workflow, url_norm, workflow_steps or [])
    run_mod("screenshot",  "screenshot" in selected_services, capture_screenshot, url_norm)
    run_mod("sandbox_report", "sandbox" in selected_services and html_text, submit_to_sandbox, html_text, url_norm)
    run_mod("fuzzer",      "fuzzer" in selected_services, parameter_fuzzer, url_norm)

    crawler_emails = results.get("crawler", {}).get("emails", [])
    run_mod("hibp", "hibp" in selected_services and crawler_emails, hibp_lookup, crawler_emails)

    should_run_exposure = ("exposure_checks" in selected_services) or mode == "semi"
    if should_run_exposure:
        run_mod("exposure_checks", True, exposure_checks, url_norm, extra_exposure_paths or [])
    if mode == "semi":
        run_mod("js_secrets", True, js_secrets_from_page, url_norm)

    current_scheme = parsed_url.scheme or "http"
    run_mod("owasp_top10", "owasp_top10" in selected_services, owasp_top10_audit, results, current_scheme)

    summary = build_summary(results)
    try:
        summary["anomalies"] = compute_anomalies(url_norm, summary)
    except Exception:
        summary["anomalies"] = {"message": "Baseline unavailable."}
    results["_summary"] = summary
    results["_meta"] = {
        "total_seconds": round(time.perf_counter() - t0, 3),
        "module_times": {k: v for k, v in module_times.items() if v},
        "scheduled_run": scheduled_run,
        "base_domain": domain,
        "scheme": parsed_url.scheme or "http",
    }
    maybe_send_notification(url_norm, summary, results)
    maybe_create_ticket(url_norm, summary, results)
    return results, url_norm

# ---------------- Routes ----------------
@app.route("/", methods=["GET"])
def index():
    return render_template_string(INDEX_HTML)

@app.route("/scan", methods=["POST"])
def scan():
    url_to_scan = request.form["url"]
    selected = request.form.getlist("services")
    view_mode = request.form.get("view_mode", "human")
    mode = request.form.get("mode", "defensive")
    extra_subdomains = parse_multiline_values(request.form.get("extra_subdomains", ""))
    extra_exposures = parse_multiline_values(request.form.get("extra_exposures", ""))
    workflow_raw = request.form.get("workflow_steps", "").strip()
    workflow_steps = []
    if workflow_raw:
        try:
            data = json.loads(workflow_raw)
            if isinstance(data, list):
                workflow_steps = data
        except json.JSONDecodeError:
            workflow_steps = []
    schedule_minutes = 0
    try:
        schedule_minutes = int(request.form.get("schedule_minutes", "0") or 0)
    except ValueError:
        schedule_minutes = 0

    results, url_norm = run_scan(url_to_scan, selected, mode, extra_subdomains, extra_exposures, workflow_steps)

    if schedule_minutes > 0:
        schedule_recurring_scan(
            url_norm,
            selected,
            mode,
            {"subdomains": extra_subdomains, "exposures": extra_exposures, "workflow": workflow_steps},
            schedule_minutes,
        )

    # Persist & capture ID
    db = get_db()
    cur = db.execute(
        'INSERT INTO scans (url, results, scan_date) VALUES (?, ?, ?)',
        (url_norm, json.dumps(results), datetime.now().isoformat())
    )
    db.commit()
    scan_id = cur.lastrowid

    # Cache latest for exports
    app.config["LATEST_RESULTS"] = results
    app.config["LATEST_URL"] = url_norm
    app.config["LATEST_SCAN_ID"] = scan_id

    return render_template_string(
        RESULTS_HTML,
        results=results,
        url=url_norm,
        view_mode=view_mode,
        mode=mode,
        pdf_available=(HTML is not None),
        scan_id=scan_id
    )

@app.route("/history")
def history():
    db = get_db()
    rows = db.execute("SELECT id, url, scan_date FROM scans ORDER BY id DESC LIMIT 100").fetchall()
    return render_template_string(HISTORY_HTML, items=rows)

@app.route("/scheduled")
def scheduled():
    db = get_db()
    rows = db.execute(
        "SELECT id, url, services, interval_minutes, next_run, last_run FROM scheduled_scans ORDER BY next_run ASC"
    ).fetchall()
    items = []
    for row in rows:
        try:
            services = ", ".join(json.loads(row["services"]))
        except Exception:
            services = row["services"]
        items.append({
            "id": row["id"],
            "url": row["url"],
            "services": services,
            "interval_minutes": row["interval_minutes"],
            "next_run": row["next_run"],
            "last_run": row["last_run"],
        })
    return render_template_string(SCHEDULED_HTML, items=items)

@app.route("/view/<int:scan_id>")
def view_scan(scan_id):
    db = get_db()
    row = db.execute("SELECT id, url, results, scan_date FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row:
        return "Not found", 404
    results = json.loads(row["results"])
    # also set LATEST so exports work after viewing history
    app.config["LATEST_RESULTS"] = results
    app.config["LATEST_URL"] = row["url"]
    app.config["LATEST_SCAN_ID"] = row["id"]
    return render_template_string(
        RESULTS_HTML,
        results=results,
        url=row["url"],
        view_mode="human",
        mode="defensive",
        pdf_available=(HTML is not None),
        scan_id=row["id"]
    )

@app.route("/graph/<int:scan_id>")
def graph(scan_id):
    db = get_db()
    row = db.execute("SELECT results FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row:
        return "Not found", 404
    results = json.loads(row["results"])
    nodes, edges = extract_relationships(results)
    return render_template_string(GRAPH_HTML, nodes=nodes, edges=edges, scan_id=scan_id)

def flatten_results_for_csv(results):
    rows = []
    for key, value in results.items():
        if key.startswith("_"):
            continue
        if isinstance(value, dict) and 'rows' in value:
            for row in value['rows']:
                rows.append({'module': key, 'data': json.dumps(row, ensure_ascii=False)})
        elif isinstance(value, dict):
            rows.append({'module': key, 'data': json.dumps(value, ensure_ascii=False)})
        elif isinstance(value, list):
            for item in value:
                rows.append({'module': key, 'data': str(item)})
        else:
            rows.append({'module': key, 'data': str(value)})
    return rows

@app.route("/export/csv")
def export_csv():
    results = app.config.get("LATEST_RESULTS", {})
    if not results:
        return "No data to export", 404

    rows = flatten_results_for_csv(results)
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=['module', 'data'])
    writer.writeheader()
    writer.writerows(rows)

    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=export.csv"
    response.headers["Content-type"] = "text/csv"
    return response

@app.route("/export/json")
def export_json():
    results = app.config.get("LATEST_RESULTS", {})
    if not results:
        return "No data to export", 404
    return Response(
        json.dumps(results, indent=2),
        mimetype='application/json',
        headers={'Content-Disposition':'attachment; filename=export.json'}
    )

@app.route("/export/pdf")
def export_pdf():
    if HTML is None:
        return "PDF export functionality is not available. Please install weasyprint.", 500
    results = app.config.get("LATEST_RESULTS", {})
    if not results:
        return "No data to export", 404
    url_norm = app.config.get("LATEST_URL", "N/A")
    rendered_html = render_template_string(
        RESULTS_HTML,
        results=results,
        url=url_norm,
        view_mode='human',
        pdf_available=False,
        scan_id=app.config.get("LATEST_SCAN_ID")
    )
    pdf = HTML(string=rendered_html).write_pdf()
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=report.pdf'
    return response

@app.route("/export/subdomains.csv")
def export_subdomains_csv():
    results = app.config.get("LATEST_RESULTS", {})
    sd = results.get("subdomain_scan", {})
    rows = sd.get("rows") or [{"subdomain": x} for x in sd.get("found", [])]
    if not rows:
        return "No subdomains", 404
    out = io.StringIO()
    cols = sorted({k for r in rows for k in r.keys()})
    writer = csv.DictWriter(out, fieldnames=cols)
    writer.writeheader()
    for r in rows:
        normalized = {}
        for k in cols:
            val = r.get(k)
            if isinstance(val, list):
                normalized[k] = ",".join(val)
            else:
                normalized[k] = val
        writer.writerow(normalized)
    resp = make_response(out.getvalue())
    resp.headers["Content-Disposition"] = "attachment; filename=subdomains.csv"
    resp.headers["Content-Type"] = "text/csv"
    return resp

@app.route("/export/report")
def export_report():
    results = app.config.get("LATEST_RESULTS", {})
    if not results:
        return "No data to export", 404
    url_val = app.config.get("LATEST_URL", "N/A")
    summary = results.get("_summary", {})
    meta = results.get("_meta", {})
    owasp = results.get("owasp_top10", {}).get("rows", [])
    exposures = results.get("exposure_checks", {}).get("rows", [])
    fuzzer = results.get("fuzzer", {}).get("rows", [])
    subdomains = results.get("subdomain_scan", {}).get("rows", [])[:15]
    signatures = results.get("signature_hits", {}).get("rows", [])
    report_html = render_template_string(
        REPORT_HTML,
        url=url_val,
        summary=summary,
        meta=meta,
        owasp=owasp,
        exposures=exposures,
        fuzzer=fuzzer,
        subdomains=subdomains,
        signatures=signatures,
        generated=datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    )
    report_format = request.args.get("format", "pdf").lower()
    if report_format == "html" or HTML is None:
        resp = make_response(report_html)
        resp.headers["Content-Type"] = "text/html"
        resp.headers["Content-Disposition"] = "attachment; filename=report.html"
        return resp
    pdf = HTML(string=report_html).write_pdf()
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=report.pdf'
    return response

# ---------------- Main ----------------
if __name__ == "__main__":
    with app.app_context():
        init_db()
    # Bind to localhost to avoid Windows firewall prompt for public networks
    app.run(host="127.0.0.1", port=8080, debug=True)
