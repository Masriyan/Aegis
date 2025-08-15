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
from datetime import datetime
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
DATABASE = os.path.join(HERE, 'threat_hunter.db')  # Windows-safe path
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

# ---------------- Flask & DB ----------------
app = Flask(__name__)
app.config.from_object(__name__)

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
            ('WHOIS Lookup', 'whois'), ('Subdomain Scan', 'subdomains'), ('VirusTotal', 'virustotal'),
            ('urlscan.io', 'urlscan'), ('AlienVault OTX', 'otx'), ('Archive.org', 'archive'),
            ('GitHub Code', 'github'), ('Shodan', 'shodan'), ('GreyNoise', 'greynoise'), ('AbuseIPDB', 'abuseipdb')
          ] %}
          <label class="flex items-center gap-2 bg-gray-700 border border-gray-600 rounded-md px-3 py-2 cursor-pointer hover:bg-gray-600">
            <input type="checkbox" name="services" value="{{ val }}" class="h-4 w-4 text-blue-500 bg-gray-600 border-gray-500 rounded focus:ring-blue-500">
            <span class="text-sm">{{ label }}</span>
          </label>
          {% endfor %}
        </div>
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
    </form>
  </div>

  <script>
    const form = document.getElementById('scanForm');
    const overlay = document.getElementById('loadingOverlay');
    form.addEventListener('submit', function() { overlay.style.display = 'flex'; });

    // Presets
    const presets = {
      recon:   ["crawler","tech","headers","sec_headers","dns","whois","archive","urlscan","github"],
      passive: ["crawler","tech","headers","sec_headers","tls","dns","whois","subdomains","virustotal","urlscan","otx","shodan","greynoise","abuseipdb"],
      semi:    ["crawler","tech","headers","sec_headers","tls","dns","whois","subdomains","virustotal","urlscan","otx","shodan","greynoise","abuseipdb"]
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
        <div class="text-sm text-gray-400">Duration (s)</div>
        <div class="text-2xl font-bold">{{ results.get('_meta', {}).get('total_seconds', '—') }}</div>
      </div>
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

    <div class="text-center mt-8">
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

def subdomain_scan(domain: str, mode: str = "defensive"):
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

    if mode == "semi":
        brute = _bruteforce_subdomains(domain)
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

EXPOSURE_PATHS = ["/.git/config", "/.env", "/server-status", "/phpinfo.php"]
def exposure_checks(base_url: str):
    rows = []
    for path in EXPOSURE_PATHS:
        url = urljoin(base_url, path)
        try:
            r = SESSION.head(url, timeout=5, allow_redirects=True)
            rows.append({"path": path, "url": url, "status": r.status_code, "length": r.headers.get("Content-Length")})
        except requests.RequestException:
            rows.append({"path": path, "url": url, "status": "Error", "length": None})
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

# ---------------- Summary & Orchestrator ----------------
def build_summary(results):
    s = {
        "subdomains": len(results.get("subdomain_scan", {}).get("rows", [])) or len(results.get("subdomain_scan", {}).get("found", [])),
        "missing_sec_headers": 0,
        "vt_malicious": 0,
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
    return s

def run_scan(url_to_scan, selected_services, mode):
    url_norm = url_normalize(url_to_scan)
    domain = get_domain(url_norm)
    results = {}
    module_times = {}
    t0 = time.perf_counter()

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
    run_mod("sec_headers",  "sec_headers" in selected_services, security_headers_report, headers)
    run_mod("tls",          "tls" in selected_services and domain, tls_info, domain)
    run_mod("whois_lookup", "whois" in selected_services and domain, get_whois_info, domain)
    run_mod("dns_records",  "dns" in selected_services and domain, get_dns_records, domain)
    run_mod("subdomain_scan", "subdomains" in selected_services and domain, subdomain_scan, domain, mode)
    run_mod("virustotal",   "virustotal" in selected_services, vt_url_lookup, url_norm)
    run_mod("urlscan",      "urlscan" in selected_services and domain, urlscan_search_domain, domain)
    run_mod("archive_org",  "archive" in selected_services, archive_cdx, url_norm)
    run_mod("otx",          "otx" in selected_services and domain, otx_domain_general, domain)
    run_mod("github",       "github" in selected_services and domain, github_code_search, domain)

    ip = ""
    if domain:
        try:
            ip = socket.gethostbyname(domain)
        except socket.gaierror:
            ip = ""

    run_mod("shodan",     "shodan" in selected_services and domain, shodan_lookup, domain)
    run_mod("greynoise",  "greynoise" in selected_services and ip, greynoise_lookup, ip)
    run_mod("abuseipdb",  "abuseipdb" in selected_services and ip, abuseipdb_lookup, ip)

    if mode == "semi":
        run_mod("exposure_checks", True, exposure_checks, url_norm)
        run_mod("js_secrets", True, js_secrets_from_page, url_norm)

    results["_summary"] = build_summary(results)
    results["_meta"] = {
        "total_seconds": round(time.perf_counter() - t0, 3),
        "module_times": {k: v for k, v in module_times.items() if v}
    }
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

    results, url_norm = run_scan(url_to_scan, selected, mode)

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

# ---------------- Main ----------------
if __name__ == "__main__":
    with app.app_context():
        init_db()
    # Bind to localhost to avoid Windows firewall prompt for public networks
    app.run(host="127.0.0.1", port=8080, debug=True)
